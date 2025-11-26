// src/wallet/spv_simple.cpp
#include "wallet/spv_simple.h"
#include "wallet/p2p_light.h"
#include "sha256.h"
#include "constants.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <cstdlib>   // getenv, strtoull
#include <thread>
#include <chrono>
#include <fstream>

#if __has_include(<filesystem>)
  #include <filesystem>
  #define MIQ_HAVE_FS 1
  namespace fs = std::filesystem;
#else
  #define MIQ_HAVE_FS 0
#endif

namespace miq {

#ifndef COINBASE_MATURITY
#define COINBASE_MATURITY 100
#endif

// ----------------- tiny helpers -----------------
static inline uint32_t rd_u32_le(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint64_t rd_u64_le(const uint8_t* p){
    uint64_t v=0; for(int i=0;i<8;i++) v |= (uint64_t)p[i] << (8*i); return v;
}
static inline void wr_u32_le(std::vector<uint8_t>& b, uint32_t v){
    b.push_back((uint8_t)(v>>0)); b.push_back((uint8_t)(v>>8));
    b.push_back((uint8_t)(v>>16)); b.push_back((uint8_t)(v>>24));
}
static inline void wr_u64_le(std::vector<uint8_t>& b, uint64_t v){
    for(int i=0;i<8;i++) b.push_back((uint8_t)(v>>(8*i)));
}

struct R {
    const uint8_t* p; size_t n, pos;
    explicit R(const std::vector<uint8_t>& v): p(v.data()), n(v.size()), pos(0) {}
    bool need(size_t k) const { return pos + k <= n; }
    bool get(void* out, size_t k){ if(!need(k)) return false; std::memcpy(out, p+pos, k); pos+=k; return true; }
    bool skip(size_t k){ if(!need(k)) return false; pos+=k; return true; }
    size_t tell() const { return pos; }
};

static bool get_varint(R& r, uint64_t& v){
    if(!r.need(1)) return false;
    uint8_t x = r.p[r.pos++];
    if(x < 0xFD){ v=x; return true; }
    if(x == 0xFD){ if(!r.need(2)) return false; v = (uint64_t)r.p[r.pos] | ((uint64_t)r.p[r.pos+1]<<8); r.pos+=2; return true; }
    if(x == 0xFE){ if(!r.need(4)) return false; v = rd_u32_le(r.p+r.pos); r.pos+=4; return true; }
    if(x == 0xFF){ if(!r.need(8)) return false; v = rd_u64_le(r.p+r.pos); r.pos+=8; return true; }
    return false;
}

static inline std::vector<uint8_t> dsha256_bytes(const uint8_t* b, size_t len){
    std::vector<uint8_t> tmp(b,b+len); return dsha256(tmp);
}
static inline std::vector<uint8_t> to_le32(const std::vector<uint8_t>& h){
    std::vector<uint8_t> r=h; std::reverse(r.begin(), r.end()); return r;
}

// key = txid (bytes, LE) + vout u32 LE
static inline std::string key_of(const std::vector<uint8_t>& txid, uint32_t vout){
    std::string k; k.reserve(36);
    k.assign((const char*)txid.data(), txid.size());
    k.push_back((char)((vout>>0)&0xFF));
    k.push_back((char)((vout>>8)&0xFF));
    k.push_back((char)((vout>>16)&0xFF));
    k.push_back((char)((vout>>24)&0xFF));
    return k;
}

struct VecHash {
    size_t operator()(const std::vector<uint8_t>& v) const noexcept {
        size_t h = 1469598103934665603ull; // FNV-1a
        for(uint8_t b: v){ h ^= b; h *= 1099511628211ull; }
        return h;
    }
};

// env overrides for pacing knobs (safe defaults)
static inline uint32_t env_u32(const char* name, uint32_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr;
    unsigned long long t = std::strtoull(v, &end, 10);
    if(end && *end=='\0') return (uint32_t)t;
    return defv;
}

// ----------------- tx / block parsing -----------------

struct TxParsed {
    std::vector<uint8_t> txid_le; // wire order (LE)
    bool coinbase{false};
    struct In  { std::vector<uint8_t> prev_txid; uint32_t vout; };
    struct Out { uint64_t value; std::vector<uint8_t> pkh;      };
    std::vector<In>  vin;
    std::vector<Out> vout;
};

// --- Bitcoin-like (fallback only; MIQ path is primary) ---
static bool parse_tx_bitcoin(R& r, TxParsed& out){
    size_t start = r.tell();
    uint32_t version=0; if(!r.get(&version,4)) return false;

    // (No segwit support; not needed for MIQ. Keep it minimal.)
    uint64_t in_count=0; if(!get_varint(r, in_count)) return false;
    out.vin.clear(); out.vin.reserve((size_t)in_count);
    for(uint64_t i=0;i<in_count;i++){
        if(!r.need(36)) return false;
        TxParsed::In in{};
        in.prev_txid.assign(r.p + r.pos, r.p + r.pos + 32); r.pos += 32; // txid (LE on wire)
        uint32_t vout=0; if(!r.get(&vout,4)) return false; in.vout=vout;
        uint64_t sl=0; if(!get_varint(r,sl)) return false;
        if(!r.skip((size_t)sl)) return false;
        uint32_t seq=0; if(!r.get(&seq,4)) return false;
        out.vin.push_back(std::move(in));
    }

    uint64_t out_count=0; if(!get_varint(r, out_count)) return false;
    out.vout.clear(); out.vout.reserve((size_t)out_count);
    for(uint64_t i=0;i<out_count;i++){
        if(!r.need(8)) return false;
        uint64_t val = rd_u64_le(r.p + r.pos); r.pos += 8;
        uint64_t pk_len=0; if(!get_varint(r, pk_len)) return false;
        if(!r.need((size_t)pk_len)) return false;

        TxParsed::Out o{val, {}};
        // P2PKH: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
        if(pk_len == 25
           && r.p[r.pos+0] == 0x76 && r.p[r.pos+1] == 0xA9
           && r.p[r.pos+2] == 0x14 && r.p[r.pos+23] == 0x88 && r.p[r.pos+24] == 0xAC)
        {
            o.pkh.assign(r.p + r.pos + 3, r.p + r.pos + 23);
        }
        r.pos += (size_t)pk_len;
        out.vout.push_back(std::move(o));
    }

    uint32_t lock_time=0; if(!r.get(&lock_time,4)) return false;

    // coinbase: single input, prev_hash=0..0, vout=0xffffffff
    out.coinbase = false;
    if(in_count==1){
        const auto& in0 = out.vin[0];
        bool allz=true; for(uint8_t b: in0.prev_txid) if(b){ allz=false; break; }
        if(allz && in0.vout==0xffffffffu) out.coinbase = true;
    }

    auto h = dsha256_bytes(r.p + start, r.tell() - start);
    out.txid_le = to_le32(h);
    return true;
}

// --- MIQ compact (primary) ---
static bool parse_tx_miq_blockwrapped(R& r, TxParsed& out){
    if(!r.need(4)) return false;
    uint32_t tx_size = rd_u32_le(r.p + r.pos); r.pos += 4;

    const uint32_t tx_size_limit = env_u32("MIQ_MAX_TX_SIZE", 900u*1024u); // align with node hint
    if (tx_size == 0 || tx_size > tx_size_limit) return false;
    if(!r.need(tx_size)) return false;

    size_t start = r.tell();
    size_t end   = start + tx_size;

    // sub-reader over the tx payload
    std::vector<uint8_t> slice(r.p + start, r.p + end);
    R tr(slice);

    uint32_t version=0; if(!tr.get(&version,4)) return false;

    uint32_t in_count=0; if(!tr.get(&in_count,4)) return false;
    out.vin.clear(); out.vin.reserve(in_count);
    for(uint32_t i=0;i<in_count;i++){
        uint32_t pt_len=0; if(!tr.get(&pt_len,4)) return false;
        if(pt_len!=32 || !tr.need(32)) return false;
        TxParsed::In in{};
        in.prev_txid.assign(tr.p + tr.pos, tr.p + tr.pos + 32); tr.pos += 32;
        uint32_t vout=0; if(!tr.get(&vout,4)) return false; in.vout=vout;

        uint32_t sig_len=0; if(!tr.get(&sig_len,4)) return false; if(!tr.skip(sig_len)) return false;
        uint32_t pub_len=0; if(!tr.get(&pub_len,4)) return false; if(!tr.skip(pub_len)) return false;

        out.vin.push_back(std::move(in));
    }

    uint32_t out_count=0; if(!tr.get(&out_count,4)) return false;
    out.vout.clear(); out.vout.reserve(out_count);
    for(uint32_t i=0;i<out_count;i++){
        if(!tr.need(8)) return false;
        uint64_t val = rd_u64_le(tr.p + tr.pos); tr.pos += 8;
        uint32_t pkh_len=0; if(!tr.get(&pkh_len,4)) return false;
        if(pkh_len!=20 || !tr.need(20)) return false;
        TxParsed::Out o{val, {}};
        o.pkh.assign(tr.p + tr.pos, tr.p + tr.pos + 20); tr.pos += 20;
        out.vout.push_back(std::move(o));
    }

    uint32_t lock_time=0; if(!tr.get(&lock_time,4)) return false;

    // coinbase heuristic for MIQ: single input with zero prev hash and vout=0xffffffff
    out.coinbase = false;
    if(in_count==1){
        const auto& in0 = out.vin[0];
        bool allz=true; for(uint8_t b: in0.prev_txid) if(b){ allz=false; break; }
        // Standard coinbase: all-zero prev_txid AND vout=0xffffffff (or 0 for some implementations)
        if(allz && (in0.vout == 0xffffffffu || in0.vout == 0)) out.coinbase = true;
    }

    auto h = dsha256_bytes(r.p + start, tx_size);
    out.txid_le = to_le32(h);

    // advance outer reader
    r.pos = end;
    return true;
}

// Try MIQ block first (our chain), then conservative Bitcoin as a fallback
static bool parse_block_collect(const std::vector<uint8_t>& raw,
                                std::vector<TxParsed>& out_txs)
{
    out_txs.clear();

    // --- MIQ compact (primary) ---
    // MIQ header is 88 bytes: version(4) + prev_hash(32) + merkle_root(32) + time(8) + bits(4) + nonce(8)
    {
        R r(raw);
        if(!r.need(88)) return false;
        r.skip(88);

        if(!r.need(4)) return false;
        uint32_t txcnt = rd_u32_le(r.p + r.pos); r.pos += 4;

        const uint32_t MAX_TXS = env_u32("MIQ_MAX_TXS_PER_BLOCK", 10000);
        if (txcnt > MAX_TXS) return false;

        std::vector<TxParsed> txs; txs.reserve(txcnt);
        for(uint32_t i=0;i<txcnt;i++){
            TxParsed t; if(!parse_tx_miq_blockwrapped(r, t)) { txs.clear(); goto try_bitcoin; }
            txs.push_back(std::move(t));
        }
        out_txs.swap(txs);
        return true;
    }

try_bitcoin:
    // --- Bitcoin-like (fallback only) ---
    {
        R r2(raw);
        if(!r2.need(80)) return false;
        r2.skip(80);
        uint64_t txcnt=0; if(!get_varint(r2, txcnt)) return false;

        const uint64_t MAX_TXS_BTC = env_u32("MIQ_MAX_TXS_PER_BLOCK_BTC", 5000);
        if(txcnt > MAX_TXS_BTC) return false;

        std::vector<TxParsed> txs; txs.reserve((size_t)txcnt);
        for(uint64_t i=0;i<txcnt;i++){
            TxParsed t; if(!parse_tx_bitcoin(r2, t)) return false;
            txs.push_back(std::move(t));
        }
        out_txs.swap(txs);
        return true;
    }
}

// ----------------- tiny persistent cache -----------------

struct CacheState { uint32_t scanned_upto = 0; };

// =============================================================================
// IN-MEMORY UTXO CACHE - Avoid repeated disk reads for performance
// =============================================================================
struct UtxoMemCache {
    std::vector<UtxoLite> entries;
    std::string cache_dir;
    uint32_t scanned_height{0};
    int64_t last_load_time{0};
    bool valid{false};

    static UtxoMemCache& instance() {
        static UtxoMemCache cache;
        return cache;
    }

    void invalidate() {
        entries.clear();
        scanned_height = 0;
        last_load_time = 0;
        valid = false;
    }

    bool is_valid(const std::string& dir, uint32_t current_tip) const {
        // Cache is valid if:
        // 1. It's been loaded
        // 2. Same cache directory
        // 3. We're at or ahead of the cached height (no new blocks)
        // 4. Within 30 seconds of last load (for mempool changes)
        if (!valid) return false;
        if (cache_dir != dir) return false;

        auto now = std::chrono::system_clock::now().time_since_epoch();
        int64_t now_sec = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        if ((now_sec - last_load_time) > 30) return false;

        // If tip is the same or behind our cache, we're up to date
        return current_tip <= scanned_height;
    }

    void update(const std::string& dir, const std::vector<UtxoLite>& utxos, uint32_t height) {
        entries = utxos;
        cache_dir = dir;
        scanned_height = height;

        auto now = std::chrono::system_clock::now().time_since_epoch();
        last_load_time = std::chrono::duration_cast<std::chrono::seconds>(now).count();
        valid = true;
    }
};

static inline std::string path_join(const std::string& dir, const char* fname){
    if (dir.empty()) return std::string(fname);
    char sep = '/';
#if defined(_WIN32)
    sep = '\\';
#endif
    if (dir.back() == '/' || dir.back() == '\\') return dir + fname;
    return dir + sep + fname;
}

static inline uint32_t csum4(const std::vector<uint8_t>& v){
    auto d = dsha256(v);
    return (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
}

static bool load_state(const std::string& dir, CacheState& st){
    std::string p = path_join(dir, "spv_state.dat");
    std::ifstream f(p, std::ios::binary);
    if(!f.good()) return false;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
    if(buf.size() < 8) return false;
    const char magic[] = "MIQSPV1";
    if(std::memcmp(buf.data(), magic, 7)!=0) return false;
    if(buf.size() < 7 + 4 + 4) return false;
    uint32_t height = rd_u32_le(buf.data()+7);
    uint32_t want = rd_u32_le(buf.data()+7+4);
    std::vector<uint8_t> body(buf.begin(), buf.begin()+7+4);
    if(csum4(body) != want) return false;

    // Sanity check: height should be reasonable (not 0xFFFFFFFF from corruption)
    const uint32_t MAX_REASONABLE_HEIGHT = 100000000; // 100M blocks
    if(height > MAX_REASONABLE_HEIGHT) return false;

    st.scanned_upto = height;
    return true;
}
static void save_state(const std::string& dir, const CacheState& st){
#if MIQ_HAVE_FS
    if(!dir.empty()){
        std::error_code ec;
        fs::create_directories(dir, ec); // best-effort
    }
#endif
    std::vector<uint8_t> buf;
    const char magic[] = "MIQSPV1";
    buf.insert(buf.end(), magic, magic+7);
    wr_u32_le(buf, st.scanned_upto);
    uint32_t sum = csum4(buf);
    wr_u32_le(buf, sum);
    std::string p = path_join(dir, "spv_state.dat");
    std::ofstream f(p, std::ios::binary|std::ios::trunc);
    if(f.good()) f.write((const char*)buf.data(), (std::streamsize)buf.size());
}

static bool load_utxo_cache(const std::string& dir, std::vector<UtxoLite>& out){
    out.clear();
    std::string p = path_join(dir, "utxo_cache.dat");
    std::ifstream f(p, std::ios::binary);
    if(!f.good()) return false;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
    if(buf.size() < 8) return false;
    const char magic[] = "MIQUTXO1";
    if(std::memcmp(buf.data(), magic, 8)!=0) return false;
    if(buf.size() < 8 + 4 + 4) return false;
    uint32_t cnt = rd_u32_le(buf.data()+8);

    // Sanity check: prevent huge allocations from corrupted files
    const uint32_t MAX_CACHE_ENTRIES = 10000000; // 10M entries max
    if(cnt > MAX_CACHE_ENTRIES) return false;

    size_t need = 8 + 4 + (size_t)cnt * (32+4+8+20+4+1) + 4;
    if(buf.size() != need) return false;
    uint32_t have = rd_u32_le(buf.data()+need-4);
    std::vector<uint8_t> body(buf.begin(), buf.begin()+need-4);
    if(csum4(body) != have) return false;

    out.reserve(cnt);
    size_t pos = 8 + 4;
    for(uint32_t i=0;i<cnt;i++){
        // Bounds check before reading
        if(pos + 32 + 4 + 8 + 20 + 4 + 1 > buf.size()) return false;

        UtxoLite u;
        u.txid.assign(buf.begin()+pos, buf.begin()+pos+32); pos+=32;
        u.vout = rd_u32_le(buf.data()+pos); pos+=4;
        u.value = rd_u64_le(buf.data()+pos); pos+=8;
        u.pkh.assign(buf.begin()+pos, buf.begin()+pos+20); pos+=20;
        u.height = rd_u32_le(buf.data()+pos); pos+=4;
        u.coinbase = buf[pos++] ? true : false;
        out.push_back(std::move(u));
    }
    return true;
}
static void save_utxo_cache(const std::string& dir, const std::vector<UtxoLite>& v){
#if MIQ_HAVE_FS
    if(!dir.empty()){
        std::error_code ec;
        fs::create_directories(dir, ec); // best-effort
    }
#endif
    std::vector<uint8_t> buf;
    const char magic[] = "MIQUTXO1";
    buf.insert(buf.end(), magic, magic+8);
    wr_u32_le(buf, (uint32_t)v.size());
    for(const auto& u : v){
        buf.insert(buf.end(), u.txid.begin(), u.txid.end());          // 32
        wr_u32_le(buf, u.vout);                                       // 4
        wr_u64_le(buf, u.value);                                      // 8
        buf.insert(buf.end(), u.pkh.begin(), u.pkh.end());             // 20
        wr_u32_le(buf, u.height);                                     // 4
        buf.push_back(u.coinbase ? 1 : 0);                             // 1
    }
    uint32_t sum = csum4(buf);
    wr_u32_le(buf, sum);
    std::string p = path_join(dir, "utxo_cache.dat");
    std::ofstream f(p, std::ios::binary|std::ios::trunc);
    if(f.good()) f.write((const char*)buf.data(), (std::streamsize)buf.size());
}

// ----------------- SPV main -----------------

bool spv_collect_utxos(const std::string& p2p_host, const std::string& p2p_port,
                       const std::vector<std::vector<uint8_t>>& pkhs,
                       const SpvOptions& opt,
                       std::vector<UtxoLite>& out,
                       std::string& err)
{
    out.clear();

    // 1) connect + handshake
    P2POpts po;
    po.host = p2p_host;
    po.port = p2p_port;
    po.user_agent = "/miqwallet-spv:0.5/"; // bumped ua
    if (opt.timeout_ms > 0) {
        po.io_timeout_ms = opt.timeout_ms;
    }
    P2PLight p2p;
    if(!p2p.connect_and_handshake(po, err)) return false;

    // 2) headers -> tip (this syncs all headers which may take time)
    // BULLETPROOF FIX: Retry header sync up to 3 times for reliability
    uint32_t tip_height=0; std::vector<uint8_t> tip_hash_le;
    bool header_success = false;
    for(int header_retry = 0; header_retry < 3 && !header_success; ++header_retry){
        if(p2p.get_best_header(tip_height, tip_hash_le, err)){
            header_success = true;
        } else {
            if(header_retry < 2){
                // Wait before retry with exponential backoff
                std::this_thread::sleep_for(std::chrono::milliseconds(500 * (1 << header_retry)));
                err.clear();
            }
        }
    }
    if(!header_success){ p2p.close(); return false; }

    // Validate tip hash
    if(tip_hash_le.size() != 32){
        err = "invalid tip hash from peer";
        p2p.close();
        return false;
    }

    // PERFORMANCE: Check in-memory cache first to avoid disk reads and block scanning
    // If cache is valid (same wallet, recent, and no new blocks), return cached UTXOs
    {
        auto& mem_cache = UtxoMemCache::instance();
        if(mem_cache.is_valid(opt.cache_dir, tip_height)){
            // Filter cached UTXOs by current wallet's PKHs
            std::unordered_set<std::vector<uint8_t>, VecHash> pkhset(pkhs.begin(), pkhs.end());
            out.clear();
            out.reserve(mem_cache.entries.size());
            for(const auto& u : mem_cache.entries){
                if(pkhset.find(u.pkh) != pkhset.end()){
                    out.push_back(u);
                }
            }
            p2p.close();
            return true;
        }
    }

    // 3) decide start height from cache (or full/genesis on first run)
    CacheState st{};
    const bool have_state = load_state(opt.cache_dir, st);
    uint32_t start_h = 0;
    if(have_state){
        // Validate cached height against tip
        if(st.scanned_upto > tip_height){
            // Chain reorg detected - rescan from before the reorg point
            // Use a safety margin to handle any reorg
            const uint32_t reorg_margin = 100;
            if(tip_height > reorg_margin)
                start_h = tip_height - reorg_margin;
            else
                start_h = 0;
        } else if(st.scanned_upto < tip_height){
            start_h = st.scanned_upto + 1;
        } else {
            start_h = tip_height; // nothing to do
        }
    } else {
        // First ever run: if user provided a small window, use it; else go from genesis.
        if(opt.recent_block_window > 0 && opt.recent_block_window < tip_height)
            start_h = tip_height - opt.recent_block_window;
        else
            start_h = 0;
    }

    // 4) load previous UTXO view if present (for incremental updates)
    std::vector<UtxoLite> view;
    if(!have_state || !load_utxo_cache(opt.cache_dir, view)){
        view.clear(); // no prior
    }

    // Build fast index
    std::unordered_map<std::string,size_t> idx;
    idx.reserve(view.size()*2 + 16);
    for(size_t i=0;i<view.size(); ++i){
        idx[key_of(view[i].txid, view[i].vout)] = (uint32_t)i;
    }

    // 5) block enumeration for [start_h .. tip_height]
    std::vector<std::pair<std::vector<uint8_t>, uint32_t>> blocks;
    // IMPORTANT: ask peer to pre-filter using our PKHs
    if(!p2p.match_recent_blocks(pkhs, start_h, tip_height, blocks, err)){ p2p.close(); return false; }

    // 6) fast PKH lookup
    std::unordered_set<std::vector<uint8_t>, VecHash> pkhset(pkhs.begin(), pkhs.end());

    // 6b) Re-filter cached UTXOs against current wallet's PKHs
    // This ensures that when switching wallets, we don't show UTXOs from other wallets
    {
        std::vector<UtxoLite> filtered_view;
        filtered_view.reserve(view.size());
        for(const auto& u : view){
            if(pkhset.find(u.pkh) != pkhset.end()){
                filtered_view.push_back(u);
            }
        }
        if(filtered_view.size() != view.size()){
            // Cache contained UTXOs from different wallet, rebuild index
            view = std::move(filtered_view);
            idx.clear();
            idx.reserve(view.size() * 2 + 16);
            for(size_t i = 0; i < view.size(); ++i){
                idx[key_of(view[i].txid, view[i].vout)] = i;
            }
        }
    }

    auto add_out = [&](const std::vector<uint8_t>& txid_le, uint32_t vout,
                       uint64_t value, const std::vector<uint8_t>& pkh,
                       uint32_t height, bool coinbase)
    {
        if(pkhset.find(pkh)==pkhset.end()) return;
        UtxoLite u;
        u.txid = txid_le; u.vout=vout; u.value=value; u.pkh=pkh; u.height=height; u.coinbase=coinbase;
        idx[key_of(u.txid, u.vout)] = (uint32_t)view.size();
        view.push_back(std::move(u));
    };

    auto del_in = [&](const std::vector<uint8_t>& prev_txid, uint32_t vout){
        // Try both byte orders since txids can be stored in LE or BE
        auto k = key_of(prev_txid, vout);
        auto it = idx.find(k);
        if(it==idx.end()){
            std::vector<uint8_t> rev = prev_txid; std::reverse(rev.begin(), rev.end());
            k = key_of(rev, vout);
            it = idx.find(k);
        }
        if(it!=idx.end()){
            size_t pos  = it->second;
            // Bounds check before swap
            if(view.empty()) return;
            size_t last = view.size()-1;
            if(pos > last) return; // Safety check
            if(pos!=last){
                // Update index for the element being swapped
                auto last_key = key_of(view[last].txid, view[last].vout);
                idx[last_key] = pos;
                std::swap(view[pos], view[last]);
            }
            view.pop_back();
            idx.erase(it);
        }
    };

    // 7) stream blocks, update view — chunked + paced to protect the node
    // IMPROVED: Added streaming with progressive cache flushing and memory limits
    const uint32_t MAX_PER_CHUNK = env_u32("MIQ_MAX_BLOCKS_PER_CHUNK", 64);
    const uint32_t SLEEP_MS      = env_u32("MIQ_SLEEP_BETWEEN_CHUNKS_MS", 50);
    const uint32_t FLUSH_EVERY   = env_u32("MIQ_FLUSH_CACHE_EVERY", 500); // Flush every N blocks
    const size_t   MAX_VIEW_SIZE = env_u32("MIQ_MAX_UTXO_VIEW_SIZE", 100000); // Max UTXOs in memory
    uint32_t chunk_count = 0;
    uint32_t blocks_processed = 0;
    const size_t total_blocks = blocks.size();
    const uint32_t PROGRESS_EVERY = env_u32("MIQ_PROGRESS_EVERY", 100); // Show progress every N blocks

    for(const auto& bh : blocks){
        const auto& hash_le = bh.first;
        const uint32_t height = bh.second;

        // Validate hash size
        if(hash_le.size() != 32){
            err = "invalid block hash size at height " + std::to_string(height);
            p2p.close();
            return false;
        }

        std::vector<uint8_t> raw;
        // BULLETPROOF FIX: Retry block fetch up to 3 times before failing
        bool block_success = false;
        for(int block_retry = 0; block_retry < 3 && !block_success; ++block_retry){
            if(p2p.get_block_by_hash(hash_le, raw, err)){
                block_success = true;
            } else {
                // Wait before retry with exponential backoff
                if(block_retry < 2){
                    std::this_thread::sleep_for(std::chrono::milliseconds(100 * (1 << block_retry)));
                }
            }
        }
        if(!block_success){
            // Append height info to error for better debugging
            if(!err.empty()) err += " (at height " + std::to_string(height) + ")";
            p2p.close();
            return false;
        }

        // Validate we got data
        if(raw.empty()){
            err = "empty block data at height " + std::to_string(height);
            p2p.close();
            return false;
        }

        std::vector<TxParsed> txs;
        if(!parse_block_collect(raw, txs)){ err = "failed to parse block @" + std::to_string(height); p2p.close(); return false; }

        // Process deletions first (spends)
        for(const auto& tx : txs){
            for(const auto& in : tx.vin) del_in(in.prev_txid, in.vout);
        }

        // Then process additions (new outputs)
        for(const auto& tx : txs){
            for(uint32_t i=0;i<(uint32_t)tx.vout.size(); ++i){
                const auto& o = tx.vout[i];
                if(o.pkh.size()==20) add_out(tx.txid_le, i, o.value, o.pkh, height, tx.coinbase);
            }
        }

        blocks_processed++;

        // Show progress periodically
        if(blocks_processed % PROGRESS_EVERY == 0 || blocks_processed == total_blocks){
            fprintf(stderr, "\r  Scanning: %u/%zu blocks (height %u), %zu UTXOs found...",
                    blocks_processed, total_blocks, height, view.size());
            fflush(stderr);
        }

        // Progressive cache flushing to prevent memory overflow
        if(blocks_processed % FLUSH_EVERY == 0){
            // Save intermediate state
            CacheState tempst; tempst.scanned_upto = height;
            save_state(opt.cache_dir, tempst);
            save_utxo_cache(opt.cache_dir, view);
        }

        // Memory pressure check: if UTXO set is too large, compact it
        if(view.size() > MAX_VIEW_SIZE){
            // Rebuild index to remove any stale entries
            std::vector<UtxoLite> compacted;
            compacted.reserve(view.size());
            idx.clear();
            idx.reserve(view.size() + 16);

            for(size_t i = 0; i < view.size(); ++i){
                // Only keep UTXOs that match our watched PKHs
                if(pkhset.find(view[i].pkh) != pkhset.end()){
                    idx[key_of(view[i].txid, view[i].vout)] = compacted.size();
                    compacted.push_back(std::move(view[i]));
                }
            }
            view = std::move(compacted);
        }

        if(++chunk_count >= MAX_PER_CHUNK){
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
            chunk_count = 0;
        }
    }

    p2p.close();

    // Clear progress line
    if(blocks_processed > 0){
        fprintf(stderr, "\r  Scan complete: %u blocks processed, %zu UTXOs found\n",
                blocks_processed, view.size());
    }

    // 8) save checkpoint at the tip we just synced to
    CacheState newst; newst.scanned_upto = tip_height;
    save_state(opt.cache_dir, newst);
    save_utxo_cache(opt.cache_dir, view);

    // 9) post-filter: require ≥1 conf AND match wallet PKHs
    // NOTE: We return immature coinbase so wallet can display them as "Immature" balance
    // The wallet will filter them from spendable but show them in the UI
    std::vector<UtxoLite> finalv; finalv.reserve(view.size());
    for(const auto& u : view){
        uint32_t conf = (u.height <= tip_height) ? (tip_height - u.height + 1) : 0;
        if(conf < 1) continue;
        // Only include UTXOs that belong to this wallet's addresses
        if(pkhset.find(u.pkh) == pkhset.end()) continue;
        finalv.push_back(u);
    }

    // PERFORMANCE: Update in-memory cache for instant subsequent loads
    UtxoMemCache::instance().update(opt.cache_dir, finalv, tip_height);

    out.swap(finalv);
    return true;
}

uint64_t spv_sum_value(const std::vector<UtxoLite>& v){
    uint64_t s=0; for(const auto& u : v) s += u.value; return s;
}

}
