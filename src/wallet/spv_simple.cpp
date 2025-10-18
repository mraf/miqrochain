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

    const uint32_t MAX_TX_SIZE = env_u32("MIQ_MAX_TX_SIZE", 900u*1024u); // align with node hint
    if (tx_size == 0 || tx_size > MAX_TX_SIZE) return false;
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

    // coinbase heuristic for MIQ: single input with zero prev hash
    out.coinbase = false;
    if(in_count==1){
        const auto& in0 = out.vin[0];
        bool allz=true; for(uint8_t b: in0.prev_txid) if(b){ allz=false; break; }
        if(allz) out.coinbase = true;
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
    {
        R r(raw);
        if(!r.need(80)) return false;
        r.skip(80);

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
    size_t need = 8 + 4 + (size_t)cnt * (32+4+8+20+4+1) + 4;
    if(buf.size() != need) return false;
    uint32_t have = rd_u32_le(buf.data()+need-4);
    std::vector<uint8_t> body(buf.begin(), buf.begin()+need-4);
    if(csum4(body) != have) return false;

    size_t pos = 8 + 4;
    for(uint32_t i=0;i<cnt;i++){
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
    P2PLight p2p;
    if(!p2p.connect_and_handshake(po, err)) return false;

    // 2) headers -> tip
    uint32_t tip_height=0; std::vector<uint8_t> tip_hash_le;
    if(!p2p.get_best_header(tip_height, tip_hash_le, err)){ p2p.close(); return false; }

    // 3) decide start height from cache (or full/genesis on first run)
    CacheState st{};
    const bool have_state = load_state(opt.cache_dir, st);
    uint32_t start_h = 0;
    if(have_state){
        if(st.scanned_upto < tip_height) start_h = st.scanned_upto + 1;
        else start_h = tip_height; // nothing to do
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
        auto k = key_of(prev_txid, vout);
        auto it = idx.find(k);
        if(it==idx.end()){
            std::vector<uint8_t> rev = prev_txid; std::reverse(rev.begin(), rev.end());
            k = key_of(rev, vout);
            it = idx.find(k);
        }
        if(it!=idx.end()){
            size_t pos  = it->second;
            size_t last = view.size()-1;
            if(pos!=last){
                idx[key_of(view[last].txid, view[last].vout)] = pos;
                std::swap(view[pos], view[last]);
            }
            view.pop_back();
            idx.erase(it);
        }
    };

    // 7) stream blocks, update view — chunked + paced to protect the node
    const uint32_t MAX_PER_CHUNK = env_u32("MIQ_MAX_BLOCKS_PER_CHUNK", 64);
    const uint32_t SLEEP_MS      = env_u32("MIQ_SLEEP_BETWEEN_CHUNKS_MS", 50);
    uint32_t chunk_count = 0;

    for(const auto& bh : blocks){
        const auto& hash_le = bh.first;
        const uint32_t height = bh.second;

        std::vector<uint8_t> raw;
        if(!p2p.get_block_by_hash(hash_le, raw, err)){ p2p.close(); return false; }

        std::vector<TxParsed> txs;
        if(!parse_block_collect(raw, txs)){ err = "failed to parse block @" + std::to_string(height); p2p.close(); return false; }

        for(const auto& tx : txs){
            for(const auto& in : tx.vin) del_in(in.prev_txid, in.vout);
        }
        for(const auto& tx : txs){
            for(uint32_t i=0;i<(uint32_t)tx.vout.size(); ++i){
                const auto& o = tx.vout[i];
                if(o.pkh.size()==20) add_out(tx.txid_le, i, o.value, o.pkh, height, tx.coinbase);
            }
        }

        if(++chunk_count >= MAX_PER_CHUNK){
            std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_MS));
            chunk_count = 0;
        }
    }

    p2p.close();

    // 8) save checkpoint at the tip we just synced to
    CacheState newst; newst.scanned_upto = tip_height;
    save_state(opt.cache_dir, newst);
    save_utxo_cache(opt.cache_dir, view);

    // 9) post-filter: require ≥1 conf for all; coinbases need full maturity
    std::vector<UtxoLite> finalv; finalv.reserve(view.size());
    for(const auto& u : view){
        uint32_t conf = (u.height <= tip_height) ? (tip_height - u.height + 1) : 0;
        if(conf < 1) continue;
        if(u.coinbase && conf < COINBASE_MATURITY) continue;
        finalv.push_back(u);
    }

    out.swap(finalv);
    return true;
}

uint64_t spv_sum_value(const std::vector<UtxoLite>& v){
    uint64_t s=0; for(const auto& u : v) s += u.value; return s;
}

}
