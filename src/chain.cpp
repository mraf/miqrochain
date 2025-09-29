#include "chain.h"
#include <cmath>      // std::pow
#include <optional>
#include "sha256.h"
#include "mtp.h"
#include <deque>
#include "reorg_manager.h"
#include "merkle.h"
#include <unordered_map>
#include "hasher.h"
#include <cstdlib>
#include "log.h"
#include "sig_encoding.h"
#include "hash160.h"
#include "crypto/ecdsa_iface.h"
#include "constants.h"     // BLOCK_TIME_SECS, GENESIS_BITS, etc.
#include "difficulty.h"    // lwma_next_bits
#include "supply.h"        // MAX_SUPPLY helpers (GetBlockSubsidy, WouldExceedMaxSupply, CoinbaseWithinLimits)
#include <sstream>
#include <unordered_set>

// === Added includes for security checks ===
#include <algorithm>       // std::any_of, std::sort
#include <chrono>          // future-time bound
#include <cstring>         // std::memcmp, std::memset
#include <type_traits>     // compile-time detection (SFINAE)

#ifndef MAX_TX_SIZE
#define MIQ_FALLBACK_MAX_TX_SIZE (100u * 1024u) // 100 KiB default
#else
#define MIQ_FALLBACK_MAX_TX_SIZE (MAX_TX_SIZE)
#endif

// Default ON: enforce Low-S in consensus (may be overridden in constants.h)
#ifndef MIQ_RULE_ENFORCE_LOW_S
#define MIQ_RULE_ENFORCE_LOW_S 1
#endif

#include <cstdio>
#include <string>
#include <vector>
#include <sys/types.h>
#ifdef _WIN32
  #include <direct.h>
  #include <io.h>
  #define miq_mkdir(p) _mkdir(p)
  #define miq_fsync(fd) _commit(fd)
  #define miq_fileno _fileno
#else
  #include <sys/stat.h>
  #include <unistd.h>
  #include <fcntl.h>
  #define miq_mkdir(p) mkdir(p, 0755)
  #define miq_fsync(fd) fsync(fd)
  #define miq_fileno fileno
#endif

namespace miq {

struct UndoIn {
    std::vector<uint8_t> prev_txid;
    uint32_t             prev_vout{0};
    UTXOEntry            prev_entry;
};

// Binary-safe key for unordered_map (store raw 32 bytes)
static inline std::string hk(const std::vector<uint8_t>& h){
    return std::string(reinterpret_cast<const char*>(h.data()), h.size());
}

static inline std::vector<uint8_t> header_hash_of(const BlockHeader& h) {
    Block tmp; 
    tmp.header = h;
    return tmp.block_hash();
}

static inline size_t env_szt(const char* name, size_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; long long x = std::strtoll(v, &end, 10);
    if(end==v || x < 0) return defv;
    return (size_t)x;
}
static const size_t UNDO_WINDOW = env_szt("MIQ_UNDO_WINDOW", 2000); // keep last N blocks' undo

static inline std::string hexstr(const std::vector<uint8_t>& v){
    static const char* hexd="0123456789abcdef";
    std::string s; s.resize(v.size()*2);
    for(size_t i=0;i<v.size();++i){ unsigned b=v[i]; s[2*i]=hexd[b>>4]; s[2*i+1]=hexd[b&15]; }
    return s;
}
static inline std::string join_path(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}

static inline std::string undo_dir(const std::string& base){ return join_path(base, "undo"); }

static void ensure_dir_exists(const std::string& path){
#ifdef _WIN32
    _mkdir(path.c_str()); // ok if exists
#else
    mkdir(path.c_str(), 0755); // ok if exists
#endif
}

static bool write_undo_file(const std::string& base_dir,
                            uint64_t height,
                            const std::vector<uint8_t>& block_hash,
                            const std::vector<UndoIn>& undo_vec)
{
    std::string dir = undo_dir(base_dir);
    ensure_dir_exists(dir);
    char name[64];
    std::snprintf(name, sizeof(name), "%08llu_%s.undo",
                  (unsigned long long)height, hexstr(block_hash).c_str());
    std::string path = join_path(dir, name);
    std::string tmp  = path + ".tmp";

    FILE* f = std::fopen(tmp.c_str(), "wb");
    if(!f) return false;

    auto W8  =[&](uint8_t v){ std::fwrite(&v,1,1,f); };
    auto W32 =[&](uint32_t v){ uint8_t b[4]; for(int i=0;i<4;i++) b[i]=(v>>(i*8))&0xff; std::fwrite(b,1,4,f); };
    auto W64 =[&](uint64_t v){ uint8_t b[8]; for(int i=0;i<8;i++) b[i]=(v>>(i*8))&0xff; std::fwrite(b,1,8,f); };
    auto WVS =[&](const std::vector<uint8_t>& s){ W8((uint8_t)s.size()); if(!s.empty()) std::fwrite(s.data(),1,s.size(),f); };

    // format: magic "MIQU", version=1, height, hash(32), count, then entries
    std::fwrite("MIQU",1,4,f); W32(1);
    W64((uint64_t)height);
    std::fwrite(block_hash.data(),1,block_hash.size(),f);
    W32((uint32_t)undo_vec.size());
    for(const auto& u : undo_vec){
        std::fwrite(u.prev_txid.data(),1,u.prev_txid.size(),f);
        W32(u.prev_vout);
        W64(u.prev_entry.value);
        W64((uint64_t)u.prev_entry.height);
        W8( u.prev_entry.coinbase ? 1 : 0 );
        WVS(u.prev_entry.pkh);
    }
    std::fflush(f);
    miq_fsync(miq_fileno(f));
    std::fclose(f);

    // atomic-ish rename
    std::remove(path.c_str()); // ignore failure
    if(std::rename(tmp.c_str(), path.c_str()) != 0){
        std::remove(tmp.c_str());
        return false;
    }
#ifndef _WIN32
    // fsync parent directory to make the rename durable
    {
        int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
        if (dfd >= 0) { ::fsync(dfd); ::close(dfd); }
    }
#endif
    return true;
}

static bool read_exact(FILE* f, void* buf, size_t n){
    return std::fread(buf, 1, n, f) == n;
}

static bool read_undo_file(const std::string& base_dir,
                           uint64_t height,
                           const std::vector<uint8_t>& block_hash,
                           std::vector<UndoIn>& out)
{
    char name[64];
    std::snprintf(name, sizeof(name), "%08llu_%s.undo",
                  (unsigned long long)height, hexstr(block_hash).c_str());
    std::string path = join_path(undo_dir(base_dir), name);
    FILE* f = std::fopen(path.c_str(), "rb");
    if(!f) return false;

    char magic[4];
    if(!read_exact(f, magic, 4) || std::memcmp(magic,"MIQU",4)!=0){ std::fclose(f); return false; }

    uint32_t ver=0; if(!read_exact(f, &ver, sizeof(ver))) { std::fclose(f); return false; }
    (void)ver;

    uint64_t h=0; if(!read_exact(f, &h, sizeof(h))) { std::fclose(f); return false; }
    (void)h;

    std::vector<uint8_t> hh(32,0);
    if(!read_exact(f, hh.data(), 32)) { std::fclose(f); return false; }

    uint32_t cnt=0; if(!read_exact(f, &cnt, sizeof(cnt))) { std::fclose(f); return false; }

    out.clear(); out.reserve(cnt);

    for(uint32_t i=0;i<cnt;i++){
        UndoIn u;
        u.prev_txid.resize(32);
        if(!read_exact(f, u.prev_txid.data(), 32)) { std::fclose(f); return false; }

        if(!read_exact(f, &u.prev_vout, sizeof(u.prev_vout))) { std::fclose(f); return false; }

        if(!read_exact(f, &u.prev_entry.value, sizeof(u.prev_entry.value))) { std::fclose(f); return false; }
        if(!read_exact(f, &u.prev_entry.height, sizeof(u.prev_entry.height))) { std::fclose(f); return false; }

        uint8_t coinbase_flag=0;
        if(!read_exact(f, &coinbase_flag, 1)) { std::fclose(f); return false; }
        u.prev_entry.coinbase = (coinbase_flag != 0);

        uint8_t n=0;
        if(!read_exact(f, &n, 1)) { std::fclose(f); return false; }
        u.prev_entry.pkh.resize(n);
        if(n){
            if(!read_exact(f, u.prev_entry.pkh.data(), n)) { std::fclose(f); return false; }
        }

        out.push_back(std::move(u));
    }
    std::fclose(f);
    return true;
}

static void remove_undo_file(const std::string& base_dir,
                             uint64_t height,
                             const std::vector<uint8_t>& block_hash)
{
    char name[64];
    std::snprintf(name, sizeof(name), "%08llu_%s.undo",
                  (unsigned long long)height, hexstr(block_hash).c_str());
    std::string path = join_path(undo_dir(base_dir), name);
    std::remove(path.c_str());
}

static inline bool env_truthy(const char* v){ return v && (*v=='1'||*v=='t'||*v=='T'||*v=='y'||*v=='Y'); }

// Limits (override via env if you like)
static const size_t ORPHAN_MAX_BLOCKS = env_szt("MIQ_ORPHAN_MAX_BLOCKS", 1024);        // 1k blocks
static const size_t ORPHAN_MAX_BYTES  = env_szt("MIQ_ORPHAN_MAX_BYTES",  64ull<<20);   // 64 MiB

struct OrphanRec {
    std::vector<uint8_t> raw;     // serialized block
    std::vector<uint8_t> parent;  // prev_hash
    size_t bytes{0};
};

static std::unordered_map<std::string, OrphanRec> g_orphans; // key = hash (binary string)
static std::deque<std::string> g_orphan_order;               // FIFO/LRU-ish
static size_t g_orphan_bytes = 0;

static void orphan_prune_if_needed(){
    while ( (g_orphans.size() > ORPHAN_MAX_BLOCKS) || (g_orphan_bytes > ORPHAN_MAX_BYTES) ){
        if (g_orphan_order.empty()) break;
        auto key = g_orphan_order.front();
        g_orphan_order.pop_front();
        auto it = g_orphans.find(key);
        if (it != g_orphans.end()){
            g_orphan_bytes -= it->second.bytes;
            g_orphans.erase(it);
        }
    }
}

static bool orphan_put(const std::vector<uint8_t>& hash32,
                       const std::vector<uint8_t>& prev32,
                       std::vector<uint8_t>&& raw)
{
    std::string key = hk(hash32);
    if (g_orphans.find(key) != g_orphans.end()) return true; // already cached

    OrphanRec rec;
    rec.bytes  = raw.size();
    rec.raw    = std::move(raw);
    rec.parent = prev32;

    g_orphan_order.push_back(key);
    g_orphan_bytes += rec.bytes;
    g_orphans.emplace(std::move(key), std::move(rec));

    orphan_prune_if_needed();
    return true;
}

static bool orphan_get(const std::vector<uint8_t>& hash32, std::vector<uint8_t>& out_raw){
    auto it = g_orphans.find(hk(hash32));
    if (it == g_orphans.end()) return false;
    out_raw = it->second.raw; // copy out (cheap enough at this size)
    return true;
}

static void orphan_erase(const std::vector<uint8_t>& hash32){
    std::string key = hk(hash32);
    auto it = g_orphans.find(key);
    if (it == g_orphans.end()) return;
    g_orphan_bytes -= it->second.bytes;
    g_orphans.erase(it);
    // note: we leave a stale key in g_orphan_order; harmless for pruning
}

static std::unordered_map<std::string, std::vector<UndoIn>> g_undo;

// keep your other statics (e.g., the reorg manager) here too:

static miq::ReorgManager g_reorg;

// === Local constants (non-breaking) ===
static constexpr size_t MAX_BLOCK_SIZE_LOCAL = 1 * 1024 * 1024; // 1 MiB

// --- Low-S helper (RAW-64 r||s) --------------------------------------------
static inline bool is_low_s64(const std::vector<uint8_t>& sig64){
    if (sig64.size() != 64) return false;
    static const uint8_t N_HALF[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
    };
    const uint8_t* s = sig64.data() + 32;
    for (int i=0;i<32;i++){
        if (s[i] < N_HALF[i]) return true;
        if (s[i] > N_HALF[i]) return false;
    }
    return true; // equal allowed
}

// === compact bits -> big-endian target, and hash <= target check ============
static inline void bits_to_target_be(uint32_t bits, uint8_t out[32]) {
    std::memset(out, 0, 32);
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) { return; } // invalid -> zero target (will fail compare)

    if (exp <= 3) {
        uint32_t mant2 = mant >> (8 * (3 - exp));
        out[29] = uint8_t((mant2 >> 16) & 0xff);
        out[30] = uint8_t((mant2 >> 8)  & 0xff);
        out[31] = uint8_t((mant2 >> 0)  & 0xff);
    } else {
        int pos = int(32) - int(exp);
        if (pos < 0) { out[0] = out[1] = out[2] = 0xff; return; }
        if (pos > 29) pos = 29;
        out[pos + 0] = uint8_t((mant >> 16) & 0xff);
        out[pos + 1] = uint8_t((mant >> 8)  & 0xff);
        out[pos + 2] = uint8_t((mant >> 0)  & 0xff);
    }
}
static inline bool meets_target_be(const std::vector<uint8_t>& hash32, uint32_t bits) {
    if (hash32.size() != 32) return false;
    uint8_t target[32];
    bits_to_target_be(bits, target);
    return std::memcmp(hash32.data(), target, 32) <= 0; // hash <= target
}

// ===========================================================================

long double Chain::work_from_bits(uint32_t bits) {
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) return 0.0L;

    uint32_t bexp  = GENESIS_BITS >> 24;
    uint32_t bmant = GENESIS_BITS & 0x007fffff;

    long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
    long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
    if (target <= 0.0L) return 0.0L;

    long double difficulty = base_target / target;
    if (difficulty < 0.0L) difficulty = 0.0L;
    return difficulty;
}

bool Chain::validate_header(const BlockHeader& h, std::string& err) const {
    // Parent must exist in header index (except genesis)
    if (tip_.height == 0 && tip_.hash == std::vector<uint8_t>(32,0)) {
        // before genesis init
    } else {
        if (!header_exists(h.prev_hash) && h.prev_hash != tip_.hash && !have_block(h.prev_hash)) {
            err = "unknown parent header";
            return false;
        }
    }

    // MTP
    int64_t mtp = tip_.time;
    {
        auto hdrs = last_headers(11);
        if (!hdrs.empty()) {
            std::vector<int64_t> ts; ts.reserve(hdrs.size());
            for (auto& p : hdrs) ts.push_back(p.first);
            std::sort(ts.begin(), ts.end());
            mtp = ts[ts.size()/2];
        }
    }
    if (h.time <= mtp) { err = "header time <= MTP"; return false; }

    // Future bound
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    if (h.time > now + (int64_t)MAX_TIME_SKEW) { err="header time too far in future"; return false; }

    // Bits: LWMA
    {
        auto last = last_headers(90);
        uint32_t expected;
        if (last.size() < 2) expected = last.empty() ? GENESIS_BITS : last.back().second;
        else expected = lwma_next_bits(last, BLOCK_TIME_SECS, GENESIS_BITS);
        if (h.bits != expected) { err = "bad header bits"; return false; }
    }

    // POW
    if (!meets_target_be(header_hash_of(h), h.bits)) { err = "bad header pow"; return false; }

    return true;
}

bool Chain::header_exists(const std::vector<uint8_t>& h) const {
    return header_index_.find(hk(h)) != header_index_.end();
}

std::vector<uint8_t> Chain::best_header_hash() const {
    if (best_header_key_.empty()) return tip_.hash;
    const auto& m = header_index_.at(best_header_key_);
    return m.hash;
}

bool Chain::accept_header(const BlockHeader& h, std::string& err) {
    if (!validate_header(h, err)) return false;

    const auto hh = header_hash_of(h);
    const auto key = hk(hh);
    if (header_index_.find(key) != header_index_.end()) return true;

    HeaderMeta m;
    m.hash   = hh;
    m.prev   = h.prev_hash;
    m.bits   = h.bits;
    m.time   = h.time;
    m.have_block = have_block(m.hash);
    // Height & cumulative work
    uint64_t parent_height = 0;
    long double parent_work = 0.0L;
    auto itp = header_index_.find(hk(h.prev_hash));
    if (itp != header_index_.end()) {
        parent_height = itp->second.height;
        parent_work   = itp->second.work_sum;
    } else if (h.prev_hash == tip_.hash) {
        parent_height = tip_.height;
    }
    m.height   = parent_height + 1;
    m.work_sum = parent_work + work_from_bits(h.bits);

    header_index_.emplace(key, std::move(m));

    if (best_header_key_.empty()) best_header_key_ = key;
    else {
        const auto& cur = header_index_.at(best_header_key_);
        const auto& neu = header_index_.at(key);
        if (neu.work_sum > cur.work_sum || (neu.work_sum == cur.work_sum && neu.height > cur.height)) {
            best_header_key_ = key;
        }
    }
    return true;
}

void Chain::orphan_put(const std::vector<uint8_t>& h, const std::vector<uint8_t>& raw){
    orphan_blocks_[hk(h)] = raw;
}

void Chain::next_block_fetch_targets(std::vector<std::vector<uint8_t>>& out, size_t max) const {
    out.clear();
    if (best_header_key_.empty()) return;

    std::vector<uint8_t> bh = header_index_.at(best_header_key_).hash;
    std::vector<std::vector<uint8_t>> up, down;
    if (!find_header_fork(tip_.hash, bh, up, down)) return;

    for (const auto& hh : down) {
        if (out.size() >= max) break;
        if (!have_block(hh) && orphan_blocks_.find(hk(hh)) == orphan_blocks_.end()) out.push_back(hh);
    }
}

bool Chain::find_header_fork(const std::vector<uint8_t>& a,
                             const std::vector<uint8_t>& b,
                             std::vector<std::vector<uint8_t>>& path_up_from_b,
                             std::vector<std::vector<uint8_t>>& path_down_from_a) const {
    path_up_from_b.clear();
    path_down_from_a.clear();

    auto getH = [&](const std::vector<uint8_t>& h)->std::optional<HeaderMeta>{
        auto it = header_index_.find(hk(h));
        if (it != header_index_.end()) return it->second;
        if (h == tip_.hash) { HeaderMeta t; t.hash=h; t.prev=std::vector<uint8_t>(32,0); t.height=tip_.height; t.work_sum=0; return t; }
        return std::nullopt;
    };

    auto A = getH(a);
    auto B = getH(b);
    if (!B) return false;

    std::vector<uint8_t> x = B->hash;
    std::vector<uint8_t> y = a;

    auto hx = *B;
    auto hy = A ? *A : hx;

    while (A && hx.height > hy.height) {
        path_up_from_b.push_back(x);
        auto it = header_index_.find(hk(hx.prev));
        if (it == header_index_.end()) break;
        hx = it->second;
        x = hx.hash;
    }
    while (A && hy.height > hx.height) {
        path_down_from_a.push_back(y);
        auto it = header_index_.find(hk(hy.prev));
        if (it == header_index_.end()) break;
        hy = it->second;
        y = hy.hash;
    }
    while (x != y) {
        path_up_from_b.push_back(x);
        path_down_from_a.push_back(y);
        auto itx = header_index_.find(hk(hx.prev));
        auto ity = header_index_.find(hk(hy.prev));
        if (itx == header_index_.end() || ity == header_index_.end()) break;
        hx = itx->second; x = hx.hash;
        hy = ity->second; y = hy.hash;
    }
    std::reverse(path_down_from_a.begin(), path_down_from_a.end());
    return true;
}

bool Chain::reconsider_best_chain(std::string& err){
    if (best_header_key_.empty()) return true;
    const auto& best = header_index_.at(best_header_key_);
    if (best.hash == tip_.hash) return true;

    std::vector<std::vector<uint8_t>> up, down;
    if (!find_header_fork(tip_.hash, best.hash, up, down)) return true;

    for (size_t i = 0; i < up.size(); ++i) {
        if (!disconnect_tip_once(err)) return false;
    }

    for (const auto& hh : down) {
        Block blk;
        if (!read_block_any(hh, blk)) {
            err = "reorg missing block body";
            return false;
        }
        if (!submit_block(blk, err)) {
            return false;
        }
    }
    return true;
}

bool Chain::get_hash_by_index(size_t idx, std::vector<uint8_t>& out) const{
    Block b;
    if (!get_block_by_index(idx, b)) return false;
    out = b.block_hash();
    return true;
}

void Chain::build_locator(std::vector<std::vector<uint8_t>>& out) const{
    out.clear();
    if (tip_.time == 0) return;
    uint64_t step = 1;
    uint64_t h = tip_.height;
    while (true){
        std::vector<uint8_t> hh;
        if (!get_hash_by_index((size_t)h, hh)) break;
        out.push_back(std::move(hh));
        if (h == 0) break;
        if (out.size() > 10) step *= 2;
        if (h > step) h -= step;
        else h = 0;
    }
}

bool Chain::get_headers_from_locator(const std::vector<std::vector<uint8_t>>& locators,
                                     size_t max,
                                     std::vector<BlockHeader>& out) const
{
    out.clear();
    std::unordered_map<std::string, int> lset;
    for (const auto& h : locators) lset[hk(h)] = 1;

    uint64_t start_h = 0;
    bool found=false;
    if (tip_.time != 0){
        for (int64_t h=(int64_t)tip_.height; h>=0; --h){
            std::vector<uint8_t> hh;
            if (!get_hash_by_index((size_t)h, hh)) break;
            if (lset.find(hk(hh)) != lset.end()){
                start_h = (uint64_t)h;
                found = true;
                break;
            }
        }
    }
    if (!found) start_h = 0;

    uint64_t h = start_h + 1;
    for (size_t i=0; i<max; ++i){
        if (h > tip_.height) break;
        Block b;
        if (!get_block_by_index((size_t)h, b)) break;
        out.push_back(b.header);
        ++h;
    }
    return !out.empty();
}

bool Chain::read_block_any(const std::vector<uint8_t>& h, Block& out) const{
    std::vector<uint8_t> raw;
    if (storage_.read_block_by_hash(h, raw)) return deser_block(raw, out);
    if (orphan_get(h, raw)) return deser_block(raw, out);
    return false;
}

bool Chain::open(const std::string& dir){
    bool ok = storage_.open(dir) && utxo_.open(dir);
    if(!ok) return false;
    datadir_ = dir;
    ensure_dir_exists(undo_dir(datadir_));
    (void)load_state();
    return true;
}

bool Chain::accept_block_for_reorg(const Block& b, std::string& err){
    auto raw = ser_block(b);
    if (raw.size() > MAX_BLOCK_SIZE_LOCAL) { err = "oversize block"; return false; }
    if (have_block(b.block_hash())) return true;

    if (b.txs.empty()) { err = "no coinbase"; return false; }
    {
        std::unordered_set<std::string> seen;
        std::vector<std::vector<uint8_t>> txids;
        txids.reserve(b.txs.size());
        for (const auto& tx : b.txs) {
            auto id = tx.txid();
            std::string key(reinterpret_cast<const char*>(id.data()), id.size());
            if (!seen.insert(key).second) { err="duplicate txid"; return false; }
            txids.push_back(std::move(id));
        }
        auto mr = merkle_root(txids);
        if (mr != b.header.merkle_root) { err = "bad merkle"; return false; }
    }

    if (!meets_target_be(b.block_hash(), b.header.bits)) { err = "bad pow"; return false; }

    // Explicitly use the file-scope orphan cache (stores parent, used by reorg planner)
    ::miq::orphan_put(b.block_hash(), b.header.prev_hash, std::move(raw));

    miq::HeaderView hv;
    hv.hash   = b.block_hash();
    hv.prev   = b.header.prev_hash;
    hv.bits   = b.header.bits;
    hv.time   = b.header.time;
    hv.height = 0;
    (void)g_reorg.on_validated_header(hv);

    std::vector<miq::HashBytes> to_disconnect, to_connect;
    if (g_reorg.plan_reorg(tip_.hash, to_disconnect, to_connect)) {
        for (size_t i = 0; i < to_disconnect.size(); ++i) {
            if (!disconnect_tip_once(err)) return false;
        }
        for (const auto& h : to_connect) {
            Block blk;
            if (!read_block_any(h, blk)) { err = "reorg missing block body"; return false; }
            if (!submit_block(blk, err)) return false;
            if (have_block(b.block_hash())) { return true; }
            orphan_erase(h);
        }
    }
    return true;
}

bool Chain::save_state(){
    std::vector<uint8_t> b;
    auto P64=[&](uint64_t x){ for(int i=0;i<8;i++) b.push_back((x>>(i*8))&0xff); };
    auto P32=[&](uint32_t x){ for(int i=0;i<4;i++) b.push_back((x>>(i*8))&0xff); };

    b.insert(b.end(), tip_.hash.begin(), tip_.hash.end());
    P64(tip_.height);
    P64((uint64_t)tip_.time);
    P32(tip_.bits);
    P64(tip_.issued);

    return storage_.write_state(b);
}

bool Chain::load_state(){
    std::vector<uint8_t> b;

    if(!storage_.read_state(b)){
        tip_.hash = std::vector<uint8_t>(32, 0);
        tip_.height = 0;
        tip_.time = 0;
        tip_.bits = 0;
        tip_.issued = 0;
        return true;
    }

    if(b.size() < 32 + 8 + 8 + 4 + 8){
        tip_.hash = std::vector<uint8_t>(32, 0);
        tip_.height = 0;
        tip_.time = 0;
        tip_.bits = 0;
        tip_.issued = 0;
        return true;
    }

    size_t i = 0;
    tip_.hash.assign(b.begin() + i, b.begin() + i + 32); i += 32;

    tip_.height = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.height |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    tip_.time = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.time |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    tip_.bits = b[i] | (b[i+1] << 8) | (b[i+2] << 16) | (b[i+3] << 24);
    i += 4;

    tip_.issued = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.issued |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    return true;
}

uint64_t Chain::subsidy_for_height(uint64_t h) const {
    uint64_t halv = h / HALVING_INTERVAL;
    if(halv >= 64) return 0;
    return INITIAL_SUBSIDY >> halv;
}

bool Chain::init_genesis(const Block& g){
    if(tip_.hash != std::vector<uint8_t>(32,0)) return true;
    g_reorg.init_genesis(tip_.hash, tip_.bits, tip_.time);

    std::vector<std::vector<uint8_t>> txids;
    for(const auto& tx : g.txs) txids.push_back(tx.txid());
    auto mr = merkle_root(txids);
    if(mr != g.header.merkle_root) return false;

    storage_.append_block(ser_block(g), g.block_hash());

    const auto& cb = g.txs[0];
    uint64_t cb_sum = 0;
    for(size_t i=0;i<cb.vout.size();++i){
        UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, 0, true};
        utxo_.add(cb.txid(), (uint32_t)i, e);
        cb_sum += cb.vout[i].value;
    }

    tip_ = Tip{0, g.block_hash(), g.header.bits, g.header.time, cb_sum};
    index_.reset(tip_.hash, tip_.time, tip_.bits);
    save_state();
    return true;
}

bool Chain::verify_block(const Block& b, std::string& err) const{
    if(b.header.prev_hash != tip_.hash){ err="bad prev hash"; return false; }

    // MTP
    auto hdrs = last_headers(11);
    int64_t mtp = tip_.time;
    if (!hdrs.empty()) {
        std::vector<int64_t> ts; ts.reserve(hdrs.size());
        for (auto& p : hdrs) ts.push_back(p.first);
        std::sort(ts.begin(), ts.end());
        mtp = ts[ts.size()/2];
    }
    if (b.header.time <= mtp) { err = "time <= MTP"; return false; }

    // Future bound
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (b.header.time > now + (int64_t)MAX_TIME_SKEW) { err="time too far in future"; return false; }
    }

    // Merkle + duplicate guard
    if (b.txs.empty()){ err="no coinbase"; return false; }
    {
        std::unordered_set<std::string> seen;
        std::vector<std::vector<uint8_t>> txids;
        txids.reserve(b.txs.size());
        for (const auto& tx : b.txs) {
            auto id = tx.txid();
            std::string key(reinterpret_cast<const char*>(id.data()), id.size());
            if (!seen.insert(key).second) { err="duplicate txid"; return false; }
            txids.push_back(std::move(id));
        }
        auto mr = merkle_root(txids);
        if(mr != b.header.merkle_root){ err="bad merkle"; return false; }
    }

    // Coinbase shape
    const auto& cb = b.txs[0];
    if (cb.vin.size()!=1 || !cb.vin[0].sig.empty() || !cb.vin[0].pubkey.empty()) { err="bad coinbase"; return false; }
    if (cb.vin[0].prev.txid.size()!=32) { err="bad coinbase prev size"; return false; }
    if (std::any_of(cb.vin[0].prev.txid.begin(), cb.vin[0].prev.txid.end(), [](uint8_t v){ return v!=0; })) { err="bad coinbase prev"; return false; }
    if (cb.vin[0].prev.vout != 0) { err="bad coinbase vout"; return false; }

    // Non-coinbase tx checks
    for (size_t ti=1; ti<b.txs.size(); ++ti) {
        const auto& tx = b.txs[ti];
        if (tx.vin.empty() || tx.vout.empty()) { err="empty tx"; return false; }
        if (tx.vin.size()==1 && tx.vin[0].prev.vout==0 &&
            tx.vin[0].prev.txid.size()==32 &&
            std::all_of(tx.vin[0].prev.txid.begin(), tx.vin[0].prev.txid.end(), [](uint8_t v){return v==0;})) {
            err="multiple coinbase"; return false;
        }
        auto raw = ser_tx(tx);
        if (raw.size() > MIQ_FALLBACK_MAX_TX_SIZE) { err="tx too large"; return false; }
    }

    // Difficulty bits must match LWMA
    {
        auto last = last_headers(90);
        uint32_t expected;
        if (last.size() < 2) expected = last.empty() ? GENESIS_BITS : last.back().second;
        else expected = lwma_next_bits(last, BLOCK_TIME_SECS, GENESIS_BITS);
        if (b.header.bits != expected) { err = "bad bits"; return false; }
    }

    // POW
    if (!meets_target_be(b.block_hash(), b.header.bits)) { err = "bad pow"; return false; }

    // Block raw size cap
    if (ser_block(b).size() > MAX_BLOCK_SIZE_LOCAL) { err = "oversize block"; return false; }

    // ---- Safe math helpers ----
    auto add_u64_safe = [](uint64_t a, uint64_t b, uint64_t& out)->bool { out = a + b; return out >= a; };
    auto leq_max_money = [](uint64_t v)->bool { return v <= (uint64_t)MAX_MONEY; };

    struct Key { std::vector<uint8_t> txid; uint32_t vout; };
    struct KH { size_t operator()(Key const& k) const noexcept {
        size_t h = k.vout * 1315423911u;
        if(!k.txid.empty()){ h ^= (size_t)k.txid.front() * 2654435761u; h ^= (size_t)k.txid.back() * 2246822519u; }
        return h;
    }};
    struct KE { bool operator()(Key const& a, Key const& b) const noexcept { return a.vout==b.vout && a.txid==b.txid; } };
    std::unordered_set<Key, KH, KE> spent_in_block;

    auto sigh=[&](const Transaction& t){ Transaction tmp=t; for(auto& i: tmp.vin) i.sig.clear(); return dsha256(ser_tx(tmp)); };

    uint64_t fees = 0, tmp = 0;
    for(size_t ti=1; ti<b.txs.size(); ++ti){
        const auto& tx=b.txs[ti];
        uint64_t in=0, out=0;

        for (const auto& o : tx.vout) {
            if (!leq_max_money(o.value)) { err="txout>MAX_MONEY"; return false; }
            if (!add_u64_safe(out, o.value, tmp)) { err="tx out overflow"; return false; }
            out = tmp;
        }
        if (!leq_max_money(out)) { err="sum(out)>MAX_MONEY"; return false; }

        auto hash = sigh(tx);

        for(const auto& inx: tx.vin){
            if (inx.pubkey.size() != 33 && inx.pubkey.size() != 65) { err="bad pubkey size"; return false; }

            Key k{inx.prev.txid, inx.prev.vout};
            if (spent_in_block.find(k) != spent_in_block.end()){ err="in-block double-spend"; return false; }
            spent_in_block.insert(k);

            UTXOEntry e;
            if(!utxo_.get(inx.prev.txid, inx.prev.vout, e)){ err="missing utxo"; return false; }
            if(e.coinbase && tip_.height+1 < e.height + COINBASE_MATURITY){ err="immature coinbase"; return false; }
            if(hash160(inx.pubkey)!=e.pkh){ err="pkh mismatch"; return false; }
            if(!crypto::ECDSA::verify(inx.pubkey, hash, inx.sig)){ err="bad signature"; return false; }
        #if MIQ_RULE_ENFORCE_LOW_S
            // Consensus: reject non-low-S signatures in blocks
            if (!is_low_s64(inx.sig)) { err="high-S signature"; return false; }
        #endif

            if (!leq_max_money(e.value)) { err="utxo>MAX_MONEY"; return false; }
            if (!add_u64_safe(in, e.value, tmp)) { err="tx in overflow"; return false; }
            in = tmp;
        }
        if (!leq_max_money(in)) { err="sum(in)>MAX_MONEY"; return false; }

        if(out > in){ err="outputs>inputs"; return false; }
        uint64_t fee = in - out;
        if (!leq_max_money(fee)) { err="fee>MAX_MONEY"; return false; }
        if (!add_u64_safe(fees, fee, tmp)) { err="fees overflow"; return false; }
        fees = tmp;
    }

    // Coinbase payout checks
    uint64_t sub = subsidy_for_height(tip_.height+1);
    uint64_t cb_sum = 0, tmp2 = 0;
    for(const auto& o:cb.vout){
        if (!leq_max_money(o.value)) { err="coinbase out>MAX_MONEY"; return false; }
        if (!add_u64_safe(cb_sum, o.value, tmp2)) { err="coinbase overflow"; return false; }
        cb_sum = tmp2;
    }
    if(cb_sum > sub + fees){ err="coinbase too high"; return false; }
    if(!leq_max_money(cb_sum)){ err="coinbase>MAX_MONEY"; return false; }

    // *** NEW: Hard MAX_SUPPLY enforcement (subsidy-only against remaining supply) ***
    {
        uint64_t coinbase_without_fees = (cb_sum > fees) ? (cb_sum - fees) : 0;
        if (WouldExceedMaxSupply((uint32_t)(tip_.height + 1), coinbase_without_fees)) {
            err = "exceeds max supply";
            return false;
        }
    }

    if(tip_.issued > (uint64_t)MAX_MONEY - cb_sum){ err="exceeds cap"; return false; }

    return true;
}

// ---------- UTXO atomic-apply helper (uses batch if available) ----------
struct UtxoOp {
    bool is_add{false};
    std::vector<uint8_t> txid;
    uint32_t vout{0};
    UTXOEntry entry; // valid only when is_add=true
};

template<typename DB>
static auto has_make_batch_impl(int) -> decltype(std::declval<DB&>().make_batch(), std::true_type{});
template<typename DB>
static auto has_make_batch_impl(...) -> std::false_type;
template<typename DB>
static constexpr bool has_make_batch_v = decltype(has_make_batch_impl<DB>(0))::value;

template<typename DB>
static bool utxo_apply_ops(DB& db, const std::vector<UtxoOp>& ops, std::string& err) {
    if constexpr (has_make_batch_v<DB>) {
        auto batch = db.make_batch();
        for (const auto& op : ops) {
            if (op.is_add) batch.add(op.txid, op.vout, op.entry);
            else           batch.spend(op.txid, op.vout);
        }
        std::string kv_err;
        if (!batch.commit(/*sync=*/true, &kv_err)) {
            err = kv_err.empty() ? "utxo batch commit failed" : kv_err;
            return false;
        }
        return true;
    } else {
        // Fallback: immediate fsynced writes (existing behavior)
        for (const auto& op : ops) {
            if (op.is_add) {
                if (!db.add(op.txid, op.vout, op.entry)) {
                    err = "utxo add failed";
                    return false;
                }
            } else {
                if (!db.spend(op.txid, op.vout)) {
                    err = "utxo spend failed";
                    return false;
                }
            }
        }
        return true;
    }
}
// -----------------------------------------------------------------------

bool Chain::disconnect_tip_once(std::string& err){
    if (tip_.height == 0) { err = "cannot disconnect genesis"; return false; }

    Block cur;
    if (!get_block_by_hash(tip_.hash, cur)) {
        err = "failed to read tip block";
        return false;
    }

    std::vector<UndoIn> undo_tmp;
    auto it_ram = g_undo.find(hk(tip_.hash));
    if (it_ram != g_undo.end()) {
        undo_tmp = it_ram->second;
    } else {
        if (!read_undo_file(datadir_, tip_.height, tip_.hash, undo_tmp)) {
            err = "no undo data for tip (restart or missing undo)";
            return false;
        }
    }
    const std::vector<UndoIn>& undo = undo_tmp;

    // Build UTXO reversal ops
    std::vector<UtxoOp> ops;
    ops.reserve(64);

    // Spend non-coinbase created outs
    for (size_t ti = cur.txs.size(); ti-- > 1; ){
        const auto& tx = cur.txs[ti];
        for (size_t i = 0; i < tx.vout.size(); ++i) {
            ops.push_back(UtxoOp{false, tx.txid(), (uint32_t)i, {}});
        }
    }

    // Restore previous inputs from undo (reverse order)
    for (size_t i = undo.size(); i-- > 0; ){
        const auto& u = undo[i];
        ops.push_back(UtxoOp{true, u.prev_txid, u.prev_vout, u.prev_entry});
    }

    // Remove coinbase outs and compute sum
    const auto& cb = cur.txs[0];
    uint64_t cb_sum = 0;
    for (size_t i = 0; i < cb.vout.size(); ++i) {
        ops.push_back(UtxoOp{false, cb.txid(), (uint32_t)i, {}});
        cb_sum += cb.vout[i].value;
    }
    if (tip_.issued < cb_sum) { err = "issued underflow"; return false; }

    // Commit reversals atomically if backend supports it
    if (!utxo_apply_ops(utxo_, ops, err)) return false;

    Block prev;
    if (!get_block_by_hash(cur.header.prev_hash, prev)) {
        err = "failed to read prev block";
        return false;
    }

    tip_.height -= 1;
    tip_.hash   = cur.header.prev_hash;
    tip_.bits   = prev.header.bits;
    tip_.time   = prev.header.time;
    tip_.issued -= cb_sum;

    if (it_ram != g_undo.end()) g_undo.erase(it_ram);
    remove_undo_file(datadir_, (uint64_t)(tip_.height + 1), cur.block_hash());

    save_state();
    return true;
}

bool Chain::submit_block(const Block& b, std::string& err){
    if (!verify_block(b, err)) return false;

    if (have_block(b.block_hash())) return true;

    // NOTE: additional MTP/future-time checks were already done in verify_block().

    // --- Collect undo BEFORE mutating UTXO ---
    std::vector<UndoIn> undo;
    undo.reserve(b.txs.size() * 2);

    for (size_t ti = 1; ti < b.txs.size(); ++ti){
        const auto& tx = b.txs[ti];
        for (const auto& in : tx.vin){
            UTXOEntry e;
            if (!utxo_.get(in.prev.txid, in.prev.vout, e)){
                err = "missing utxo during undo-capture";
                return false;
            }
            undo.push_back(UndoIn{in.prev.txid, in.prev.vout, e});
        }
    }

    // Persist the block body (unchanged order wrt previous code)
    storage_.append_block(ser_block(b), b.block_hash());

    // --- NEW ORDERING FOR CRASH-SAFETY ---
    // Write & fsync the undo file for (height+1, block_hash) BEFORE mutating UTXO.
    const uint64_t new_height = tip_.height + 1;
    const auto     new_hash   = b.block_hash();
    if (!write_undo_file(datadir_, new_height, new_hash, undo)) {
        err = "failed to write undo";
        return false;
    }

    // Build UTXO apply ops
    std::vector<UtxoOp> ops;
    ops.reserve(64);

    for (size_t ti = 1; ti < b.txs.size(); ++ti){
        const auto& tx = b.txs[ti];

        // spends
        for (const auto& in : tx.vin){
            ops.push_back(UtxoOp{false, in.prev.txid, in.prev.vout, {}});
        }
        // adds
        for (size_t i = 0; i < tx.vout.size(); ++i){
            UTXOEntry e{tx.vout[i].value, tx.vout[i].pkh, new_height, false};
            ops.push_back(UtxoOp{true, tx.txid(), (uint32_t)i, e});
        }
    }

    // coinbase adds + sum
    const auto& cb = b.txs[0];
    uint64_t cb_sum = 0;
    for (size_t i = 0; i < cb.vout.size(); ++i){
        UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, new_height, true};
        ops.push_back(UtxoOp{true, cb.txid(), (uint32_t)i, e});
        cb_sum += cb.vout[i].value;
    }

    // Apply all UTXO changes (atomically if supported)
    if (!utxo_apply_ops(utxo_, ops, err)) return false;

    // Advance tip
    tip_.height = new_height;
    tip_.hash   = new_hash;
    tip_.bits   = b.header.bits;
    tip_.time   = b.header.time;
    tip_.issued += cb_sum;

    // Cache undo in RAM map (unchanged behavior)
    g_undo[hk(tip_.hash)] = std::move(undo);

    // Prune old undo if beyond window
    if (tip_.height >= UNDO_WINDOW) {
        size_t prune_h = (size_t)(tip_.height - UNDO_WINDOW);
        std::vector<uint8_t> prune_hash;
        if (get_hash_by_index(prune_h, prune_hash)) {
            remove_undo_file(datadir_, prune_h, prune_hash);
        }
    }

    // Notify reorg manager
    miq::HeaderView hv;
    hv.hash   = tip_.hash;
    hv.prev   = b.header.prev_hash;
    hv.bits   = b.header.bits;
    hv.time   = b.header.time;
    hv.height = (uint32_t)tip_.height;
    g_reorg.on_validated_header(hv);

    save_state();
    return true;
}

std::vector<std::pair<int64_t,uint32_t>> Chain::last_headers(size_t n) const{
    std::vector<std::pair<int64_t,uint32_t>> v;
    if (tip_.time == 0) return v;

    size_t start = 0;
    if (tip_.height + 1 > n) start = (size_t)(tip_.height + 1 - n);

    for (size_t idx = start; idx <= (size_t)tip_.height; ++idx) {
        Block b;
        if (!get_block_by_index(idx, b)) break;
        v.emplace_back(b.header.time, b.header.bits);
    }
    return v;
}

bool Chain::get_block_by_index(size_t idx, Block& out) const{
    std::vector<uint8_t> raw;
    if(!storage_.read_block_by_index(idx, raw)) return false;
    return deser_block(raw, out);
}

bool Chain::get_block_by_hash(const std::vector<uint8_t>& h, Block& out) const{
    std::vector<uint8_t> raw;
    if(!storage_.read_block_by_hash(h, raw)) return false;
    return deser_block(raw, out);
}

bool Chain::have_block(const std::vector<uint8_t>& h) const{
    std::vector<uint8_t> raw;
    return storage_.read_block_by_hash(h, raw);
}

long double Chain::work_from_bits_public(uint32_t bits) {
    return work_from_bits(bits);
}

}
