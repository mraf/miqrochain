// src/mempool.cpp
#include "serialize.h"

#include "mempool.h"
#include "util.h"
#include "sig_encoding.h"     // still used for other helpers elsewhere
#include "sha256.h"
#include "crypto/ecdsa_iface.h"
#include "hash160.h"
#include <unordered_set>
#include <algorithm>
#include <vector>
#include <string>
#include <cstdint>
#include <cstdlib>   // getenv, strtoull

// OPTIONAL include of constants (for MAX_TX_SIZE or toggles).
#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifndef MAX_TX_SIZE
#define MIQ_FALLBACK_MAX_TX_SIZE (100u * 1024u) // 100 KiB fallback
#else
#define MIQ_FALLBACK_MAX_TX_SIZE (MAX_TX_SIZE)
#endif

// Default: ENFORCE Low-S & canonical RAW-64 in mempool (policy)
#ifndef MIQ_RULE_ENFORCE_LOW_S
#define MIQ_RULE_ENFORCE_LOW_S 1
#endif

namespace miq {

// =================== env helpers (policy, non-consensus) =====================

static inline uint64_t env_u64(const char* name, uint64_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr;
    unsigned long long x = std::strtoull(v, &end, 10);
    if(end==v) return defv;
    return (uint64_t)x;
}
static inline size_t env_szt(const char* name, size_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; unsigned long long x = std::strtoull(v, &end, 10);
    if(end==v) return defv;
    return (size_t)x;
}

// =================== secp256k1 order constants ===============================

static inline const uint8_t* SECP256K1_N_BE(){
    // n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    static const uint8_t N[32] = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    };
    return N;
}
static inline const uint8_t* SECP256K1_N_HALF_BE(){
    // n/2 = 7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
    static const uint8_t H[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
        0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
    };
    return H;
}

// =================== Canonical RAW-64 (r||s) + Low-S =========================

// Big-endian compare (32B)
static inline int be_cmp32(const uint8_t* a, const uint8_t* b){
    for(int i=0;i<32;i++){
        if(a[i] < b[i]) return -1;
        if(a[i] > b[i]) return 1;
    }
    return 0;
}

static inline bool be_is_zero32(const uint8_t* a){
    for(int i=0;i<32;i++) if(a[i]!=0) return false;
    return true;
}

// Check r in [1, n-1], s in [1, n/2] (Low-S) for RAW-64 signature
static inline bool is_canonical_raw64_lows(const std::vector<uint8_t>& sig64){
    if (sig64.size() != 64) return false;
    const uint8_t* r = sig64.data();
    const uint8_t* s = sig64.data() + 32;

    // r != 0 and r < n
    if (be_is_zero32(r)) return false;
    if (be_cmp32(r, SECP256K1_N_BE()) >= 0) return false;

    // s != 0 and s <= n/2  (low-S)
    if (be_is_zero32(s)) return false;
    if (be_cmp32(s, SECP256K1_N_HALF_BE()) > 0) return false;

    return true;
}

// =================== Sighash for verify =====================================

static std::vector<uint8_t> sighash_simple(const Transaction& tx){
    // Simple SIGHASH: hash of serialized tx without signatures
    Transaction t=tx; for(auto& in: t.vin){ in.sig.clear(); }
    return dsha256(ser_tx(t));
}

// =================== Mempool impl ===========================================

std::string Mempool::key(const std::vector<uint8_t>& txid) const { return hex(txid); }

void Mempool::maybe_evict(){
    if(map_.size()<=max_) return;
    std::vector<std::pair<std::string,double>> v; v.reserve(map_.size());
    for(const auto& kv: map_) v.push_back({kv.first, kv.second.feerate});
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second<b.second;});
    size_t rm=map_.size()-max_;
    for(size_t i=0;i<rm;i++) map_.erase(v[i].first);
}

// NOTE: height type is size_t to match callers (avoids ABI mismatch)
bool Mempool::accept(const Transaction& tx, const UTXOSet& utxo, size_t height, std::string& err){
    if (tx.vin.empty() || tx.vout.empty()) { err = "empty vin/vout"; return false; }

    // Policy knobs (env-overridable)
    const uint64_t DUST_SAT           = env_u64("MIQ_DUST_SAT", 546ULL);               // default ~BTC P2PKH dust
    const uint64_t MIN_RELAY_PER_KB   = env_u64("MIQ_MIN_RELAY_PER_KB", 1000ULL);      // 1000 sat/kB == 1 sat/vB
    const size_t   MAX_VIN_POLICY     = env_szt("MIQ_MEMPOOL_MAX_VIN",  256);
    const size_t   MAX_VOUT_POLICY    = env_szt("MIQ_MEMPOOL_MAX_VOUT", 128);

    // Size cap (DoS)
    const auto raw = ser_tx(tx);
    const size_t raw_sz = raw.size();
    if (raw_sz > MIQ_FALLBACK_MAX_TX_SIZE) { err = "tx too large"; return false; }

    // Simple structural caps (policy)
    if (tx.vin.size()  > MAX_VIN_POLICY)  { err = "too many inputs";  return false; }
    if (tx.vout.size() > MAX_VOUT_POLICY) { err = "too many outputs"; return false; }

    // No duplicate txid in mempool
    const std::string txk = key(tx.txid());
    if (map_.count(txk)) { err = "duplicate"; return false; }

    // Reject conflicts against already-seen spends in mempool
    for (const auto& kv : map_) {
        const auto& other = kv.second.tx;
        for (const auto& i1 : tx.vin) {
            for (const auto& i2 : other.vin) {
                if (i1.prev.vout == i2.prev.vout && i1.prev.txid == i2.prev.txid) {
                    err = "conflict"; return false;
                }
            }
        }
    }

    // ---- Safe math helpers ----
    auto add_u64_safe = [](uint64_t a, uint64_t b, uint64_t& out)->bool { out = a + b; return out >= a; };

#ifndef MAX_MONEY
#  define MIQ_FALLBACK_MAX_MONEY (26280000ull * 100000000ull) // 26,280,000 * COIN
#  define MIQ__USE_FALLBACK_MAX_MONEY
#endif
    auto leq_max_money = [](uint64_t v)->bool {
    #ifdef MIQ__USE_FALLBACK_MAX_MONEY
        return v <= MIQ_FALLBACK_MAX_MONEY;
    #else
        return v <= (uint64_t)MAX_MONEY;
    #endif
    };

    // Dedup inputs within this tx; compute in/out with overflow checks
    std::unordered_set<std::string> ins;
    uint64_t in = 0, out = 0, tmp = 0;

    const auto h = sighash_simple(tx);

    for (const auto& i : tx.vin) {
        // Strict pubkey length (compressed 33B or uncompressed 65B)
        if (i.pubkey.size() != 33 && i.pubkey.size() != 65) { err = "bad pubkey size"; return false; }

        const std::string k = key(i.prev.txid) + ":" + std::to_string(i.prev.vout);
        if (ins.count(k)) { err = "dup input"; return false; }
        ins.insert(k);

        UTXOEntry e;
        if (!utxo.get(i.prev.txid, i.prev.vout, e)) { err = "missing utxo"; return false; }
        if (e.coinbase && height < e.height + COINBASE_MATURITY) { err = "immature"; return false; }
        if (hash160(i.pubkey) != e.pkh) { err = "pkh mismatch"; return false; }

        // Signature verification against simple sighash
        if (i.sig.size() != 64) { err = "bad sig size"; return false; }
        if (!crypto::ECDSA::verify(i.pubkey, h, i.sig)) { err = "bad signature"; return false; }

    #if MIQ_RULE_ENFORCE_LOW_S
        // Enforce canonical RAW-64 (r||s) + Low-S in mempool (policy)
        if (!is_canonical_raw64_lows(i.sig)) { err = "non-canonical or high-S signature"; return false; }
    #endif

        if (!leq_max_money(e.value)) { err = "utxo>MAX_MONEY"; return false; }
        if (!add_u64_safe(in, e.value, tmp)) { err = "tx in overflow"; return false; }
        in = tmp;
    }

    for (const auto& o : tx.vout) {
        if (!leq_max_money(o.value)) { err = "txout>MAX_MONEY"; return false; }
        if (o.value < DUST_SAT)      { err = "dust output";     return false; }
        if (!add_u64_safe(out, o.value, tmp)) { err = "tx out overflow"; return false; }
        out = tmp;
    }

    if (!leq_max_money(in) || !leq_max_money(out)) { err = "sum>MAX_MONEY"; return false; }
    if (out > in) { err = "outputs>inputs"; return false; }

    // ---- Fee policy (non-consensus; env-tunable) ----------------------------
    // Old heuristic (kept for compatibility): ~1 sat/byte using rough estimator.
    const size_t est_sz = tx.vin.size()*180 + tx.vout.size()*34 + 10;
    const uint64_t legacy_minfee = (est_sz/100) + 1; // (~1 sat/100B + 1)

    // New policy: sat/kilobyte floor on *actual serialized size*.
    // MIN_RELAY_PER_KB=1000 ⇒ 1 sat/vB.
    uint64_t kb = (uint64_t)((raw_sz + 999) / 1000);
    if (kb == 0) kb = 1;
    const uint64_t env_minfee = MIN_RELAY_PER_KB * kb;

    const uint64_t minfee = std::max(legacy_minfee, env_minfee);
    const uint64_t fee    = in - out;

    if (fee < minfee) { err = "low fee"; return false; }

    const double fr = (double)fee / (double)raw_sz; // feerate by real size
    map_[txk] = MempoolEntry{tx, fee, raw_sz, fr};
    maybe_evict();
    return true;
}

std::vector<Transaction> Mempool::collect(size_t n) const{
    std::vector<std::pair<double,const Transaction*>> v;
    for(const auto& kv: map_) v.push_back({kv.second.feerate,&kv.second.tx});
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.first>b.first;});
    std::vector<Transaction> out;
    for(const auto& p:v){ out.push_back(*p.second); if(out.size()>=n) break; }
    return out;
}

std::vector<std::vector<uint8_t>> Mempool::txids() const{
    std::vector<std::vector<uint8_t>> v;
    for(const auto& kv: map_) v.push_back(kv.second.tx.txid());
    return v;
}

}
