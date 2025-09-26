#include "serialize.h"

#include "mempool.h"
#include "util.h"
#include "sha256.h"
#include "crypto/ecdsa_iface.h"
#include "hash160.h"
#include <unordered_set>
#include <algorithm>
#include <vector>
#include <string>

// OPTIONAL include of constants (for MAX_TX_SIZE, COINBASE_MATURITY). If not present, we use safe fallbacks.
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

#ifndef COINBASE_MATURITY
#define COINBASE_MATURITY 100
#endif

namespace miq {

static std::vector<uint8_t> sighash_simple(const Transaction& tx){
    // Simple SIGHASH: hash of serialized tx without signatures
    Transaction t=tx; for(auto& in: t.vin){ in.sig.clear(); }
    return dsha256(ser_tx(t));
}

std::string Mempool::key(const std::vector<uint8_t>& txid) const { return hex(txid); }

void Mempool::maybe_evict(){
    if(map_.size()<=max_) return;
    std::vector<std::pair<std::string,double>> v; v.reserve(map_.size());
    for(const auto& kv: map_) v.push_back({kv.first, kv.second.feerate});
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second<b.second;});
    size_t rm=map_.size()-max_;
    for(size_t i=0;i<rm;i++) map_.erase(v[i].first);
}

bool Mempool::accept(const Transaction& tx, const UTXOSet& utxo, uint64_t height, std::string& err){
    if (tx.vin.empty() || tx.vout.empty()) { err = "empty vin/vout"; return false; }

    // Size cap (DoS)
    const auto raw = ser_tx(tx);
    const size_t raw_sz = raw.size();
    if (raw_sz > MIQ_FALLBACK_MAX_TX_SIZE) { err = "tx too large"; return false; }

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

    // Low-S threshold (secp256k1 order/2) for canonical signatures
    static const uint8_t SECP256K1_N_HALF[32] = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0xE7,0x57,0x12,0xA2,0x4F,
        0x56,0x28,0x14,0x81,0x68,0xB9,0xC5,0x8D
    };

    for (const auto& i : tx.vin) {
        const std::string k = key(i.prev.txid) + ":" + std::to_string(i.prev.vout);
        if (ins.count(k)) { err = "dup input"; return false; }
        ins.insert(k);

        UTXOEntry e;
        if (!utxo.get(i.prev.txid, i.prev.vout, e)) { err = "missing utxo"; return false; }
        if (e.coinbase && height < e.height + COINBASE_MATURITY) { err = "immature"; return false; }

        // Pubkey must match output hash160
        if (hash160(i.pubkey) != e.pkh) { err = "pkh mismatch"; return false; }

        // Pubkey must be compressed (33 bytes, 0x02 or 0x03)
        if (i.pubkey.size() != 33 || (i.pubkey[0] != 0x02 && i.pubkey[0] != 0x03)) {
            err = "bad pubkey"; return false;
        }

        // Signature must be 64 bytes (r||s)
        if (i.sig.size() != 64) { err = "bad siglen"; return false; }

        // Optional: low-S check (canonical s <= n/2). s is last 32 bytes (big-endian)
        bool s_is_high = false;
        const uint8_t* s_ptr = i.sig.data() + 32;
        for (int j = 0; j < 32; ++j) {
            if (s_ptr[j] > SECP256K1_N_HALF[j]) { s_is_high = true; break; }
            if (s_ptr[j] < SECP256K1_N_HALF[j]) { break; }
        }
        if (s_is_high) { err = "non-canonical-S"; return false; }

        // Backend verification
        if (!crypto::ECDSA::verify(i.pubkey, h, i.sig)) { err = "bad signature"; return false; }

        if (!leq_max_money(e.value)) { err = "utxo>MAX_MONEY"; return false; }
        if (!add_u64_safe(in, e.value, tmp)) { err = "tx in overflow"; return false; }
        in = tmp;
    }

    for (const auto& o : tx.vout) {
        if (!leq_max_money(o.value)) { err = "txout>MAX_MONEY"; return false; }
        if (!add_u64_safe(out, o.value, tmp)) { err = "tx out overflow"; return false; }
        out = tmp;
    }

    if (!leq_max_money(in) || !leq_max_money(out)) { err = "sum>MAX_MONEY"; return false; }
    if (out > in) { err = "outputs>inputs"; return false; }

    // Fee policy (unchanged)
    const size_t sz = tx.vin.size()*180 + tx.vout.size()*34 + 10;
    const uint64_t minfee = (sz/100) + 1;
    const uint64_t fee = in - out;
    if (fee < minfee) { err = "low fee"; return false; }

    const double fr = (double)fee / (double)sz;
    map_[txk] = MempoolEntry{tx, fee, sz, fr};
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

} // namespace miq
