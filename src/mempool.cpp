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

// OPTIONAL include of constants (for MAX_TX_SIZE). If not present, we use a safe fallback.
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
    if(tx.vin.empty()||tx.vout.empty()){ err="empty vin/vout"; return false; }

    // === ADDED: raw size cap to prevent oversized tx DoS ===
    const auto raw = ser_tx(tx);
    const size_t raw_sz = raw.size();
    if (raw_sz > MIQ_FALLBACK_MAX_TX_SIZE) { err="tx too large"; return false; }

    // === ADDED: reject duplicate txid already in mempool ===
    const std::string txk = key(tx.txid());
    if (map_.count(txk)) { err="duplicate"; return false; }

    // === ADDED: reject conflicts with existing mempool spends (double-spend within mempool) ===
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

    std::unordered_set<std::string> ins; uint64_t in=0,out=0;
    auto h = sighash_simple(tx);
    for(const auto& i: tx.vin){
        std::string k=key(i.prev.txid)+":"+std::to_string(i.prev.vout);
        if(ins.count(k)){ err="dup input"; return false; } ins.insert(k);
        UTXOEntry e; if(!utxo.get(i.prev.txid, i.prev.vout, e)){ err="missing utxo"; return false; }
        if(e.coinbase && height < e.height + COINBASE_MATURITY){ err="immature"; return false; }
        // Verify P2PKH: HASH160(pubkey) == pkh and ECDSA verify(sig, pubkey, sighash)
        if(hash160(i.pubkey) != e.pkh){ err="pkh mismatch"; return false; }
        if(!crypto::ECDSA::verify(i.pubkey, h, i.sig)){ err="bad signature"; return false; }
        in+=e.value;
    }
    for(const auto& o: tx.vout) out+=o.value;
    if(out>in){ err="outputs>inputs"; return false; }

    // Keep your existing fee/minfee logic and size estimate
    size_t sz = tx.vin.size()*180 + tx.vout.size()*34 + 10;
    uint64_t minfee=(sz/100)+1;
    uint64_t fee=in-out;
    if(fee<minfee){ err="low fee"; return false; }

    double fr=(double)fee/(double)sz;
    map_[txk]=MempoolEntry{tx,fee,sz,fr};
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

