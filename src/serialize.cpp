#include "serialize.h"
#include <cstring>
#include <stdexcept>

namespace miq {
// (implementation continues below - exact as in v1.7.5)
static inline void put_u32(std::vector<uint8_t>& v, uint32_t x){ for(int i=0;i<4;i++) v.push_back(uint8_t((x>>(i*8))&0xff)); }
static inline void put_u64(std::vector<uint8_t>& v, uint64_t x){ for(int i=0;i<8;i++) v.push_back(uint8_t((x>>(i*8))&0xff)); }
static inline uint32_t get_u32(const std::vector<uint8_t>& v, size_t i){ return uint32_t(v[i] | (v[i+1]<<8) | (v[i+2]<<16) | (v[i+3]<<24)); }
static inline uint64_t get_u64(const std::vector<uint8_t>& v, size_t i){ uint64_t x=0; for(int k=0;k<8;k++) x |= (uint64_t)v[i+k] << (k*8); return x; }

static inline void put_bytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b){ v.insert(v.end(), b.begin(), b.end()); }
static inline void put_var(std::vector<uint8_t>& v, const std::vector<uint8_t>& b){ put_u32(v, (uint32_t)b.size()); put_bytes(v, b); }

static inline bool get_var(const std::vector<uint8_t>& v, size_t& i, std::vector<uint8_t>& out){
    if(i+4>v.size()) return false; uint32_t sz = get_u32(v, i); i+=4;
    if(i+sz>v.size()) return false; out.assign(v.begin()+i, v.begin()+i+sz); i+=sz; return true;
}

std::vector<uint8_t> ser_tx(const Transaction& tx){
    std::vector<uint8_t> v;
    put_u32(v, tx.version);
    put_u32(v, (uint32_t)tx.vin.size());
    for(const auto& in : tx.vin){
        put_var(v, in.prev.txid);
        put_u32(v, in.prev.vout);
        put_var(v, in.sig);
        put_var(v, in.pubkey);
    }
    put_u32(v, (uint32_t)tx.vout.size());
    for(const auto& o : tx.vout){
        put_u64(v, o.value);
        put_var(v, o.pkh);
    }
    put_u32(v, tx.lock_time);
    return v;
}

bool deser_tx(const std::vector<uint8_t>& b, Transaction& tx){
    size_t i=0; if(b.size()<4) return false;
    tx.version = get_u32(b, i); i+=4;
    if(i+4>b.size()) return false; uint32_t nin = get_u32(b,i); i+=4;
    tx.vin.clear(); tx.vin.reserve(nin);
    for(uint32_t k=0;k<nin;k++){
        TxIn in{};
        if(!get_var(b,i,in.prev.txid)) return false;
        if(i+4>b.size()) return false; in.prev.vout = get_u32(b,i); i+=4;
        if(!get_var(b,i,in.sig)) return false;
        if(!get_var(b,i,in.pubkey)) return false;
        tx.vin.push_back(std::move(in));
    }
    if(i+4>b.size()) return false; uint32_t nout = get_u32(b,i); i+=4;
    tx.vout.clear(); tx.vout.reserve(nout);
    for(uint32_t k=0;k<nout;k++){
        TxOut o{};
        if(i+8>b.size()) return false; o.value = get_u64(b,i); i+=8;
        if(!get_var(b,i,o.pkh)) return false;
        tx.vout.push_back(std::move(o));
    }
    if(i+4>b.size()) return false; tx.lock_time = get_u32(b,i); i+=4;
    return i==b.size();
}

std::vector<uint8_t> ser_block(const Block& bl){
    std::vector<uint8_t> v;
    put_u32(v, bl.header.version);
    if(bl.header.prev_hash.size()!=32){ put_u32(v,(uint32_t)bl.header.prev_hash.size()); put_bytes(v, bl.header.prev_hash); }
    else { put_bytes(v, bl.header.prev_hash); }
    if(bl.header.merkle_root.size()!=32){ put_u32(v,(uint32_t)bl.header.merkle_root.size()); put_bytes(v, bl.header.merkle_root); }
    else { put_bytes(v, bl.header.merkle_root); }
    put_u64(v, (uint64_t)bl.header.time);
    put_u32(v, bl.header.bits);
    put_u64(v, bl.header.nonce);
    put_u32(v, (uint32_t)bl.txs.size());
    for(const auto& tx : bl.txs){
        auto raw = ser_tx(tx);
        put_u32(v, (uint32_t)raw.size());
        put_bytes(v, raw);
    }
    return v;
}

static inline bool read_hash_field(const std::vector<uint8_t>& b, size_t& i, std::vector<uint8_t>& out){
    if(i>=b.size()) return false;
    if(i+32<=b.size()){ out.assign(b.begin()+i, b.begin()+i+32); i+=32; return true; }
    if(i+4>b.size()) return false; uint32_t len = get_u32(b,i); i+=4;
    if(i+len>b.size()) return false; out.assign(b.begin()+i, b.begin()+i+len); i+=len; return true;
}

bool deser_block(const std::vector<uint8_t>& b, Block& out){
    size_t i=0; if(b.size()<4) return false;
    out.header.version = get_u32(b,i); i+=4;
    if(!read_hash_field(b,i,out.header.prev_hash)) return false;
    if(!read_hash_field(b,i,out.header.merkle_root)) return false;
    if(i+8+4+8>b.size()) return false;
    out.header.time = (int64_t)get_u64(b,i); i+=8;
    out.header.bits = get_u32(b,i); i+=4;
    out.header.nonce = get_u64(b,i); i+=8;
    if(i+4>b.size()) return false; uint32_t ntx = get_u32(b,i); i+=4;
    out.txs.clear(); out.txs.reserve(ntx);
    for(uint32_t k=0;k<ntx;k++){
        if(i+4>b.size()) return false; uint32_t sz = get_u32(b,i); i+=4;
        if(i+sz>b.size()) return false;
        Transaction tx;
        std::vector<uint8_t> span(b.begin()+i, b.begin()+i+sz);
        if(!deser_tx(span, tx)) return false;
        out.txs.push_back(std::move(tx)); i += sz;
    }
    return i==b.size();
}

} // namespace miq
