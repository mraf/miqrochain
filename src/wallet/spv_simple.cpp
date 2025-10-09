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

namespace miq {

// ---------- tiny helpers ----------
static inline uint32_t rd_u32_le(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}
static inline uint64_t rd_u64_le(const uint8_t* p){
    uint64_t v=0; for(int i=0;i<8;i++) v |= (uint64_t)p[i] << (8*i); return v;
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

// ---------- tx / block parsing ----------

struct TxParsed {
    std::vector<uint8_t> txid_le; // wire order (LE)
    bool coinbase{false};
    struct In  { std::vector<uint8_t> prev_txid; uint32_t vout; };
    struct Out { uint64_t value; std::vector<uint8_t> pkh;      };
    std::vector<In>  vin;
    std::vector<Out> vout;
};

static bool parse_tx_bitcoin(R& r, TxParsed& out){
    size_t start = r.tell();
    uint32_t version=0; if(!r.get(&version,4)) return false;

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

// MIQ-compact tx (prefixed by u32 size)
static bool parse_tx_miq_blockwrapped(R& r, TxParsed& out){
    if(!r.need(4)) return false;
    uint32_t tx_size = rd_u32_le(r.p + r.pos); r.pos += 4;
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

    // coinbase heuristic for MIQ: single input with zero prev hash (vout may be 0)
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

static bool parse_block_collect(const std::vector<uint8_t>& raw,
                                std::vector<TxParsed>& out_txs)
{
    out_txs.clear();

    // Try Bitcoin-like block first
    {
        R r(raw);
        if(!r.need(80)) goto try_miq;
        r.skip(80);
        uint64_t txcnt=0; if(!get_varint(r, txcnt)) goto try_miq;
        std::vector<TxParsed> txs; txs.reserve((size_t)txcnt);
        for(uint64_t i=0;i<txcnt;i++){
            TxParsed t; if(!parse_tx_bitcoin(r, t)) goto try_miq;
            txs.push_back(std::move(t));
        }
        out_txs.swap(txs);
        return true;
    }

try_miq:
    // MIQ-compact
    {
        R r2(raw);
        if(!r2.need(80)) return false;
        r2.skip(80);
        if(!r2.need(4)) return false;
        uint32_t txcnt = rd_u32_le(r2.p + r2.pos); r2.pos += 4;
        std::vector<TxParsed> txs; txs.reserve(txcnt);
        for(uint32_t i=0;i<txcnt;i++){
            TxParsed t; if(!parse_tx_miq_blockwrapped(r2, t)) return false;
            txs.push_back(std::move(t));
        }
        out_txs.swap(txs);
        return true;
    }
}

// ---------- SPV main ----------

bool spv_collect_utxos(const std::string& p2p_host, const std::string& p2p_port,
                       const std::vector<std::vector<uint8_t>>& pkhs,
                       const SpvOptions& /*opts*/,
                       std::vector<UtxoLite>& out,
                       std::string& err)
{
    out.clear();

    // 1) connect + handshake
    P2POpts po;
    po.host = p2p_host;
    po.port = p2p_port;
    po.user_agent = "/miqwallet-spv:0.3/";
    P2PLight p2p;
    if(!p2p.connect_and_handshake(po, err)) return false;

    // 2) headers -> tip
    uint32_t tip_height=0; std::vector<uint8_t> tip_hash_le;
    if(!p2p.get_best_header(tip_height, tip_hash_le, err)){ p2p.close(); return false; }

    // 3) choose a conservative scan window (8k blocks back)
    const uint32_t recent_block_window = 8000;
    uint32_t from_h = (tip_height > recent_block_window) ? (tip_height - recent_block_window) : 0;

    // 4) enumerate candidate blocks (no filters yet)
    std::vector<std::pair<std::vector<uint8_t>, uint32_t>> blocks;
    if(!p2p.match_recent_blocks(pkhs, from_h, tip_height, blocks, err)){ p2p.close(); return false; }

    // 5) fast PKH lookup
    std::unordered_set<std::vector<uint8_t>, VecHash> pkhset(pkhs.begin(), pkhs.end());

    // 6) rolling UTXO view
    std::vector<UtxoLite> view;
    std::unordered_map<std::string,size_t> idx;

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

    // 7) stream blocks, update view
    for(const auto& [hash_le, height] : blocks){
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
    }

    p2p.close();

    // 8) post-filter: require ≥1 conf for all; coinbases need full maturity
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

}
