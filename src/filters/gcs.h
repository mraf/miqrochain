#pragma once

#include <array>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <limits>

// Bring in the project types we actually use in the real build.
#include "tx.h"        // Transaction, TxIn, TxOut, OutPoint
#include "block.h"     // Block::block_hash(), Block::txs
#include "hash160.h"   // std::vector<uint8_t> hash160(const std::vector<uint8_t>&)

namespace miq {
namespace gcs {

// ---------------- Public types ----------------

struct Params {
    uint32_t P; // Golomb-Rice parameter (e.g., 19 for BIP158)
    uint32_t M; // Scaling factor (e.g., 784931 for BIP158)
};

struct Filter {
    std::array<uint8_t,16> key{};   // 128-bit SipHash key
    std::vector<uint8_t>   bytes;   // serialized filter: CompactSize(N) || GR encoded deltas
};

// ---------------- CompactSize helpers ----------------

inline void write_u16_le(std::vector<uint8_t>& o, uint16_t v){
    o.push_back((uint8_t)(v & 0xff));
    o.push_back((uint8_t)((v >> 8) & 0xff));
}
inline void write_u32_le(std::vector<uint8_t>& o, uint32_t v){
    o.push_back((uint8_t)(v & 0xff));
    o.push_back((uint8_t)((v >> 8) & 0xff));
    o.push_back((uint8_t)((v >> 16) & 0xff));
    o.push_back((uint8_t)((v >> 24) & 0xff));
}
inline void write_u64_le(std::vector<uint8_t>& o, uint64_t v){
    for (int i=0;i<8;i++) { o.push_back((uint8_t)(v & 0xff)); v >>= 8; }
}

inline void write_compact_size(std::vector<uint8_t>& out, uint64_t v){
    if (v < 253) {
        out.push_back((uint8_t)v);
    } else if (v <= 0xFFFFULL) {
        out.push_back(253); write_u16_le(out, (uint16_t)v);
    } else if (v <= 0xFFFFFFFFULL) {
        out.push_back(254); write_u32_le(out, (uint32_t)v);
    } else {
        out.push_back(255); write_u64_le(out, v);
    }
}

inline bool read_compact_size(const uint8_t*& p, const uint8_t* end, uint64_t& v){
    if (p >= end) return false;
    uint8_t ch = *p++;
    if (ch < 253) { v = ch; return true; }
    if (ch == 253) {
        if ((end - p) < 2) return false;
        v = (uint64_t)p[0] | ((uint64_t)p[1] << 8);
        p += 2; return true;
    }
    if (ch == 254) {
        if ((end - p) < 4) return false;
        v =  (uint64_t)p[0]
           | ((uint64_t)p[1] << 8)
           | ((uint64_t)p[2] << 16)
           | ((uint64_t)p[3] << 24);
        p += 4; return true;
    }
    if ((end - p) < 8) return false;
    uint64_t r=0; for (int i=0;i<8;i++) r |= ((uint64_t)p[i]) << (8*i);
    p += 8; v = r; return true;
}

// ---------------- Bit I/O (MSB-first within each byte) ----------------

class BitWriter {
public:
    BitWriter() : bit_in_byte_(0) {}

    inline void write_bit(uint32_t b){
        if (bit_in_byte_ == 0) buf_.push_back(0);
        if (b & 1) buf_.back() |= (uint8_t)(0x80u >> bit_in_byte_);
        if (++bit_in_byte_ == 8) bit_in_byte_ = 0;
    }
    inline void write_unary(uint64_t q){ for (uint64_t i=0;i<q;i++) write_bit(1); write_bit(0); }
    inline void write_bits_be(uint32_t nbits, uint64_t value){
        for (int i = (int)nbits - 1; i >= 0; --i) write_bit((uint32_t)((value >> i) & 1ull));
    }
    inline void write_golomb(uint64_t x, uint32_t P){
        uint64_t q = (P ? (x >> P) : x);
        uint64_t r = (P ? (x & ((1ull<<P)-1)) : 0ull);
        write_unary(q);
        if (P) write_bits_be(P, r);
    }
    inline std::vector<uint8_t> take(){ return std::move(buf_); }
private:
    std::vector<uint8_t> buf_;
    uint8_t bit_in_byte_;
};

class BitReader {
public:
    BitReader(const uint8_t* data, size_t len)
        : p_(data), n_(len), byte_pos_(0), bit_in_byte_(0) {}
    inline bool read_bit(uint32_t& b){
        if (byte_pos_ >= n_) return false;
        uint8_t cur = p_[byte_pos_];
        b = (cur >> (7 - bit_in_byte_)) & 1u;
        if (++bit_in_byte_ == 8) { bit_in_byte_ = 0; ++byte_pos_; }
        return true;
    }
    inline bool read_unary(uint64_t& q){
        q = 0;
        for (;;) {
            uint32_t bit=0; if (!read_bit(bit)) return false;
            if (bit == 0) { return true; }
            ++q;
        }
    }
    inline bool read_bits_be(uint32_t nbits, uint64_t& value){
        value = 0;
        for (uint32_t i=0;i<nbits;i++){
            uint32_t bit=0; if (!read_bit(bit)) return false;
            value = (value << 1) | (uint64_t)bit;
        }
        return true;
    }
private:
    const uint8_t* p_;
    size_t n_;
    size_t byte_pos_;
    uint8_t bit_in_byte_;
};

// ---------------- SipHash-2-4 (64-bit) ----------------

inline uint64_t load64_le(const uint8_t* p){
    return  (uint64_t)p[0]
          | ((uint64_t)p[1] << 8)
          | ((uint64_t)p[2] << 16)
          | ((uint64_t)p[3] << 24)
          | ((uint64_t)p[4] << 32)
          | ((uint64_t)p[5] << 40)
          | ((uint64_t)p[6] << 48)
          | ((uint64_t)p[7] << 56);
}
inline uint64_t rotl64(uint64_t x, int b){ return (x << b) | (x >> (64 - b)); }

inline uint64_t siphash24(const uint8_t key[16], const uint8_t* data, size_t len){
    uint64_t k0 = load64_le(key + 0);
    uint64_t k1 = load64_le(key + 8);

    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;

    const uint8_t* end = data + len - (len % 8);
    for (const uint8_t* p = data; p != end; p += 8) {
        uint64_t m = load64_le(p);
        v3 ^= m;
        for (int i=0;i<2;i++){
            v0 += v1; v2 += v3; v1 = rotl64(v1,13); v3 = rotl64(v3,16);
            v1 ^= v0; v3 ^= v2; v0 = rotl64(v0,32);
            v2 += v1; v0 += v3; v1 = rotl64(v1,17); v3 = rotl64(v3,21);
            v1 ^= v2; v3 ^= v0; v2 = rotl64(v2,32);
        }
        v0 ^= m;
    }

    uint64_t b = ((uint64_t)len) << 56;
    switch (len & 7) {
        case 7: b |= ((uint64_t)end[6]) << 48; [[fallthrough]];
        case 6: b |= ((uint64_t)end[5]) << 40; [[fallthrough]];
        case 5: b |= ((uint64_t)end[4]) << 32; [[fallthrough]];
        case 4: b |= ((uint64_t)end[3]) << 24; [[fallthrough]];
        case 3: b |= ((uint64_t)end[2]) << 16; [[fallthrough]];
        case 2: b |= ((uint64_t)end[1]) << 8;  [[fallthrough]];
        case 1: b |= ((uint64_t)end[0]);       [[fallthrough]];
        default: break;
    }

    v3 ^= b;
    for (int i=0;i<2;i++){
        v0 += v1; v2 += v3; v1 = rotl64(v1,13); v3 = rotl64(v3,16);
        v1 ^= v0; v3 ^= v2; v0 = rotl64(v0,32);
        v2 += v1; v0 += v3; v1 = rotl64(v1,17); v3 = rotl64(v3,21);
        v1 ^= v2; v3 ^= v0; v2 = rotl64(v2,32);
    }
    v0 ^= b;

    v2 ^= 0xff;
    for (int i=0;i<4;i++){
        v0 += v1; v2 += v3; v1 = rotl64(v1,13); v3 = rotl64(v3,16);
        v1 ^= v0; v3 ^= v2; v0 = rotl64(v0,32);
        v2 += v1; v0 += v3; v1 = rotl64(v1,17); v3 = rotl64(v3,21);
        v1 ^= v2; v3 ^= v0; v2 = rotl64(v2,32);
    }

    return v0 ^ v1 ^ v2 ^ v3;
}

inline uint64_t hash_to_range(const uint8_t key16[16],
                              const std::vector<uint8_t>& item,
                              uint64_t F)
{
    if (F == 0) return 0;
    uint64_t h = siphash24(key16, item.data(), item.size());
#if defined(__SIZEOF_INT128__)
    __uint128_t wide = ( (__uint128_t)h * (__uint128_t)F );
    return (uint64_t)(wide >> 64);
#else
    return h % F;
#endif
}

// ---------------- Build ---------------------

inline std::vector<uint64_t> hashed_set(const std::array<uint8_t,16>& key,
                                        const std::vector<std::vector<uint8_t>>& items,
                                        uint32_t M)
{
    const uint64_t N = (uint64_t)items.size();
    const uint64_t F = N * (uint64_t)M;
    std::vector<uint64_t> vals; vals.reserve(items.size());
    if (F == 0) return vals;
    for (const auto& it : items) vals.push_back(hash_to_range(key.data(), it, F));
    std::sort(vals.begin(), vals.end());
    return vals;
}

inline gcs::Filter build(const std::array<uint8_t,16>& key16,
                         const std::vector<std::vector<uint8_t>>& items,
                         const Params& params)
{
    gcs::Filter f; f.key = key16;
    const uint64_t N = (uint64_t)items.size();
    if (N == 0) { f.bytes = {0x00}; return f; }

    const auto vals = hashed_set(key16, items, params.M);

    BitWriter bw;
    uint64_t prev = 0;
    for (size_t i=0;i<vals.size();++i){
        const uint64_t v = vals[i];
        const uint64_t delta = (i==0)? v : (v - prev);
        bw.write_golomb(delta, params.P);
        prev = v;
    }
    auto compressed = bw.take();

    std::vector<uint8_t> out;
    write_compact_size(out, N);
    out.insert(out.end(), compressed.begin(), compressed.end());
    f.bytes = std::move(out);
    return f;
}

// --------------- Query ------------------------------------------------------

inline bool decode_next(BitReader& br, uint32_t P, uint64_t& val) {
    uint64_t q=0; if (!br.read_unary(q)) return false;
    uint64_t r=0; if (P > 0 && !br.read_bits_be(P, r)) return false;
    val = (q << P) | r; return true;
}

inline bool match_one(const Filter& f, const std::vector<uint8_t>& item, const Params& params){
    const auto& bytes = f.bytes;
    if (bytes.empty()) return false;
    if (bytes.size()==1 && bytes[0]==0x00) return false;

    const uint8_t* p = bytes.data();
    const uint8_t* e = bytes.data() + bytes.size();

    uint64_t N = 0;
    if (!read_compact_size(p, e, N) || N == 0) return false;

    const uint64_t F = N * (uint64_t)params.M;
    const uint64_t target = hash_to_range(f.key.data(), item, F);

    BitReader br(p, (size_t)(e - p));
    uint64_t last = 0;

    for (uint64_t i=0; i<N; ++i){
        uint64_t delta = 0;
        if (!decode_next(br, params.P, delta)) return false;
        uint64_t set_item = last + delta;
        if (set_item == target) return true;
        if (set_item > target) return false;
        last = set_item;
    }
    return false;
}

inline bool match_any(const Filter& f, const std::vector<std::vector<uint8_t>>& items, const Params& params){
    if (items.empty()) return false;
    const auto& bytes = f.bytes;
    if (bytes.empty()) return false;
    if (bytes.size()==1 && bytes[0]==0x00) return false;

    const uint8_t* p = bytes.data();
    const uint8_t* e = bytes.data() + bytes.size();

    uint64_t N = 0;
    if (!read_compact_size(p, e, N) || N == 0) return false;

    const uint64_t F = N * (uint64_t)params.M;

    std::vector<uint64_t> q; q.reserve(items.size());
    for (auto& it: items) q.push_back(hash_to_range(f.key.data(), it, F));
    std::sort(q.begin(), q.end());

    BitReader br(p, (size_t)(e - p));
    uint64_t last = 0;
    size_t qi = 0;

    for (uint64_t i=0; i<N && qi < q.size(); ++i){
        uint64_t delta = 0;
        if (!decode_next(br, params.P, delta)) return false;
        uint64_t val = last + delta;
        while (qi < q.size() && q[qi] < val) ++qi;
        if (qi < q.size() && q[qi] == val) return true;
        last = val;
    }
    return false;
}

// ---------------- Real element extraction + wiring ----------------

// Helpers
inline bool is_zero32(const std::vector<uint8_t>& v){
    if (v.size() != 32) return false;
    for (uint8_t b : v) if (b) return false;
    return true;
}
inline bool is_coinbase(const Transaction& tx){
    return tx.vin.size() == 1
        && is_zero32(tx.vin[0].prev.txid)
        && tx.vin[0].prev.vout == 0;
}

// BIP158 basic params
static inline Params basic_params(){
    return Params{19u, 784931u};
}

// Build a block filter:
//  - Elements:
//      * For every TxOut: 20-byte pkh (scriptPubKey key material in this P2PKH-only design).
//      * For every non-coinbase TxIn: HASH160(pubkey) (equals prevout scriptPubKey’s pkh).
//  - Key: first 16 bytes of the block hash.
inline bool build_block_filter(const ::miq::Block& b, std::vector<uint8_t>& out_bytes)
{
    // Collect elements
    std::vector<std::vector<uint8_t>> elements;
    elements.reserve(64);

    for (const auto& tx : b.txs) {
        // Outputs: include pkh (20 bytes)
        for (const auto& o : tx.vout) {
            if (o.pkh.size() == 20) elements.push_back(o.pkh);
        }
        // Inputs: if not coinbase, include HASH160(pubkey)
        if (!is_coinbase(tx)) {
            for (const auto& in : tx.vin) {
                if (!in.pubkey.empty()) {
                    auto h = hash160(in.pubkey);
                    if (h.size() == 20) elements.push_back(std::move(h));
                }
            }
        }
    }

    // Derive SipHash key from the block hash (first 16 bytes)
    auto bh = b.block_hash();
    if (bh.size() < 16) return false;
    std::array<uint8_t,16> key{};
    std::copy(bh.begin(), bh.begin()+16, key.begin());

    // Build the filter
    const auto params = basic_params();
    auto f = build(key, elements, params);
    out_bytes = std::move(f.bytes);
    return true;
}

}
}
