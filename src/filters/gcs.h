#include "filters/gcs.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace miq {
namespace gcs {

// ---------------- CompactSize ----------------

void write_u16_le(std::vector<uint8_t>& o, uint16_t v){
    o.push_back((uint8_t)(v & 0xff));
    o.push_back((uint8_t)((v >> 8) & 0xff));
}
void write_u32_le(std::vector<uint8_t>& o, uint32_t v){
    o.push_back((uint8_t)(v & 0xff));
    o.push_back((uint8_t)((v >> 8) & 0xff));
    o.push_back((uint8_t)((v >> 16) & 0xff));
    o.push_back((uint8_t)((v >> 24) & 0xff));
}
void write_u64_le(std::vector<uint8_t>& o, uint64_t v){
    for (int i=0;i<8;i++) { o.push_back((uint8_t)(v & 0xff)); v >>= 8; }
}

void write_compact_size(std::vector<uint8_t>& out, uint64_t v){
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

bool read_compact_size(const uint8_t*& p, const uint8_t* end, uint64_t& v){
    if (p >= end) return false;
    uint8_t ch = *p++;
    if (ch < 253) { v = ch; return true; }
    if (ch == 253) {
        if (end - p < 2) return false;
        v = (uint64_t)p[0] | ((uint64_t)p[1] << 8);
        p += 2; return true;
    }
    if (ch == 254) {
        if (end - p < 4) return false;
        v = (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24);
        p += 4; return true;
    }
    if (end - p < 8) return false;
    uint64_t r=0; for (int i=0;i<8;i++) r |= ((uint64_t)p[i]) << (8*i);
    p += 8; v = r; return true;
}

// ---------------- Build ---------------------

static std::vector<uint64_t> hashed_set(const std::array<uint8_t,16>& key,
                                        const std::vector<std::vector<uint8_t>>& items,
                                        uint32_t M)
{
    const uint64_t N = (uint64_t)items.size();
    const uint64_t F = N * (uint64_t)M;
    std::vector<uint64_t> vals; vals.reserve(items.size());
    if (F == 0) return vals;
    for (const auto& it : items) {
        vals.push_back(hash_to_range(key.data(), it, F));
    }
    std::sort(vals.begin(), vals.end());
    return vals;
}

gcs::Filter build(const std::array<uint8_t,16>& key16,
                  const std::vector<std::vector<uint8_t>>& items,
                  const Params& params)
{
    gcs::Filter f; f.key = key16;
    const uint64_t N = (uint64_t)items.size();
    if (N == 0) {
        f.bytes = {0x00}; // per BIP158: zero-element filter is a single zero byte
        return f;
    }

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

    // Serialize: CompactSize(N) || compressed
    std::vector<uint8_t> out;
    write_compact_size(out, N);
    out.insert(out.end(), compressed.begin(), compressed.end());
    f.bytes = std::move(out);
    return f;
}

// --------------- Query ------------------------------------------------------

static bool decode_next(BitReader& br, uint32_t P, uint64_t& val) {
    uint64_t q=0;
    if (!br.read_unary(q)) return false;
    uint64_t r=0;
    if (P > 0 && !br.read_bits_be(P, r)) return false;
    val = (q << P) | r;
    return true;
}

bool match_one(const Filter& f, const std::vector<uint8_t>& item, const Params& params){
    const auto& bytes = f.bytes;
    if (bytes.empty()) return false;
    if (bytes.size()==1 && bytes[0]==0x00) return false; // empty set

    const uint8_t* p = bytes.data();
    const uint8_t* e = bytes.data() + bytes.size();

    uint64_t N = 0;
    if (!read_compact_size(p, e, N)) return false;
    if (N == 0) return false;

    const uint64_t F = N * (uint64_t)params.M;
    const uint64_t target = hash_to_range(f.key.data(), item, F);

    BitReader br(p, (size_t)(e - p));
    uint64_t last = 0;

    for (uint64_t i=0; i<N; ++i){
        uint64_t delta = 0;
        if (!decode_next(br, params.P, delta)) return false;
        uint64_t set_item = last + delta;
        if (set_item == target) return true;
        if (set_item > target) return false; // early out
        last = set_item;
    }
    return false;
}

bool match_any(const Filter& f, const std::vector<std::vector<uint8_t>>& items, const Params& params){
    if (items.empty()) return false;
    const auto& bytes = f.bytes;
    if (bytes.empty()) return false;
    if (bytes.size()==1 && bytes[0]==0x00) return false;

    const uint8_t* p = bytes.data();
    const uint8_t* e = bytes.data() + bytes.size();

    uint64_t N = 0;
    if (!read_compact_size(p, e, N)) return false;
    if (N == 0) return false;

    const uint64_t F = N * (uint64_t)params.M;

    // hash & sort queries
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
        // advance queries up to/including val
        while (qi < q.size() && q[qi] < val) ++qi;
        if (qi < q.size() && q[qi] == val) return true;
        last = val;
    }
    return false;
}

}
}
