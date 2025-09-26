#include "block.h"
#include "sha256.h"
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>
#include <cassert>

namespace miq {

// Helpers to serialize integers in little-endian for the header
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t((x >> 0) & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff));
    v.push_back(uint8_t((x >> 24) & 0xff));
}
static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    v.push_back(uint8_t((x >> 0) & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff));
    v.push_back(uint8_t((x >> 24) & 0xff));
    v.push_back(uint8_t((x >> 32) & 0xff));
    v.push_back(uint8_t((x >> 40) & 0xff));
    v.push_back(uint8_t((x >> 48) & 0xff));
    v.push_back(uint8_t((x >> 56) & 0xff));
}

std::vector<uint8_t> Block::block_hash() const {
    // Canonical binary header:
    //   uint32 ver | 32 prev_hash | 32 merkle_root | int64 time | uint32 bits | uint64 nonce
    // Integers are serialized little-endian.
    std::vector<uint8_t> h;
    h.reserve(4 + 32 + 32 + 8 + 4 + 8);

    put_u32_le(h, header.version);

#ifndef NDEBUG
    // Sanity: these fields must be exactly 32 bytes in canonical headers.
    assert(header.prev_hash.size()   == 32 && "prev_hash must be 32 bytes");
    assert(header.merkle_root.size() == 32 && "merkle_root must be 32 bytes");
#endif

    // prev_hash (expect 32 bytes; in Release we still serialize whatever is present)
    h.insert(h.end(), header.prev_hash.begin(), header.prev_hash.end());

    // merkle_root (expect 32 bytes)
    h.insert(h.end(), header.merkle_root.begin(), header.merkle_root.end());

    // time (stored as int64)
    put_u64_le(h, static_cast<uint64_t>(header.time));

    // bits and nonce
    put_u32_le(h, header.bits);
    put_u64_le(h, header.nonce);

    return dsha256(h);
}

} // namespace miq
