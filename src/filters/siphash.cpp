#include "filters/siphash.h"

#include <cstring> // std::memcpy

namespace miq {
namespace sip {

static inline uint64_t read_u64_le(const void* p) noexcept {
    uint64_t x;
    std::memcpy(&x, p, sizeof(x));
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    // portable bswap64
    x = ((x & 0x00000000000000FFULL) << 56) |
        ((x & 0x000000000000FF00ULL) << 40) |
        ((x & 0x0000000000FF0000ULL) << 24) |
        ((x & 0x00000000FF000000ULL) << 8 ) |
        ((x & 0x000000FF00000000ULL) >> 8 ) |
        ((x & 0x0000FF0000000000ULL) >> 24) |
        ((x & 0x00FF000000000000ULL) >> 40) |
        ((x & 0xFF00000000000000ULL) >> 56);
#endif
    return x;
}

void SipHasher::init(uint64_t k0, uint64_t k1) noexcept {
    k0_ = k0; k1_ = k1;

    v0 = 0x736f6d6570736575ULL ^ k0_;
    v1 = 0x646f72616e646f6dULL ^ k1_;
    v2 = 0x6c7967656e657261ULL ^ k0_;
    v3 = 0x7465646279746573ULL ^ k1_;

    buf_used_ = 0;
    total_len_ = 0;
}

void SipHasher::write(const void* data, size_t len) noexcept {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    total_len_ += static_cast<uint64_t>(len);

    // If we have pending bytes in the buffer, fill to 8 first
    if (buf_used_ > 0) {
        size_t need = 8 - buf_used_;
        size_t take = (len < need) ? len : need;
        std::memcpy(buf_ + buf_used_, p, take);
        buf_used_ += take;
        p += take;
        len -= take;
        if (buf_used_ < 8) return;

        // Process one 8-byte word from buffer
        uint64_t m = read_u64_le(buf_);
        v3 ^= m;
        sipround(); sipround(); // c=2
        v0 ^= m;
        buf_used_ = 0;
    }

    // Process as many 8-byte words as possible
    while (len >= 8) {
        uint64_t m = read_u64_le(p);
        v3 ^= m;
        sipround(); sipround();
        v0 ^= m;
        p += 8;
        len -= 8;
    }

    // Save remaining tail into buffer
    if (len > 0) {
        std::memcpy(buf_, p, len);
        buf_used_ = len;
    }
}

uint64_t SipHasher::finalize() noexcept {
    // Build the final 8-byte last block: leftover bytes + length in top byte
    uint64_t b = (total_len_ & 0xffULL) << 56; // SipHash packs length in the top byte

    switch (buf_used_) { // fallthrough-style packing
        default: /* 0 */ break;
        case 7: b |= (uint64_t)buf_[6] << 48; [[fallthrough]];
        case 6: b |= (uint64_t)buf_[5] << 40; [[fallthrough]];
        case 5: b |= (uint64_t)buf_[4] << 32; [[fallthrough]];
        case 4: b |= (uint64_t)buf_[3] << 24; [[fallthrough]];
        case 3: b |= (uint64_t)buf_[2] << 16; [[fallthrough]];
        case 2: b |= (uint64_t)buf_[1] << 8;  [[fallthrough]];
        case 1: b |= (uint64_t)buf_[0];       break;
    }

    // Final compression
    v3 ^= b;
    sipround(); sipround();
    v0 ^= b;

    // Finalization (d=4)
    v2 ^= 0xff;
    sipround(); sipround(); sipround(); sipround();

    uint64_t out = v0 ^ v1 ^ v2 ^ v3;

    // (Optionally) re-init if someone wants to reuse the instance safely:
    // init(k0_, k1_);

    return out;
}

}
}
