#pragma once
// SipHash-2-4 (public domain/CC0-style implementation) for MIQ filters.
// Minimal, dependency-free, C++17.  See: https://131002.net/siphash/

#include <cstdint>
#include <cstddef>

namespace miq {
namespace sip {

// Streaming SipHasher-2-4
class SipHasher {
public:
    SipHasher(uint64_t k0, uint64_t k1) noexcept { init(k0, k1); }

    // Feed bytes (can be called multiple times)
    void write(const void* data, size_t len) noexcept;

    // Finalize and return 64-bit MAC (does NOT reset the hasher)
    uint64_t finalize() noexcept;

    // One-shot helper
    static uint64_t siphash24(const void* data, size_t len,
                              uint64_t k0, uint64_t k1) noexcept {
        SipHasher h(k0, k1);
        h.write(data, len);
        return h.finalize();
    }

private:
    void init(uint64_t k0, uint64_t k1) noexcept;

    static inline uint64_t rotl(uint64_t x, int b) noexcept {
        return (x << b) | (x >> (64 - b));
    }

    // The “compress” round (SipRound)
    inline void sipround() noexcept {
        v0 += v1; v1 = rotl(v1, 13); v1 ^= v0; v0 = rotl(v0, 32);
        v2 += v3; v3 = rotl(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotl(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotl(v1, 17); v1 ^= v2; v2 = rotl(v2, 32);
    }

    uint64_t v0{}, v1{}, v2{}, v3{};
    uint64_t k0_{}, k1_{};

    // Buffer for partial 8-byte chunk
    uint8_t  buf_[8]{};
    size_t   buf_used_{0};
    uint64_t total_len_{0};
};

// Convenience wrappers
inline uint64_t SipHash24(const void* data, size_t len,
                          uint64_t k0, uint64_t k1) noexcept {
    return SipHasher::siphash24(data, len, k0, k1);
}

}
}
