#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>

namespace miq {

struct SHA256 {
    void init();
    void update(const uint8_t* data, size_t len);
    void final(uint8_t out[32]);

    // state
    uint32_t h[8];
    uint64_t bits;     // total message length in bits
    uint8_t  buf[64];  // partial block buffer
    size_t   idx;      // number of bytes currently in buf
};

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data);
std::vector<uint8_t> dsha256(const std::vector<uint8_t>& data);

} // namespace miq
