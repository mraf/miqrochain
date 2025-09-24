#include "hex.h"
#include <stdexcept>
#include <cctype>
#include <string>
#include <vector>

namespace miq {

static inline uint8_t unhex_nibble(char c) {
    if (c >= '0' && c <= '9') return uint8_t(c - '0');
    if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return uint8_t(c - 'A' + 10);
    throw std::runtime_error("hex: invalid nibble");
}

std::vector<uint8_t> from_hex(const std::string& h) {
    const size_t n = h.size();
    if (n & 1u) throw std::runtime_error("hex: odd length");
    std::vector<uint8_t> out;
    out.resize(n / 2);
    for (size_t i = 0, j = 0; i < n; i += 2, ++j) {
        const uint8_t hi = unhex_nibble(h[i]);
        const uint8_t lo = unhex_nibble(h[i + 1]);
        out[j] = uint8_t((hi << 4) | lo);
    }
    return out;
}

std::string to_hex(const std::vector<uint8_t>& v) {
    static const char LUT[16] = {
        '0','1','2','3','4','5','6','7',
        '8','9','a','b','c','d','e','f'
    };
    const size_t n = v.size();
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t b = v[i];
        out[2*i    ] = LUT[b >> 4];
        out[2*i + 1] = LUT[b & 0xF];
    }
    return out;
}

} // namespace miq
