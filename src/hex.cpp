#include "hex.h"
#include <array>
#include <cctype>
#include <cstdint>
#include <string>

namespace miq {

static inline uint8_t unhex_nibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + (c - 'a'));
    return 0;
}

std::vector<uint8_t> from_hex(const std::string& h) {
    const size_t n = h.size();
    if (n % 2 != 0) return {};
    std::vector<uint8_t> out(n / 2);
    for (size_t i = 0, j = 0; i < n; i += 2, ++j) {
        const uint8_t hi = unhex_nibble(h[i]);
        const uint8_t lo = unhex_nibble(h[i + 1]);
        out[j] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return out;
}

std::string to_hex(const std::vector<uint8_t>& v) {
    static constexpr char LUT[] = "0123456789abcdef";
    const size_t n = v.size();
    std::string out;
    out.resize(n * 2);
    for (size_t i = 0; i < n; ++i) {
        const uint8_t b = v[i];
        out[2 * i]     = LUT[b >> 4];
        out[2 * i + 1] = LUT[b & 0x0F];
    }
    return out;
}

} // namespace miq
