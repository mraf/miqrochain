#include "netmsg.h"
#include "sha256.h"  // dsha256(payload)
#include <cstring>
#include <algorithm>

namespace miq {

// ---- Network magic configuration -------------------------------------------
// Option A: define MIQ_NET_MAGIC_STR to a 4-byte string (e.g., "miq1")
// Option B: define MIQ_NET_MAGIC to a 32-bit constant (e.g., 0xD9B4BEF9u)
// Defaults to literal bytes: 'm','i','q','1'
static inline void get_magic(uint8_t out4[4]) {
#ifdef MIQ_NET_MAGIC_STR
    static_assert(sizeof(MIQ_NET_MAGIC_STR) >= 4, "MIQ_NET_MAGIC_STR must be at least 4 chars");
    out4[0] = (uint8_t)MIQ_NET_MAGIC_STR[0];
    out4[1] = (uint8_t)MIQ_NET_MAGIC_STR[1];
    out4[2] = (uint8_t)MIQ_NET_MAGIC_STR[2];
    out4[3] = (uint8_t)MIQ_NET_MAGIC_STR[3];
#elif defined(MIQ_NET_MAGIC)
    uint32_t m = (uint32_t)MIQ_NET_MAGIC; // emit in little-endian to match BTC-like layouts
    out4[0] = (uint8_t)(m >> 0);
    out4[1] = (uint8_t)(m >> 8);
    out4[2] = (uint8_t)(m >> 16);
    out4[3] = (uint8_t)(m >> 24);
#else
    out4[0] = 'm'; out4[1] = 'i'; out4[2] = 'q'; out4[3] = '1';
#endif
}

static inline void put_u32_le(uint32_t x, uint8_t* p) {
    p[0]=uint8_t(x>>0); p[1]=uint8_t(x>>8); p[2]=uint8_t(x>>16); p[3]=uint8_t(x>>24);
}
static inline uint32_t get_u32_le(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

// First 4 bytes of dsha256(payload)
static inline void checksum4(const std::vector<uint8_t>& payload, uint8_t out[4]) {
    std::vector<uint8_t> h = dsha256(payload);
    out[0]=h[0]; out[1]=h[1]; out[2]=h[2]; out[3]=h[3];
}

std::vector<uint8_t> encode_msg(const char* ccmd, const std::vector<uint8_t>& payload) {
    // Clamp payload size defensively
    const uint32_t len = (payload.size() > MIQ_FALLBACK_MAX_MSG_SIZE)
        ? (uint32_t)MIQ_FALLBACK_MAX_MSG_SIZE
        : (uint32_t)payload.size();

    uint8_t magic[4]; get_magic(magic);

    uint8_t header[4 + 12 + 4 + 4];
    std::memcpy(header + 0, magic, 4);

    char cmd[12] = {0};
    if (ccmd) {
        size_t L = std::min<size_t>(11, std::strlen(ccmd));
        std::memcpy(cmd, ccmd, L);
    }
    std::memcpy(header + 4, cmd, 12);

    put_u32_le(len, header + 16);

    uint8_t csum[4]; checksum4(payload, csum);
    std::memcpy(header + 20, csum, 4);

    std::vector<uint8_t> out;
    out.reserve(sizeof(header) + len);
    out.insert(out.end(), header, header + sizeof(header));
    out.insert(out.end(), payload.begin(), payload.begin() + len);
    return out;
}

// Robust, scanning decoder with resync
bool decode_msg(const std::vector<uint8_t>& buf, size_t& off, NetMsg& out) {
    const size_t HLEN = 4 + 12 + 4 + 4;
    uint8_t magic[4]; get_magic(magic);

    size_t pos = off;
    for (;;) {
        // Need at least a full header to start
        if (buf.size() - pos < HLEN) {
            // Not enough data; don't consume anything
            return false;
        }

        // Magic check
        if (std::memcmp(&buf[pos], magic, 4) != 0) {
            // Resync: advance one byte and keep scanning
            ++pos;
            continue;
        }

        // We have magic + full header available
        const uint8_t* ph = &buf[pos];

        const char* pcmd = reinterpret_cast<const char*>(ph + 4);
        char cmd[12];
        std::memcpy(cmd, pcmd, 12);

        const uint32_t len = get_u32_le(ph + 16);
        const uint8_t* pchk = ph + 20;

        // Sanity on length
        if (len > MIQ_FALLBACK_MAX_MSG_SIZE) {
            // Corrupt length -> skip this magic and resync at next byte
            ++pos;
            continue;
        }

        // Need full payload
        if (buf.size() - pos < (size_t)HLEN + (size_t)len) {
            // Wait for more; don't consume
            return false;
        }

        // Verify checksum
        std::vector<uint8_t> payload;
        if (len) {
            payload.assign(buf.begin() + pos + HLEN, buf.begin() + pos + HLEN + len);
        }
        uint8_t chk[4]; checksum4(payload, chk);
        if (std::memcmp(pchk, chk, 4) != 0) {
            // Bad checksum -> skip this magic and resync
            ++pos;
            continue;
        }

        // OK: fill out message and advance off
        std::memcpy(out.cmd, cmd, 12);
        out.payload.swap(payload);
        off = pos + HLEN + len;
        return true;
    }
}

}
