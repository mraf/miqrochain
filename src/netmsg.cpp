#include "netmsg.h"
#include "sha256.h"  // dsha256(payload)
#include <cstring>
#include <algorithm>

namespace miq {

// ---- Network magic configuration -------------------------------------------
static inline void get_magic(uint8_t out4[4]) {
#ifdef MIQ_NET_MAGIC_STR
    static_assert(sizeof(MIQ_NET_MAGIC_STR) >= 4, "MIQ_NET_MAGIC_STR must be at least 4 chars");
    out4[0] = (uint8_t)MIQ_NET_MAGIC_STR[0];
    out4[1] = (uint8_t)MIQ_NET_MAGIC_STR[1];
    out4[2] = (uint8_t)MIQ_NET_MAGIC_STR[2];
    out4[3] = (uint8_t)MIQ_NET_MAGIC_STR[3];
#elif defined(MIQ_NET_MAGIC)
    uint32_t m = (uint32_t)MIQ_NET_MAGIC; // little-endian to match BTC-like layouts
    out4[0] = (uint8_t)(m >> 0);
    out4[1] = (uint8_t)(m >> 8);
    out4[2] = (uint8_t)(m >> 16);
    out4[3] = (uint8_t)(m >> 24);
#else
    out4[0] = 'm'; out4[1] = 'i'; out4[2] = 'q'; out4[3] = '1';
#endif
}

static inline void put_u32_le(uint32_t x, uint8_t* p) {
    p[0] = (uint8_t)(x >> 0);
    p[1] = (uint8_t)(x >> 8);
    p[2] = (uint8_t)(x >> 16);
    p[3] = (uint8_t)(x >> 24);
}
static inline uint32_t get_u32_le(const uint8_t* p) {
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

// First 4 bytes of dsha256(payload)
static inline void checksum4(const std::vector<uint8_t>& payload, uint8_t out[4]) {
    std::vector<uint8_t> h = dsha256(payload);
    out[0] = h[0]; out[1] = h[1]; out[2] = h[2]; out[3] = h[3];
}

// Serialize to: [4 magic][12 cmd][4 len (LE)][4 csum][payload]
std::vector<uint8_t> encode_msg(const std::string& cmd,
                                const std::vector<uint8_t>& payload) {
    const uint32_t len = (payload.size() > MIQ_FALLBACK_MAX_MSG_SIZE)
        ? (uint32_t)MIQ_FALLBACK_MAX_MSG_SIZE
        : (uint32_t)payload.size();

    uint8_t magic[4]; get_magic(magic);

    uint8_t header[4 + 12 + 4 + 4];
    std::memcpy(header + 0, magic, 4);

    char cmdbuf[12] = {0};
    if (!cmd.empty()) {
        const std::size_t L = std::min<std::size_t>(sizeof(cmdbuf), cmd.size());
        std::memcpy(cmdbuf, cmd.data(), L);
    }
    std::memcpy(header + 4, cmdbuf, 12);

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
bool decode_msg(const std::vector<uint8_t>& buf, std::size_t& off, NetMsg& out) {
    const std::size_t HLEN = 4 + 12 + 4 + 4;
    uint8_t magic[4]; get_magic(magic);

    std::size_t pos = off;
    for (;;) {
        if (buf.size() < pos + HLEN) return false; // not enough data for header

        // Magic check
        if (std::memcmp(&buf[pos], magic, 4) != 0) {
            ++pos; // resync: advance one byte
            continue;
        }

        const uint8_t* ph = &buf[pos];

        char cmd[12];
        std::memcpy(cmd, ph + 4, 12);

        const uint32_t len = get_u32_le(ph + 16);
        const uint8_t* pchk = ph + 20;

        if (len > MIQ_FALLBACK_MAX_MSG_SIZE) { ++pos; continue; } // insane length

        if (buf.size() < pos + HLEN + (std::size_t)len) {
            return false; // wait for more payload bytes
        }

        // Verify checksum
        std::vector<uint8_t> payload;
        if (len) {
            payload.assign(buf.begin() + pos + HLEN,
                           buf.begin() + pos + HLEN + len);
        }
        uint8_t chk[4]; checksum4(payload, chk);
        if (std::memcmp(pchk, chk, 4) != 0) {
            ++pos; // bad checksum -> resync
            continue;
        }

        // OK
        std::memcpy(out.cmd, cmd, 12);
        out.payload.swap(payload);
        off = pos + HLEN + len;
        return true;
    }
}

}
