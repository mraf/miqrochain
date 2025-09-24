#include "netmsg.h"
#include "sha256.h"
#include <cstring>
#include <vector>
#include <string>

// OPTIONAL: if you already have MAX_MSG_SIZE in constants.h, we’ll use it.
// Otherwise we fall back to 2 MiB to avoid a build dependency here.
#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifndef MAX_MSG_SIZE
#define MIQ_FALLBACK_MAX_MSG_SIZE (2u * 1024u * 1024u)
#else
#define MIQ_FALLBACK_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

namespace miq {

// ---- helpers: little-endian put/get (explicit, no UB) ----
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t((x >> 0) & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff));
    v.push_back(uint8_t((x >> 24) & 0xff));
}
static inline uint32_t get_u32_le(const uint8_t* p) {
    return (uint32_t(p[0])      ) |
           (uint32_t(p[1]) <<  8) |
           (uint32_t(p[2]) << 16) |
           (uint32_t(p[3]) << 24);
}

std::vector<uint8_t> encode_msg(const std::string& cmd, const std::vector<uint8_t>& payload){
    std::vector<uint8_t> b;
    b.reserve(24 + payload.size());

    // magic
    put_u32_le(b, MAGIC);

    // cmd (12 bytes, zero-padded)
    char c[12] = {0};
    std::memcpy(c, cmd.c_str(), cmd.size() > 12 ? 12 : cmd.size());
    b.insert(b.end(), c, c + 12);

    // length
    put_u32_le(b, static_cast<uint32_t>(payload.size()));

    // checksum = first 4 bytes of dsha256(payload)
    auto chk = dsha256(payload);
    uint32_t cc = get_u32_le(chk.data());
    put_u32_le(b, cc);

    // payload
    b.insert(b.end(), payload.begin(), payload.end());
    return b;
}

bool decode_msg(const std::vector<uint8_t>& in, size_t& off, NetMsg& out){
    // Header is 24 bytes: magic(4) | cmd(12) | len(4) | checksum(4)
    if(off + 24 > in.size()) return false;

    // magic
    uint32_t magic = get_u32_le(&in[off]);
    if(magic != MAGIC) return false;
    off += 4;

    // cmd
    std::memcpy(out.cmd, &in[off], 12);
    off += 12;

    // length
    uint32_t len = get_u32_le(&in[off]);
    off += 4;

    // checksum
    uint32_t cc = get_u32_le(&in[off]);
    off += 4;

    // basic sanity: cap message size to avoid OOM/DoS
    if(len > MIQ_FALLBACK_MAX_MSG_SIZE) return false;

    // ensure full payload present
    if(off + len > in.size()) return false;

    // payload
    out.payload.assign(in.begin() + off, in.begin() + off + len);
    off += len;

    // verify checksum (first 4 bytes of dsha256(payload))
    auto chk = dsha256(out.payload);
    if(get_u32_le(chk.data()) != cc) return false;

    return true;
}

} // namespace miq
