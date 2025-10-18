#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstddef>

#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"   // for MAGIC_BE (wire magic) if present
#  endif
#endif

// Prefer modern framed messages on the wire by default.
// Set to 1 only if you MUST speak legacy to very old peers.
#ifndef MIQ_WIRE_LEGACY_SEND
#define MIQ_WIRE_LEGACY_SEND 0
#endif

#ifndef MAX_MSG_SIZE
// Safe default if project doesn't define one
#define MIQ_FALLBACK_MAX_MSG_SIZE (2u * 1024u * 1024u) // 2 MiB
#else
#define MIQ_FALLBACK_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

namespace miq {

struct NetMsg {
    char cmd[12];
    std::vector<uint8_t> payload;
};

// Implemented in netmsg.cpp (if you use it in the node).
// If MIQ_WIRE_LEGACY_SEND==0, encodes NEW:
//   [ magic(4) | cmd(12) | len(4-le) | checksum(4) | payload ]
// If MIQ_WIRE_LEGACY_SEND==1, encodes LEGACY:
//   [ cmd(12) | len(4-le) | payload ]
std::vector<uint8_t> encode_msg(const std::string& cmd,
                                const std::vector<uint8_t>& payload);

// Convenience inline overload
inline std::vector<uint8_t> encode_msg(const char* cmd,
                                       const std::vector<uint8_t>& payload) {
    return encode_msg(cmd ? std::string(cmd) : std::string(), payload);
}

// Decode one full message starting at/after 'off' inside 'buf'.
// Accepts BOTH modern frames (with magic+checksum) and the legacy format
// (no magic/checksum) for backward compatibility.
// On success: fills 'out', advances 'off' to first byte after the message, and returns true.
// On need-more-bytes: returns false without changing 'off'.
// On corruption: scans forward past bad bytes to next candidate and continues on next call.
bool decode_msg(const std::vector<uint8_t>& buf, std::size_t& off, NetMsg& out);

}
