#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <cstddef>

#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
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

// Implemented in netmsg.cpp
std::vector<uint8_t> encode_msg(const std::string& cmd,
                                const std::vector<uint8_t>& payload);

// Convenience inline so calls like encode_msg("version", {}) work without
// needing a separate TU definition (avoids LNK/ODR issues).
inline std::vector<uint8_t> encode_msg(const char* cmd,
                                       const std::vector<uint8_t>& payload) {
    return encode_msg(cmd ? std::string(cmd) : std::string(), payload);
}

// Decode one full message starting at/after 'off' inside 'buf'.
// On success: fills 'out', advances 'off' to first byte after the message, and returns true.
// On need-more-bytes: returns false without changing 'off'.
// On corruption: scans forward past bad bytes to next magic and continues on next call.
bool decode_msg(const std::vector<uint8_t>& buf, std::size_t& off, NetMsg& out);

}
