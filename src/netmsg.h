#pragma once
#include <cstdint>
#include <vector>
#include <string>

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

// 12-char, NUL-padded command + payload
struct NetMsg {
    char cmd[12];
    std::vector<uint8_t> payload;
};

// Serialize to: [4 magic][12 cmd][4 len (LE)][4 csum][payload]
std::vector<uint8_t> encode_msg(const char* cmd, const std::vector<uint8_t>& payload);

// Decode one full message starting at/after 'off' inside 'buf'.
// On success: fills 'out', advances 'off' to first byte after the message, and returns true.
// On need-more-bytes: returns false without changing 'off'.
// On corruption: scans forward past bad bytes to next magic and keeps going in the next call.
bool decode_msg(const std::vector<uint8_t>& buf, size_t& off, NetMsg& out);

} // namespace miq
