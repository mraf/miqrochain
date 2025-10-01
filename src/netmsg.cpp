// netmsg.cpp (drop-in replacement)

#include "netmsg.h"

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <algorithm>

#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifndef MAX_BLOCK_SIZE
#define MIQ_FALLBACK_MAX_BLOCK_SZ (1u * 1024u * 1024u)   // 1 MiB
#else
#define MIQ_FALLBACK_MAX_BLOCK_SZ (MAX_BLOCK_SIZE)
#endif

#ifndef MAX_MSG_SIZE
#define MIQ_FALLBACK_MAX_MSG_SIZE (2u * 1024u * 1024u)   // 2 MiB
#else
#define MIQ_FALLBACK_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

#ifndef MAX_TX_SIZE
#define MIQ_FALLBACK_MAX_TX_SIZE  (1024u * 1024u)        // 1 MiB cap for tx wire payloads
#else
#define MIQ_FALLBACK_MAX_TX_SIZE  (MAX_TX_SIZE)
#endif

#ifndef MIQ_ADDR_MAX_BATCH
#define MIQ_ADDR_MAX_BATCH 1000
#endif

// Headers-first wire constants (must match p2p.cpp)
#ifndef MIQ_HDR_WIRE_BYTES
#define MIQ_HDR_WIRE_BYTES 88            // serialized BlockHeader size on the wire
#endif
#ifndef MIQ_MAX_HEADERS_PER_MSG
#define MIQ_MAX_HEADERS_PER_MSG 2000
#endif
#ifndef MIQ_MAX_LOCATOR_HASHES
#define MIQ_MAX_LOCATOR_HASHES 32        // locator cap used by p2p.cpp
#endif

namespace miq {

// ---- local helpers ---------------------------------------------------------

static inline uint32_t rd32le(const uint8_t* p){
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}
static inline void wr32le(uint8_t* p, uint32_t v){
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

// Strict ASCII-lowercase command allowlist (zero-padded to 12 in the header)
static bool cmd_is_allowed(const std::string& c){
    static const char* k[] = {
        "version","verack","ping","pong",
        "invb","getb","getbi","block",
        "invtx","gettx","tx",
        "getaddr","addr",
        // headers-first & relay extras
        "getheaders","headers","feefilter"
    };
    for (auto* s : k) if (c == s) return true;
    return false;
}

// Per-command payload length guard (does not trust peer-supplied length blindly)
static bool length_ok_for_command(const std::string& cmd, size_t n){
    if (n > MIQ_FALLBACK_MAX_MSG_SIZE) return false;

    if (cmd == "version" || cmd == "verack" || cmd == "getaddr" ||
        cmd == "ping"    || cmd == "pong")
    {
        return n == 0;
    }

    if (cmd == "invb" || cmd == "getb" || cmd == "invtx" || cmd == "gettx"){
        return n == 32;
    }

    if (cmd == "getbi"){
        return n == 8;
    }

    if (cmd == "addr"){
        // 4 bytes per IPv4, up to MIQ_ADDR_MAX_BATCH
        return (n % 4 == 0) && (n <= (size_t)MIQ_ADDR_MAX_BATCH * 4u);
    }

    if (cmd == "block"){
        return n > 0 && n <= (size_t)MIQ_FALLBACK_MAX_BLOCK_SZ;
    }

    if (cmd == "tx"){
        // allow up to configured tx size (or fallback)
        return n > 0 && n <= (size_t)MIQ_FALLBACK_MAX_TX_SIZE;
    }

    if (cmd == "feefilter"){
        return n == 8; // uint64 min-relay (per kB)
    }

    if (cmd == "getheaders"){
        // 1 byte count (0..32), count*32 locator hashes, 32 bytes stop-hash
        // Accept any n that matches this shape & <= cap
        if (n < 33) return false;              // at least 1 + 0*32 + 32
        if ((n - 33) % 32 != 0) return false;  // (n - (1+32)) must be multiple of 32
        size_t count = (n - 33) / 32;
        if (count > MIQ_MAX_LOCATOR_HASHES) return false;
        // absolute upper bound to guard
        if (n > (size_t)(1 + MIQ_MAX_LOCATOR_HASHES*32 + 32)) return false;
        return true;
    }

    if (cmd == "headers"){
        // 2-byte count (LE), then count * 88-byte headers
        if (n < 2) return false;
        if ((n - 2) % MIQ_HDR_WIRE_BYTES != 0) return false;
        size_t count = (n - 2) / MIQ_HDR_WIRE_BYTES;
        if (count == 0 || count > MIQ_MAX_HEADERS_PER_MSG) return false;
        return true;
    }

    // Unknown command: reject
    return false;
}

// ---- public API ------------------------------------------------------------

// Wire format: command[12] (ASCII, NUL-padded) | len[4-le] | payload[len]
std::vector<uint8_t> encode_msg(const std::string& cmd_in, const std::vector<uint8_t>& payload){
    // Normalize command: lower-case, max 12 chars, ASCII
    std::string cmd = cmd_in;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c){ return (char)std::tolower(c); });

    // Safety: if not in allowlist or size invalid, emit empty vector (caller should not send)
    if (!cmd_is_allowed(cmd)) return {};
    if (!length_ok_for_command(cmd, payload.size())) return {};

    std::vector<uint8_t> out;
    out.resize(12 + 4 + payload.size());

    // cmd (12, NUL-padded)
    std::memset(out.data(), 0, 12);
    std::memcpy(out.data(), cmd.data(), std::min<size_t>(12, cmd.size()));

    // length
    wr32le(out.data() + 12, (uint32_t)payload.size());

    // payload
    if (!payload.empty()){
        std::memcpy(out.data() + 16, payload.data(), payload.size());
    }
    return out;
}

// Streaming decoder:
// - Parses a single message starting at buf[off].
// - On success: fills out, advances off to end-of-message, returns true.
// - On incomplete frame: returns false and DOES NOT change off.
// - On malformed frame (bad cmd/length): advances off by 1 (resync) and returns false.
bool decode_msg(const std::vector<uint8_t>& buf, size_t& off, NetMsg& out){
    const size_t n = buf.size();
    size_t i = off;

    // Need header
    if (n < i + 16) return false;

    // Read header
    char cmd_raw[12];
    std::memcpy(cmd_raw, buf.data() + i, 12);
    i += 12;

    uint32_t len = rd32le(buf.data() + i);
    i += 4;

    // Fast sanity: cap huge claims early
    if (len > MIQ_FALLBACK_MAX_MSG_SIZE) {
        // drop a byte to resync
        off += 1;
        return false;
    }

    // Need full payload
    if (n < i + (size_t)len) return false;

    // Canonicalize command (strip trailing NULs)
    std::string cmd(cmd_raw, cmd_raw + 12);
    size_t z = cmd.find('\0');
    if (z != std::string::npos) cmd.resize(z);
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c){ return (char)std::tolower(c); });

    // Validate command + length
    if (!cmd_is_allowed(cmd) || !length_ok_for_command(cmd, len)) {
        // Skip just this header byte-by-byte until next round; conservative
        off += 1;
        return false;
    }

    // Fill NetMsg
    std::memset(out.cmd, 0, sizeof(out.cmd));
    std::memcpy(out.cmd, cmd.data(), std::min<size_t>(sizeof(out.cmd), cmd.size()));
    out.payload.assign(buf.begin() + (i), buf.begin() + (i + len));

    // Advance consumer offset to end of this frame
    off = i + len;
    return true;
}

}
