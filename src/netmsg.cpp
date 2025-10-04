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
#  if __has_include("sha256.h")
#    include "sha256.h"
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

static inline uint32_t dsha256_4(const uint8_t* data, size_t n) {
#if __has_include("sha256.h")
    uint8_t h[32];
    {
        SHA256 a; a.update(data, n); a.final(h);
        SHA256 b; b.update(h, 32); b.final(h);
    }
    // First 4 bytes as LE integer on the wire (same as Bitcoin)
    return (uint32_t(h[0])      )
         | (uint32_t(h[1]) <<  8)
         | (uint32_t(h[2]) << 16)
         | (uint32_t(h[3]) << 24);
#else
    // Fallback (should never happen): trivial sum; NOT secure, but keeps build green
    uint32_t x = 0;
    for (size_t i=0;i<n;i++) x = (x * 131u) + data[i];
    return x;
#endif
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

    // verack/getaddr/ping/pong must be empty
    if (cmd == "verack" || cmd == "getaddr" || cmd == "ping" || cmd == "pong") {
        return n == 0;
    }

    // version: accept legacy zero-payload and small payloads (interop)
    if (cmd == "version") {
        return n <= 24; // allow 0..24 bytes
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

// NEW wire format: magic(4) | cmd[12] | len[4-le] | checksum[4] | payload
// Legacy format (accepted on decode): cmd[12] | len[4-le] | payload
std::vector<uint8_t> encode_msg(const std::string& cmd_in, const std::vector<uint8_t>& payload){
    // Normalize command: lower-case, max 12 chars, ASCII
    std::string cmd = cmd_in;
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c){ return (char)std::tolower(c); });

    // Safety: if not in allowlist or size invalid, emit empty vector (caller should not send)
    if (!cmd_is_allowed(cmd)) return {};
    if (!length_ok_for_command(cmd, payload.size())) return {};

#if MIQ_WIRE_LEGACY_SEND
    // ---- LEGACY ENCODING: cmd[12] | len[4] | payload ----
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
#else
    // ---- NEW ENCODING: magic(4) | cmd(12) | len(4) | csum(4) | payload ----
    std::vector<uint8_t> out;
    out.resize(4 + 12 + 4 + 4 + payload.size()); // magic + cmd + len + csum + payload

    // magic (big endian bytes of miq::MAGIC)
    std::memcpy(out.data() + 0,  miq::MAGIC_BE, 4);

    // cmd (12, NUL-padded)
    std::memset(out.data() + 4, 0, 12);
    std::memcpy(out.data() + 4, cmd.data(), std::min<size_t>(12, cmd.size()));

    // length
    wr32le(out.data() + 16, (uint32_t)payload.size());

    // checksum of payload (double SHA256 first 4 bytes, LE)
    uint32_t csum = dsha256_4(payload.data(), payload.size());
    wr32le(out.data() + 20, csum);

    // payload
    if (!payload.empty()){
        std::memcpy(out.data() + 24, payload.data(), payload.size());
    }
    return out;
#endif
}

// Streaming decoder:
// - Parses a single message starting at buf[off].
// - Accepts new framed or legacy messages.
// - On success: fills out, advances off, returns true.
// - On incomplete frame: returns false and DOES NOT change off.
// - On malformed frame: advances off by 1 (resync) and returns false.
bool decode_msg(const std::vector<uint8_t>& buf, size_t& off, NetMsg& out){
    const size_t n = buf.size();
    size_t i = off;

    // Need at least minimal legacy header
    if (n < i + 16) return false;

    // Decide whether this looks like NEW or LEGACY by checking magic
    bool looks_new = false;
    if (n >= i + 24) {
        // Compare first 4 bytes to MAGIC
        looks_new = (std::memcmp(buf.data() + i, miq::MAGIC_BE, 4) == 0);
    }

    if (looks_new) {
        // NEW: magic(4) | cmd(12) | len(4) | csum(4) | payload
        if (n < i + 24) return false;

        // header fields
        char cmd_raw[12];
        std::memcpy(cmd_raw, buf.data() + i + 4, 12);
        uint32_t len = rd32le(buf.data() + i + 16);
        uint32_t csum = rd32le(buf.data() + i + 20);

        // Fast sanity: cap huge claims early
        if (len > MIQ_FALLBACK_MAX_MSG_SIZE) {
            off += 1;
            return false;
        }

        // Need full payload
        if (n < i + 24 + (size_t)len) return false;

        // Canonicalize command (strip trailing NULs)
        std::string cmd(cmd_raw, cmd_raw + 12);
        size_t z = cmd.find('\0');
        if (z != std::string::npos) cmd.resize(z);
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c){ return (char)std::tolower(c); });

        // Validate command + length
        if (!cmd_is_allowed(cmd) || !length_ok_for_command(cmd, len)) {
            off += 1;
            return false;
        }

        // Checksum
        const uint8_t* pay = buf.data() + i + 24;
        if (csum != dsha256_4(pay, len)) {
            off += 1;
            return false;
        }

        // Fill NetMsg
        std::memset(out.cmd, 0, sizeof(out.cmd));
        std::memcpy(out.cmd, cmd.data(), std::min<size_t>(sizeof(out.cmd), cmd.size()));
        out.payload.assign(pay, pay + len);

        // Advance past entire frame
        off = i + 24 + len;
        return true;
    }

    // LEGACY path: cmd[12] | len[4] | payload
    {
        // Need full legacy header
        if (n < i + 16) return false;

        // Read header
        char cmd_raw[12];
        std::memcpy(cmd_raw, buf.data() + i, 12);
        uint32_t len = rd32le(buf.data() + i + 12);

        // Fast sanity: cap huge claims early
        if (len > MIQ_FALLBACK_MAX_MSG_SIZE) {
            off += 1;
            return false;
        }

        // Need full payload
        if (n < i + 16 + (size_t)len) return false;

        // Canonicalize command
        std::string cmd(cmd_raw, cmd_raw + 12);
        size_t z = cmd.find('\0');
        if (z != std::string::npos) cmd.resize(z);
        std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](unsigned char c){ return (char)std::tolower(c); });

        // Validate
        if (!cmd_is_allowed(cmd) || !length_ok_for_command(cmd, len)) {
            off += 1;
            return false;
        }

        // Fill
        std::memset(out.cmd, 0, sizeof(out.cmd));
        std::memcpy(out.cmd, cmd.data(), std::min<size_t>(sizeof(out.cmd), cmd.size()));
        out.payload.assign(buf.begin() + (i + 16), buf.begin() + (i + 16 + len));

        // Advance
        off = i + 16 + len;
        return true;
    }
}

}
