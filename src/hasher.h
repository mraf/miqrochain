#pragma once
#include <vector>
#include <cstdint>
#include <cstddef>

namespace miq {

// Returns double-SHA256 of the ASCII header bytes (and optional salt if enabled).
// Preserves consensus semantics; only the implementation is accelerated.
std::vector<uint8_t> salted_header_hash(const std::vector<uint8_t>& header);

// -------- Midstate accelerator for miners (safe helper) --------
// PowHasher precomputes SHA-256 state for the fixed prefix "<ver>:<time>:<bits>:"
// (and optional salt if MIQ_POW_SALT is defined). Then per nonce we only
// append the nonce ASCII digits (and salt, if configured) and finalize.
class PowHasher {
public:
    // prefix points to the bytes of "<ver>:<time>:<bits>:" (no nonce)
    PowHasher(const uint8_t* prefix, size_t prefix_len);

    // Computes double-SHA256 of prefix || <nonce_ascii> [|| salt]
    // and writes a 32-byte big-endian digest to out32.
    void hash_nonce_ascii(const char* nonce_ascii, size_t nlen, uint8_t out32[32]) const;

    // Portable one-shot double-SHA256 (exposed so salted_header_hash can use it)
    static void dsha256(const uint8_t* data, size_t len, uint8_t out32[32]);

private:
    // Internal streaming SHA-256 context (portable)
    struct Ctx {
        uint32_t H[8];
        uint64_t total;      // total bytes processed
        uint8_t  buf[64];
        size_t   blen;       // bytes in buf
    };

    Ctx base_;              // state after processing prefix (and nothing else)
    // If a salt is configured, we append it after the nonce to match salted_header_hash semantics.
    static void ctx_init(Ctx& c);
    static void ctx_update(Ctx& c, const uint8_t* p, size_t n);
    static void ctx_final(const Ctx& c_in, uint8_t out32[32]); // takes a copy so base_ stays intact

    // Salt append (compiled out if not defined)
    static void append_salt(std::vector<uint8_t>& v);
    static void append_salt_ctx(Ctx& c); // streaming append
};

struct FastSha256Ctx {
    uint32_t H[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   blen;
};

void fastsha_init(FastSha256Ctx& c);
void fastsha_update(FastSha256Ctx& c, const uint8_t* p, size_t n);
void fastsha_final_copy(const FastSha256Ctx& c_in, uint8_t out32[32]);
// Double-SHA256 using a precomputed base (e.g., first 80 bytes of a header).
void dsha256_from_base(const FastSha256Ctx& base, const uint8_t* suffix, size_t n, uint8_t out32[32]);

} // namespace miq
