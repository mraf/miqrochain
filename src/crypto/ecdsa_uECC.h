#pragma once
#include <vector>
#include <cstdint>

namespace miq {
namespace crypto {

// Backend implemented with micro-ecc.
// NOTE: This header has DECLARATIONS ONLY. No inline definitions here.
struct ECDSA_uECC {
    // Generate a 32-byte private key in [1..N-1] using OS RNG.
    static bool generate_priv(std::vector<uint8_t>& out32);

    // Derive compressed public key (33 bytes) from 32-byte private key.
    static bool derive_pub(const std::vector<uint8_t>& priv32,
                           std::vector<uint8_t>& out33);

    // RFC6979-like determinism is handled by micro-ecc if configured; otherwise uses RNG set via uECC_set_rng.
    // Enforces low-S normalization before returning (r||s), 64 bytes.
    static bool sign(const std::vector<uint8_t>& priv32,
                     const std::vector<uint8_t>& msg32,
                     std::vector<uint8_t>& sig64);

    // Accepts 33-byte (compressed), 65-byte (uncompressed 0x04+XY), or 64-byte raw XY public key.
    // Requires msg32 == 32 bytes; sig64 == 64 bytes (r||s). Enforces canonical low-S.
    static bool verify(const std::vector<uint8_t>& pubkey,
                       const std::vector<uint8_t>& msg32,
                       const std::vector<uint8_t>& sig64);
};

} // namespace crypto
} // namespace miq
