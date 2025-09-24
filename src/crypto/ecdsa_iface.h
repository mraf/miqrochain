
#pragma once
#include <vector>
#include <cstdint>
#include <string>
namespace miq { namespace crypto {
// Interface for ECDSA-like backends. Provide a drop-in implementation using micro-ecc (BSD-2) or ed25519-donna (public domain).
struct ECDSA {
    // Generate a private key (32 bytes). Returns true on success.
    static bool generate_priv(std::vector<uint8_t>& out);
    // Derive public key (compressed) from private key. Returns pubkey (33 bytes) into out.
    static bool derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33);
    // Sign msg (32-byte hash) with priv, returning signature (64 bytes r||s or Ed25519 signature length 64).
    static bool sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64);
    // Verify msg with pubkey and signature.
    static bool verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64);
    // Name of backend
    static std::string backend();
};
}} // namespace
