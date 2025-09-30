// src/crypto/ecdsa_iface.h
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace miq {
namespace crypto {

// Unified ECDSA interface. Backends implement these static methods.
class ECDSA {
public:
    // Generate a valid 32-byte private key (secp256k1 order range).
    static bool generate_priv(std::vector<uint8_t>& out32);

    // Derive compressed 33-byte public key from 32-byte private key.
    static bool derive_pub(const std::vector<uint8_t>& priv32,
                           std::vector<uint8_t>& out_pub33);

    // Sign a 32-byte message hash. Writes 64-byte (r||s) signature.
    static bool sign(const std::vector<uint8_t>& priv32,
                     const std::vector<uint8_t>& msg32,
                     std::vector<uint8_t>& out_sig64);

    // Verify 64-byte (r||s) signature against compressed 33-byte pubkey.
    static bool verify(const std::vector<uint8_t>& pubkey33,
                       const std::vector<uint8_t>& msg32,
                       const std::vector<uint8_t>& sig64);

    // Human-readable backend name ("libsecp256k1" or "micro-ecc").
    static std::string backend();
};

}
}
