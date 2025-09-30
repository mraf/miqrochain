#pragma once
#include <vector>
#include <string>
#include <cstdint>

namespace miq { namespace crypto { namespace ECDSA {

// 32-byte private key
bool generate_priv(std::vector<uint8_t>& out32);

// Derive 33-byte compressed public key from 32-byte priv
bool derive_pub(const std::vector<uint8_t>& priv32, std::vector<uint8_t>& out33);

// Sign 32-byte message hash, return 64-byte (r||s) (low-S normalized)
bool sign(const std::vector<uint8_t>& priv32,
          const std::vector<uint8_t>& msg32,
          std::vector<uint8_t>& sig64);

// Verify (accepts 33-byte compressed or 64-byte uncompressed pubkey)
bool verify(const std::vector<uint8_t>& pubkey,
            const std::vector<uint8_t>& msg32,
            const std::vector<uint8_t>& sig64);

// Human-readable backend name
std::string backend();

}}}
