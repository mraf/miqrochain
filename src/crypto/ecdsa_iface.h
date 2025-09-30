// src/crypto/ecdsa_iface.h
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace crypto {
namespace ECDSA {

// Derive compressed 33-byte pubkey from 32-byte privkey.
bool derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out_pub33);

// Sign 32-byte message hash. Returns 64-byte (r||s) signature.
bool sign(const std::vector<uint8_t>& priv,
          const std::vector<uint8_t>& msg32,
          std::vector<uint8_t>& out_sig64);

// Human-readable backend name.
std::string backend();

}
}
