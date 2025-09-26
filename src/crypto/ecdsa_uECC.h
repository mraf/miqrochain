#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include "ecdsa_iface.h"

// Thin, header-only bridge for helpers used by the micro-ecc backend.
// NO definitions of ECDSA’s static methods live here (to avoid ODR/linker issues).

namespace miq { namespace crypto {

/**
 * Convert a compressed (33-byte) or uncompressed (65-byte, 0x04||X||Y)
 * secp256k1 public key into raw XY (64 bytes). Returns true on success.
 * For compressed keys, this calls uECC_decompress() in the .cpp.
 */
bool normalize_pubkey_xy(const std::vector<uint8_t>& pub, uint8_t out_xy[64]);

}} // namespace miq::crypto
