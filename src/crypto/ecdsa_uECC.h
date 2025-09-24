
#pragma once
#include "ecdsa_iface.h"
#include <vector>
#include <cstdint>
namespace miq { namespace crypto {
struct ECDSA_uECC {
    static bool generate_priv(std::vector<uint8_t>& out);
    static bool derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33);
    static bool sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64);
    static bool verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64);
    static std::string backend(){ return "micro-ecc compatible (secp256k1, RFC6979)"; }
};
}} // ns
