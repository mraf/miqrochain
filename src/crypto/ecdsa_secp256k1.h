
#pragma once
#include <vector>
#include <cstdint>
#include <string>
namespace miq { namespace crypto {
struct Secp256k1 {
    static bool generate_priv(std::vector<uint8_t>& out32);
    static bool derive_pub_uncompressed(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out64);
    static bool compress_pub(const std::vector<uint8_t>& pub64, std::vector<uint8_t>& out33);
    static bool decompress_pub(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64);
    static bool sign_rfc6979(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64);
    static bool verify(const std::vector<uint8_t>& pub64, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64);
    static std::string name();
};
}} // ns
