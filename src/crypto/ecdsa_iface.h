#include "ecdsa_iface.h"
#include <vector>
#include <string>

namespace crypto {
namespace ECDSA {

// Forward decls implemented in the backend .cpps
bool secp_derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& pub);
bool secp_sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64);

bool uecc_derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& pub);
bool uecc_sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64);

bool derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& pub) {
#ifdef MIQ_USE_SECP256K1
    return secp_derive_pub(priv, pub);
#else
    return uecc_derive_pub(priv, pub);
#endif
}

bool sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64) {
#ifdef MIQ_USE_SECP256K1
    return secp_sign(priv, msg32, sig64);
#else
    return uecc_sign(priv, msg32, sig64);
#endif
}

std::string backend() {
#ifdef MIQ_USE_SECP256K1
    return "libsecp256k1";
#else
    return "micro-ecc";
#endif
}

}
}
