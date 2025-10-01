#include <vector>
#include <string>
#include <array>
#include <mutex>
#include <cstring>

#include "crypto/ecdsa_iface.h"
#include "crypto/secure_random.h"

#include <secp256k1.h>

namespace miq { namespace crypto { namespace ECDSA {

static secp256k1_context* g_ctx = nullptr;
static std::once_flag g_once;

static void init_ctx() {
    std::call_once(g_once, []{
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        uint8_t seed[32];
        // Use your OS RNG wrapper
        ::miq::secure_random(seed, sizeof(seed), nullptr);
        (void)secp256k1_context_randomize(g_ctx, seed);
        std::memset(seed, 0, sizeof(seed));
    });
}

static inline bool is_valid_priv(const std::vector<uint8_t>& sk) {
    return sk.size() == 32 && secp256k1_ec_seckey_verify(g_ctx, sk.data()) == 1;
}

bool generate_priv(std::vector<uint8_t>& out32) {
    init_ctx();
    out32.resize(32);
    do {
        ::miq::secure_random(out32.data(), out32.size(), nullptr);
    } while (!is_valid_priv(out32));
    return true;
}

bool derive_pub(const std::vector<uint8_t>& priv32, std::vector<uint8_t>& out33) {
    init_ctx();
    if (!is_valid_priv(priv32)) return false;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(g_ctx, &pk, priv32.data()) != 1) return false;

    size_t outlen = 33;
    out33.resize(33);
    if (secp256k1_ec_pubkey_serialize(g_ctx, out33.data(), &outlen, &pk, SECP256K1_EC_COMPRESSED) != 1) return false;
    return outlen == 33;
}

bool sign(const std::vector<uint8_t>& priv32,
          const std::vector<uint8_t>& msg32,
          std::vector<uint8_t>& sig64) {
    init_ctx();
    if (!is_valid_priv(priv32)) return false;
    if (msg32.size() != 32) return false;

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_sign(g_ctx, &sig, msg32.data(), priv32.data(), nullptr, nullptr) != 1) return false;

    // Low-S normalize for policy compatibility
    secp256k1_ecdsa_signature sig_low;
    secp256k1_ecdsa_signature_normalize(g_ctx, &sig_low, &sig);

    sig64.resize(64);
    return secp256k1_ecdsa_signature_serialize_compact(g_ctx, sig64.data(), &sig_low) == 1;
}

static bool parse_pubkey_any(const std::vector<uint8_t>& pub, secp256k1_pubkey* out) {
    // Accept 33-byte compressed, 65-byte uncompressed, and 64-byte raw (x||y without 0x04)
    if (secp256k1_ec_pubkey_parse(g_ctx, out, pub.data(), pub.size()) == 1) return true;
    if (pub.size() == 64) {
        uint8_t u[65];
        u[0] = 0x04;
        std::memcpy(u + 1, pub.data(), 64);
        return secp256k1_ec_pubkey_parse(g_ctx, out, u, sizeof(u)) == 1;
    }
    return false;
}

bool verify(const std::vector<uint8_t>& pubkey,
            const std::vector<uint8_t>& msg32,
            const std::vector<uint8_t>& sig64) {
    init_ctx();
    if (msg32.size() != 32 || sig64.size() != 64) return false;

    secp256k1_pubkey pk;
    if (!parse_pubkey_any(pubkey, &pk)) return false;

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_compact(g_ctx, &sig, sig64.data()) != 1) return false;

    return secp256k1_ecdsa_verify(g_ctx, &sig, msg32.data(), &pk) == 1;
}

std::string backend() {
    return "libsecp256k1";
}

}}}
