// src/crypto/ecdsa_libsecp256k1.cpp
#include <array>
#include <vector>
#include <mutex>
#include <cstring>
#include "crypto/ecdsa_iface.h"        // keep your existing iface unchanged
#include "crypto/secure_random.h"      // your OS RNG wrapper (BCryptGenRandom / /dev/urandom)
#include <secp256k1.h>

namespace miq::crypto {

static secp256k1_context* g_ctx = nullptr;
static std::once_flag g_once;

static void init_ctx() {
    std::call_once(g_once, []{
        g_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
        uint8_t seed[32];
        secure_random_bytes(seed, sizeof(seed));
        secp256k1_context_randomize(g_ctx, seed);
        std::memset(seed, 0, sizeof(seed));
    });
}

static inline bool is_valid_priv(const std::vector<uint8_t>& sk) {
    return sk.size() == 32 && secp256k1_ec_seckey_verify(g_ctx, sk.data()) == 1;
}

bool ECDSA::generate_priv(std::vector<uint8_t>& out32) {
    init_ctx();
    out32.resize(32);
    do {
        secure_random_bytes(out32.data(), 32);
    } while (!is_valid_priv(out32));
    return true;
}

bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33) {
    init_ctx();
    if (!is_valid_priv(priv)) return false;

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(g_ctx, &pk, priv.data()) != 1) return false;

    size_t outlen = 33;
    out33.resize(33);
    if (secp256k1_ec_pubkey_serialize(g_ctx, out33.data(), &outlen, &pk, SECP256K1_EC_COMPRESSED) != 1) return false;
    return outlen == 33;
}

// --- Compact (64B) signature path ------------------------------------------
bool ECDSA::sign_compact(const uint8_t msg32[32], const std::vector<uint8_t>& priv,
                         std::array<uint8_t,64>& sig64) {
    init_ctx();
    if (!is_valid_priv(priv)) return false;

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_sign(g_ctx, &sig, msg32, priv.data(), nullptr, nullptr) != 1) return false;

    // Low-S normalize
    secp256k1_ecdsa_signature sig_low;
    secp256k1_ecdsa_signature_normalize(g_ctx, &sig_low, &sig);

    return secp256k1_ecdsa_signature_serialize_compact(g_ctx, sig64.data(), &sig_low) == 1;
}

bool ECDSA::verify_compact(const uint8_t msg32[32], const std::vector<uint8_t>& pubkey,
                           const std::array<uint8_t,64>& sig64) {
    init_ctx();

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(g_ctx, &pk, pubkey.data(), pubkey.size()) != 1) return false;

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_compact(g_ctx, &sig, sig64.data()) != 1) return false;

    return secp256k1_ecdsa_verify(g_ctx, &sig, msg32, &pk) == 1;
}

// --- DER signature helpers (if your tx path uses DER) -----------------------
bool ECDSA::sign_der(const uint8_t msg32[32], const std::vector<uint8_t>& priv,
                     std::vector<uint8_t>& der_out) {
    init_ctx();
    if (!is_valid_priv(priv)) return false;

    secp256k1_ecdsa_signature sig, sig_low;
    if (secp256k1_ecdsa_sign(g_ctx, &sig, msg32, priv.data(), nullptr, nullptr) != 1) return false;
    secp256k1_ecdsa_signature_normalize(g_ctx, &sig_low, &sig);

    // Worst-case DER is 72 bytes
    der_out.resize(72);
    size_t len = der_out.size();
    if (secp256k1_ecdsa_signature_serialize_der(g_ctx, der_out.data(), &len, &sig_low) != 1) return false;
    der_out.resize(len);
    return true;
}

bool ECDSA::verify_der(const uint8_t msg32[32], const std::vector<uint8_t>& pubkey,
                       const std::vector<uint8_t>& der) {
    init_ctx();

    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_parse(g_ctx, &pk, pubkey.data(), pubkey.size()) != 1) return false;

    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_der(g_ctx, &sig, der.data(), der.size()) != 1) return false;

    return secp256k1_ecdsa_verify(g_ctx, &sig, msg32, &pk) == 1;
}

const char* ECDSA::backend() {
    return "libsecp256k1";
}

}
