#include "ecdsa_uECC.h"
#include "../../vendor/microecc/uECC.h"
#include "../sha256.h"

#include <vector>
#include <cstring>
#include <random>
#include <atomic>

namespace miq { namespace crypto {

// ---- micro-ecc helpers -----------------------------------------------------

// RNG adapter for micro-ecc (non-deterministic signing).
// Uses std::random_device which maps to a cryptographic source on major platforms.
static int uecc_rng(uint8_t* dest, unsigned size) {
    std::random_device rd;
    for (unsigned i = 0; i < size; ++i) dest[i] = static_cast<uint8_t>(rd());
    return 1;
}

static void ensure_rng_once() {
    static std::atomic<bool> done{false};
    bool expected = false;
    if (done.compare_exchange_strong(expected, true)) {
        uECC_set_rng(&uecc_rng);
    }
}

// Compress/uncompress wrappers (micro-ecc works with uncompressed 64B pub)
static void compress64to33(const uint8_t* pub64, std::vector<uint8_t>& out33){
    out33.resize(33);
    uECC_compress(pub64, out33.data(), uECC_secp256k1());
}
static bool decompress33to64(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64){
    out64.resize(64);
    return uECC_decompress(in33.data(), out64.data(), uECC_secp256k1())==1;
}

// ---- ECDSA_uECC backend (secp256k1) ----------------------------------------

bool ECDSA_uECC::generate_priv(std::vector<uint8_t>& out){
    ensure_rng_once();
    out.resize(32);
    // uECC_make_key fills both public and private; we keep the private part.
    std::vector<uint8_t> pub(64);
    if(!uECC_make_key(pub.data(), out.data(), uECC_secp256k1())) return false;
    return true;
}

bool ECDSA_uECC::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){
    if(priv.size()!=32) return false;
    std::vector<uint8_t> pub64(64);
    // Proper derivation from private scalar (no randomness, pure scalar*G)
    if(uECC_compute_public_key(priv.data(), pub64.data(), uECC_secp256k1()) != 1) return false;
    compress64to33(pub64.data(), out33);
    return true;
}

bool ECDSA_uECC::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){
    if(priv.size()!=32 || msg32.size()!=32) return false;
    ensure_rng_once(); // required for uECC_sign()
    sig64.resize(64);
    // Sign the 32-byte message hash (already hashed by caller).
    // micro-ecc expects message_hash and its size in bytes.
    return uECC_sign(priv.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1()) == 1;
}

bool ECDSA_uECC::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){
    if(pub33.size()!=33 || msg32.size()!=32 || sig64.size()!=64) return false;
    std::vector<uint8_t> pub64; if(!decompress33to64(pub33, pub64)) return false;
    return uECC_verify(pub64.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1())==1;
}

// ---- Wire into iface -------------------------------------------------------

bool ECDSA::generate_priv(std::vector<uint8_t>& out){ return ECDSA_uECC::generate_priv(out); }
bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){ return ECDSA_uECC::derive_pub(priv, out33); }
bool ECDSA::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){ return ECDSA_uECC::sign(priv, msg32, sig64); }
bool ECDSA::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){ return ECDSA_uECC::verify(pub33, msg32, sig64); }
std::string ECDSA::backend(){ return "micro-ecc (secp256k1)"; }

}} // namespace
