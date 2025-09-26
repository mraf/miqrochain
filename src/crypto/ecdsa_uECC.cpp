#include "ecdsa_uECC.h"
#include "sha256.h" // (not strictly needed here but harmless if other code includes us)
#include <uECC.h>

#include <vector>
#include <cstring>
#include <random>
#include <atomic>
#include <mutex>

namespace miq { namespace crypto {

// -----------------------------------------------------------------------------
// RNG for micro-ecc (default, non-deterministic)
static int uecc_rng(uint8_t* dest, unsigned size) {
    // std::random_device generally maps to OS CSPRNG on Linux/macOS/Windows
    std::random_device rd;
    for (unsigned i = 0; i < size; ++i) dest[i] = static_cast<uint8_t>(rd());
    return 1;
}

// Install the default RNG once
static void ensure_rng_once() {
    static std::atomic<bool> done{false};
    bool expected = false;
    if (done.compare_exchange_strong(expected, true)) {
        uECC_set_rng(&uecc_rng);
    }
}

// -----------------------------------------------------------------------------
// Deterministic RNG used ONLY to force uECC_make_key() to use the caller's priv
// We protect set/restore with a mutex so other threads won't see the swap.
static std::mutex g_rng_mx;
struct ForcedRngCtx {
    const uint8_t* ptr;
    unsigned       len;
};
static thread_local ForcedRngCtx g_forced{nullptr, 0};

static int uecc_forced_rng(uint8_t* dest, unsigned size) {
    if (!g_forced.ptr || g_forced.len == 0) return 0;
    // micro-ecc typically asks for 32 bytes (curve size). Provide exactly our priv.
    const unsigned n = (size <= g_forced.len) ? size : g_forced.len;
    std::memcpy(dest, g_forced.ptr, n);
    // If it asks for more, repeat the last byte (benign; won't be used in our path).
    for (unsigned i = n; i < size; ++i) dest[i] = g_forced.ptr[g_forced.len - 1];
    return 1;
}

// Compress/uncompress wrappers (micro-ecc core uses 64-byte uncompressed)
static void compress64to33(const uint8_t* pub64, std::vector<uint8_t>& out33){
    out33.resize(33);
    uECC_compress(pub64, out33.data(), uECC_secp256k1());
}
static bool decompress33to64(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64){
    out64.resize(64);
    return uECC_decompress(in33.data(), out64.data(), uECC_secp256k1())==1;
}

// -----------------------------------------------------------------------------
// ECDSA_uECC backend (secp256k1)

// Generate a new private key (32 bytes) and throw away the public here.
// (Keygen is not used in consensus; this is just a convenience.)
bool ECDSA_uECC::generate_priv(std::vector<uint8_t>& out){
    ensure_rng_once();
    out.resize(32);
    std::vector<uint8_t> pub64(64);
    if(!uECC_make_key(pub64.data(), out.data(), uECC_secp256k1())) return false;
    return true;
}

// Derive public key (33B compressed) from a given 32B private key.
// This version works on ALL micro-ecc versions (no uECC_compute_public_key needed):
//  1) Validate 'priv' with uECC_valid_private_key()
//  2) Temporarily set RNG to a forced provider that returns 'priv'
//  3) Call uECC_make_key(tmpPub64, tmpPrivOut, curve)  -> computes pub = priv*G
//  4) Restore the default RNG immediately
bool ECDSA_uECC::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){
    if(priv.size()!=32) return false;

    // Reject invalid scalars (prevents make_key from looping)
    if(uECC_valid_private_key(priv.data(), uECC_secp256k1()) != 1) return false;

    std::lock_guard<std::mutex> lock(g_rng_mx);

    // Swap to forced RNG
    g_forced = { priv.data(), 32 };
    uECC_set_rng(&uecc_forced_rng);

    std::vector<uint8_t> pub64(64), tmp_priv(32);
    const int ok = uECC_make_key(pub64.data(), tmp_priv.data(), uECC_secp256k1());

    // Restore default RNG immediately
    g_forced = { nullptr, 0 };
    ensure_rng_once(); // sets uecc_rng

    if(ok != 1) return false;
    compress64to33(pub64.data(), out33);
    return true;
}

// Sign 32-byte message hash with 32-byte private key; returns 64-byte (r||s)
bool ECDSA_uECC::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){
    if(priv.size()!=32 || msg32.size()!=32) return false;
    ensure_rng_once(); // required by uECC_sign()
    sig64.resize(64);
    return uECC_sign(priv.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1()) == 1;
}

// Verify 64-byte signature against 33-byte compressed public key
bool ECDSA_uECC::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){
    if(pub33.size()!=33 || msg32.size()!=32 || sig64.size()!=64) return false;
    std::vector<uint8_t> pub64; if(!decompress33to64(pub33, pub64)) return false;
    return uECC_verify(pub64.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1())==1;
}

// ---- Wire into the generic iface -------------------------------------------
bool ECDSA::generate_priv(std::vector<uint8_t>& out){ return ECDSA_uECC::generate_priv(out); }
bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){ return ECDSA_uECC::derive_pub(priv, out33); }
bool ECDSA::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){ return ECDSA_uECC::sign(priv, msg32, sig64); }
bool ECDSA::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){ return ECDSA_uECC::verify(pub33, msg32, sig64); }
std::string ECDSA::backend(){ return "micro-ecc (secp256k1)"; }

}} // namespace miq::crypto
