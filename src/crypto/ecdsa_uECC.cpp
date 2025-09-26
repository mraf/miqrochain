#include "ecdsa_uECC.h"
#include "ecdsa_iface.h"
#include <uECC.h>

#include <vector>
#include <cstring>
#include <random>
#include <atomic>
#include <mutex>
#include <cstdint>

namespace miq { namespace crypto {

// -----------------------------------------------------------------------------
// Default RNG for micro-ecc (OS-backed)
static int uecc_rng(uint8_t* dest, unsigned size) {
    std::random_device rd;
    for (unsigned i = 0; i < size; ++i) dest[i] = static_cast<uint8_t>(rd());
    return 1;
}

// Set default RNG exactly once (first use)
static void ensure_rng_once() {
    static std::atomic<bool> done{false};
    bool expected = false;
    if (done.compare_exchange_strong(expected, true)) {
        uECC_set_rng(&uecc_rng);
    }
}

// -----------------------------------------------------------------------------
// Bounded-forced RNG: try provided priv once; otherwise OS RNG.
// Lets us compute pub = priv·G via uECC_make_key() without uECC_compute_public_key.
static std::mutex g_rng_mx;
static thread_local const uint8_t* g_try_priv = nullptr;
static thread_local unsigned       g_try_len  = 0;
static thread_local bool           g_tried    = false;

static int uecc_rng_try_then_os(uint8_t* dest, unsigned size) {
    if (!g_tried && g_try_priv && g_try_len >= size) {
        std::memcpy(dest, g_try_priv, size);
        g_tried = true;
        return 1;
    }
    return uecc_rng(dest, size);
}

// micro-ecc uses 64-byte uncompressed pubkeys internally
static void compress64to33(const uint8_t* pub64, std::vector<uint8_t>& out33){
    out33.resize(33);
    uECC_compress(pub64, out33.data(), uECC_secp256k1());
}

static bool decompress33to64(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64){
    out64.resize(64);
    // Some micro-ecc versions return void here; validate afterward:
    uECC_decompress(in33.data(), out64.data(), uECC_secp256k1());
    return uECC_valid_public_key(out64.data(), uECC_secp256k1()) == 1;
}

// -----------------------------------------------------------------------------
// ECDSA_uECC backend (secp256k1)

bool ECDSA_uECC::generate_priv(std::vector<uint8_t>& out){
    ensure_rng_once();
    out.resize(32);
    std::vector<uint8_t> pub64(64);
    return uECC_make_key(pub64.data(), out.data(), uECC_secp256k1()) == 1;
}

// Derive public key (33B compressed) from a given 32B private key.
// Strategy:
//  - Temporarily set RNG to "try provided priv once, else OS RNG".
//  - Call uECC_make_key(); if priv is valid, it succeeds with pub=priv·G and tmp_priv==priv.
//  - If priv is invalid, the lib picks a random key; we detect mismatch and fail.
bool ECDSA_uECC::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){
    if(priv.size()!=32) return false;

    std::lock_guard<std::mutex> lock(g_rng_mx);

    // Install bounded RNG
    const uint8_t* save_ptr = g_try_priv;
    unsigned       save_len = g_try_len;
    bool           save_tr  = g_tried;
    g_try_priv = priv.data();
    g_try_len  = 32;
    g_tried    = false;
    uECC_set_rng(&uecc_rng_try_then_os);

    std::vector<uint8_t> pub64(64), tmp_priv(32);
    const int ok = uECC_make_key(pub64.data(), tmp_priv.data(), uECC_secp256k1());

    // Restore default RNG immediately (do not rely on ensure_rng_once here)
    g_try_priv = save_ptr; g_try_len = save_len; g_tried = save_tr;
    uECC_set_rng(&uecc_rng);

    if(ok != 1) return false;

    // Confirm the library used our exact private key
    if(std::memcmp(tmp_priv.data(), priv.data(), 32) != 0){
        return false; // provided private key is invalid for the curve
    }

    compress64to33(pub64.data(), out33);
    return true;
}

bool ECDSA_uECC::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){
    if(priv.size()!=32 || msg32.size()!=32) return false;
    // Ensure a sane RNG (not strictly needed if derive_pub already restored it)
    ensure_rng_once();
    sig64.resize(64);
    return uECC_sign(priv.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1()) == 1;
}

bool ECDSA_uECC::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){
    if(pub33.size()!=33 || msg32.size()!=32 || sig64.size()!=64) return false;
    std::vector<uint8_t> pub64; if(!decompress33to64(pub33, pub64)) return false;
    return uECC_verify(pub64.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1()) == 1;
}

// ---- Wire into the generic iface -------------------------------------------
bool ECDSA::generate_priv(std::vector<uint8_t>& out){ return ECDSA_uECC::generate_priv(out); }
bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){ return ECDSA_uECC::derive_pub(priv, out33); }
bool ECDSA::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){ return ECDSA_uECC::sign(priv, msg32, sig64); }
bool ECDSA::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){ return ECDSA_uECC::verify(pub33, msg32, sig64); }
std::string ECDSA::backend(){ return "micro-ecc (secp256k1)"; }

}} // namespace miq::crypto
