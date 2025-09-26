// src/crypto/ecdsa_uECC.cpp
#include "crypto/ecdsa_iface.h"

#include <vector>
#include <cstdint>
#include <cstring>

// micro-ecc (brought in via CMake)
extern "C" {
#include "uECC.h"
}

namespace miq {
namespace crypto {

// secp256k1 order N (big-endian)
static const uint8_t SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,
    0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
    0x8C,0xD0,0x36,0x41,0x41,0x00,0x00,0x00
};
// N/2 (big-endian)
static const uint8_t SECP256K1_N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0xFF,0xFF,0xFF,0xFF,0xFF,0x5D,0x57,0x6E,
    0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,
    0x46,0x68,0x1B,0x20,0xA0,0x80,0x00,0x00
};

static inline int cmp_be_32(const uint8_t* a, const uint8_t* b) {
    // big-endian compare (32 bytes)
    return std::memcmp(a, b, 32);
}
static inline bool is_zero32(const uint8_t* x){
    uint32_t acc = 0;
    for(int i=0;i<32;i++) acc |= x[i];
    return acc==0;
}
static inline void be_sub_32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]){
    // out = a - b  (big-endian)
    int borrow = 0;
    for(int i=31;i>=0;--i){
        int v = (int)a[i] - (int)b[i] - borrow;
        borrow = (v<0);
        out[i] = (uint8_t)(v + (borrow?256:0));
    }
}

// Normalize pubkey to 64-byte uncompressed XY for micro-ecc
// Accepts 33-byte (02/03 + X) or 65-byte (04 + X + Y); returns false on invalid.
static bool normalize_pubkey_xy(const std::vector<uint8_t>& in, uint8_t out_xy[64]){
    const uECC_Curve curve = uECC_secp256k1();
    if(in.size()==33 && (in[0]==0x02 || in[0]==0x03)) {
        // compressed
        if(!uECC_decompress(in.data(), out_xy, curve)) return false;
        return uECC_valid_public_key(out_xy, curve) == 1;
    }
    if(in.size()==65 && in[0]==0x04) {
        // uncompressed with prefix 0x04
        std::memcpy(out_xy, &in[1], 64);
        return uECC_valid_public_key(out_xy, curve) == 1;
    }
    if(in.size()==64){
        // raw XY
        std::memcpy(out_xy, in.data(), 64);
        return uECC_valid_public_key(out_xy, curve) == 1;
    }
    return false;
}

// Low-S check + range checks for r,s
static bool check_sig_canonical(const uint8_t sig64[64]){
    const uint8_t* r = sig64 + 0;
    const uint8_t* s = sig64 + 32;

    // r,s != 0
    if (is_zero32(r) || is_zero32(s)) return false;

    // r,s < N
    if (cmp_be_32(r, SECP256K1_N) >= 0) return false;
    if (cmp_be_32(s, SECP256K1_N) >= 0) return false;

    // Enforce Low-S: s <= N/2
    if (cmp_be_32(s, SECP256K1_N_HALF) > 0) return false;

    return true;
}

bool ECDSA::verify(const std::vector<uint8_t>& pubkey,
                   const std::vector<uint8_t>& msg32,
                   const std::vector<uint8_t>& sig64)
{
    if (msg32.size() != 32) return false;
    if (sig64.size() != 64) return false;

    // Canonical (low-S, ranges)
    if (!check_sig_canonical(sig64.data())) return false;

    uint8_t pub_xy[64];
    if (!normalize_pubkey_xy(pubkey, pub_xy)) return false;

    const uECC_Curve curve = uECC_secp256k1();
    // micro-ecc expects (pubXY, msg, msg_len, sig(r||s))
    int ok = uECC_verify(pub_xy, msg32.data(), 32, sig64.data(), curve);
    return ok == 1;
}

// Optional: keep sign() low-S if you use it anywhere (miq-keygen / wallet)
bool ECDSA::sign(const std::vector<uint8_t>& priv32,
                 const std::vector<uint8_t>& msg32,
                 std::vector<uint8_t>& sig64_out)
{
    if (priv32.size()!=32 || msg32.size()!=32) return false;
    sig64_out.assign(64, 0);

    const uECC_Curve curve = uECC_secp256k1();
    if (!uECC_valid_private_key(priv32.data(), curve)) return false;

    if (uECC_sign(priv32.data(), msg32.data(), 32, sig64_out.data(), curve) != 1) {
        return false;
    }

    // Ensure low-S: if s > N/2, replace s with N - s
    uint8_t* s = sig64_out.data() + 32;
    if (cmp_be_32(s, SECP256K1_N_HALF) > 0) {
        uint8_t s_fixed[32];
        be_sub_32(s_fixed, SECP256K1_N, s); // s' = N - s
        std::memcpy(s, s_fixed, 32);
    }
    // micro-ecc already returns r in [1..N-1] with overwhelming probability,
    // but we could re-sign on r==0/s==0 extremely-rare cases; skip for simplicity.
    return true;
}

} // namespace crypto
} // namespace miq
