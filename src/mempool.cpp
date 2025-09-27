// src/sig_encoding.h
#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <string>
#include <algorithm>
#include <cstring>

namespace miq {

// ============================================================================
// secp256k1 constants (big-endian) — canonical sources:
//   n  = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
//   n/2= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
// ============================================================================

static inline const std::array<uint8_t,32>& Secp256k1_N() {
    static const std::array<uint8_t,32> N = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
        0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,
        0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
    };
    return N;
}

static inline const std::array<uint8_t,32>& Secp256k1_N_Half() {
    static const std::array<uint8_t,32> HALF = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,
        0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
    };
    return HALF;
}

// Back-compat raw pointer accessor (if any old code used it)
static inline const uint8_t* secp256k1_n_half_be(){
    return Secp256k1_N_Half().data();
}

// ============================================================================
// Helpers
// ============================================================================

static inline bool be_cmp_le(const uint8_t* a, const uint8_t* b, size_t n){
    // return (a <= b) for big-endian byte arrays of length n
    for (size_t i=0;i<n;i++){
        if (a[i] < b[i]) return true;
        if (a[i] > b[i]) return false;
    }
    return true; // equal
}

static inline void be_pad_to_32(const uint8_t* src, size_t len, uint8_t out32[32]){
    std::memset(out32, 0, 32);
    if (len > 32) {
        std::memcpy(out32, src + (len - 32), 32); // keep least-significant 32B
    } else {
        std::memcpy(out32 + (32 - len), src, len);
    }
}

// Strict minimal DER INTEGER rules (positive, minimal)
static inline bool der_minimal_positive_integer(const uint8_t* p, size_t len){
    if (len == 0) return false;
    if (len == 1) {
        // single byte 0x00..0x7f acceptable here; negatives are filtered upstream
        return true;
    }
    if (p[0] & 0x80) return false;              // negative
    if (p[0] == 0x00 && !(p[1] & 0x80)) return false; // unnecessary leading zero
    return true;
}

// ============================================================================
// Strict BIP66 DER parsing (no sighash mode byte here)
// 0x30 <len> 0x02 <rlen> <r> 0x02 <slen> <s>
// ============================================================================

static inline bool ParseDERSignature(const uint8_t* der, size_t der_len,
                                     /*out*/ size_t& r_off, /*out*/ size_t& r_len,
                                     /*out*/ size_t& s_off, /*out*/ size_t& s_len)
{
    r_off = r_len = s_off = s_len = 0;
    if (der_len < 8 || der_len > 72) return false;
    if (der[0] != 0x30) return false;
    if (der[1] != der_len - 2) return false;

    if (der[2] != 0x02) return false;
    uint8_t rlen = der[3];
    if (rlen == 0) return false;
    if ((size_t)4 + rlen + 2 > der_len) return false;
    r_off = 4; r_len = rlen;
    if (!der_minimal_positive_integer(der + r_off, r_len)) return false;

    size_t s_hdr = r_off + r_len;
    if (s_hdr + 2 > der_len) return false;
    if (der[s_hdr] != 0x02) return false;
    uint8_t slen = der[s_hdr + 1];
    if (slen == 0) return false;
    s_off = s_hdr + 2; s_len = slen;
    if (s_off + s_len != der_len) return false;
    if (!der_minimal_positive_integer(der + s_off, s_len)) return false;

    if (r_len > 33 || s_len > 33) return false; // at most 33 with leading 0x00
    return true;
}

static inline bool IsCanonicalDERSig(const uint8_t* der, size_t der_len){
    size_t ro=0, rl=0, so=0, sl=0;
    return ParseDERSignature(der, der_len, ro, rl, so, sl);
}

static inline bool IsLowS_RS64(const uint8_t* sig64, size_t len){
    if (len != 64) return false;
    const uint8_t* S = sig64 + 32;
    return be_cmp_le(S, Secp256k1_N_Half().data(), 32);
}

static inline bool IsLowS(const uint8_t* der, size_t der_len){
    size_t ro=0, rl=0, so=0, sl=0;
    if (!ParseDERSignature(der, der_len, ro, rl, so, sl)) return false;
    uint8_t S32[32];
    be_pad_to_32(der + so, sl, S32);
    return be_cmp_le(S32, Secp256k1_N_Half().data(), 32);
}

static inline bool IsCanonicalDERSig_LowS(const uint8_t* der, size_t der_len){
    size_t ro=0, rl=0, so=0, sl=0;
    if (!ParseDERSignature(der, der_len, ro, rl, so, sl)) return false;
    uint8_t S32[32];
    be_pad_to_32(der + so, sl, S32);
    return be_cmp_le(S32, Secp256k1_N_Half().data(), 32);
}

static inline bool DER_To_Compact64(const uint8_t* der, size_t der_len, uint8_t out64[64]){
    size_t ro=0, rl=0, so=0, sl=0;
    if (!ParseDERSignature(der, der_len, ro, rl, so, sl)) return false;
    uint8_t R32[32], S32[32];
    be_pad_to_32(der + ro, rl, R32);
    be_pad_to_32(der + so, sl, S32);
    std::memcpy(out64 + 0,  R32, 32);
    std::memcpy(out64 + 32, S32, 32);
    return true;
}

// Vector overloads
static inline bool IsCanonicalDERSig(const std::vector<uint8_t>& der){
    return IsCanonicalDERSig(der.data(), der.size());
}
static inline bool IsCanonicalDERSig_LowS(const std::vector<uint8_t>& der){
    return IsCanonicalDERSig_LowS(der.data(), der.size());
}
static inline bool IsLowS(const std::vector<uint8_t>& der){
    return IsLowS(der.data(), der.size());
}
static inline bool IsLowS_RS64(const std::vector<uint8_t>& rs64){
    return IsLowS_RS64(rs64.data(), rs64.size());
}
static inline bool DER_To_Compact64(const std::vector<uint8_t>& der, std::array<uint8_t,64>& out){
    return DER_To_Compact64(der.data(), der.size(), out.data());
}

}
