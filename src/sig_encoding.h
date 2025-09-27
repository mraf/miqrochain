// src/sig_encoding.h
#pragma once
#include <cstdint>
#include <cstddef>
#include <array>

namespace miq {

// secp256k1 group order (n) in big-endian
static inline const std::array<uint8_t,32>& Secp256k1_N() {
    static const std::array<uint8_t,32> N = {
        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,
        0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
        0x8C,0xD0,0x36,0x41,0x41,0x02,0x6E,0xBF
    };
    return N;
}

// N/2 (half the order), big-endian
static inline const std::array<uint8_t,32>& Secp256k1_N_Half() {
    static const std::array<uint8_t,32> H = {
        0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
        0xFF,0xFF,0xFF,0xFF,0x7F,0x5D,0x57,0x6E,
        0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,
        0x46,0x68,0x1B,0x20,0xA0,0x81,0x37,0x5F
    };
    return H;
}

// Lexicographic big-endian compare of two unsigned bigints (same length)
static inline int be_cmp(const uint8_t* a, const uint8_t* b, size_t len){
    for(size_t i=0;i<len;i++){
        if(a[i] < b[i]) return -1;
        if(a[i] > b[i]) return 1;
    }
    return 0;
}

// Check strict DER per Bitcoin's IsValidSignatureEncoding() rules (no sighash byte here).
// Accepts a DER signature WITHOUT any appended sighash-type byte.
// Returns true if canonical DER (minimal R/S encodings, positives, correct sequence/lengths).
static inline bool IsValidDERSignature(const uint8_t* sig, size_t len){
    // Min/max sizes per DER (sequence(2) + R(2+1..33) + S(2+1..33)) => 9..73 bytes
    if(len < 9 || len > 73) return false;
    // 0x30 = DER sequence
    if(sig[0] != 0x30) return false;
    // sequence length must match (len-2)
    if(sig[1] != (len - 2)) return false;

    // R element
    size_t pos = 2;
    if(pos + 2 > len) return false;
    if(sig[pos] != 0x02) return false;
    uint8_t rlen = sig[pos+1];
    pos += 2;
    if(rlen == 0) return false;
    if(pos + rlen > len) return false;
    const uint8_t* R = sig + pos;
    // R must be positive (no high bit) and minimal (no leading zero unless needed)
    if((R[0] & 0x80) != 0) return false;
    if(rlen > 1 && R[0] == 0x00 && (R[1] & 0x80) == 0) return false;
    pos += rlen;

    // S element
    if(pos + 2 > len) return false;
    if(sig[pos] != 0x02) return false;
    uint8_t slen = sig[pos+1];
    pos += 2;
    if(slen == 0) return false;
    if(pos + slen != len) return false; // must end exactly
    const uint8_t* S = sig + pos;
    if((S[0] & 0x80) != 0) return false;
    if(slen > 1 && S[0] == 0x00 && (S[1] & 0x80) == 0) return false;

    return true;
}

// Extract R/S pointers and lengths from a DER signature (no sighash byte).
// Returns false if format invalid.
static inline bool ParseDERSignature(const uint8_t* sig, size_t len,
                                     const uint8_t*& R, size_t& rlen,
                                     const uint8_t*& S, size_t& slen){
    if(!IsValidDERSignature(sig, len)) return false;
    size_t pos = 2;
    pos += 1; // 0x02
    rlen = sig[pos]; ++pos;
    R = sig + pos; pos += rlen;
    pos += 1; // 0x02
    slen = sig[pos]; ++pos;
    S = sig + pos;
    return (pos + slen == len);
}

// True if S <= N/2 (Low-S rule)
static inline bool IsLowS(const uint8_t* S, size_t slen){
    // Left-pad S to 32 bytes for comparison
    if(slen == 0 || slen > 33) return false; // should be <=33 with leading zero possible
    // Normalize possible leading zero (due to DER positivity)
    size_t off = (slen == 33 && S[0]==0x00) ? 1 : 0;
    if(slen - off > 32) return false;

    uint8_t S32[32] = {0};
    // copy to right-align
    size_t copy = slen - off;
    std::memcpy(S32 + (32 - copy), S + off, copy);

    return be_cmp(S32, Secp256k1_N_Half().data(), 32) <= 0;
}

// Full policy: strict DER + Low-S
// Accepts signature without sighash byte. Returns true if passes both rules.
static inline bool IsCanonicalDERSig_LowS(const uint8_t* sig, size_t len){
    const uint8_t* R=nullptr; const uint8_t* S=nullptr; size_t rlen=0, slen=0;
    if(!ParseDERSignature(sig, len, R, rlen, S, slen)) return false;
    return IsLowS(S, slen);
}

}
