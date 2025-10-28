// src/hasher.cpp — salted_header_hash + PowHasher midstate with SHA-NI fast path (runtime detected)
// Safe: self-test + portable fallback preserved.
#include "hasher.h"
#include <vector>
#include <cstdint>
#include <cstring>
#include <mutex>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#endif

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
#include <immintrin.h> // SHA-NI intrinsics
#include <intrin.h>    // __cpuidex
#endif

namespace miq {

// ---- Optional compile-time salt (keeps old semantics if you had a salt) ----
#ifdef MIQ_POW_SALT
#ifndef MIQ_POW_SALT_LEN
#error "If MIQ_POW_SALT is defined, also define MIQ_POW_SALT_LEN (size_t)."
#endif
static inline void append_salt_vec(std::vector<uint8_t>& buf){
    buf.insert(buf.end(), MIQ_POW_SALT, MIQ_POW_SALT + (size_t)MIQ_POW_SALT_LEN);
}
#else
[[maybe_unused]] static inline void append_salt_vec(std::vector<uint8_t>&){ /* no salt */ }
#endif

// ========= Portable SHA-256 (streaming) =========
static inline uint32_t ROR(uint32_t x, int n){ return (x>>n) | (x<<(32-n)); }
static inline uint32_t Ch(uint32_t x,uint32_t y,uint32_t z){ return (x & y) ^ (~x & z); }
static inline uint32_t Maj(uint32_t x,uint32_t y,uint32_t z){ return (x & y) ^ (x & z) ^ (y & z); }
static inline uint32_t BS0(uint32_t x){ return ROR(x,2) ^ ROR(x,13) ^ ROR(x,22); }
static inline uint32_t BS1(uint32_t x){ return ROR(x,6) ^ ROR(x,11) ^ ROR(x,25); }
static inline uint32_t SS0(uint32_t x){ return ROR(x,7) ^ ROR(x,18) ^ (x>>3); }
static inline uint32_t SS1(uint32_t x){ return ROR(x,17) ^ ROR(x,19) ^ (x>>10); }

static const uint32_t Ktbl[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline void sha256_compress_portable(uint32_t H[8], const uint8_t block[64]){
    uint32_t W[64];
    for(int i=0;i<16;i++){
        W[i] = (uint32_t)block[4*i]<<24 | (uint32_t)block[4*i+1]<<16 |
               (uint32_t)block[4*i+2]<<8 | (uint32_t)block[4*i+3];
    }
    for(int i=16;i<64;i++) W[i] = SS1(W[i-2]) + W[i-7] + SS0(W[i-15]) + W[i-16];

    uint32_t a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
    for(int i=0;i<64;i++){
        uint32_t T1 = h + BS1(e) + Ch(e,f,g) + Ktbl[i] + W[i];
        uint32_t T2 = BS0(a) + Maj(a,b,c);
        h=g; g=f; f=e; e=d + T1; d=c; c=b; b=a; a=T1 + T2;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e; H[5]+=f; H[6]+=g; H[7]+=h;
}

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
static bool g_use_shani = false;

// runtime detection of SHA extensions
static bool cpu_supports_shani(){
    int info[4] = {0,0,0,0};
    __cpuidex(info, 7, 0);
    // EBX bit 29 = SHA
    return (info[1] & (1<<29)) != 0;
}

// Minimal SHA-NI round driver using sha256rnds2 in 2-round steps.
// We build the scalar schedule W[64] and feed pairs (W[i]+K[i], W[i+1]+K[i+1]).
// Self-test below ensures state packing is correct; if not, we fall back.
static inline void sha256_compress_shani(uint32_t H[8], const uint8_t block[64]){
    // Scalar message schedule (safe & cheap)
    uint32_t W[64];
    for(int i=0;i<16;i++){
        W[i] = (uint32_t)block[4*i]<<24 | (uint32_t)block[4*i+1]<<16 |
               (uint32_t)block[4*i+2]<<8 | (uint32_t)block[4*i+3];
    }
    for(int i=16;i<64;i++) W[i] = SS1(W[i-2]) + W[i-7] + SS0(W[i-15]) + W[i-16];

    // Pack state: STATE0 = (a,b,c,d), STATE1 = (e,f,g,h).
    // Note: _mm_set_epi32 sets lanes as (w3,w2,w1,w0). We place (a,b,c,d) as (w3,w2,w1,w0) = (d,c,b,a)?
    // For our lane usage (extract at end), we'll store STATE0 lanes as (a,b,c,d) in order of extracts:
    __m128i STATE0 = _mm_set_epi32((int)H[3], (int)H[2], (int)H[1], (int)H[0]);
    __m128i STATE1 = _mm_set_epi32((int)H[7], (int)H[6], (int)H[5], (int)H[4]);

    auto pair_as_msg = [] (uint32_t w0, uint32_t w1)->__m128i{
        // lanes: [w3 w2 w1 w0] — put message in low two lanes, zeros above
        return _mm_set_epi32(0, 0, (int)w1, (int)w0);
    };

    for(int i=0;i<64; i+=2){
        __m128i MSG = pair_as_msg(W[i] + Ktbl[i], W[i+1] + Ktbl[i+1]);
        __m128i TMP = STATE1;
        STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
        STATE0 = _mm_sha256rnds2_epu32(STATE0, TMP, MSG);
    }

    H[0] += (uint32_t)_mm_extract_epi32(STATE0, 0);
    H[1] += (uint32_t)_mm_extract_epi32(STATE0, 1);
    H[2] += (uint32_t)_mm_extract_epi32(STATE0, 2);
    H[3] += (uint32_t)_mm_extract_epi32(STATE0, 3);
    H[4] += (uint32_t)_mm_extract_epi32(STATE1, 0);
    H[5] += (uint32_t)_mm_extract_epi32(STATE1, 1);
    H[6] += (uint32_t)_mm_extract_epi32(STATE1, 2);
    H[7] += (uint32_t)_mm_extract_epi32(STATE1, 3);
}
#endif // MSVC x86/x64

// Dispatch pointer (defaults to portable)
static void (*g_sha256_compress)(uint32_t H[8], const uint8_t block[64]) = sha256_compress_portable;

// ---- PowHasher streaming helpers ----
void PowHasher::ctx_init(Ctx& c){
    c.H[0]=0x6a09e667u; c.H[1]=0xbb67ae85u; c.H[2]=0x3c6ef372u; c.H[3]=0xa54ff53au;
    c.H[4]=0x510e527fu; c.H[5]=0x9b05688cu; c.H[6]=0x1f83d9abu; c.H[7]=0x5be0cd19u;
    c.total = 0;
    c.blen = 0;
}
void PowHasher::ctx_update(Ctx& c, const uint8_t* p, size_t n){
    if(n==0) return;
    c.total += (uint64_t)n;
    if(c.blen){
        size_t t = 64 - c.blen;
        if(t > n) t = n;
        std::memcpy(c.buf + c.blen, p, t);
        c.blen += t; p += t; n -= t;
        if(c.blen == 64){
            g_sha256_compress(c.H, c.buf);
            c.blen = 0;
        }
    }
    while(n >= 64){
        g_sha256_compress(c.H, p);
        p += 64; n -= 64;
    }
    if(n){
        std::memcpy(c.buf, p, n);
        c.blen = n;
    }
}
void PowHasher::ctx_final(const Ctx& c_in, uint8_t out32[32]){
    Ctx c = c_in; // copy to preserve base_
    uint8_t pad[128];
    size_t bl = c.blen;
    std::memcpy(pad, c.buf, bl);
    pad[bl++] = 0x80;
    size_t padzeros = ((bl % 64) <= 56) ? (56 - (bl % 64)) : (120 - (bl % 64));
    std::memset(pad+bl, 0, padzeros); bl += padzeros;
    uint64_t bits = c.total * 8ull;
    for(int i=7;i>=0;--i) pad[bl++] = (uint8_t)(bits >> (8*i));
    g_sha256_compress(c.H, pad);
    if(bl > 64) g_sha256_compress(c.H, pad+64);
    for(int i=0;i<8;i++){
        out32[4*i+0] = (uint8_t)(c.H[i] >> 24);
        out32[4*i+1] = (uint8_t)(c.H[i] >> 16);
        out32[4*i+2] = (uint8_t)(c.H[i] >> 8);
        out32[4*i+3] = (uint8_t)(c.H[i]);
    }
}

// Portable one-shot double-SHA256
void PowHasher::dsha256(const uint8_t* data, size_t len, uint8_t out32[32]){
    Ctx c; ctx_init(c); ctx_update(c, data, len); uint8_t h1[32]; ctx_final(c, h1);
    Ctx c2; ctx_init(c2); ctx_update(c2, h1, 32); ctx_final(c2, out32);
}

// Salt append: streaming form
void PowHasher::append_salt(std::vector<uint8_t>& v){
#ifdef MIQ_POW_SALT
    append_salt_vec(v);
#else
    (void)v;
#endif
}
void PowHasher::append_salt_ctx(Ctx& c){
#ifdef MIQ_POW_SALT
    const uint8_t* s = (const uint8_t*)MIQ_POW_SALT;
    ctx_update(c, s, (size_t)MIQ_POW_SALT_LEN);
#else
    (void)c;
#endif
}

// ---- Windows CNG one-shot accelerator for salted_header_hash (unchanged) ----
#if defined(_WIN32)
static BCRYPT_ALG_HANDLE g_shaAlg = nullptr;
static DWORD             g_objLen = 0;
static std::once_flag    g_shaInitOnce;

static void init_cng_sha(){
    NTSTATUS s = BCryptOpenAlgorithmProvider(&g_shaAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0);
    if(s < 0){ g_shaAlg=nullptr; return; }
    DWORD cb=0;
    s = BCryptGetProperty(g_shaAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&g_objLen, sizeof(g_objLen), &cb, 0);
    if(s < 0){ BCryptCloseAlgorithmProvider(g_shaAlg,0); g_shaAlg=nullptr; g_objLen=0; }
}
static inline bool dsha256_cng(const uint8_t* data, size_t len, uint8_t out32[32]){
    std::call_once(g_shaInitOnce, init_cng_sha);
    if(!g_shaAlg || g_objLen==0) return false;

    std::vector<uint8_t> obj(g_objLen);
    BCRYPT_HASH_HANDLE hHash = nullptr;
    uint8_t h1[32];

    NTSTATUS s = BCryptCreateHash(g_shaAlg, &hHash, obj.data(), g_objLen, nullptr, 0, 0);
    if(s < 0) return false;
    s = BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0);
    if(s >= 0) s = BCryptFinishHash(hHash, h1, 32, 0);
    BCryptDestroyHash(hHash);
    if(s < 0) return false;

    obj.assign(g_objLen, 0);
    hHash = nullptr;
    s = BCryptCreateHash(g_shaAlg, &hHash, obj.data(), g_objLen, nullptr, 0, 0);
    if(s < 0) return false;
    s = BCryptHashData(hHash, (PUCHAR)h1, 32, 0);
    if(s >= 0) s = BCryptFinishHash(hHash, out32, 32, 0);
    BCryptDestroyHash(hHash);
    return s >= 0;
}
#endif

std::vector<uint8_t> salted_header_hash(const std::vector<uint8_t>& header){
    std::vector<uint8_t> msg;
    msg.reserve(header.size()
#ifdef MIQ_POW_SALT
        + (size_t)MIQ_POW_SALT_LEN
#endif
    );
    msg.insert(msg.end(), header.begin(), header.end());
#ifdef MIQ_POW_SALT
    append_salt_vec(msg);
#endif

    uint8_t out[32];

#if defined(_WIN32)
    if (dsha256_cng(msg.data(), msg.size(), out)) {
        return std::vector<uint8_t>(out, out+32);
    }
#endif
    PowHasher::dsha256(msg.data(), msg.size(), out);
    return std::vector<uint8_t>(out, out+32);
}

// ---- PowHasher implementation ----
PowHasher::PowHasher(const uint8_t* prefix, size_t prefix_len){
    ctx_init(base_);
    ctx_update(base_, prefix, prefix_len);
    // NOTE: salt (if any) is appended AFTER nonce, to match salted_header_hash semantics.
}

void PowHasher::hash_nonce_ascii(const char* nonce_ascii, size_t nlen, uint8_t out32[32]) const{
    // First hash (streaming): base_ + nonce_ascii [+ salt]
    Ctx c = base_;
    ctx_update(c, reinterpret_cast<const uint8_t*>(nonce_ascii), nlen);
    append_salt_ctx(c);
    uint8_t h1[32];
    ctx_final(c, h1);

    // Second hash (one-shot portable dispatcher)
    Ctx c2; ctx_init(c2); ctx_update(c2, h1, 32); ctx_final(c2, out32);
}

// ---- One-time SHA-NI enable (with self-test) ----
static std::once_flag g_shaniOnce;
static void try_enable_shani(){
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    if (cpu_supports_shani()){
        // Self-test: SHA256("abc") = BA7816BF... (FIPS 180-4)
        const uint8_t abc[] = {'a','b','c'};
        uint32_t Htest[8] = {
            0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
            0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u
        };
        // single-block padded message for "abc"
        uint8_t blk[64] = {0};
        blk[0]='a'; blk[1]='b'; blk[2]='c'; blk[3]=0x80;
        blk[63] = 24; // bit length

        // run our SHA-NI compressor once
        sha256_compress_shani(Htest, blk);

        uint8_t h[32];
        for(int i=0;i<8;i++){
            h[4*i+0]=(uint8_t)(Htest[i]>>24);
            h[4*i+1]=(uint8_t)(Htest[i]>>16);
            h[4*i+2]=(uint8_t)(Htest[i]>>8);
            h[4*i+3]=(uint8_t)(Htest[i]);
        }
        static const uint8_t ref[32] = {
            0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
            0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
        };
        bool ok = (std::memcmp(h, ref, 32)==0);
        if(ok){
            g_sha256_compress = sha256_compress_shani;
            g_use_shani = true;
        }
    }
#endif
}

// Static initializer
struct ShaniInit {
    ShaniInit(){ std::call_once(g_shaniOnce, try_enable_shani); }
} s_shani_init;

void fastsha_init(FastSha256Ctx& c){
    c.H[0]=0x6a09e667u; c.H[1]=0xbb67ae85u; c.H[2]=0x3c6ef372u; c.H[3]=0xa54ff53au;
    c.H[4]=0x510e527fu; c.H[5]=0x9b05688cu; c.H[6]=0x1f83d9abu; c.H[7]=0x5be0cd19u;
    c.total = 0; c.blen = 0;
}
void fastsha_update(FastSha256Ctx& c, const uint8_t* p, size_t n){
    if(n==0) return;
    if(c.blen){
        size_t need = 64 - c.blen;
        size_t take = (n < need) ? n : need;
        std::memcpy(c.buf + c.blen, p, take);
        c.blen += take; p += take; n -= take;
        if(c.blen == 64){
            g_sha256_compress(c.H, c.buf);
            c.total += 64; c.blen = 0;
        }
    }
    while(n >= 64){
        g_sha256_compress(c.H, p);
        c.total += 64; p += 64; n -= 64;
    }
    if(n){ std::memcpy(c.buf, p, n); c.blen = n; }
}
void fastsha_final_copy(const FastSha256Ctx& c_in, uint8_t out32[32]){
    FastSha256Ctx c = c_in;
    uint8_t pad[128];

    // original buffered bytes before padding:
    size_t bl = c.blen;
    const uint64_t msg_len_bits = (uint64_t)(c.total + bl) * 8ull; // <-- FIX: include bl

    // copy buffered data and append 0x80
    std::memcpy(pad, c.buf, bl);
    pad[bl++] = 0x80;

    // pad with zeros to reach 56 mod 64
    size_t padzeros = ((bl % 64) <= 56) ? (56 - (bl % 64)) : (120 - (bl % 64));
    std::memset(pad + bl, 0, padzeros);
    bl += padzeros;

    // append 64-bit big-endian length (bits)
    for(int i = 7; i >= 0; --i) pad[bl++] = (uint8_t)(msg_len_bits >> (8*i));

    // compress 1 or 2 final blocks
    g_sha256_compress(c.H, pad);
    if (bl > 64) g_sha256_compress(c.H, pad + 64);

    // output big-endian digest
    for(int i=0;i<8;i++){
        out32[4*i+0] = (uint8_t)(c.H[i] >> 24);
        out32[4*i+1] = (uint8_t)(c.H[i] >> 16);
        out32[4*i+2] = (uint8_t)(c.H[i] >>  8);
        out32[4*i+3] = (uint8_t)(c.H[i]);
    }
}
void dsha256_from_base(const FastSha256Ctx& base, const uint8_t* suffix, size_t n, uint8_t out32[32]){
    FastSha256Ctx c = base;
    if(n) fastsha_update(c, suffix, n);
    uint8_t h1[32];
    fastsha_final_copy(c, h1);
    FastSha256Ctx c2; fastsha_init(c2); fastsha_update(c2, h1, 32); fastsha_final_copy(c2, out32);
}

} // namespace miq
