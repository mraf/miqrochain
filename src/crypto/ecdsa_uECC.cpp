#include "crypto/ecdsa_iface.h"   // public API: ECDSA::...
#include "crypto/ecdsa_uECC.h"    // backend declarations

#include <vector>
#include <cstdint>
#include <cstring>

extern "C" {
#include "uECC.h"                 // micro-ecc header (provided by submodule/fetch)
}

#if defined(_WIN32)
  #define WIN32_LEAN_AND_MEAN
  #include <windows.h>
  #include <bcrypt.h>
  // Link bcrypt automatically on MSVC; harmless elsewhere due to the guard.
  #if defined(_MSC_VER)
    #pragma comment(lib, "bcrypt.lib")
  #endif
#else
  #include <sys/types.h>
  #include <fcntl.h>
  #include <unistd.h>
#endif

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
    return std::memcmp(a, b, 32); // big-endian lexicographic compare
}
static inline bool is_zero32(const uint8_t* x){
    uint32_t acc = 0; for (int i=0;i<32;i++) acc |= x[i]; return acc==0;
}
static inline void be_sub_32(uint8_t out[32], const uint8_t a[32], const uint8_t b[32]){
    // out = a - b (big-endian)
    int borrow = 0;
    for (int i = 31; i >= 0; --i){
        int v = (int)a[i] - (int)b[i] - borrow;
        int new_borrow = (v < 0);
        out[i] = (uint8_t)(v + (new_borrow ? 256 : 0));
        borrow = new_borrow;
    }
}

// ----- OS RNG (portable) for private key generation -----
static bool os_random_bytes(uint8_t* dst, size_t len) {
#if defined(_WIN32)
    NTSTATUS s = BCryptGenRandom(nullptr, dst, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return s >= 0;
#else
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t got = 0;
    while (got < len) {
        ssize_t n = ::read(fd, dst + got, len - got);
        if (n <= 0) { ::close(fd); return false; }
        got += (size_t)n;
    }
    ::close(fd);
    return true;
#endif
}

// Normalize pubkey to 64-byte XY for uECC (supports 33/65/64 input forms).
static bool normalize_pubkey_xy(const std::vector<uint8_t>& in, uint8_t out_xy[64]){
    const uECC_Curve curve = uECC_secp256k1();

    if (in.size()==33 && (in[0]==0x02 || in[0]==0x03)) {
        // uECC_decompress returns void; decompress then validate.
        uECC_decompress(in.data(), out_xy, curve);
        return uECC_valid_public_key(out_xy, curve) == 1;
    }
    if (in.size()==65 && in[0]==0x04) {
        std::memcpy(out_xy, &in[1], 64);
        return uECC_valid_public_key(out_xy, curve) == 1;
    }
    if (in.size()==64) {
        std::memcpy(out_xy, in.data(), 64);
        return uECC_valid_public_key(out_xy, curve) == 1;
    }
    return false;
}

// Check (r,s) in [1..N-1] and enforce s <= N/2 (low-S)
static bool sig_is_canonical_lows(const uint8_t sig64[64]){
    const uint8_t* r = sig64 + 0;
    const uint8_t* s = sig64 + 32;
    if (is_zero32(r) || is_zero32(s)) return false;
    if (cmp_be_32(r, SECP256K1_N) >= 0) return false;
    if (cmp_be_32(s, SECP256K1_N) >= 0) return false;
    if (cmp_be_32(s, SECP256K1_N_HALF) > 0) return false;
    return true;
}

// ---- Backend: generate/derive/sign/verify -----------------------------------

bool ECDSA_uECC::generate_priv(std::vector<uint8_t>& out32){
    out32.assign(32, 0);
    // Sample until 0 < priv < N
    for (int tries=0; tries<32; ++tries) {
        if (!os_random_bytes(out32.data(), 32)) return false;
        if (!is_zero32(out32.data()) && cmp_be_32(out32.data(), SECP256K1_N) < 0) {
            return true;
        }
    }
    return false;
}

bool ECDSA_uECC::derive_pub(const std::vector<uint8_t>& priv32, std::vector<uint8_t>& out33){
    if (priv32.size() != 32) return false;
    const uECC_Curve curve = uECC_secp256k1();

    uint8_t pub_xy[64] = {0};
    if (!uECC_compute_public_key(priv32.data(), pub_xy, curve)) {
        return false;
    }

    out33.assign(33, 0);
    uECC_compress(pub_xy, out33.data(), curve);
    return true;
}

bool ECDSA_uECC::sign(const std::vector<uint8_t>& priv32,
                      const std::vector<uint8_t>& msg32,
                      std::vector<uint8_t>& sig64)
{
    if (priv32.size()!=32 || msg32.size()!=32) return false;
    sig64.assign(64, 0);

    const uECC_Curve curve = uECC_secp256k1();
    if (!uECC_sign(priv32.data(), msg32.data(), 32, sig64.data(), curve)) {
        return false;
    }

    // Enforce low-S: if s > N/2, set s := N - s
    uint8_t* s = sig64.data() + 32;
    if (cmp_be_32(s, SECP256K1_N_HALF) > 0) {
        uint8_t s_fix[32];
        be_sub_32(s_fix, SECP256K1_N, s);
        std::memcpy(s, s_fix, 32);
    }
    return true;
}

bool ECDSA_uECC::verify(const std::vector<uint8_t>& pubkey,
                        const std::vector<uint8_t>& msg32,
                        const std::vector<uint8_t>& sig64)
{
    if (msg32.size()!=32 || sig64.size()!=64) return false;
    if (!sig_is_canonical_lows(sig64.data())) return false;

    uint8_t pub_xy[64];
    if (!normalize_pubkey_xy(pubkey, pub_xy)) return false;

    const uECC_Curve curve = uECC_secp256k1();
    int ok = uECC_verify(pub_xy, msg32.data(), 32, sig64.data(), curve);
    return ok == 1;
}

} // namespace crypto
} // namespace miq

// ---- Public API adapters (from ecdsa_iface.h) --------------------------------
namespace miq {
namespace crypto {

bool ECDSA::generate_priv(std::vector<uint8_t>& out) {
    return ECDSA_uECC::generate_priv(out);
}
bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33) {
    return ECDSA_uECC::derive_pub(priv, out33);
}
bool ECDSA::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64) {
    return ECDSA_uECC::sign(priv, msg32, sig64);
}
bool ECDSA::verify(const std::vector<uint8_t>& pubkey, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64) {
    return ECDSA_uECC::verify(pubkey, msg32, sig64);
}

} // namespace crypto
} // namespace miq
