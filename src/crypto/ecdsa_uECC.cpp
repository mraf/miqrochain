// src/crypto/ecdsa_uECC.cpp
#include "crypto/ecdsa_uECC.h"
#include "crypto/ecdsa_iface.h"

extern "C" {
#include "uECC.h"
}

#include <vector>
#include <cstdint>
#include <cstring>

#ifdef MIQ_USE_SECP256K1
// libsecp build selected -> do not compile micro-ecc backend
#  ifdef _MSC_VER
#    pragma message("Skipping micro-ecc backend because MIQ_USE_SECP256K1=1")
#  endif
#else
// (no guard -> compile uECC backend)
#endif

// ---- OS randomness (portable) ----
#if defined(_WIN32)
  #include <windows.h>
  #include <bcrypt.h>
  #pragma comment(lib, "bcrypt.lib")
#else
  #include <fcntl.h>
  #include <unistd.h>
  #ifndef O_CLOEXEC
  #define O_CLOEXEC 0
  #endif
#endif

namespace miq { namespace crypto {

static uECC_Curve curve() { return uECC_secp256k1(); }

// ===== helpers: big-endian compare/sub for 32-byte scalars =====
static int cmp_be(const uint8_t* a, const uint8_t* b, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (a[i] != b[i]) return (a[i] < b[i]) ? -1 : 1;
    }
    return 0;
}
static void sub_be(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t n) {
    int borrow = 0;
    for (size_t i = 0; i < n; ++i) {
        size_t idx = n - 1 - i;
        int x = (int)a[idx] - (int)b[idx] - borrow;
        if (x < 0) { x += 256; borrow = 1; } else borrow = 0;
        out[idx] = (uint8_t)x;
    }
}

// secp256k1 group order n and n/2 (big-endian)
static const uint8_t SECP256K1_N[32] = {
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
    0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint8_t SECP256K1_N_HALF[32] = {
    0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
    0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

// ---- RNG ----
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

// Adapter for micro-ecc RNG signature: int rng(uint8_t* dest, unsigned size)
static int rng_uECC(uint8_t* dest, unsigned sz) {
    return os_random_bytes(dest, sz) ? 1 : 0;
}

// Ensure RNG set exactly once per process (idempotent).
static void ensure_rng() {
    static bool set = false;
    if (!set) { uECC_set_rng(&rng_uECC); set = true; }
}

// ---- pubkey normalization (compressed/uncompressed -> XY) ----
bool normalize_pubkey_xy(const std::vector<uint8_t>& pub, uint8_t out_xy[64]) {
    if (pub.size() == 33 && (pub[0] == 0x02 || pub[0] == 0x03)) {
        uECC_decompress(pub.data(), out_xy, curve());
        return true;
    }
    if (pub.size() == 65 && pub[0] == 0x04) {
        std::memcpy(out_xy + 0,  &pub[1],  32);
        std::memcpy(out_xy + 32, &pub[33], 32);
        return true;
    }
    return false;
}

// ========================= ECDSA (micro-ecc backend) =========================

bool ECDSA::generate_priv(std::vector<uint8_t>& out) {
    ensure_rng();
    out.resize(32);

    for (int tries = 0; tries < 16; ++tries) {
        if (!os_random_bytes(out.data(), out.size())) continue;
        bool all_zero = true; for (uint8_t b : out) if (b) { all_zero = false; break; }
        if (all_zero) continue;

        uint8_t pub_xy[64];
        if (uECC_compute_public_key(out.data(), pub_xy, curve())) {
            return true; // valid private key
        }
    }
    return false;
}

bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33) {
    if (priv.size() != 32) return false;
    uint8_t pub_xy[64];
    if (!uECC_compute_public_key(priv.data(), pub_xy, curve())) return false;

    out33.resize(33);
    uECC_compress(pub_xy, out33.data(), curve()); // 33 bytes (02/03||X)
    return true;
}

bool ECDSA::sign(const std::vector<uint8_t>& priv32,
                 const std::vector<uint8_t>& msg32,
                 std::vector<uint8_t>& sig64) {
    if (priv32.size() != 32 || msg32.size() != 32) return false;
    ensure_rng();
    sig64.resize(64);
    if (uECC_sign(priv32.data(), msg32.data(), (unsigned)msg32.size(), sig64.data(), curve()) != 1) {
        return false;
    }

    // ---- Low-S normalization (consensus-neutral here; only affects our signatures) ----
    uint8_t* r = sig64.data();
    uint8_t* s = sig64.data() + 32;
    if (cmp_be(s, SECP256K1_N_HALF, 32) > 0) {
        uint8_t s_norm[32];
        sub_be(s_norm, SECP256K1_N, s, 32);   // s = n - s
        std::memcpy(s, s_norm, 32);
    }
    (void)r; // r untouched, present for clarity
    return true;
}

bool ECDSA::verify(const std::vector<uint8_t>& pubkey,
                   const std::vector<uint8_t>& msg32,
                   const std::vector<uint8_t>& sig64) {
    if (msg32.size() != 32 || sig64.size() != 64) return false;
    uint8_t pub_xy[64];
    if (!normalize_pubkey_xy(pubkey, pub_xy)) return false;

    // uECC_verify returns 1 on success. It will fail if pubkey is invalid.
    return uECC_verify(pub_xy, msg32.data(), (unsigned)msg32.size(), sig64.data(), curve()) == 1;
}

std::string ECDSA::backend() {
    return "micro-ecc";
}

}
