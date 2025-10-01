#include <array>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "constants.h"
#include "crypto/ecdsa_iface.h"
#include "sha256.h"
#include "ripemd160.h"
#include "hash160.h"
#include "base58.h"

#if defined(_WIN32)
  #define NOMINMAX
  #include <windows.h>
  #include <bcrypt.h>   // BCryptGenRandom
  // link with bcrypt on Windows (we add it in CMake too)
  static int rng_os(uint8_t* dest, unsigned size) {
      NTSTATUS st = BCryptGenRandom(NULL, dest, size, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
      return st == 0 ? 1 : 0;
  }
#else
  #include <unistd.h>
  #include <fcntl.h>
  static int rng_os(uint8_t* dest, unsigned size) {
      int fd = open("/dev/urandom", O_RDONLY);
      if (fd < 0) return 0;
      unsigned off = 0;
      while (off < size) {
          ssize_t n = read(fd, dest + off, size - off);
          if (n <= 0) { close(fd); return 0; }
          off += (unsigned)n;
      }
      close(fd);
      return 1;
  }
#endif

// Base58Check encode: ver_byte + payload20 + checksum4
static std::string b58check_p2pkh(uint8_t ver, const std::vector<uint8_t>& payload20) {
    std::vector<uint8_t> buf;
    buf.reserve(1 + payload20.size() + 4);
    buf.push_back(ver);
    buf.insert(buf.end(), payload20.begin(), payload20.end());

    auto d1 = miq::sha256(buf);
    auto d2 = miq::sha256(d1);
    buf.insert(buf.end(), d2.begin(), d2.begin() + 4);

    return miq::base58_encode(buf);
}

// Compress 64-byte (x||y) pubkey -> 33 bytes 0x02/0x03 || x
static std::array<uint8_t,33> compress_pubkey(const uint8_t* pub64) {
    std::array<uint8_t,33> out{};
    // micro-ecc uses big-endian 32-byte coords: X[0..31], Y[32..63]
    const uint8_t* X = pub64;
    const uint8_t* Y = pub64 + 32;
    out[0] = (Y[31] & 1) ? 0x03 : 0x02;
    std::memcpy(out.data() + 1, X, 32);
    return out;
}

int main() {
    // Ensure a cryptographically secure RNG is set for micro-ecc
    uECC_set_rng(&rng_os);

    const struct uECC_Curve_t* curve = uECC_secp256k1();
    uint8_t pub[64];

    std::vector<uint8_t> priv(32), pub33;
    if (!miq::crypto::ECDSA::generate_priv(priv)) { std::cerr << "rng failed\n"; return 1; }
    if (!miq::crypto::ECDSA::derive_pub(priv, pub33)) { std::cerr << "derive_pub failed\n"; return 1; }

    // Build PKH/address from compressed pubkey (33 bytes) – you already have helpers:
    auto pkh = hash160(pub33);
    std::string addr = b58check_p2pkh(miq::VERSION_P2PKH, pkh);

    // print hex priv (same helper you already have):
    std::cout << "Address (P2PKH): " << addr << "\n";
    std::cout << "PrivateKey (hex, keep secret!): " << hex2(priv.data(), 32) << "\n";

    if (!uECC_make_key(pub, priv, curve)) {
        std::cerr << "ERROR: key generation failed (rng not available?)\n";
        return 1;
    }

    auto cpub = compress_pubkey(pub);
    std::vector<uint8_t> cpub_vec(cpub.begin(), cpub.end());

    auto pkh = miq::hash160(cpub_vec); // 20 bytes
    std::string addr = b58check_p2pkh(miq::VERSION_P2PKH, pkh);

    // hex helper
    auto hex2 = [](const uint8_t* p, size_t n){
        static const char* hexd="0123456789abcdef";
        std::string s; s.resize(n*2);
        for(size_t i=0;i<n;i++){ s[2*i]=hexd[p[i]>>4]; s[2*i+1]=hexd[p[i]&0xF]; }
        return s;
    };

    std::cout << "Address (P2PKH): " << addr << "\n";
    std::cout << "PrivateKey (hex, keep secret!): " << hex2(priv,32) << "\n";
    return 0;
}
