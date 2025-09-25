#include <array>
#include <vector>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "constants.h"
#include "sha256.h"
#include "ripemd160.h"
#include "hash160.h"
#include "base58.h"

extern "C" {
#include "uECC.h"
}

// Base58Check encode: ver_byte + payload20 + checksum4
static std::string b58check_p2pkh(uint8_t ver, const std::vector<uint8_t>& payload20) {
    std::vector<uint8_t> buf;
    buf.reserve(1 + payload20.size() + 4);
    buf.push_back(ver);
    buf.insert(buf.end(), payload20.begin(), payload20.end());

    auto d1 = sha256(buf);
    auto d2 = sha256(d1);
    buf.insert(buf.end(), d2.begin(), d2.begin()+4);

    return miq::base58_encode(buf);
}

// Compress 64-byte (x||y) pubkey -> 33 bytes 0x02/0x03 || x
static std::array<uint8_t,33> compress_pubkey(const uint8_t* pub64) {
    std::array<uint8_t,33> out{};
    // uECC uses big-endian 32-byte coords. y parity = LSB of last byte of Y.
    const uint8_t* X = pub64;
    const uint8_t* Y = pub64 + 32;
    out[0] = (Y[31] & 1) ? 0x03 : 0x02;
    std::memcpy(out.data()+1, X, 32);
    return out;
}

int main() {
    const struct uECC_Curve_t* curve = uECC_secp256k1();
    uint8_t pub[64];
    uint8_t priv[32];

    // Generate keypair with micro-ecc (secure RNG internally or system RNG hook)
    if (!uECC_make_key(pub, priv, curve)) {
        std::cerr << "ERROR: keygen failed\n";
        return 1;
    }

    // Compressed pubkey -> HASH160 -> Base58Check P2PKH
    auto cpub = compress_pubkey(pub);
    std::vector<uint8_t> cpub_vec(cpub.begin(), cpub.end());
    auto pkh = hash160(cpub_vec); // 20 bytes

    std::string addr = b58check_p2pkh(miq::VERSION_P2PKH, pkh);

    // Print results
    auto hex2 = [](const uint8_t* p, size_t n){
        static const char* hexd="0123456789abcdef";
        std::string s; s.resize(n*2);
        for(size_t i=0;i<n;i++){ s[2*i]=hexd[p[i]>>4]; s[2*i+1]=hexd[p[i]&0xF]; }
        return s;
    };

    std::cout << "Address (P2PKH): " << addr << "\n";
    std::cout << "PrivateKey (hex, keep secret!): " << hex2(priv,32) << "\n";
    // If you later add an import/restore command, this hex is enough.
    return 0;
}
