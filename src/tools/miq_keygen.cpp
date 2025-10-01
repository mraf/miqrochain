// src/tools/miq_keygen.cpp
#include <vector>
#include <string>
#include <iostream>

#include "constants.h"
#include "crypto/ecdsa_iface.h"
#include "sha256.h"
#include "ripemd160.h"
#include "hash160.h"
#include "base58.h"

// hex helper
static std::string hex2(const uint8_t* p, size_t n){
    static const char* hexd = "0123456789abcdef";
    std::string s; s.resize(n*2);
    for(size_t i=0;i<n;i++){ s[2*i]=hexd[p[i]>>4]; s[2*i+1]=hexd[p[i]&0xF]; }
    return s;
}

// Base58Check(P2PKH): ver || payload20 || checksum4 ; checksum = first 4 bytes of SHA256(SHA256(ver||payload))
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

int main() {
    // Generate private key and compressed pubkey via common ECDSA iface (libsecp backend)
    std::vector<uint8_t> priv(32), pub33;
    if (!miq::crypto::ECDSA::generate_priv(priv)) { std::cerr << "RNG failed\n"; return 1; }
    if (!miq::crypto::ECDSA::derive_pub(priv, pub33)) { std::cerr << "derive_pub failed\n"; return 1; }

    // Hash160 of compressed pubkey → P2PKH
    auto pkh  = miq::hash160(pub33);
    auto addr = b58check_p2pkh(miq::VERSION_P2PKH, pkh);

    std::cout << "Address (P2PKH): " << addr << "\n";
    std::cout << "PrivateKey (hex, keep secret!): " << hex2(priv.data(), 32) << "\n";
    return 0;
}
