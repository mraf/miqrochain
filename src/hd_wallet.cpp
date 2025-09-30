#include "hd_wallet.h"
#include "bip39_words_en.h"

#include "address.h"
#include "hash160.h"
#include "base58check.h"
#include "hex.h"
#include "wallet_encryptor.h"   // your AES-GCM helpers (if MIQ_ENABLE_WALLET_ENC)
#include "crypto/ecdsa_iface.h" // your secp256k1 bridge
#include "constants.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <sstream>
#include <fstream>
#include <random>
#include <algorithm>

namespace miq {

// ---- small utils ----
static inline void put32(uint8_t* p, uint32_t v){ p[0]=v>>24; p[1]=(v>>16)&0xff; p[2]=(v>>8)&0xff; p[3]=v&0xff; }

// HMAC-SHA512 via OpenSSL
static bool hmac_sha512(const uint8_t* key, size_t klen,
                        const uint8_t* msg, size_t mlen,
                        uint8_t out[64]){
    unsigned int outlen=64;
    unsigned char* r = HMAC(EVP_sha512(), key, (int)klen, msg, (int)mlen, out, &outlen);
    return r!=nullptr && outlen==64;
}

// SHA256 (for mnemonic checksum)
static void sha256_once(const uint8_t* data, size_t len, uint8_t out[32]){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    unsigned int l=0;
    EVP_DigestFinal_ex(ctx, out, &l);
    EVP_MD_CTX_free(ctx);
}

// PBKDF2-HMAC-SHA512 (mnemonic -> seed)
static bool pbkdf2_hmac_sha512(const std::string& pass, const std::string& salt,
                               uint8_t out[64], int iters=2048){
    return PKCS5_PBKDF2_HMAC(pass.c_str(), (int)pass.size(),
                             (const unsigned char*)salt.data(), (int)salt.size(),
                             iters, EVP_sha512(), 64, out)==1;
}

// Provided by your secp256k1 wrapper (compressed 33B)
extern bool ecdsa_derive_pub_from_priv(const std::vector<uint8_t>& priv, std::vector<uint8_t>& pub33);

// ---------- BIP39 ----------

static bool entropy_to_mnemonic(const std::vector<uint8_t>& ent, std::string& out_mn){
    if(ent.size()!=16 && ent.size()!=32) return false;
    uint8_t hash[32]; sha256_once(ent.data(), ent.size(), hash);
    const int entbits = (int)ent.size()*8;
    const int csbits  = entbits/32;
    const int total   = entbits + csbits;  // 132 or 264
    const int words   = total/11;          // 12 or 24

    // Build bitstring ent||cs
    std::vector<int> bits(total,0);
    for(size_t i=0;i<ent.size();++i){
        for(int b=0;b<8;b++){
            bits[i*8+b] = (ent[i]>>(7-b)) & 1;
        }
    }
    for(int i=0;i<csbits;i++){
        bits[entbits+i] = (hash[0]>>(7-i)) & 1;
    }

    std::ostringstream oss;
    for(int w=0; w<words; ++w){
        int idx=0;
        for(int b=0;b<11;b++){
            idx = (idx<<1) | bits[w*11 + b];
        }
        if(w) oss << ' ';
        oss << BIP39_EN_WORDS[idx];
    }
    out_mn = oss.str();
    return true;
}

bool HdWallet::GenerateMnemonic(int entropy_bits, std::string& out_mnemonic){
    if(entropy_bits!=128 && entropy_bits!=256) return false;
    std::vector<uint8_t> ent(entropy_bits/8);
    RAND_bytes(ent.data(), (int)ent.size());
    return entropy_to_mnemonic(ent, out_mnemonic);
}

bool HdWallet::MnemonicToSeed(const std::string& mnemonic,
                              const std::string& passphrase,
                              std::vector<uint8_t>& out_seed){
    // For brevity we assume normalized/trimmed input (can add NFKD later if needed).
    std::string salt = std::string("mnemonic") + passphrase;
    out_seed.assign(64,0);
    if(!pbkdf2_hmac_sha512(mnemonic, salt, out_seed.data(), 2048)) return false;
    return true;
}

// ---------- BIP32 ----------

// Master: I = HMAC-SHA512(key="Bitcoin seed", data=seed) => IL, IR
static bool bip32_master_from_seed(const std::vector<uint8_t>& seed,
                                   std::vector<uint8_t>& k_master,
                                   std::vector<uint8_t>& c_master){
    uint8_t I[64];
    if(!hmac_sha512((const uint8_t*)"Bitcoin seed", 12, seed.data(), seed.size(), I)) return false;
    k_master.assign(I, I+32);
    c_master.assign(I+32, I+64);
    return true;
}

// CKDpriv((k,c), i): hardened if i>=2^31 -> data=0x00||k||i; else serP(k)||i
static bool bip32_ckd_priv(std::vector<uint8_t>& k, std::vector<uint8_t>& c, uint32_t i, bool hardened){
    uint8_t data[1+33+4];
    size_t off=0;
    if(hardened){
        data[0]=0x00; off=1;
        std::copy(k.begin(), k.end(), data+off); off+=32;
    }else{
        std::vector<uint8_t> pub33;
        if(!ecdsa_derive_pub_from_priv(k, pub33)) return false;
        std::copy(pub33.begin(), pub33.end(), data); off=33;
    }
    put32(data+off, i);
    uint8_t I[64];
    if(!hmac_sha512(c.data(), c.size(), data, off+4, I)) return false;

    // k' = (IL + k) mod n
    BIGNUM* n = BN_new(); BN_hex2bn(n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    BIGNUM* IL= BN_bin2bn(I,32,nullptr);
    BIGNUM* kk= BN_bin2bn(k.data(),32,nullptr);
    BN_CTX*  ctx= BN_CTX_new();
    BN_mod_add(kk, kk, IL, n, ctx);
    std::vector<uint8_t> kout(32,0);
    BN_bn2binpad(kk, kout.data(), 32);
    k.swap(kout);
    BN_free(IL); BN_free(kk); BN_free(n); BN_CTX_free(ctx);

    // c' = IR
    c.assign(I+32, I+64);
    return true;
}

HdWallet::HdWallet(const std::vector<uint8_t>& seed, const HdAccountMeta& meta)
: seed_(seed), meta_(meta) {}

bool HdWallet::DerivePrivPub(uint32_t account, uint32_t chain, uint32_t index,
                             std::vector<uint8_t>& out_priv,
                             std::vector<uint8_t>& out_pub) const {
    std::vector<uint8_t> k, c;
    if(!bip32_master_from_seed(seed_, k, c)) return false;
    auto H = [](uint32_t v){ return v | 0x80000000u; };

    // m/44'/MIQ'/account'/chain/index
    if(!bip32_ckd_priv(k,c,H(44), true)) return false;
    if(!bip32_ckd_priv(k,c,H(MIQ_COIN_TYPE), true)) return false;
    if(!bip32_ckd_priv(k,c,H(account), true)) return false;
    if(!bip32_ckd_priv(k,c,chain, false)) return false;
    if(!bip32_ckd_priv(k,c,index, false)) return false;

    out_priv = k;
    if(!ecdsa_derive_pub_from_priv(out_priv, out_pub)) return false;
    return true;
}

std::string PubkeyToAddress(const std::vector<uint8_t>& pub33){
    std::vector<uint8_t> h160;
    hash160(pub33, h160);
    // VERSION_P2PKH should be defined in your constants.h (uint8_t)
    return base58check_encode(VERSION_P2PKH, h160);
}

bool HdWallet::GetNewAddress(std::string& out_addr){
    std::vector<uint8_t> priv, pub;
    if(!DerivePrivPub(meta_.account, 0, meta_.next_recv, priv, pub)) return false;
    out_addr = PubkeyToAddress(pub);
    meta_.next_recv += 1;
    return true;
}

bool HdWallet::GetAddressAt(uint32_t index, std::string& out_addr) const {
    std::vector<uint8_t> priv, pub;
    if(!DerivePrivPub(meta_.account, 0, index, priv, pub)) return false;
    out_addr = PubkeyToAddress(pub);
    return true;
}

std::string HdWallet::MetaToIni(const HdAccountMeta& m){
    std::ostringstream o;
    o << "account="    << m.account    << "\n";
    o << "next_recv="  << m.next_recv  << "\n";
    o << "next_change="<< m.next_change<< "\n";
    return o.str();
}

bool HdWallet::MetaFromIni(const std::string& t, HdAccountMeta& m){
    std::istringstream is(t); std::string line;
    while(std::getline(is, line)){
        auto p = line.find('=');
        if(p==std::string::npos) continue;
        auto k = line.substr(0,p);
        auto v = line.substr(p+1);
        if(k=="account") m.account = (uint32_t)std::stoul(v);
        else if(k=="next_recv") m.next_recv = (uint32_t)std::stoul(v);
        else if(k=="next_change") m.next_change = (uint32_t)std::stoul(v);
    }
    return true;
}

// ---------- persistence ----------

static std::string join_path(const std::string& a, const std::string& b){
    if(a.empty()) return b;
    char sep = '/';
#ifdef _WIN32
    sep = '\\';
#endif
    if(a.back()==sep) return a + b;
    return a + sep + b;
}

bool SaveHdWallet(const std::string& dir,
                  const std::vector<uint8_t>& seed,
                  const HdAccountMeta& meta,
                  const std::string& walletpass,
                  std::string& err){
    // write meta
    {
        std::ofstream f(join_path(dir,"wallet.meta"), std::ios::binary);
        if(!f.good()){ err = "cannot write wallet.meta"; return false; }
        f << HdWallet::MetaToIni(meta);
    }
    // write/enc seed
    const std::string blob = join_path(dir,"wallet.seed");
    std::vector<uint8_t> plain(seed.begin(), seed.end());
    if(!walletpass.empty()){
        if(!wallet_encrypt_to_file(blob, plain, walletpass, err)) return false;
    } else {
        std::ofstream f(blob, std::ios::binary);
        if(!f.good()){ err="cannot write wallet.seed"; return false; }
        const char hdr[8]={'M','I','Q','S','E','E','D','\0'};
        f.write(hdr, 8);
        f.write((const char*)plain.data(), (std::streamsize)plain.size());
    }
    return true;
}

bool LoadHdWallet(const std::string& dir,
                  std::vector<uint8_t>& out_seed,
                  HdAccountMeta& out_meta,
                  const std::string& walletpass,
                  std::string& err){
    // meta
    {
        std::ifstream f(join_path(dir,"wallet.meta"), std::ios::binary);
        if(!f.good()){ err = "wallet.meta missing"; return false; }
        std::ostringstream ss; ss << f.rdbuf();
        HdWallet::MetaFromIni(ss.str(), out_meta);
    }
    // seed
    {
        const std::string blob = join_path(dir,"wallet.seed");
        if(!walletpass.empty()){
            std::vector<uint8_t> plain;
            if(!wallet_decrypt_from_file(blob, plain, walletpass, err)) return false;
            out_seed = plain;
        } else {
            std::ifstream f(blob, std::ios::binary);
            if(!f.good()){ err="wallet.seed missing"; return false; }
            char hdr[8]={0}; f.read(hdr,8);
            std::ostringstream ss; ss << f.rdbuf();
            std::string rest=ss.str();
            out_seed.assign(rest.begin(), rest.end());
        }
    }
    return true;
}

}
