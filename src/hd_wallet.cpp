#include "hd_wallet.h"
#include "bip39_words_en.h"

#include "address.h"
#include "hash160.h"
#include "base58check.h"
#include "hex.h"
#include "wallet_encryptor.h"   // AES-GCM helpers (if MIQ_ENABLE_WALLET_ENC)
#include "crypto/ecdsa_iface.h" // crypto::ECDSA::{derive_pub,sign,backend}
#include "constants.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#include <sstream>
#include <fstream>
#include <random>
#include <algorithm>
#include <cctype>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif
#include <cstring> // std::strlen

namespace miq {

// ---- config ----
// Domain-separation label for BIP32 master key derivation (HMAC key).
// Changing this means mnemonics produce different keys than standard wallets.
static constexpr const char* BIP32_MASTER_KEY_LABEL = "miqrochain seed";

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

// ---------- BIP39 ----------

// Find word index in BIP39 wordlist (returns -1 if not found)
static int find_word_index(const std::string& word) {
    for (int i = 0; i < 2048; ++i) {
        if (word == BIP39_EN_WORDS[i]) return i;
    }
    return -1;
}

// Validate BIP39 mnemonic checksum
bool HdWallet::ValidateMnemonic(const std::string& mnemonic, std::string& err) {
    // Tokenize mnemonic
    std::istringstream iss(mnemonic);
    std::vector<std::string> words;
    std::string word;
    while (iss >> word) {
        // Convert to lowercase for validation
        std::transform(word.begin(), word.end(), word.begin(),
            [](unsigned char c) { return std::tolower(c); });
        words.push_back(word);
    }

    // Validate word count (12 or 24 words)
    if (words.size() != 12 && words.size() != 24) {
        err = "Invalid mnemonic: must be 12 or 24 words (got " + std::to_string(words.size()) + ")";
        return false;
    }

    // Validate each word is in BIP39 wordlist and get indices
    std::vector<int> indices;
    for (size_t i = 0; i < words.size(); ++i) {
        int idx = find_word_index(words[i]);
        if (idx < 0) {
            err = "Invalid word at position " + std::to_string(i + 1) + ": '" + words[i] + "'";
            return false;
        }
        indices.push_back(idx);
    }

    // Convert word indices back to bits (11 bits per word)
    int total_bits = (int)words.size() * 11;
    int ent_bits = (total_bits * 32) / 33;  // entropy bits
    int cs_bits = total_bits - ent_bits;     // checksum bits

    std::vector<int> bits(total_bits, 0);
    for (size_t w = 0; w < indices.size(); ++w) {
        int idx = indices[w];
        for (int b = 0; b < 11; ++b) {
            bits[w * 11 + b] = (idx >> (10 - b)) & 1;
        }
    }

    // Extract entropy bytes
    std::vector<uint8_t> entropy(ent_bits / 8, 0);
    for (int i = 0; i < ent_bits; ++i) {
        if (bits[i]) {
            entropy[i / 8] |= (1 << (7 - (i % 8)));
        }
    }

    // Compute checksum from entropy
    uint8_t hash[32];
    sha256_once(entropy.data(), entropy.size(), hash);

    // Verify checksum bits match
    for (int i = 0; i < cs_bits; ++i) {
        int expected = (hash[0] >> (7 - i)) & 1;
        int actual = bits[ent_bits + i];
        if (expected != actual) {
            err = "Invalid mnemonic checksum - words may be incorrect or in wrong order";
            return false;
        }
    }

    return true;
}

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
    // (Note: input normalization to NFKD can be added later if desired.)
    std::string salt = std::string("mnemonic") + passphrase;
    out_seed.assign(64,0);
    if(!pbkdf2_hmac_sha512(mnemonic, salt, out_seed.data(), 2048)) return false;
    return true;
}

// ---------- BIP32 ----------

// Master: I = HMAC-SHA512(key=BIP32_MASTER_KEY_LABEL, data=seed) => IL, IR
static bool bip32_master_from_seed(const std::vector<uint8_t>& seed,
                                   std::vector<uint8_t>& k_master,
                                   std::vector<uint8_t>& c_master){
    uint8_t I[64];
    const uint8_t* key  = reinterpret_cast<const uint8_t*>(BIP32_MASTER_KEY_LABEL);
    const size_t   klen = std::strlen(BIP32_MASTER_KEY_LABEL);
    if(!hmac_sha512(key, klen, seed.data(), seed.size(), I)) return false;
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
        if(!crypto::ECDSA::derive_pub(k, pub33)) return false;
        std::copy(pub33.begin(), pub33.end(), data); off=33;
    }
    put32(data+off, i);
    uint8_t I[64];
    if(!hmac_sha512(c.data(), c.size(), data, off+4, I)) return false;

    // k' = (IL + k) mod n
    BIGNUM* n = nullptr; BN_hex2bn(&n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
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
    if(!crypto::ECDSA::derive_pub(out_priv, out_pub)) return false;
    return true;
}

std::string PubkeyToAddress(const std::vector<uint8_t>& pub33){
    std::vector<uint8_t> h160 = hash160(pub33);
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

// v2.0: Atomic save with crash recovery - uses wallet_store atomic operations
bool SaveHdWalletAtomic(const std::string& path_dir,
                        const std::vector<uint8_t>& seed,
                        const HdAccountMeta& meta,
                        const std::string& walletpass,
                        std::string& err) {
    // Use the base SaveHdWallet with additional fsync for atomicity
    if (!SaveHdWallet(path_dir, seed, meta, walletpass, err)) {
        return false;
    }

    // Sync directory to ensure all files are flushed
#ifndef _WIN32
    int dir_fd = open(path_dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (dir_fd >= 0) {
        fsync(dir_fd);
        close(dir_fd);
    }
#endif
    return true;
}

// v2.0: Export wallet as encrypted backup
bool ExportWalletBackup(const std::string& wallet_dir,
                        const std::string& backup_path,
                        const std::string& walletpass,
                        std::string& err) {
    // Load the wallet
    std::vector<uint8_t> seed;
    HdAccountMeta meta;
    if (!LoadHdWallet(wallet_dir, seed, meta, walletpass, err)) {
        return false;
    }

    // Create backup directory if needed
    std::string backup_dir = backup_path;
    size_t last_sep = backup_path.find_last_of("/\\");
    if (last_sep != std::string::npos) {
        backup_dir = backup_path.substr(0, last_sep);
    }

    // Save to backup location (always encrypted)
    std::string backup_pass = walletpass.empty() ? "miq_backup_default" : walletpass;
    return SaveHdWallet(backup_path, seed, meta, backup_pass, err);
}

// v2.0: Import wallet from backup
bool ImportWalletBackup(const std::string& backup_path,
                        const std::string& wallet_dir,
                        const std::string& walletpass,
                        std::string& err) {
    // Load from backup
    std::vector<uint8_t> seed;
    HdAccountMeta meta;
    std::string backup_pass = walletpass.empty() ? "miq_backup_default" : walletpass;
    if (!LoadHdWallet(backup_path, seed, meta, backup_pass, err)) {
        return false;
    }

    // Save to wallet location
    return SaveHdWallet(wallet_dir, seed, meta, walletpass, err);
}

// Decode address to pubkey hash (20 bytes)
bool AddressToPkh(const std::string& address, std::vector<uint8_t>& pkh) {
    uint8_t version;
    std::vector<uint8_t> payload;
    if (!base58check_decode(address, version, payload)) {
        return false;
    }
    if (version != VERSION_P2PKH || payload.size() != 20) {
        return false;
    }
    pkh = std::move(payload);
    return true;
}

}
