#include "wallet_encryptor.h"
#include "log.h"
#include "crypto/secure_random.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <string>
#include <vector>
#include <memory>

#if defined(MIQ_ENABLE_WALLET_ENC)

// OpenSSL path (optional feature)
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace miq {

static constexpr uint32_t MIQW_VER = 1;
static constexpr size_t   SALT_LEN = 16;
static constexpr size_t   IV_LEN   = 12;  // AES-GCM 96-bit IV
static constexpr size_t   TAG_LEN  = 16;  // AES-GCM tag
static constexpr int      PBKDF2_ITERS = 200000; // ~200k (tune in CI if needed)

// File layout (all little-endian where applicable):
//  magic[4] = 'M','I','Q','W'
//  version  (u32) = 1
//  kdf_id   (u32) = 1  (PBKDF2-HMAC-SHA256)
//  iters    (u32) = PBKDF2_ITERS
//  salt     (16)
//  iv       (12)
//  clen     (u32) ciphertext length
//  ct       (clen)
//  tag      (16)

static bool write_all(FILE* f, const void* p, size_t n){ return std::fwrite(p,1,n,f)==n; }
static bool read_all (FILE* f, void* p, size_t n){ return std::fread (p,1,n,f)==n; }

static void put_u32(std::vector<uint8_t>& b, uint32_t v){
    for(int i=0;i<4;i++) b.push_back(uint8_t((v>>(i*8))&0xff));
}

static uint32_t get_u32(const uint8_t* p){
    return (uint32_t)p[0] | ((uint32_t)p[1]<<8) | ((uint32_t)p[2]<<16) | ((uint32_t)p[3]<<24);
}

static bool kdf_derive_key(const std::string& pass,
                           const uint8_t* salt, size_t salt_len,
                           int iters,
                           uint8_t out32[32],
                           std::string& err)
{
    if(pass.empty()){ err = "empty passphrase"; return false; }
    if(1 != PKCS5_PBKDF2_HMAC(pass.c_str(), (int)pass.size(),
                               salt, (int)salt_len, iters,
                               EVP_sha256(), 32, out32))
    {
        err = "PBKDF2 failed";
        return false;
    }
    return true;
}

static bool aes256_gcm_encrypt(const std::vector<uint8_t>& key32,
                               const uint8_t iv[IV_LEN],
                               const uint8_t* ad, size_t ad_len,
                               const std::vector<uint8_t>& pt,
                               std::vector<uint8_t>& ct,
                               uint8_t tag[TAG_LEN],
                               std::string& err)
{
    const EVP_CIPHER* C = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ err="EVP_CIPHER_CTX_new failed"; return false; }

    bool ok=false;
    do{
        if(1!=EVP_EncryptInit_ex(ctx, C, nullptr, nullptr, nullptr)){ err="EncryptInit"; break; }
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr)){ err="GCM_SET_IVLEN"; break; }
        if(1!=EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), iv)){ err="EncryptInit key/iv"; break; }

        int outl=0;
        if(ad && ad_len){
            if(1!=EVP_EncryptUpdate(ctx, nullptr, &outl, ad, (int)ad_len)){ err="AAD update"; break; }
        }

        ct.resize(pt.size());
        if(!pt.empty()){
            if(1!=EVP_EncryptUpdate(ctx, ct.data(), &outl, pt.data(), (int)pt.size())){ err="EncryptUpdate"; break; }
        }
        int tmplen=0;
        if(1!=EVP_EncryptFinal_ex(ctx, ct.data()+outl, &tmplen)){ err="EncryptFinal"; break; }
        outl += tmplen;
        ct.resize((size_t)outl);

        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag)){ err="GET_TAG"; break; }
        ok=true;
    }while(false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static bool aes256_gcm_decrypt(const std::vector<uint8_t>& key32,
                               const uint8_t iv[IV_LEN],
                               const uint8_t* ad, size_t ad_len,
                               const std::vector<uint8_t>& ct,
                               const uint8_t tag[TAG_LEN],
                               std::vector<uint8_t>& pt,
                               std::string& err)
{
    const EVP_CIPHER* C = EVP_aes_256_gcm();
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if(!ctx){ err="EVP_CIPHER_CTX_new failed"; return false; }

    bool ok=false;
    do{
        if(1!=EVP_DecryptInit_ex(ctx, C, nullptr, nullptr, nullptr)){ err="DecryptInit"; break; }
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr)){ err="GCM_SET_IVLEN"; break; }
        if(1!=EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), iv)){ err="DecryptInit key/iv"; break; }

        int outl=0;
        if(ad && ad_len){
            if(1!=EVP_DecryptUpdate(ctx, nullptr, &outl, ad, (int)ad_len)){ err="AAD update"; break; }
        }

        pt.resize(ct.size());
        if(!ct.empty()){
            if(1!=EVP_DecryptUpdate(ctx, pt.data(), &outl, ct.data(), (int)ct.size())){ err="DecryptUpdate"; break; }
        }

        // set expected tag *before* final
        if(1!=EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void*)tag)){ err="SET_TAG"; break; }

        int tmplen=0;
        if(1!=EVP_DecryptFinal_ex(ctx, pt.data()+outl, &tmplen)){
            err="auth failed (wrong password or corrupted file)";
            break;
        }
        outl += tmplen;
        pt.resize((size_t)outl);
        ok=true;
    }while(false);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool wallet_encrypt_to_file(const std::string& path,
                            const std::vector<uint8_t>& plaintext,
                            const std::string& passphrase,
                            std::string& err)
{
    // Header AAD (authenticated, not encrypted)
    const uint8_t magic[4] = {'M','I','Q','W'};
    const uint32_t ver = MIQW_VER;
    const uint32_t kdf_id = 1; // PBKDF2-SHA256
    const uint32_t iters = PBKDF2_ITERS;

    uint8_t salt[SALT_LEN]; if(!secure_random(salt, sizeof(salt), &err)) return false;
    uint8_t iv[IV_LEN];     if(!secure_random(iv,   sizeof(iv),   &err)) return false;

    uint8_t key32[32];
    if(!kdf_derive_key(passphrase, salt, sizeof(salt), (int)iters, key32, err)) return false;
    std::vector<uint8_t> key(key32, key32+32);

    // Build AAD = magic||ver||kdf_id||iters||salt
    std::vector<uint8_t> aad;
    aad.insert(aad.end(), magic, magic+4);
    put_u32(aad, ver);
    put_u32(aad, kdf_id);
    put_u32(aad, iters);
    aad.insert(aad.end(), salt, salt+SALT_LEN);

    std::vector<uint8_t> ct;
    uint8_t tag[TAG_LEN];
    if(!aes256_gcm_encrypt(key, iv, aad.data(), aad.size(), plaintext, ct, tag, err))
        return false;

    std::string tmp = path + ".tmp";
    FILE* f = std::fopen(tmp.c_str(), "wb");
    if(!f){ err = "open tmp failed"; return false; }

    bool ok =
        write_all(f, magic, 4) &&
        write_all(f, &ver, sizeof(ver)) &&
        write_all(f, &kdf_id, sizeof(kdf_id)) &&
        write_all(f, &iters, sizeof(iters)) &&
        write_all(f, salt, SALT_LEN) &&
        write_all(f, iv, IV_LEN);

    uint32_t clen = (uint32_t)ct.size();
    ok = ok && write_all(f, &clen, sizeof(clen)) &&
             (clen ? write_all(f, ct.data(), ct.size()) : true) &&
             write_all(f, tag, TAG_LEN);

    std::fflush(f);
    std::fclose(f);

    if(!ok){
        std::remove(tmp.c_str());
        err = "write failed";
        return false;
    }

    std::remove(path.c_str()); // ignore errors
    if(std::rename(tmp.c_str(), path.c_str()) != 0){
        std::remove(tmp.c_str());
        err = "rename failed";
        return false;
    }
    return true;
}

bool wallet_decrypt_from_file(const std::string& path,
                              std::vector<uint8_t>& plaintext_out,
                              const std::string& passphrase,
                              std::string& err)
{
    FILE* f = std::fopen(path.c_str(), "rb");
    if(!f){ err="open failed"; return false; }

    uint8_t magic[4];
    uint32_t ver=0, kdf_id=0, iters=0;
    uint8_t salt[SALT_LEN], iv[IV_LEN];
    uint32_t clen=0;
    std::vector<uint8_t> ct;
    uint8_t tag[TAG_LEN];

    bool ok =
        read_all(f, magic, 4) &&
        read_all(f, &ver, sizeof(ver)) &&
        read_all(f, &kdf_id, sizeof(kdf_id)) &&
        read_all(f, &iters, sizeof(iters)) &&
        read_all(f, salt, SALT_LEN) &&
        read_all(f, iv, IV_LEN) &&
        read_all(f, &clen, sizeof(clen));

    if(!ok || std::memcmp(magic,"MIQW",4)!=0 || ver!=MIQW_VER || kdf_id!=1){
        std::fclose(f); err="bad header"; return false;
    }
    ct.resize(clen);
    if(clen && !read_all(f, ct.data(), clen)) { std::fclose(f); err="short file"; return false; }
    if(!read_all(f, tag, TAG_LEN)) { std::fclose(f); err="no tag"; return false; }
    std::fclose(f);

    // Rebuild AAD to verify
    std::vector<uint8_t> aad;
    aad.insert(aad.end(), magic, magic+4);
    {
        // write ver, kdf_id, iters (little-endian) into aad
        auto put = [&](uint32_t v){ for(int i=0;i<4;i++) aad.push_back(uint8_t((v>>(i*8))&0xff)); };
        put(ver); put(kdf_id); put(iters);
    }
    aad.insert(aad.end(), salt, salt+SALT_LEN);

    uint8_t key32[32];
    if(!kdf_derive_key(passphrase, salt, sizeof(salt), (int)iters, key32, err)) return false;
    std::vector<uint8_t> key(key32, key32+32);

    std::vector<uint8_t> pt;
    if(!aes256_gcm_decrypt(key, iv, aad.data(), aad.size(), ct, tag, pt, err))
        return false;

    plaintext_out.swap(pt);
    return true;
}

} // namespace miq

#else // MIQ_ENABLE_WALLET_ENC not defined

namespace miq {

bool wallet_encrypt_to_file(const std::string&, const std::vector<uint8_t>&,
                            const std::string&, std::string& err){
    err = "wallet encryption disabled at build time (MIQ_ENABLE_WALLET_ENC=OFF)";
    return false;
}

bool wallet_decrypt_from_file(const std::string&, std::vector<uint8_t>&,
                              const std::string&, std::string& err){
    err = "wallet encryption disabled at build time (MIQ_ENABLE_WALLET_ENC=OFF)";
    return false;
}

} // namespace miq
#endif
