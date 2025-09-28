#include "wallet_store.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>

// Optional encryption hooks (compile-time switch in CMake)
#include "wallet_encryptor.h"

namespace fs = std::filesystem;
namespace miq {

// -------------------- helpers --------------------

static std::string appdata_dir() {
    const char* a = std::getenv("APPDATA");
    if (!a || !*a) return std::string(".");
    fs::path p(a);
    p /= "miqro";
    fs::create_directories(p);
    return p.string();
}

static std::string getenv_str(const char* k) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string();
}

static bool is_encrypted_wallet_file(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    unsigned char m[4] = {0,0,0,0};
    size_t n = std::fread(m, 1, 4, f);
    std::fclose(f);
    return n == 4 && m[0] == 'M' && m[1] == 'I' && m[2] == 'Q' && m[3] == 'W';
}

// Write bytes to disk, optionally encrypting when passphrase != "" and feature enabled.
static bool wallet_write_bytes(const std::string& path,
                               const std::vector<uint8_t>& bytes,
                               const std::string& passphrase,
                               std::string& err)
{
#if defined(MIQ_ENABLE_WALLET_ENC)
    if (!passphrase.empty()) {
        return miq::wallet_encrypt_to_file(path, bytes, passphrase, err);
    }
#endif
    std::string tmp = path + ".tmp";
    FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) { err = "open tmp failed"; return false; }
    bool ok = true;
    if (!bytes.empty()) {
        ok = std::fwrite(bytes.data(), 1, bytes.size(), f) == bytes.size();
    }
    std::fflush(f);
    std::fclose(f);
    if (!ok) { std::remove(tmp.c_str()); err = "write failed"; return false; }
    std::remove(path.c_str()); // ignore error
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        std::remove(tmp.c_str());
        err = "rename failed";
        return false;
    }
    return true;
}

// Read bytes from disk, auto-detecting encryption by magic when enabled.
static bool wallet_read_bytes(const std::string& path,
                              std::vector<uint8_t>& out,
                              const std::string& passphrase,
                              std::string& err)
{
#if defined(MIQ_ENABLE_WALLET_ENC)
    if (is_encrypted_wallet_file(path)) {
        return miq::wallet_decrypt_from_file(path, out, passphrase, err);
    }
#else
    // If encryption is disabled at build time and file is encrypted, refuse.
    if (is_encrypted_wallet_file(path)) {
        err = "wallet file is encrypted but MIQ_ENABLE_WALLET_ENC=OFF";
        return false;
    }
#endif
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) { err = "open failed"; return false; }
    std::vector<uint8_t> buf;
    unsigned char tmp[4096];
    while (true) {
        size_t n = std::fread(tmp, 1, sizeof(tmp), f);
        if (n) buf.insert(buf.end(), tmp, tmp + n);
        if (n < sizeof(tmp)) break;
    }
    std::fclose(f);
    out.swap(buf);
    return true;
}

// -------------------- public API --------------------

std::string default_wallet_file() {
    fs::path p(appdata_dir());
    p /= "wallets";
    p /= "default";
    fs::create_directories(p);
    p /= "wallet.kv";
    return p.string();
}

bool load_default_wallet_address(std::string& out) {
    const auto path = default_wallet_file();

    // If the file doesn't exist, just return false (legacy behavior)
    if (!fs::exists(path)) return false;

    std::string passphrase = getenv_str("MIQ_WALLET_PASSPHRASE");
    std::string err;
    std::vector<uint8_t> bytes;
    if (!wallet_read_bytes(path, bytes, passphrase, err)) {
        // Silent failure preserves legacy minimalism (no logging dependency here)
        return false;
    }

    // Parse the plaintext contents we just read (decrypted or plain)
    std::string text(bytes.begin(), bytes.end());
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.rfind("address=", 0) == 0) {
            out = line.substr(8);
            return !out.empty();
        }
    }
    return false;
}

bool save_default_wallet(const std::string& priv_hex,
                         const std::string& pub_hex,
                         const std::string& address)
{
    const auto path = default_wallet_file();

    // Serialize plaintext payload (same format as legacy)
    std::string payload;
    {
        std::ostringstream oss;
        oss << "version=1\n";
        oss << "curve=secp256k1\n";
        oss << "address="  << address  << "\n";
        oss << "priv_hex=" << priv_hex << "\n";
        oss << "pub_hex="  << pub_hex  << "\n";
        payload = oss.str();
    }

    std::vector<uint8_t> bytes(payload.begin(), payload.end());

    // Optional encryption via env var (no config changes needed)
    std::string passphrase = getenv_str("MIQ_WALLET_PASSPHRASE");
    std::string err;
    if (!wallet_write_bytes(path, bytes, passphrase, err)) {
        return false;
    }

    // Also write address.txt (plain) for convenience (no secrets leaked)
    std::ofstream a(fs::path(path).parent_path() / "address.txt",
                    std::ios::binary | std::ios::trunc);
    if (a) { a << address << "\n"; a.flush(); }

    return true;
}

}
