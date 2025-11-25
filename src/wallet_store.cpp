#include "wallet_store.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <cstdio>
#include <vector>
#include <string>
#include <mutex>
#include <random>
#include <chrono>

#ifndef _WIN32
#include <unistd.h>  // for fsync
#endif

// Optional encryption hooks (compile-time switch in CMake)
#include "wallet_encryptor.h"

namespace fs = std::filesystem;
namespace miq {

// =============================================================================
// BULLETPROOF WALLET STORE v1.0 - Production-grade wallet file handling
// =============================================================================

// Global mutex for thread-safe file operations
static std::mutex g_wallet_file_mutex;

// -------------------- helpers --------------------

static std::string appdata_dir() {
#ifdef _WIN32
    const char* a = std::getenv("APPDATA");
    if (!a || !*a) {
        // Fallback to USERPROFILE if APPDATA is not set
        const char* up = std::getenv("USERPROFILE");
        if (up && *up) {
            fs::path p(up);
            p /= "AppData";
            p /= "Roaming";
            p /= "miqro";
            std::error_code ec;
            fs::create_directories(p, ec);
            return p.string();
        }
        return std::string(".");
    }
    fs::path p(a);
    p /= "miqro";
    std::error_code ec;
    fs::create_directories(p, ec);
    return p.string();
#else
    // Linux/macOS: use XDG_DATA_HOME or fallback to ~/.local/share
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && *xdg) {
        fs::path p(xdg);
        p /= "miqro";
        std::error_code ec;
        fs::create_directories(p, ec);
        return p.string();
    }
    const char* home = std::getenv("HOME");
    if (home && *home) {
        fs::path p(home);
        p /= ".local";
        p /= "share";
        p /= "miqro";
        std::error_code ec;
        fs::create_directories(p, ec);
        return p.string();
    }
    return std::string(".");
#endif
}

static std::string getenv_str(const char* k) {
    const char* v = std::getenv(k);
    return (v && *v) ? std::string(v) : std::string();
}

// Generate a unique temporary filename to avoid collisions
static std::string generate_tmp_filename(const std::string& base_path) {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 9999);
    return base_path + ".tmp." + std::to_string(now) + "." + std::to_string(dis(gen));
}

static bool is_encrypted_wallet_file(const std::string& path) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return false;
    unsigned char m[4] = {0,0,0,0};
    size_t n = std::fread(m, 1, 4, f);
    std::fclose(f);
    return n == 4 && m[0] == 'M' && m[1] == 'I' && m[2] == 'Q' && m[3] == 'W';
}

// IMPROVED: Write bytes to disk with thread-safety and robust atomic operations
static bool wallet_write_bytes(const std::string& path,
                               const std::vector<uint8_t>& bytes,
                               const std::string& passphrase,
                               std::string& err)
{
    // Thread-safe file operations
    std::lock_guard<std::mutex> lock(g_wallet_file_mutex);

#if defined(MIQ_ENABLE_WALLET_ENC)
    if (!passphrase.empty()) {
        return miq::wallet_encrypt_to_file(path, bytes, passphrase, err);
    }
#else
    (void)passphrase;  // Suppress unused parameter warning when encryption is disabled
#endif

    // Use unique temp filename to avoid collisions
    std::string tmp = generate_tmp_filename(path);

    // Ensure parent directory exists
    std::error_code ec;
    fs::path parent = fs::path(path).parent_path();
    if (!parent.empty()) {
        fs::create_directories(parent, ec);
        if (ec) {
            err = "failed to create directory: " + ec.message();
            return false;
        }
    }

    // Write to temporary file
    FILE* f = std::fopen(tmp.c_str(), "wb");
    if (!f) {
        err = "failed to create temporary file";
        return false;
    }

    bool write_ok = true;
    if (!bytes.empty()) {
        size_t written = std::fwrite(bytes.data(), 1, bytes.size(), f);
        write_ok = (written == bytes.size());
    }

    // Flush and sync to ensure data is on disk
    if (write_ok) {
        write_ok = (std::fflush(f) == 0);
    }

#ifndef _WIN32
    // On Unix, fsync to ensure durability
    if (write_ok) {
        int fd = fileno(f);
        if (fd >= 0) {
            fsync(fd);
        }
    }
#endif

    std::fclose(f);

    if (!write_ok) {
        std::remove(tmp.c_str());
        err = "write to temporary file failed";
        return false;
    }

    // Verify temp file was written correctly
    {
        std::error_code verify_ec;
        auto size = fs::file_size(tmp, verify_ec);
        if (verify_ec || size != bytes.size()) {
            std::remove(tmp.c_str());
            err = "file size verification failed";
            return false;
        }
    }

    // Create backup of existing file before replacing
    std::string backup = path + ".bak";
    if (fs::exists(path, ec)) {
        fs::copy_file(path, backup, fs::copy_options::overwrite_existing, ec);
        // Ignore backup errors - not critical
    }

    // Atomic rename: remove old file then rename temp to target
    std::remove(path.c_str()); // ignore error
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        // Try to recover from backup
        if (fs::exists(backup, ec)) {
            fs::copy_file(backup, path, fs::copy_options::overwrite_existing, ec);
        }
        std::remove(tmp.c_str());
        err = "atomic rename failed";
        return false;
    }

    // Clean up backup on success (optional - keep for recovery)
    // std::remove(backup.c_str());

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
    (void)passphrase;  // Suppress unused parameter warning when encryption is disabled
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
