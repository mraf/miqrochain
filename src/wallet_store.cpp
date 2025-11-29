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
#include <algorithm>
#include <ctime>

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

// =============================================================================
// CRASH-SAFE WALLET FILE OPERATIONS v2.0
// =============================================================================

// Simple CRC32 for integrity checking
static uint32_t crc32_wallet(const uint8_t* data, size_t len) {
    static const uint32_t crc_table[256] = {
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
        0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
        0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
        0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
        0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
        0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
        0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
        0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
        0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
        0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
        0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
        0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
        0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
        0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
        0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
        0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
        0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
        0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
        0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7822, 0x5005713c, 0x270241aa,
        0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
        0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
        0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
        0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
        0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
        0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
        0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
        0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
        0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
        0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
        0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
        0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
        0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
        0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
        0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
        0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
        0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
        0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
        0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
        0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
        0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
        0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
        0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
        0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
    };
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc = crc_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
    }
    return crc ^ 0xFFFFFFFF;
}

bool wallet_atomic_save(const std::string& path,
                        const std::vector<uint8_t>& data,
                        const std::string& passphrase,
                        std::string& err)
{
    std::lock_guard<std::mutex> lock(g_wallet_file_mutex);

    // Create versioned backup before save
    if (fs::exists(path)) {
        std::string backup_err;
        wallet_create_backup(path, 3, backup_err);  // Keep 3 backups
    }

    // Build wallet file with header
    std::vector<uint8_t> file_data;
    file_data.reserve(16 + data.size());

    // Magic (4 bytes)
    file_data.push_back('M');
    file_data.push_back('Q');
    file_data.push_back('W');
    file_data.push_back('2');

    // Version (4 bytes, little-endian)
    uint32_t ver = WALLET_FILE_VERSION;
    file_data.push_back(ver & 0xFF);
    file_data.push_back((ver >> 8) & 0xFF);
    file_data.push_back((ver >> 16) & 0xFF);
    file_data.push_back((ver >> 24) & 0xFF);

    // Payload length (4 bytes, little-endian)
    uint32_t len = static_cast<uint32_t>(data.size());
    file_data.push_back(len & 0xFF);
    file_data.push_back((len >> 8) & 0xFF);
    file_data.push_back((len >> 16) & 0xFF);
    file_data.push_back((len >> 24) & 0xFF);

    // CRC32 of payload (4 bytes, little-endian)
    uint32_t crc = crc32_wallet(data.data(), data.size());
    file_data.push_back(crc & 0xFF);
    file_data.push_back((crc >> 8) & 0xFF);
    file_data.push_back((crc >> 16) & 0xFF);
    file_data.push_back((crc >> 24) & 0xFF);

    // Payload
    file_data.insert(file_data.end(), data.begin(), data.end());

    // Write using existing atomic write function
    return wallet_write_bytes(path, file_data, passphrase, err);
}

bool wallet_atomic_load(const std::string& path,
                        std::vector<uint8_t>& data,
                        const std::string& passphrase,
                        std::string& err)
{
    std::vector<uint8_t> file_data;

    // Try to read primary file
    if (!wallet_read_bytes(path, file_data, passphrase, err)) {
        // Try to recover from backup
        std::string backup = wallet_get_latest_backup(path);
        if (!backup.empty()) {
            if (wallet_read_bytes(backup, file_data, passphrase, err)) {
                // Restore from backup
                std::error_code ec;
                fs::copy_file(backup, path, fs::copy_options::overwrite_existing, ec);
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    // Check minimum size (header = 16 bytes)
    if (file_data.size() < 16) {
        // Legacy file format - no header
        data = std::move(file_data);
        return true;
    }

    // Check magic
    if (file_data[0] != 'M' || file_data[1] != 'Q' ||
        file_data[2] != 'W' || file_data[3] != '2') {
        // Legacy file format - no header
        data = std::move(file_data);
        return true;
    }

    // Parse header
    uint32_t ver = file_data[4] | (file_data[5] << 8) |
                   (file_data[6] << 16) | (file_data[7] << 24);
    uint32_t len = file_data[8] | (file_data[9] << 8) |
                   (file_data[10] << 16) | (file_data[11] << 24);
    uint32_t stored_crc = file_data[12] | (file_data[13] << 8) |
                          (file_data[14] << 16) | (file_data[15] << 24);

    (void)ver;  // Version check could be added here

    // Validate length
    if (16 + len > file_data.size()) {
        err = "corrupted wallet file: length mismatch";
        // Try backup recovery
        return wallet_recover_from_backup(path, err);
    }

    // Extract payload
    data.assign(file_data.begin() + 16, file_data.begin() + 16 + len);

    // Verify CRC
    uint32_t computed_crc = crc32_wallet(data.data(), data.size());
    if (computed_crc != stored_crc) {
        err = "corrupted wallet file: CRC mismatch";
        // Try backup recovery
        return wallet_recover_from_backup(path, err);
    }

    return true;
}

bool wallet_verify_integrity(const std::string& path, std::string& err) {
    std::vector<uint8_t> data;
    std::string passphrase = getenv_str("MIQ_WALLET_PASSPHRASE");
    return wallet_atomic_load(path, data, passphrase, err);
}

bool wallet_recover_from_backup(const std::string& path, std::string& err) {
    std::string backup = wallet_get_latest_backup(path);
    if (backup.empty()) {
        err = "no backup available";
        return false;
    }

    std::error_code ec;
    fs::copy_file(backup, path, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        err = "failed to restore from backup: " + ec.message();
        return false;
    }

    return true;
}

bool wallet_create_backup(const std::string& path, int max_backups, std::string& err) {
    if (!fs::exists(path)) {
        return true;  // Nothing to backup
    }

    // Generate backup filename with timestamp
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", std::localtime(&time));
    std::string backup_path = path + ".bak." + buf;

    std::error_code ec;
    fs::copy_file(path, backup_path, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        err = "backup failed: " + ec.message();
        return false;
    }

    // Clean up old backups
    std::vector<std::string> backups;
    fs::path parent = fs::path(path).parent_path();
    std::string base = fs::path(path).filename().string();

    for (const auto& entry : fs::directory_iterator(parent, ec)) {
        std::string name = entry.path().filename().string();
        if (name.rfind(base + ".bak.", 0) == 0) {
            backups.push_back(entry.path().string());
        }
    }

    // Sort backups by name (which includes timestamp)
    std::sort(backups.begin(), backups.end());

    // Remove old backups
    while (backups.size() > static_cast<size_t>(max_backups)) {
        std::remove(backups.front().c_str());
        backups.erase(backups.begin());
    }

    return true;
}

std::string wallet_get_latest_backup(const std::string& path) {
    std::error_code ec;
    fs::path parent = fs::path(path).parent_path();
    std::string base = fs::path(path).filename().string();

    std::vector<std::string> backups;
    for (const auto& entry : fs::directory_iterator(parent, ec)) {
        std::string name = entry.path().filename().string();
        if (name.rfind(base + ".bak", 0) == 0) {
            backups.push_back(entry.path().string());
        }
    }

    if (backups.empty()) return "";

    std::sort(backups.begin(), backups.end());
    return backups.back();  // Most recent
}

bool wallet_read_metadata(const std::string& path, WalletMetadata& meta, std::string& err) {
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        err = "cannot open file";
        return false;
    }

    unsigned char header[16];
    if (std::fread(header, 1, 16, f) != 16) {
        std::fclose(f);
        meta.version = 1;  // Legacy format
        return true;
    }
    std::fclose(f);

    // Check magic
    if (header[0] == 'M' && header[1] == 'Q' &&
        header[2] == 'W' && header[3] == '2') {
        meta.version = header[4] | (header[5] << 8) |
                       (header[6] << 16) | (header[7] << 24);
        meta.encrypted = is_encrypted_wallet_file(path);
    } else if (header[0] == 'M' && header[1] == 'I' &&
               header[2] == 'Q' && header[3] == 'W') {
        meta.version = 1;
        meta.encrypted = true;
    } else {
        meta.version = 1;
        meta.encrypted = false;
    }

    // Get file timestamps
    std::error_code ec;
    auto ftime = fs::last_write_time(path, ec);
    if (!ec) {
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now());
        meta.last_modified = std::chrono::system_clock::to_time_t(sctp);
    }

    return true;
}

// Lock file support
#ifdef _WIN32
#include <windows.h>
int wallet_acquire_lock(const std::string& wallet_path, std::string& err) {
    std::string lock_path = wallet_path + ".lock";
    HANDLE h = CreateFileA(lock_path.c_str(), GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        err = "failed to acquire wallet lock";
        return -1;
    }
    return (int)(intptr_t)h;
}

void wallet_release_lock(int lock_fd) {
    if (lock_fd >= 0) {
        CloseHandle((HANDLE)(intptr_t)lock_fd);
    }
}

bool wallet_is_locked(const std::string& wallet_path) {
    std::string lock_path = wallet_path + ".lock";
    HANDLE h = CreateFileA(lock_path.c_str(), GENERIC_WRITE, 0, NULL,
                           OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        return GetLastError() == ERROR_SHARING_VIOLATION;
    }
    CloseHandle(h);
    return false;
}
#else
#include <fcntl.h>
#include <sys/file.h>

int wallet_acquire_lock(const std::string& wallet_path, std::string& err) {
    std::string lock_path = wallet_path + ".lock";
    int fd = open(lock_path.c_str(), O_CREAT | O_RDWR, 0644);
    if (fd < 0) {
        err = "failed to create lock file";
        return -1;
    }
    if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
        close(fd);
        err = "wallet is locked by another process";
        return -1;
    }
    return fd;
}

void wallet_release_lock(int lock_fd) {
    if (lock_fd >= 0) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
    }
}

bool wallet_is_locked(const std::string& wallet_path) {
    std::string lock_path = wallet_path + ".lock";
    int fd = open(lock_path.c_str(), O_RDWR);
    if (fd < 0) return false;
    bool locked = (flock(fd, LOCK_EX | LOCK_NB) < 0);
    if (!locked) flock(fd, LOCK_UN);
    close(fd);
    return locked;
}
#endif

std::string get_wallet_dir() {
    return appdata_dir();
}

std::vector<std::string> list_wallet_files() {
    std::vector<std::string> result;
    std::error_code ec;
    fs::path dir = fs::path(appdata_dir()) / "wallets";

    if (!fs::exists(dir, ec)) return result;

    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        if (entry.is_directory()) {
            fs::path wallet_file = entry.path() / "wallet.kv";
            if (fs::exists(wallet_file)) {
                result.push_back(wallet_file.string());
            }
        }
    }

    return result;
}

bool wallet_exists(const std::string& path) {
    return fs::exists(path);
}

bool wallet_delete(const std::string& path, bool create_backup, std::string& err) {
    if (!fs::exists(path)) {
        return true;  // Already gone
    }

    if (create_backup) {
        wallet_create_backup(path, 5, err);
    }

    std::error_code ec;
    fs::remove(path, ec);
    if (ec) {
        err = "failed to delete: " + ec.message();
        return false;
    }

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
