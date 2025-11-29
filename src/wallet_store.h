#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// =============================================================================
// PRODUCTION WALLET STORE v2.0
// =============================================================================
// Crash-safe, versioned wallet storage with atomic saves and recovery
// =============================================================================

// Returns e.g. "C:\\Users\\You\\AppData\\Roaming\\miqro\\wallets\\default\\wallet.kv"
std::string default_wallet_file();

// Reads "address=<base58>" from default wallet file. Returns true & sets out on success.
// If built with MIQ_ENABLE_WALLET_ENC=ON and the file is encrypted, it will be
// transparently decrypted using the environment variable MIQ_WALLET_PASSPHRASE.
bool load_default_wallet_address(std::string& out);

// Writes priv/pub/address to the default wallet file. If MIQ_ENABLE_WALLET_ENC=ON
// and the environment variable MIQ_WALLET_PASSPHRASE is non-empty, the file is
// written encrypted (AES-256-GCM). Otherwise, legacy plaintext is used.
bool save_default_wallet(const std::string& priv_hex,
                         const std::string& pub_hex,
                         const std::string& address);

// =============================================================================
// CRASH-SAFE WALLET FILE OPERATIONS v2.0
// =============================================================================

// Wallet file format version
static constexpr uint32_t WALLET_FILE_VERSION = 2;

// Wallet file magic bytes for validation
static constexpr char WALLET_MAGIC[4] = {'M', 'Q', 'W', '2'};

// Write wallet data with crash-safe atomic operation
// Uses: write-to-temp -> fsync -> atomic-rename pattern
// Maintains versioned backups for recovery
bool wallet_atomic_save(const std::string& path,
                        const std::vector<uint8_t>& data,
                        const std::string& passphrase,
                        std::string& err);

// Load wallet with integrity verification
// Checks magic bytes, version, and checksum
// Falls back to backup if primary is corrupted
bool wallet_atomic_load(const std::string& path,
                        std::vector<uint8_t>& data,
                        const std::string& passphrase,
                        std::string& err);

// Verify wallet file integrity without loading
bool wallet_verify_integrity(const std::string& path, std::string& err);

// Recover wallet from backup files
bool wallet_recover_from_backup(const std::string& path, std::string& err);

// Create a versioned backup of the wallet
bool wallet_create_backup(const std::string& path,
                          int max_backups,
                          std::string& err);

// Get path to latest valid backup
std::string wallet_get_latest_backup(const std::string& path);

// =============================================================================
// WALLET METADATA
// =============================================================================

struct WalletMetadata {
    uint32_t version{WALLET_FILE_VERSION};
    int64_t created_at{0};           // Unix timestamp
    int64_t last_modified{0};        // Unix timestamp
    uint32_t save_count{0};          // Incremented on each save
    std::string wallet_name;         // User-defined name
    std::vector<uint8_t> checksum;   // SHA256 of payload
    bool encrypted{false};           // Is wallet encrypted
};

// Read metadata from wallet file (without decrypting payload)
bool wallet_read_metadata(const std::string& path, WalletMetadata& meta, std::string& err);

// =============================================================================
// WALLET LOCK FILE
// =============================================================================

// Acquire exclusive lock on wallet file (prevents concurrent access)
// Returns lock file descriptor/handle, or -1 on failure
int wallet_acquire_lock(const std::string& wallet_path, std::string& err);

// Release wallet lock
void wallet_release_lock(int lock_fd);

// Check if wallet is locked by another process
bool wallet_is_locked(const std::string& wallet_path);

// =============================================================================
// WALLET DIRECTORY UTILITIES
// =============================================================================

// Get wallet directory path
std::string get_wallet_dir();

// List all wallet files in default directory
std::vector<std::string> list_wallet_files();

// Check if wallet file exists
bool wallet_exists(const std::string& path);

// Delete wallet file (with backup)
bool wallet_delete(const std::string& path, bool create_backup, std::string& err);

}
