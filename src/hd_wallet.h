#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <functional>

namespace miq {

// =============================================================================
// PRODUCTION HD WALLET v2.0
// =============================================================================
// BIP-39, BIP-32, BIP-44 compliant with gap limit support
// =============================================================================

// Provisional SLIP-44 coin type for MIQ (update when registered)
static constexpr uint32_t MIQ_COIN_TYPE = 5355; // placeholder

// BIP-44 derivation path constants
static constexpr uint32_t BIP44_PURPOSE = 44;
static constexpr uint32_t HARDENED_BIT = 0x80000000;

// Gap limit constants (industry standard)
static constexpr uint32_t DEFAULT_GAP_LIMIT = 20;      // Standard BIP-44 gap
static constexpr uint32_t MAX_GAP_LIMIT = 100;         // Reasonable maximum
static constexpr uint32_t MIN_GAP_LIMIT = 5;           // Minimum for safety

struct HdAccountMeta {
    uint32_t account = 0;
    uint32_t next_recv = 0;     // external chain (0) - next address to generate
    uint32_t next_change = 0;   // change chain   (1) - next change address
    uint32_t gap_limit = DEFAULT_GAP_LIMIT;  // v2.0: configurable gap limit
    uint32_t last_used_recv = 0;    // v2.0: highest used external index
    uint32_t last_used_change = 0;  // v2.0: highest used change index
    int64_t created_at = 0;         // v2.0: creation timestamp
    int64_t last_scan_height = 0;   // v2.0: last blockchain height scanned
    std::string wallet_name;        // v2.0: user-defined wallet name
};

// Address info for wallet UX
struct AddressInfo {
    std::string address;
    uint32_t chain;         // 0 = external, 1 = change
    uint32_t index;
    bool used;              // Has received transactions
    int64_t first_seen;     // First transaction timestamp
    uint64_t total_received;
    uint64_t current_balance;
};

// Wallet balance summary
struct WalletBalance {
    uint64_t confirmed;         // Spendable (6+ confirmations)
    uint64_t unconfirmed;       // Pending (1-5 confirmations)
    uint64_t immature;          // Coinbase rewards (100 block lock)
    uint64_t total;             // Sum of above
    uint64_t pending_send;      // Outgoing unconfirmed

    // Derived
    uint64_t spendable() const { return confirmed; }
    uint64_t awaiting() const { return unconfirmed + immature; }
};

// BIP-39 + BIP-32 light HD wallet. Stores only the seed (encrypted) + simple INI metadata.
class HdWallet {
public:
    HdWallet(const std::vector<uint8_t>& seed, const HdAccountMeta& meta);

    // Default constructor for loading
    HdWallet() = default;

    // ==========================================================================
    // BIP-39 MNEMONIC GENERATION
    // ==========================================================================

    // 12/24-word English mnemonic
    static bool GenerateMnemonic(int entropy_bits, std::string& out_mnemonic);

    // Validate mnemonic (checksum verification)
    static bool ValidateMnemonic(const std::string& mnemonic, std::string& err);

    // BIP-39 mnemonic -> 64-byte seed (PBKDF2-HMAC-SHA512)
    static bool MnemonicToSeed(const std::string& mnemonic,
                               const std::string& passphrase,
                               std::vector<uint8_t>& out_seed);

    // ==========================================================================
    // KEY DERIVATION (BIP-32/BIP-44)
    // ==========================================================================

    // Derive key for m/44'/MIQ'/account'/chain/index. Returns 32B priv + 33B compressed pub.
    bool DerivePrivPub(uint32_t account, uint32_t chain, uint32_t index,
                       std::vector<uint8_t>& out_priv,
                       std::vector<uint8_t>& out_pub) const;

    // Get extended public key (xpub) for account - for watch-only wallets
    bool GetAccountXpub(uint32_t account, std::string& out_xpub) const;

    // ==========================================================================
    // ADDRESS GENERATION (v2.0: Gap limit aware)
    // ==========================================================================

    // Next external address (increments next_recv, respects gap limit).
    bool GetNewAddress(std::string& out_addr);

    // Next change address (increments next_change).
    bool GetNewChangeAddress(std::string& out_addr);

    // Read-only: external address at index (does not change counters).
    bool GetAddressAt(uint32_t index, std::string& out_addr) const;

    // Read-only: change address at index.
    bool GetChangeAddressAt(uint32_t index, std::string& out_addr) const;

    // Get address info with usage status
    bool GetAddressInfo(uint32_t chain, uint32_t index, AddressInfo& info) const;

    // ==========================================================================
    // GAP LIMIT MANAGEMENT (v2.0)
    // ==========================================================================

    // Set gap limit (validates range)
    bool SetGapLimit(uint32_t gap_limit, std::string& err);

    // Mark an address as used (updates last_used counters)
    void MarkAddressUsed(uint32_t chain, uint32_t index);

    // Check if more addresses can be generated (respects gap limit)
    bool CanGenerateMore(uint32_t chain) const;

    // Get number of unused addresses in lookahead
    uint32_t UnusedAddressCount(uint32_t chain) const;

    // Scan for used addresses up to gap_limit after last known used
    // Returns highest used index found, or -1 if none
    int32_t ScanForUsedAddresses(uint32_t chain,
                                  std::function<bool(const std::string&)> is_used);

    // ==========================================================================
    // WALLET STATE
    // ==========================================================================

    const HdAccountMeta& meta() const { return meta_; }
    void set_meta(const HdAccountMeta& m) { meta_ = m; }

    const std::vector<uint8_t>& seed() const { return seed_; }
    bool has_seed() const { return seed_.size() == 64; }

    // ==========================================================================
    // SERIALIZATION
    // ==========================================================================

    static std::string MetaToIni(const HdAccountMeta& m);
    static bool MetaFromIni(const std::string& text, HdAccountMeta& m_out);

    // v2.0: JSON serialization for metadata
    static std::string MetaToJson(const HdAccountMeta& m);
    static bool MetaFromJson(const std::string& json, HdAccountMeta& m_out);

private:
    std::vector<uint8_t> seed_; // 64 bytes
    HdAccountMeta meta_;
};

// =============================================================================
// WALLET PERSISTENCE
// =============================================================================

// Save/Load encrypted seed + INI metadata under a wallet directory.
// If MIQ_ENABLE_WALLET_ENC and walletpass != "", the seed is encrypted.
bool SaveHdWallet(const std::string& path_dir,
                  const std::vector<uint8_t>& seed,
                  const HdAccountMeta& meta,
                  const std::string& walletpass,
                  std::string& err);

bool LoadHdWallet(const std::string& path_dir,
                  std::vector<uint8_t>& out_seed,
                  HdAccountMeta& out_meta,
                  const std::string& walletpass,
                  std::string& err);

// v2.0: Atomic save with crash recovery
bool SaveHdWalletAtomic(const std::string& path_dir,
                        const std::vector<uint8_t>& seed,
                        const HdAccountMeta& meta,
                        const std::string& walletpass,
                        std::string& err);

// v2.0: Export wallet as encrypted backup
bool ExportWalletBackup(const std::string& wallet_dir,
                        const std::string& backup_path,
                        const std::string& walletpass,
                        std::string& err);

// v2.0: Import wallet from backup
bool ImportWalletBackup(const std::string& backup_path,
                        const std::string& wallet_dir,
                        const std::string& walletpass,
                        std::string& err);

// =============================================================================
// ADDRESS UTILITIES
// =============================================================================

// Convert a compressed pubkey (33B) to Base58 P2PKH using your chain's version byte.
std::string PubkeyToAddress(const std::vector<uint8_t>& pub33);

// Validate address format and checksum
bool ValidateAddress(const std::string& address, std::string& err);

// Decode address to pubkey hash (20 bytes)
bool AddressToPkh(const std::string& address, std::vector<uint8_t>& pkh);

}
