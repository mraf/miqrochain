#pragma once
// =============================================================================
// ADDRESS INDEX - Fast lookup of transactions by address (PKH)
// =============================================================================
// This index enables blockchain explorer functionality by mapping:
//   - Address (PKH) → List of transactions involving that address
//   - Block Hash → Block Height (for O(1) block lookups)
//
// Design:
//   - Tracks both inputs (spent from) and outputs (received to) for each address
//   - Persisted to disk using append-only log + periodic compaction
//   - Thread-safe with fine-grained locking
//   - Supports efficient pagination for large address histories
//
// Storage format (LevelDB-like key-value):
//   Key: PKH (20 bytes) + height (8 bytes) + txpos (4 bytes) + type (1 byte)
//   Value: txid (32 bytes) + value (8 bytes) + vout/vin index (4 bytes)
// =============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <map>
#include <mutex>
#include <functional>
#include <fstream>
#include <array>

namespace miq {

// Forward declarations
struct Transaction;
struct Block;

// =============================================================================
// ADDRESS TRANSACTION ENTRY
// =============================================================================
// Represents a single transaction interaction with an address
struct AddressTxEntry {
    std::vector<uint8_t> txid;      // 32-byte transaction ID
    uint64_t block_height{0};       // Block height (0 = mempool/unconfirmed)
    uint32_t tx_position{0};        // Position within block
    int64_t  timestamp{0};          // Block timestamp

    // Transaction details
    bool     is_input{false};       // true = spent FROM this address, false = received TO
    uint64_t value{0};              // Amount in miqrons
    uint32_t io_index{0};           // vout index (if output) or vin index (if input)

    // For inputs: which output was spent
    std::vector<uint8_t> spent_txid;  // TXID of the spent output (only for inputs)
    uint32_t spent_vout{0};           // vout index of spent output (only for inputs)

    // Comparison for sorting (by height desc, then tx_position desc)
    bool operator<(const AddressTxEntry& o) const {
        if (block_height != o.block_height) return block_height > o.block_height;
        if (tx_position != o.tx_position) return tx_position > o.tx_position;
        return is_input < o.is_input;  // outputs before inputs at same position
    }
};

// =============================================================================
// ADDRESS BALANCE
// =============================================================================
struct AddressBalance {
    uint64_t confirmed{0};          // Confirmed balance (spendable)
    uint64_t unconfirmed{0};        // Unconfirmed incoming
    uint64_t immature{0};           // Coinbase not yet mature
    uint64_t total_received{0};     // Total ever received
    uint64_t total_sent{0};         // Total ever sent
    uint32_t tx_count{0};           // Number of transactions
    uint32_t utxo_count{0};         // Number of unspent outputs
};

// =============================================================================
// ADDRESS INDEX CLASS
// =============================================================================
class AddressIndex {
public:
    AddressIndex() = default;
    ~AddressIndex();

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    // Open/create the index at the given data directory
    bool open(const std::string& datadir);

    // Close and flush all data
    void close();

    // Check if index is enabled/open
    bool is_enabled() const { return enabled_; }

    // -------------------------------------------------------------------------
    // Index Maintenance (called by Chain on block connect/disconnect)
    // -------------------------------------------------------------------------

    // Index a block's transactions
    bool index_block(const Block& block, uint64_t height);

    // Remove a block's transactions from index (for reorg)
    bool unindex_block(const Block& block, uint64_t height);

    // Index a single transaction (for mempool)
    bool index_transaction(const Transaction& tx, uint64_t height, uint32_t tx_pos, int64_t timestamp);

    // Remove transaction from index
    bool unindex_transaction(const std::vector<uint8_t>& txid);

    // -------------------------------------------------------------------------
    // Query API (for RPC)
    // -------------------------------------------------------------------------

    // Get all transaction IDs for an address
    // Returns txids sorted by height (most recent first)
    std::vector<std::vector<uint8_t>> get_address_txids(
        const std::vector<uint8_t>& pkh,
        uint64_t start_height = 0,
        uint64_t end_height = UINT64_MAX,
        size_t skip = 0,
        size_t limit = 100
    ) const;

    // Get full transaction history for an address
    std::vector<AddressTxEntry> get_address_history(
        const std::vector<uint8_t>& pkh,
        uint64_t start_height = 0,
        uint64_t end_height = UINT64_MAX,
        size_t skip = 0,
        size_t limit = 100
    ) const;

    // Get address balance
    AddressBalance get_address_balance(
        const std::vector<uint8_t>& pkh,
        uint64_t current_height,
        uint64_t coinbase_maturity = 100
    ) const;

    // Get transaction count for address
    size_t get_address_tx_count(const std::vector<uint8_t>& pkh) const;

    // Check if address has any transactions
    bool has_transactions(const std::vector<uint8_t>& pkh) const;

    // -------------------------------------------------------------------------
    // Block Hash Index (for O(1) block-by-hash lookup)
    // -------------------------------------------------------------------------

    // Add block hash → height mapping
    void add_block_hash(const std::vector<uint8_t>& hash, uint64_t height);

    // Remove block hash mapping
    void remove_block_hash(const std::vector<uint8_t>& hash);

    // Get height for block hash (returns -1 if not found)
    int64_t get_height_for_hash(const std::vector<uint8_t>& hash) const;

    // Check if block hash exists
    bool has_block_hash(const std::vector<uint8_t>& hash) const;

    // -------------------------------------------------------------------------
    // Persistence
    // -------------------------------------------------------------------------

    // Flush pending changes to disk
    bool flush();

    // Full reindex from genesis (call with chain data)
    // Progress callback: (current_height, total_height) -> bool (return false to abort)
    using ProgressCallback = std::function<bool(uint64_t, uint64_t)>;
    bool reindex(const std::function<bool(uint64_t, Block&)>& get_block_fn,
                 uint64_t chain_height,
                 ProgressCallback progress = nullptr);

    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------

    // Get number of indexed addresses
    size_t address_count() const;

    // Get number of indexed transactions
    size_t transaction_count() const;

    // Get number of indexed block hashes
    size_t block_hash_count() const;

    // Get index size on disk (bytes)
    size_t disk_usage() const;

    // Get highest indexed block
    uint64_t best_indexed_height() const { return best_height_; }

private:
    // -------------------------------------------------------------------------
    // Internal Types
    // -------------------------------------------------------------------------

    // Key for address entries: combines PKH with transaction details
    struct AddrKey {
        std::array<uint8_t, 20> pkh;
        uint64_t height;
        uint32_t tx_pos;
        uint8_t  type;  // 0 = output (received), 1 = input (spent)
        uint32_t io_idx;

        bool operator<(const AddrKey& o) const;
        bool operator==(const AddrKey& o) const;
        std::string to_string() const;
        static AddrKey from_string(const std::string& s);
    };

    struct AddrKeyHash {
        size_t operator()(const AddrKey& k) const noexcept;
    };

    // Stored value for each entry
    struct AddrValue {
        std::array<uint8_t, 32> txid;
        uint64_t value;
        int64_t  timestamp;
        std::array<uint8_t, 32> spent_txid;  // Only for inputs
        uint32_t spent_vout;                  // Only for inputs

        std::string serialize() const;
        static AddrValue deserialize(const std::string& s);
    };

    // -------------------------------------------------------------------------
    // Internal Methods
    // -------------------------------------------------------------------------

    // Convert PKH to map key
    static std::string pkh_key(const std::vector<uint8_t>& pkh);
    static std::string hash_key(const std::vector<uint8_t>& hash);

    // Persistence helpers
    bool load_from_disk();
    bool save_to_disk() const;
    bool append_log(char op, const AddrKey& key, const AddrValue* val);
    bool append_hash_log(char op, const std::vector<uint8_t>& hash, uint64_t height);

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------
    mutable std::recursive_mutex mtx_;

    std::string datadir_;
    std::string addr_log_path_;
    std::string hash_log_path_;
    std::string state_path_;

    bool enabled_{false};
    bool dirty_{false};
    uint64_t best_height_{0};

    // Address → Transaction entries
    // Key: PKH hex string
    // Value: sorted set of transaction entries for this address
    std::unordered_map<std::string, std::vector<AddressTxEntry>> addr_index_;

    // Block hash → height mapping
    std::unordered_map<std::string, uint64_t> hash_index_;

    // Transaction → addresses mapping (for fast unindexing)
    std::unordered_map<std::string, std::vector<std::string>> tx_to_addrs_;

    // Statistics
    size_t total_entries_{0};

    // Constants
    static constexpr uint32_t ADDR_INDEX_MAGIC = 0x41444958;  // "ADIX"
    static constexpr uint32_t ADDR_INDEX_VERSION = 1;
    static constexpr size_t MAX_ENTRIES_PER_ADDRESS = 10000000;  // 10M tx limit per address
    static constexpr size_t FLUSH_INTERVAL = 1000;  // Flush every N blocks
};

// =============================================================================
// BLOCK HASH INDEX (Standalone helper for Chain class)
// =============================================================================
// Lightweight hash→height index that can be embedded in Chain
class BlockHashIndex {
public:
    BlockHashIndex() = default;

    void add(const std::vector<uint8_t>& hash, uint64_t height);
    void remove(const std::vector<uint8_t>& hash);
    int64_t get(const std::vector<uint8_t>& hash) const;
    bool has(const std::vector<uint8_t>& hash) const;
    size_t size() const;
    void clear();

    // Persistence
    bool save(const std::string& path) const;
    bool load(const std::string& path);

private:
    mutable std::mutex mtx_;
    std::unordered_map<std::string, uint64_t> index_;

    static std::string key(const std::vector<uint8_t>& hash);
};

}  // namespace miq
