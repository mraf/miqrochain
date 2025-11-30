#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <chrono>
#include <mutex>         // CRITICAL FIX: Thread safety

#include "tx.h"          // Transaction

namespace miq {

// Forward declarations to avoid heavy includes here.
struct UTXOEntry;        // defined in utxo.h / utxo_kv.h
struct Block;            // defined in block.h
class  UTXOSet;          // defined in utxo.h

// =============================================================================
// PRODUCTION-GRADE MEMPOOL CONFIGURATION
// =============================================================================

// Tunables (can be overridden via -D or constants.h if you expose them there)
#ifndef MIQ_MEMPOOL_MAX_BYTES
#define MIQ_MEMPOOL_MAX_BYTES (300u * 1024u * 1024u) // 300 MiB production
#endif
#ifndef MIQ_MEMPOOL_MAX_ANCESTORS
#define MIQ_MEMPOOL_MAX_ANCESTORS 50  // Production: deeper chains
#endif
#ifndef MIQ_MEMPOOL_MAX_DESCENDANTS
#define MIQ_MEMPOOL_MAX_DESCENDANTS 50  // Production: more descendants
#endif
#ifndef MIQ_MEMPOOL_TX_EXPIRY_SECS
#define MIQ_MEMPOOL_TX_EXPIRY_SECS (14u * 24u * 60u * 60u) // 14 days
#endif
#ifndef MIQ_MEMPOOL_MIN_RELAY_FEE
#define MIQ_MEMPOOL_MIN_RELAY_FEE 1  // 1 miqron/byte minimum
#endif
#ifndef MIQ_MEMPOOL_INCREMENTAL_FEE
#define MIQ_MEMPOOL_INCREMENTAL_FEE 1  // 1 miqron/byte for RBF bump
#endif
#ifndef MIQ_MEMPOOL_RBF_ENABLED
#define MIQ_MEMPOOL_RBF_ENABLED 1  // Enable Replace-By-Fee
#endif

// Lightweight UTXO view interface (Chain passes its UTXO backend)
class UTXOView {
public:
    virtual ~UTXOView() = default;
    virtual bool get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const = 0;
};

// Policy parameters for acceptance (reserved for future extension)
struct AcceptPolicy {
    uint32_t current_height{0};
    size_t   max_ancestors{MIQ_MEMPOOL_MAX_ANCESTORS};
    size_t   max_descendants{MIQ_MEMPOOL_MAX_DESCENDANTS};
    size_t   max_pool_bytes{MIQ_MEMPOOL_MAX_BYTES};
    bool     require_standard{false};
};

struct MempoolEntry {
    Transaction tx;
    size_t      size_bytes{0};
    uint64_t    fee{0};
    double      fee_rate{0.0}; // miqron/byte
    int64_t     added_ms{0};

    // Graph links
    std::unordered_set<std::string> parents;   // txid keys of parents in mempool
    std::unordered_set<std::string> children;  // txid keys of direct children in mempool

    // Aggregate limits
    size_t ancestor_count{0};
    size_t ancestor_size{0};
    size_t descendant_count{0};
    size_t descendant_size{0};

    // Production enhancements
    uint64_t    ancestor_fee{0};      // Total ancestor fees (for CPFP)
    uint64_t    descendant_fee{0};    // Total descendant fees
    double      modified_fee_rate{0.0}; // Fee rate including CPFP bonus
    uint32_t    height_entered{0};    // Block height when entered mempool
    bool        replaceable{true};    // BIP-125 RBF signaling
    uint32_t    time_in_mempool{0};   // Seconds in mempool

    // Mining score (higher = more likely to be mined)
    double mining_score() const {
        // CPFP-aware: use the better of individual or package rate
        // Note: Using (std::max) with parentheses to avoid Windows max macro conflict
        return (std::max)(fee_rate, modified_fee_rate);
    }
};

// Fee estimation bucket for production-grade fee estimation
struct FeeEstimateBucket {
    double low_priority{1.0};    // miqron/byte for 6+ blocks
    double medium_priority{2.0}; // miqron/byte for 2-6 blocks
    double high_priority{5.0};   // miqron/byte for next block
    int64_t last_updated_ms{0};
};

class Mempool {
public:
    Mempool();
    ~Mempool() = default;

    // Primary accept (generic UTXOView)
    bool accept(const Transaction& tx, const UTXOView& utxo, uint32_t height, std::string& err);
    // Convenience overload for existing call sites that pass UTXOSet directly.
    bool accept(const Transaction& tx, const UTXOSet& utxo, uint32_t height, std::string& err);

    // When a block connects: remove its transactions and any conflicts.
    void on_block_connect(const Block& b);

    // When a block disconnects (reorg): try re-adding its non-coinbase txs.
    void on_block_disconnect(const Block& b, const UTXOView& utxo, uint32_t height);
    // Convenience overload for UTXOSet
    void on_block_disconnect(const Block& b, const UTXOSet& utxo, uint32_t height);

    // Periodic house-keeping: expire old txs and trim to max size.
    void maintenance();

    // Manual trim (e.g., after large batch)
    void trim_to_size(size_t max_bytes);

    // Snapshots
    size_t size()        const { return map_.size(); }
    size_t bytes_used()  const { return total_bytes_; }
    size_t orphan_count() const { return orphans_.size(); }
    bool   exists(const std::vector<uint8_t>& txid) const;

    // For miner: simple parents-first, highest-feerate up to `max` transactions
    std::vector<Transaction> collect(size_t max) const;

    // For miner (SFINAE target): take a size-capped parents-first snapshot
    void snapshot(std::vector<Transaction>& out) const;
    void collect_for_block(std::vector<Transaction>& out, size_t max_bytes) const;

    // For P2P serving (ids only)
    std::vector<std::vector<uint8_t>> txids() const;

    // === PRODUCTION-GRADE ENHANCEMENTS ===

    // Fee estimation (returns miqron/byte for target confirmation)
    double estimate_fee(int target_blocks) const;
    FeeEstimateBucket get_fee_estimates() const;
    void update_fee_estimates(uint32_t height);

    // RBF (Replace-By-Fee) support
    bool accept_replacement(const Transaction& tx, const UTXOView& utxo,
                           uint32_t height, std::string& err);
    // Convenience overload for UTXOSet
    bool accept_replacement(const Transaction& tx, const UTXOSet& utxo,
                           uint32_t height, std::string& err);
    bool is_rbf_candidate(const Transaction& tx) const;

    // CPFP (Child-Pays-For-Parent) support
    void update_cpfp_scores();
    double get_package_fee_rate(const std::vector<uint8_t>& txid) const;

    // Production statistics
    struct MempoolStats {
        size_t tx_count{0};
        size_t bytes_used{0};
        size_t orphan_count{0};
        size_t orphan_bytes{0};
        double min_fee_rate{0.0};
        double max_fee_rate{0.0};
        double avg_fee_rate{0.0};
        double median_fee_rate{0.0};
        uint64_t total_fees{0};
        int64_t avg_age_ms{0};
    };
    MempoolStats get_stats() const;

    // Get transaction by txid
    bool get_transaction(const std::vector<uint8_t>& txid, Transaction& out) const;

    // Check if inputs are spent in mempool
    bool has_spent_input(const std::vector<uint8_t>& txid, uint32_t vout) const;

    // Memory usage details
    size_t dynamic_memory_usage() const;

    // === MEMPOOL PERSISTENCE ===
    // Save mempool to disk for recovery after restart
    bool save_to_disk(const std::string& path) const;
    // Load mempool from disk (call after construction, before accepting new txs)
    bool load_from_disk(const std::string& path, const UTXOView& utxo, uint32_t height);

    // Get all raw transactions for persistence/relay
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> get_all_raw_txs() const;

private:
    using Key = std::string; // binary-safe txid key

    static Key k(const std::vector<uint8_t>& txid);
    static size_t est_tx_size(const Transaction& tx);
    static uint64_t sum_outputs(const Transaction& tx);
    static int64_t now_ms();

    // Graph management
    void link_child_to_parents(const Key& child, const std::vector<TxIn>& vin);
    void unlink_entry(const Key& k);

    // Ancestor/descendant accounting
    bool compute_ancestor_stats(const Key& k, size_t& cnt, size_t& bytes) const;
    bool compute_descendant_stats(const Key& k, size_t& cnt, size_t& bytes) const;

    // Acceptance path
    bool validate_inputs_and_calc_fee(const Transaction& tx, const UTXOView& utxo, uint32_t height, uint64_t& fee, std::string& err) const;
    bool enforce_limits_and_insert(const Transaction& tx, uint64_t fee, std::string& err);

    // Orphan handling
    void add_orphan(const Transaction& tx);
    void remove_orphan(const Key& k);
    void try_promote_orphans_depending_on(const Key& parent, const UTXOView& utxo, uint32_t height);

    // Eviction helpers
    void evict_lowest_feerate_until(size_t target_bytes);

private:
    // CRITICAL FIX: Thread safety - protect all mutable state
    mutable std::recursive_mutex mtx_;

    std::unordered_map<Key, MempoolEntry> map_;
    size_t total_bytes_{0};

    // CRITICAL FIX: Double-spend detection - track spent outputs
    // Key format: txid_hex + ":" + vout_str
    std::unordered_set<std::string> spent_outputs_;

    // Orphans: key=child txid (presently missing at least one input)
    std::unordered_map<Key, Transaction> orphans_;
    // Reverse index: missing parent txid key -> set of orphans waiting on it
    std::unordered_map<Key, std::unordered_set<Key>> waiting_on_;

    // CRITICAL FIX: Orphan pool limits
    static constexpr size_t MAX_ORPHANS = 10000;  // Production: 10x more
    static constexpr size_t MAX_ORPHAN_BYTES = 64 * 1024 * 1024; // 64 MiB production
    size_t orphan_bytes_{0};

    // === PRODUCTION FEE ESTIMATION ===
    FeeEstimateBucket fee_estimates_;

    // Fee rate histogram for estimation (buckets: 1, 2, 5, 10, 20, 50, 100+ miqron/byte)
    std::vector<std::pair<double, size_t>> fee_histogram_;  // (feerate, count)

    // Track confirmed transactions for fee estimation
    struct ConfirmedTxData {
        double fee_rate;
        int blocks_to_confirm;
        int64_t timestamp_ms;
    };
    std::deque<ConfirmedTxData> confirmed_history_;
    static constexpr size_t MAX_CONFIRMED_HISTORY = 10000;

    // RBF tracking
    std::unordered_map<Key, uint64_t> replacement_count_;  // txid -> times replaced

    // Helper for RBF validation
    bool validate_rbf_rules(const Transaction& new_tx, const MempoolEntry& old_entry,
                           uint64_t new_fee, std::string& err) const;
};

}  // namespace miq
