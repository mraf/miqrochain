#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <chrono>

#include "tx.h"          // Transaction

namespace miq {

// Forward declarations to avoid heavy includes here.
struct UTXOEntry;        // defined in utxo.h / utxo_kv.h
struct Block;            // defined in block.h
class  UTXOSet;          // defined in utxo.h

// Tunables (can be overridden via -D or constants.h if you expose them there)
#ifndef MIQ_MEMPOOL_MAX_BYTES
#define MIQ_MEMPOOL_MAX_BYTES (64u * 1024u * 1024u) // 64 MiB
#endif
#ifndef MIQ_MEMPOOL_MAX_ANCESTORS
#define MIQ_MEMPOOL_MAX_ANCESTORS 25
#endif
#ifndef MIQ_MEMPOOL_MAX_DESCENDANTS
#define MIQ_MEMPOOL_MAX_DESCENDANTS 25
#endif
#ifndef MIQ_MEMPOOL_TX_EXPIRY_SECS
#define MIQ_MEMPOOL_TX_EXPIRY_SECS (14u * 24u * 60u * 60u) // 14 days
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
    double      fee_rate{0.0}; // sat/byte
    int64_t     added_ms{0};
    // Graph links
    std::unordered_set<std::string> parents;   // txid keys of parents in mempool
    std::unordered_set<std::string> children;  // txid keys of direct children in mempool
    // Aggregate limits
    size_t ancestor_count{0};
    size_t ancestor_size{0};
    size_t descendant_count{0};
    size_t descendant_size{0};
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
    bool   exists(const std::vector<uint8_t>& txid) const;

    // For miner: collect up to `max` txs (parents-first, highest feerate)
    std::vector<Transaction> collect(size_t max) const;

    // For P2P serving (ids only)
    std::vector<std::vector<uint8_t>> txids() const;

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
    bool validate_inputs_and_calc_fee(const Transaction& tx, const UTXOView& utxo, uint64_t& fee, std::string& err) const;
    bool enforce_limits_and_insert(const Transaction& tx, uint64_t fee, std::string& err);

    // Orphan handling
    void add_orphan(const Transaction& tx);
    void remove_orphan(const Key& k);
    void try_promote_orphans_depending_on(const Key& parent, const UTXOView& utxo, uint32_t height);

    // Eviction helpers
    void evict_lowest_feerate_until(size_t target_bytes);

private:
    std::unordered_map<Key, MempoolEntry> map_;
    size_t total_bytes_{0};

    // Orphans: key=child txid (presently missing at least one input)
    std::unordered_map<Key, Transaction> orphans_;
    // Reverse index: missing parent txid key -> set of orphans waiting on it
    std::unordered_map<Key, std::unordered_set<Key>> waiting_on_;
};

}
