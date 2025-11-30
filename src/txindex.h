#pragma once
// =============================================================================
// TRANSACTION INDEX - Lookup confirmed transactions by TXID
// =============================================================================
// This index stores the location (block height + position) of every confirmed
// transaction, allowing fast lookup of historical transactions by TXID.
//
// Format: LevelDB or file-based key-value store
// Key: txid (32 bytes)
// Value: block_height (8 bytes) + tx_position (4 bytes)
// =============================================================================

#include <string>
#include <vector>
#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <fstream>

namespace miq {

struct TxLocation {
    uint64_t block_height{0};
    uint32_t tx_position{0};  // Position within block (0 = coinbase)
    bool valid{false};
};

class TxIndex {
public:
    TxIndex() = default;
    ~TxIndex() = default;

    // Open/create the index at the given path
    bool open(const std::string& datadir);

    // Add a transaction to the index
    bool add(const std::vector<uint8_t>& txid, uint64_t block_height, uint32_t tx_position);

    // Remove transactions from a block (for reorg handling)
    bool remove_block(uint64_t block_height);

    // Look up a transaction
    bool get(const std::vector<uint8_t>& txid, TxLocation& out) const;

    // Check if index contains a transaction
    bool contains(const std::vector<uint8_t>& txid) const;

    // Flush to disk
    bool flush();

    // Get number of indexed transactions
    size_t size() const;

private:
    mutable std::mutex mtx_;
    std::string path_;
    std::unordered_map<std::string, TxLocation> index_;
    bool dirty_{false};

    static std::string key_from_txid(const std::vector<uint8_t>& txid);
    bool load_from_disk();
    bool save_to_disk() const;
};

}  // namespace miq
