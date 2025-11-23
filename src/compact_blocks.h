#pragma once
// src/compact_blocks.h - BIP-152 Compact Block Relay
// Reduces bandwidth by sending short transaction IDs instead of full transactions

#include <vector>
#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <cstring>
#include <mutex>
#include <array>

#include "block.h"
#include "tx.h"
#include "sha256.h"
#include "mempool.h"

namespace miq {

// =============================================================================
// BIP-152 COMPACT BLOCK RELAY
// Significantly reduces block propagation bandwidth by:
// 1. Sending only short transaction IDs (6 bytes instead of full tx)
// 2. Receiver reconstructs block from mempool
// 3. Only missing transactions are requested
// =============================================================================

// Compact block version
constexpr uint64_t COMPACT_BLOCK_VERSION = 1;

// Short transaction ID size (6 bytes)
constexpr size_t SHORT_TXID_SIZE = 6;

// SipHash key derivation
struct CompactBlockKey {
    uint64_t k0{0};
    uint64_t k1{0};
};

// Derive SipHash key from block header hash and nonce
inline CompactBlockKey derive_compact_key(const std::vector<uint8_t>& header_hash, uint64_t nonce) {
    // Concatenate header_hash and nonce, then SHA256
    std::vector<uint8_t> data;
    data.reserve(header_hash.size() + 8);
    data.insert(data.end(), header_hash.begin(), header_hash.end());
    for (int i = 0; i < 8; ++i) {
        data.push_back((nonce >> (i * 8)) & 0xff);
    }

    auto hash = sha256(data);

    CompactBlockKey key;
    for (int i = 0; i < 8; ++i) {
        key.k0 |= ((uint64_t)hash[i]) << (i * 8);
        key.k1 |= ((uint64_t)hash[8 + i]) << (i * 8);
    }

    return key;
}

// SipHash-2-4 for short txid computation
inline uint64_t siphash24(const CompactBlockKey& key, const std::vector<uint8_t>& data) {
    uint64_t v0 = key.k0 ^ 0x736f6d6570736575ULL;
    uint64_t v1 = key.k1 ^ 0x646f72616e646f6dULL;
    uint64_t v2 = key.k0 ^ 0x6c7967656e657261ULL;
    uint64_t v3 = key.k1 ^ 0x7465646279746573ULL;

    auto sipround = [&]() {
        v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0;
        v0 = (v0 << 32) | (v0 >> 32);
        v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2;
        v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0;
        v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2;
        v2 = (v2 << 32) | (v2 >> 32);
    };

    size_t blocks = data.size() / 8;
    for (size_t i = 0; i < blocks; ++i) {
        uint64_t m = 0;
        for (int j = 0; j < 8; ++j) {
            m |= ((uint64_t)data[i * 8 + j]) << (j * 8);
        }
        v3 ^= m;
        sipround(); sipround();
        v0 ^= m;
    }

    // Handle remaining bytes
    uint64_t m = ((uint64_t)(data.size() & 0xff)) << 56;
    size_t remaining = data.size() % 8;
    for (size_t i = 0; i < remaining; ++i) {
        m |= ((uint64_t)data[blocks * 8 + i]) << (i * 8);
    }

    v3 ^= m;
    sipround(); sipround();
    v0 ^= m;

    v2 ^= 0xff;
    sipround(); sipround(); sipround(); sipround();

    return v0 ^ v1 ^ v2 ^ v3;
}

// Compute short transaction ID (6 bytes)
inline std::array<uint8_t, SHORT_TXID_SIZE> compute_short_txid(
    const CompactBlockKey& key,
    const std::vector<uint8_t>& txid)
{
    uint64_t hash = siphash24(key, txid);

    std::array<uint8_t, SHORT_TXID_SIZE> short_id;
    for (size_t i = 0; i < SHORT_TXID_SIZE; ++i) {
        short_id[i] = (hash >> (i * 8)) & 0xff;
    }

    return short_id;
}

// =============================================================================
// COMPACT BLOCK MESSAGE STRUCTURES
// =============================================================================

// Prefilled transaction (sent with compact block)
struct PrefilledTransaction {
    uint16_t index{0};          // Differentially encoded index
    Transaction tx;
};

// Compact block message (cmpctblock)
struct CompactBlock {
    BlockHeader header;
    uint64_t nonce{0};
    std::vector<std::array<uint8_t, SHORT_TXID_SIZE>> short_ids;
    std::vector<PrefilledTransaction> prefilled_txs;

    // Derived data (not serialized)
    CompactBlockKey key;
    std::vector<uint8_t> block_hash;
};

// Block transactions request (getblocktxn)
struct BlockTransactionsRequest {
    std::vector<uint8_t> block_hash;
    std::vector<uint16_t> indexes;  // Differentially encoded
};

// Block transactions response (blocktxn)
struct BlockTransactions {
    std::vector<uint8_t> block_hash;
    std::vector<Transaction> txs;
};

// =============================================================================
// COMPACT BLOCK BUILDER
// Create compact blocks from full blocks
// =============================================================================

class CompactBlockBuilder {
public:
    // Create a compact block from a full block
    static CompactBlock create(const Block& block, Mempool& mempool) {
        CompactBlock cb;
        cb.header = block.header;
        cb.block_hash = block.block_hash();

        // Generate random nonce
        cb.nonce = 0;
        for (int i = 0; i < 8; ++i) {
            cb.nonce |= ((uint64_t)(rand() & 0xff)) << (i * 8);
        }

        // Derive key
        cb.key = derive_compact_key(cb.block_hash, cb.nonce);

        // Always prefill coinbase
        if (!block.txs.empty()) {
            PrefilledTransaction pf;
            pf.index = 0;
            pf.tx = block.txs[0];
            cb.prefilled_txs.push_back(pf);
        }

        // Compute short IDs for remaining transactions
        for (size_t i = 1; i < block.txs.size(); ++i) {
            auto txid = block.txs[i].txid();
            auto short_id = compute_short_txid(cb.key, txid);
            cb.short_ids.push_back(short_id);
        }

        return cb;
    }
};

// =============================================================================
// COMPACT BLOCK RECONSTRUCTOR
// Reconstruct full block from compact block + mempool
// =============================================================================

class CompactBlockReconstructor {
public:
    explicit CompactBlockReconstructor(Mempool& mempool) : mempool_(mempool) {}

    // Result of reconstruction attempt
    struct Result {
        bool success{false};
        Block block;
        std::vector<uint16_t> missing_indexes;  // Indexes of missing transactions
        std::string error;
    };

    // Attempt to reconstruct block
    Result reconstruct(const CompactBlock& cb) {
        Result result;
        result.block.header = cb.header;

        // Derive key if not already set
        CompactBlockKey key = cb.key;
        if (key.k0 == 0 && key.k1 == 0) {
            auto hash = result.block.block_hash();
            key = derive_compact_key(hash, cb.nonce);
        }

        // Build index of mempool transactions by short ID
        std::unordered_map<std::string, Transaction> mempool_by_short;
        auto mempool_txids = mempool_.txids();
        for (const auto& txid : mempool_txids) {
            auto short_id = compute_short_txid(key, txid);
            std::string key_str(short_id.begin(), short_id.end());

            Transaction tx;
            if (mempool_.get_tx(txid, tx)) {
                mempool_by_short[key_str] = tx;
            }
        }

        // Build transaction list
        size_t total_txs = cb.prefilled_txs.size() + cb.short_ids.size();
        result.block.txs.resize(total_txs);

        // Fill prefilled transactions
        std::unordered_set<size_t> prefilled_indexes;
        uint16_t last_idx = 0;
        for (const auto& pf : cb.prefilled_txs) {
            uint16_t idx = last_idx + pf.index;
            if (idx >= total_txs) {
                result.error = "invalid prefilled index";
                return result;
            }
            result.block.txs[idx] = pf.tx;
            prefilled_indexes.insert(idx);
            last_idx = idx + 1;
        }

        // Fill from mempool using short IDs
        size_t short_idx = 0;
        for (size_t i = 0; i < total_txs; ++i) {
            if (prefilled_indexes.count(i)) continue;

            if (short_idx >= cb.short_ids.size()) {
                result.error = "short_id index out of range";
                return result;
            }

            const auto& short_id = cb.short_ids[short_idx++];
            std::string key_str(short_id.begin(), short_id.end());

            auto it = mempool_by_short.find(key_str);
            if (it != mempool_by_short.end()) {
                result.block.txs[i] = it->second;
            } else {
                // Transaction not in mempool - need to request it
                result.missing_indexes.push_back((uint16_t)i);
            }
        }

        if (result.missing_indexes.empty()) {
            result.success = true;
        }

        return result;
    }

    // Fill in missing transactions
    bool fill_missing(Block& block, const BlockTransactions& txs,
                      const std::vector<uint16_t>& missing_indexes) {
        if (txs.txs.size() != missing_indexes.size()) {
            return false;
        }

        for (size_t i = 0; i < missing_indexes.size(); ++i) {
            size_t idx = missing_indexes[i];
            if (idx >= block.txs.size()) {
                return false;
            }
            block.txs[idx] = txs.txs[i];
        }

        return true;
    }

private:
    Mempool& mempool_;
};

// =============================================================================
// COMPACT BLOCK SERIALIZATION
// =============================================================================

inline std::vector<uint8_t> serialize_compact_block(const CompactBlock& cb) {
    std::vector<uint8_t> data;
    data.reserve(1024);  // Initial capacity

    // Header (88 bytes for MIQ)
    // Version (4 bytes LE)
    uint32_t ver = cb.header.version;
    data.push_back(ver & 0xff);
    data.push_back((ver >> 8) & 0xff);
    data.push_back((ver >> 16) & 0xff);
    data.push_back((ver >> 24) & 0xff);

    // Prev hash (32 bytes)
    data.insert(data.end(), cb.header.prev_hash.begin(), cb.header.prev_hash.end());

    // Merkle root (32 bytes)
    data.insert(data.end(), cb.header.merkle_root.begin(), cb.header.merkle_root.end());

    // Time (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back((cb.header.time >> (i * 8)) & 0xff);
    }

    // Bits (4 bytes LE)
    data.push_back(cb.header.bits & 0xff);
    data.push_back((cb.header.bits >> 8) & 0xff);
    data.push_back((cb.header.bits >> 16) & 0xff);
    data.push_back((cb.header.bits >> 24) & 0xff);

    // Nonce (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back((cb.header.nonce >> (i * 8)) & 0xff);
    }

    // Compact block nonce (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back((cb.nonce >> (i * 8)) & 0xff);
    }

    // Short IDs count (varint)
    uint64_t count = cb.short_ids.size();
    if (count < 0xfd) {
        data.push_back((uint8_t)count);
    } else if (count <= 0xffff) {
        data.push_back(0xfd);
        data.push_back(count & 0xff);
        data.push_back((count >> 8) & 0xff);
    } else {
        data.push_back(0xfe);
        data.push_back(count & 0xff);
        data.push_back((count >> 8) & 0xff);
        data.push_back((count >> 16) & 0xff);
        data.push_back((count >> 24) & 0xff);
    }

    // Short IDs (6 bytes each)
    for (const auto& sid : cb.short_ids) {
        data.insert(data.end(), sid.begin(), sid.end());
    }

    // Prefilled count (varint)
    count = cb.prefilled_txs.size();
    if (count < 0xfd) {
        data.push_back((uint8_t)count);
    } else {
        data.push_back(0xfd);
        data.push_back(count & 0xff);
        data.push_back((count >> 8) & 0xff);
    }

    // Prefilled transactions
    for (const auto& pf : cb.prefilled_txs) {
        // Index (varint, differentially encoded)
        if (pf.index < 0xfd) {
            data.push_back((uint8_t)pf.index);
        } else {
            data.push_back(0xfd);
            data.push_back(pf.index & 0xff);
            data.push_back((pf.index >> 8) & 0xff);
        }

        // Transaction
        auto tx_data = ser_tx(pf.tx);
        data.insert(data.end(), tx_data.begin(), tx_data.end());
    }

    return data;
}

// =============================================================================
// COMPACT BLOCK PEER SUPPORT
// Track which peers support compact blocks
// =============================================================================

class CompactBlockPeerManager {
public:
    // Peer announced high-bandwidth compact block relay
    void add_high_bandwidth_peer(const std::string& peer_id) {
        std::lock_guard<std::mutex> lk(mtx_);
        high_bandwidth_peers_.insert(peer_id);
    }

    // Remove peer
    void remove_peer(const std::string& peer_id) {
        std::lock_guard<std::mutex> lk(mtx_);
        high_bandwidth_peers_.erase(peer_id);
    }

    // Check if peer supports high-bandwidth mode
    bool is_high_bandwidth(const std::string& peer_id) const {
        std::lock_guard<std::mutex> lk(mtx_);
        return high_bandwidth_peers_.count(peer_id) > 0;
    }

    // Get all high-bandwidth peers
    std::vector<std::string> get_high_bandwidth_peers() const {
        std::lock_guard<std::mutex> lk(mtx_);
        return std::vector<std::string>(high_bandwidth_peers_.begin(),
                                        high_bandwidth_peers_.end());
    }

private:
    mutable std::mutex mtx_;
    std::unordered_set<std::string> high_bandwidth_peers_;
};

} // namespace miq
