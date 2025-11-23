#pragma once
// src/utxo_commitment.h - UTXO Set Commitments for Fast Sync
// Enables nodes to verify UTXO set integrity without replaying entire blockchain

#include <vector>
#include <cstdint>
#include <string>
#include <array>
#include <mutex>
#include <unordered_map>

#include "sha256.h"
#include "utxo.h"

namespace miq {

// =============================================================================
// UTXO COMMITMENT SYSTEM
// Cryptographic commitment to the entire UTXO set at a given block height.
// Enables fast sync by downloading and verifying a snapshot instead of
// replaying all historical transactions.
// =============================================================================

// =============================================================================
// MUHASH (Multiplicative Hash) - Rolling Hash for UTXO Set
// Properties:
// - Associative and commutative
// - Can add/remove elements incrementally
// - Final hash is order-independent
// =============================================================================

class MuHash {
public:
    // Prime modulus for MuHash (2^3072 - 1103717)
    // We use a simplified 256-bit version for this implementation
    static constexpr size_t HASH_SIZE = 32;

    MuHash() {
        // Initialize to multiplicative identity
        state_.fill(0);
        state_[0] = 1;
    }

    // Add an element to the set
    void insert(const std::vector<uint8_t>& element) {
        auto h = hash_element(element);
        multiply(h);
    }

    // Remove an element from the set
    void remove(const std::vector<uint8_t>& element) {
        auto h = hash_element(element);
        auto inv = modular_inverse(h);
        multiply(inv);
    }

    // Combine with another MuHash (for parallel computation)
    void combine(const MuHash& other) {
        multiply(other.state_);
    }

    // Get the final commitment hash
    std::vector<uint8_t> finalize() const {
        // SHA256 of the internal state
        std::vector<uint8_t> data(state_.begin(), state_.end());
        return sha256(data);
    }

    // Serialize state
    std::vector<uint8_t> serialize() const {
        return std::vector<uint8_t>(state_.begin(), state_.end());
    }

    // Deserialize state
    bool deserialize(const std::vector<uint8_t>& data) {
        if (data.size() != HASH_SIZE) return false;
        std::copy(data.begin(), data.end(), state_.begin());
        return true;
    }

private:
    std::array<uint8_t, HASH_SIZE> state_;

    // Hash element to group element
    std::array<uint8_t, HASH_SIZE> hash_element(const std::vector<uint8_t>& element) {
        auto h = sha256(element);
        std::array<uint8_t, HASH_SIZE> result;
        std::copy(h.begin(), h.end(), result.begin());
        return result;
    }

    // Modular multiplication (simplified - uses XOR for demo)
    // In production, use proper big-integer arithmetic
    void multiply(const std::array<uint8_t, HASH_SIZE>& other) {
        for (size_t i = 0; i < HASH_SIZE; ++i) {
            state_[i] ^= other[i];
        }
    }

    // Modular inverse (for removal)
    std::array<uint8_t, HASH_SIZE> modular_inverse(const std::array<uint8_t, HASH_SIZE>& element) {
        // In XOR-based implementation, element is its own inverse
        return element;
    }
};

// =============================================================================
// UTXO COMMITMENT DATA STRUCTURES
// =============================================================================

// Commitment at a specific block
struct UTXOCommitment {
    uint64_t height{0};
    std::vector<uint8_t> block_hash;
    std::vector<uint8_t> commitment;  // MuHash finalized
    uint64_t utxo_count{0};
    uint64_t total_value{0};  // Total value in UTXO set
};

// Serialized UTXO for commitment
inline std::vector<uint8_t> serialize_utxo_for_commitment(
    const std::vector<uint8_t>& txid,
    uint32_t vout,
    const UTXOEntry& entry)
{
    std::vector<uint8_t> data;
    data.reserve(32 + 4 + 8 + 8 + 1 + entry.pkh.size());

    // txid (32 bytes)
    data.insert(data.end(), txid.begin(), txid.end());

    // vout (4 bytes LE)
    data.push_back(vout & 0xff);
    data.push_back((vout >> 8) & 0xff);
    data.push_back((vout >> 16) & 0xff);
    data.push_back((vout >> 24) & 0xff);

    // value (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back((entry.value >> (i * 8)) & 0xff);
    }

    // height (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back((entry.height >> (i * 8)) & 0xff);
    }

    // coinbase flag (1 byte)
    data.push_back(entry.coinbase ? 1 : 0);

    // pkh (variable)
    data.insert(data.end(), entry.pkh.begin(), entry.pkh.end());

    return data;
}

// =============================================================================
// UTXO COMMITMENT MANAGER
// Manages computation and verification of UTXO commitments
// =============================================================================

class UTXOCommitmentManager {
public:
    // Compute commitment for current UTXO set
    UTXOCommitment compute(const UTXOSet& utxo_set, uint64_t height,
                            const std::vector<uint8_t>& block_hash) {
        MuHash hasher;
        uint64_t count = 0;
        uint64_t total_value = 0;

        // Iterate all UTXOs
        utxo_set.for_each([&](const std::vector<uint8_t>& txid, uint32_t vout,
                               const UTXOEntry& entry) {
            auto serialized = serialize_utxo_for_commitment(txid, vout, entry);
            hasher.insert(serialized);
            count++;
            total_value += entry.value;
        });

        UTXOCommitment result;
        result.height = height;
        result.block_hash = block_hash;
        result.commitment = hasher.finalize();
        result.utxo_count = count;
        result.total_value = total_value;

        return result;
    }

    // Update commitment incrementally with a block
    void apply_block(MuHash& hasher, const std::vector<uint8_t>& block_hash,
                      uint64_t height, const Block& block, const UTXOSet& utxo_set) {
        // Remove spent UTXOs
        for (const auto& tx : block.txs) {
            for (const auto& in : tx.vin) {
                // Skip coinbase inputs
                if (in.prev.txid == std::vector<uint8_t>(32, 0)) continue;

                UTXOEntry entry;
                if (utxo_set.get(in.prev.txid, in.prev.vout, entry)) {
                    auto serialized = serialize_utxo_for_commitment(
                        in.prev.txid, in.prev.vout, entry);
                    hasher.remove(serialized);
                }
            }
        }

        // Add new UTXOs
        for (const auto& tx : block.txs) {
            auto txid = tx.txid();
            for (size_t i = 0; i < tx.vout.size(); ++i) {
                UTXOEntry entry;
                entry.value = tx.vout[i].value;
                entry.pkh = tx.vout[i].pkh;
                entry.height = height;
                entry.coinbase = (tx.vin.size() == 1 &&
                                  tx.vin[0].prev.txid == std::vector<uint8_t>(32, 0));

                auto serialized = serialize_utxo_for_commitment(txid, (uint32_t)i, entry);
                hasher.insert(serialized);
            }
        }
    }

    // Verify a UTXO snapshot against commitment
    bool verify_snapshot(const std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>>& snapshot,
                          const UTXOCommitment& expected) {
        MuHash hasher;
        uint64_t count = 0;
        uint64_t total_value = 0;

        for (const auto& [txid, vout, entry] : snapshot) {
            auto serialized = serialize_utxo_for_commitment(txid, vout, entry);
            hasher.insert(serialized);
            count++;
            total_value += entry.value;
        }

        auto computed = hasher.finalize();

        return computed == expected.commitment &&
               count == expected.utxo_count &&
               total_value == expected.total_value;
    }

    // Store commitment checkpoint
    void add_checkpoint(const UTXOCommitment& commitment) {
        std::lock_guard<std::mutex> lk(mtx_);
        checkpoints_[commitment.height] = commitment;
    }

    // Get nearest checkpoint at or before height
    bool get_checkpoint(uint64_t height, UTXOCommitment& out) const {
        std::lock_guard<std::mutex> lk(mtx_);

        UTXOCommitment best;
        bool found = false;

        for (const auto& [h, c] : checkpoints_) {
            if (h <= height && (!found || h > best.height)) {
                best = c;
                found = true;
            }
        }

        if (found) {
            out = best;
        }

        return found;
    }

    // List all checkpoints
    std::vector<UTXOCommitment> list_checkpoints() const {
        std::lock_guard<std::mutex> lk(mtx_);
        std::vector<UTXOCommitment> result;
        for (const auto& [h, c] : checkpoints_) {
            result.push_back(c);
        }
        return result;
    }

private:
    mutable std::mutex mtx_;
    std::unordered_map<uint64_t, UTXOCommitment> checkpoints_;
};

// =============================================================================
// FAST SYNC PROTOCOL
// Download and verify UTXO snapshot for instant sync
// =============================================================================

struct FastSyncRequest {
    uint64_t height{0};
    std::vector<uint8_t> commitment;
};

struct FastSyncChunk {
    uint64_t chunk_index{0};
    uint64_t total_chunks{0};
    std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>> utxos;
    std::vector<uint8_t> chunk_hash;  // For integrity
};

// Serialize UTXO chunk
inline std::vector<uint8_t> serialize_fast_sync_chunk(const FastSyncChunk& chunk) {
    std::vector<uint8_t> data;

    // Chunk metadata
    for (int i = 0; i < 8; ++i) {
        data.push_back((chunk.chunk_index >> (i * 8)) & 0xff);
    }
    for (int i = 0; i < 8; ++i) {
        data.push_back((chunk.total_chunks >> (i * 8)) & 0xff);
    }

    // UTXO count
    uint64_t count = chunk.utxos.size();
    for (int i = 0; i < 8; ++i) {
        data.push_back((count >> (i * 8)) & 0xff);
    }

    // UTXOs
    for (const auto& [txid, vout, entry] : chunk.utxos) {
        auto serialized = serialize_utxo_for_commitment(txid, vout, entry);
        // Length prefix
        uint32_t len = (uint32_t)serialized.size();
        for (int i = 0; i < 4; ++i) {
            data.push_back((len >> (i * 8)) & 0xff);
        }
        data.insert(data.end(), serialized.begin(), serialized.end());
    }

    return data;
}

// =============================================================================
// GLOBAL UTXO COMMITMENT INSTANCE
// =============================================================================

inline UTXOCommitmentManager& utxo_commitment_manager() {
    static UTXOCommitmentManager mgr;
    return mgr;
}

} // namespace miq
