#pragma once
#include <vector>
#include <cstdint>
#include <string>

namespace miq {

// =============================================================================
// BIP37 BLOOM FILTER IMPLEMENTATION
// For SPV wallet filtering
// =============================================================================

// Bloom filter flags (BIP37)
enum BloomFlags : uint8_t {
    BLOOM_UPDATE_NONE = 0,
    BLOOM_UPDATE_ALL = 1,
    BLOOM_UPDATE_P2PUBKEY_ONLY = 2,
    BLOOM_UPDATE_MASK = 3
};

class BloomFilter {
public:
    // Default constructor creates an empty filter
    BloomFilter();

    // Create a filter with specified parameters
    // nElements: Expected number of elements
    // fpRate: False positive rate (e.g., 0.0001 for 0.01%)
    // nTweak: Random value to add entropy
    // nFlags: Update flags
    BloomFilter(uint32_t nElements, double fpRate, uint32_t nTweak, uint8_t nFlags);

    // Check if data is in the filter
    bool contains(const std::vector<uint8_t>& data) const;
    bool contains(const uint8_t* data, size_t len) const;

    // Add data to the filter
    void insert(const std::vector<uint8_t>& data);
    void insert(const uint8_t* data, size_t len);

    // Clear the filter
    void clear();

    // Check if filter is empty/valid
    bool is_empty() const { return vData_.empty(); }
    bool is_valid() const { return !vData_.empty() && nHashFuncs_ > 0; }

    // Serialization for P2P protocol
    std::vector<uint8_t> serialize() const;
    bool deserialize(const std::vector<uint8_t>& data);

    // Get filter data for debugging/inspection
    const std::vector<uint8_t>& get_data() const { return vData_; }
    uint32_t get_hash_funcs() const { return nHashFuncs_; }
    uint32_t get_tweak() const { return nTweak_; }
    uint8_t get_flags() const { return nFlags_; }

    // Static helpers
    static uint32_t optimal_filter_size(uint32_t nElements, double fpRate);
    static uint32_t optimal_hash_funcs(uint32_t nFilterBytes, uint32_t nElements);

private:
    std::vector<uint8_t> vData_;
    uint32_t nHashFuncs_{0};
    uint32_t nTweak_{0};
    uint8_t nFlags_{0};

    // MurmurHash3 for bloom hashing
    uint32_t hash(uint32_t nHashNum, const uint8_t* data, size_t len) const;
};

// Helper to create a filter for wallet PKHs
BloomFilter create_wallet_filter(const std::vector<std::vector<uint8_t>>& pkhs,
                                  double fpRate = 0.0001);

}
