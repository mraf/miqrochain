// src/filters/bloom.cpp
#include "bloom.h"
#include <cmath>
#include <cstring>
#include <algorithm>
#include <random>

namespace miq {

// Constants from BIP37
static constexpr uint32_t MAX_BLOOM_FILTER_SIZE = 36000; // bytes
static constexpr uint32_t MAX_HASH_FUNCS = 50;
static constexpr double LN2SQUARED = 0.4804530139182014246671025263266649717305529515945455;
static constexpr double LN2 = 0.6931471805599453094172321214581765680755001343602552;

BloomFilter::BloomFilter() {}

BloomFilter::BloomFilter(uint32_t nElements, double fpRate, uint32_t nTweak, uint8_t nFlags)
    : nTweak_(nTweak), nFlags_(nFlags) {

    uint32_t nFilterBytes = optimal_filter_size(nElements, fpRate);
    vData_.assign(nFilterBytes, 0);
    nHashFuncs_ = optimal_hash_funcs(nFilterBytes, nElements);
}

uint32_t BloomFilter::optimal_filter_size(uint32_t nElements, double fpRate) {
    // Formula from BIP37: -1.0 / LN2SQUARED * n * log(p) / 8.0
    uint32_t nFilterBytes = (uint32_t)(-1.0 / LN2SQUARED * nElements * std::log(fpRate) / 8.0);
    return std::min(nFilterBytes, MAX_BLOOM_FILTER_SIZE);
}

uint32_t BloomFilter::optimal_hash_funcs(uint32_t nFilterBytes, uint32_t nElements) {
    // Formula from BIP37: filterSize * 8 / nElements * LN2
    if (nElements == 0) return 1;
    uint32_t nHashFuncs = (uint32_t)(nFilterBytes * 8.0 / nElements * LN2);
    return std::max<uint32_t>(1, std::min(nHashFuncs, MAX_HASH_FUNCS));
}

// MurmurHash3 implementation
uint32_t BloomFilter::hash(uint32_t nHashNum, const uint8_t* data, size_t len) const {
    // MurmurHash3 with seed = nHashNum * 0xFBA4C795 + nTweak
    uint32_t h1 = nHashNum * 0xFBA4C795 + nTweak_;
    const uint32_t c1 = 0xcc9e2d51;
    const uint32_t c2 = 0x1b873593;

    const int nblocks = (int)(len / 4);
    const uint8_t* tail = data + nblocks * 4;

    // Body
    for (int i = 0; i < nblocks; i++) {
        uint32_t k1 = (uint32_t)data[i * 4] |
                      ((uint32_t)data[i * 4 + 1] << 8) |
                      ((uint32_t)data[i * 4 + 2] << 16) |
                      ((uint32_t)data[i * 4 + 3] << 24);

        k1 *= c1;
        k1 = (k1 << 15) | (k1 >> 17);
        k1 *= c2;

        h1 ^= k1;
        h1 = (h1 << 13) | (h1 >> 19);
        h1 = h1 * 5 + 0xe6546b64;
    }

    // Tail
    uint32_t k1 = 0;
    switch (len & 3) {
        case 3: k1 ^= ((uint32_t)tail[2]) << 16; [[fallthrough]];
        case 2: k1 ^= ((uint32_t)tail[1]) << 8; [[fallthrough]];
        case 1: k1 ^= tail[0];
                k1 *= c1;
                k1 = (k1 << 15) | (k1 >> 17);
                k1 *= c2;
                h1 ^= k1;
    }

    // Finalization
    h1 ^= (uint32_t)len;
    h1 ^= h1 >> 16;
    h1 *= 0x85ebca6b;
    h1 ^= h1 >> 13;
    h1 *= 0xc2b2ae35;
    h1 ^= h1 >> 16;

    return h1 % (vData_.size() * 8);
}

bool BloomFilter::contains(const std::vector<uint8_t>& data) const {
    return contains(data.data(), data.size());
}

bool BloomFilter::contains(const uint8_t* data, size_t len) const {
    if (vData_.empty()) return true; // Empty filter matches everything

    for (uint32_t i = 0; i < nHashFuncs_; i++) {
        uint32_t nIndex = hash(i, data, len);
        if (!(vData_[nIndex >> 3] & (1 << (nIndex & 7)))) {
            return false;
        }
    }
    return true;
}

void BloomFilter::insert(const std::vector<uint8_t>& data) {
    insert(data.data(), data.size());
}

void BloomFilter::insert(const uint8_t* data, size_t len) {
    if (vData_.empty()) return;

    for (uint32_t i = 0; i < nHashFuncs_; i++) {
        uint32_t nIndex = hash(i, data, len);
        vData_[nIndex >> 3] |= (1 << (nIndex & 7));
    }
}

void BloomFilter::clear() {
    vData_.assign(vData_.size(), 0);
}

std::vector<uint8_t> BloomFilter::serialize() const {
    // Format: [filter_size(4)] [filter_data] [nHashFuncs(4)] [nTweak(4)] [nFlags(1)]
    std::vector<uint8_t> result;
    result.reserve(vData_.size() + 13);

    // Filter size (varint-like, but we'll use 4 bytes for simplicity)
    uint32_t sz = (uint32_t)vData_.size();
    result.push_back((uint8_t)(sz >> 0));
    result.push_back((uint8_t)(sz >> 8));
    result.push_back((uint8_t)(sz >> 16));
    result.push_back((uint8_t)(sz >> 24));

    // Filter data
    result.insert(result.end(), vData_.begin(), vData_.end());

    // nHashFuncs
    result.push_back((uint8_t)(nHashFuncs_ >> 0));
    result.push_back((uint8_t)(nHashFuncs_ >> 8));
    result.push_back((uint8_t)(nHashFuncs_ >> 16));
    result.push_back((uint8_t)(nHashFuncs_ >> 24));

    // nTweak
    result.push_back((uint8_t)(nTweak_ >> 0));
    result.push_back((uint8_t)(nTweak_ >> 8));
    result.push_back((uint8_t)(nTweak_ >> 16));
    result.push_back((uint8_t)(nTweak_ >> 24));

    // nFlags
    result.push_back(nFlags_);

    return result;
}

bool BloomFilter::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 13) return false;

    // Read filter size
    uint32_t sz = (uint32_t)data[0] |
                  ((uint32_t)data[1] << 8) |
                  ((uint32_t)data[2] << 16) |
                  ((uint32_t)data[3] << 24);

    if (sz > MAX_BLOOM_FILTER_SIZE) return false;
    if (data.size() < 4 + sz + 9) return false;

    // Read filter data
    vData_.assign(data.begin() + 4, data.begin() + 4 + sz);

    // Read nHashFuncs
    size_t pos = 4 + sz;
    nHashFuncs_ = (uint32_t)data[pos] |
                  ((uint32_t)data[pos + 1] << 8) |
                  ((uint32_t)data[pos + 2] << 16) |
                  ((uint32_t)data[pos + 3] << 24);

    if (nHashFuncs_ > MAX_HASH_FUNCS) return false;

    // Read nTweak
    pos += 4;
    nTweak_ = (uint32_t)data[pos] |
              ((uint32_t)data[pos + 1] << 8) |
              ((uint32_t)data[pos + 2] << 16) |
              ((uint32_t)data[pos + 3] << 24);

    // Read nFlags
    pos += 4;
    nFlags_ = data[pos];

    return true;
}

BloomFilter create_wallet_filter(const std::vector<std::vector<uint8_t>>& pkhs, double fpRate) {
    if (pkhs.empty()) return BloomFilter();

    // Generate random tweak
    std::random_device rd;
    uint32_t nTweak = rd();

    // Create filter
    BloomFilter filter((uint32_t)pkhs.size(), fpRate, nTweak, BLOOM_UPDATE_P2PUBKEY_ONLY);

    // Insert all PKHs
    for (const auto& pkh : pkhs) {
        if (pkh.size() == 20) {
            filter.insert(pkh);
        }
    }

    return filter;
}

}
