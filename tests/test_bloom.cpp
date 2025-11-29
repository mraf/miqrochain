// Test bloom filter implementation (BIP37)
#include "../src/filters/bloom.h"
#include <cassert>
#include <string>
#include <cstdio>

int main() {
    printf("Testing bloom filter...\n");

    // Test 1: Basic filter creation
    {
        miq::BloomFilter filter(10, 0.0001, 0, 0);
        assert(filter.get_data().size() > 0);
        printf("  [PASS] Filter creation\n");
    }

    // Test 2: Insert and contains
    {
        miq::BloomFilter filter(10, 0.0001, 0, 0);
        std::vector<uint8_t> data1 = {0x01, 0x02, 0x03, 0x04};
        std::vector<uint8_t> data2 = {0xaa, 0xbb, 0xcc, 0xdd};

        filter.insert(data1);
        assert(filter.contains(data1));
        // data2 might have false positive, but shouldn't be guaranteed
        printf("  [PASS] Insert and contains\n");
    }

    // Test 3: Multiple inserts
    {
        miq::BloomFilter filter(100, 0.0001, 0, 0);
        for (int i = 0; i < 50; i++) {
            std::vector<uint8_t> data = {(uint8_t)i, (uint8_t)(i+1), (uint8_t)(i+2)};
            filter.insert(data);
        }
        // Verify all are found
        for (int i = 0; i < 50; i++) {
            std::vector<uint8_t> data = {(uint8_t)i, (uint8_t)(i+1), (uint8_t)(i+2)};
            assert(filter.contains(data));
        }
        printf("  [PASS] Multiple inserts\n");
    }

    // Test 4: Serialization
    {
        miq::BloomFilter filter(10, 0.001, 12345, 1);
        std::vector<uint8_t> data = {0xde, 0xad, 0xbe, 0xef};
        filter.insert(data);

        auto serialized = filter.serialize();
        assert(serialized.size() > 0);
        printf("  [PASS] Serialization (size=%zu)\n", serialized.size());
    }

    // Test 5: Optimal filter size calculation
    {
        uint32_t size = miq::BloomFilter::optimal_filter_size(100, 0.0001);
        assert(size > 0 && size < 100000);
        printf("  [PASS] Optimal filter size = %u bytes\n", size);
    }

    // Test 6: Wallet filter creation helper
    {
        std::vector<std::vector<uint8_t>> pkhs;
        pkhs.push_back({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                        0x11, 0x12, 0x13, 0x14});
        pkhs.push_back({0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
                        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
                        0x31, 0x32, 0x33, 0x34});

        auto filter = miq::create_wallet_filter(pkhs, 0.00001);

        // Both PKHs should be found
        assert(filter.contains(pkhs[0]));
        assert(filter.contains(pkhs[1]));
        printf("  [PASS] Wallet filter creation\n");
    }

    printf("All bloom filter tests passed!\n");
    return 0;
}
