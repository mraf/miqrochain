// Test MIQ block header format (88 bytes with 8-byte time and 8-byte nonce)
#include <cassert>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>

// Serialization helpers
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(x & 0xff);
    v.push_back((x >> 8) & 0xff);
    v.push_back((x >> 16) & 0xff);
    v.push_back((x >> 24) & 0xff);
}

static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 0; i < 8; i++) {
        v.push_back((x >> (8 * i)) & 0xff);
    }
}

static inline void store_u64_le(uint8_t* p, uint64_t x) {
    for (int i = 0; i < 8; i++) {
        p[i] = (x >> (8 * i)) & 0xff;
    }
}

static inline uint64_t load_u64_le(const uint8_t* p) {
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) {
        x |= (uint64_t)p[i] << (8 * i);
    }
    return x;
}

// Build header prefix (without nonce) - should be 80 bytes
static std::vector<uint8_t> build_header_prefix(uint32_t version,
                                                 const std::vector<uint8_t>& prev_hash,
                                                 const std::vector<uint8_t>& merkle_root,
                                                 uint64_t time,
                                                 uint32_t bits) {
    std::vector<uint8_t> v;
    v.reserve(4 + 32 + 32 + 8 + 4);  // 80 bytes

    put_u32_le(v, version);
    v.insert(v.end(), prev_hash.begin(), prev_hash.end());
    v.insert(v.end(), merkle_root.begin(), merkle_root.end());
    put_u64_le(v, time);   // 8 bytes for time
    put_u32_le(v, bits);

    return v;
}

// Build full header (88 bytes)
static std::vector<uint8_t> build_full_header(uint32_t version,
                                               const std::vector<uint8_t>& prev_hash,
                                               const std::vector<uint8_t>& merkle_root,
                                               uint64_t time,
                                               uint32_t bits,
                                               uint64_t nonce) {
    auto v = build_header_prefix(version, prev_hash, merkle_root, time, bits);
    v.reserve(88);  // 80 + 8
    put_u64_le(v, nonce);  // 8 bytes for nonce
    return v;
}

int main() {
    printf("Testing MIQ header format...\n");

    // Test 1: Header prefix size should be 80 bytes
    {
        std::vector<uint8_t> prev_hash(32, 0xaa);
        std::vector<uint8_t> merkle_root(32, 0xbb);

        auto prefix = build_header_prefix(1, prev_hash, merkle_root, 1234567890, 0x1d00ffff);

        assert(prefix.size() == 80);
        printf("  [PASS] Header prefix size = %zu bytes\n", prefix.size());
    }

    // Test 2: Full header size should be 88 bytes
    {
        std::vector<uint8_t> prev_hash(32, 0xaa);
        std::vector<uint8_t> merkle_root(32, 0xbb);

        auto header = build_full_header(1, prev_hash, merkle_root, 1234567890, 0x1d00ffff, 0xdeadbeef);

        assert(header.size() == 88);
        printf("  [PASS] Full header size = %zu bytes\n", header.size());
    }

    // Test 3: Verify version serialization (4 bytes)
    {
        std::vector<uint8_t> prev_hash(32, 0);
        std::vector<uint8_t> merkle_root(32, 0);

        auto header = build_full_header(0x12345678, prev_hash, merkle_root, 0, 0, 0);

        // Check version in little-endian
        assert(header[0] == 0x78);
        assert(header[1] == 0x56);
        assert(header[2] == 0x34);
        assert(header[3] == 0x12);
        printf("  [PASS] Version serialization\n");
    }

    // Test 4: Verify time serialization (8 bytes)
    {
        std::vector<uint8_t> prev_hash(32, 0);
        std::vector<uint8_t> merkle_root(32, 0);

        uint64_t time = 0x123456789abcdef0ULL;
        auto header = build_full_header(1, prev_hash, merkle_root, time, 0, 0);

        // Time starts at offset 4 + 32 + 32 = 68
        uint64_t read_time = load_u64_le(&header[68]);
        assert(read_time == time);
        printf("  [PASS] Time serialization (8 bytes): 0x%llx\n", (unsigned long long)read_time);
    }

    // Test 5: Verify bits serialization (4 bytes)
    {
        std::vector<uint8_t> prev_hash(32, 0);
        std::vector<uint8_t> merkle_root(32, 0);

        uint32_t bits = 0x1d00ffff;
        auto header = build_full_header(1, prev_hash, merkle_root, 0, bits, 0);

        // Bits starts at offset 4 + 32 + 32 + 8 = 76
        uint32_t read_bits = header[76] | (header[77] << 8) | (header[78] << 16) | (header[79] << 24);
        assert(read_bits == bits);
        printf("  [PASS] Bits serialization (4 bytes): 0x%08x\n", read_bits);
    }

    // Test 6: Verify nonce serialization (8 bytes)
    {
        std::vector<uint8_t> prev_hash(32, 0);
        std::vector<uint8_t> merkle_root(32, 0);

        uint64_t nonce = 0xfedcba9876543210ULL;
        auto header = build_full_header(1, prev_hash, merkle_root, 0, 0, nonce);

        // Nonce starts at offset 80
        uint64_t read_nonce = load_u64_le(&header[80]);
        assert(read_nonce == nonce);
        printf("  [PASS] Nonce serialization (8 bytes): 0x%llx\n", (unsigned long long)read_nonce);
    }

    // Test 7: Verify store_u64_le helper
    {
        uint8_t buf[8];
        uint64_t val = 0x0102030405060708ULL;
        store_u64_le(buf, val);

        assert(buf[0] == 0x08);
        assert(buf[1] == 0x07);
        assert(buf[2] == 0x06);
        assert(buf[3] == 0x05);
        assert(buf[4] == 0x04);
        assert(buf[5] == 0x03);
        assert(buf[6] == 0x02);
        assert(buf[7] == 0x01);
        printf("  [PASS] store_u64_le helper\n");
    }

    // Test 8: Verify complete header structure
    {
        // MIQ header structure:
        // - version:     4 bytes
        // - prev_hash:  32 bytes
        // - merkle_root: 32 bytes
        // - time:        8 bytes  (NOT 4!)
        // - bits:        4 bytes
        // - nonce:       8 bytes  (NOT 4!)
        // Total:        88 bytes  (NOT 80!)

        size_t expected_size = 4 + 32 + 32 + 8 + 4 + 8;
        assert(expected_size == 88);
        printf("  [PASS] Header structure: 4+32+32+8+4+8 = %zu bytes\n", expected_size);
    }

    printf("All header format tests passed!\n");
    printf("\nIMPORTANT: MIQ uses 88-byte headers with:\n");
    printf("  - 8-byte time (not 4-byte)\n");
    printf("  - 8-byte nonce (not 4-byte)\n");
    printf("This differs from Bitcoin's 80-byte headers!\n");
    return 0;
}
