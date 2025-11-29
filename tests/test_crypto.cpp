#include "sha256.h"
#include "ripemd160.h"
#include "hash160.h"
#include "base58check.h"
#include <cstdio>
#include <vector>

// Test macro that works in both debug and release builds
#define TEST_CHECK(cond, msg) do { \
    if (!(cond)) { \
        std::fprintf(stderr, "FAIL: %s\n", msg); \
        return 1; \
    } \
} while(0)

int main(){
    // Test SHA256
    auto h = miq::sha256(std::vector<uint8_t>({'a','b','c'}));
    TEST_CHECK(h.size() == 32, "SHA256 should produce 32 bytes");
    TEST_CHECK(h[0] == 0xba && h[1] == 0x78, "SHA256('abc') should start with 0xba78");

    // Test RIPEMD160
    auto r = miq::ripemd160(std::vector<uint8_t>({'a','b','c'}));
    TEST_CHECK(r.size() == 20, "RIPEMD160 should produce 20 bytes");

    // Test Hash160
    auto pkh = miq::hash160(std::vector<uint8_t>({'x'}));
    TEST_CHECK(pkh.size() == 20, "Hash160 should produce 20 bytes");

    // Test Base58Check encode/decode roundtrip
    auto addr = miq::base58check_encode(0x35, std::vector<uint8_t>(20, 1));
    TEST_CHECK(!addr.empty(), "Base58Check encode should produce non-empty string");

    uint8_t v = 0;
    std::vector<uint8_t> pl;
    bool decoded = miq::base58check_decode(addr, v, pl);
    TEST_CHECK(decoded, "Base58Check decode should succeed");
    TEST_CHECK(v == 0x35, "Decoded version should match encoded version");
    TEST_CHECK(pl.size() == 20, "Decoded payload should be 20 bytes");

    std::printf("All crypto tests passed!\n");
    return 0;
}
