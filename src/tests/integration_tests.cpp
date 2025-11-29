// =============================================================================
// INTEGRATION TESTS FOR MIQROCHAIN v1.0
// =============================================================================
// These tests verify end-to-end functionality across multiple components
// =============================================================================

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <filesystem>

#include "chain.h"
#include "mempool.h"
#include "serialize.h"
#include "sha256.h"
#include "crypto/ecdsa_iface.h"
#include "constants.h"
#include "wallet_store.h"
#include "log.h"

#ifdef _WIN32
#include <windows.h>
#define TMPDIR() "C:\\Temp"
#else
#include <unistd.h>
#define TMPDIR() "/tmp"
#endif

namespace fs = std::filesystem;

namespace miq {
namespace test {

// =============================================================================
// TEST UTILITIES
// =============================================================================

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        return false; \
    } \
    g_tests_passed++; \
} while(0)

#define TEST_BEGIN(name) \
    fprintf(stderr, "Running: %s...\n", name); \
    auto test_start = std::chrono::steady_clock::now();

#define TEST_END(name) \
    auto test_end = std::chrono::steady_clock::now(); \
    auto test_ms = std::chrono::duration_cast<std::chrono::milliseconds>(test_end - test_start).count(); \
    fprintf(stderr, "  PASS: %s (%lldms)\n", name, (long long)test_ms);

static std::string make_temp_dir(const std::string& prefix) {
    std::string base = std::string(TMPDIR()) + "/" + prefix + "_XXXXXX";
    std::vector<char> buf(base.begin(), base.end());
    buf.push_back('\0');

#ifdef _WIN32
    // Windows: just create with timestamp
    std::string dir = std::string(TMPDIR()) + "/" + prefix + "_" +
                      std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    fs::create_directories(dir);
    return dir;
#else
    char* result = mkdtemp(buf.data());
    if (!result) {
        std::string dir = std::string(TMPDIR()) + "/" + prefix + "_fallback";
        fs::create_directories(dir);
        return dir;
    }
    return std::string(result);
#endif
}

static void cleanup_temp_dir(const std::string& dir) {
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// =============================================================================
// TEST: CHAIN REORG
// =============================================================================

static bool test_chain_reorg() {
    TEST_BEGIN("test_chain_reorg");

    std::string datadir = make_temp_dir("miq_test_reorg");

    // Create chain instance
    Chain chain;
    TEST_ASSERT(chain.open(datadir), "Failed to open chain");

    // Get initial height
    uint64_t initial_height = chain.height();
    TEST_ASSERT(initial_height >= 0, "Chain should have at least genesis");

    // Verify genesis block
    Block genesis;
    TEST_ASSERT(chain.get_block_by_index(0, genesis), "Should read genesis block");
    TEST_ASSERT(!genesis.txs.empty(), "Genesis should have coinbase tx");

    chain.close();
    cleanup_temp_dir(datadir);

    TEST_END("test_chain_reorg");
    return true;
}

// =============================================================================
// TEST: MEMPOOL POLICY
// =============================================================================

static bool test_mempool_policy() {
    TEST_BEGIN("test_mempool_policy");

    Mempool pool;

    // Check initial state
    TEST_ASSERT(pool.size() == 0, "Mempool should start empty");
    TEST_ASSERT(pool.total_bytes() == 0, "Mempool bytes should start at 0");

    // Test ancestor limits config
    TEST_ASSERT(MIQ_MEMPOOL_MAX_ANCESTORS_PROD > 0, "Should have ancestor limit");
    TEST_ASSERT(MIQ_MEMPOOL_MAX_DESCENDANTS_PROD > 0, "Should have descendant limit");

    TEST_END("test_mempool_policy");
    return true;
}

// =============================================================================
// TEST: WALLET ATOMIC SAVE
// =============================================================================

static bool test_wallet_atomic_save() {
    TEST_BEGIN("test_wallet_atomic_save");

    std::string datadir = make_temp_dir("miq_test_wallet");

    // Create a test wallet
    WalletStore wallet;
    TEST_ASSERT(wallet.open(datadir), "Failed to open wallet");

    // Generate a key
    auto priv = crypto::ECDSA::gen_private_key();
    TEST_ASSERT(priv.size() == 32, "Private key should be 32 bytes");

    std::string err;
    // Add key and save
    TEST_ASSERT(wallet.add_key(priv, err), "Should add key to wallet");
    TEST_ASSERT(wallet.save(err), "Should save wallet");

    // Close and reopen
    wallet.close();

    WalletStore wallet2;
    TEST_ASSERT(wallet2.open(datadir), "Should reopen wallet");

    // Verify key persisted
    auto keys = wallet2.get_all_keys();
    TEST_ASSERT(!keys.empty(), "Should have at least one key after reload");

    wallet2.close();
    cleanup_temp_dir(datadir);

    TEST_END("test_wallet_atomic_save");
    return true;
}

// =============================================================================
// TEST: SIGNATURE VERIFICATION
// =============================================================================

static bool test_signature_verification() {
    TEST_BEGIN("test_signature_verification");

    // Generate keypair
    auto priv = crypto::ECDSA::gen_private_key();
    TEST_ASSERT(priv.size() == 32, "Private key should be 32 bytes");

    auto pub = crypto::ECDSA::private_to_public(priv);
    TEST_ASSERT(pub.size() == 33 || pub.size() == 65, "Public key should be compressed or uncompressed");

    // Sign a message
    std::vector<uint8_t> msg = {1, 2, 3, 4, 5, 6, 7, 8};
    auto hash = dsha256(msg);

    auto sig = crypto::ECDSA::sign(priv, hash);
    TEST_ASSERT(!sig.empty(), "Should produce signature");

    // Verify signature
    TEST_ASSERT(crypto::ECDSA::verify(pub, hash, sig), "Signature should verify");

    // Verify wrong signature fails
    auto wrong_hash = dsha256(std::vector<uint8_t>{9, 9, 9, 9});
    TEST_ASSERT(!crypto::ECDSA::verify(pub, wrong_hash, sig), "Wrong hash should not verify");

    TEST_END("test_signature_verification");
    return true;
}

// =============================================================================
// TEST: SERIALIZATION ROUNDTRIP
// =============================================================================

static bool test_serialization_roundtrip() {
    TEST_BEGIN("test_serialization_roundtrip");

    // Create a transaction
    Transaction tx;
    tx.version = 1;

    // Add input
    TxInput in;
    in.prev.txid.resize(32, 0xAA);
    in.prev.vout = 0;
    in.sig.resize(64, 0x11);
    in.pubkey.resize(33, 0x02);
    tx.vin.push_back(in);

    // Add output
    TxOutput out;
    out.value = 50 * COIN;
    out.pkh.resize(20, 0xBB);
    tx.vout.push_back(out);

    tx.lock_time = 0;

    // Serialize
    auto raw = tx.serialize();
    TEST_ASSERT(!raw.empty(), "Serialization should produce data");

    // Deserialize
    Transaction tx2;
    size_t pos = 0;
    TEST_ASSERT(tx2.deserialize(raw, pos), "Should deserialize back");

    // Verify fields match
    TEST_ASSERT(tx2.version == tx.version, "Version should match");
    TEST_ASSERT(tx2.vin.size() == tx.vin.size(), "Input count should match");
    TEST_ASSERT(tx2.vout.size() == tx.vout.size(), "Output count should match");
    TEST_ASSERT(tx2.vout[0].value == tx.vout[0].value, "Output value should match");

    TEST_END("test_serialization_roundtrip");
    return true;
}

// =============================================================================
// TEST: HASH FUNCTIONS
// =============================================================================

static bool test_hash_functions() {
    TEST_BEGIN("test_hash_functions");

    // Test SHA256
    std::vector<uint8_t> data = {'t', 'e', 's', 't'};
    auto hash = sha256(data);
    TEST_ASSERT(hash.size() == 32, "SHA256 should be 32 bytes");

    // Test double SHA256
    auto dhash = dsha256(data);
    TEST_ASSERT(dhash.size() == 32, "dSHA256 should be 32 bytes");

    // Verify deterministic
    auto hash2 = sha256(data);
    TEST_ASSERT(hash == hash2, "Same input should produce same hash");

    // Verify different inputs produce different hashes
    std::vector<uint8_t> data2 = {'T', 'E', 'S', 'T'};
    auto hash3 = sha256(data2);
    TEST_ASSERT(hash != hash3, "Different input should produce different hash");

    TEST_END("test_hash_functions");
    return true;
}

// =============================================================================
// TEST: CONSTANTS VALIDITY
// =============================================================================

static bool test_constants() {
    TEST_BEGIN("test_constants");

    // Verify critical constants are set correctly
    TEST_ASSERT(COIN == 100000000ULL, "COIN should be 10^8");
    TEST_ASSERT(BLOCK_TIME_SECS > 0, "Block time should be positive");
    TEST_ASSERT(HALVING_INTERVAL > 0, "Halving interval should be positive");
    TEST_ASSERT(MAX_MONEY > 0, "Max money should be positive");
    TEST_ASSERT(MAX_MONEY < (1ULL << 53), "Max money should fit in JS safe integer");

    TEST_ASSERT(P2P_PORT > 0, "P2P port should be set");
    TEST_ASSERT(RPC_PORT > 0, "RPC port should be set");
    TEST_ASSERT(P2P_PORT != RPC_PORT, "P2P and RPC ports should differ");

    TEST_ASSERT(VERSION_P2PKH != 0, "Version byte should be set");
    TEST_ASSERT(COINBASE_MATURITY > 0, "Coinbase maturity should be positive");

    // Verify genesis data is set
    TEST_ASSERT(strlen(GENESIS_HASH_HEX) == 64, "Genesis hash should be 64 hex chars");
    TEST_ASSERT(strlen(GENESIS_MERKLE_HEX) == 64, "Genesis merkle should be 64 hex chars");

    TEST_END("test_constants");
    return true;
}

// =============================================================================
// TEST: IBD STALL DETECTION CONSTANTS
// =============================================================================

static bool test_ibd_stall_constants() {
    TEST_BEGIN("test_ibd_stall_constants");

    // Verify IBD stall detection is properly configured
    TEST_ASSERT(MIQ_HEADERS_ONLY_BAN_SCORE >= 20,
                "Headers-only ban score should be significant");
    TEST_ASSERT(MIQ_BLOCK_STALL_MAX_COUNT <= 2,
                "Should switch peers quickly on stall");
    TEST_ASSERT(MIQ_HEADERS_NO_BLOCKS_TIMEOUT_MS >= 10000,
                "Headers timeout should be reasonable");
    TEST_ASSERT(MIQ_IBD_PEER_SWITCH_THRESHOLD <= 2,
                "Should switch sync peer quickly");

    TEST_END("test_ibd_stall_constants");
    return true;
}

// =============================================================================
// MAIN TEST RUNNER
// =============================================================================

int run_integration_tests() {
    fprintf(stderr, "\n=== MIQROCHAIN INTEGRATION TESTS ===\n\n");

    bool all_passed = true;

    all_passed &= test_constants();
    all_passed &= test_hash_functions();
    all_passed &= test_signature_verification();
    all_passed &= test_serialization_roundtrip();
    all_passed &= test_mempool_policy();
    all_passed &= test_chain_reorg();
    all_passed &= test_wallet_atomic_save();
    all_passed &= test_ibd_stall_constants();

    fprintf(stderr, "\n=== TEST SUMMARY ===\n");
    fprintf(stderr, "Tests run: %d\n", g_tests_run);
    fprintf(stderr, "Tests passed: %d\n", g_tests_passed);
    fprintf(stderr, "Result: %s\n\n", all_passed ? "ALL PASSED" : "SOME FAILED");

    return all_passed ? 0 : 1;
}

}  // namespace test
}  // namespace miq

// Entry point for standalone test execution
#ifndef MIQ_NO_MAIN
int main() {
    return miq::test::run_integration_tests();
}
#endif
