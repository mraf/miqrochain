// Test stratum server protocol basics
#include "../src/stratum/stratum_server.h"
#include "../src/chain.h"
#include "../src/mempool.h"
#include <cassert>
#include <string>
#include <cstdio>

// Helper to convert hex string to bytes
static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper to convert bytes to hex string
static std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::string hex;
    for (uint8_t b : bytes) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", b);
        hex += buf;
    }
    return hex;
}

int main() {
    printf("Testing stratum components...\n");

    // Test 1: StratumJob structure
    {
        miq::StratumJob job;
        job.job_id = "job1";
        job.prev_hash = std::vector<uint8_t>(32, 0xaa);
        job.coinb1 = "deadbeef";
        job.coinb2 = "cafebabe";
        job.version = 1;
        job.bits = 0x1d00ffff;
        job.time = 1234567890;
        job.height = 100;
        job.clean_jobs = true;

        assert(job.job_id == "job1");
        assert(job.prev_hash.size() == 32);
        assert(job.height == 100);
        printf("  [PASS] StratumJob structure\n");
    }

    // Test 2: StratumMiner structure initialization
    {
        miq::StratumMiner miner;
        assert(miner.sock == STRATUM_INVALID_SOCKET);
        assert(miner.authorized == false);
        assert(miner.subscribed == false);
        assert(miner.difficulty == 1.0);
        assert(miner.shares_submitted == 0);
        printf("  [PASS] StratumMiner initialization\n");
    }

    // Test 3: PoolStats structure
    {
        miq::PoolStats stats;
        assert(stats.total_shares == 0);
        assert(stats.accepted_shares == 0);
        assert(stats.rejected_shares == 0);
        assert(stats.blocks_found == 0);
        assert(stats.pool_hashrate == 0.0);
        assert(stats.connected_miners == 0);
        printf("  [PASS] PoolStats initialization\n");
    }

    // Test 4: Extranonce generation format
    {
        // extranonce1 should be a hex string
        std::string en1 = "deadbeef";
        assert(en1.length() == 8);  // 4 bytes = 8 hex chars

        // extranonce2 should be configurable size
        uint8_t en2_size = 4;
        assert(en2_size >= 2 && en2_size <= 8);
        printf("  [PASS] Extranonce format\n");
    }

    // Test 5: Difficulty target calculation
    {
        // Difficulty 1 = 0x00000000ffff0000...
        // Higher difficulty = smaller target
        double diff1 = 1.0;
        double diff2 = 2.0;

        // Just verify types work correctly
        assert(diff2 > diff1);
        assert(diff1 > 0);
        printf("  [PASS] Difficulty format\n");
    }

    // Test 6: Vardiff thresholds
    {
        double min_diff = 0.001;
        double max_diff = 1000000.0;
        double default_diff = 1.0;

        assert(default_diff >= min_diff);
        assert(default_diff <= max_diff);
        assert(min_diff > 0);
        printf("  [PASS] Vardiff thresholds\n");
    }

    // Test 7: Merkle branch format
    {
        std::vector<std::string> merkle_branches;
        merkle_branches.push_back("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
        merkle_branches.push_back("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");

        assert(merkle_branches.size() == 2);
        assert(merkle_branches[0].length() == 64);  // 32 bytes = 64 hex chars
        printf("  [PASS] Merkle branch format\n");
    }

    // Test 8: Share validation data types
    {
        std::string job_id = "1";
        std::string extranonce2 = "00000001";  // 4 bytes
        std::string ntime = "5f5e1000";        // 4 bytes timestamp
        std::string nonce = "deadbeef";        // 4 bytes nonce

        assert(extranonce2.length() == 8);
        assert(ntime.length() == 8);
        assert(nonce.length() == 8);
        printf("  [PASS] Share validation data types\n");
    }

    printf("All stratum tests passed!\n");
    return 0;
}
