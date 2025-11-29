#pragma once
// =============================================================================
// MIQROCHAIN NETWORK PARAMETERS v1.0
// =============================================================================
// Provides network-specific configuration for mainnet, testnet, and regtest
// =============================================================================

#include <cstdint>
#include <string>
#include <vector>

namespace miq {

// Network type enumeration
enum class NetworkType : uint8_t {
    MAINNET = 0,
    TESTNET = 1,
    REGTEST = 2
};

// Network parameters structure
struct NetworkParams {
    // Network identity
    NetworkType type;
    std::string name;
    std::string bech32_hrp;  // Reserved for future SegWit-style addresses

    // Network ports
    uint16_t default_p2p_port;
    uint16_t default_rpc_port;

    // Network magic bytes (4 bytes)
    uint32_t magic;

    // Address version bytes
    uint8_t version_p2pkh;
    uint8_t version_p2sh;    // Reserved for future
    uint8_t version_wif;     // WIF private key version

    // Genesis block parameters
    int64_t genesis_time;
    uint32_t genesis_bits;
    uint32_t genesis_nonce;
    const char* genesis_hash_hex;
    const char* genesis_merkle_hex;
    const char* genesis_coinbase_pkh_hex;

    // Consensus parameters
    uint64_t coin;
    uint64_t initial_subsidy;
    uint64_t halving_interval;
    uint64_t max_money;
    uint32_t coinbase_maturity;
    int64_t block_time_secs;
    uint32_t retarget_interval;

    // Difficulty
    uint32_t min_difficulty_bits;  // Minimum difficulty (regtest override)
    bool allow_min_difficulty;     // Allow min difficulty blocks after timeout

    // DNS seeds
    std::vector<std::string> dns_seeds;

    // Checkpoints (height -> hash)
    // std::vector<std::pair<uint64_t, std::string>> checkpoints;
};

// =============================================================================
// MAINNET PARAMETERS
// =============================================================================
inline NetworkParams mainnet_params() {
    NetworkParams p;
    p.type = NetworkType::MAINNET;
    p.name = "mainnet";
    p.bech32_hrp = "miq";

    p.default_p2p_port = 9883;
    p.default_rpc_port = 9834;
    p.magic = 0xA3FB9E21;

    p.version_p2pkh = 0x35;  // '5' prefix in Base58
    p.version_p2sh = 0x32;   // Reserved
    p.version_wif = 0xB5;    // 0x80 + 0x35

    p.genesis_time = 1758890772;
    p.genesis_bits = 0x1d00ffff;
    p.genesis_nonce = 0xd3dda73c;
    p.genesis_hash_hex = "00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8";
    p.genesis_merkle_hex = "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097";
    p.genesis_coinbase_pkh_hex = "00c649e06c60278501aad8a3b05d345fe8008836";

    p.coin = 100000000ULL;
    p.initial_subsidy = 50ULL * p.coin;
    p.halving_interval = 262800ULL;
    p.max_money = 26280000ULL * p.coin;
    p.coinbase_maturity = 100;
    p.block_time_secs = 480;  // 8 minutes
    p.retarget_interval = 2628;

    p.min_difficulty_bits = 0x1d00ffff;
    p.allow_min_difficulty = false;

    p.dns_seeds = {
        "seed.miqrochain.org",
        "miqseed1.duckdns.org",
        "miqseed2.freeddns.org"
    };

    return p;
}

// =============================================================================
// TESTNET PARAMETERS
// =============================================================================
inline NetworkParams testnet_params() {
    NetworkParams p;
    p.type = NetworkType::TESTNET;
    p.name = "testnet";
    p.bech32_hrp = "tmiq";

    p.default_p2p_port = 19883;  // Different from mainnet
    p.default_rpc_port = 19834;
    p.magic = 0xB4FC9F32;  // Different magic for testnet

    p.version_p2pkh = 0x6F;  // 'n' or 'm' prefix (like Bitcoin testnet)
    p.version_p2sh = 0xC4;   // Reserved
    p.version_wif = 0xEF;    // Testnet WIF

    // Testnet genesis (can be regenerated for fresh testnet)
    p.genesis_time = 1758890772;  // Can use same or different
    p.genesis_bits = 0x1d00ffff;
    p.genesis_nonce = 0x00000001;  // Easier to find for testnet
    p.genesis_hash_hex = "0000000000000000000000000000000000000000000000000000000000000000";  // Placeholder
    p.genesis_merkle_hex = "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097";
    p.genesis_coinbase_pkh_hex = "00c649e06c60278501aad8a3b05d345fe8008836";

    p.coin = 100000000ULL;
    p.initial_subsidy = 50ULL * p.coin;
    p.halving_interval = 262800ULL;
    p.max_money = 26280000ULL * p.coin;
    p.coinbase_maturity = 100;
    p.block_time_secs = 480;
    p.retarget_interval = 2628;

    p.min_difficulty_bits = 0x1d00ffff;
    p.allow_min_difficulty = true;  // Allow easy blocks on testnet

    p.dns_seeds = {
        "testnet-seed.miqrochain.org"
    };

    return p;
}

// =============================================================================
// REGTEST PARAMETERS
// =============================================================================
inline NetworkParams regtest_params() {
    NetworkParams p;
    p.type = NetworkType::REGTEST;
    p.name = "regtest";
    p.bech32_hrp = "rmiq";

    p.default_p2p_port = 29883;  // Different from mainnet/testnet
    p.default_rpc_port = 29834;
    p.magic = 0xC5FDA043;  // Unique magic for regtest

    p.version_p2pkh = 0x6F;  // Same as testnet
    p.version_p2sh = 0xC4;
    p.version_wif = 0xEF;

    // Regtest genesis (trivial difficulty)
    p.genesis_time = 1758890772;
    p.genesis_bits = 0x207fffff;  // Very easy difficulty for instant mining
    p.genesis_nonce = 0x00000000;
    p.genesis_hash_hex = "0000000000000000000000000000000000000000000000000000000000000000";  // Computed at runtime
    p.genesis_merkle_hex = "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097";
    p.genesis_coinbase_pkh_hex = "00c649e06c60278501aad8a3b05d345fe8008836";

    p.coin = 100000000ULL;
    p.initial_subsidy = 50ULL * p.coin;
    p.halving_interval = 150;  // Short halving for testing
    p.max_money = 26280000ULL * p.coin;
    p.coinbase_maturity = 100;
    p.block_time_secs = 480;
    p.retarget_interval = 144;  // Shorter interval for regtest

    p.min_difficulty_bits = 0x207fffff;  // Minimum possible difficulty
    p.allow_min_difficulty = true;

    p.dns_seeds = {};  // No DNS seeds for regtest

    return p;
}

// =============================================================================
// NETWORK SELECTION
// =============================================================================

// Global network selection (can be set via CLI)
inline NetworkParams& active_network() {
    static NetworkParams params = mainnet_params();
    return params;
}

inline void set_network(NetworkType type) {
    switch (type) {
        case NetworkType::MAINNET:
            active_network() = mainnet_params();
            break;
        case NetworkType::TESTNET:
            active_network() = testnet_params();
            break;
        case NetworkType::REGTEST:
            active_network() = regtest_params();
            break;
    }
}

inline NetworkType parse_network_type(const std::string& name) {
    if (name == "testnet" || name == "test") return NetworkType::TESTNET;
    if (name == "regtest" || name == "reg") return NetworkType::REGTEST;
    return NetworkType::MAINNET;
}

inline std::string network_type_name(NetworkType type) {
    switch (type) {
        case NetworkType::TESTNET: return "testnet";
        case NetworkType::REGTEST: return "regtest";
        default: return "mainnet";
    }
}

}  // namespace miq
