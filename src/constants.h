#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

// ==== P2P/addrman tuning (macros picked up by p2p.cpp) =====================
// These are optional overrides; p2p.cpp only defines its own defaults if these
// are *not* defined here. Adjust as you like without touching code.

// Enable the new persistent addrman path
#ifndef MIQ_ENABLE_ADDRMAN
#define MIQ_ENABLE_ADDRMAN 1
#endif

// Addrman persistence file name (distinct from legacy peers.dat)
#ifndef MIQ_ADDRMAN_FILE
#define MIQ_ADDRMAN_FILE "peers2.dat"
#endif

// Outbound peer target
#ifndef MIQ_OUTBOUND_TARGET
#define MIQ_OUTBOUND_TARGET 4
#endif

// Outbound dialing cadence (ms)
#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 15000
#endif

// Feeler cadence (ms) for probing NEW addresses
#ifndef MIQ_FEELER_INTERVAL_MS
#define MIQ_FEELER_INTERVAL_MS 60000
#endif

// Max outbounds per IPv4 /16 group (anti-eclipse)
#ifndef MIQ_GROUP_OUTBOUND_MAX
#define MIQ_GROUP_OUTBOUND_MAX 2
#endif

// Legacy addrset autosave interval & cap (used by current code)
#ifndef MIQ_ADDR_SAVE_INTERVAL_MS
#define MIQ_ADDR_SAVE_INTERVAL_MS 60000
#endif
#ifndef MIQ_ADDR_MAX_STORE
#define MIQ_ADDR_MAX_STORE 10000
#endif
// ===========================================================================

namespace miq {

// ---------------------------------------------------------------------
// Existing identifiers (unchanged)
static constexpr const char* COIN_NAME  = "miq";
static constexpr const char* CHAIN_NAME = "miqrochain";
static constexpr const char* UNIT_NAME  = "miqron";

static constexpr uint64_t COIN = 100000000ULL;
static constexpr uint64_t BLOCK_TIME_SECS = 480; // 8 minutes
static constexpr uint16_t P2P_PORT = 55001;      // (kept as-is per your current config)
static constexpr uint16_t RPC_PORT = 9834;
static constexpr uint32_t MAGIC    = 0xA3FB9E21;

static constexpr uint64_t MAX_MONEY        = 26280000ULL * COIN;
static constexpr uint64_t INITIAL_SUBSIDY  = 50ULL * COIN;
static constexpr uint64_t HALVING_INTERVAL = 262800ULL;
static constexpr uint32_t COINBASE_MATURITY = 100;

// Address version bytes : mainnet P2PKH = 0x35 ('5')
static constexpr uint8_t VERSION_P2PKH = 0x35;

// ---------------------------------------------------------------------
// GENESIS (pinned to the currently running network)
// Use these in your init path to build/verify genesis deterministically.
static constexpr int64_t  GENESIS_TIME = 1758890000;     // from your dump
static constexpr uint32_t GENESIS_BITS = 0x1d00ffff;     // compact target (unchanged)
static constexpr uint32_t GENESIS_NONCE = 0xd3dda73c;    // from your dump

// NEW: explicit hash & merkle of block 0 (big-endian hex)
static constexpr const char* GENESIS_HASH_HEX   = "00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8";
static constexpr const char* GENESIS_MERKLE_HEX = "97a08487d57f8e55c4368308978703ad51e733df73950d4bcded07b8cdf3d2c5";

// Bundled genesis private key (leave empty if you don’t embed it)
static constexpr const char* GENESIS_ECDSA_PRIV_HEX = "";

// NEW: make it crystal-clear who receives the genesis coinbase (your PKH)
// (This matches address NKz4j64Wv3h7EZz5eHrkk3EKYgXMFsHd4t that you mined to)
static constexpr const char* GENESIS_COINBASE_PKH_HEX = "00c649e06c60278501aad8a3b05d345fe8008836";
static constexpr uint64_t    GENESIS_COINBASE_VALUE   = INITIAL_SUBSIDY;

// NEW: byte-for-byte serialized genesis block for fresh datadirs
// On an empty chain: deserialize this and append as block 0 to guarantee exact match.
static constexpr const char* GENESIS_RAW_BLOCK_HEX =
    "01000000f14b2f88c25fb8d87df687a6f5f94be2304a319f1b71209f632d2fffdbfe7856"
    "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097"
    "148bd66800000000ffff001d3ca7ddd3"
    "f2e65f9e010000006000000001000000010000002000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000100000000f2052a010000001400000000c649e06c60278501aad8a3b05d345fe800883600000000";

// ---------------------------------------------------------------------
// Seeds (kept intact)
static const std::string DNS_SEED = "185.162.238.19";

// Multi-seed list (add-only). Your node can try these in order.
static inline const char* const DNS_SEEDS[] = {
    "s626853.name-servers.gr",
    "miqseed1.duckdns.org",
    "miqseed2.freeddns.org"
};
static constexpr size_t DNS_SEEDS_COUNT = sizeof(DNS_SEEDS) / sizeof(DNS_SEEDS[0]);

// ---------------------------------------------------------------------
// DoS/time
static constexpr int64_t MAX_TIME_SKEW = 2*60*60; // 2 hours

// Security caps (kept intact)
static constexpr size_t MAX_BLOCK_SIZE = 1 * 1024 * 1024; // 1 MiB
static constexpr size_t MAX_TX_SIZE    = 100 * 1024;      // 100 KiB
static constexpr size_t MAX_MSG_SIZE   = 2 * 1024 * 1024; // 2 MiB

// Optional: default RPC token (empty = no token unless MIQ_RPC_TOKEN env set)
static constexpr const char* RPC_TOKEN_DEFAULT = "";

}
