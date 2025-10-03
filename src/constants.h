#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

//
// ==== P2P/addrman tuning (macros picked up by p2p.cpp) =====================
// These are optional overrides; p2p.cpp only defines its own defaults if these
// are *not* defined here. Adjust as you like without touching code.
//

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

// Historical 32-bit network tag you already had; we continue to honor it.
static constexpr uint32_t MAGIC = 0xA3FB9E21;

// Canonical **wire** magic bytes (big-endian rendering of MAGIC). Keep stable forever.
static constexpr uint8_t MAGIC_BE[4] = {
    static_cast<uint8_t>((MAGIC >> 24) & 0xFF),
    static_cast<uint8_t>((MAGIC >> 16) & 0xFF),
    static_cast<uint8_t>((MAGIC >>  8) & 0xFF),
    static_cast<uint8_t>((MAGIC >>  0) & 0xFF),
};

// Money / subsidy
static constexpr uint64_t MAX_MONEY        = 26280000ULL * COIN;
static constexpr uint64_t INITIAL_SUBSIDY  = 50ULL * COIN;
static constexpr uint64_t HALVING_INTERVAL = 262800ULL;
static constexpr uint32_t COINBASE_MATURITY = 100;

// Address version bytes : mainnet P2PKH = 0x35 ('5')
static constexpr uint8_t VERSION_P2PKH = 0x35;

// ---------------------------------------------------------------------
// GENESIS (pinned to the currently running network)
// Use these in your init path to build/verify genesis deterministically.
static constexpr int64_t  GENESIS_TIME = 1758890772;     // from dump / matches header bytes
static constexpr uint32_t GENESIS_BITS = 0x1d00ffff;     // compact target (unchanged)
static constexpr uint32_t GENESIS_NONCE = 0xd3dda73c;    // low 32 bits

// Explicit hash & merkle of block 0 (display/big-endian hex as you had)
static constexpr const char* GENESIS_HASH_HEX   = "00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8";
static constexpr const char* GENESIS_MERKLE_HEX = "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097";

// Bundled genesis private key (leave empty if you don’t embed it)
static constexpr const char* GENESIS_ECDSA_PRIV_HEX = "";

// Who receives the genesis coinbase (your PKH)
static constexpr const char* GENESIS_COINBASE_PKH_HEX = "00c649e06c60278501aad8a3b05d345fe8008836";
static constexpr uint64_t    GENESIS_COINBASE_VALUE   = INITIAL_SUBSIDY;

// Byte-for-byte serialized genesis block for fresh datadirs (exactly 192 bytes)
static constexpr const char* GENESIS_RAW_BLOCK_HEX =
    "01000000f14b2f88c25fb8d87df687a6f5f94be2304a319f1b71209f632d2fffdbfe7856"
    "c5d2f3cdb807edcd4b0d9573df33e751ad038797088336c4558e7fd58784a097"
    "148bd66800000000ffff001d3ca7ddd3f2e65f9e"
    "01000000"  // tx count (4)
    "60000000"  // tx size (96)
    "01000000"  // tx.version
    "01000000"  // #inputs
    "20000000"  // prev.txid size (32)
    "0000000000000000000000000000000000000000000000000000000000000000"
    "00000000"  // prev.vout
    "00000000"  // sig len
    "00000000"  // pubkey len
    "01000000"  // #outputs (LE)
    "00f2052a01000000"  // value = 50*COIN (u64 LE)
    "14000000"          // pkh len = 20 (LE)
    "00c649e06c60278501aad8a3b05d345fe8008836"  // PKH (20 bytes)
    "00000000";         // lock_time

// ---------------------------------------------------------------------
// Seeds (kept intact)
static const std::string DNS_SEED = "62.38.73.147";

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
