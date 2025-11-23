#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

// =============================================================================
// MIQROCHAIN PRODUCTION-GRADE CONSTANTS v2.0
// Optimized for millions of users, high throughput, and Bitcoin-level reliability
// =============================================================================

// === RATE LIMITING (Production-tuned for high throughput) ===
#ifndef MIQ_RATE_BLOCK_BPS
#define MIQ_RATE_BLOCK_BPS   (32u * 1024u * 1024u)  // 32 MB/s block rate
#endif
#ifndef MIQ_RATE_BLOCK_BURST
#define MIQ_RATE_BLOCK_BURST (128u * 1024u * 1024u) // 128 MB burst capacity
#endif
#ifndef MIQ_RATE_TX_BPS
#define MIQ_RATE_TX_BPS      (4u * 1024u * 1024u)   // 4 MB/s tx rate
#endif
#ifndef MIQ_RATE_TX_BURST
#define MIQ_RATE_TX_BURST    (16u * 1024u * 1024u)  // 16 MB tx burst
#endif

// === SYNCHRONIZATION TUNING ===
#ifndef MIQ_P2P_STALL_RETRY_MS
#define MIQ_P2P_STALL_RETRY_MS 3000  // Faster retry for better sync speed
#endif
#ifndef MIQ_IBD_FALLBACK_AFTER_MS
#define MIQ_IBD_FALLBACK_AFTER_MS (8 * 1000)  // 8s fallback for IBD
#endif
#ifndef MIQ_OUTBOUND_TARGET
#define MIQ_OUTBOUND_TARGET 12  // More outbound for better connectivity
#endif
#ifndef MIQ_SEED_MODE_OUTBOUND_TARGET
#define MIQ_SEED_MODE_OUTBOUND_TARGET 4  // More seeds for reliability
#endif

// === PRODUCTION PERFORMANCE CONSTANTS ===
#ifndef MIQ_SIGNATURE_CACHE_SIZE
#define MIQ_SIGNATURE_CACHE_SIZE (131072u)  // 128K signature cache entries
#endif
#ifndef MIQ_SCRIPT_EXECUTION_CACHE_SIZE
#define MIQ_SCRIPT_EXECUTION_CACHE_SIZE (65536u)  // 64K script cache entries
#endif
#ifndef MIQ_BLOCK_DOWNLOAD_WINDOW
#define MIQ_BLOCK_DOWNLOAD_WINDOW 1024  // Blocks to download ahead
#endif
#ifndef MIQ_MAX_HEADERS_BATCH
#define MIQ_MAX_HEADERS_BATCH 2000  // Headers per batch
#endif
#ifndef MIQ_PARALLEL_BLOCKS
#define MIQ_PARALLEL_BLOCKS 16  // Parallel block downloads
#endif

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

// Outbound peer target (production: more connections for reliability)
#ifndef MIQ_OUTBOUND_TARGET
#define MIQ_OUTBOUND_TARGET 12
#endif

#ifndef MIQ_INDEX_PIPELINE
#define MIQ_INDEX_PIPELINE 32  // Doubled for faster sync
#endif

// Outbound dialing cadence (ms) - faster for quicker network formation
#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 10000
#endif

// Feeler cadence (ms) for probing NEW addresses
#ifndef MIQ_FEELER_INTERVAL_MS
#define MIQ_FEELER_INTERVAL_MS 45000  // More frequent for better discovery
#endif

// Max outbounds per IPv4 /16 group (anti-eclipse protection)
#ifndef MIQ_GROUP_OUTBOUND_MAX
#define MIQ_GROUP_OUTBOUND_MAX 2
#endif

// Legacy addrset autosave interval & cap (used by current code)
#ifndef MIQ_ADDR_SAVE_INTERVAL_MS
#define MIQ_ADDR_SAVE_INTERVAL_MS 45000  // More frequent saves
#endif
#ifndef MIQ_ADDR_MAX_STORE
#define MIQ_ADDR_MAX_STORE 50000  // Store more addresses for better connectivity
#endif

// === PRODUCTION NETWORK RESILIENCE ===
#ifndef MIQ_MIN_PEERS_FOR_HEALTHY
#define MIQ_MIN_PEERS_FOR_HEALTHY 4  // Minimum peers for healthy state
#endif
#ifndef MIQ_TARGET_PEERS
#define MIQ_TARGET_PEERS 32  // Target total peer count
#endif
#ifndef MIQ_STALE_TIP_AGE_SECS
#define MIQ_STALE_TIP_AGE_SECS 1800  // 30 minutes = stale tip
#endif
// ===========================================================================

// ======= Consensus activation height (grandfather existing chain) ===========
#ifndef MIQ_RULES_ACTIVATE_AT
// Default: effectively "disabled" until you set TIP+1 at build time
// or drop <datadir>/activation.height. This avoids forking past-mined blocks.
#define MIQ_RULES_ACTIVATE_AT 0xFFFFFFFFFFFFFFFFULL
#endif

// Optional: keep low-S enforcement explicitly enabled (chain.cpp also defaults it)
#ifndef MIQ_RULE_ENFORCE_LOW_S
#define MIQ_RULE_ENFORCE_LOW_S 1
#endif

namespace miq {

// ---------------------------------------------------------------------
// Existing identifiers (unchanged)
static constexpr const char* COIN_NAME  = "miq";
static constexpr const char* CHAIN_NAME = "miqrochain";
static constexpr const char* UNIT_NAME  = "miqron";

static constexpr uint64_t COIN = 100000000ULL;
static constexpr uint64_t BLOCK_TIME_SECS = 480; // 8 minutes
static constexpr uint16_t P2P_PORT = 9883;      // (kept as-is per your current config)
static constexpr uint16_t RPC_PORT = 9834;

#ifndef MIQ_INDEX_PIPELINE
#define MIQ_INDEX_PIPELINE 8
#endif

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
static const std::string DNS_SEED = "seed.miqrochain.org";

// Multi-seed list (add-only). Your node can try these in order.
static inline const char* const DNS_SEEDS[] = {
    "miqseed1.duckdns.org",
    "miqseed2.freeddns.org"
};
static constexpr size_t DNS_SEEDS_COUNT = sizeof(DNS_SEEDS) / sizeof(DNS_SEEDS[0]);

// ---------------------------------------------------------------------
// DoS/time
static constexpr int64_t MAX_TIME_SKEW = 2*60*60; // 2 hours

// === PRODUCTION SECURITY CAPS ===
static constexpr size_t MAX_BLOCK_SIZE = 4 * 1024 * 1024;  // 4 MiB (scalable)
static constexpr size_t MAX_TX_SIZE    = 400 * 1024;       // 400 KiB
static constexpr size_t MAX_MSG_SIZE   = 8 * 1024 * 1024;  // 8 MiB (for large INVs)

// Optional: default RPC token (empty = no token unless MIQ_RPC_TOKEN env set)
static constexpr const char* RPC_TOKEN_DEFAULT = "";

#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 3000
#endif
#ifndef MIQ_HEADERS_EMPTY_LIMIT
#define MIQ_HEADERS_EMPTY_LIMIT 3
#endif

// === PRODUCTION MEMPOOL CONFIGURATION ===
#ifndef MIQ_MEMPOOL_MAX_BYTES_PROD
#define MIQ_MEMPOOL_MAX_BYTES_PROD (300u * 1024u * 1024u)  // 300 MiB mempool
#endif
#ifndef MIQ_MEMPOOL_MIN_FEE_RATE
#define MIQ_MEMPOOL_MIN_FEE_RATE 1  // 1 sat/byte minimum relay fee
#endif
#ifndef MIQ_MEMPOOL_MAX_ANCESTORS_PROD
#define MIQ_MEMPOOL_MAX_ANCESTORS_PROD 50  // Allow deeper chains
#endif
#ifndef MIQ_MEMPOOL_MAX_DESCENDANTS_PROD
#define MIQ_MEMPOOL_MAX_DESCENDANTS_PROD 50
#endif
#ifndef MIQ_MEMPOOL_EXPIRY_HOURS
#define MIQ_MEMPOOL_EXPIRY_HOURS 336  // 14 days
#endif

// === PRODUCTION UTXO OPTIMIZATION ===
#ifndef MIQ_UTXO_CACHE_SIZE_MB
#define MIQ_UTXO_CACHE_SIZE_MB 450  // 450 MB UTXO cache
#endif
#ifndef MIQ_UTXO_FLUSH_INTERVAL
#define MIQ_UTXO_FLUSH_INTERVAL 10000  // Flush every 10k blocks
#endif

// === PRODUCTION MINING DEFAULTS ===
#ifndef MIQ_DEFAULT_MINING_THREADS
#define MIQ_DEFAULT_MINING_THREADS 0  // 0 = auto-detect CPU cores
#endif
#ifndef MIQ_BLOCK_MIN_TX_FEE
#define MIQ_BLOCK_MIN_TX_FEE 1000  // Minimum 1000 sats fee for inclusion
#endif

// === PRODUCTION LOGGING & MONITORING ===
#ifndef MIQ_LOG_LEVEL_DEFAULT
#define MIQ_LOG_LEVEL_DEFAULT 1  // 0=debug, 1=info, 2=warn, 3=error
#endif
#ifndef MIQ_METRICS_INTERVAL_MS
#define MIQ_METRICS_INTERVAL_MS 60000  // Log metrics every minute
#endif

// === PRODUCTION SECURITY HARDENING ===
#ifndef MIQ_MAX_ORPHAN_TX_SIZE
#define MIQ_MAX_ORPHAN_TX_SIZE (100u * 1024u)  // 100 KB max orphan tx
#endif
#ifndef MIQ_MAX_ORPHAN_TRANSACTIONS
#define MIQ_MAX_ORPHAN_TRANSACTIONS 10000  // Max orphan tx pool size
#endif
#ifndef MIQ_BAN_SCORE_THRESHOLD
#define MIQ_BAN_SCORE_THRESHOLD 100  // Ban after 100 points
#endif
#ifndef MIQ_BAN_DURATION_SECS
#define MIQ_BAN_DURATION_SECS 86400  // 24 hour ban
#endif

// === PRODUCTION CHECKPOINTS (add actual checkpoints for your chain) ===
// Format: {height, "blockhash"}
// These provide DoS protection during IBD

// === VERSION & PROTOCOL ===
static constexpr uint32_t PROTOCOL_VERSION = 70016;  // Protocol version
static constexpr uint32_t MIN_PEER_PROTO_VERSION = 70015;  // Minimum supported

}
