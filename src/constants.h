#pragma once
#pragma once
#include <cstdint>

// === Pinned genesis (Option A: keep your current chain) ===
// Fill these with YOUR values (from your logs/dump). Leave strings quoted.
#define MIQ_GENESIS_HASH_HEX        "PASTE_HASH"
#define MIQ_GENESIS_MERKLE_HEX      "PASTE_MERKLE"
static constexpr std::uint32_t MIQ_GENESIS_TIME  = /* e.g. 1738023456 */ 0u;
static constexpr std::uint32_t MIQ_GENESIS_BITS  = /* e.g. 0x1e0ffff0 */ 0u;
static constexpr std::uint32_t MIQ_GENESIS_NONCE = /* e.g. 2083236893 */ 0u;
#define MIQ_GENESIS_CB_TXID         "PASTE_CB_TXID"

// Coinbase recipient (your PKH for NKz...)
// You already confirmed: 00c649e06c60278501aad8a3b05d345fe8008836
#define MIQ_GENESIS_COINBASE_PKH_HEX "00c649e06c60278501aad8a3b05d345fe8008836"
static constexpr std::uint64_t MIQ_GENESIS_COINBASE_VALUE = 50ull * 100000000ull;

// --- Optional: tiny hex helper (header-only, no deps) ---
inline static std::string miq_to_hex(const unsigned char* p, std::size_t n) {
    static const char* H="0123456789abcdef";
    std::string s; s.resize(n*2);
    for (std::size_t i=0;i<n;++i){ s[2*i]=H[(p[i]>>4)&0xF]; s[2*i+1]=H[p[i]&0xF]; }
    return s;
}

namespace miq {
static constexpr const char* COIN_NAME = "miq";
static constexpr const char* CHAIN_NAME = "miqrochain";
static constexpr const char* UNIT_NAME = "miqron";

static constexpr uint64_t COIN = 100000000ULL;
static constexpr uint64_t BLOCK_TIME_SECS = 480; // 8 minutes
static constexpr uint16_t P2P_PORT = 443;
static constexpr uint16_t RPC_PORT = 9834;
static constexpr uint32_t MAGIC = 0xA3FB9E21;

static constexpr uint64_t MAX_MONEY = 26280000ULL * COIN;
static constexpr uint64_t INITIAL_SUBSIDY = 50ULL * COIN;
static constexpr uint64_t HALVING_INTERVAL = 262800ULL;
static constexpr uint32_t COINBASE_MATURITY = 100;

// Address version bytes : mainnet P2PKH = 0x35 ('5')
static constexpr uint8_t VERSION_P2PKH = 0x35;

struct Genesis {
    // From GENESIS_DUMP:
    static constexpr const char* HASH_HEX        = "PASTE_HASH";
    static constexpr const char* MERKLE_HEX      = "PASTE_MERKLE";
    static constexpr uint32_t    TIME            = PASTE_TIME;  
    static constexpr uint32_t    BITS            = PASTE_BITS;   
    static constexpr uint32_t    NONCE           = PASTE_NONCE;   
    static constexpr const char* COINBASE_TXID   = "PASTE_CB_TXID";

    // Entire serialized genesis block (from GENESIS_RAW).
    // This is the simplest, bullet-proof way to reconstruct exactly.
    static constexpr const char* RAW_BLOCK_HEX   = "PASTE_GENESIS_RAW_HEX";

    // Optional info:
    static constexpr const char* COINBASE_PKH_HEX = "00c649e06c60278501aad8a3b05d345fe8008836";
    static constexpr uint64_t    COINBASE_VALUE   = 50ull * 100000000ull;
};

} } // namespace

static constexpr int64_t GENESIS_TIME = 1758230400; // 2025-09-19 00:00:00Z approx
static constexpr uint32_t GENESIS_BITS = 0x1d00ffff;

// Bundled genesis private key (secp256k1 32 bytes hex) for coinbase
static constexpr const char* GENESIS_ECDSA_PRIV_HEX = "";

// Kept for backward-compat: some code paths may still use this single seed
static const std::string DNS_SEED = "185.162.238.19";

// NEW: Multi-seed list (add-only). Your node can try these in order.
static inline const char* const DNS_SEEDS[] = {
    "s626853.name-servers.gr",
    "miqseed1.duckdns.org",
    "miqseed2.freeddns.org"
};
static constexpr size_t DNS_SEEDS_COUNT = sizeof(DNS_SEEDS) / sizeof(DNS_SEEDS[0]);

// DoS/time
static constexpr int64_t MAX_TIME_SKEW = 2*60*60; // 2 hours

// ===== ADDED: security caps =====
// Maximum serialized block size accepted (prevents giant-block DoS)
static constexpr size_t MAX_BLOCK_SIZE = 1 * 1024 * 1024; // 1 MiB

// Maximum serialized transaction size accepted (prevents giant-tx DoS)
static constexpr size_t MAX_TX_SIZE    = 100 * 1024;      // 100 KiB

// Maximum P2P payload length (wire "len" field cap)
static constexpr size_t MAX_MSG_SIZE   = 2 * 1024 * 1024; // 2 MiB

// Optional: default RPC token (empty = no token unless MIQ_RPC_TOKEN env set)
static constexpr const char* RPC_TOKEN_DEFAULT = "";
} // namespace miq
