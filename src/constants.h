#pragma once
#include <cstdint>
#include <string>
// ADDED for size_t
#include <cstddef>

namespace miq {
static constexpr const char* COIN_NAME = "miq";
static constexpr const char* CHAIN_NAME = "miqrochain";
static constexpr const char* UNIT_NAME = "miqron";

static constexpr uint64_t COIN = 100000000ULL;
static constexpr uint64_t BLOCK_TIME_SECS = 480; // 8 minutes
static constexpr uint16_t P2P_PORT = 443;
static constexpr uint16_t RPC_PORT = 9834;
static constexpr uint32_t MAGIC = 0xA3FB9E21;

static constexpr uint64_t MAX_MONEY = 28260000ULL * COIN;
static constexpr uint64_t INITIAL_SUBSIDY = 50ULL * COIN;
static constexpr uint64_t HALVING_INTERVAL = 282600ULL;
static constexpr uint32_t COINBASE_MATURITY = 100;

// Address version bytes : mainnet P2PKH = 0x35 ('5')
static constexpr uint8_t VERSION_P2PKH = 0x35;

static constexpr int64_t GENESIS_TIME = 1758230400; // 2025-09-19 00:00:00Z approx
static constexpr uint32_t GENESIS_BITS = 0x1d00ffff;

// Bundled genesis private key (secp256k1 32 bytes hex) for coinbase
static constexpr const char* GENESIS_ECDSA_PRIV_HEX = "";

static const std::string DNS_SEED = "miqroseed1.dedyn.io";

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

