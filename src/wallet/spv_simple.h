#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

struct UtxoLite {
    std::vector<uint8_t> txid;   // 32 (LE)
    uint32_t vout;               // output index
    uint64_t value;              // in miqron
    std::vector<uint8_t> pkh;    // 20
    uint32_t height;             // block height (0 for mempool)
    bool coinbase;
};

struct SpvOptions {
    // How many most-recent blocks to scan when no cache exists.
    // (Ignored once a cache exists; we resume from last scanned height.)
    uint32_t recent_block_window = 8000;

    // Directory to persist a tiny SPV cache (checkpoint + UTXO set for this wallet).
    // If empty, files are written into the current working directory.
    // Cache files: <cache_dir>/spv_state.dat and <cache_dir>/utxo_cache.dat
    std::string cache_dir; // e.g. "wallets/default"

    // Connection timeout in milliseconds (0 = use default from P2POpts)
    int timeout_ms = 0;
};

// Collect UTXOs that pay to any of `pkhs` using only P2P.
// Returns true on success and fills `out` (deduped & pruned for spends).
bool spv_collect_utxos(
    const std::string& p2p_host, const std::string& p2p_port,
    const std::vector<std::vector<uint8_t>>& pkhs,
    const SpvOptions& opt,
    std::vector<UtxoLite>& out,
    std::string& err);

// Optional: quick sum helper.
uint64_t spv_sum_value(const std::vector<UtxoLite>& v);

// CRITICAL FIX: Invalidate in-memory UTXO cache after sending transactions
// This ensures fresh data is fetched from network after spending UTXOs
void spv_invalidate_mem_cache();

}
