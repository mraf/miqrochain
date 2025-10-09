#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

struct UtxoLite {
    std::vector<uint8_t> txid;   // 32
    uint32_t vout;               // index
    uint64_t value;              // in miqron
    std::vector<uint8_t> pkh;    // 20
    uint32_t height;             // block height (0 for mempool)
    bool coinbase;
};

struct SpvOptions {
    // how many most-recent blocks we scan when peer lacks filters
    uint32_t recent_block_window = 8000;
    // where to store a tiny on-disk cache per wallet
    std::string cache_dir; // e.g. "wallets/default"
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

}
