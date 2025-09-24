#pragma once
#include "block.h"
#include "hasher.h"
#include "mempool.h"
#include <vector>
#include <cstdint>

namespace miq {

// Same target rule as before (declared for external use).
bool meets_target(const std::vector<uint8_t>& h, uint32_t bits);

// Build a candidate block on top of prev_hash, including coinbase and mempool_txs,
// then search for a nonce using `threads` worker threads.
Block mine_block(const std::vector<uint8_t>& prev_hash,
                 uint32_t bits,
                 const Transaction& coinbase,
                 const std::vector<Transaction>& mempool_txs,
                 unsigned threads);

// --- Miner stats (new; does not affect consensus) ---
// Number of hashes attempted since the last snapshot; resets the rolling counter.
uint64_t miner_hashes_snapshot_and_reset();

// Total hashes attempted since process start (monotonic; not reset by snapshot).
uint64_t miner_hashes_total();

} // namespace miq
