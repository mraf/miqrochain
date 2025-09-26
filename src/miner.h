#pragma once
#include "block.h"
#include "hasher.h"
#include "mempool.h"

#include <cstdint>
#include <vector>

namespace miq {

// == Difficulty check (unchanged signature/behavior) =========================
// Returns true iff 32-byte hash 'hv' satisfies the compact difficulty 'bits'.
// Safe for use both in validation and miner fast-path comparisons.
bool meets_target(const std::vector<uint8_t>& hv, uint32_t bits);

// == Mining ==================================================================
// Build a candidate block on top of 'prev_hash', including 'coinbase' and
// 'mempool_txs', then search for a valid nonce using 'threads' worker threads.
// NOTE: Does not alter consensus parameters; header layout & hashing semantics
// remain identical to validation path.
Block mine_block(const std::vector<uint8_t>& prev_hash,
                 uint32_t bits,
                 const Transaction& coinbase,
                 const std::vector<Transaction>& mempool_txs,
                 unsigned threads);

// == Miner stats (consensus-neutral, thread-safe) ============================
// Rolling counter since last snapshot; atomically resets that rolling window.
uint64_t miner_hashes_snapshot_and_reset();

// Monotonic total number of hashes attempted since process start.
uint64_t miner_hashes_total();

// Instantaneous stats over a moving window.
//  - hps     : current hashes per second estimate
//  - hashes  : total hashes since process start (monotonic)
//  - seconds : wall time of the last sampling window
struct MinerStats {
    double   hps;      // hashes per second (estimate)
    uint64_t hashes;   // total hashes since start
    double   seconds;  // seconds covered by this sample window
};

// Snapshot the current miner statistics. Purely diagnostic; no consensus effect.
MinerStats miner_stats_now();

} // namespace miq
