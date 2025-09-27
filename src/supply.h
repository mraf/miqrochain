#pragma once
// supply.h — header-only helpers for subsidy + hard max supply enforcement
// Safe on MSVC & GCC/Clang (64-bit only; no __int128).

#include <cstdint>

// Pull chain params if available; provide safe fallbacks to avoid breaking builds.
#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifndef COIN
// Smallest unit per coin (default 1e8 like Bitcoin). Override in constants.h if different.
#define COIN 100000000ULL
#endif

#ifndef INITIAL_SUBSIDY
#define INITIAL_SUBSIDY 50ULL
#endif

#ifndef HALVING_INTERVAL
// Blocks per halving (e.g., 262,800 for ~4 years at 8 min/blk)
#define HALVING_INTERVAL 262800ULL
#endif

namespace miq {

// Public, fixed total supply in whole coins.
static constexpr uint64_t MAX_SUPPLY_COINS = 26280000ULL; // 26.28 million
// Precompute max in smallest units (fits in uint64_t: 2.628e15 << 2^64)
static constexpr uint64_t MAX_SUPPLY_SATS  = MAX_SUPPLY_COINS * COIN;

// Return the per-block subsidy (in sats) at height.
inline uint64_t GetBlockSubsidy(uint32_t height) {
    uint64_t eras = static_cast<uint64_t>(height) / HALVING_INTERVAL;
    if (eras >= 64) return 0ULL;
    uint64_t sub = INITIAL_SUBSIDY * COIN;
    // Right shift halves the subsidy per era; saturates to zero after enough eras.
    return (eras >= 64) ? 0ULL : (sub >> eras);
}

// Sum of all subsidies from height 0 up to (but not including) `height`.
inline uint64_t TotalSubsidyUpTo(uint32_t height) {
    uint64_t blocks = height;
    uint64_t era_blocks = HALVING_INTERVAL;
    uint64_t sub0 = INITIAL_SUBSIDY * COIN;

    uint64_t total = 0ULL;
    uint64_t era = 0ULL;

    while (blocks > 0 && era < 64) {
        uint64_t take = (blocks > era_blocks) ? era_blocks : blocks;
        uint64_t sub  = (era >= 64) ? 0ULL : (sub0 >> era);

        // Safe add: total += take * sub
        if (sub != 0) {
            // take*sub fits well under uint64_t with these parameters
            uint64_t add = take * sub;
            if (UINT64_MAX - total < add) {
                return UINT64_MAX; // saturate (shouldn't happen with given params)
            }
            total += add;
        }
        if (blocks <= take) break;
        blocks -= take;
        ++era;
    }
    return total;
}

// True if minting the subsidy portion `coinbase_value_without_fees` at `height` would exceed MAX_SUPPLY.
inline bool WouldExceedMaxSupply(uint32_t height, uint64_t coinbase_value_without_fees) {
    // minted_so_far is the sum of past subsidies only (no fees)
    const uint64_t minted = TotalSubsidyUpTo(height);

    // Remaining = MAX_SUPPLY_SATS - minted  (with underflow guard)
    if (minted >= MAX_SUPPLY_SATS) {
        return (coinbase_value_without_fees > 0ULL);
    }
    const uint64_t remaining = MAX_SUPPLY_SATS - minted;

    return coinbase_value_without_fees > remaining;
}

// Convenience: coinbase must not exceed subsidy+fees.
inline bool CoinbaseWithinLimits(uint32_t height, uint64_t coinbase_value, uint64_t total_fees) {
    const uint64_t sub = GetBlockSubsidy(height);
    // Safe add: sub + total_fees
    if (UINT64_MAX - sub < total_fees) return false;
    const uint64_t limit = sub + total_fees;
    return coinbase_value <= limit;
}

}
