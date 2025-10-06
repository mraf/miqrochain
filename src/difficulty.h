#pragma once
#include <cstdint>
#include <cstddef>
#include <utility>
#include <vector>

namespace miq {

// Existing LWMA (kept for reuse in epoch retarget)
uint32_t lwma_next_bits(const std::vector<std::pair<int64_t,uint32_t>>& last,
                        int64_t target_spacing,
                        uint32_t min_bits);

// Retarget every N blocks (freeze inside the epoch).
// Default: 2628-block epochs (set here, or pass a custom interval).
#ifndef MIQ_RETARGET_INTERVAL
#define MIQ_RETARGET_INTERVAL 2628u
#endif

// Epoch-style next-bits:
// - last: recent headers as (time,bits), newest last (e.g., chain.last_headers(MIQ_RETARGET_INTERVAL))
// - target_spacing: seconds per block
// - min_bits: fallback (genesis bits)
// - next_height: height of the block being mined/validated (tip+1)
// - interval: retarget period (default MIQ_RETARGET_INTERVAL)
uint32_t epoch_next_bits(const std::vector<std::pair<int64_t, uint32_t>>& last,
                         int64_t target_spacing,
                         uint32_t min_bits,
                         uint64_t next_height,
                         size_t interval = MIQ_RETARGET_INTERVAL);

}
