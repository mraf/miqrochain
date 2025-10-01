#pragma once
#include <cstdint>
#include <vector>
#include <utility>

namespace miq {

// LWMA difficulty adjustment:
//   last: vector of (timestamp, bits) for recent blocks (oldest -> newest)
//   target_spacing: desired seconds per block
//   min_bits: fallback/lowest difficulty to use when not enough history
uint32_t lwma_next_bits(const std::vector<std::pair<int64_t,uint32_t>>& last,
                        int64_t target_spacing,
                        uint32_t min_bits);

}
