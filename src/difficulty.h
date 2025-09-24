
#pragma once
#include <cstdint>
#include <vector>
#include <utility>
namespace miq { uint32_t lwma_next_bits(const std::vector<std::pair<int64_t,uint32_t>>& last, int64_t target_spacing, uint32_t min_bits); }
