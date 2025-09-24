
#pragma once
#include <cstdint>
#include <vector>
#include "tx.h"
namespace miq {
struct BlockHeader { uint32_t version{1}; std::vector<uint8_t> prev_hash; std::vector<uint8_t> merkle_root; int64_t time{0}; uint32_t bits{0}; uint64_t nonce{0}; };
struct Block { BlockHeader header; std::vector<Transaction> txs; std::vector<uint8_t> block_hash() const; };
}
