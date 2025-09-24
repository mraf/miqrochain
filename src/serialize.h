
#pragma once
#include <vector>
#include <cstdint>
#include "tx.h"
#include "block.h"
namespace miq {
std::vector<uint8_t> ser_tx(const Transaction& tx);
bool deser_tx(const std::vector<uint8_t>& b, Transaction& tx);
std::vector<uint8_t> ser_block(const Block& b);
bool deser_block(const std::vector<uint8_t>& b, Block& out);
}
