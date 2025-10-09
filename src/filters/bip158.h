#pragma once
// BIP158 "basic" block filters for MIQ (P2PKH-only chain).
// We include: prevout PKH for each non-coinbase input, and every output PKH.

#include <vector>
#include <array>
#include <string>

#include "block.h"
#include "utxo.h"     // UTXOEntry & UTXO view
#include "filters/gcs.h"

namespace miq {
namespace bip158 {

struct BasicFilter {
    std::array<uint8_t,16> key;   // first 16 bytes of block hash (LE) per BIP158
    std::vector<uint8_t>   bytes; // serialized filter (CompactSize N || data)
};

// Build a basic filter for a block using the provided UTXO view (must contain
// the prevouts being spent by the block). Returns false on hard errors.
bool BuildBasicFilter(const Block& blk, const UTXO& utxo, BasicFilter& out, std::string* err = nullptr);

// Convenience query helpers (PKH-based wallet lookups)
bool MatchPKH(const BasicFilter& f, const std::vector<uint8_t>& pkh20);
bool MatchAnyPKH(const BasicFilter& f, const std::vector<std::vector<uint8_t>>& pkhs);

}
}
