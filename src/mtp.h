#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "block.h"
#include "blockindex.h"

namespace miq {

// RFC: Bitcoin-style MTP uses the median of the last 11 block **times**.
// We mirror that: parent -> walk back up to 11 headers (including parent).
static constexpr int MIQ_MTP_WINDOW = 11;

// Allow up to +2 hours future drift for received headers/blocks.
// (You can move this to constants.h if you prefer.)
static constexpr int64_t MIQ_MAX_FUTURE_DRIFT_SECS = 2 * 60 * 60;

// Compute MTP for a given parent header record.
// If parent is null (genesis accept), returns parent's time (0 safe-fallback).
int64_t compute_mtp(const std::shared_ptr<HeaderRec>& parent);

// Strict header timestamp rules (Bitcoin-like):
//   1) h.time > MTP(parent)
//   2) h.time <= now + MAX_FUTURE_DRIFT
// Returns true if OK; false and sets err otherwise.
bool check_header_time_rules(const BlockHeader& h,
                             const std::shared_ptr<HeaderRec>& parent,
                             std::string& err);

// Strict block (full) timestamp rules (same checks as header stage).
bool check_block_time_rules(const Block& b,
                            const std::shared_ptr<HeaderRec>& parent,
                            std::string& err);

}
