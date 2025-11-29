#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <functional>
#include "block.h"
#include "blockindex.h"

namespace miq {

// =============================================================================
// PRODUCTION MTP (MEDIAN TIME PAST) IMPLEMENTATION v2.0
// =============================================================================
// RFC: Bitcoin-style MTP uses the median of the last 11 block **times**.
// We mirror that: parent -> walk back up to 11 headers (including parent).
// =============================================================================

static constexpr int MIQ_MTP_WINDOW = 11;

// Allow up to +2 hours future drift for received headers/blocks.
static constexpr int64_t MIQ_MAX_FUTURE_DRIFT_SECS = 2 * 60 * 60;

// Minimum time increment between blocks (1 second - prevents timestamp gaming)
static constexpr int64_t MIQ_MIN_TIME_INCREMENT = 1;

// Maximum time decrement tolerance for orphan handling (5 minutes)
static constexpr int64_t MIQ_ORPHAN_TIME_TOLERANCE_SECS = 5 * 60;

// =============================================================================
// MTP COMPUTATION
// =============================================================================

// Compute MTP for a given parent header record.
// If parent is null (genesis accept), returns parent's time (0 safe-fallback).
int64_t compute_mtp(const std::shared_ptr<HeaderRec>& parent);

// Compute MTP from a vector of timestamps (utility function)
int64_t compute_mtp_from_times(const std::vector<int64_t>& times);

// =============================================================================
// TIME RULE VALIDATION
// =============================================================================

// Strict header timestamp rules (Bitcoin-like):
//   1) h.time > MTP(parent)  [strictly greater than]
//   2) h.time <= now + MAX_FUTURE_DRIFT
//   3) h.time >= parent.time (monotonic check, soft enforcement)
// Returns true if OK; false and sets err otherwise.
bool check_header_time_rules(const BlockHeader& h,
                             const std::shared_ptr<HeaderRec>& parent,
                             std::string& err);

// Strict block (full) timestamp rules (same checks as header stage).
bool check_block_time_rules(const Block& b,
                            const std::shared_ptr<HeaderRec>& parent,
                            std::string& err);

// =============================================================================
// ADVANCED TIME VALIDATION
// =============================================================================

// Validate header time with custom time source (for testing)
bool check_header_time_rules_with_time(const BlockHeader& h,
                                       const std::shared_ptr<HeaderRec>& parent,
                                       int64_t current_time,
                                       std::string& err);

// Check if time is acceptable during IBD (more lenient for historical blocks)
bool check_time_rules_ibd(const BlockHeader& h,
                          int64_t mtp,
                          std::string& err);

// Validate block timestamp for transaction locktime purposes
// Returns the effective time for locktime comparison
int64_t get_block_time_for_locktime(const std::shared_ptr<HeaderRec>& tip);

// =============================================================================
// TIME ATTACK DETECTION
// =============================================================================

// Detect potential timewarp attack (rapid timestamp decrease)
bool detect_timewarp_attack(const std::vector<int64_t>& recent_times,
                            int64_t new_time);

// Get time adjustment based on peer median time (future use)
int64_t get_time_offset();
void add_time_sample(int64_t peer_time);

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

// Get current network time (wall clock + offset)
int64_t get_adjusted_time();

// Check if we should warn about time skew
bool should_warn_time_skew(int64_t local_time, int64_t network_time);

}
