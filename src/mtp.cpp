#include "mtp.h"
#include "log.h"
#include <algorithm>
#include <ctime>
#include <mutex>
#include <deque>
#include <atomic>
#include <numeric>
#include <cmath>

namespace miq {

// =============================================================================
// PRODUCTION MTP IMPLEMENTATION v2.0
// =============================================================================
// Enhanced with time attack detection, peer time sampling, and IBD support
// =============================================================================

// Time offset management for network time synchronization
static std::mutex g_time_samples_mtx;
static std::deque<int64_t> g_time_samples;
static constexpr size_t MAX_TIME_SAMPLES = 200;
static std::atomic<int64_t> g_time_offset{0};

// =============================================================================
// CORE MTP COMPUTATION
// =============================================================================

int64_t compute_mtp(const std::shared_ptr<HeaderRec>& parent){
    if (!parent) return 0;

    // Collect up to last 11 header times walking parents
    std::vector<int64_t> times;
    times.reserve(MIQ_MTP_WINDOW);
    auto cur = parent;
    for (int i = 0; i < MIQ_MTP_WINDOW && cur; ++i) {
        times.push_back(cur->time);
        cur = cur->parent;
    }

    return compute_mtp_from_times(times);
}

int64_t compute_mtp_from_times(const std::vector<int64_t>& times){
    if (times.empty()) return 0;

    // Create sorted copy for median calculation
    std::vector<int64_t> sorted = times;
    std::sort(sorted.begin(), sorted.end());

    // Return median element (floor for odd length)
    return sorted[sorted.size() / 2];
}

// =============================================================================
// TIME UTILITIES
// =============================================================================

static inline int64_t now_utc(){
    return static_cast<int64_t>(std::time(nullptr));
}

int64_t get_adjusted_time(){
    return now_utc() + g_time_offset.load(std::memory_order_relaxed);
}

int64_t get_time_offset(){
    return g_time_offset.load(std::memory_order_relaxed);
}

void add_time_sample(int64_t peer_time){
    int64_t local = now_utc();
    int64_t offset = peer_time - local;

    // Reject extreme outliers (more than 24 hours off)
    if (std::abs(offset) > 24 * 60 * 60) {
        return;
    }

    std::lock_guard<std::mutex> lk(g_time_samples_mtx);
    g_time_samples.push_back(offset);

    // Trim to max samples
    while (g_time_samples.size() > MAX_TIME_SAMPLES) {
        g_time_samples.pop_front();
    }

    // Recompute median offset
    if (g_time_samples.size() >= 5) {
        std::vector<int64_t> sorted(g_time_samples.begin(), g_time_samples.end());
        std::sort(sorted.begin(), sorted.end());
        int64_t median = sorted[sorted.size() / 2];

        // Clamp offset to +/- 70 minutes (Bitcoin-style)
        constexpr int64_t MAX_OFFSET = 70 * 60;
        if (median > MAX_OFFSET) median = MAX_OFFSET;
        if (median < -MAX_OFFSET) median = -MAX_OFFSET;

        g_time_offset.store(median, std::memory_order_relaxed);
    }
}

bool should_warn_time_skew(int64_t local_time, int64_t network_time){
    // Warn if local clock differs from network by more than 10 minutes
    constexpr int64_t WARN_THRESHOLD = 10 * 60;
    return std::abs(local_time - network_time) > WARN_THRESHOLD;
}

// =============================================================================
// TIME RULE VALIDATION
// =============================================================================

bool check_header_time_rules_with_time(const BlockHeader& h,
                                       const std::shared_ptr<HeaderRec>& parent,
                                       int64_t current_time,
                                       std::string& err)
{
    const int64_t mtp = compute_mtp(parent);

    // Rule 1: Block time must be strictly greater than MTP
    if (!(h.time > mtp)) {
        err = "bad-header-time: timestamp " + std::to_string(h.time) +
              " not greater than MTP " + std::to_string(mtp);
        return false;
    }

    // Rule 2: Block time must not be too far in the future
    const int64_t max_future = current_time + MIQ_MAX_FUTURE_DRIFT_SECS;
    if (h.time > max_future) {
        err = "bad-header-time: timestamp " + std::to_string(h.time) +
              " too far in future (max " + std::to_string(max_future) + ")";
        return false;
    }

    // Rule 3 (soft): Warn if time is less than parent (but don't reject during IBD)
    if (parent && h.time < parent->time) {
        // This is suspicious but allowed - MTP rule is the hard rule
        // Log it for monitoring
        log_debug(LogCategory::VALIDATION,
                  "block time " + std::to_string(h.time) +
                  " is before parent time " + std::to_string(parent->time));
    }

    return true;
}

bool check_header_time_rules(const BlockHeader& h,
                             const std::shared_ptr<HeaderRec>& parent,
                             std::string& err)
{
    return check_header_time_rules_with_time(h, parent, get_adjusted_time(), err);
}

bool check_block_time_rules(const Block& b,
                            const std::shared_ptr<HeaderRec>& parent,
                            std::string& err)
{
    return check_header_time_rules(b.header, parent, err);
}

bool check_time_rules_ibd(const BlockHeader& h,
                          int64_t mtp,
                          std::string& err)
{
    // During IBD, we only enforce the MTP rule (not future time check)
    // This allows syncing historical blocks without time issues
    if (!(h.time > mtp)) {
        err = "bad-header-time-ibd: timestamp " + std::to_string(h.time) +
              " not greater than MTP " + std::to_string(mtp);
        return false;
    }
    return true;
}

int64_t get_block_time_for_locktime(const std::shared_ptr<HeaderRec>& tip){
    // For BIP113: use MTP for locktime comparisons
    return compute_mtp(tip);
}

// =============================================================================
// TIME ATTACK DETECTION
// =============================================================================

bool detect_timewarp_attack(const std::vector<int64_t>& recent_times,
                            int64_t new_time)
{
    if (recent_times.size() < 3) return false;

    // Check for suspicious patterns:
    // 1. Rapid decrease in timestamps (potential timewarp)
    // 2. Oscillating timestamps designed to manipulate difficulty

    // Get the last few timestamps
    size_t n = std::min(recent_times.size(), size_t(10));
    std::vector<int64_t> window(recent_times.end() - n, recent_times.end());
    window.push_back(new_time);

    // Check for timewarp: if new_time is significantly less than average
    int64_t sum = std::accumulate(window.begin(), window.end() - 1, int64_t(0));
    int64_t avg = sum / (int64_t)(window.size() - 1);

    // If new time is more than 30 minutes behind average, suspicious
    if (new_time < avg - 30 * 60) {
        log_warn("Potential timewarp attack detected: new_time=" +
                 std::to_string(new_time) + " avg=" + std::to_string(avg));
        return true;
    }

    // Check for oscillation pattern
    int direction_changes = 0;
    for (size_t i = 2; i < window.size(); ++i) {
        int64_t d1 = window[i-1] - window[i-2];
        int64_t d2 = window[i] - window[i-1];
        if ((d1 > 0 && d2 < -60) || (d1 < 0 && d2 > 60)) {
            direction_changes++;
        }
    }

    // More than 3 significant direction changes in 10 blocks is suspicious
    if (direction_changes >= 3) {
        log_warn("Suspicious timestamp oscillation detected: " +
                 std::to_string(direction_changes) + " direction changes");
        return true;
    }

    return false;
}

}
