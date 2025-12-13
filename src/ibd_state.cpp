// =============================================================================
// IBD STATE MACHINE - Implementation
// =============================================================================

#include "ibd_state.h"
#include "log.h"
#include <algorithm>
#include <sstream>

namespace miq {
namespace ibd {

// =============================================================================
// STATE TRANSITIONS
// =============================================================================
// Bitcoin Core principle: State transitions are monotonic.
// CONNECTING → HEADERS → BLOCKS → DONE
// Never go backwards.
// =============================================================================

void IBDState::transition_to(SyncState new_state) {
    SyncState old_state = state_.load(std::memory_order_acquire);

    // Monotonic: only allow forward transitions
    if (static_cast<uint8_t>(new_state) <= static_cast<uint8_t>(old_state)) {
        // Log attempt to go backwards (invariant violation)
        if (new_state != old_state) {
            log_warn("[IBD-INVARIANT] Blocked non-monotonic state transition: " +
                     std::string(state_name(old_state)) + " → " + state_name(new_state));
        }
        return;
    }

    // Perform transition
    state_.store(new_state, std::memory_order_release);
    log_info("[IBD-STATE] " + std::string(state_name(old_state)) + " → " + state_name(new_state) +
             " (headers=" + std::to_string(header_height_.load()) +
             " blocks=" + std::to_string(block_height_.load()) +
             " peer_tip=" + std::to_string(best_peer_tip_.load()) + ")");
}

// =============================================================================
// HEIGHT TRACKING
// =============================================================================
// Heights are monotonic within a session. If we receive a header/block at
// height H, header_height/block_height never goes below H.
// =============================================================================

void IBDState::set_header_height(uint64_t h) {
    uint64_t old = header_height_.load(std::memory_order_acquire);
    if (h > old) {
        header_height_.store(h, std::memory_order_release);

        // Track highest ever (for invariant checking)
        uint64_t highest = highest_header_ever_.load(std::memory_order_relaxed);
        while (h > highest && !highest_header_ever_.compare_exchange_weak(
                highest, h, std::memory_order_release, std::memory_order_relaxed)) {}
    }
}

void IBDState::set_block_height(uint64_t h) {
    uint64_t old = block_height_.load(std::memory_order_acquire);
    if (h > old) {
        block_height_.store(h, std::memory_order_release);

        // Track highest ever (for invariant checking)
        uint64_t highest = highest_block_ever_.load(std::memory_order_relaxed);
        while (h > highest && !highest_block_ever_.compare_exchange_weak(
                highest, h, std::memory_order_release, std::memory_order_relaxed)) {}

        // Update last receive timestamp
        last_recv_timestamp_ms_.store(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count(),
            std::memory_order_release);
    }
}

void IBDState::update_peer_tip(uint64_t tip) {
    uint64_t old = best_peer_tip_.load(std::memory_order_acquire);
    while (tip > old && !best_peer_tip_.compare_exchange_weak(
            old, tip, std::memory_order_release, std::memory_order_relaxed)) {}
}

// =============================================================================
// INFLIGHT MANAGEMENT
// =============================================================================
// Bitcoin Core principle: Hole-filling without pipeline reset.
// When a block times out, we mark it as available for re-request from another
// peer, but we DON'T cancel other inflight requests.
// =============================================================================

bool IBDState::request_block(uint64_t index, uint64_t peer_id) {
    std::lock_guard<std::mutex> lk(inflight_mu_);

    // Already inflight from this or another peer
    if (inflight_indices_.count(index)) {
        return false;
    }

    // Track request
    inflight_indices_.insert(index);
    inflight_timestamps_[index] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    inflight_peer_[index] = peer_id;

    return true;
}

void IBDState::block_received(uint64_t index, uint64_t peer_id) {
    std::lock_guard<std::mutex> lk(inflight_mu_);

    inflight_indices_.erase(index);
    inflight_timestamps_.erase(index);
    inflight_peer_.erase(index);

    total_blocks_received_.fetch_add(1, std::memory_order_relaxed);
    last_recv_timestamp_ms_.store(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count(),
        std::memory_order_release);
}

void IBDState::block_timeout(uint64_t index, uint64_t peer_id) {
    std::lock_guard<std::mutex> lk(inflight_mu_);

    // Only remove if still attributed to this peer
    auto it = inflight_peer_.find(index);
    if (it != inflight_peer_.end() && it->second == peer_id) {
        inflight_indices_.erase(index);
        inflight_timestamps_.erase(index);
        inflight_peer_.erase(index);
    }
}

bool IBDState::is_index_inflight(uint64_t index) const {
    std::lock_guard<std::mutex> lk(inflight_mu_);
    return inflight_indices_.count(index) > 0;
}

std::vector<uint64_t> IBDState::get_holes(uint64_t count) const {
    std::lock_guard<std::mutex> lk(inflight_mu_);

    std::vector<uint64_t> holes;
    uint64_t current = block_height_.load(std::memory_order_acquire) + 1;
    uint64_t target = std::min(header_height_.load(std::memory_order_acquire),
                               best_peer_tip_.load(std::memory_order_acquire));

    while (holes.size() < count && current <= target) {
        if (!inflight_indices_.count(current)) {
            holes.push_back(current);
        }
        current++;
    }

    return holes;
}

// =============================================================================
// STALL DETECTION
// =============================================================================
// Bitcoin Core principle: Edge-triggered based on reception timestamps.
// We only care if ANY data was received recently, not whether commit height
// increased. This handles out-of-order block arrival correctly.
// =============================================================================

bool IBDState::has_recent_activity(int64_t threshold_ms) const {
    int64_t last = last_recv_timestamp_ms_.load(std::memory_order_acquire);
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return (now - last) < threshold_ms;
}

// =============================================================================
// INVARIANT LOGGING
// =============================================================================
// Proves that progress is monotonic across the session.
// =============================================================================

void IBDState::log_progress(const std::string& event) const {
    std::ostringstream oss;
    oss << event
        << " state=" << state_name(state_.load())
        << " headers=" << header_height_.load()
        << " blocks=" << block_height_.load()
        << " peer_tip=" << best_peer_tip_.load()
        << " inflight=" << inflight_indices_.size()
        << " total_recv=" << total_blocks_received_.load();
    log_info(oss.str());
}

bool IBDState::check_invariants() const {
    bool ok = true;

    // Invariant 1: header_height >= block_height
    uint64_t hdr = header_height_.load();
    uint64_t blk = block_height_.load();
    if (blk > hdr) {
        log_warn("[IBD-INVARIANT-FAIL] block_height > header_height: " +
                 std::to_string(blk) + " > " + std::to_string(hdr));
        ok = false;
    }

    // Invariant 2: highest_ever >= current (monotonic)
    if (hdr > highest_header_ever_.load()) {
        log_warn("[IBD-INVARIANT-FAIL] header_height > highest_header_ever");
        ok = false;
    }
    if (blk > highest_block_ever_.load()) {
        log_warn("[IBD-INVARIANT-FAIL] block_height > highest_block_ever");
        ok = false;
    }

    // Invariant 3: inflight indices are > block_height
    {
        std::lock_guard<std::mutex> lk(inflight_mu_);
        for (uint64_t idx : inflight_indices_) {
            if (idx <= blk) {
                log_warn("[IBD-INVARIANT-FAIL] inflight index " + std::to_string(idx) +
                         " <= block_height " + std::to_string(blk));
                ok = false;
            }
        }
    }

    return ok;
}

} // namespace ibd
} // namespace miq
