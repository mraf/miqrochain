// =============================================================================
// IBD STATE MACHINE - Bitcoin Core-aligned Initial Block Download
// =============================================================================
//
// This implements a single authoritative sync state machine following Bitcoin
// Core's proven design (net_processing.cpp, headerssync.cpp).
//
// KEY DESIGN PRINCIPLES (from Bitcoin Core):
// 1. Single state machine: HEADERS → BLOCKS → DONE (no overlapping fallbacks)
// 2. Edge-triggered stall detection based on reception timestamps
// 3. Hole-filling without pipeline resets (never cancel good inflight requests)
// 4. Minimum inflight window guarantee (≥16 blocks per peer during IBD)
// 5. Monotonic progress: headers height, block height never decrease
// 6. Deterministic behavior: same peers → same sequence of events
//
// REFERENCES:
// - Bitcoin Core net_processing.cpp: ProcessHeadersMessage(), ProcessBlockMessage()
// - Bitcoin Core headerssync.cpp: HeadersSyncState
// - BIP 130: sendheaders
// - Bitcoin Core validation.cpp: ActivateBestChain()
//
// =============================================================================

#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <vector>
#include <string>

namespace miq {
namespace ibd {

// =============================================================================
// SYNC STATE MACHINE
// =============================================================================
// Bitcoin Core equivalent: ChainstateManager::IsInitialBlockDownload()
// combined with header sync state tracking.
//
// State transitions are MONOTONIC within a session:
//   CONNECTING → HEADERS → BLOCKS → DONE
//
// Once in BLOCKS state, we NEVER go back to HEADERS (Bitcoin Core principle).
// Once in DONE state, we stay there until restart.
// =============================================================================

enum class SyncState : uint8_t {
    CONNECTING = 0,  // Finding peers, no sync started
    HEADERS    = 1,  // Downloading headers (headers-first sync)
    BLOCKS     = 2,  // Downloading blocks (have headers to tip)
    DONE       = 3   // Fully synced (within N blocks of peers)
};

inline const char* state_name(SyncState s) {
    switch (s) {
        case SyncState::CONNECTING: return "CONNECTING";
        case SyncState::HEADERS:    return "HEADERS";
        case SyncState::BLOCKS:     return "BLOCKS";
        case SyncState::DONE:       return "DONE";
    }
    return "UNKNOWN";
}

// =============================================================================
// PER-PEER SYNC STATE
// =============================================================================
// Bitcoin Core equivalent: CNodeState in net_processing.cpp
//
// Tracks per-peer download state with monotonic counters that NEVER reset
// during IBD. This ensures deterministic behavior.
// =============================================================================

struct PeerSyncState {
    // Monotonic counters (NEVER reset during IBD)
    uint64_t headers_received = 0;      // Total headers received from this peer
    uint64_t blocks_received = 0;       // Total blocks received from this peer
    uint64_t blocks_requested = 0;      // Total blocks requested from this peer

    // Timestamps for edge-triggered stall detection
    int64_t last_header_recv_ms = 0;    // When we last received a header
    int64_t last_block_recv_ms = 0;     // When we last received a block
    int64_t last_request_ms = 0;        // When we last sent a request

    // Current inflight tracking (can decrease as blocks arrive)
    std::unordered_set<uint64_t> inflight_indices;  // Block indices in flight
    std::unordered_set<std::string> inflight_hashes; // Block hashes in flight

    // Quality metrics
    double avg_response_ms = 5000.0;    // EMA of response time
    int consecutive_timeouts = 0;        // Consecutive request timeouts

    // State
    bool headers_sync_peer = false;      // Designated for headers sync
    bool block_sync_peer = false;        // Designated for block sync

    // Bitcoin Core: "nUnconnectingHeaders" equivalent
    int disconnecting_headers = 0;       // Headers that don't connect

    // Inflight count (for quick access)
    size_t inflight_count() const {
        return inflight_indices.size() + inflight_hashes.size();
    }
};

// =============================================================================
// GLOBAL IBD STATE
// =============================================================================
// Single source of truth for IBD progress. All sync decisions are based on
// this state, not scattered globals.
// =============================================================================

class IBDState {
public:
    // Singleton access (thread-safe initialization)
    static IBDState& instance() {
        static IBDState s_instance;
        return s_instance;
    }

    // State transitions (monotonic)
    void transition_to(SyncState new_state);
    SyncState current_state() const { return state_.load(std::memory_order_acquire); }

    // Height tracking (monotonic - never decreases)
    void set_header_height(uint64_t h);
    void set_block_height(uint64_t h);
    uint64_t header_height() const { return header_height_.load(std::memory_order_acquire); }
    uint64_t block_height() const { return block_height_.load(std::memory_order_acquire); }

    // Peer tip tracking
    void update_peer_tip(uint64_t tip);
    uint64_t best_peer_tip() const { return best_peer_tip_.load(std::memory_order_acquire); }

    // Inflight management (hole-filling without reset)
    bool request_block(uint64_t index, uint64_t peer_id);
    void block_received(uint64_t index, uint64_t peer_id);
    void block_timeout(uint64_t index, uint64_t peer_id);
    bool is_index_inflight(uint64_t index) const;
    std::vector<uint64_t> get_holes(uint64_t count) const;  // Get unfilled gaps

    // Minimum inflight guarantee (Bitcoin Core: MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16)
    static constexpr size_t MIN_INFLIGHT_PER_PEER = 16;
    static constexpr size_t MAX_INFLIGHT_PER_PEER = 128;

    // Stall detection (edge-triggered, based on reception timestamps)
    // Returns true if ANY peer has received data recently
    bool has_recent_activity(int64_t threshold_ms) const;

    // Monotonic progress invariant logging
    void log_progress(const std::string& event) const;

    // Check invariants (for debugging)
    bool check_invariants() const;

private:
    IBDState() = default;

    // Core state (atomic for lock-free reads)
    std::atomic<SyncState> state_{SyncState::CONNECTING};
    std::atomic<uint64_t> header_height_{0};
    std::atomic<uint64_t> block_height_{0};
    std::atomic<uint64_t> best_peer_tip_{0};

    // Inflight tracking
    mutable std::mutex inflight_mu_;
    std::unordered_set<uint64_t> inflight_indices_;
    std::unordered_map<uint64_t, int64_t> inflight_timestamps_;  // index → request time
    std::unordered_map<uint64_t, uint64_t> inflight_peer_;       // index → peer_id

    // Per-peer state
    mutable std::mutex peer_mu_;
    std::unordered_map<uint64_t, PeerSyncState> peer_states_;

    // Monotonic progress tracking
    std::atomic<uint64_t> total_headers_received_{0};
    std::atomic<uint64_t> total_blocks_received_{0};
    std::atomic<int64_t> last_recv_timestamp_ms_{0};

    // Highest indices ever seen (for invariant checking)
    std::atomic<uint64_t> highest_header_ever_{0};
    std::atomic<uint64_t> highest_block_ever_{0};
};

// =============================================================================
// CONVENIENCE MACROS FOR INVARIANT LOGGING
// =============================================================================
// Bitcoin Core uses LogPrint with BCLog::NET category.
// We use similar pattern for tracking monotonic progress.
// =============================================================================

#define IBD_INVARIANT_LOG(fmt, ...) \
    do { \
        miq::ibd::IBDState::instance().log_progress( \
            std::string("[IBD-INVARIANT] ") + fmt); \
    } while(0)

// Assert that a condition holds, log violation if not
#define IBD_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            miq::log_warn(std::string("[IBD-VIOLATION] ") + msg); \
        } \
    } while(0)

} // namespace ibd
} // namespace miq
