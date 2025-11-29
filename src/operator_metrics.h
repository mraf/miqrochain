#pragma once
// =============================================================================
// OPERATOR METRICS - Production monitoring and diagnostics
// =============================================================================

#include <string>
#include <cstdint>
#include <atomic>
#include <chrono>
#include <mutex>
#include <vector>

namespace miq {

// =============================================================================
// METRICS COLLECTION
// =============================================================================

struct PeerMetrics {
    std::atomic<uint64_t> total_connected{0};
    std::atomic<uint64_t> inbound_count{0};
    std::atomic<uint64_t> outbound_count{0};
    std::atomic<uint64_t> stall_count{0};
    std::atomic<uint64_t> ban_count{0};
    std::atomic<uint64_t> bytes_sent{0};
    std::atomic<uint64_t> bytes_recv{0};
    std::atomic<uint64_t> messages_sent{0};
    std::atomic<uint64_t> messages_recv{0};
};

struct ValidationMetrics {
    std::atomic<uint64_t> blocks_validated{0};
    std::atomic<uint64_t> txs_validated{0};
    std::atomic<uint64_t> blocks_rejected{0};
    std::atomic<uint64_t> txs_rejected{0};
    std::atomic<uint64_t> total_validation_ms{0};
    std::atomic<uint64_t> last_block_ms{0};
};

struct MempoolMetrics {
    std::atomic<uint64_t> size{0};
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> txs_added{0};
    std::atomic<uint64_t> txs_removed{0};
    std::atomic<uint64_t> txs_expired{0};
};

struct ReorgMetrics {
    std::atomic<uint64_t> reorg_count{0};
    std::atomic<uint64_t> max_reorg_depth{0};
    std::atomic<uint64_t> blocks_disconnected{0};
    std::atomic<uint64_t> blocks_reconnected{0};
    std::atomic<int64_t> last_reorg_time{0};
};

struct ChainMetrics {
    std::atomic<uint64_t> height{0};
    std::atomic<uint64_t> difficulty{0};
    std::atomic<uint64_t> total_work{0};
    std::atomic<int64_t> tip_time{0};
    std::atomic<uint64_t> utxo_count{0};
};

struct RPCMetrics {
    std::atomic<uint64_t> requests_total{0};
    std::atomic<uint64_t> requests_failed{0};
    std::atomic<uint64_t> total_latency_ms{0};
};

// =============================================================================
// GLOBAL METRICS INSTANCE
// =============================================================================

class OperatorMetrics {
public:
    static OperatorMetrics& instance();

    PeerMetrics peer;
    ValidationMetrics validation;
    MempoolMetrics mempool;
    ReorgMetrics reorg;
    ChainMetrics chain;
    RPCMetrics rpc;

    // Log current metrics summary
    void log_summary() const;

    // Log reorg event
    void log_reorg(uint64_t depth, uint64_t old_height, uint64_t new_height);

    // Log difficulty adjustment
    void log_difficulty_epoch(uint64_t height, uint64_t old_diff, uint64_t new_diff);

    // Log peer stall
    void log_peer_stall(const std::string& ip, uint64_t stall_duration_ms);

    // Log block validation timing
    void log_block_validated(uint64_t height, uint64_t validation_ms, uint64_t tx_count);

    // Get JSON metrics for RPC/API
    std::string to_json() const;

    // Reset all counters
    void reset();

private:
    OperatorMetrics() = default;
    mutable std::mutex mtx_;
};

// =============================================================================
// HELPER MACROS FOR EASY METRIC UPDATES
// =============================================================================

#define MIQ_METRIC_INC(category, field) \
    miq::OperatorMetrics::instance().category.field.fetch_add(1, std::memory_order_relaxed)

#define MIQ_METRIC_ADD(category, field, val) \
    miq::OperatorMetrics::instance().category.field.fetch_add(val, std::memory_order_relaxed)

#define MIQ_METRIC_SET(category, field, val) \
    miq::OperatorMetrics::instance().category.field.store(val, std::memory_order_relaxed)

}  // namespace miq
