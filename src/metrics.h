#pragma once
// src/metrics.h - Prometheus-compatible metrics export for global-scale monitoring

#include <string>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include <vector>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace miq {

// =============================================================================
// PROMETHEUS METRICS SYSTEM
// Provides observability for production deployments at global scale
// =============================================================================

class Metrics {
public:
    static Metrics& instance() {
        static Metrics m;
        return m;
    }

    // --- Counter metrics (monotonically increasing) ---
    void inc_blocks_received() { blocks_received_++; }
    void inc_blocks_validated() { blocks_validated_++; }
    void inc_blocks_rejected() { blocks_rejected_++; }
    void inc_txs_received() { txs_received_++; }
    void inc_txs_validated() { txs_validated_++; }
    void inc_txs_rejected() { txs_rejected_++; }
    void inc_peers_connected() { peers_connected_total_++; }
    void inc_peers_disconnected() { peers_disconnected_total_++; }
    void inc_rpc_requests() { rpc_requests_++; }
    void inc_rpc_errors() { rpc_errors_++; }
    void inc_mining_hashes(uint64_t n) { mining_hashes_ += n; }
    void inc_blocks_mined() { blocks_mined_++; }
    void inc_orphan_blocks() { orphan_blocks_++; }
    void inc_reorgs() { reorgs_++; }
    void add_bytes_sent(uint64_t n) { bytes_sent_ += n; }
    void add_bytes_received(uint64_t n) { bytes_received_ += n; }

    // --- Gauge metrics (can go up and down) ---
    void set_chain_height(uint64_t h) { chain_height_ = h; }
    void set_peers_count(uint32_t n) { peers_count_ = n; }
    void set_mempool_size(uint64_t bytes) { mempool_bytes_ = bytes; }
    void set_mempool_txs(uint32_t n) { mempool_txs_ = n; }
    void set_utxo_count(uint64_t n) { utxo_count_ = n; }
    void set_difficulty(double d) { difficulty_ = d; }
    void set_hash_rate(double h) { hash_rate_ = h; }
    void set_ibd_progress(double p) { ibd_progress_ = p; }
    void set_uptime_seconds(uint64_t s) { uptime_seconds_ = s; }

    // --- Histogram observations ---
    void observe_block_validation_ms(double ms) {
        std::lock_guard<std::mutex> lk(hist_mtx_);
        block_validation_ms_.push_back(ms);
        if (block_validation_ms_.size() > 10000) {
            block_validation_ms_.erase(block_validation_ms_.begin(),
                                       block_validation_ms_.begin() + 5000);
        }
    }
    void observe_tx_validation_us(double us) {
        std::lock_guard<std::mutex> lk(hist_mtx_);
        tx_validation_us_.push_back(us);
        if (tx_validation_us_.size() > 10000) {
            tx_validation_us_.erase(tx_validation_us_.begin(),
                                    tx_validation_us_.begin() + 5000);
        }
    }
    void observe_peer_latency_ms(double ms) {
        std::lock_guard<std::mutex> lk(hist_mtx_);
        peer_latency_ms_.push_back(ms);
        if (peer_latency_ms_.size() > 10000) {
            peer_latency_ms_.erase(peer_latency_ms_.begin(),
                                   peer_latency_ms_.begin() + 5000);
        }
    }

    // --- Export in Prometheus text format ---
    std::string export_prometheus() const {
        std::ostringstream ss;
        ss << std::fixed << std::setprecision(6);

        // Counters
        ss << "# HELP miq_blocks_received_total Total blocks received from peers\n";
        ss << "# TYPE miq_blocks_received_total counter\n";
        ss << "miq_blocks_received_total " << blocks_received_.load() << "\n\n";

        ss << "# HELP miq_blocks_validated_total Total blocks successfully validated\n";
        ss << "# TYPE miq_blocks_validated_total counter\n";
        ss << "miq_blocks_validated_total " << blocks_validated_.load() << "\n\n";

        ss << "# HELP miq_blocks_rejected_total Total blocks rejected\n";
        ss << "# TYPE miq_blocks_rejected_total counter\n";
        ss << "miq_blocks_rejected_total " << blocks_rejected_.load() << "\n\n";

        ss << "# HELP miq_txs_received_total Total transactions received\n";
        ss << "# TYPE miq_txs_received_total counter\n";
        ss << "miq_txs_received_total " << txs_received_.load() << "\n\n";

        ss << "# HELP miq_txs_validated_total Total transactions validated\n";
        ss << "# TYPE miq_txs_validated_total counter\n";
        ss << "miq_txs_validated_total " << txs_validated_.load() << "\n\n";

        ss << "# HELP miq_txs_rejected_total Total transactions rejected\n";
        ss << "# TYPE miq_txs_rejected_total counter\n";
        ss << "miq_txs_rejected_total " << txs_rejected_.load() << "\n\n";

        ss << "# HELP miq_peers_connected_total Total peer connections established\n";
        ss << "# TYPE miq_peers_connected_total counter\n";
        ss << "miq_peers_connected_total " << peers_connected_total_.load() << "\n\n";

        ss << "# HELP miq_peers_disconnected_total Total peer disconnections\n";
        ss << "# TYPE miq_peers_disconnected_total counter\n";
        ss << "miq_peers_disconnected_total " << peers_disconnected_total_.load() << "\n\n";

        ss << "# HELP miq_rpc_requests_total Total RPC requests processed\n";
        ss << "# TYPE miq_rpc_requests_total counter\n";
        ss << "miq_rpc_requests_total " << rpc_requests_.load() << "\n\n";

        ss << "# HELP miq_rpc_errors_total Total RPC errors\n";
        ss << "# TYPE miq_rpc_errors_total counter\n";
        ss << "miq_rpc_errors_total " << rpc_errors_.load() << "\n\n";

        ss << "# HELP miq_mining_hashes_total Total mining hashes computed\n";
        ss << "# TYPE miq_mining_hashes_total counter\n";
        ss << "miq_mining_hashes_total " << mining_hashes_.load() << "\n\n";

        ss << "# HELP miq_blocks_mined_total Total blocks mined by this node\n";
        ss << "# TYPE miq_blocks_mined_total counter\n";
        ss << "miq_blocks_mined_total " << blocks_mined_.load() << "\n\n";

        ss << "# HELP miq_orphan_blocks_total Total orphan blocks received\n";
        ss << "# TYPE miq_orphan_blocks_total counter\n";
        ss << "miq_orphan_blocks_total " << orphan_blocks_.load() << "\n\n";

        ss << "# HELP miq_reorgs_total Total chain reorganizations\n";
        ss << "# TYPE miq_reorgs_total counter\n";
        ss << "miq_reorgs_total " << reorgs_.load() << "\n\n";

        ss << "# HELP miq_bytes_sent_total Total bytes sent to peers\n";
        ss << "# TYPE miq_bytes_sent_total counter\n";
        ss << "miq_bytes_sent_total " << bytes_sent_.load() << "\n\n";

        ss << "# HELP miq_bytes_received_total Total bytes received from peers\n";
        ss << "# TYPE miq_bytes_received_total counter\n";
        ss << "miq_bytes_received_total " << bytes_received_.load() << "\n\n";

        // Gauges
        ss << "# HELP miq_chain_height Current blockchain height\n";
        ss << "# TYPE miq_chain_height gauge\n";
        ss << "miq_chain_height " << chain_height_.load() << "\n\n";

        ss << "# HELP miq_peers_count Current number of connected peers\n";
        ss << "# TYPE miq_peers_count gauge\n";
        ss << "miq_peers_count " << peers_count_.load() << "\n\n";

        ss << "# HELP miq_mempool_bytes Current mempool size in bytes\n";
        ss << "# TYPE miq_mempool_bytes gauge\n";
        ss << "miq_mempool_bytes " << mempool_bytes_.load() << "\n\n";

        ss << "# HELP miq_mempool_txs Current number of transactions in mempool\n";
        ss << "# TYPE miq_mempool_txs gauge\n";
        ss << "miq_mempool_txs " << mempool_txs_.load() << "\n\n";

        ss << "# HELP miq_utxo_count Current UTXO set size\n";
        ss << "# TYPE miq_utxo_count gauge\n";
        ss << "miq_utxo_count " << utxo_count_.load() << "\n\n";

        ss << "# HELP miq_difficulty Current mining difficulty\n";
        ss << "# TYPE miq_difficulty gauge\n";
        ss << "miq_difficulty " << difficulty_.load() << "\n\n";

        ss << "# HELP miq_hash_rate Current hash rate (H/s)\n";
        ss << "# TYPE miq_hash_rate gauge\n";
        ss << "miq_hash_rate " << hash_rate_.load() << "\n\n";

        ss << "# HELP miq_ibd_progress Initial block download progress (0-1)\n";
        ss << "# TYPE miq_ibd_progress gauge\n";
        ss << "miq_ibd_progress " << ibd_progress_.load() << "\n\n";

        ss << "# HELP miq_uptime_seconds Node uptime in seconds\n";
        ss << "# TYPE miq_uptime_seconds gauge\n";
        ss << "miq_uptime_seconds " << uptime_seconds_.load() << "\n\n";

        // Histograms (simplified - showing count, sum, and percentiles)
        {
            std::lock_guard<std::mutex> lk(hist_mtx_);

            if (!block_validation_ms_.empty()) {
                auto stats = compute_histogram_stats(block_validation_ms_);
                ss << "# HELP miq_block_validation_ms Block validation time in milliseconds\n";
                ss << "# TYPE miq_block_validation_ms summary\n";
                ss << "miq_block_validation_ms{quantile=\"0.5\"} " << stats.p50 << "\n";
                ss << "miq_block_validation_ms{quantile=\"0.9\"} " << stats.p90 << "\n";
                ss << "miq_block_validation_ms{quantile=\"0.99\"} " << stats.p99 << "\n";
                ss << "miq_block_validation_ms_sum " << stats.sum << "\n";
                ss << "miq_block_validation_ms_count " << stats.count << "\n\n";
            }

            if (!tx_validation_us_.empty()) {
                auto stats = compute_histogram_stats(tx_validation_us_);
                ss << "# HELP miq_tx_validation_us Transaction validation time in microseconds\n";
                ss << "# TYPE miq_tx_validation_us summary\n";
                ss << "miq_tx_validation_us{quantile=\"0.5\"} " << stats.p50 << "\n";
                ss << "miq_tx_validation_us{quantile=\"0.9\"} " << stats.p90 << "\n";
                ss << "miq_tx_validation_us{quantile=\"0.99\"} " << stats.p99 << "\n";
                ss << "miq_tx_validation_us_sum " << stats.sum << "\n";
                ss << "miq_tx_validation_us_count " << stats.count << "\n\n";
            }

            if (!peer_latency_ms_.empty()) {
                auto stats = compute_histogram_stats(peer_latency_ms_);
                ss << "# HELP miq_peer_latency_ms Peer round-trip latency in milliseconds\n";
                ss << "# TYPE miq_peer_latency_ms summary\n";
                ss << "miq_peer_latency_ms{quantile=\"0.5\"} " << stats.p50 << "\n";
                ss << "miq_peer_latency_ms{quantile=\"0.9\"} " << stats.p90 << "\n";
                ss << "miq_peer_latency_ms{quantile=\"0.99\"} " << stats.p99 << "\n";
                ss << "miq_peer_latency_ms_sum " << stats.sum << "\n";
                ss << "miq_peer_latency_ms_count " << stats.count << "\n\n";
            }
        }

        return ss.str();
    }

private:
    Metrics() = default;

    // Counters
    std::atomic<uint64_t> blocks_received_{0};
    std::atomic<uint64_t> blocks_validated_{0};
    std::atomic<uint64_t> blocks_rejected_{0};
    std::atomic<uint64_t> txs_received_{0};
    std::atomic<uint64_t> txs_validated_{0};
    std::atomic<uint64_t> txs_rejected_{0};
    std::atomic<uint64_t> peers_connected_total_{0};
    std::atomic<uint64_t> peers_disconnected_total_{0};
    std::atomic<uint64_t> rpc_requests_{0};
    std::atomic<uint64_t> rpc_errors_{0};
    std::atomic<uint64_t> mining_hashes_{0};
    std::atomic<uint64_t> blocks_mined_{0};
    std::atomic<uint64_t> orphan_blocks_{0};
    std::atomic<uint64_t> reorgs_{0};
    std::atomic<uint64_t> bytes_sent_{0};
    std::atomic<uint64_t> bytes_received_{0};

    // Gauges
    std::atomic<uint64_t> chain_height_{0};
    std::atomic<uint32_t> peers_count_{0};
    std::atomic<uint64_t> mempool_bytes_{0};
    std::atomic<uint32_t> mempool_txs_{0};
    std::atomic<uint64_t> utxo_count_{0};
    std::atomic<double> difficulty_{0.0};
    std::atomic<double> hash_rate_{0.0};
    std::atomic<double> ibd_progress_{0.0};
    std::atomic<uint64_t> uptime_seconds_{0};

    // Histograms
    mutable std::mutex hist_mtx_;
    std::vector<double> block_validation_ms_;
    std::vector<double> tx_validation_us_;
    std::vector<double> peer_latency_ms_;

    struct HistStats {
        double p50{0}, p90{0}, p99{0}, sum{0};
        size_t count{0};
    };

    static HistStats compute_histogram_stats(std::vector<double> data) {
        HistStats s;
        if (data.empty()) return s;

        std::sort(data.begin(), data.end());
        s.count = data.size();

        for (double v : data) s.sum += v;

        s.p50 = data[data.size() * 50 / 100];
        s.p90 = data[data.size() * 90 / 100];
        s.p99 = data[std::min(data.size() - 1, data.size() * 99 / 100)];

        return s;
    }
};

// Convenience macros for instrumentation
#define MIQ_METRIC_INC_BLOCKS_RECEIVED() miq::Metrics::instance().inc_blocks_received()
#define MIQ_METRIC_INC_BLOCKS_VALIDATED() miq::Metrics::instance().inc_blocks_validated()
#define MIQ_METRIC_INC_BLOCKS_REJECTED() miq::Metrics::instance().inc_blocks_rejected()
#define MIQ_METRIC_INC_TXS_RECEIVED() miq::Metrics::instance().inc_txs_received()
#define MIQ_METRIC_INC_TXS_VALIDATED() miq::Metrics::instance().inc_txs_validated()
#define MIQ_METRIC_INC_TXS_REJECTED() miq::Metrics::instance().inc_txs_rejected()
#define MIQ_METRIC_SET_HEIGHT(h) miq::Metrics::instance().set_chain_height(h)
#define MIQ_METRIC_SET_PEERS(n) miq::Metrics::instance().set_peers_count(n)

// =============================================================================
// OPERATOR METRICS v2.0
// =============================================================================
// Extended metrics for production node operators
// =============================================================================

struct NodeHealth {
    bool is_synced{false};
    bool has_peers{false};
    bool is_mining{false};
    bool rpc_responsive{false};
    double sync_progress{0.0};   // 0.0 to 1.0
    int64_t blocks_behind{0};
    int64_t headers_behind{0};
    int64_t uptime_seconds{0};
    int64_t last_block_time{0};  // Unix timestamp of last block received

    // Overall health score (0.0 to 1.0)
    double health_score() const {
        double score = 0.0;
        if (is_synced) score += 0.3;
        if (has_peers) score += 0.3;
        if (rpc_responsive) score += 0.2;
        score += sync_progress * 0.2;
        return score;
    }

    // Human-readable status
    const char* status_string() const {
        if (!has_peers) return "NO_PEERS";
        if (!is_synced) return "SYNCING";
        if (health_score() >= 0.8) return "HEALTHY";
        if (health_score() >= 0.5) return "DEGRADED";
        return "UNHEALTHY";
    }
};

// Get current node health status
NodeHealth get_node_health();

// Export metrics in JSON format for dashboards
std::string export_metrics_json();

// =============================================================================
// SCOPED TIMER FOR PERFORMANCE MEASUREMENT
// =============================================================================

class ScopedMetricTimer {
public:
    enum TimerType { BLOCK_VALIDATION, TX_VALIDATION, PEER_LATENCY };

    explicit ScopedMetricTimer(TimerType type)
        : type_(type)
        , start_(std::chrono::high_resolution_clock::now())
    {}

    ~ScopedMetricTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto& m = Metrics::instance();

        if (type_ == BLOCK_VALIDATION) {
            double ms = std::chrono::duration<double, std::milli>(end - start_).count();
            m.observe_block_validation_ms(ms);
        } else if (type_ == TX_VALIDATION) {
            double us = std::chrono::duration<double, std::micro>(end - start_).count();
            m.observe_tx_validation_us(us);
        } else if (type_ == PEER_LATENCY) {
            double ms = std::chrono::duration<double, std::milli>(end - start_).count();
            m.observe_peer_latency_ms(ms);
        }
    }

private:
    TimerType type_;
    std::chrono::high_resolution_clock::time_point start_;
};

#define MIQ_SCOPED_BLOCK_TIMER() \
    miq::ScopedMetricTimer _block_timer_(miq::ScopedMetricTimer::BLOCK_VALIDATION)

#define MIQ_SCOPED_TX_TIMER() \
    miq::ScopedMetricTimer _tx_timer_(miq::ScopedMetricTimer::TX_VALIDATION)

#define MIQ_SCOPED_PEER_TIMER() \
    miq::ScopedMetricTimer _peer_timer_(miq::ScopedMetricTimer::PEER_LATENCY)

} // namespace miq
