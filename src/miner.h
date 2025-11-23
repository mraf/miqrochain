#pragma once
#include <vector>
#include <cstdint>
#include <atomic>
#include <thread>
#include <deque>
#include <chrono>
#include "block.h"

namespace miq {

// =============================================================================
// PRODUCTION-GRADE MINING CONFIGURATION
// =============================================================================

#ifndef MIQ_MINER_DEFAULT_THREADS
#define MIQ_MINER_DEFAULT_THREADS 0  // 0 = auto-detect
#endif
#ifndef MIQ_MINER_DEFAULT_MAX_TXS
#define MIQ_MINER_DEFAULT_MAX_TXS 4000  // More txs per block
#endif
#ifndef MIQ_MINER_DEFAULT_REBUILD_MS
#define MIQ_MINER_DEFAULT_REBUILD_MS 3000  // 3 second template refresh
#endif
#ifndef MIQ_MINER_NONCE_SEARCH_BATCH
#define MIQ_MINER_NONCE_SEARCH_BATCH (1ULL << 20)  // 1M hashes per batch
#endif

// === Public miner stats API (production-enhanced) ===
struct MinerStats {
    double hps;           // Current hash rate (hashes per second)
    uint64_t total;       // Total hashes computed
    double window_secs;   // Measurement window

    // Production additions
    uint64_t blocks_found{0};        // Total blocks mined
    uint64_t blocks_submitted{0};    // Blocks submitted to chain
    uint64_t blocks_accepted{0};     // Blocks accepted by chain
    uint64_t blocks_rejected{0};     // Blocks rejected by chain
    uint64_t stale_blocks{0};        // Stale blocks (tip changed)
    double avg_block_time_secs{0.0}; // Average time to find block
    int64_t last_block_time_ms{0};   // Timestamp of last found block
    uint32_t current_difficulty{0};  // Current difficulty bits
    double estimated_difficulty{0.0};// Human-readable difficulty
};

// Extended stats for monitoring
struct MinerExtendedStats : public MinerStats {
    size_t active_threads{0};
    size_t txs_in_template{0};
    uint64_t template_fees{0};
    int64_t template_age_ms{0};
    bool is_mining{false};
};

uint64_t miner_hashes_snapshot_and_reset();
uint64_t miner_hashes_total();
MinerStats miner_stats_now();
bool meets_target(const std::vector<uint8_t>& hv, uint32_t bits);

class Chain;
class P2P;

// Integrated, network-aware background miner (production-grade)
class Miner {
public:
    explicit Miner(Chain& chain, P2P* p2p = nullptr);
    ~Miner();

    // Configuration
    void set_reward_pkh(const std::vector<uint8_t>& pkh20);  // 20-byte PKH
    void set_threads(unsigned t);                             // 0 => auto (hw_concurrency)
    void set_max_txs(size_t n);                               // txs to include from mempool
    void set_rebuild_interval_ms(int64_t ms);                 // refresh template (time/txs)
    void set_min_fee_rate(double rate);                       // minimum fee rate for txs
    void set_extra_nonce_range(uint64_t start, uint64_t end); // nonce range

    // Control
    void start();
    void stop();
    void pause();
    void resume();
    bool running() const { return running_; }
    bool paused() const { return paused_; }

    // Statistics
    MinerExtendedStats get_extended_stats() const;
    uint64_t get_blocks_found() const { return blocks_found_; }
    uint64_t get_blocks_accepted() const { return blocks_accepted_; }
    double get_current_hashrate() const;

    // Callback for block found (optional)
    using BlockFoundCallback = void(*)(const Block& block, void* user_data);
    void set_block_found_callback(BlockFoundCallback cb, void* user_data);

private:
    Chain& chain_;
    P2P*   p2p_;
    std::thread th_;
    std::atomic<bool> running_{false};
    std::atomic<bool> paused_{false};

    std::vector<uint8_t> reward_pkh20_;
    unsigned threads_{MIQ_MINER_DEFAULT_THREADS};
    size_t   max_txs_{MIQ_MINER_DEFAULT_MAX_TXS};
    int64_t  rebuild_ms_{MIQ_MINER_DEFAULT_REBUILD_MS};
    double   min_fee_rate_{0.0};
    uint64_t extra_nonce_start_{0};
    uint64_t extra_nonce_end_{UINT64_MAX};

    // Statistics tracking
    std::atomic<uint64_t> blocks_found_{0};
    std::atomic<uint64_t> blocks_submitted_{0};
    std::atomic<uint64_t> blocks_accepted_{0};
    std::atomic<uint64_t> blocks_rejected_{0};
    std::atomic<uint64_t> stale_blocks_{0};

    // Timing for statistics
    int64_t mining_started_ms_{0};
    std::deque<int64_t> block_times_;  // Last N block find times
    static constexpr size_t MAX_BLOCK_TIMES = 100;

    // Current template info
    std::atomic<size_t> current_template_txs_{0};
    std::atomic<uint64_t> current_template_fees_{0};
    std::atomic<int64_t> current_template_time_ms_{0};

    // Callback
    BlockFoundCallback block_found_cb_{nullptr};
    void* block_found_user_data_{nullptr};

    void run();
    bool build_template(Block& b, uint32_t& bits);
    bool pow_loop(Block& b, uint32_t bits); // returns true if found (fills nonce)
};

Block mine_block(const std::vector<uint8_t>& prev_hash,
                 uint32_t bits,
                 const Transaction& coinbase,
                 const std::vector<Transaction>& mempool_txs,
                 unsigned threads);

}
