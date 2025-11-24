#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <thread>
#include <atomic>
#include <functional>
#include <cstdint>
#include <deque>
#include "tx.h"  // PRODUCTION FIX: For Transaction type in StratumJob

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  using StratumSock = SOCKET;
  #define STRATUM_INVALID_SOCKET INVALID_SOCKET
#else
  using StratumSock = int;
  #define STRATUM_INVALID_SOCKET (-1)
#endif

namespace miq {

class Chain;
class Mempool;

// =============================================================================
// STRATUM V1 SERVER FOR POOL MINING
// Implements standard Stratum protocol for external mining software
// =============================================================================

// Stratum job template
struct StratumJob {
    std::string job_id;
    std::vector<uint8_t> prev_hash;      // 32 bytes
    std::string coinb1;                   // Coinbase part 1 (before extranonce)
    std::string coinb2;                   // Coinbase part 2 (after extranonce)
    std::vector<std::string> merkle_branches;
    uint32_t version;
    uint32_t bits;
    uint32_t time;
    uint64_t height;
    bool clean_jobs;                      // True if new block, clear old jobs

    // PRODUCTION FIX: Store mempool transactions and total fees for proper block building
    std::vector<Transaction> mempool_txs; // Transactions to include in block
    uint64_t total_fees{0};              // Total fees from mempool transactions
};

// Connected miner state
struct StratumMiner {
    StratumSock sock{STRATUM_INVALID_SOCKET};
    std::string ip;
    std::string worker_name;
    std::string extranonce1;              // Unique per connection
    bool authorized{false};
    bool subscribed{false};

    // Difficulty tracking
    double difficulty{1.0};
    double target_difficulty{1.0};
    int64_t shares_submitted{0};
    int64_t shares_accepted{0};
    int64_t shares_rejected{0};

    // Timing
    int64_t connected_ms{0};
    int64_t last_activity_ms{0};
    int64_t last_share_ms{0};

    // Rate limiting
    int64_t shares_window_start{0};
    int shares_in_window{0};

    // Receive buffer
    std::string rx_buffer;

    // Vardiff state
    int64_t vardiff_last_adjust_ms{0};
    int vardiff_shares_since_adjust{0};
};

// Pool statistics
struct PoolStats {
    uint64_t total_shares{0};
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    uint64_t blocks_found{0};
    double pool_hashrate{0.0};
    size_t connected_miners{0};
};

class StratumServer {
public:
    explicit StratumServer(Chain& chain, Mempool& mempool);
    ~StratumServer();

    // Configuration
    void set_port(uint16_t port) { port_ = port; }
    uint16_t get_port() const { return port_; }
    void set_reward_address(const std::vector<uint8_t>& pkh20) { reward_pkh_ = pkh20; }
    void set_extranonce2_size(uint8_t size) { extranonce2_size_ = size; }
    void set_default_difficulty(double diff) { default_difficulty_ = diff; }
    void set_min_difficulty(double diff) { min_difficulty_ = diff; }
    void set_max_difficulty(double diff) { max_difficulty_ = diff; }
    void set_vardiff_enabled(bool enabled) { vardiff_enabled_ = enabled; }
    void set_vardiff_target_time_secs(int secs) { vardiff_target_secs_ = secs; }

    // Control
    bool start();
    void stop();
    bool running() const { return running_; }

    // Stats
    PoolStats get_stats() const;
    size_t miner_count() const;

    // Block notification (call when new block arrives)
    void notify_new_block();

private:
    Chain& chain_;
    Mempool& mempool_;

    // Configuration
    uint16_t port_{3333};
    std::vector<uint8_t> reward_pkh_;
    uint8_t extranonce2_size_{4};
    double default_difficulty_{1.0};
    double min_difficulty_{0.001};
    double max_difficulty_{1000000.0};
    bool vardiff_enabled_{true};
    int vardiff_target_secs_{10};

    // Connection limits
    static constexpr size_t MAX_MINERS = 10000;
    static constexpr size_t MAX_PER_IP = 10;

    // State
    std::atomic<bool> running_{false};
    StratumSock listen_sock_{STRATUM_INVALID_SOCKET};
    std::thread accept_thread_;
    std::thread work_thread_;

    // Miners
    mutable std::mutex miners_mutex_;
    std::unordered_map<StratumSock, StratumMiner> miners_;

    // Jobs
    mutable std::mutex jobs_mutex_;
    std::unordered_map<std::string, StratumJob> jobs_;
    std::deque<std::string> job_order_;
    std::string current_job_id_;
    uint64_t job_counter_{0};

    // Extranonce management
    std::atomic<uint32_t> extranonce_counter_{0};

    // Stats
    mutable std::mutex stats_mutex_;
    PoolStats stats_;

    // Threads
    void accept_loop();
    void work_loop();

    // Miner handling
    void handle_miner_data(StratumMiner& miner);
    void process_message(StratumMiner& miner, const std::string& line);
    void disconnect_miner(StratumSock sock, const std::string& reason);

    // Stratum protocol handlers
    void handle_subscribe(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params);
    void handle_authorize(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params);
    void handle_submit(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params);
    void handle_extranonce_subscribe(StratumMiner& miner, uint64_t id);

    // Job management
    StratumJob create_job();
    void broadcast_job(const StratumJob& job);
    void send_job_to_miner(StratumMiner& miner, const StratumJob& job);
    void cleanup_old_jobs();

    // Share validation
    bool validate_share(StratumMiner& miner, const std::string& job_id,
                        const std::string& extranonce2, const std::string& ntime,
                        const std::string& nonce, std::string& error);
    bool check_pow(const std::vector<uint8_t>& header_hash, uint32_t bits, double difficulty);

    // Vardiff
    void update_vardiff(StratumMiner& miner);
    void send_set_difficulty(StratumMiner& miner, double difficulty);

    // Communication
    bool send_json(StratumMiner& miner, const std::string& json);
    void send_result(StratumMiner& miner, uint64_t id, const std::string& result);
    void send_error(StratumMiner& miner, uint64_t id, int code, const std::string& message);

    // Helpers
    std::string generate_extranonce1();
    std::string generate_job_id();
    static int64_t now_ms();
};

}
