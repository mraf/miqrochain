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
#include <map>
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
// STRATUM V1 SERVER FOR POOL MINING WITH PROPORTIONAL PAYOUTS
// Implements standard Stratum protocol with PPLNS-style reward distribution
// =============================================================================

// =============================================================================
// POOL PAYOUT SYSTEM - Proportional reward distribution based on hashpower
// =============================================================================

// Miner account for tracking balances and contributions
struct MinerAccount {
    std::string address;                  // Base58check payout address
    std::vector<uint8_t> pkh;             // 20-byte public key hash
    uint64_t balance{0};                  // Pending payout balance (in base units)
    uint64_t total_paid{0};               // Total amount paid out historically
    uint64_t lifetime_shares{0};          // Total shares submitted (for stats)
    double current_round_work{0.0};       // Difficulty-weighted work this round
    int64_t last_share_ms{0};             // Last share timestamp
    int64_t created_ms{0};                // Account creation time
};

// Share record for PPLNS window (Pay Per Last N Shares)
struct ShareRecord {
    std::string miner_address;            // Which miner submitted this share
    double difficulty;                    // Share difficulty (weighted contribution)
    int64_t timestamp_ms;                 // When share was submitted
};

// Payout record for history/auditing
struct PayoutRecord {
    std::string txid;                     // Transaction ID of payout
    std::string address;                  // Recipient address
    uint64_t amount;                      // Amount paid
    int64_t timestamp_ms;                 // When payout was created
    uint64_t block_height;                // Block height when payout confirmed
    bool confirmed{false};                // Whether payout tx is confirmed
};

// Pool configuration for payouts
struct PoolPayoutConfig {
    double pool_fee_percent{1.0};         // Pool operator fee (default 1%)
    uint64_t min_payout{1000000};         // Minimum payout threshold (0.01 MIQ = 1M base units)
    uint64_t payout_interval_ms{3600000}; // Check payouts every hour
    size_t pplns_window_size{10000};      // PPLNS window: last N shares
    bool auto_payout{true};               // Automatic payouts when threshold reached
    std::vector<uint8_t> fee_address_pkh; // Pool fee recipient (20 bytes)
};

// Coinbase payout output (for direct-to-miner payments)
struct CoinbaseOutput {
    std::string address;           // Base58check address (for stats tracking)
    std::vector<uint8_t> pkh;      // 20-byte PKH for the output
    uint64_t amount;               // Amount in base units
    bool is_pool_fee{false};       // True if this is pool operator fee
};

// Stratum job template
struct StratumJob {
    std::string job_id;
    std::vector<uint8_t> prev_hash;      // 32 bytes
    std::string coinb1;                   // Coinbase part 1 (before extranonce)
    std::string coinb2;                   // Coinbase part 2 (after extranonce)
    std::vector<std::string> merkle_branches;
    uint32_t version;
    uint32_t bits;
    uint64_t time;  // MIQ uses 64-bit timestamps
    uint64_t height;
    bool clean_jobs;                      // True if new block, clear old jobs

    // PRODUCTION FIX: Store mempool transactions and total fees for proper block building
    std::vector<Transaction> mempool_txs; // Transactions to include in block
    uint64_t total_fees{0};              // Total fees from mempool transactions

    // DIRECT COINBASE PAYOUTS: Output distribution calculated at job creation
    // Each miner gets paid directly in the coinbase based on their PPLNS share
    std::vector<CoinbaseOutput> coinbase_outputs;  // All outputs in coinbase
    uint64_t total_reward{0};                      // Total block reward (subsidy + fees)
};

// Connected miner state
struct StratumMiner {
    StratumSock sock{STRATUM_INVALID_SOCKET};
    std::string ip;
    std::string worker_name;
    std::string extranonce1;              // Unique per connection
    bool authorized{false};
    bool subscribed{false};
    bool pending_disconnect{false};       // CRITICAL FIX: Mark miner for disconnect after send failure

    // Payout system: miner's payout address (extracted from worker_name)
    std::string payout_address;           // Base58check address for payouts
    std::vector<uint8_t> payout_pkh;      // 20-byte PKH for this miner

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

// Pool statistics (extended for payout system)
struct PoolStats {
    uint64_t total_shares{0};
    uint64_t accepted_shares{0};
    uint64_t rejected_shares{0};
    uint64_t blocks_found{0};
    double pool_hashrate{0.0};
    size_t connected_miners{0};

    // Payout system stats
    uint64_t total_rewards_distributed{0};  // Total MIQ distributed to miners
    uint64_t total_fees_collected{0};       // Total pool fees collected
    uint64_t pending_payouts{0};            // Total pending in miner balances
    size_t registered_miners{0};            // Total unique miner accounts
    uint64_t payouts_sent{0};               // Number of payout transactions sent
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

    // Payout configuration
    void set_pool_fee(double percent) { payout_config_.pool_fee_percent = percent; }
    void set_min_payout(uint64_t amount) { payout_config_.min_payout = amount; }
    void set_auto_payout(bool enabled) { payout_config_.auto_payout = enabled; }
    void set_fee_address(const std::vector<uint8_t>& pkh20) { payout_config_.fee_address_pkh = pkh20; }
    void set_pplns_window(size_t shares) { payout_config_.pplns_window_size = shares; }
    void set_data_dir(const std::string& dir) { data_dir_ = dir; }

    // Control
    bool start();
    void stop();
    bool running() const { return running_; }

    // Stats
    PoolStats get_stats() const;
    size_t miner_count() const;

    // Block notification (call when new block arrives)
    void notify_new_block();

    // Payout system public interface
    MinerAccount* get_miner_account(const std::string& address);
    std::vector<MinerAccount> get_all_accounts() const;
    uint64_t get_miner_balance(const std::string& address) const;
    bool trigger_manual_payout(const std::string& address, std::string& error);

private:
    Chain& chain_;
    Mempool& mempool_;

    // Configuration
    uint16_t port_{3333};
    std::vector<uint8_t> reward_pkh_;       // Pool's hot wallet for coinbase (receives all, then distributes)
    uint8_t extranonce2_size_{4};
    double default_difficulty_{1.0};
    double min_difficulty_{0.001};
    double max_difficulty_{1000000.0};
    bool vardiff_enabled_{true};
    int vardiff_target_secs_{10};
    std::string data_dir_;                  // Data directory for persistence

    // Payout configuration
    PoolPayoutConfig payout_config_;

    // Connection limits
    static constexpr size_t MAX_MINERS = 10000;
    static constexpr size_t MAX_PER_IP = 10;

    // State
    std::atomic<bool> running_{false};
    StratumSock listen_sock_{STRATUM_INVALID_SOCKET};
    std::thread accept_thread_;
    std::thread work_thread_;
    std::thread payout_thread_;             // Payout processing thread

    // Miners (active connections)
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

    // ==========================================================================
    // PAYOUT SYSTEM STATE
    // ==========================================================================

    // Miner accounts (keyed by base58 address)
    mutable std::mutex accounts_mutex_;
    std::map<std::string, MinerAccount> miner_accounts_;

    // PPLNS share window (circular buffer of recent shares)
    mutable std::mutex shares_mutex_;
    std::deque<ShareRecord> pplns_shares_;
    double total_round_work_{0.0};          // Sum of all share difficulties this round

    // Payout history
    mutable std::mutex payouts_mutex_;
    std::deque<PayoutRecord> payout_history_;
    int64_t last_payout_check_ms_{0};

    // Persistence
    bool dirty_accounts_{false};            // Flag for save-on-change
    int64_t last_save_ms_{0};

    // ==========================================================================
    // THREADS
    // ==========================================================================
    void accept_loop();
    void work_loop();
    void payout_loop();                     // Background payout processing

    // ==========================================================================
    // MINER HANDLING
    // ==========================================================================
    void handle_miner_data(StratumMiner& miner);
    void process_message(StratumMiner& miner, const std::string& line);
    void disconnect_miner(StratumSock sock, const std::string& reason);

    // Stratum protocol handlers
    void handle_subscribe(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params);
    void handle_authorize(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params);
    void handle_submit(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params);
    void handle_extranonce_subscribe(StratumMiner& miner, uint64_t id);

    // ==========================================================================
    // JOB MANAGEMENT
    // ==========================================================================
    StratumJob create_job();
    void broadcast_job(const StratumJob& job);
    bool send_job_to_miner(StratumMiner& miner, const StratumJob& job);
    void cleanup_old_jobs();

    // ==========================================================================
    // SHARE VALIDATION
    // ==========================================================================
    bool validate_share(StratumMiner& miner, const std::string& job_id,
                        const std::string& extranonce2, const std::string& ntime,
                        const std::string& nonce, std::string& error);
    bool check_pow(const std::vector<uint8_t>& header_hash, uint32_t bits, double difficulty);

    // ==========================================================================
    // PAYOUT SYSTEM IMPLEMENTATION
    // ==========================================================================

    // Account management
    MinerAccount& get_or_create_account(const std::string& address, const std::vector<uint8_t>& pkh);

    // Share tracking (PPLNS)
    void record_share(const std::string& miner_address, double difficulty);
    void trim_pplns_window();

    // Reward distribution (called when block found)
    void distribute_block_reward(uint64_t block_reward, uint64_t block_height);

    // Payout processing
    void process_pending_payouts();
    bool create_payout_transaction(const std::string& address, uint64_t amount, std::string& txid, std::string& error);

    // Persistence
    bool save_accounts();
    bool load_accounts();
    std::string get_accounts_file_path() const;

    // ==========================================================================
    // VARDIFF
    // ==========================================================================
    void update_vardiff(StratumMiner& miner);
    bool send_set_difficulty(StratumMiner& miner, double difficulty);

    // ==========================================================================
    // COMMUNICATION
    // ==========================================================================
    bool send_json(StratumMiner& miner, const std::string& json);
    bool send_result(StratumMiner& miner, uint64_t id, const std::string& result);
    bool send_error(StratumMiner& miner, uint64_t id, int code, const std::string& message);

    // ==========================================================================
    // HELPERS
    // ==========================================================================
    std::string generate_extranonce1();
    std::string generate_job_id();
    static int64_t now_ms();
};

}
