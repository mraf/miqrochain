#pragma once
// PRODUCTION-GRADE P2P NETWORKING - Miqrochain
// Complete drop-in replacement with integrated production features
// Version: 1.0.0-production

#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <queue>
#include <cstdint>
#include <utility>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <chrono>
#include <memory>
#include <functional>
#include <limits>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
  #ifndef socklen_t
    using socklen_t = int;
  #endif
  using Sock = SOCKET;
#else
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <unistd.h>
  using Sock = int;
#endif

#include "mempool.h"

namespace miq {

// Forward declarations
class Chain;
class CircuitBreaker;
class ConnectionPool;
struct HealthMetrics;
struct P2PConfig;

// === Circuit Breaker Pattern ================================================
class CircuitBreaker {
public:
    enum State { CLOSED, OPEN, HALF_OPEN };
    
    explicit CircuitBreaker(size_t threshold = 5, 
                           size_t timeout_ms = 60000,
                           double success_rate = 0.6);
    
    bool allow_request();
    void record_success();
    void record_failure();
    State get_state() const;
    double get_success_rate() const;
    size_t get_failure_count() const { return failure_count_; }
    void reset();
    
private:
    mutable std::mutex mutex_;
    State state_{CLOSED};
    size_t failure_count_{0};
    size_t success_count_{0};
    size_t consecutive_successes_{0};
    std::chrono::steady_clock::time_point last_failure_;
    std::chrono::steady_clock::time_point state_change_time_;
    size_t threshold_;
    size_t timeout_ms_;
    double required_success_rate_;
    std::deque<bool> recent_results_;
    size_t sample_size_{20};
};

// === Health Metrics ==========================================================
struct HealthMetrics {
    double min_latency_ms{std::numeric_limits<double>::max()};
    double max_latency_ms{0};
    double avg_latency_ms{0};
    double jitter_ms{0};
    std::deque<double> latency_samples;
    
    double upload_bps{0};
    double download_bps{0};
    std::atomic<size_t> bytes_sent{0};
    std::atomic<size_t> bytes_received{0};
    
    std::atomic<size_t> successful_requests{0};
    std::atomic<size_t> failed_requests{0};
    double packet_loss_rate{0};
    
    std::chrono::steady_clock::time_point last_check;
    std::chrono::steady_clock::time_point last_activity;
    
    double calculate_health_score() const;
    void update_latency(double latency_ms);
    void update_throughput(size_t bytes, bool upload);
};

// === Configuration ===========================================================
struct P2PConfig {
    size_t max_inbound{125};
    size_t max_outbound{8};
    size_t max_connections{150};
    size_t connection_timeout_ms{5000};
    size_t handshake_timeout_ms{10000};
    size_t idle_timeout_ms{900000};
    
    size_t initial_retry_delay_ms{1000};
    size_t max_retry_delay_ms{300000};
    double retry_backoff_multiplier{2.0};
    size_t max_retry_attempts{10};
    double retry_jitter{0.25};
    
    size_t circuit_breaker_threshold{5};
    size_t circuit_breaker_timeout_ms{60000};
    double circuit_breaker_success_rate{0.6};
    
    size_t health_check_interval_ms{30000};
    double health_score_threshold{0.5};
    
    bool adaptive_rate_limiting{true};
    
    static P2PConfig from_env();
};

// === Hardening knobs ========================================================
#ifndef MIQ_P2P_INV_WINDOW_MS
#define MIQ_P2P_INV_WINDOW_MS 10000
#endif
#ifndef MIQ_P2P_INV_WINDOW_CAP
#define MIQ_P2P_INV_WINDOW_CAP 500
#endif
#ifndef MIQ_P2P_GETADDR_INTERVAL_MS
#define MIQ_P2P_GETADDR_INTERVAL_MS 120000
#endif
#ifndef MIQ_P2P_ADDR_BATCH_CAP
#define MIQ_P2P_ADDR_BATCH_CAP 1000
#endif
#ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
#define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 30
#endif
#ifndef MIQ_P2P_BAN_MS
#define MIQ_P2P_BAN_MS (60LL*60LL*1000LL)
#endif
#ifndef MIQ_P2P_MSG_DEADLINE_MS
#define MIQ_P2P_MSG_DEADLINE_MS 15000
#endif
#ifndef MIQ_P2P_HDR_BATCH_SPACING_MS
#define MIQ_P2P_HDR_BATCH_SPACING_MS 200
#endif
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE 100
#endif

// === Core Data Structures ===================================================
struct OrphanRec {
    std::vector<uint8_t> hash;
    std::vector<uint8_t> prev;
    std::vector<uint8_t> raw;
};

struct RateCounters {
    int64_t last_ms{0};
    std::unordered_map<std::string, double> buckets;
    std::unordered_map<std::string, double> adaptive_limits;
};

struct PeerState {
    // Headers-first
    bool     sent_getheaders{false};
    int64_t  last_headers_ms{0};

    // Socket
#ifdef _WIN32
    Sock     sock{INVALID_SOCKET};
#else
    Sock     sock{-1};
#endif
    std::string ip;

    // Basic tracking
    int         mis{0};
    int64_t     last_ms{0};

    // Sync state
    bool        syncing{false};
    uint64_t    next_index{0};
    uint32_t    inflight_index{0};

    // RX buffer & liveness
    std::vector<uint8_t> rx;
    bool        verack_ok{false};
    int64_t     last_ping_ms{0};
    bool        awaiting_pong{false};
    int         banscore{0};

    // Rate limiting
    uint64_t    blk_tokens{0};
    uint64_t    tx_tokens{0};
    int64_t     last_refill_ms{0};

    // Address throttling
    int64_t     last_addr_ms{0};

    // TX relay
    std::unordered_set<std::string> inflight_tx;

    // Block/header tracking
    std::unordered_set<std::string> inflight_blocks;
    int                              inflight_hdr_batches{0};
    int64_t                          last_hdr_batch_done_ms{0};

    // Version & features
    uint32_t    version{0};
    uint64_t    features{0};
    bool        whitelisted{false};

    // INV/ADDR throttling
    int64_t     inv_win_start_ms{0};
    uint32_t    inv_in_window{0};
    int64_t     last_getaddr_ms{0};
    std::unordered_set<std::string> recent_inv_keys;

    // Rate counters
    RateCounters rate;

    // Reputation & adaptive batching
    int64_t blocks_delivered_successfully{0};
    int64_t blocks_failed_delivery{0};
    int64_t total_blocks_received{0};
    int64_t total_block_bytes_received{0};
    int64_t total_block_delivery_time_ms{0};
    double reputation_score{1.0};
    double health_score{1.0};

    uint32_t adaptive_batch_size{16};
    int64_t last_batch_completion_ms{0};
    int64_t last_batch_duration_ms{0};

    int64_t avg_block_delivery_ms{30000};

    // Connection quality
    int64_t last_activity_ms{0};
    uint32_t blocks_served{0};
    uint32_t headers_served{0};
    int64_t connected_ms{0};
    int64_t last_useful_ms{0};
    uint32_t blocks_sent{0};
    uint32_t blocks_received{0};
    uint32_t headers_received{0};
    bool is_syncing{false};
    std::vector<uint8_t> best_known_tip;
    int64_t max_timeout_ms{60000};
    int64_t last_block_received_ms{0};

    int64_t connection_failures{0};
    int64_t next_retry_ms{0};

    uint64_t peer_tip_height{0};
    
    // PRODUCTION: Enhanced fields
    std::string peer_id;
    std::shared_ptr<CircuitBreaker> circuit_breaker;
    HealthMetrics health_metrics;
    std::chrono::steady_clock::time_point connected_at;
    std::atomic<bool> is_closing{false};
    
    enum ConnectionState {
        CONNECTING, HANDSHAKING, CONNECTED, DISCONNECTING, DISCONNECTED
    } connection_state{CONNECTING};
    
    size_t retry_count{0};
    std::atomic<size_t> invalid_message_count{0};
    std::atomic<size_t> protocol_violation_count{0};
};

struct PeerSnapshot {
    std::string  ip;
    bool         verack_ok;
    bool         awaiting_pong;
    int          mis;
    uint64_t     next_index;
    bool         syncing;
    double       last_seen_ms;
    uint64_t     blk_tokens;
    uint64_t     tx_tokens;
    size_t       rx_buf;
    size_t       inflight;
    uint64_t     peer_tip;
    std::string  peer_id;
    double       health_score_val;
};

// === Main P2P Class ==========================================================
class P2P {
public:
    explicit P2P(Chain& c);
    ~P2P();

    // Mempool hookup
    inline void set_mempool(Mempool* mp) { mempool_ = mp; }
    inline Mempool*       mempool()       { return mempool_; }
    inline const Mempool* mempool() const { return mempool_; }

    // Rate checking
    bool check_rate(PeerState& ps, const char* key);
    bool check_rate(PeerState& ps, const char* family, const char* name,
                    uint32_t burst, uint32_t window_ms);
    bool check_rate(PeerState& ps, const char* family, double cost, int64_t now_ms);

    // Core operations
    bool start(uint16_t port);
    void stop();
    bool connect_seed(const std::string& host, uint16_t port);

    // Broadcasting
    void announce_block_async(const std::vector<uint8_t>& h);
    void broadcast_inv_block(const std::vector<uint8_t>& h);
    void broadcast_inv_tx(const std::vector<uint8_t>& txid);

    // Configuration
    inline void set_datadir(const std::string& d) { datadir_ = d; }
    std::string hexkey(const std::vector<uint8_t>& h);

    // Stats
    size_t connection_count() const { return peers_.size(); }
    std::vector<PeerSnapshot> snapshot_peers() const;

    // Tuning
    struct InflightCaps { size_t max_txs{256}; size_t max_blocks{256}; };
    inline void set_inflight_caps(size_t max_txs, size_t max_blocks) {
        caps_.max_txs = max_txs;
        caps_.max_blocks = max_blocks;
    }
    inline void set_min_peer_version(uint32_t v) { min_peer_version_ = v; }
    inline void set_feature_required(uint64_t mask) { required_features_mask_ = mask; }
    inline void set_msg_deadlines_ms(int64_t ms) { msg_deadline_ms_ = ms; }

    // Whitelist
    inline void set_whitelist(const std::vector<std::string>& entries) {
        whitelist_ips_.clear();
        whitelist_cidrs_.clear();
        for (const auto& e : entries) {
            auto slash = e.find('/');
            if (slash == std::string::npos) {
                whitelist_ips_.insert(e);
            } else {
                std::string host = e.substr(0, slash);
                std::string bits = e.substr(slash+1);
                uint32_t be_ip = 0;
                if (!parse_ipv4(host, be_ip)) continue;
                int b = 0;
                for (char ch : bits) { 
                    if (ch<'0'||ch>'9'){ b=-1; break; } 
                    b = b*10 + (ch-'0'); 
                }
                if (b < 0 || b > 32) continue;
                uint32_t ip_host = ntohl(be_ip);
                struct Cidr c;
                c.bits = (uint8_t)b;
                c.net = (b==0) ? 0u : (ip_host & (~uint32_t(0) << (32-b)));
                whitelist_cidrs_.push_back(c);
            }
        }
    }
    
    // PRODUCTION: Configuration & health
    void set_config(const P2PConfig& config) { config_ = config; }
    const P2PConfig& get_config() const { return config_; }
    HealthMetrics get_network_health() const;

private:
    // TX relay
    void request_tx(PeerState& ps, const std::vector<uint8_t>& txid);
    void send_tx(Sock sock, const std::vector<uint8_t>& raw);
    void send_block(Sock s, const std::vector<uint8_t>& raw);

    // Caches
    mutable std::mutex announce_mu_;
    std::vector<std::vector<uint8_t>> announce_blocks_q_;
    mutable std::mutex announce_tx_mu_;
    std::vector<std::vector<uint8_t>> announce_tx_q_;
    std::unordered_set<std::string> seen_txids_;
    std::unordered_map<std::string, std::vector<uint8_t>> tx_store_;
    std::deque<std::string> tx_order_;

    // Core members
    Mempool* mempool_{nullptr};
    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
#ifdef _WIN32
    Sock srv_{INVALID_SOCKET};
#else
    Sock srv_{-1};
#endif
    std::unordered_map<Sock, PeerState> peers_;
    std::unordered_set<std::string> banned_;
    std::string datadir_{"./miqdata"};

    // Address manager
    std::unordered_set<uint32_t> addrv4_;

    // Orphan manager
    std::unordered_map<std::string, OrphanRec> orphans_;
    std::unordered_map<std::string, std::vector<std::string>> orphan_children_;
    std::deque<std::string> orphan_order_;
    size_t orphan_bytes_{0};
    size_t orphan_bytes_limit_{0};
    size_t orphan_count_limit_{0};

    // Rate gating
    int64_t  inbound_win_start_ms_{0};
    uint32_t inbound_accepts_in_window_{0};

    // Bans & whitelist
    std::unordered_map<std::string,int64_t> timed_bans_;
    int64_t  default_ban_ms_{MIQ_P2P_BAN_MS};
    uint32_t min_peer_version_{0};
    uint64_t required_features_mask_{0};
    int64_t  msg_deadline_ms_{MIQ_P2P_MSG_DEADLINE_MS};

    struct Cidr { uint32_t net; uint8_t bits; };
    std::unordered_set<std::string> whitelist_ips_;
    std::vector<Cidr> whitelist_cidrs_;

    // Rate config
    struct FamilyRate { double per_sec; double burst; };
    std::unordered_map<std::string, FamilyRate> rate_cfg_{
        {"get",  {20.0,  40.0}},
        {"inv",  {100.0, 200.0}},
        {"addr", {1.0,   2.0}},
    };

    InflightCaps caps_{};

    // PRODUCTION: Enhanced members
    P2PConfig config_;
    mutable std::mutex circuit_breakers_mutex_;
    std::unordered_map<std::string, std::shared_ptr<CircuitBreaker>> circuit_breakers_;
    std::thread health_monitor_thread_;
    std::atomic<bool> health_monitor_running_{false};
    
    struct NetworkMetrics {
        std::atomic<size_t> total_bytes_sent{0};
        std::atomic<size_t> total_bytes_received{0};
        std::atomic<size_t> total_connections{0};
        std::atomic<size_t> failed_connections{0};
        std::atomic<size_t> active_connections{0};
        std::chrono::steady_clock::time_point start_time;
    } metrics_;

    // Core functions
    void loop();
    void handle_new_peer(Sock c, const std::string& ip);
    void load_bans();
    void save_bans();
    void bump_ban(PeerState& ps, const std::string& ip, const char* reason, int64_t now_ms);

    // Sync & blocks
    void start_sync_with_peer(PeerState& ps);
    void request_block_index(PeerState& ps, uint64_t index);
    void fill_index_pipeline(PeerState& ps);
    void request_block_hash(PeerState& ps, const std::vector<uint8_t>& h);
    void handle_incoming_block(Sock sock, const std::vector<uint8_t>& raw);

    // Rate limiting
    void rate_refill(PeerState& ps, int64_t now);
    bool rate_consume_block(PeerState& ps, size_t nbytes);
    bool rate_consume_tx(PeerState& ps, size_t nbytes);

    // Address handling
    void maybe_send_getaddr(PeerState& ps);
    void send_addr_snapshot(PeerState& ps);
    void handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload);

    // IPv4 helpers
    bool parse_ipv4(const std::string& dotted, uint32_t& be_ip);
    bool ipv4_is_public(uint32_t be_ip);

    // Orphan handlers
    void evict_orphans_if_needed();
    void remove_orphan_by_hex(const std::string& child_hex);
    void try_connect_orphans(const std::string& parent_hex);

    // PRODUCTION: Enhanced functions
    void health_monitor_loop();
    void check_peer_health(PeerState& ps);
    void handle_unhealthy_peer(PeerState& ps);
    bool should_reconnect(const PeerState& ps) const;
    void graceful_disconnect(Sock s, const std::string& reason);
    void flush_peer_send_queue(PeerState& ps);
    void schedule_reconnection(const std::string& ip, uint16_t port, size_t delay_ms);
    std::shared_ptr<CircuitBreaker> get_circuit_breaker(const std::string& endpoint);
    bool validate_message(const std::string& cmd, const std::vector<uint8_t>& payload);
    bool check_adaptive_rate_limit(PeerState& ps, const std::string& cmd);
    void check_stalled_connections();
    std::string generate_peer_id();

    // Inline helpers
    inline bool is_ip_banned(const std::string& ip, int64_t now_ms) const {
        if (is_loopback(ip) || is_whitelisted_ip(ip)) return false;
        auto it = timed_bans_.find(ip);
        if (it != timed_bans_.end()) {
            if (it->second > now_ms) return true;
        }
        return banned_.count(ip) != 0;
    }

    inline bool is_loopback(const std::string& ip) const {
        return ip.rfind("127.", 0) == 0;
    }

    inline bool is_whitelisted_ip(const std::string& ip) const {
        if (whitelist_ips_.count(ip)) return true;
        sockaddr_in tmp{};
    #ifdef _WIN32
        if (InetPtonA(AF_INET, ip.c_str(), &tmp.sin_addr) != 1) return false;
    #else
        if (inet_pton(AF_INET, ip.c_str(), &tmp.sin_addr) != 1) return false;
    #endif
        uint32_t host_ip = ntohl(tmp.sin_addr.s_addr);
        for (const auto& c : whitelist_cidrs_) {
            if (c.bits == 0) return true;
            uint32_t mask = (c.bits==0) ? 0u : (~uint32_t(0) << (32 - c.bits));
            if ((host_ip & mask) == (c.net & mask)) return true;
        }
        return false;
    }

    inline bool unsolicited_drop(PeerState& ps, const char* kind, const std::string& key) {
        if (!kind) return false;
        if (ps.whitelisted) return false;

        if (std::string(kind) == "tx") {
            if (!key.empty() && ps.inflight_tx.count(key)) return false;
            if (!key.empty() && ps.recent_inv_keys.count(key)) return false;
            return true;
        }
        if (std::string(kind) == "block") {
            if (!key.empty() && ps.inflight_blocks.count(key)) return false;
            if (!key.empty() && ps.recent_inv_keys.count(key)) return false;
            return true;
        }
        if (std::string(kind) == "headers") {
            return ps.inflight_hdr_batches == 0 && !ps.sent_getheaders;
        }
        return false;
    }

    inline bool can_accept_hdr_batch(const PeerState& ps, int64_t now_ms) const {
        if (ps.inflight_hdr_batches >= 2) return false;
        if (now_ms - ps.last_hdr_batch_done_ms < MIQ_P2P_HDR_BATCH_SPACING_MS) return false;
        return true;
    }
};

}
