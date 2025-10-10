#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <cstdint>
#include <utility>
#include <mutex>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <BaseTsd.h>
  typedef SSIZE_T ssize_t;
  #ifndef socklen_t
    using socklen_t = int;
  #endif
#else
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <unistd.h>
#endif

#include "mempool.h"

namespace miq {

// === Optional hardening knobs (can be overridden at compile time) ============
#ifndef MIQ_P2P_INV_WINDOW_MS
#define MIQ_P2P_INV_WINDOW_MS 10000   // window for INV rate checks (must match .cpp)
#endif
#ifndef MIQ_P2P_INV_WINDOW_CAP
#define MIQ_P2P_INV_WINDOW_CAP 500    // max INVs accepted per window per peer (match .cpp)
#endif
#ifndef MIQ_P2P_GETADDR_INTERVAL_MS
#define MIQ_P2P_GETADDR_INTERVAL_MS 120000  // throttle our getaddr requests per peer
#endif
#ifndef MIQ_P2P_ADDR_BATCH_CAP
#define MIQ_P2P_ADDR_BATCH_CAP 1000   // max addrs we accept per addr message
#endif
#ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
#define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 60 // soft cap: new inbound per minute
#endif
#ifndef MIQ_P2P_BAN_MS
#define MIQ_P2P_BAN_MS (60LL*60LL*1000LL)  // 1 hour timed ban by default
#endif
#ifndef MIQ_P2P_MSG_DEADLINE_MS
#define MIQ_P2P_MSG_DEADLINE_MS 15000      // partial-frame parse timeout (slowloris guard)
#endif
#ifndef MIQ_P2P_HDR_BATCH_SPACING_MS
#define MIQ_P2P_HDR_BATCH_SPACING_MS 200   // min spacing between header batches from a peer
#endif
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE 100           // keep in sync with p2p.cpp
#endif

class Chain; // fwd

struct OrphanRec {
    std::vector<uint8_t> hash;
    std::vector<uint8_t> prev;
    std::vector<uint8_t> raw;
};

// ---- Per-peer, lightweight rate counters (token buckets by "family") -------
struct RateCounters {
    int64_t last_ms{0};
    // family -> tokens
    std::unordered_map<std::string, double> buckets;
};

struct PeerState {
    // headers-first (reserved/current use)
    bool     sent_getheaders{false};
    int64_t  last_headers_ms{0};

    // identity/socket
    int         sock{-1};
    std::string ip;

    // misc tracking
    int         mis{0};
    int64_t     last_ms{0};

    // sync
    bool        syncing{false};
    uint64_t    next_index{0};

    // per-peer RX buffer & liveness
    std::vector<uint8_t> rx;
    bool        verack_ok{false};
    int64_t     last_ping_ms{0};
    bool        awaiting_pong{false};
    int         banscore{0};

    // rate-limit tokens
    uint64_t    blk_tokens{0};
    uint64_t    tx_tokens{0};
    int64_t     last_refill_ms{0};

    // addr throttling
    int64_t     last_addr_ms{0};

    // tx relay: which txids we’ve requested and await
    std::unordered_set<std::string> inflight_tx;

    // --- New: block/header inflight tracking --------------------------------
    std::unordered_set<std::string> inflight_blocks; // keys are hex block-hash
    int                              inflight_hdr_batches{0};
    int64_t                          last_hdr_batch_done_ms{0};

    // --- New: version/features gating & whitelist flags ---------------------
    uint32_t    version{0};
    uint64_t    features{0};
    bool        whitelisted{false};

    // --- New: INV/ADDR throttling state (DoS hardening) --------------------
    // Rolling INV window (basic storm damping)
    int64_t     inv_win_start_ms{0};
    uint32_t    inv_in_window{0};

    // throttle how often we send getaddr to this peer
    int64_t     last_getaddr_ms{0};

    // Per-peer duplicate INV suppression (keys are hex txid/block-hash)
    std::unordered_set<std::string> recent_inv_keys;

    // Per-family lightweight token buckets
    RateCounters rate;
};

// Lightweight read-only snapshot for RPC/UI
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
};

class P2P {
public:
    explicit P2P(Chain& c);
    ~P2P();

    // Optional mempool hookup (nullable = tx relay disabled but node runs fine)
    inline void set_mempool(Mempool* mp) { mempool_ = mp; }
    inline Mempool*       mempool()       { return mempool_; }
    inline const Mempool* mempool() const { return mempool_; }

    // key-based helper ("invb","getb", etc.)
    bool check_rate(PeerState& ps, const char* key);

    // explicit family:name burst/window helper (implemented in .cpp)
    bool check_rate(PeerState& ps,
                    const char* family,
                    const char* name,
                    uint32_t burst,
                    uint32_t window_ms);

    bool start(uint16_t port);
    void stop();

    // Outbound connect to a seed (hostname or IP)
    bool connect_seed(const std::string& host, uint16_t port);

    // Broadcast inventory for a new block/tx we just accepted/mined
    void announce_block_async(const std::vector<uint8_t>& block_hash);
    void broadcast_inv_block(const std::vector<uint8_t>& block_hash);
    void broadcast_inv_tx(const std::vector<uint8_t>& txid);

    // Optional: where to store bans.txt and peers.dat
    inline void set_datadir(const std::string& d) { datadir_ = d; }

    // tiny, local and fast hex for keys
    std::string hexkey(const std::vector<uint8_t>& h);

    // Read-only stats for RPC/UI
    size_t connection_count() const { return peers_.size(); }
    std::vector<PeerSnapshot> snapshot_peers() const;

    // ---- New runtime tuning knobs (inline; no .cpp changes needed) ----------
    struct InflightCaps { size_t max_txs{64}; size_t max_blocks{16}; };

    inline void set_inflight_caps(size_t max_txs, size_t max_blocks) {
        caps_.max_txs   = max_txs;
        caps_.max_blocks= max_blocks;
    }
    inline void set_min_peer_version(uint32_t v) { min_peer_version_ = v; }
    inline void set_feature_required(uint64_t mask) { required_features_mask_ = mask; }
    inline void set_msg_deadlines_ms(int64_t ms) { msg_deadline_ms_ = ms; }

    // Whitelist setter: entries can be single IPv4 (e.g., "127.0.0.1")
    // or CIDR (e.g., "192.168.1.0/24"). Non-parsable entries are ignored.
    inline void set_whitelist(const std::vector<std::string>& entries) {
        whitelist_ips_.clear();
        whitelist_cidrs_.clear();
        for (const auto& e : entries) {
            auto slash = e.find('/');
            if (slash == std::string::npos) {
                // single IP
                whitelist_ips_.insert(e);
            } else {
                // CIDR
                std::string host = e.substr(0, slash);
                std::string bits = e.substr(slash+1);
                uint32_t be_ip = 0;
                if (!parse_ipv4(host, be_ip)) continue;
                int b = 0;
                for (char ch : bits) { if (ch<'0'||ch>'9'){ b=-1; break; } b = b*10 + (ch-'0'); }
                if (b < 0 || b > 32) continue;
                uint32_t ip_host = ntohl(be_ip); // to host order for masking math
                Cidr c;
                c.bits = (uint8_t)b;
                c.net  = (b==0) ? 0u : (ip_host & (~uint32_t(0) << (32-b)));
                whitelist_cidrs_.push_back(c);
            }
        }
    }

private:
    // ---- headers-first helpers (declared for completeness; not used directly) ----
    void send_getheaders(PeerState& ps);
    void send_headers_snapshot(PeerState& ps, const std::vector<std::vector<uint8_t>>& locator);

    // ---- tx relay (basic) ----
    void request_tx(PeerState& ps, const std::vector<uint8_t>& txid);
    void send_tx(int sock, const std::vector<uint8_t>& raw);

    // Small, bounded caches (in-memory)
    std::mutex announce_mu_;
    std::vector<std::vector<uint8_t>> announce_blocks_q_;
    std::unordered_set<std::string> seen_txids_;
    std::unordered_map<std::string, std::vector<uint8_t>> tx_store_;
    std::deque<std::string> tx_order_; // for eviction

    Mempool* mempool_{nullptr};  // nullable, safe to run without
    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
    int srv_{-1};
    std::unordered_map<int, PeerState> peers_;
    std::unordered_set<std::string> banned_; // legacy flat ban list (bans.txt)
    std::string datadir_{"./miqdata"};

    // address manager: IPv4s in network byte order
    std::unordered_set<uint32_t> addrv4_;

    // orphan manager
    std::unordered_map<std::string, OrphanRec> orphans_;
    std::unordered_map<std::string, std::vector<std::string>> orphan_children_;
    std::deque<std::string> orphan_order_;
    size_t orphan_bytes_{0};
    size_t orphan_bytes_limit_{0};
    size_t orphan_count_limit_{0};

    // Inbound rate gating (soft Sybil friction)
    int64_t  inbound_win_start_ms_{0};     // NOTE: underscore to match p2p.cpp
    uint32_t inbound_accepts_in_window_{0};

    // --- New: timed bans + whitelist + feature gates -------------------------
    std::unordered_map<std::string,int64_t> timed_bans_; // ip -> expiry_ms
    int64_t  default_ban_ms_{MIQ_P2P_BAN_MS};
    uint32_t min_peer_version_{0};
    uint64_t required_features_mask_{0};
    int64_t  msg_deadline_ms_{MIQ_P2P_MSG_DEADLINE_MS};

    struct Cidr { uint32_t net; uint8_t bits; };
    std::unordered_set<std::string> whitelist_ips_;
    std::vector<Cidr>               whitelist_cidrs_;

    // --- New: per-family lightweight pacing config ---------------------------
    struct FamilyRate { double per_sec; double burst; };
    std::unordered_map<std::string, FamilyRate> rate_cfg_{
        {"get",  {5.0,   10.0}},  // pings/get* and getheaders
        {"inv",  {100.0, 200.0}}, // inv/announcements
        {"addr", {1.0,   2.0}},   // addr/addr sends
    };

    InflightCaps caps_{};

    // core
    void loop();
    void handle_new_peer(int c, const std::string& ip);
    void load_bans();
    void save_bans();

    // helpers for sync & block serving
    void start_sync_with_peer(PeerState& ps);
    void request_block_index(PeerState& ps, uint64_t index);
    void request_block_hash(PeerState& ps, const std::vector<uint8_t>& h);
    void send_block(int s, const std::vector<uint8_t>& raw);

    // rate-limit helpers
    void rate_refill(PeerState& ps, int64_t now);
    bool rate_consume_block(PeerState& ps, size_t nbytes);
    bool rate_consume_tx(PeerState& ps, size_t nbytes);

    // addr handling
    void maybe_send_getaddr(PeerState& ps);
    void send_addr_snapshot(PeerState& ps);
    void handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload);

    // IPv4 helpers
    bool parse_ipv4(const std::string& dotted, uint32_t& be_ip);
    bool ipv4_is_public(uint32_t be_ip);

    // orphan handlers
    void evict_orphans_if_needed();
    void remove_orphan_by_hex(const std::string& child_hex);
    void handle_incoming_block(int sock, const std::vector<uint8_t>& raw);
    void try_connect_orphans(const std::string& parent_hex);

    // ================== Inline helpers required by p2p.cpp ===================

    // Very small token-bucket helper; "cost" is the tokens to spend.
    inline bool check_rate(PeerState& ps, const char* family, double cost, int64_t now_ms) {
        if (!family || cost <= 0.0) return true;
        auto it_cfg = rate_cfg_.find(family);
        if (it_cfg == rate_cfg_.end()) return true; // unspecified -> allow
        auto& cfg = it_cfg->second;

        // Initialize bucket lazily to full burst
        auto& bmap = ps.rate.buckets;
        auto it_b  = bmap.find(family);
        if (it_b == bmap.end()) it_b = bmap.emplace(family, cfg.burst).first;

        // Refill by elapsed time
        if (ps.rate.last_ms == 0) ps.rate.last_ms = now_ms;
        int64_t dt = now_ms - ps.rate.last_ms;
        if (dt > 0) {
            double add = cfg.per_sec * (double)dt / 1000.0;
            it_b->second = (it_b->second + add);
            if (it_b->second > cfg.burst) it_b->second = cfg.burst;
            ps.rate.last_ms = now_ms;
        }

        if (it_b->second + 1e-9 < cost) return false; // not enough tokens
        it_b->second -= cost;
        return true;
    }

    // ---- CHANGED: never time-ban loopback or whitelisted peers --------------
    inline void bump_ban(PeerState& ps, const std::string& ip, const char* /*reason*/, int64_t now_ms) {
        if (is_loopback(ip) || is_whitelisted_ip(ip)) {
            if (ps.banscore < 0) ps.banscore = 0;
            return; // no timed ban for loopback/whitelisted
        }
        if (ps.banscore < 0) ps.banscore = 0;
        if (ps.banscore >= MIQ_P2P_MAX_BANSCORE) {
            timed_bans_[ip] = now_ms + default_ban_ms_;
        }
    }

    // ---- CHANGED: loopback/whitelisted are never considered banned ----------
    inline bool is_ip_banned(const std::string& ip, int64_t now_ms) const {
        if (is_loopback(ip) || is_whitelisted_ip(ip)) return false;

        auto it = timed_bans_.find(ip);
        if (it != timed_bans_.end()) {
            if (it->second > now_ms) return true;
        }
        // legacy flat list (ignore loopback handled above)
        return banned_.count(ip) != 0;
    }

    inline bool is_loopback(const std::string& ip) const {
        // crude but fine for IPv4
        return ip.rfind("127.", 0) == 0;
    }

    inline bool is_whitelisted_ip(const std::string& ip) const {
        if (whitelist_ips_.count(ip)) return true;
        // CIDR check (IPv4 only)
        sockaddr_in tmp{};
    #ifdef _WIN32
        if (InetPtonA(AF_INET, ip.c_str(), &tmp.sin_addr) != 1) return false;
    #else
        if (inet_pton(AF_INET, ip.c_str(), &tmp.sin_addr) != 1) return false;
    #endif
        uint32_t host_ip = ntohl(tmp.sin_addr.s_addr);
        for (const auto& c : whitelist_cidrs_) {
            if (c.bits == 0) return true; // 0.0.0.0/0
            uint32_t mask = (c.bits==0) ? 0u : (~uint32_t(0) << (32 - c.bits));
            if ((host_ip & mask) == (c.net & mask)) return true;
        }
        return false;
    }

    inline bool unsolicited_drop(PeerState& ps, const char* kind, const std::string& key) {
        if (!kind) return false;
        // Whitelisted peers bypass unsolicited checks
        if (ps.whitelisted) return false;

        if (std::string(kind) == "tx") {
            if (!key.empty() && ps.inflight_tx.count(key)) return false;
            if (!key.empty() && ps.recent_inv_keys.count(key)) return false; // seen inv
            return true; // unsolicited push
        }
        if (std::string(kind) == "block") {
            if (!key.empty() && ps.inflight_blocks.count(key)) return false;
            if (!key.empty() && ps.recent_inv_keys.count(key)) return false; // seen inv
            return true;
        }
        if (std::string(kind) == "headers") {
            // only accept headers in direct response to our getheaders
            return ps.inflight_hdr_batches == 0 && !ps.sent_getheaders;
        }
        return false;
    }

    inline bool can_accept_hdr_batch(const PeerState& ps, int64_t now_ms) const {
        if (ps.inflight_hdr_batches >= 2) return false; // at most 2 in flight
        if (now_ms - ps.last_hdr_batch_done_ms < MIQ_P2P_HDR_BATCH_SPACING_MS) return false;
        return true;
    }
};

}
