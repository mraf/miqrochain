#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <cstdint>

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

#ifndef MIQ_PEER_MAX_BLOCKS_INFLIGHT
#define MIQ_PEER_MAX_BLOCKS_INFLIGHT 8
#endif
#ifndef MIQ_GLOBAL_MAX_BLOCKS_INFLIGHT
#define MIQ_GLOBAL_MAX_BLOCKS_INFLIGHT 64
#endif
#ifndef MIQ_BLOCK_REQ_TIMEOUT_MS
#define MIQ_BLOCK_REQ_TIMEOUT_MS 15000
#endif

namespace miq {

class Chain; // fwd

struct OrphanRec {
    std::vector<uint8_t> hash;
    std::vector<uint8_t> prev;
    std::vector<uint8_t> raw;
};

struct PeerState {
    // headers-first (reserved / future use)
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

    // ---- NEW: block fetch scheduler state (per peer) ----
    std::unordered_set<std::string> inflight_blocks;            // hex(blockhash)
    std::unordered_map<std::string, int64_t> req_time_ms;       // hex(blockhash) -> sent_ms
    size_t inflight_bytes{0};                                   // optional future use
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

    bool start(uint16_t port);
    void stop();

    // Outbound connect to a seed (hostname or IP)
    bool connect_seed(const std::string& host, uint16_t port);

    // Broadcast inventory for a new block/tx we just accepted/mined
    void broadcast_inv_block(const std::vector<uint8_t>& block_hash);
    void broadcast_inv_tx(const std::vector<uint8_t>& txid);

    // Optional: where to store bans.txt and peers.dat
    inline void set_datadir(const std::string& d) { datadir_ = d; }

    // tiny, local and fast hex for keys
    std::string hexkey(const std::vector<uint8_t>& h);

    // Read-only stats for RPC/UI
    size_t connection_count() const { return peers_.size(); }
    std::vector<PeerSnapshot> snapshot_peers() const;

private:
    // ---- headers-first helpers (present for future use; not enabled) ----
    void send_getheaders(PeerState& ps);
    void send_headers_snapshot(PeerState& ps, const std::vector<std::vector<uint8_t>>& locator);

    // ---- tx relay (basic) ----
    void request_tx(PeerState& ps, const std::vector<uint8_t>& txid);
    void send_tx(int sock, const std::vector<uint8_t>& raw);

    // Small, bounded caches (in-memory)
    std::unordered_set<std::string> seen_txids_;
    std::unordered_map<std::string, std::vector<uint8_t>> tx_store_;
    std::deque<std::string> tx_order_; // for eviction

    Mempool* mempool_{nullptr};  // nullable, safe to run without
    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
    int srv_{-1};
    std::unordered_map<int, PeerState> peers_;
    std::unordered_set<std::string> banned_;
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

    // ---- NEW: global block fetch scheduler state ----
    // map hex(blockhash) -> owning socket (or -1 if unassigned)
    std::unordered_map<std::string, int>   blk_owner_;
    // quick presence set of inflight (same keys as blk_owner_)
    std::unordered_set<std::string>        blk_inflight_;
    // global counter for simple cap
    size_t                                 global_inflight_{0};

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

    // ---- NEW: scheduler helpers ----
    void pump_block_scheduler(); // figure out next wanted hashes and assign across peers
    bool assign_block_to_peer(PeerState& ps, const std::vector<uint8_t>& h);
    void mark_block_inflight(PeerState& ps, const std::string& hex, int64_t now);
    void clear_block_inflight_any(const std::string& hex); // remove from whichever peer had it
    void reap_stalled_requests(int64_t now);

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
};

}
