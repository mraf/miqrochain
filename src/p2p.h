#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <set>
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

namespace miq {

class Chain; // forward declaration

struct PeerState {
    int         sock{-1};
    std::string ip;
    int         mis{0};
    int64_t     last_ms{0};

    // sync state
    bool        syncing{false};
    uint64_t    next_index{0};

    // RX buffer & liveness
    std::vector<uint8_t> rx;
    bool        verack_ok{false};
    int64_t     last_ping_ms{0};
    bool        awaiting_pong{false};
    int         banscore{0};

    // addr throttling
    int64_t     last_addr_ms{0};

    // rate limiting
    uint64_t    blk_tokens{0};
    uint64_t    tx_tokens{0};
    int64_t     last_refill_ms{0};
};

// Orphan block record
struct OrphanRec {
    std::vector<uint8_t> hash;  // child block hash
    std::vector<uint8_t> prev;  // parent hash
    std::vector<uint8_t> raw;   // serialized block
};

class P2P {
public:
    explicit P2P(Chain& c);
    ~P2P();

    bool start(uint16_t port);
    void stop();

    // Outbound connect to a seed (hostname or IP)
    bool connect_seed(const std::string& host, uint16_t port);

    // Broadcast inventory for a new block hash we just accepted/mined
    void broadcast_inv_block(const std::vector<uint8_t>& block_hash);

    // Optional: where to store bans.txt
    inline void set_datadir(const std::string& d) { datadir_ = d; }

    // hex for keys (small helper)
    static std::string hexkey(const std::vector<uint8_t>& h);

private:
    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
    int srv_{-1};
    std::unordered_map<int, PeerState> peers_;
    std::set<std::string> banned_;

    // known IPv4 addrs (network byte order) learned from peers
    std::set<uint32_t> addrv4_;

    std::string datadir_{"./miqdata"};

    void loop();
    void handle_new_peer(int c, const std::string& ip);
    void load_bans();
    void save_bans();

    // helpers for sync & block serving
    void start_sync_with_peer(PeerState& ps);
    void request_block_index(PeerState& ps, uint64_t index);
    void request_block_hash(PeerState& ps, const std::vector<uint8_t>& h);
    void send_block(int s, const std::vector<uint8_t>& raw);

    // rate limiting
    void rate_refill(PeerState& ps, int64_t now);
    bool rate_consume_block(PeerState& ps, size_t nbytes);
    bool rate_consume_tx(PeerState& ps, size_t nbytes);

    // addr handling
    void maybe_send_getaddr(PeerState& ps);
    void send_addr_snapshot(PeerState& ps);
    void handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload);

    // IPv4 helpers
    static bool parse_ipv4(const std::string& dotted, uint32_t& be_ip);
    static bool ipv4_is_public(uint32_t be_ip);

    // ---- Orphan manager (matches your p2p.cpp) ----
    void evict_orphans_if_needed();
    void remove_orphan_by_hex(const std::string& child_hex);
    void handle_incoming_block(int sock, const std::vector<uint8_t>& raw);
    void try_connect_orphans(const std::string& parent_hex);

    // orphan state
    std::unordered_map<std::string, OrphanRec> orphans_;                 // child_hex -> record
    std::unordered_map<std::string, std::vector<std::string>> orphan_children_; // parent_hex -> list of child_hex
    std::deque<std::string> orphan_order_;                               // FIFO for eviction
    size_t orphan_bytes_{0};
    size_t orphan_bytes_limit_{0};
    size_t orphan_count_limit_{0};
};

} // namespace miq
