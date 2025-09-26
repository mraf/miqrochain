#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <set>
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

    // per-peer RX buffer & liveness
    std::vector<uint8_t> rx;
    bool        verack_ok{false};
    int64_t     last_ping_ms{0};
    bool        awaiting_pong{false};
    int         banscore{0};

    // --- NEW: per-peer rate-limiting (token buckets) ---
    uint64_t    blk_tokens{0};        // bytes available for blocks
    uint64_t    tx_tokens{0};         // bytes available for txs
    int64_t     last_refill_ms{0};    // last refill timestamp

    // --- NEW: addr anti-spam ---
    int64_t     last_addr_ms{0};      // last time we accepted an addr batch
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

private:
    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
    int srv_{-1};
    std::unordered_map<int, PeerState> peers_;
    std::set<std::string> banned_;
    std::string datadir_{"./miqdata"};

    // addr table (IPv4, network byte order)
    std::unordered_set<uint32_t> addrv4_;
    int64_t last_addr_broadcast_ms_{0};

    void loop();
    void handle_new_peer(int c, const std::string& ip);
    void load_bans();
    void save_bans();

    // helpers for sync & block serving
    void start_sync_with_peer(PeerState& ps);
    void request_block_index(PeerState& ps, uint64_t index);
    void request_block_hash(PeerState& ps, const std::vector<uint8_t>& h);
    void send_block(int s, const std::vector<uint8_t>& raw);

    // --- NEW: rate limiting helpers ---
    void rate_refill(PeerState& ps, int64_t now_ms);
    bool rate_consume_block(PeerState& ps, size_t nbytes); // true = ok
    bool rate_consume_tx(PeerState& ps, size_t nbytes);    // true = ok

    // --- NEW: addr filtering / handling ---
    void maybe_send_getaddr(PeerState& ps);
    void handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload);
    void send_addr_snapshot(PeerState& ps);

    // utils
    static std::string hexkey(const std::vector<uint8_t>& h);
    static bool ipv4_is_public(uint32_t be_ip);
    static bool parse_ipv4(const std::string& dotted, uint32_t& be_ip);
};

} // namespace miq
