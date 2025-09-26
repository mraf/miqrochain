#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
    // ----------- Orphan manager -----------
    struct OrphanRec {
        std::vector<uint8_t> hash;  // child hash (32)
        std::vector<uint8_t> prev;  // parent hash (32)
        std::vector<uint8_t> raw;   // raw serialized block
    };

    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
    int srv_{-1};

    struct PeerState {
        int         sock{-1};
        std::string ip;
        int         mis{0};
        int64_t     last_ms{0};

        // --- sync state ---
        bool        syncing{false};
        uint64_t    next_index{0};

        // --- per-peer RX buffer & liveness ---
        std::vector<uint8_t> rx;
        bool        verack_ok{false};
        int64_t     last_ping_ms{0};
        bool        awaiting_pong{false};
        int         banscore{0};
    };

    std::unordered_map<int, PeerState> peers_;
    std::set<std::string> banned_;
    std::string datadir_{"./miqdata"};

    // Orphan pool (bounded)
    std::unordered_map<std::string, OrphanRec> orphans_;              // childHex -> rec
    std::unordered_map<std::string, std::vector<std::string>> orphan_children_; // parentHex -> [childHex...]
    std::deque<std::string> orphan_order_;                            // insertion order for eviction
    size_t orphan_bytes_{0};
    // defaults; can be adjusted by compile-time macros in .cpp
    size_t orphan_bytes_limit_{32u * 1024u * 1024u};  // 32 MiB
    size_t orphan_count_limit_{4096};

    // ---- main loop & helpers ----
    void loop();
    void handle_new_peer(int c, const std::string& ip);
    void load_bans();
    void save_bans();

    // helpers for sync & block serving
    void start_sync_with_peer(PeerState& ps);
    void request_block_index(PeerState& ps, uint64_t index);
    void request_block_hash(PeerState& ps, const std::vector<uint8_t>& h);
    void send_block(int s, const std::vector<uint8_t>& raw);

    // orphan manager helpers
    static std::string hexkey(const std::vector<uint8_t>& h);
    void handle_incoming_block(int sock, const std::vector<uint8_t>& raw);
    void try_connect_orphans(const std::string& parent_hex);
    void evict_orphans_if_needed();
    void remove_orphan_by_hex(const std::string& child_hex);
};

} // namespace miq
