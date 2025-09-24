#pragma once
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <unordered_map>
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
    int sock{-1};
    std::string ip;
    int mis{0};
    int64_t last_ms{0};
};

class P2P {
public:
    explicit P2P(Chain& c);
    ~P2P();

    bool start(uint16_t port);
    void stop();
    bool connect_seed(const std::string& host, uint16_t port);
    void broadcast_inv_block(const std::vector<uint8_t>& block_hash);

private:
    Chain& chain_;
    std::thread th_;
    std::atomic<bool> running_{false};
    int srv_{-1};
    std::unordered_map<int, PeerState> peers_;
    std::set<std::string> banned_;
    std::string datadir_{"./miqdata"};

    void loop();
    void handle_new_peer(int c, const std::string& ip);
    void load_bans();
    void save_bans();
};

} // namespace miq
