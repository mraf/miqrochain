#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// Minimal, blocking P2P client: version/verack + tx broadcast.
// NOTE: Uses Bitcoin-like framing. Wire magic bytes come from constants.h (MAGIC_BE).
struct P2POpts {
    std::string host = "62.38.73.147";
    std::string port = "9833";
    int         connect_timeout_ms = 5000;
    int         io_timeout_ms      = 5000;
    uint32_t    start_height       = 0;
    bool        send_verack        = true;
    std::string user_agent         = "/miqwallet:0.1/";
};

class P2PLight {
public:
    P2PLight();
    ~P2PLight();

    // Connect + handshake (version/verack).
    bool connect_and_handshake(const P2POpts& opts, std::string& err);

    // Broadcast a raw tx (payload already serialized).
    bool send_tx(const std::vector<uint8_t>& tx_bytes, std::string& err);

    // Ask peer for known addresses (getaddr); returns immediately (fire-and-forget).
    bool send_getaddr(std::string& err);

    void close();

private:
    int     sock_ = -1;
    P2POpts o_{};

    bool send_msg(const char cmd[12], const std::vector<uint8_t>& payload, std::string& err);
    bool read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err);
    bool read_exact(void* buf, size_t len, std::string& err);
    bool write_all(const void* buf, size_t len, std::string& err);

    bool send_version(std::string& err);
    bool read_until_verack(std::string& err);
};

}
