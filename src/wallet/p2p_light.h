#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

struct P2POpts {
    std::string host;            // e.g. "127.0.0.1"
    std::string port;            // e.g. "9833"
    std::string user_agent;      // e.g. "/miqwallet:0.1/"
    uint32_t    start_height{0};
    int         io_timeout_ms{10000};
    bool        send_verack{true}; // keep true; node expects verack timing
};

class P2PLight {
public:
    P2PLight();
    ~P2PLight();

    bool connect_and_handshake(const P2POpts& opts, std::string& err);
    void close();

    // Headers / blocks
    bool get_best_header(uint32_t& tip_height,
                         std::vector<uint8_t>& tip_hash_le,
                         std::string& err);

    bool match_recent_blocks(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                             uint32_t from_height,
                             uint32_t to_height,
                             std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& matched,
                             std::string& err);

    bool get_block_by_hash(const std::vector<uint8_t>& hash_le,
                           std::vector<uint8_t>& raw_block,
                           std::string& err);

    // Broadcast
    bool send_tx(const std::vector<uint8_t>& tx_bytes, std::string& err);

private:
    // handshake
    bool send_version(std::string& err);
    bool send_getaddr(std::string& err);
    bool read_until_verack(std::string& err);

    // headers helpers
    bool request_headers_from_locator(const std::vector<std::vector<uint8_t>>& locator_hashes_le,
                                      std::vector<uint8_t>& stop_le,
                                      std::string& err);
    bool read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le,
                            std::string& err);

    // wire I/O
    bool send_msg(const char cmd12[12], const std::vector<uint8_t>& payload, std::string& err);
    bool read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err);
    bool read_exact(void* buf, size_t len, std::string& err);
    bool write_all(const void* buf, size_t len, std::string& err);

private:
#ifdef _WIN32
    using NetSock = uintptr_t; // SOCKET is uintptr_t-compatible
#else
    using NetSock = int;
#endif
    NetSock sock_{(NetSock)-1};
    P2POpts o_{};
    std::vector<std::vector<uint8_t>> header_hashes_le_;
};

}
