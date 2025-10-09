#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// Minimal, blocking P2P client: version/verack + headers + block fetch + tx broadcast.
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

    // Ask peer for known addresses (getaddr); fire-and-forget.
    bool send_getaddr(std::string& err);

    // --- SPV helpers ---
    // Sync headers (once per connection) and return best height + tip hash (LE).
    bool get_best_header(uint32_t& tip_height, std::vector<uint8_t>& tip_hash_le, std::string& err);

    // Return header hashes (LE) for a height window; wallet can fetch blocks & scan.
    bool match_recent_blocks(const std::vector<std::vector<uint8_t>>& pkhs,
                             uint32_t from_height,
                             uint32_t to_height,
                             std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& matched,
                             std::string& err);

    // Fetch a raw block by header hash (LE).
    bool get_block_by_hash(const std::vector<uint8_t>& hash_le,
                           std::vector<uint8_t>& raw_block,
                           std::string& err);

    void close();

private:
    int     sock_ = -1;
    P2POpts o_{};

    // cached header chain (hashes LE)
    std::vector<std::vector<uint8_t>> header_hashes_le_;

    // wire helpers
    bool send_msg(const char cmd[12], const std::vector<uint8_t>& payload, std::string& err);
    bool read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err);
    bool read_exact(void* buf, size_t len, std::string& err);
    bool write_all(const void* buf, size_t len, std::string& err);

    // handshake
    bool send_version(std::string& err);
    bool read_until_verack(std::string& err);

    // headers
    bool request_headers_from_locator(const std::vector<std::vector<uint8_t>>& locator_hashes_le,
                                      std::vector<uint8_t>& stop_le,
                                      std::string& err);
    bool read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le, std::string& err);
};

}
