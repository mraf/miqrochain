#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// Minimal, blocking P2P client: version/verack + headers + getdata + tx broadcast.
// NOTE: Uses Bitcoin-like framing. Make sure P2P_MAGIC matches daemon.
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

    // --- SPV helpers ---------------------------------------------------------
    // Sync headers to tip. On success, returns best height and best hash (LE as on the wire).
    bool get_best_header(uint32_t& tip_height, std::vector<uint8_t>& tip_hash_le, std::string& err);

    // Return whether the peer/network supports compact filters. (Not yet.)
    bool has_compact_filters() const { return false; }

    // If filters existed, we'd use them; kept for API parity.
    bool scan_blocks_with_filters(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                                  uint32_t /*up_to_height*/,
                                  std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& /*matched*/,
                                  std::string& err)
    {
        err = "compact filters not supported on this network";
        return false;
    }

    // Fallback: return [hash,height] list for the recent height window.
    // The wallet will fetch & scan each block for matches.
    bool match_recent_blocks(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                             uint32_t from_height,
                             uint32_t to_height,
                             std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& matched,
                             std::string& err);

    // Fetch raw block by hash (hash_le is little-endian as sent on the wire).
    bool get_block_by_hash(const std::vector<uint8_t>& hash_le,
                           std::vector<uint8_t>& raw_block,
                           std::string& err);

    void close();

private:
    int sock_ = -1;
    P2POpts o_;

    // Header chain we learned (hashes in little-endian, as on the wire).
    std::vector<std::vector<uint8_t>> header_hashes_le_;

    bool send_msg(const char cmd[12], const std::vector<uint8_t>& payload, std::string& err);
    bool read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err);
    bool read_exact(void* buf, size_t len, std::string& err);
    bool write_all(const void* buf, size_t len, std::string& err);

    bool send_version(std::string& err);
    bool read_until_verack(std::string& err);

    // Helpers
    bool request_headers_from_locator(const std::vector<std::vector<uint8_t>>& locator_hashes_le,
                                      std::vector<uint8_t>& stop_le,
                                      std::string& err);
    bool read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le, std::string& err);
};

}
