#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// Minimal, blocking P2P client: version/verack + headers sync + block fetch + tx broadcast.
// Wire framing is Bitcoin-like. Magic MUST match your daemon.
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

    // Graceful close.
    void close();

    // -------- SPV helpers (used by miqwallet.cpp) --------

    // Sync headers (or reuse memoized ones) and return current tip.
    // tip_hash_le is LE (wire-style) 32 bytes.
    bool get_best_header(uint32_t& tip_height,
                         std::vector<uint8_t>& tip_hash_le,
                         std::string& err);

    // Fallback listing of recent blocks (no filters): returns the header-hashes (LE) for [from..to].
    bool match_recent_blocks(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                             uint32_t from_height,
                             uint32_t to_height,
                             std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& matched,
                             std::string& err);

    // Fetch a full block by header-hash (LE) into raw_block (wire bytes).
    bool get_block_by_hash(const std::vector<uint8_t>& hash_le,
                           std::vector<uint8_t>& raw_block,
                           std::string& err);

    // Compact filters — not implemented yet; wallet will fall back automatically.
    // Keep inline stubs so there’s no link dependency.
    bool has_compact_filters() const { return false; }
    bool scan_blocks_with_filters(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                                  uint32_t /*tip_height*/,
                                  std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& /*matched*/,
                                  std::string& /*err*/) { return false; }

private:
    int sock_ = -1;
    P2POpts o_{};

    // Memoized chain of header hashes (LE) from genesis..tip
    std::vector<std::vector<uint8_t>> header_hashes_le_;

    // Wire helpers
    bool send_msg(const char cmd[12], const std::vector<uint8_t>& payload, std::string& err);
    bool read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err);
    bool read_exact(void* buf, size_t len, std::string& err);
    bool write_all(const void* buf, size_t len, std::string& err);

    bool send_version(std::string& err);
    bool read_until_verack(std::string& err);

    // Headers flow
    bool request_headers_from_locator(const std::vector<std::vector<uint8_t>>& locator_hashes_le,
                                      std::vector<uint8_t>& stop_le,
                                      std::string& err);
    bool read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le, std::string& err);
};

}
