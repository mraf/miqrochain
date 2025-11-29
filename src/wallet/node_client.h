#pragma once
#include "node_discovery.h"
#include "serialize.h"   // JNode/json_parse/json_dump
#include <string>
#include <vector>
#include <mutex>
#include <utility>

namespace miq {

// =============================================================================
// BULLETPROOF NODE CLIENT v1.0 - Production-grade RPC client
// =============================================================================

class NodeClient {
public:
    static NodeClient Auto(const std::string& datadir, int timeout_ms = 5000);
    explicit NodeClient(std::vector<NodeEndpoint> endpoints, int timeout_ms = 5000);

    // Main RPC call with automatic retry and endpoint failover
    bool call(const std::string& method,
              const std::vector<JNode>& params,
              JNode& out,
              std::string& err);

    // String version of call for raw JSON output
    bool call_str(const std::string& method,
                  const std::vector<JNode>& params,
                  std::string& out_str,
                  std::string& err);

    // Get current active endpoint
    NodeEndpoint current() const;

    // NEW: Health check - verify endpoint connectivity
    bool health_check(std::string& status);

    // NEW: Get endpoint statistics for debugging/monitoring
    std::vector<std::pair<std::string, std::string>> get_endpoint_stats() const;

    // =========================================================================
    // BIP158 COMPACT BLOCK FILTER SUPPORT
    // =========================================================================

    // Check if the connected node supports BIP158 filters
    bool supports_filters();

    // Get filter headers for a range of blocks
    // Returns array of 32-byte filter header hashes
    bool get_filter_headers(uint32_t start, uint32_t count,
                           std::vector<std::vector<uint8_t>>& headers,
                           std::string& err);

    // Get filters for a range of blocks
    // Returns pairs of (block_hash, filter_bytes)
    bool get_filters(uint32_t start, uint32_t count,
                    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>>& filters,
                    std::string& err);

    // Match script pubkeys against a filter
    // Returns true if any element matches (may have false positives)
    static bool filter_match(const std::vector<uint8_t>& filter,
                            const std::vector<std::vector<uint8_t>>& elements);

private:
    bool call_once(size_t idx, const std::string& body, JNode& out, std::string& err);

    std::vector<NodeEndpoint> eps_;
    int timeout_ms_{5000};
    mutable std::mutex mtx_;
    size_t cursor_{0};
};

}
