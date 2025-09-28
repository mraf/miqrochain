#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace miq {

// One resolved endpoint from a seed (hostname or IP → concrete IP + port)
struct SeedEndpoint {
    std::string host;  // original seed entry (e.g., s626853.name-servers.gr)
    std::string ip;    // resolved numeric IP (v4 or v6) as string
    uint16_t    port;  // target P2P port
};

// Resolve all seeds from constants.h into a unique list of IP:port endpoints.
// - include_single_dns_seed: also try the single DNS_SEED (IP/host) if true.
// Returns true if at least one endpoint was resolved (false if none).
bool resolve_dns_seeds(std::vector<SeedEndpoint>& out,
                       uint16_t port,
                       bool include_single_dns_seed = true);

}
