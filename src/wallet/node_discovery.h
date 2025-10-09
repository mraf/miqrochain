#pragma once
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

struct NodeEndpoint {
    std::string host;
    uint16_t    port{0};
    std::string token;   // optional
    int         last_ms{-1}; // latency probe
};

std::vector<NodeEndpoint> discover_nodes(const std::string& datadir, int timeout_ms = 2000);

}
