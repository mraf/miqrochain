#pragma once
#include <string>
#include <cstdint>

namespace miq {

struct Config {
    std::string datadir;
    bool no_p2p = false;
    bool no_rpc = false;
    bool no_mine = false;
    unsigned miner_threads = 0;
    std::string mining_address; // kept for future use

    // === NEW: TLS for RPC (TLS terminator binding) ===
    bool        rpc_tls_enable = false;
    std::string rpc_tls_bind   = "0.0.0.0:9835"; // external HTTPS
    std::string rpc_tls_cert;                    // PEM path
    std::string rpc_tls_key;                     // PEM path
    std::string rpc_tls_client_ca;               // optional client-auth CA PEM
};

// Parses simple key=value lines. Unknown keys are ignored.
bool load_config(const std::string& path, Config& out);

}
