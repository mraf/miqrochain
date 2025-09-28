#pragma once
#include <string>
#include <cstdint>

namespace miq {

struct Config {
    // existing fields you already had (keep them)
    std::string datadir;
    bool no_p2p = false;
    bool no_rpc = false;
    bool no_mine = false;
    int  miner_threads = 0;
    std::string mining_address;
    std::string rpc_bind = "127.0.0.1:9834"; // existing or default

    // === NEW: TLS proxy for RPC ===
    bool        rpc_tls_enable = false;          // enable TLS listener (terminates TLS then forwards to rpc_bind)
    std::string rpc_tls_bind   = "0.0.0.0:9835"; // external TLS port
    std::string rpc_tls_cert;                    // PEM cert chain
    std::string rpc_tls_key;                     // PEM private key
    std::string rpc_tls_client_ca;               // optional client-auth CA bundle (PEM). Empty = no client auth.
};

bool load_config_from_file(const std::string& path, Config& out);
}
