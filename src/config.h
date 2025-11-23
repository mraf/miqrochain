#pragma once
#include <string>
#include <cstdint>

namespace miq {

struct Config {
    std::string datadir;
    bool        no_p2p = false;
    bool        no_rpc = false;
    bool        no_mine = false;
    unsigned    miner_threads = 0;
    std::string mining_address; // kept for future use / compatibility
    uint16_t    p2p_port = 0;                    // P2P port (0 = use default from constants.h)
    std::string rpc_bind;                        // RPC bind address (host:port); empty = use default

    // === TLS for RPC (via local TLS terminator) ===
    bool        rpc_tls_enable = false;          // enable TLS listener
    std::string rpc_tls_bind   = "0.0.0.0:9835"; // external HTTPS bind (host:port)
    std::string rpc_tls_cert;                    // server cert chain (PEM)
    std::string rpc_tls_key;                     // server private key (PEM)
    std::string rpc_tls_client_ca;               // optional client-auth CA (PEM); empty = no client auth

    // === Stratum mining pool server ===
    bool        stratum_enable = false;          // enable Stratum pool server
    uint16_t    stratum_port = 3333;             // Stratum port
    double      stratum_difficulty = 1.0;        // default mining difficulty
    bool        stratum_vardiff = true;          // enable variable difficulty
};

// Simple key=value loader. Unknown keys are ignored. Returns false if file not found.
bool load_config(const std::string& path, Config& out);

}