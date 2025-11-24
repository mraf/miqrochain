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
    bool        stratum_enable = true;           // enable Stratum pool server (default: ON for v1.0)
    uint16_t    stratum_port = 3333;             // Stratum port
    double      stratum_difficulty = 1.0;        // default mining difficulty
    bool        stratum_vardiff = true;          // enable variable difficulty
    double      stratum_pool_fee = 1.0;          // pool fee percentage (default: 1%)
    uint64_t    stratum_min_payout = 1000000;    // minimum payout in base units (0.01 MIQ)
    bool        stratum_auto_payout = true;      // automatic payouts when balance reached
};

// Simple key=value loader. Unknown keys are ignored. Returns false if file not found.
bool load_config(const std::string& path, Config& out);

}