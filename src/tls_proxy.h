#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <memory>

namespace miq {

// Minimal HTTPS → HTTP proxy for JSON-RPC.
// Accepts TLS on rpc_tls_bind, forwards to 127.0.0.1:RPC_PORT.
// One request/response per TCP connection (fits JSON-RPC usage).
class TlsProxy {
public:
    TlsProxy(const std::string& tls_bind_hostport,
             const std::string& cert_pem_path,
             const std::string& key_pem_path,
             const std::string& client_ca_pem_path, // empty => no client auth
             const std::string& forward_host,
             int forward_port);
    ~TlsProxy();

    bool start(std::string& err); // returns false on immediate failure
    void stop();                  // waits for thread to join

private:
    std::string bind_host_;
    int         bind_port_ = 0;
    std::string cert_;
    std::string key_;
    std::string ca_;
    std::string fwd_host_;
    int         fwd_port_ = 0;

    std::thread       th_;
    std::atomic<bool> run_{false};
};

}
