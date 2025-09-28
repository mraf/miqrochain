#pragma once
#include <string>
#include <thread>
#include <atomic>
#include <memory>

namespace miq {

// Tiny TLS terminator that accepts HTTPS on rpc_tls_bind and forwards
// plaintext HTTP to localhost:RPC_PORT. Single-request-per-connection is enough
// for JSON-RPC. Uses OpenSSL. Runs in its own thread.
class TlsProxy {
public:
    TlsProxy(const std::string& tls_bind_hostport,
             const std::string& cert_pem_path,
             const std::string& key_pem_path,
             const std::string& client_ca_pem_path, // empty => no client auth
             const std::string& forward_host,
             int forward_port);
    ~TlsProxy();

    bool start(std::string& err);
    void stop();

private:
    std::string bind_host_;
    int bind_port_ = 0;
    std::string cert_;
    std::string key_;
    std::string ca_;
    std::string fwd_host_;
    int fwd_port_ = 0;

    std::thread th_;
    std::atomic<bool> run_{false};
};

}
