#pragma once
#include <string>
#include <thread>
#include <atomic>

namespace miq {

// A tiny TLS terminator that accepts HTTPS on rpc_tls_bind,
// then forwards plaintext HTTP to rpc_bind (usually 127.0.0.1:9834).
// Uses OpenSSL; runs in its own thread.
class TlsProxy {
public:
    TlsProxy(const std::string& tls_bind_addr,
             const std::string& tls_cert_pem,
             const std::string& tls_key_pem,
             const std::string& tls_client_ca_pem, // empty => no client auth
             const std::string& forward_host,
             int forward_port);
    ~TlsProxy();

    bool start(std::string& err); // returns false on failure
    void stop();

private:
    std::string bind_host_;
    int bind_port_ = 0;
    std::string cert_path_;
    std::string key_path_;
    std::string ca_path_;
    std::string fwd_host_;
    int fwd_port_ = 0;

    std::thread th_;
    std::atomic<bool> run_{false};
};

}
