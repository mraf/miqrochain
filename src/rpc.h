// rpc.h
#pragma once
#include <cstdint>
#include <string>
#include "http.h"     // whatever your HTTP server header is
#include "json.h"
#include "chain.h"
#include "mempool.h"

namespace miq {
    void rpc_enable_auth_cookie(const std::string& datadir);
class P2P;  // <-- add this

class RpcService {
public:
    RpcService(Chain& c, Mempool& m) : chain_(c), mempool_(m) {}
    void start(uint16_t port);
    void stop();

    // optional: let main() wire P2P here after both are constructed
    void set_p2p(P2P* p) { p2p_ = p; }

private:
    std::string handle(const std::string& body);

    HttpServer http_;
    Chain&     chain_;
    Mempool&   mempool_;
    P2P*       p2p_{nullptr};   // <-- add this
};

class HttpServer {
public:
    void start(
        uint16_t port,
        std::function<std::string(
            const std::string& body,
            const std::vector<std::pair<std::string,std::string>>& headers
        )> handler);
    void stop();
};

}
