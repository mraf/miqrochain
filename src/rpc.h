
#pragma once
#include "chain.h"
#include "mempool.h"
#include "http.h"
#include "json.h"
#include "base58check.h"
#include "hash160.h"
#include "crypto/ecdsa_iface.h"
#include <string>
namespace miq {
class RpcService {
public:
    RpcService(Chain& c, Mempool& m): chain_(c), mempool_(m) {}
    void start(uint16_t port);
    void stop();
private:
    Chain& chain_;
    Mempool& mempool_;
    HttpServer http_;
    std::string handle(const std::string& body);
};
}
