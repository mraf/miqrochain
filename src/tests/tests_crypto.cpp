#include "crypto/ecdsa_iface.h"
#include <array>
#include <vector>
#include <cstdio>

int main() {
    using namespace miq::crypto;

    std::vector<uint8_t> priv, pub33, sig;
    if(!ECDSA::generate_priv(priv)) return 1;
    if(!ECDSA::derive_pub(priv, pub33)) return 2;

    std::array<uint8_t,32> msg{};
    for (int i=0;i<32;i++) msg[i]=uint8_t(i);

    if(!ECDSA::sign(priv, {msg.begin(), msg.end()}, sig)) return 3;
    bool ok1 = ECDSA::verify(pub33, {msg.begin(), msg.end()}, sig);

    msg[0] ^= 1; // tamper
    bool ok2 = ECDSA::verify(pub33, {msg.begin(), msg.end()}, sig);

    std::printf("verify: %s, tamper: %s\n", ok1?"OK":"FAIL", ok2?"OK":"FAIL");
    return (ok1 && !ok2) ? 0 : 10;
}
