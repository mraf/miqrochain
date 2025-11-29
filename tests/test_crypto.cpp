#include "sha256.h"
#include "ripemd160.h"
#include "hash160.h"
#include "base58check.h"
#include <cassert>
#include <string>
int main(){
    auto h = miq::sha256(std::vector<uint8_t>({'a','b','c'}));
    assert(h.size()==32 && h[0]==0xba && h[1]==0x78);
    auto r = miq::ripemd160(std::vector<uint8_t>({'a','b','c'})); assert(r.size()==20);
    auto pkh = miq::hash160(std::vector<uint8_t>({'x'})); (void)pkh;
    auto addr = miq::base58check_encode(0x35, std::vector<uint8_t>(20,1));
    uint8_t v = 0; std::vector<uint8_t> pl;
    bool decoded = miq::base58check_decode(addr, v, pl);
    assert(decoded && v == 0x35 && pl.size() == 20);
    return 0;
}
