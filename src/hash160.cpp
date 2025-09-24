
#include "hash160.h"
#include "sha256.h"
#include "ripemd160.h"
std::vector<uint8_t> miq::hash160(const std::vector<uint8_t>& in){
    return ripemd160(sha256(in));
}
