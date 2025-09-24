#include "address.h"
#include "base58check.h"
#include "constants.h"
namespace miq {
bool decode_p2pkh_address(const std::string& addr, std::vector<uint8_t>& out_pkh){
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!base58check_decode(addr, ver, payload)) return false;
    if(ver != VERSION_P2PKH) return false;
    if(payload.size()!=20) return false;
    out_pkh = payload; return true;
}
std::string encode_p2pkh_address(const std::vector<uint8_t>& pkh){
    return base58check_encode(VERSION_P2PKH, pkh);
}
}
