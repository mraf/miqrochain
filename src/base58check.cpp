
#include "base58check.h"
#include "base58.h"
#include "sha256.h"
std::string miq::base58check_encode(uint8_t version, const std::vector<uint8_t>& payload){
    std::vector<uint8_t> b; b.push_back(version); b.insert(b.end(), payload.begin(), payload.end());
    auto c = dsha256(b); std::vector<uint8_t> full=b; full.insert(full.end(), c.begin(), c.begin()+4);
    return base58_encode(full);
}
bool miq::base58check_decode(const std::string& s, uint8_t& version, std::vector<uint8_t>& payload){
    std::vector<uint8_t> b; if(!base58_decode(s,b)) return false; if(b.size()<5) return false;
    version = b[0]; std::vector<uint8_t> body(b.begin(), b.end()-4); auto c = dsha256(body);
    if(!(c[0]==b[b.size()-4] && c[1]==b[b.size()-3] && c[2]==b[b.size()-2] && c[3]==b[b.size()-1])) return false;
    payload.assign(b.begin()+1, b.end()-4); return true;
}
