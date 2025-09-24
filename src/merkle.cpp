
#include "merkle.h"
#include "sha256.h"
namespace miq {
std::vector<uint8_t> merkle_root(const std::vector<std::vector<uint8_t>>& txids){
    if(txids.empty()) return std::vector<uint8_t>(32,0);
    auto layer = txids;
    while(layer.size()>1){
        std::vector<std::vector<uint8_t>> next;
        for(size_t i=0;i<layer.size();i+=2){
            auto a=layer[i]; auto b=(i+1<layer.size())?layer[i+1]:layer[i];
            a.insert(a.end(), b.begin(), b.end());
            next.push_back(dsha256(a));
        }
        layer.swap(next);
    }
    return layer[0];
}
}
