#include "config.h"
#include <fstream>
namespace miq {
bool load_config(const std::string& path, Config& cfg){
    std::ifstream f(path); if(!f) return false;
    std::string line;
    while(std::getline(f,line)){
        if(line.empty()||line[0]=='#') continue;
        auto p=line.find('='); if(p==std::string::npos) continue;
        auto k=line.substr(0,p), v=line.substr(p+1);
        if(k=="datadir") cfg.datadir=v;
        else if(k=="miner_threads") cfg.miner_threads=(unsigned)std::stoul(v);
        else if(k=="no_mine") cfg.no_mine=(v=="1"||v=="true");
        else if(k=="no_p2p") cfg.no_p2p=(v=="1"||v=="true");
        else if(k=="no_rpc") cfg.no_rpc=(v=="1"||v=="true");
        else if(k=="mining_address") cfg.mining_address=v; // NEW
    }
    return true;
}
}
