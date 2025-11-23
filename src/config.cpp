#include "config.h"
#include <fstream>
#include <sstream>
#include <algorithm>

using namespace miq;

static inline std::string trim(const std::string& s){
    auto a = s.find_first_not_of(" \t\r\n");
    if(a==std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b-a+1);
}

bool miq::load_config(const std::string& path, Config& out){
    std::ifstream f(path);
    if(!f.is_open()) return false;

    std::string line;
    while(std::getline(f, line)){
        line = trim(line);
        if(line.empty()) continue;
        if(line[0]=='#') continue;
        if(line.rfind("//",0)==0) continue;

        auto kpos = line.find('=');
        if(kpos==std::string::npos) continue;
        std::string k = trim(line.substr(0,kpos));
        std::string v = trim(line.substr(kpos+1));
        std::transform(k.begin(), k.end(), k.begin(), ::tolower);

        if(k=="datadir") out.datadir = v;
        else if(k=="no_p2p") out.no_p2p = (v=="1"||v=="true");
        else if(k=="no_rpc") out.no_rpc = (v=="1"||v=="true");
        else if(k=="no_mine") out.no_mine = (v=="1"||v=="true");
        else if(k=="miner_threads"){ try{ out.miner_threads = (unsigned)std::stoul(v); }catch(...){} }
        else if(k=="mining_address") out.mining_address = v;
        else if(k=="p2p_port"){ try{ out.p2p_port = (uint16_t)std::stoul(v); }catch(...){} }
        else if(k=="rpc_bind") out.rpc_bind = v;

        // TLS
        else if(k=="rpc_tls_enable") out.rpc_tls_enable = (v=="1"||v=="true");
        else if(k=="rpc_tls_bind")   out.rpc_tls_bind   = v;
        else if(k=="rpc_tls_cert")   out.rpc_tls_cert   = v;
        else if(k=="rpc_tls_key")    out.rpc_tls_key    = v;
        else if(k=="rpc_tls_client_ca") out.rpc_tls_client_ca = v;

        // Stratum mining pool
        else if(k=="stratum_enable") out.stratum_enable = (v=="1"||v=="true");
        else if(k=="stratum_port"){ try{ out.stratum_port = (uint16_t)std::stoul(v); }catch(...){} }
        else if(k=="stratum_difficulty"){ try{ out.stratum_difficulty = std::stod(v); }catch(...){} }
        else if(k=="stratum_vardiff") out.stratum_vardiff = (v=="1"||v=="true");
    }
    return true;
}