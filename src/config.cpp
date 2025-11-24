#include "config.h"
#include "log.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <climits>  // PRODUCTION FIX: For UINT_MAX

using namespace miq;

static inline std::string trim(const std::string& s){
    auto a = s.find_first_not_of(" \t\r\n");
    if(a==std::string::npos) return "";
    auto b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b-a+1);
}

// PRODUCTION FIX: Safe number parsing with proper error reporting
static bool safe_parse_uint(const std::string& v, unsigned& out, const std::string& key) {
    try {
        unsigned long val = std::stoul(v);
        if (val > UINT_MAX) {
            log_error("Config: " + key + " value '" + v + "' is too large");
            return false;
        }
        out = static_cast<unsigned>(val);
        return true;
    } catch (const std::exception& e) {
        log_error("Config: Invalid " + key + " value '" + v + "': " + e.what());
        return false;
    }
}

static bool safe_parse_uint16(const std::string& v, uint16_t& out, const std::string& key) {
    try {
        unsigned long val = std::stoul(v);
        if (val > 65535) {
            log_error("Config: " + key + " value '" + v + "' exceeds valid port range (0-65535)");
            return false;
        }
        out = static_cast<uint16_t>(val);
        return true;
    } catch (const std::exception& e) {
        log_error("Config: Invalid " + key + " value '" + v + "': " + e.what());
        return false;
    }
}

static bool safe_parse_double(const std::string& v, double& out, const std::string& key) {
    try {
        out = std::stod(v);
        return true;
    } catch (const std::exception& e) {
        log_error("Config: Invalid " + key + " value '" + v + "': " + e.what());
        return false;
    }
}

bool miq::load_config(const std::string& path, Config& out){
    std::ifstream f(path);
    if(!f.is_open()) return false;

    std::string line;
    int line_num = 0;
    while(std::getline(f, line)){
        ++line_num;
        line = trim(line);
        if(line.empty()) continue;
        if(line[0]=='#') continue;
        if(line.rfind("//",0)==0) continue;

        auto kpos = line.find('=');
        if(kpos==std::string::npos) {
            log_error("Config line " + std::to_string(line_num) + ": missing '=' in '" + line + "'");
            continue;
        }
        std::string k = trim(line.substr(0,kpos));
        std::string v = trim(line.substr(kpos+1));
        std::transform(k.begin(), k.end(), k.begin(), ::tolower);

        if(k=="datadir") out.datadir = v;
        else if(k=="no_p2p") out.no_p2p = (v=="1"||v=="true");
        else if(k=="no_rpc") out.no_rpc = (v=="1"||v=="true");
        else if(k=="no_mine") out.no_mine = (v=="1"||v=="true");
        else if(k=="miner_threads") safe_parse_uint(v, out.miner_threads, "miner_threads");
        else if(k=="mining_address") out.mining_address = v;
        else if(k=="p2p_port") safe_parse_uint16(v, out.p2p_port, "p2p_port");
        else if(k=="rpc_bind") out.rpc_bind = v;

        // TLS
        else if(k=="rpc_tls_enable") out.rpc_tls_enable = (v=="1"||v=="true");
        else if(k=="rpc_tls_bind")   out.rpc_tls_bind   = v;
        else if(k=="rpc_tls_cert")   out.rpc_tls_cert   = v;
        else if(k=="rpc_tls_key")    out.rpc_tls_key    = v;
        else if(k=="rpc_tls_client_ca") out.rpc_tls_client_ca = v;

        // Stratum mining pool
        else if(k=="stratum_enable") out.stratum_enable = (v=="1"||v=="true");
        else if(k=="stratum_port") safe_parse_uint16(v, out.stratum_port, "stratum_port");
        else if(k=="stratum_difficulty") safe_parse_double(v, out.stratum_difficulty, "stratum_difficulty");
        else if(k=="stratum_vardiff") out.stratum_vardiff = (v=="1"||v=="true");
    }
    return true;
}