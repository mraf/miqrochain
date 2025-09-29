#include "rpc_auth.h"
#include <cstdlib>
#include <fstream>

namespace miq {

static bool read_file(const std::string& p, std::string& out){
    std::ifstream f(p, std::ios::binary);
    if(!f) return false;
    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    // trim trailing newline/spaces
    while(!s.empty() && (s.back()=='\n' || s.back()=='\r' || s.back()==' ' || s.back()=='\t')) s.pop_back();
    out = s;
    return true;
}

bool rpc_load_expected_token(const std::string& datadir, std::string& out_token, std::string* err){
    // 1) Env
    if(const char* e = std::getenv("MIQ_RPC_TOKEN")){
        out_token = e;
        if(!out_token.empty()) return true;
    }
    // 2) Cookie file
    if(read_file(datadir + "/.cookie", out_token) && !out_token.empty()){
        return true;
    }
    if(err) *err = "no RPC token found (env MIQ_RPC_TOKEN empty and .cookie missing)";
    return false;
}

bool rpc_parse_bearer(const std::string& v, std::string& out_token){
    // Accept: "Bearer <token>" (case-insensitive on 'Bearer', tolerant on spaces)
    size_t i = 0;
    while(i < v.size() && (v[i]==' ' || v[i]=='\t')) ++i;
    if (i+6 > v.size()) return false;
    // lowercase compare for "bearer"
    std::string pfx = v.substr(i, 6);
    for (auto& c : pfx) c = (char)tolower((unsigned char)c);
    if (pfx != "bearer") return false;
    i += 6;
    while(i < v.size() && (v[i]==' ' || v[i]=='\t')) ++i;
    if (i >= v.size()) return false;
    out_token = v.substr(i);
    return !out_token.empty();
}

bool rpc_timing_safe_eq(const std::string& a, const std::string& b){
    // XOR-accumulate all bytes; same length required to avoid length leak.
    if (a.size() != b.size()) return false;
    unsigned char acc = 0;
    for (size_t i=0;i<a.size();++i){
        acc |= (unsigned char)(a[i] ^ b[i]);
    }
    return acc == 0;
}

}
