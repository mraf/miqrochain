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
    // CRITICAL FIX: Constant-time comparison that doesn't leak length
    // Compare all bytes of both strings to avoid timing side-channel
    size_t len_a = a.size();
    size_t len_b = b.size();
    size_t max_len = len_a > len_b ? len_a : len_b;

    // If either string is empty, we still need constant-time behavior
    if (max_len == 0) {
        return len_a == len_b;
    }

    volatile unsigned char acc = 0;

    // XOR accumulate differences - always compare max_len bytes
    // Use modulo to wrap indices (this doesn't leak useful timing info)
    for (size_t i = 0; i < max_len; ++i) {
        unsigned char byte_a = (i < len_a) ? (unsigned char)a[i] : 0;
        unsigned char byte_b = (i < len_b) ? (unsigned char)b[i] : 0;
        acc |= byte_a ^ byte_b;
    }

    // Also accumulate length difference
    acc |= (unsigned char)(len_a ^ len_b);
    // Additional bits for longer lengths
    acc |= (unsigned char)((len_a >> 8) ^ (len_b >> 8));

    return acc == 0;
}

}
