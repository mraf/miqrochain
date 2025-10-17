#include "constants.h"
#include "block.h"
#include "tx.h"
#include "serialize.h"
#include "sha256.h"
#include "merkle.h"
#include "hex.h"
#include "base58check.h"
#include "hash160.h"
#include "difficulty.h"
#include "supply.h"
#include "hasher.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cctype>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <map>
#include <set>
#include <cmath>
#include <limits>
#include <ctime>
#include <array>

#if defined(_WIN32)
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <direct.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  using socket_t = SOCKET;
  #define miq_closesocket closesocket
  static void miq_sleep_ms(unsigned ms){ Sleep(ms); }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <sys/time.h>
  #include <sys/resource.h>
  #include <sys/stat.h>
  #include <sched.h>
  using socket_t = int;
  #define miq_closesocket ::close
  static void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
#endif

// -------- OpenCL (optional) --------------------------------------------------
// Default-on, but disable gracefully if headers aren't present.
#ifndef MIQ_ENABLE_OPENCL
#define MIQ_ENABLE_OPENCL 1
#endif

#if defined(MIQ_ENABLE_OPENCL)
  #ifndef CL_TARGET_OPENCL_VERSION
  #define CL_TARGET_OPENCL_VERSION 120
  #endif

  #if defined(__has_include)
    #if defined(__APPLE__)
      #if __has_include(<OpenCL/opencl.h>)
        #include <OpenCL/opencl.h>
      #else
        #undef MIQ_ENABLE_OPENCL
      #endif
    #else
      #if __has_include(<CL/cl.h>)
        #include <CL/cl.h>
      #else
        #undef MIQ_ENABLE_OPENCL
      #endif
    #endif
  #else
    #if defined(__APPLE__)
      #include <OpenCL/opencl.h)
    #else
      #include <CL/cl.h>
    #endif
  #endif
#endif

// -------- OpenSSL (for HD wallet: RNG, HMAC, PBKDF2, SHA256/RIPEMD, EC) -----
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

using namespace miq;

// ===== brand & color =========================================================
static bool g_use_ansi = true;
static inline std::string C(const char* code){ return g_use_ansi ? std::string("\x1b[")+code+"m" : std::string(); }
static inline std::string R(){ return g_use_ansi ? std::string("\x1b[0m") : std::string(); }
static inline const char* CLS(){ return g_use_ansi ? "\x1b[2J\x1b[H" : ""; }

// BIG ASCII banner (cyan). This spells MiQ.
static const char* kChronenMinerBanner[] = {
"  __  __ _                                                                                      ",
" |  \\/  |                                                                                       ",
" | \\  / |                                                                                       ",
" | |\\/| |                                                                                      ",
" | |   | |                                                                                      ",
" |_|   |_|                                                                                      ",
};

// ===== helpers ===============================================================
static const uint64_t MIQ_COIN_UNITS = 100000000ULL; // 1 MIQ = 1e8 base units
static uint32_t kCoinbaseMaturity = 100; // adjust if your chain uses a different value

static inline void trim(std::string& s){
    size_t i=0,j=s.size();
    while(i<j && std::isspace((unsigned char)s[i])) ++i;
    while(j>i && std::isspace((unsigned char)s[j-1])) --j;
    s.assign(s.data()+i, j-i);
}
static std::string default_cookie_path(){
#ifdef _WIN32
    char* v=nullptr; size_t len=0;
    if (_dupenv_s(&v,&len,"APPDATA")==0 && v && len){
        std::string p(v); free(v);
        return p + "\\Miqrochain\\.cookie";
    }
    return "C:\\Miqrochain\\.cookie";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if(home && *home) return std::string(home) + "/Library/Application Support/Miqrochain/.cookie";
    return "./.cookie";
#else
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/Miqrochain/.cookie";
    const char* home = std::getenv("HOME");
    if(home && *home) return std::string(home) + "/.miqrochain/.cookie";
    return "./.cookie";
#endif
}
static bool read_all_file(const std::string& path, std::string& out){
    FILE* f = fopen(path.c_str(),"rb");
    if(!f) return false;
    std::string s; char buf[4096];
    while(true){ size_t n=fread(buf,1,sizeof(buf),f); if(!n) break; s.append(buf,n); }
    fclose(f);
    while(!s.empty() && (s.back()=='\r'||s.back()=='\n'||s.back()==' '||s.back()=='\t')) s.pop_back();
    out = std::move(s); return true;
}
static std::string to_hex_s(const std::vector<uint8_t>& v){ return miq::to_hex(v); }
static std::vector<uint8_t> from_hex_s(const std::string& h){ return miq::from_hex(h); }

// ===== NEW: seed uniqueness cache helpers ===================================
static std::string homedir_path(){
#if defined(_WIN32)
    char* v=nullptr; size_t len=0;
    if (_dupenv_s(&v,&len,"APPDATA")==0 && v && len){
        std::string p(v); free(v);
        return p;
    }
    return ".";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    return (home && *home) ? std::string(home) : std::string(".");
#else
    const char* home = std::getenv("HOME");
    return (home && *home) ? std::string(home) : std::string(".");
#endif
}
static std::string seeds_seen_path(){
#if defined(_WIN32)
    return homedir_path() + "\\Miqrochain\\seeds_seen.bin";
#elif defined(__APPLE__)
    return homedir_path() + "/Library/Application Support/Miqrochain/seeds_seen.bin";
#else
    return homedir_path() + "/.miqrochain/seeds_seen.bin";
#endif
}
static std::string parent_dir_of(const std::string& p){
    size_t s = p.find_last_of("/\\");
    if(s==std::string::npos) return std::string();
    return p.substr(0,s);
}
static void ensure_dir_simple(const std::string& dir){
    if(dir.empty()) return;
#if defined(_WIN32)
    _mkdir(dir.c_str());
#else
    mkdir(dir.c_str(), 0700);
#endif
}
static bool seen_seed_hash(const uint8_t h[32]){
    std::string path = seeds_seen_path();
    FILE* f = fopen(path.c_str(),"rb");
    if(!f) return false;
    uint8_t buf[32];
    while(fread(buf,1,32,f)==32){
        if(std::memcmp(buf,h,32)==0){ fclose(f); return true; }
    }
    fclose(f);
    return false;
}
static void append_seen_seed_hash(const uint8_t h[32]){
    std::string path = seeds_seen_path();
    ensure_dir_simple(parent_dir_of(path));
    FILE* f = fopen(path.c_str(),"ab");
    if(!f) return;
    fwrite(h,1,32,f);
    fclose(f);
}

// ===== JSON helpers ==========================================================
static inline bool json_has_error(const std::string& json){
    size_t e = json.find("\"error\"");
    if(e==std::string::npos) return false;
    size_t r = json.find("\"result\"");
    return (r==std::string::npos) || (e < r);
}
static bool json_find_string(const std::string& json, const std::string& key, std::string& out){
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if(p==std::string::npos) return false;
    p += pat.size();
    while(p<json.size() && std::isspace((unsigned char)json[p])) ++p;
    if(p>=json.size() || json[p]!='"') return false;
    ++p;
    size_t q = p;
    while(q<json.size()){
        if(json[q]=='\\') { q+=2; continue; }
        if(json[q]=='"') break;
        ++q;
    }
    if(q<=p) return false;
    out = json.substr(p, q-p);
    return true;
}
static bool json_find_number(const std::string& json, const std::string& key, long long& out){
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if(p==std::string::npos) return false;
    p += pat.size();
    while(p<json.size() && std::isspace((unsigned char)json[p])) ++p;
    size_t q = p;
    while(q<json.size() && (std::isdigit((unsigned char)json[q])||json[q]=='-'||json[q]=='+' )) ++q;
    if(q==p) return false;
    out = std::strtoll(json.c_str()+p, nullptr, 10);
    return true;
}
static bool json_find_double(const std::string& json, const std::string& key, double& out){
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if(p==std::string::npos) return false;
    p += pat.size();
    while(p<json.size() && std::isspace((unsigned char)json[p])) ++p;
    size_t q = p;
    while(q<json.size()
       && (std::isdigit((unsigned char)json[q])||json[q]=='-'||json[q]=='+'||json[q]=='.'||json[q]=='e'||json[q]=='E')) ++q;
    if(q==p) return false;
    out = std::strtod(json.c_str()+p, nullptr);
    return true;
}
static bool json_extract_top_string(const std::string& body, std::string& out){
    if(body.size()>=2 && body.front()=='"' && body.back()=='"'){
        out = body.substr(1, body.size()-2);
        return true;
    }
    return false;
}

// ===== difficulty/target =====================================================
static void bits_to_target_be(uint32_t bits, uint8_t out[32]){
    std::memset(out,0,32);
    const uint32_t exp = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;
    if(!mant) return;
    if(exp <= 3){
        uint32_t mant2 = mant >> (8*(3-exp));
        out[29] = uint8_t((mant2 >> 16) & 0xff);
        out[30] = uint8_t((mant2 >>  8) & 0xff);
        out[31] = uint8_t((mant2 >>  0) & 0xff);
    }else{
        int pos = int(32) - int(exp);
        if(pos < 0) { out[0]=out[1]=out[2]=0xff; return; }
        if(pos > 29) pos = 29;
        out[pos+0] = uint8_t((mant >> 16) & 0xff);
        out[pos+1] = uint8_t((mant >>  8) & 0xff);
        out[pos+2] = uint8_t((mant >>  0) & 0xff);
    }
}
static inline bool compact_bits_valid(uint32_t bits){
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    return exp >= 3 && mant != 0;
}
static inline uint32_t sanitize_bits(uint32_t bits){
    return compact_bits_valid(bits) ? bits : miq::GENESIS_BITS;
}
static inline bool meets_target_be_raw(const uint8_t hash32[32], uint32_t bits){
    uint8_t T[32]; bits_to_target_be(bits, T);
    bool allz = true; for(int i=0;i<32;i++) if(T[i]) { allz=false; break; }
    if(allz) return false;
    return std::memcmp(hash32, T, 32) <= 0;
}
static double difficulty_from_bits(uint32_t bits){
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (!mant) return 0.0;
    uint32_t bexp  = miq::GENESIS_BITS >> 24;
    uint32_t bmant = miq::GENESIS_BITS & 0x007fffff;
    long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
    long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
    if (target <= 0.0L) return 0.0;
    long double D = base_target / target;
    if (D < 0.0L) D = 0.0L;
    return (double)D;
}

// ===== little-endian store ===================================================
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x){
    v.push_back(uint8_t((x>>0)&0xff));
    v.push_back(uint8_t((x>>8)&0xff));
    v.push_back(uint8_t((x>>16)&0xff));
    v.push_back(uint8_t((x>>24)&0xff));
}
static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x){
    v.push_back(uint8_t((x>>0 )&0xff)); v.push_back(uint8_t((x>>8 )&0xff));
    v.push_back(uint8_t((x>>16)&0xff)); v.push_back(uint8_t((x>>24)&0xff));
    v.push_back(uint8_t((x>>32)&0xff)); v.push_back(uint8_t((x>>40)&0xff));
    v.push_back(uint8_t((x>>48)&0xff)); v.push_back(uint8_t((x>>56)&0xff));
}
static inline void store_u64_le(uint8_t* p, uint64_t x){
    p[0]=uint8_t((x>>0 )&0xff); p[1]=uint8_t((x>>8 )&0xff);
    p[2]=uint8_t((x>>16)&0xff); p[3]=uint8_t((x>>24)&0xff);
    p[4]=uint8_t((x>>32)&0xff); p[5]=uint8_t((x>>40)&0xff);
    p[6]=uint8_t((x>>48)&0xff); p[7]=uint8_t((x>>56)&0xff);
}

// ===== minimal HTTP/JSON-RPC ================================================
struct HttpResp { int code{0}; std::string body; };

static bool http_post(const std::string& host, uint16_t port, const std::string& path,
                      const std::string& auth_token, const std::string& json, HttpResp& out)
{
#if defined(_WIN32)
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    addrinfo* res=nullptr; char ps[16]; std::snprintf(ps,sizeof(ps), "%u", (unsigned)port);
    if(getaddrinfo(host.c_str(), ps, &hints, &res)!=0) {
#if defined(_WIN32)
        WSACleanup();
#endif
        return false;
    }
    socket_t s =
#if defined(_WIN32)
        INVALID_SOCKET;
#else
        -1;
#endif
    for(addrinfo* ai=res; ai; ai=ai->ai_next){
        s = (socket_t)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#if defined(_WIN32)
        if(s==INVALID_SOCKET) continue;
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = INVALID_SOCKET;
#else
        if(s<0) continue;
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = -1;
#endif
    }
    freeaddrinfo(res);
#if defined(_WIN32)
    if(s==INVALID_SOCKET){ WSACleanup(); return false; }
#else
    if(s<0) return false;
#endif

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << json.size() << "\r\n";
    if(!auth_token.empty()){
        req << "Authorization: Bearer " << auth_token << "\r\n";
        req << "X-Auth-Token: " << auth_token << "\r\n";
    }
    req << "Connection: close\r\n\r\n" << json;

    std::string data = req.str();
    size_t off=0;
    while(off < data.size()){
#if defined(_WIN32)
        int n = send(s, data.data()+off, (int)(data.size()-off), 0);
        if(n<=0){ miq_closesocket(s); WSACleanup(); return false; }
#else
        int n = ::send(s, data.data()+off, (int)(data.size()-off), 0);
        if(n<=0){ miq_closesocket(s); return false; }
#endif
        off += (size_t)n;
    }

    std::string resp; char buf[4096];
    while(true){
#if defined(_WIN32)
        int n = recv(s, buf, (int)sizeof(buf), 0);
#else
        int n = ::recv(s, buf, (int)sizeof(buf), 0);
#endif
        if(n<=0) break;
        resp.append(buf, (size_t)n);
    }
    miq_closesocket(s);
#if defined(_WIN32)
    WSACleanup();
#endif

    size_t sp = resp.find(' ');
    if(sp == std::string::npos) return false;
    int code = std::atoi(resp.c_str()+sp+1);
    size_t hdr_end = resp.find("\r\n\r\n");
    std::string body = (hdr_end==std::string::npos)? std::string() : resp.substr(hdr_end+4);
    out.code = code; out.body = std::move(body);
    return true;
}
static std::string json_escape(const std::string& s){
    std::ostringstream o; o << '"';
    for(unsigned char c : s){
        if(c=='"'||c=='\\') o << '\\' << c;
        else if(c=='\b') o << "\\b";
        else if(c=='\f') o << "\\f";
        else if(c=='\n') o << "\\n";
        else if(c=='\r') o << "\\r";
        else if(c=='\t') o << "\\t";
        else if(c<0x20) { o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)c; }
        else o << c;
    }
    o << '"'; return o.str();
}
static std::string rpc_build(const std::string& method, const std::string& params_json){
    static std::atomic<uint64_t> g_id{1};
    std::ostringstream o;
    o << "{\"jsonrpc\":\"2.0\",\"id\":" << g_id.fetch_add(1)
      << ",\"method\":" << json_escape(method)
      << ",\"params\":" << (params_json.empty()?"[]":params_json) << "}";
    return o.str();
}

// ===== RPC wrappers ==========================================================
struct TipInfo { uint64_t height{0}; std::string hash_hex; uint32_t bits{0}; int64_t time{0}; };

static bool rpc_gettipinfo(const std::string& host, uint16_t port, const std::string& auth, TipInfo& out){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("gettipinfo","[]"), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    long long h=0,b=0,t=0; std::string hh;
    if(!json_find_number(r.body,"height",h)) return false;
    if(!json_find_string(r.body,"hash",hh)) return false;
    if(!json_find_number(r.body,"bits",b)) return false;
    if(!json_find_number(r.body,"time",t)) return false;
    out.height=(uint64_t)h; out.hash_hex=hh; out.bits=sanitize_bits((uint32_t)b); out.time=(int64_t)t;
    return true;
}
static bool rpc_getminerstats(const std::string& host, uint16_t port, const std::string& auth, double& out_net_hs){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getminerstats","[]"), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    if(json_find_double(r.body, "hps", out_net_hs)) return true;
    if(json_find_double(r.body, "network_hash_ps", out_net_hs)) return true;
    return false;
}
static bool rpc_getblockhash(const std::string& host, uint16_t port, const std::string& auth, uint64_t height, std::string& out){
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblockhash", ps.str()), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    if(json_find_string(r.body, "result", out)) return true;
    if(json_extract_top_string(r.body, out)) return true;
    return false;
}
static bool rpc_getblock_header_time(const std::string& host, uint16_t port, const std::string& auth, const std::string& hh, long long& out_time){
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    long long t=0;
    if(json_find_number(r.body, "time", t)) { out_time=t; return true; }
    return false;
}
struct LastBlockInfo {
    uint64_t height{0};
    std::string hash_hex;
    uint64_t txs{0};
    std::string coinbase_txid_hex;
    std::vector<uint8_t> coinbase_pkh;
    uint64_t reward_value{0}; // raw from node; units ambiguous
};
static bool rpc_getblock_overview(const std::string& host, uint16_t port, const std::string& auth,
                                  uint64_t height, LastBlockInfo& out)
{
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    std::string hh; long long txs=0;
    if(!json_find_string(r.body, "hash", hh)) return false;
    if(!json_find_number(r.body, "txs", txs)) return false;
    out.height = height; out.hash_hex = hh; out.txs = (uint64_t)txs;
    return true;
}
static bool rpc_getcoinbaserecipient(const std::string& host, uint16_t port, const std::string& auth,
                                     uint64_t height, LastBlockInfo& io)
{
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getcoinbaserecipient", ps.str()), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    std::string pkh_hex, txid_hex; long long val=0;
    if(!json_find_string(r.body, "pkh", pkh_hex)) return false;
    (void)json_find_number(r.body, "value", val);
    if(json_find_string(r.body, "txid", txid_hex)) io.coinbase_txid_hex = txid_hex;
    io.coinbase_pkh = from_hex_s(pkh_hex);
    io.reward_value = (uint64_t)((val<0)?0:val);
    return true;
}
static double estimate_network_hashps(const std::string& host, uint16_t port, const std::string& auth, uint64_t tip_height, uint32_t bits){
    const int LOOKBACK = 64;
    if(tip_height <= 1) return 0.0;
    uint64_t start_h = (tip_height > (uint64_t)LOOKBACK) ? (tip_height - LOOKBACK) : 1;
    long long t_first=0, t_last=0;
    std::string hh_first, hh_last;
    if(!rpc_getblockhash(host, port, auth, start_h, hh_first)) return 0.0;
    if(!rpc_getblockhash(host, port, auth, tip_height, hh_last)) return 0.0;
    if(!rpc_getblock_header_time(host, port, auth, hh_first, t_first)) return 0.0;
    if(!rpc_getblock_header_time(host, port, auth, hh_last, t_last)) return 0.0;
    double dt = (double)(t_last - t_first);
    if(dt <= 0.0) return 0.0;

    double D = difficulty_from_bits(bits);
    double blocks = (double)(tip_height - start_h);
    double avg_spacing = dt / std::max(1.0, blocks);
    if (avg_spacing <= 0.0) return 0.0;
    const double two32 = 4294967296.0;
    return D * (two32 / avg_spacing);
}
static bool rpc_submitblock_verbose(const std::string& host, uint16_t port, const std::string& auth,
                                    std::string& out_body, const std::string& method, const std::string& hexblk){
    std::ostringstream ps; ps << "[\"" << hexblk << "\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build(method, ps.str()), r)) return false;
    out_body = r.body;
    if(r.code != 200) return false;
    return !json_has_error(r.body);
}
static bool rpc_submitblock_any(const std::string& host, uint16_t port, const std::string& auth,
                                std::string& accept_body, std::string& reject_body,
                                const std::string& hexblk)
{
    std::string body;
    if(rpc_submitblock_verbose(host,port,auth,body,"submitblock",hexblk)) { accept_body=body; return true; }
    if(!body.empty()) reject_body = body;
    if(rpc_submitblock_verbose(host,port,auth,body,"submitrawblock",hexblk)) { accept_body=body; return true; }
    if(!body.empty()) reject_body = body;
    if(rpc_submitblock_verbose(host,port,auth,body,"sendrawblock",hexblk)) { accept_body=body; return true; }
    if(!body.empty()) reject_body = body;
    return false;
}
// Optional: write a log line to node console (if your node implements this)
static void rpc_minerlog_best_effort(const std::string& host, uint16_t port, const std::string& auth,
                                     const std::string& msg){
    std::ostringstream ps;
    ps << "[\"" << msg << "\"]";
    HttpResp r;
    (void)http_post(host, port, "/", auth, rpc_build("minerlog", ps.str()), r);
}

// === Lifetime total received to address (best-effort) ========================
static bool rpc_result_double(const std::string& host, uint16_t port, const std::string& auth,
                              const std::string& method, const std::string& params, double& outd){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build(method, params), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    return json_find_double(r.body, "result", outd);
}
static bool rpc_result_u64_by_key(const std::string& host, uint16_t port, const std::string& auth,
                                  const std::string& method, const std::string& params,
                                  const std::string& key, uint64_t& outv){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build(method, params), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    long long v=0;
    if(json_find_number(r.body, key, v)){ outv = (v<0?0:(uint64_t)v); return true; }
    return false;
}

// choose a scaling of raw -> base units close to expected (handles 0.1×/1×/10× etc)
static uint64_t normalize_to_expected(uint64_t raw, uint64_t expected){
    if(raw==0 || expected==0) return raw;
    const long double R = (long double)raw;
    const long double E = (long double)expected;
    const long double UNIT = (long double)MIQ_COIN_UNITS;

    const long double muls[] = {
        1.0L,
        UNIT,              // coins -> base
        UNIT/10.0L,        // deci-coin -> base
        UNIT*10.0L,        // 10-coins -> base
        10.0L, 100.0L,     // raw likely centi/milli base
        0.1L, 0.01L
    };
    long double best_val = R;
    long double best_err = fabsl(E - R);
    for(long double m : muls){
        long double v = R * m;
        long double err = fabsl(E - v);
        if(err < best_err){ best_err = err; best_val = v; }
    }
    if(best_val < 0) return 0;
    long double mx = (long double)std::numeric_limits<uint64_t>::max();
    if(best_val > mx) return std::numeric_limits<uint64_t>::max();
    return (uint64_t) llround(best_val);
}

static bool rpc_get_received_total_baseunits(const std::string& host, uint16_t port, const std::string& auth,
                                             const std::string& address, uint64_t& out_base)
{
    // 1) Core-like: getreceivedbyaddress returns coins (double)
    {
        double d=0.0;
        std::ostringstream ps; ps << "[\"" << address << "\",0]";
        if(rpc_result_double(host,port,auth,"getreceivedbyaddress",ps.str(),d)){
            long double v = (long double)d * (long double)MIQ_COIN_UNITS;
            if(v < 0) v = 0;
            long double mx = (long double)std::numeric_limits<uint64_t>::max();
            if(v > mx) v = mx;
            out_base = (uint64_t) llround(v);
            return true;
        }
    }
    {
        double d=0.0;
        std::ostringstream ps; ps << "[\"" << address << "\"]";
        if(rpc_result_double(host,port,auth,"getreceivedbyaddress",ps.str(),d)){
            long double v = (long double)d * (long double)MIQ_COIN_UNITS;
            if(v < 0) v = 0;
            long double mx = (long double)std::numeric_limits<uint64_t>::max();
            if(v > mx) v = mx;
            out_base = (uint64_t) llround(v);
            return true;
        }
    }
    // 2) Address-index style: getaddressbalance {"addresses":[...]} -> "balance" (base units)
    {
        uint64_t bal=0;
        std::ostringstream ps; ps << "[{\"addresses\":[\"" << address << "\"]}]";
        if(rpc_result_u64_by_key(host,port,auth,"getaddressbalance",ps.str(),"balance",bal)){
            out_base = bal; return true;
        }
    }
    // 3) Fallbacks often return base units under result
    {
        double d=0.0; std::ostringstream ps; ps << "[\"" << address << "\"]";
        if(rpc_result_double(host,port,auth,"getaddressreceived",ps.str(),d) ||
           rpc_result_double(host,port,auth,"getaddrreceived",ps.str(),d)    ||
           rpc_result_double(host,port,auth,"getreceived",ps.str(),d)        ||
           rpc_result_double(host,port,auth,"getaddresstotalreceived",ps.str(),d))
        {
            if(d > 1e6) { // likely already base units
                long double v = d; if(v < 0) v = 0;
                long double mx = (long double)std::numeric_limits<uint64_t>::max();
                if(v > mx) v = mx;
                out_base = (uint64_t) llround(v);
                return true;
            } else {
                long double v = (long double)d * (long double)MIQ_COIN_UNITS;
                if(v < 0) v = 0;
                long double mx = (long double)std::numeric_limits<uint64_t>::max();
                if(v > mx) v = mx;
                out_base = (uint64_t) llround(v);
                return true;
            }
        }
    }
    return false;
}

// ===== template & txs ========================================================
struct MinerTemplate {
    uint64_t height{0};
    std::vector<uint8_t> prev_hash;
    uint32_t bits{0};
    int64_t  time{0};
    size_t   max_block_bytes{900*1024};
    struct TxTpl{ std::string hex; uint64_t fee{0}; };
    std::vector<TxTpl> txs;
};

static bool rpc_getminertemplate(const std::string& host, uint16_t port, const std::string& auth, MinerTemplate& out){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getminertemplate","[]"), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;

    long long h=0, b=0, adjb=0, t=0, maxb=0;
    std::string ph;
    if(!json_find_number(r.body, "height", h)) return false;
    if(!json_find_string(r.body, "prev_hash", ph)) return false;
    if(!json_find_number(r.body, "bits", b)) return false;
    (void)json_find_number(r.body, "adjusted_bits", adjb);
    if(!json_find_number(r.body, "time", t)) return false;
    if(json_find_number(r.body, "max_block_bytes", maxb)) out.max_block_bytes = (size_t)maxb;

    out.height = (uint64_t)h;
    out.prev_hash = from_hex_s(ph);
    if(out.prev_hash.size()!=32) return false;

    uint32_t chosen = (adjb>0) ? (uint32_t)adjb : (uint32_t)b;
    out.bits = sanitize_bits(chosen);
    out.time = (int64_t)t;

    // optional tx list
    size_t p = r.body.find("\"txs\"");
    if(p==std::string::npos) return true;
    p = r.body.find('[', p);
    if(p==std::string::npos) return false;
    size_t q = p; int depth=0; bool ok=false;
    while(q<r.body.size()){
        if(r.body[q]=='[') depth++;
        else if(r.body[q]==']'){ depth--; if(depth==0){ ok=true; ++q; break; } }
        ++q;
    }
    if(!ok) return false;
    std::string arr = r.body.substr(p, q-p);

    size_t pos=0;
    while(true){
        size_t ob = arr.find('{', pos);
        if(ob==std::string::npos) break;
        size_t oe = ob; int d=0; bool ok2=false;
        while(oe<arr.size()){
            if(arr[oe]=='{') d++;
            else if(arr[oe]=='}'){ d--; if(d==0){ ok2=true; ++oe; break; } }
            ++oe;
        }
        if(!ok2) break;
        std::string obj = arr.substr(ob, oe-ob);
        std::string hx; long long fee=0;
        if(!json_find_string(obj, "hex", hx)) json_find_string(obj, "raw", hx);
        json_find_number(obj, "fee", fee);
        if(!hx.empty()) out.txs.push_back({hx, (uint64_t)(fee<0?0:fee)});
        pos = oe;
    }
    return true;
}

// ===== address helpers & MIQ formatting =====================================
static bool parse_p2pkh(const std::string& addr, std::vector<uint8_t>& out_pkh){
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!miq::base58check_decode(addr, ver, payload)) return false;
    if(ver != miq::VERSION_P2PKH) return false;
    if(payload.size() != 20) return false;
    out_pkh = std::move(payload);
    return true;
}
static std::string pkh_to_address(const std::vector<uint8_t>& pkh){
    return miq::base58check_encode(miq::VERSION_P2PKH, pkh);
}
static std::string fmt_miq_amount(uint64_t base_units){
    std::ostringstream o;
    if (base_units % (MIQ_COIN_UNITS/100) == 0){
        uint64_t whole = base_units / MIQ_COIN_UNITS;
        uint64_t cents = (base_units / (MIQ_COIN_UNITS/100)) % 100;
        o << whole << '.' << std::setw(2) << std::setfill('0') << cents;
    } else {
        o << std::fixed << std::setprecision(8)
          << (double)base_units / (double)MIQ_COIN_UNITS;
    }
    o << " MIQ";
    return o.str();
}

// ===== NEW: Mnemonic (12/24 words) + BIP39 seed + BIP32 -> 5 MIQ addresses ===

// small syllable tables to algorithmically produce 2048 pronounceable words
static const char* kSyl1[] = {
  "ba","be","bi","bo","bu","ca","ce","ci","co","cu","da","de","di","do","du",
  "fa","fe","fi","fo","fu","ga","ge","gi","go","gu","ha","he","hi","ho","hu",
  "ja","je","ji","jo"
}; // 32
static const char* kSyl2[] = {
  "la","le","li","lo","lu","ma","me","mi","mo","mu","na","ne","ni","no","nu",
  "pa","pe","pi","po","pu","ra","re","ri","ro","ru","sa","se","si","so","su",
  "ta","te","ti","to","tu","va","ve","vi","vo","vu","za","ze","zi","zo","zu",
  "kra","kre","kri","kro","kru","pla","ple","pli","plo","plu","tra","tre","tri","tro","tru",
  "bra","bre","bri","bro","bru"
}; // 64
static std::string pseudo_word_from_index(uint16_t idx){ // 0..2047
    uint16_t a = idx & 31u;       // 0..31
    uint16_t b = (idx >> 5) & 63; // 0..63
    return std::string(kSyl1[a]) + kSyl2[b];
}
static bool csprng_bytes(uint8_t* out, size_t n){
    return RAND_bytes(out, (int)n)==1;
}
static void ossl_sha256_once(const uint8_t* d, size_t n, uint8_t out[32]){
    ::SHA256(d, n, out); // disambiguate from miq::SHA256
}
static bool make_mnemonic_words(size_t words, std::vector<std::string>& out_words, std::vector<uint8_t>& out_entropy){
    if(words!=12 && words!=24) return false;
    const size_t ENT = (words==12)? 16 : 32; // bytes
    std::vector<uint8_t> ent(ENT);

    // try to avoid duplicates with a simple on-disk hash list
    for(int tries=0; tries<8; ++tries){
        if(!csprng_bytes(ent.data(), ent.size())) continue;
        uint64_t t = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
        for(size_t i=0;i<sizeof(t) && i<ent.size();++i) ent[i]^=((uint8_t*)&t)[i];
#if !defined(_WIN32)
        uint32_t pid = (uint32_t)getpid();
#else
        uint32_t pid = (uint32_t)GetCurrentProcessId();
#endif
        for(size_t i=0;i<sizeof(pid) && i<ent.size();++i) ent[ent.size()-1-i]^=((uint8_t*)&pid)[i];

        uint8_t h[32]; ossl_sha256_once(ent.data(), ent.size(), h);
        if(!seen_seed_hash(h)){ append_seen_seed_hash(h); break; }
        if(tries==7){ append_seen_seed_hash(h); }
    }

    // checksum bits (BIP39 style): CS = ENT/4 bits from SHA256(ent)
    uint8_t h[32]; ossl_sha256_once(ent.data(), ent.size(), h);
    const size_t ENTbits = ENT*8;
    const size_t CSbits  = ENTbits / 32;

    std::vector<int> bits; bits.reserve(ENTbits + CSbits);
    for(size_t i=0;i<ENT;i++)
        for(int b=7;b>=0;--b) bits.push_back( (ent[i]>>b)&1 );
    for(size_t b=0;b<CSbits;b++)
        bits.push_back( (h[0] >> (7 - (int)b)) & 1 );

    size_t nwords = bits.size() / 11;
    out_words.clear(); out_words.reserve(nwords);
    for(size_t i=0;i<nwords;i++){
        uint16_t idx=0;
        for(int j=0;j<11;j++) idx = (uint16_t)((idx<<1) | bits[i*11 + j]);
        out_words.push_back(pseudo_word_from_index((uint16_t)(idx & 2047)));
    }
    out_entropy = std::move(ent);
    return true;
}
static std::string mnemonic_join(const std::vector<std::string>& ws){
    std::ostringstream o;
    for(size_t i=0;i<ws.size();++i){ if(i) o << ' '; o << ws[i]; }
    return o.str();
}
static void mnemonic_to_seed_BIP39(const std::string& mnemonic,
                                   const std::string& passphrase,
                                   std::vector<uint8_t>& out)
{
    const std::string salt = std::string("mnemonic") + passphrase;
    out.resize(64);
    PKCS5_PBKDF2_HMAC(mnemonic.c_str(), (int)mnemonic.size(),
                      (const unsigned char*)salt.data(), (int)salt.size(),
                      2048, EVP_sha512(), (int)out.size(), out.data());
}

// ===== NEW: BIP32 (OpenSSL) to derive 5 P2PKH addresses ======================
struct XPrv {
    BIGNUM* k;
    uint8_t chain[32];
    uint8_t depth;
    uint32_t child;
    uint8_t parent_fpr[4];
    XPrv(): k(BN_new()){ std::memset(chain,0,32); depth=0; child=0; std::memset(parent_fpr,0,4); }
    ~XPrv(){ if(k) BN_free(k); }
    XPrv(const XPrv&)=delete; XPrv& operator=(const XPrv&)=delete;
};
static EC_GROUP* secp_group(){
    static EC_GROUP* g = EC_GROUP_new_by_curve_name(NID_secp256k1);
    return g;
}
static const BIGNUM* secp_n(){
    static BIGNUM* n = nullptr;
    if(!n){
        n = BN_new();
        BN_hex2bn(&n, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    }
    return n;
}
static void ser32(uint32_t x, uint8_t out[4]){
    out[0]=(uint8_t)(x>>24); out[1]=(uint8_t)(x>>16); out[2]=(uint8_t)(x>>8); out[3]=(uint8_t)(x);
}
static void ser256(const BIGNUM* bn, uint8_t out[32]){
    std::memset(out,0,32);
    BN_bn2binpad(bn, out, 32);
}
static bool point_from_priv(const BIGNUM* k, std::vector<uint8_t>& out_compressed){
    EC_POINT* P = EC_POINT_new(secp_group());
    if(!P) return false;
    BN_CTX* ctx = BN_CTX_new();
    bool ok = (EC_POINT_mul(secp_group(), P, k, nullptr, nullptr, ctx)==1);
    if(!ok){ BN_CTX_free(ctx); EC_POINT_free(P); return false; }
    uint8_t buf[33];
    size_t len = EC_POINT_point2oct(secp_group(), P, POINT_CONVERSION_COMPRESSED, buf, sizeof(buf), ctx);
    BN_CTX_free(ctx); EC_POINT_free(P);
    if(len!=33) return false;
    out_compressed.assign(buf, buf+33);
    return true;
}

// UPDATED to use EVP (avoids OpenSSL 3.0 deprecation warning)
static void hash160(const uint8_t* data, size_t n, uint8_t out20[20]){
    unsigned int len = 0;
    uint8_t sha[32];

    EVP_MD_CTX* c1 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c1, EVP_sha256(), nullptr);
    EVP_DigestUpdate(c1, data, n);
    EVP_DigestFinal_ex(c1, sha, &len);
    EVP_MD_CTX_free(c1);

    EVP_MD_CTX* c2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c2, EVP_ripemd160(), nullptr);
    EVP_DigestUpdate(c2, sha, 32);
    EVP_DigestFinal_ex(c2, out20, &len);
    EVP_MD_CTX_free(c2);
}

static bool xprv_from_seed(const std::vector<uint8_t>& seed, XPrv& out){
    uint8_t I[64]; unsigned int L=64;
    HMAC(EVP_sha512(), "Bitcoin seed", 12, seed.data(), (int)seed.size(), I, &L);
    if(L!=64) return false;
    BIGNUM* Il = BN_bin2bn(I, 32, nullptr);
    if(BN_is_zero(Il) || BN_cmp(Il, secp_n())>=0){ BN_free(Il); return false; }
    BN_copy(out.k, Il);
    std::memcpy(out.chain, I+32, 32);
    out.depth = 0; out.child=0; std::memset(out.parent_fpr,0,4);
    BN_free(Il);
    return true;
}
static void fingerprint_from_pub(const std::vector<uint8_t>& pub, uint8_t fpr[4]){
    uint8_t h20[20]; hash160(pub.data(), pub.size(), h20);
    std::memcpy(fpr, h20, 4);
}
static bool xprv_ckd(XPrv& child, const XPrv& parent, uint32_t index, bool hardened){
    uint8_t data[1+32+4]; size_t dlen=0;
    std::vector<uint8_t> P;
    uint32_t idx = index;
    if(hardened){
        data[0]=0x00;
        ser256(parent.k, data+1);
        dlen=33;
        idx |= 0x80000000u;
    }else{
        if(!point_from_priv(parent.k, P)) return false;
        if(P.size()!=33) return false;
        std::memcpy(data, P.data(), 33); dlen=33;
    }
    ser32(idx, data+dlen); dlen+=4;

    uint8_t I[64]; unsigned int L=64;
    HMAC(EVP_sha512(), parent.chain, 32, data, (int)dlen, I, &L);
    if(L!=64) return false;

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* Il = BN_bin2bn(I, 32, nullptr);
    if(BN_is_zero(Il) || BN_cmp(Il, secp_n())>=0){ BN_free(Il); BN_CTX_free(ctx); return false; }

    BN_copy(child.k, Il);
    BN_mod_add(child.k, child.k, parent.k, secp_n(), ctx);
    std::memcpy(child.chain, I+32, 32);
    child.depth = parent.depth + 1;
    child.child = idx;

    if(P.empty()) point_from_priv(parent.k, P);
    fingerprint_from_pub(P, child.parent_fpr);

    BN_free(Il);
    BN_CTX_free(ctx);
    return true;
}
static bool derive_miq_addresses_from_seed(const std::vector<uint8_t>& seed,
                                           uint32_t coin_type,
                                           size_t how_many,
                                           std::vector<std::string>& out_addrs,
                                           std::vector<std::vector<uint8_t>>& out_pubkeys33)
{
    XPrv m; if(!xprv_from_seed(seed, m)) return false;
    XPrv m44; if(!xprv_ckd(m44, m, 44, true)) return false;
    XPrv m44c; if(!xprv_ckd(m44c, m44, coin_type, true)) return false;
    XPrv acct; if(!xprv_ckd(acct, m44c, 0, true)) return false;
    XPrv ext;  if(!xprv_ckd(ext, acct, 0, false)) return false;

    out_addrs.clear(); out_pubkeys33.clear();
    for(size_t i=0;i<how_many;i++){
        XPrv ch; if(!xprv_ckd(ch, ext, (uint32_t)i, false)) return false;
        std::vector<uint8_t> pub;
        if(!point_from_priv(ch.k, pub)) return false;
        uint8_t h20[20]; hash160(pub.data(), pub.size(), h20);
        std::vector<uint8_t> pkh(h20, h20+20);
        out_addrs.push_back(miq::base58check_encode(miq::VERSION_P2PKH, pkh));
        out_pubkeys33.push_back(std::move(pub));
    }
    return true;
}

// ===== coinbase/merkle =======================================================
static Transaction make_coinbase(uint64_t height, uint64_t fees, const std::vector<uint8_t>& pkh){
    Transaction cbt;
    TxIn in; in.prev.txid = std::vector<uint8_t>(32,0); in.prev.vout = 0;

    uint64_t rnd = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    uint32_t now = (uint32_t)time(nullptr);
    std::vector<uint8_t> tag; tag.reserve(1+4+4+8);
    tag.push_back(0x01);
    for(int i=0;i<4;i++) tag.push_back(uint8_t((height>>(8*i))&0xff));
    for(int i=0;i<4;i++) tag.push_back(uint8_t((now   >>(8*i))&0xff));
    for(int i=0;i<8;i++) tag.push_back(uint8_t((rnd   >>(8*i))&0xff));
    in.sig = std::move(tag);
    cbt.vin.push_back(in);

    TxOut out; out.value = GetBlockSubsidy((uint32_t)height) + fees; out.pkh = pkh;
    cbt.vout.push_back(out);

    cbt.lock_time = (uint32_t)height;
    return cbt;
}
static std::vector<uint8_t> merkle_from(const std::vector<Transaction>& txs){
    std::vector<std::vector<uint8_t>> ids; ids.reserve(txs.size());
    for(const auto& t : txs) ids.push_back(t.txid());
    return miq::merkle_root(ids);
}

// ===== UI/state ==============================================================
static void spinner_circle_ascii(int phase, std::array<std::string,5>& rows){
    const int W = 13;
    rows = { std::string(W,' '), std::string(W,' '), std::string(W,' '),
             std::string(W,' '), std::string(W,' ') };

    struct P{ int r,c; };
    static const P pos[8] = { {0,6},{1,9},{2,12},{3,9},{4,6},{3,3},{2,0},{1,3} };
    for(int i=0;i<8;i++) rows[pos[i].r][pos[i].c] = '.';
    int k  = phase & 7;
    int k2 = (k + 7) & 7;
    rows[pos[k ].r][pos[k ].c] = 'o';
    rows[pos[k2].r][pos[k2].c] = '*';
}

struct CandidateStats {
    uint64_t height{0};
    std::string prev_hex;
    uint32_t bits{0};
    int64_t time{0};
    size_t txs{0};
    size_t size_bytes{0};
    uint64_t fees{0};
    uint64_t coinbase{0};
};
struct UIState {
    std::atomic<uint64_t> tries_total{0};
    std::atomic<uint64_t> mined_blocks{0};
    std::atomic<double>   net_hashps{0.0};
    std::atomic<double>   hps_now{0.0};
    std::atomic<double>   hps_smooth{0.0};
    std::atomic<uint64_t> tip_height{0};
    std::string tip_hash_hex;
    std::atomic<uint32_t> tip_bits{0};
    CandidateStats cand{};
    std::mutex mtx;
    LastBlockInfo lastblk{};
    std::string last_found_block_hash;
    std::string last_submit_msg;
    std::chrono::steady_clock::time_point last_submit_when{};
    std::vector<uint8_t> my_pkh;
    std::atomic<uint64_t> last_seen_height{0};
    std::atomic<bool> last_tip_was_mine{false};
    std::string last_winner_addr;
    std::mutex spark_mtx;
    std::vector<double> sparkline;
    std::atomic<uint64_t> round_start_tries{0};
    std::atomic<double>   round_expected_hashes{0.0};
    std::atomic<uint64_t> total_received_base{0};
    std::atomic<uint64_t> est_total_base{0};
    std::atomic<uint64_t> est_matured_base{0};
    std::atomic<uint64_t> est_scanned_height{0};
    std::mutex            myblks_mtx;
    std::set<uint64_t>    my_block_heights;
    std::vector<std::pair<uint64_t,uint64_t>> my_blocks;

    // NEW: live "next hash" preview buffer
    std::array<uint8_t,32> next_hash_sample{};
    std::mutex next_hash_mtx;

    // GPU telemetry
    std::atomic<bool>   gpu_available{false};
    std::string         gpu_platform;
    std::string         gpu_device;
    std::string         gpu_driver;
    std::atomic<double> gpu_hps_now{0.0};
    std::atomic<double> gpu_hps_smooth{0.0};
};

// Global hook for publishing hash previews from workers
static UIState* g_ui = nullptr;
static inline void publish_next_hash_sample(const uint8_t h[32]){
    if(!g_ui) return;
    std::lock_guard<std::mutex> lk(g_ui->next_hash_mtx);
    for(int i=0;i<32;i++) g_ui->next_hash_sample[i] = h[i];
}

static std::string fmt_hs(double v){
    const char* u[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s"};
    int i=0; while(v>=1000.0 && i<5){ v/=1000.0; ++i; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i]; return o.str();
}
static std::string spark_ascii(const std::vector<double>& xs){
    static const char bars[] = " .:-=+*#";
    if(xs.empty()) return "";
    double mn=xs[0], mx=xs[0];
    for(double v: xs){ mn = std::min(mn,v); mx = std::max(mx,v); }
    double span = (mx>mn)? (mx-mn) : 1.0;
    std::string s;
    for(double v: xs){
        int idx = (int)std::round( (v-mn)/span * 7.0 );
        if(idx<0) idx=0;
        if(idx>7) idx=7;
        s.push_back(bars[idx]);
    }
    return s;
}
static inline std::string pad_fit(const std::string& s, size_t width){
    if(s.size() >= width) return s.substr(0, width);
    return s + std::string(width - s.size(), ' ');
}
static inline std::string center_fit(const std::string& s, size_t width){
    if(s.size() >= width) return s.substr(0, width);
    size_t left = (width - s.size())/2;
    size_t right = width - s.size() - left;
    return std::string(left,' ') + s + std::string(right,' ');
}
static std::string fmt_eta(double seconds){
    if(!std::isfinite(seconds) || seconds <= 0) return std::string("--:--");
    long long s = (long long)std::llround(seconds);
    long long h = s / 3600; s %= 3600;
    long long m = s / 60;   s %= 60;
    std::ostringstream o;
    if(h>0) o << h << ":" << std::setw(2) << std::setfill('0') << m
              << ":" << std::setw(2) << std::setfill('0') << s;
    else    o << std::setw(2) << std::setfill('0') << m
              << ":" << std::setw(2) << std::setfill('0') << s;
    return o.str();
}

// ===== Intro splash (10s) + address prompt ==================================
static void show_intro_and_get_address(std::string& out_addr){
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) { DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004); }
#endif
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();
    int spin = 0;
    while(std::chrono::duration<double>(clock::now()-t0).count() < 10.0){
        std::ostringstream s;
        s << CLS();
        s << C("36;1");
        const size_t N = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
        for(size_t i=0;i<N;i++) s << "  " << kChronenMinerBanner[i] << "\n";
        s << R() << "\n";

        std::array<std::string,5> rows;
        spinner_circle_ascii(spin++, rows);
        s << "  " << C("36;1") << center_fit("CHRONEN MINER", 60) << R() << "\n\n";
        for(auto& r: rows) s << "      " << C("36") << r << R() << "\n";
        s << "\n  " << C("2") << "loading components... starting in a moment" << R() << "\n";
        std::cout << s.str() << std::flush;
        miq_sleep_ms(1000/12);
    }
    std::cout << "\n  Enter P2PKH Base58 address to mine to: " << std::flush;
    std::getline(std::cin, out_addr);
    trim(out_addr);
}

// ===== OpenCL GPU miner ======================================================
enum class SaltPos { NONE=0, PRE=1, POST=2 };

#if defined(MIQ_ENABLE_OPENCL)

static const char* kCLKernel = R"CLC(
typedef unsigned int  u32;
typedef unsigned long u64;
typedef uchar u8;

inline u32 ROTR(u32 x, u32 n){ return (x>>n) | (x<<(32-n)); }
inline u32 SHR(u32 x, u32 n){ return x>>n; }
inline u32 Ch(u32 x,u32 y,u32 z){ return (x & y) ^ (~x & z); }
inline u32 Maj(u32 x,u32 y,u32 z){ return (x & y) ^ (x & z) ^ (y & z); }
inline u32 Sig0(u32 x){ return ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22); }
inline u32 Sig1(u32 x){ return ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25); }
inline u32 sig0(u32 x){ return ROTR(x,7) ^ ROTR(x,18) ^ SHR(x,3); }
inline u32 sig1(u32 x){ return ROTR(x,17)^ ROTR(x,19)^ SHR(x,10); }

__constant u32 K[64]={
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

typedef struct { u32 h[8]; } SHA256;

inline void sha256_init(SHA256* s){
  s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
  s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
}

inline void sha256_compress(SHA256* S, const u32 Winit[16]){
  u32 W[64];
  #pragma unroll
  for(int t=0;t<16;t++) W[t]=Winit[t];
  for(int t=16;t<64;t++) W[t]=sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
  u32 a=S->h[0], b=S->h[1], c=S->h[2], d=S->h[3], e=S->h[4], f=S->h[5], g=S->h[6], h=S->h[7];
  #pragma unroll
  for(int t=0;t<64;t++){
    u32 T1 = h + Sig1(e) + Ch(e,f,g) + K[t] + W[t];
    u32 T2 = Sig0(a) + Maj(a,b,c);
    h=g; g=f; f=e; e=d + T1;
    d=c; c=b; b=a; a=T1 + T2;
  }
  S->h[0]+=a; S->h[1]+=b; S->h[2]+=c; S->h[3]+=d; S->h[4]+=e; S->h[5]+=f; S->h[6]+=g; S->h[7]+=h;
}

inline void build_block(u32 W16[16],
                        __constant u8* prefix, uint prefix_len,
                        u64 nonce_le, uint blk_idx, uint nblks)
{
  u8 B[64];
  u64 L = (u64)prefix_len + 8u;
  u64 Lbits = L * 8u;

  for(int i=0;i<64;i++){
    u64 off = (u64)blk_idx*64u + (u64)i;
    u8 v = 0;
    if(off < (u64)prefix_len){
      v = prefix[off];
    } else if(off < (u64)prefix_len + 8u){
      uint j = (uint)(off - (u64)prefix_len);
      v = (u8)((nonce_le >> (8u*j)) & 0xffu);
    } else if(off == (u64)prefix_len + 8u){
      v = 0x80u;
    } else {
      u64 last_block_start = (u64)(nblks*64u);
      u64 lenpos = last_block_start - 8u;
      if(off >= lenpos && blk_idx == (nblks-1)){
        int k = (int)(off - lenpos);
        v = (u8)((Lbits >> (8*(7-k))) & 0xffu);
      } else {
        v = 0;
      }
    }
    B[i]=v;
  }

  for(int t=0;t<16;t++){
    int j = 4*t;
    W16[t] = ((u32)B[j]<<24)|((u32)B[j+1]<<16)|((u32)B[j+2]<<8)|((u32)B[j+3]);
  }
}

inline void sha256d_any(u8 out[32], __constant u8* prefix, uint prefix_len, u64 nonce_le){
  u64 L = (u64)prefix_len + 8u;
  uint nblks = (uint)((L + 1u + 8u + 63u)/64u);
  SHA256 S; sha256_init(&S);
  for(uint b=0;b<nblks;b++){
    u32 W16[16];
    build_block(W16, prefix, prefix_len, nonce_le, b, nblks);
    sha256_compress(&S, W16);
  }
  // big-endian digest
  u8 H[32];
  for(int i=0;i<8;i++){
    H[i*4+0]=(u8)((S.h[i]>>24)&0xff);
    H[i*4+1]=(u8)((S.h[i]>>16)&0xff);
    H[i*4+2]=(u8)((S.h[i]>> 8)&0xff);
    H[i*4+3]=(u8)((S.h[i]>> 0)&0xff);
  }

  // second SHA256 over 32 bytes (single block)
  SHA256 S2; sha256_init(&S2);
  u32 W16b[16];
  for(int t=0;t<8;t++){
    int j=4*t; W16b[t]=((u32)H[j]<<24)|((u32)H[j+1]<<16)|((u32)H[j+2]<<8)|((u32)H[j+3]);
  }
  W16b[8]=0x80000000u;
  for(int t=9;t<15;t++) W16b[t]=0;
  W16b[15]= (u32)(32u*8u);
  sha256_compress(&S2, W16b);

  for(int i=0;i<8;i++){
    out[i*4+0]=(u8)((S2.h[i]>>24)&0xff);
    out[i*4+1]=(u8)((S2.h[i]>>16)&0xff);
    out[i*4+2]=(u8)((S2.h[i]>> 8)&0xff);
    out[i*4+3]=(u8)((S2.h[i]>> 0)&0xff);
  }
}

__kernel void sha256d_scan(__constant u8* prefix,
                           uint prefix_len,
                           __constant u8* target_be,
                           ulong base_nonce,
                           uint nonces_per_item,
                           __global volatile int*  out_found,
                           __global ulong* out_nonce)
{
  size_t gid = get_global_id(0);
  ulong nonce0 = base_nonce + (ulong)gid;
  ulong step = (ulong)get_global_size(0);

  u8 h[32];

  for(uint i=0;i<nonces_per_item;i++){
    ulong n = nonce0 + (ulong)i*step;
    sha256d_any(h, prefix, prefix_len, n);

    // compare big-endian h <= target_be
    int leq = 1;
    for(int k=0;k<32;k++){
      if(h[k] < target_be[k]) { leq=1; break; }
      if(h[k] > target_be[k]) { leq=0; break; }
    }
    if(leq){
      if(atomic_cmpxchg(out_found, 0, 1) == 0){
        *out_nonce = n;
      }
      return;
    }
    if(*out_found != 0) return;
  }
}
)CLC";

static const char* clerr(cl_int e){
  switch(e){
    case CL_SUCCESS: return "CL_SUCCESS";
    case CL_DEVICE_NOT_FOUND: return "CL_DEVICE_NOT_FOUND";
    case CL_DEVICE_NOT_AVAILABLE: return "CL_DEVICE_NOT_AVAILABLE";
    case CL_COMPILER_NOT_AVAILABLE: return "CL_COMPILER_NOT_AVAILABLE";
    case CL_MEM_OBJECT_ALLOCATION_FAILURE: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
    case CL_OUT_OF_RESOURCES: return "CL_OUT_OF_RESOURCES";
    case CL_OUT_OF_HOST_MEMORY: return "CL_OUT_OF_HOST_MEMORY";
    case CL_PROFILING_INFO_NOT_AVAILABLE: return "CL_PROFILING_INFO_NOT_AVAILABLE";
    case CL_MEM_COPY_OVERLAP: return "CL_MEM_COPY_OVERLAP";
    case CL_IMAGE_FORMAT_MISMATCH: return "CL_IMAGE_FORMAT_MISMATCH";
    case CL_IMAGE_FORMAT_NOT_SUPPORTED: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
    case CL_BUILD_PROGRAM_FAILURE: return "CL_BUILD_PROGRAM_FAILURE";
    case CL_MAP_FAILURE: return "CL_MAP_FAILURE";
    case CL_INVALID_VALUE: return "CL_INVALID_VALUE";
    case CL_INVALID_DEVICE_TYPE: return "CL_INVALID_DEVICE_TYPE";
    case CL_INVALID_PLATFORM: return "CL_INVALID_PLATFORM";
    case CL_INVALID_DEVICE: return "CL_INVALID_DEVICE";
    case CL_INVALID_CONTEXT: return "CL_INVALID_CONTEXT";
    case CL_INVALID_QUEUE_PROPERTIES: return "CL_INVALID_QUEUE_PROPERTIES";
    case CL_INVALID_COMMAND_QUEUE: return "CL_INVALID_COMMAND_QUEUE";
    case CL_INVALID_HOST_PTR: return "CL_INVALID_HOST_PTR";
    case CL_INVALID_MEM_OBJECT: return "CL_INVALID_MEM_OBJECT";
    case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
    case CL_INVALID_IMAGE_SIZE: return "CL_INVALID_IMAGE_SIZE";
    case CL_INVALID_SAMPLER: return "CL_INVALID_SAMPLER";
    case CL_INVALID_BINARY: return "CL_INVALID_BINARY";
    case CL_INVALID_BUILD_OPTIONS: return "CL_INVALID_BUILD_OPTIONS";
    case CL_INVALID_PROGRAM: return "CL_INVALID_PROGRAM";
    case CL_INVALID_PROGRAM_EXECUTABLE: return "CL_INVALID_PROGRAM_EXECUTABLE";
    case CL_INVALID_KERNEL_NAME: return "CL_INVALID_KERNEL_NAME";
    case CL_INVALID_KERNEL_DEFINITION: return "CL_INVALID_KERNEL_DEFINITION";
    case CL_INVALID_KERNEL: return "CL_INVALID_KERNEL";
    case CL_INVALID_ARG_INDEX: return "CL_INVALID_ARG_INDEX";
    case CL_INVALID_ARG_VALUE: return "CL_INVALID_ARG_VALUE";
    case CL_INVALID_ARG_SIZE: return "CL_INVALID_ARG_SIZE";
    case CL_INVALID_KERNEL_ARGS: return "CL_INVALID_KERNEL_ARGS";
    case CL_INVALID_WORK_DIMENSION: return "CL_INVALID_WORK_DIMENSION";
    case CL_INVALID_WORK_GROUP_SIZE: return "CL_INVALID_WORK_GROUP_SIZE";
    case CL_INVALID_WORK_ITEM_SIZE: return "CL_INVALID_WORK_ITEM_SIZE";
    case CL_INVALID_GLOBAL_OFFSET: return "CL_INVALID_GLOBAL_OFFSET";
    case CL_INVALID_EVENT_WAIT_LIST: return "CL_INVALID_EVENT_WAIT_LIST";
    case CL_INVALID_EVENT: return "CL_INVALID_EVENT";
    case CL_INVALID_OPERATION: return "CL_INVALID_OPERATION";
    case CL_INVALID_GL_OBJECT: return "CL_INVALID_GL_OBJECT";
    case CL_INVALID_BUFFER_SIZE: return "CL_INVALID_BUFFER_SIZE";
    case CL_INVALID_MIP_LEVEL: return "CL_INVALID_MIP_LEVEL";
    case CL_INVALID_GLOBAL_WORK_SIZE: return "CL_INVALID_GLOBAL_WORK_SIZE";
    default: return "CL_ERROR";
  }
}

struct GpuMiner {
  cl_context       ctx = nullptr;
  cl_command_queue q   = nullptr; // OpenCL 1.2
  cl_program       prog= nullptr;
  cl_kernel        krn = nullptr;
  cl_device_id     dev = nullptr;
  std::string      plat_name, dev_name, driver;

  cl_mem buf_prefix=nullptr, buf_target=nullptr, buf_found=nullptr, buf_nonce=nullptr;

  // Safer defaults for laptops (reduce TDR risk)
  size_t  gws = 131072;      // was 262144
  uint32_t npi = 512;        // was 2048
  bool ready=false;

  double ema_now=0.0, ema_smooth=0.0;

  void release_buffers(){
    if(buf_prefix){ clReleaseMemObject(buf_prefix); buf_prefix=nullptr; }
    if(buf_target){ clReleaseMemObject(buf_target); buf_target=nullptr; }
    if(buf_found ){ clReleaseMemObject(buf_found ); buf_found =nullptr; }
    if(buf_nonce ){ clReleaseMemObject(buf_nonce ); buf_nonce =nullptr; }
  }
  void release_all(){
    release_buffers();
    if(krn){ clReleaseKernel(krn); krn=nullptr; }
    if(prog){ clReleaseProgram(prog); prog=nullptr; }
    if(q){ clReleaseCommandQueue(q); q=nullptr; }
    if(ctx){ clReleaseContext(ctx); ctx=nullptr; }
    ready=false;
  }
  ~GpuMiner(){ release_all(); }

  bool init(int plat_index, int dev_index, size_t gws_in, uint32_t npi_in, std::string* err){
    gws = gws_in; npi = npi_in;
    cl_int e;

    cl_uint nplat=0;
    e = clGetPlatformIDs(0,nullptr,&nplat);
    if(e!=CL_SUCCESS || nplat==0){ if(err) *err="No OpenCL platforms."; return false; }
    std::vector<cl_platform_id> plats(nplat);
    clGetPlatformIDs(nplat, plats.data(), nullptr);
    if(plat_index<0 || plat_index>=(int)nplat) plat_index=0;
    cl_platform_id P = plats[(size_t)plat_index];

    char buf[512];
    clGetPlatformInfo(P, CL_PLATFORM_NAME, sizeof(buf), buf, nullptr);
    plat_name = buf;

    cl_uint ndev=0;
    clGetDeviceIDs(P, CL_DEVICE_TYPE_ALL, 0, nullptr, &ndev);
    if(ndev==0){ if(err) *err="No devices on platform."; return false; }
    std::vector<cl_device_id> devs(ndev);
    clGetDeviceIDs(P, CL_DEVICE_TYPE_ALL, ndev, devs.data(), nullptr);

    if(dev_index<0 || dev_index>=(int)ndev){
      int gpu_idx=-1;
      for(cl_uint i=0;i<ndev;i++){
        cl_device_type t=0; clGetDeviceInfo(devs[i], CL_DEVICE_TYPE, sizeof(t), &t, nullptr);
        if(t==CL_DEVICE_TYPE_GPU){ gpu_idx=(int)i; break; }
      }
      dev = (gpu_idx>=0) ? devs[gpu_idx] : devs[0];
    }else{
      dev = devs[(size_t)dev_index];
    }

    clGetDeviceInfo(dev, CL_DEVICE_NAME, sizeof(buf), buf, nullptr);
    dev_name = buf;
    clGetDeviceInfo(dev, CL_DRIVER_VERSION, sizeof(buf), buf, nullptr);
    driver = buf;

    ctx = clCreateContext(nullptr, 1, &dev, nullptr, nullptr, &e);
    if(!ctx || e){ if(err) *err=std::string("clCreateContext failed: ")+clerr(e); release_all(); return false; }
    q = clCreateCommandQueue(ctx, dev, 0, &e);
    if(!q || e){ if(err) *err=std::string("clCreateCommandQueue failed: ")+clerr(e); release_all(); return false; }

    const char* src = kCLKernel;
    size_t srclen = std::strlen(src);
    prog = clCreateProgramWithSource(ctx, 1, &src, &srclen, &e);
    if(!prog || e){ if(err) *err=std::string("clCreateProgramWithSource failed: ")+clerr(e); release_all(); return false; }
    const char* opts = "-cl-std=CL1.2";
    e = clBuildProgram(prog, 1, &dev, opts, nullptr, nullptr);
    if(e!=CL_SUCCESS){
      size_t logsz=0; clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, 0, nullptr, &logsz);
      std::string log(logsz, '\0');
      clGetProgramBuildInfo(prog, dev, CL_PROGRAM_BUILD_LOG, logsz, &log[0], nullptr);
      if(err){ *err = "clBuildProgram failed:\n" + log; }
      release_all(); return false;
    }

    krn = clCreateKernel(prog, "sha256d_scan", &e);
    if(!krn || e){ if(err) *err=std::string("clCreateKernel failed: ")+clerr(e); release_all(); return false; }

    // Compile-time sanity
    static_assert(sizeof(cl_ulong)==8, "cl_ulong must be 8 bytes");
    static_assert(sizeof(cl_uint)==4,  "cl_uint must be 4 bytes");

    ready=true;
    return true;
  }

  bool set_job(const std::vector<uint8_t>& prefix, const uint8_t target_be[32], std::string* err){
    if(!ready){ if(err) *err="GPU not initialized."; return false; }
    cl_int e;
    release_buffers();

    buf_prefix = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                prefix.size(), (void*)prefix.data(), &e);
    if(!buf_prefix || e){ if(err) *err=std::string("clCreateBuffer(buf_prefix) failed: ")+clerr(e); release_buffers(); return false; }

    buf_target = clCreateBuffer(ctx, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                32, (void*)target_be, &e);
    if(!buf_target || e){ if(err) *err=std::string("clCreateBuffer(buf_target) failed: ")+clerr(e); release_buffers(); return false; }

    int zero=0;
    buf_found = clCreateBuffer(ctx, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                               sizeof(int), &zero, &e);
    if(!buf_found || e){ if(err) *err=std::string("clCreateBuffer(buf_found) failed: ")+clerr(e); release_buffers(); return false; }

    cl_ulong init_nonce=0;
    buf_nonce = clCreateBuffer(ctx, CL_MEM_WRITE_ONLY | CL_MEM_COPY_HOST_PTR,
                               sizeof(cl_ulong), &init_nonce, &e);
    if(!buf_nonce || e){ if(err) *err=std::string("clCreateBuffer(buf_nonce) failed: ")+clerr(e); release_buffers(); return false; }

    e = clSetKernelArg(krn, 0, sizeof(cl_mem), &buf_prefix); if(e){ if(err) *err=std::string("clSetArg0 failed: ")+clerr(e); return false; }
    cl_uint prefix_len = (cl_uint)prefix.size();
    e = clSetKernelArg(krn, 1, sizeof(cl_uint), &prefix_len); if(e){ if(err) *err=std::string("clSetArg1 failed: ")+clerr(e); return false; }
    e = clSetKernelArg(krn, 2, sizeof(cl_mem), &buf_target); if(e){ if(err) *err=std::string("clSetArg2 failed: ")+clerr(e); return false; }

    return true;
  }

  bool run_round(uint64_t base_nonce, uint32_t npi_in, uint64_t& out_nonce, bool& found, double& hps, double tau_now=0.5, double tau_smooth=2.0){
    if(!ready) return false;
    cl_int e;

    cl_ulong base_nonce_arg = (cl_ulong)base_nonce;
    e = clSetKernelArg(krn, 3, sizeof(cl_ulong), &base_nonce_arg); if(e){ std::fprintf(stderr,"[GPU] SetArg3: %s\n", clerr(e)); return false; }

    cl_uint npi_arg = (cl_uint)npi_in;
    e = clSetKernelArg(krn, 4, sizeof(cl_uint), &npi_arg); if(e){ std::fprintf(stderr,"[GPU] SetArg4: %s\n", clerr(e)); return false; }

    e = clSetKernelArg(krn, 5, sizeof(cl_mem), &buf_found); if(e){ std::fprintf(stderr,"[GPU] SetArg5: %s\n", clerr(e)); return false; }
    e = clSetKernelArg(krn, 6, sizeof(cl_mem), &buf_nonce); if(e){ std::fprintf(stderr,"[GPU] SetArg6: %s\n", clerr(e)); return false; }

    size_t g = gws;

    auto t0 = std::chrono::steady_clock::now();
    e = clEnqueueNDRangeKernel(q, krn, 1, nullptr, &g, nullptr, 0, nullptr, nullptr);
    if(e){ std::fprintf(stderr,"[GPU] Enqueue: %s\n", clerr(e)); return false; }

    e = clFinish(q);
    if(e){ std::fprintf(stderr,"[GPU] Finish: %s\n", clerr(e)); return false; }

    auto t1 = std::chrono::steady_clock::now();
    double dt = std::chrono::duration<double>(t1 - t0).count();
    if(dt <= 0.0) dt = 1e-6;

    int f=0;
    e = clEnqueueReadBuffer(q, buf_found, CL_TRUE, 0, sizeof(int), &f, 0, nullptr, nullptr);
    if(e){ std::fprintf(stderr,"[GPU] Read found: %s\n", clerr(e)); return false; }

    double hashes = (double)g * (double)npi_in;
    double inst = hashes / dt;
    double a1 = 1.0 - std::exp(-dt / std::max(0.2, tau_now));
    double a2 = 1.0 - std::exp(-dt / std::max(0.5, tau_smooth));
    ema_now    = ema_now*(1.0-a1) + inst*a1;
    ema_smooth = ema_smooth*(1.0-a2) + inst*a2;
    hps = ema_smooth;

    if(f){
      cl_ulong n=0;
      e = clEnqueueReadBuffer(q, buf_nonce, CL_TRUE, 0, sizeof(cl_ulong), &n, 0, nullptr, nullptr);
      if(e){ std::fprintf(stderr,"[GPU] Read nonce: %s\n", clerr(e)); return false; }
      out_nonce = (uint64_t)n;
      found = true;
      return true;
    } else {
      found = false;
      return true;
    }
  }
};

#else // no OpenCL
struct GpuMiner {
  bool init(int,int,size_t,uint32_t,std::string*){ return false; }
  bool set_job(const std::vector<uint8_t>&, const uint8_t[32], std::string*){ return false; }
  bool run_round(uint64_t, uint32_t, uint64_t&, bool&, double&, double,double){ return false; }
  double ema_now=0.0, ema_smooth=0.0;
  size_t gws=0; uint32_t npi=0;
  std::string plat_name, dev_name, driver;
};
#endif

// ===== priority / affinity ===================================================
static void set_process_priority(bool high){
#if defined(_WIN32)
    if(high) SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    else     SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
#else
    if(high){ setpriority(PRIO_PROCESS, 0, -10); }
#endif
}
static void pin_thread_to_cpu(unsigned tid){
#if defined(_WIN32)
    DWORD_PTR mask = (DWORD_PTR)1 << (tid % (8*sizeof(DWORD_PTR)));
    SetThreadAffinityMask(GetCurrentThread(), mask);
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(tid % CPU_SETSIZE, &set);
    sched_setaffinity(0, sizeof(set), &set);
#endif
}

// ===== miner core (CPU) ======================================================
struct ThreadCounter { std::atomic<uint64_t> hashes{0}; };

static void mine_worker_optimized(const BlockHeader hdr_base,
                                  const std::vector<Transaction> txs_including_cb,
                                  uint32_t bits,
                                  std::atomic<bool>* found,
                                  ThreadCounter* counter,
                                  bool pin_affinity,
                                  unsigned tid, unsigned stride,
                                  Block* out_block)
{
    if(pin_affinity) pin_thread_to_cpu(tid);

    Block b; b.header = hdr_base; b.txs = txs_including_cb;
    b.header.merkle_root = merkle_from(b.txs);

    // Build header prefix: 4|32|32|8|4   (80 bytes)
    std::vector<uint8_t> header_prefix;
    header_prefix.reserve(4+32+32+8+4);
    put_u32_le(header_prefix, b.header.version);
    header_prefix.insert(header_prefix.end(), b.header.prev_hash.begin(),   b.header.prev_hash.end());
    header_prefix.insert(header_prefix.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
    put_u64_le(header_prefix, (uint64_t)b.header.time);
    put_u32_le(header_prefix, b.header.bits);
    const size_t nonce_off = header_prefix.size();

    bits = sanitize_bits(bits);

#if !defined(MIQ_POW_SALT)
    FastSha256Ctx base1;
    fastsha_init(base1);
    fastsha_update(base1, header_prefix.data(), header_prefix.size());
#endif

    std::vector<uint8_t> hdr = header_prefix;
    hdr.resize(header_prefix.size() + 8);
    uint8_t* nonce_ptr = hdr.data() + nonce_off;
    (void)nonce_ptr;

    const uint64_t base_nonce =
        (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull;

    uint64_t nonce = base_nonce + (uint64_t)tid;
    const uint64_t step  = (uint64_t)stride;

    const uint64_t BATCH = (1ull<<15);
    uint64_t local_hashes = 0;

    while(!found->load(std::memory_order_relaxed)){
        uint64_t todo = BATCH;
        while(todo && !found->load(std::memory_order_relaxed)){
            const uint64_t n0 = nonce; nonce += step;
            const uint64_t n1 = nonce; nonce += step;
            const uint64_t n2 = nonce; nonce += step;
            const uint64_t n3 = nonce; nonce += step;
            const uint64_t n4 = nonce; nonce += step;
            const uint64_t n5 = nonce; nonce += step;
            const uint64_t n6 = nonce; nonce += step;
            const uint64_t n7 = nonce; nonce += step;

            uint8_t h[8][32];

        #if !defined(MIQ_POW_SALT)
            uint8_t le[8][8];
            store_u64_le(le[0], n0); dsha256_from_base(base1, le[0], 8, h[0]);
            store_u64_le(le[1], n1); dsha256_from_base(base1, le[1], 8, h[1]);
            store_u64_le(le[2], n2); dsha256_from_base(base1, le[2], 8, h[2]);
            store_u64_le(le[3], n3); dsha256_from_base(base1, le[3], 8, h[3]);
            store_u64_le(le[4], n4); dsha256_from_base(base1, le[4], 8, h[4]);
            store_u64_le(le[5], n5); dsha256_from_base(base1, le[5], 8, h[5]);
            store_u64_le(le[6], n6); dsha256_from_base(base1, le[6], 8, h[6]);
            store_u64_le(le[7], n7); dsha256_from_base(base1, le[7], 8, h[7]);
        #else
            // Salted path on CPU via your hasher.h implementation.
            store_u64_le(nonce_ptr, n0); { auto hv = salted_header_hash(hdr); std::memcpy(h[0], hv.data(), 32); }
            store_u64_le(nonce_ptr, n1); { auto hv = salted_header_hash(hdr); std::memcpy(h[1], hv.data(), 32); }
            store_u64_le(nonce_ptr, n2); { auto hv = salted_header_hash(hdr); std::memcpy(h[2], hv.data(), 32); }
            store_u64_le(nonce_ptr, n3); { auto hv = salted_header_hash(hdr); std::memcpy(h[3], hv.data(), 32); }
            store_u64_le(nonce_ptr, n4); { auto hv = salted_header_hash(hdr); std::memcpy(h[4], hv.data(), 32); }
            store_u64_le(nonce_ptr, n5); { auto hv = salted_header_hash(hdr); std::memcpy(h[5], hv.data(), 32); }
            store_u64_le(nonce_ptr, n6); { auto hv = salted_header_hash(hdr); std::memcpy(h[6], hv.data(), 32); }
            store_u64_le(nonce_ptr, n7); { auto hv = salted_header_hash(hdr); std::memcpy(h[7], hv.data(), 32); }
        #endif

            if(meets_target_be_raw(h[0], bits)){ b.header.nonce=n0; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[1], bits)){ b.header.nonce=n1; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[2], bits)){ b.header.nonce=n2; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[3], bits)){ b.header.nonce=n3; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[4], bits)){ b.header.nonce=n4; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[5], bits)){ b.header.nonce=n5; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[6], bits)){ b.header.nonce=n6; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[7], bits)){ b.header.nonce=n7; *out_block=b; found->store(true); break; }

            // NEW: publish a live "next hash" sample to UI periodically
            if((local_hashes & ((1u<<10)-1)) == 0){
                int pick = (int)((n0 ^ n3 ^ n7) & 7u);
                publish_next_hash_sample(h[pick]);
            }

            local_hashes += 8;
            todo = (todo>=8)? (todo-8) : 0;

            if((local_hashes & ((1u<<12)-1)) == 0){
                counter->hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                local_hashes = 0;
            }
        }
        if(found->load(std::memory_order_relaxed)) break;
    }
    if(local_hashes){
        counter->hashes.fetch_add(local_hashes, std::memory_order_relaxed);
    }
}

// ===== tx packer =============================================================
static bool pack_template(const MinerTemplate& tpl,
                          size_t coinbase_bytes,
                          std::vector<Transaction>& out_txs,
                          uint64_t& out_fees,
                          size_t& out_bytes)
{
    out_txs.clear(); out_fees=0; out_bytes=coinbase_bytes;
    for(const auto& xt : tpl.txs){
        std::vector<uint8_t> raw;
        try{ raw = from_hex_s(xt.hex); }catch(...){ continue; }
        Transaction t; if(!deser_tx(raw, t)) continue;
        size_t sz = ser_tx(t).size();
        if(out_bytes + sz > tpl.max_block_bytes) continue;
        out_txs.push_back(std::move(t));
        out_bytes += sz;
        out_fees += xt.fee;
    }
    return true;
}

// ===== usage =================================================================
static void usage(){
    std::cout <<
    "miqminer_rpc — Chronen Miner (CPU + OpenCL GPU)\n"
    "Usage:\n"
    "  miqminer_rpc [--rpc=host:port] [--token=TOKEN] [--threads=N]\n"
    "               [--address=Base58P2PKH] [--no-ansi]\n"
    "               [--priority=high|normal] [--affinity=on|off]\n"
    "               [--smooth=SECONDS]\n"
    "               [--gpu=on|off] [--gpu-platform=IDX] [--gpu-device=IDX]\n"
    "               [--gws=GLOBAL_WORK_SIZE] [--gnpi=NONCES_PER_ITEM]\n"
    "               [--salt-hex=HEXBYTES] [--salt-pos=pre|post]\n"
    "               [--make-seed=12|24] [--seed-pass=PHRASE]\n"
    "               [--mine-to-first=on|off] [--coin-type=N]\n"
    "Notes:\n"
    "  - Token from --token, MIQ_RPC_TOKEN, or datadir/.cookie\n"
    "  - Default threads: 6 (override with --threads)\n"
    "  - GPU requires build with -DMIQ_ENABLE_OPENCL and OpenCL runtime installed\n";
}

// ===== NEW: interactive start menu (create/import wallet or start miner) =====
static bool interactive_start_menu(std::string& out_addr, uint32_t coin_type){
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) { DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004); }
#endif
    auto banner = [](){
        std::ostringstream s;
        s << CLS();
        s << C("36;1");
        const size_t N = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
        for(size_t i=0;i<N;i++) s << "  " << kChronenMinerBanner[i] << "\n";
        s << R() << "\n";
        std::cout << s.str();
    };

    while(true){
        banner();
        std::cout
            << "  " << C("36;1") << "CHRONEN MINER — START" << R() << "\n\n"
            << "  1) Create NEW wallet (12 words)\n"
            << "  2) Create NEW wallet (24 words)\n"
            << "  3) Import mnemonic (12 or 24 words)\n"
            << "  4) Start miner with existing address\n"
            << "  q) Quit\n\n"
            << "  Select an option: " << std::flush;

        std::string choice;
        if(!std::getline(std::cin, choice)) return false;
        trim(choice);
        if(choice=="q" || choice=="Q") return false;

        if(choice=="1" || choice=="2"){
            const int words = (choice=="1") ? 12 : 24;

            // generate mnemonic + seed
            std::vector<std::string> words_out;
            std::vector<uint8_t> entropy;
            if(!make_mnemonic_words((size_t)words, words_out, entropy)){
                std::fprintf(stderr,"Failed to create %d-word mnemonic.\n", words);
                miq_sleep_ms(1200);
                continue;
            }
            std::string mnemonic = mnemonic_join(words_out);

            banner();
            std::cout << C("36;1") << "YOUR " << words << "-WORD MNEMONIC" << R() << "\n\n"
                      << "  " << mnemonic << "\n\n"
                      << C("33;1") << "Write these words down. "
                      << "Anyone with this mnemonic can spend your MIQ." << R() << "\n\n";

            // optional BIP39 passphrase
            std::string passphrase;
            std::cout << "  Optional BIP39 passphrase (ENTER to skip): " << std::flush;
            std::getline(std::cin, passphrase);

            // BIP39 seed
            std::vector<uint8_t> seed64;
            mnemonic_to_seed_BIP39(mnemonic, passphrase, seed64);

            // derive 5 addresses
            std::vector<std::string> addrs;
            std::vector<std::vector<uint8_t>> pubs;
            if(!derive_miq_addresses_from_seed(seed64, coin_type, 5, addrs, pubs)){
                std::fprintf(stderr,"Failed to derive addresses.\n");
                miq_sleep_ms(1200);
                continue;
            }

            banner();
            std::cout << C("36;1") << "FIRST 5 MIQ ADDRESSES (m/44'/"<< coin_type << "'/0'/0/i)" << R() << "\n";
            for(size_t i=0;i<addrs.size();++i){
                std::cout << "  ["<<i<<"] " << addrs[i] << "\n";
            }
            std::cout << "\n";

            // choose one to mine to
            std::cout << "  Choose address index 0-4 (ENTER = 0): " << std::flush;
            std::string idxs; std::getline(std::cin, idxs); trim(idxs);
            int idx = 0;
            if(!idxs.empty()){
                try { idx = std::stoi(idxs); } catch(...) { idx = 0; }
            }
            if(idx < 0) idx = 0;
            if(idx > 4) idx = 4;

            out_addr = addrs[(size_t)idx];

            banner();
            std::cout << C("33;1") << "Mining to: " << out_addr << R() << "\n\n"
                      << C("2") << "(Tip: store your mnemonic safely. You can recreate these same 5 addresses any time.)" << R() << "\n\n";
            miq_sleep_ms(1200);
            return true;
        }
        else if(choice=="3"){
            // Import mnemonic
            banner();
            std::cout << C("36;1") << "IMPORT MNEMONIC" << R() << "\n\n";
            std::cout << "  Paste your 12 or 24 words:\n  > " << std::flush;

            std::string mnemonic;
            if(!std::getline(std::cin, mnemonic)) return false;
            trim(mnemonic);
            if(mnemonic.empty()){
                std::fprintf(stderr,"No mnemonic provided.\n");
                miq_sleep_ms(1200);
                continue;
            }
            // optional passphrase
            std::string passphrase;
            std::cout << "\n  Optional BIP39 passphrase (ENTER to skip): " << std::flush;
            std::getline(std::cin, passphrase);

            // derive seed directly from the phrase (BIP39 PBKDF2)
            std::vector<uint8_t> seed64;
            mnemonic_to_seed_BIP39(mnemonic, passphrase, seed64);

            // derive 5 addresses
            std::vector<std::string> addrs;
            std::vector<std::vector<uint8_t>> pubs;
            if(!derive_miq_addresses_from_seed(seed64, coin_type, 5, addrs, pubs)){
                std::fprintf(stderr,"Failed to derive addresses from mnemonic.\n");
                miq_sleep_ms(1500);
                continue;
            }

            banner();
            std::cout << C("36;1") << "FIRST 5 MIQ ADDRESSES (m/44'/"<< coin_type << "'/0'/0/i)" << R() << "\n";
            for(size_t i=0;i<addrs.size();++i){
                std::cout << "  ["<<i<<"] " << addrs[i] << "\n";
            }
            std::cout << "\n";

            std::cout << "  Choose address index 0-4 (ENTER = 0): " << std::flush;
            std::string idxs; std::getline(std::cin, idxs); trim(idxs);
            int idx = 0;
            if(!idxs.empty()){
                try { idx = std::stoi(idxs); } catch(...) { idx = 0; }
            }
            if(idx < 0) idx = 0;
            if(idx > 4) idx = 4;

            out_addr = addrs[(size_t)idx];

            banner();
            std::cout << C("33;1") << "Mining to: " << out_addr << R() << "\n\n";
            miq_sleep_ms(1200);
            return true;
        }
        else if(choice=="4"){
            // start miner with existing address
            banner();
            std::cout << "  Enter P2PKH Base58 address to mine to: " << std::flush;
            std::string addr; std::getline(std::cin, addr); trim(addr);

            std::vector<uint8_t> pkh;
            if(!parse_p2pkh(addr, pkh)){
                std::fprintf(stderr,"Invalid address (expected Base58Check P2PKH, version 0x%02x)\n",(unsigned)miq::VERSION_P2PKH);
                miq_sleep_ms(1500);
                continue;
            }
            out_addr = addr;
            return true;
        }
        else{
            // invalid choice; loop
            continue;
        }
    }
}

// ===== main ==================================================================
int main(int argc, char** argv){
    try{
#if defined(_WIN32)
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004);
        }
#endif
        std::string rpc_host = "127.0.0.1";
        uint16_t    rpc_port = (uint16_t)miq::RPC_PORT;
        std::string token;
        unsigned threads = 6;
        std::string address_cli;
        bool pin_affinity = false;
        bool high_priority = false;
        double smooth_seconds = 15.0;

        // GPU options (auto-enable; disable with --gpu=off)
        bool   gpu_enabled = true;
        int    gpu_platform_index = 0;
        int    gpu_device_index   = -1;
        size_t gpu_gws = 131072;   // safer default
        uint32_t gpu_npi = 512;    // safer default

        // Salt options (for GPU & optional CPU conformity when MIQ_POW_SALT is defined)
        std::vector<uint8_t> salt_bytes;
        SaltPos salt_pos = SaltPos::NONE;

        // NEW: seed/hd-wallet options
        int make_seed_words = 0;            // 0=no, 12 or 24
        std::string seed_passphrase;        // optional
        bool mine_to_first = false;
        uint32_t bip44_coin_type = 0;       // default coin type

        for(int i=1;i<argc;i++){
            std::string a(argv[i]);
            if(a=="--help"||a=="-h"){ usage(); return 0; }
            else if(a.rfind("--rpc=",0)==0){
                std::string hp = a.substr(6); size_t c = hp.find(':');
                if(c==std::string::npos){ std::fprintf(stderr,"Bad --rpc=host:port\n"); return 2; }
                rpc_host = hp.substr(0,c); rpc_port = (uint16_t)std::stoi(hp.substr(c+1));
            } else if(a.rfind("--token=",0)==0){
                token = a.substr(8);
            } else if(a.rfind("--threads=",0)==0){
                long v = std::strtol(a.c_str()+10,nullptr,10);
                if(v>0 && v<=1024) threads = (unsigned)v;
            } else if(a=="--no-ansi"){
                g_use_ansi = false;
            } else if(a.rfind("--address=",0)==0){
                address_cli = a.substr(10);
            } else if(a.rfind("--priority=",0)==0){
                std::string p = a.substr(11);
                std::transform(p.begin(),p.end(),p.begin(),::tolower);
                high_priority = (p=="high");
            } else if(a.rfind("--affinity=",0)==0){
                std::string p = a.substr(11);
                std::transform(p.begin(),p.end(),p.begin(),::tolower);
                pin_affinity = (p=="on"||p=="true"||p=="1");
            } else if(a.rfind("--smooth=",0)==0){
                smooth_seconds = std::max(1.0, std::stod(a.substr(9)));
            } else if(a.rfind("--gpu=",0)==0){
                std::string p = a.substr(6);
                std::transform(p.begin(),p.end(),p.begin(),::tolower);
                gpu_enabled = !(p=="off"||p=="false"||p=="0");
            } else if(a.rfind("--gpu-platform=",0)==0){
                gpu_platform_index = std::stoi(a.substr(14));
            } else if(a.rfind("--gpu-device=",0)==0){
                gpu_device_index = std::stoi(a.substr(13));
            } else if(a.rfind("--gws=",0)==0){
                gpu_gws = (size_t) std::stoull(a.substr(6));
            } else if(a.rfind("--gnpi=",0)==0){
                gpu_npi = (uint32_t) std::stoul(a.substr(7));
            } else if(a.rfind("--salt-hex=",0)==0){
                std::string hx = a.substr(11);
                try { salt_bytes = from_hex_s(hx); } catch(...) { std::fprintf(stderr,"Bad --salt-hex\n"); return 2; }
            } else if(a.rfind("--salt-pos=",0)==0){
                std::string p = a.substr(11);
                std::transform(p.begin(),p.end(),p.begin(),::tolower);
                if(p=="pre") salt_pos = SaltPos::PRE;
                else if(p=="post") salt_pos = SaltPos::POST;
                else salt_pos = SaltPos::NONE;
            } else if(a.rfind("--make-seed=",0)==0){
                int w = std::stoi(a.substr(12));
                make_seed_words = (w==12 || w==24) ? w : 0;
            } else if(a.rfind("--seed-pass=",0)==0){
                seed_passphrase = a.substr(12);
            } else if(a.rfind("--mine-to-first=",0)==0){
                std::string p = a.substr(16);
                std::transform(p.begin(),p.end(),p.begin(),::tolower);
                mine_to_first = (p=="on"||p=="true"||p=="1");
            } else if(a.rfind("--coin-type=",0)==0){
                bip44_coin_type = (uint32_t)std::stoul(a.substr(12));
            } else {
                std::fprintf(stderr,"Unknown arg: %s\n", argv[i]); return 2;
            }
        }

        if(token.empty()){
            if(const char* t = std::getenv("MIQ_RPC_TOKEN")) token = t;
            if(token.empty()){
                std::string cookie;
                if(read_all_file(default_cookie_path(), cookie)) token = cookie;
            }
        }

        // Process priority
        set_process_priority(high_priority);

        // NEW: optional seed generation & 5 addresses via CLI flags (non-interactive)
        if(make_seed_words){
            std::vector<std::string> words;
            std::vector<uint8_t> entropy;
            if(!make_mnemonic_words((size_t)make_seed_words, words, entropy)){
                std::fprintf(stderr,"Failed to create %d-word mnemonic.\n", make_seed_words);
                return 2;
            }
            std::string mnemonic = mnemonic_join(words);

            std::vector<uint8_t> seed64;
            mnemonic_to_seed_BIP39(mnemonic, seed_passphrase, seed64);

            std::vector<std::string> addrs;
            std::vector<std::vector<uint8_t>> pubs;
            if(!derive_miq_addresses_from_seed(seed64, bip44_coin_type, 5, addrs, pubs)){
                std::fprintf(stderr,"Failed to derive addresses from seed.\n");
                return 2;
            }

            std::cout << "\n" << C("36;1") << "NEW " << make_seed_words << "-WORD MNEMONIC" << R() << "\n";
            std::cout << "  " << mnemonic << "\n\n";
            std::cout << C("36;1") << "FIRST 5 MIQ ADDRESSES (m/44'/"<< bip44_coin_type << "'/0'/0/i):" << R() << "\n";
            for(size_t i=0;i<addrs.size();++i){
                std::cout << "  ["<<i<<"] " << addrs[i] << "\n";
            }
            std::cout << "\n" << C("2") << "Store these words safely. Anyone with this mnemonic can spend your MIQ." << R() << "\n\n";

            if(mine_to_first || address_cli.empty()){
                address_cli = addrs[0];
                std::cout << C("33;1") << "Mining to first derived address: " << address_cli << R() << "\n\n";
            }
        }

        // Decide payout address
        std::string addr = address_cli;

        // If user didn’t pass --address or --make-seed flags, show the menu.
        if(addr.empty() && make_seed_words == 0){
            if(!interactive_start_menu(addr, bip44_coin_type)){
                std::fprintf(stderr,"Aborted.\n");
                return 0;
            }
        }

        // If still empty here, fall back to quick prompt.
        if(addr.empty()){
            show_intro_and_get_address(addr);
            if(addr.empty()){ std::fprintf(stderr,"stdin closed\n"); return 1; }
        } else {
            // Show banner for consistency when starting directly with an address
            std::ostringstream s; s << CLS();
            s << C("36;1");
            const size_t N = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
            for(size_t i=0;i<N;i++) s << "  " << kChronenMinerBanner[i] << "\n";
            s << R() << "\n";
            std::cout << s.str() << std::flush;
        }

        std::vector<uint8_t> pkh;
        if(!parse_p2pkh(addr, pkh)){
            std::fprintf(stderr,"Invalid address (expected Base58Check P2PKH, version 0x%02x)\n",(unsigned)miq::VERSION_P2PKH);
            return 1;
        }

        // GPU init (optional)
        GpuMiner gpu;
        UIState ui;
        g_ui = &ui; // NEW: allow workers to publish next-hash previews
        ui.my_pkh = pkh;
        std::atomic<bool> running{true};

#if defined(MIQ_ENABLE_OPENCL)
        if(gpu_enabled){
            std::string gerr;
            if(!gpu.init(gpu_platform_index, gpu_device_index, gpu_gws, gpu_npi, &gerr)){
                std::fprintf(stderr,"[GPU] init failed: %s\n", gerr.c_str());
                gpu_enabled = false;
            } else {
                ui.gpu_available.store(true);
                ui.gpu_platform = gpu.plat_name;
                ui.gpu_device   = gpu.dev_name;
                ui.gpu_driver   = gpu.driver;
                std::fprintf(stderr,"[GPU] Using platform: %s\n", ui.gpu_platform.c_str());
                std::fprintf(stderr,"[GPU] Using device  : %s\n", ui.gpu_device.c_str());
                std::fprintf(stderr,"[GPU] Driver        : %s\n", ui.gpu_driver.c_str());
                std::fprintf(stderr,"[GPU] gws=%zu  nonces/item=%u\n", gpu_gws, gpu_npi);
            }
        }
#else
        if(gpu_enabled){
            std::fprintf(stderr,"[GPU] disabled: binary not built with -DMIQ_ENABLE_OPENCL\n");
            gpu_enabled = false;
        }
#endif

        // UI thread
        std::thread ui_th([&](){
            using clock = std::chrono::steady_clock;
            const int FPS = 12;
            const auto frame_dt = std::chrono::milliseconds(1000/FPS);
            const int inner = 28;
            int spin_idx = 0;
            while(running.load(std::memory_order_relaxed)){
                std::ostringstream out;
                out << CLS();

                out << C("36;1");
                const size_t kBannerN = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
                for(size_t i=0;i<kBannerN;i++) out << "  " << kChronenMinerBanner[i] << "\n";
                out << R() << "\n";

                uint64_t th = ui.tip_height.load();
                if(th){
                    out << "  " << C("1") << "tip height:      " << R() << th << "\n";
                    out << "  " << C("1") << "tip hash:        " << R() << ui.tip_hash_hex
                        << "  " << C("2") << "(last accepted)" << R() << "\n";
                    uint32_t bits = ui.tip_bits.load();
                    out << "  " << C("1") << "tip bits:        " << R()
                        << "0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)bits
                        << std::dec << "  (difficulty " << std::fixed << std::setprecision(2) << difficulty_from_bits(bits) << ")\n";
                } else {
                    out << "  (waiting for template)\n";
                }

                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    if(ui.cand.height){
                        out << "\n";
                        out << "  " << C("36;1") << "mining candidate:" << R()
                            << "  height=" << ui.cand.height
                            << "  prev=" << ui.cand.prev_hex
                            << "  " << C("2") << "(prev=tip)" << R() << "\n";
                        out << "                     bits=0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)ui.cand.bits
                            << std::dec << "  (difficulty " << std::fixed << std::setprecision(2) << difficulty_from_bits(ui.cand.bits) << ")\n";
                        out << "                     txs=" << ui.cand.txs
                            << "  size=" << ui.cand.size_bytes << " bytes"
                            << "  fees=" << fmt_miq_amount(ui.cand.fees) << "\n";
                        out << "                     coinbase=" << C("32;1") << fmt_miq_amount(ui.cand.coinbase) << R() << "\n";

                        // NEW: live next-hash preview
                        std::string nxh;
                        {
                            std::lock_guard<std::mutex> lk2(ui.next_hash_mtx);
                            std::ostringstream hh;
                            for(int i=0;i<32;i++) hh << std::hex << std::setw(2) << std::setfill('0') << (unsigned)ui.next_hash_sample[i];
                            nxh = hh.str();
                        }
                        if(!nxh.empty()){
                            out << "                     next hash: " << C("2") << nxh.substr(0,64) << R() << "\n";
                        }
                    }
                }

                if(ui.lastblk.height){
                    const auto& lb = ui.lastblk;
                    out << "\n";
                    out << "  " << C("33;1") << "last block:" << R()
                        << "       height=" << lb.height
                        << "  hash=" << lb.hash_hex
                        << "  txs=" << lb.txs << "\n";
                    if(!lb.coinbase_txid_hex.empty())
                        out << "                     coinbase_txid=" << lb.coinbase_txid_hex << "\n";
                    if(!lb.coinbase_pkh.empty()){
                        const std::string winner = pkh_to_address(lb.coinbase_pkh);
                        out << "                     paid to: " << winner
                            << "  (pkh=" << to_hex_s(lb.coinbase_pkh) << ")\n";
                        uint64_t expected = GetBlockSubsidy((uint32_t)lb.height);
                        if(lb.reward_value){
                            uint64_t normalized = normalize_to_expected(lb.reward_value, expected);
                            out << "                     reward: expected " << fmt_miq_amount(expected)
                                << "  |  node reported " << fmt_miq_amount(normalized) << "\n";
                        }else{
                            out << "                     reward: expected " << fmt_miq_amount(expected) << "\n";
                        }
                    }
                }

                out << "\n";
                out << "  " << C("1") << "CPU hashrate:    " << R() << C("36") << fmt_hs(ui.hps_smooth.load()) << R()
                    << "  " << C("2") << "(now " << fmt_hs(ui.hps_now.load()) << ")" << R() << "\n";

                if(ui.gpu_available.load()){
                    out << "  " << C("1") << "GPU hashrate:    " << R()
                        << C("36") << fmt_hs(ui.gpu_hps_smooth.load()) << R()
                        << "  " << C("2") << "(now " << fmt_hs(ui.gpu_hps_now.load()) << ")" << R() << "\n";
                    out << "  " << C("1") << "GPU device:      " << R()
                        << ui.gpu_device << "  | driver: " << ui.gpu_driver
                        << "  | platform: " << ui.gpu_platform << "\n";
                } else {
                    out << "  " << C("1") << "GPU:             " << R() << C("2") << "(not available)" << R() << "\n";
                }

                out << "  " << C("1") << "network hashrate: " << R() << fmt_hs(ui.net_hashps.load()) << "\n";
                out << "  " << C("1") << "mined (session):  " << R() << ui.mined_blocks.load() << "\n";

                out << "  " << C("1") << "paid to address:  " << R()
                    << fmt_miq_amount(ui.total_received_base.load());
                {
                    uint64_t estTot = ui.est_total_base.load();
                    if (ui.total_received_base.load() == 0 && estTot > 0) {
                        out << "  " << C("2")
                            << "  (est. " << fmt_miq_amount(estTot)
                            << " | matured " << fmt_miq_amount(ui.est_matured_base.load())
                            << ")"
                            << R();
                    }
                }
                out << "\n";

                uint64_t th2 = ui.tip_height.load();
                if(ui.last_seen_height.load() == th2){
                    if(ui.last_tip_was_mine.load()){
                        out << "  " << C("32;1") << "YOU MINED THE LATEST BLOCK." << R() << "\n";
                    }else if(!ui.last_winner_addr.empty()){
                        out << "  " << C("31;1") << "Another miner won the latest block: " << ui.last_winner_addr << R() << "\n";
                    }
                }

                {
                    auto age = std::chrono::duration<double>(clock::now() - ui.last_submit_when).count();
                    if(!ui.last_submit_msg.empty() && age < 5.0){
                        out << "  " << ui.last_submit_msg << "\n";
                    }
                }

                {
                    std::lock_guard<std::mutex> lk(ui.spark_mtx);
                    if(!ui.sparkline.empty()){
                        out << "\n  " << C("2") << "h/s trend:" << R() << "        " << spark_ascii(ui.sparkline) << "\n";
                    }
                }

                std::array<std::string,5> spin_rows;
                spinner_circle_ascii(spin_idx, spin_rows);
                ++spin_idx;

                const uint64_t tries_now = ui.tries_total.load();
                const uint64_t round_start = ui.round_start_tries.load();
                const double   round_expect = ui.round_expected_hashes.load();
                const double   done = (tries_now >= round_start) ? (double)(tries_now - round_start) : 0.0;
                const double   hps   = std::max(1e-9, ui.hps_smooth.load()+ui.gpu_hps_smooth.load());
                const double   eta   = (hps > 0.0 && round_expect > done) ? (round_expect - done)/hps : std::numeric_limits<double>::infinity();

                std::vector<std::string> lines;
                lines.push_back("  ##############################   ##############################");
                lines.push_back("  #                            #   #                            #");
                lines.push_back("  #"+center_fit("MINING IN PROGRESS", inner)+"#   #"+center_fit("CHRONEN  MINER", inner)+"#");
                lines.push_back("  #                            #   #                            #");
                for(int r=0;r<5;r++){
                    lines.push_back("  #"+center_fit(spin_rows[r], inner)+"#   #"+center_fit("                    ", inner)+"#");
                }
                std::string eta_line = std::string("   ETA ~ ") + fmt_eta(eta);
                lines.push_back("  #"+pad_fit(eta_line, inner)+"#   #"+center_fit("                    ", inner)+"#");
                lines.push_back("  ##############################   ##############################");
                for(const auto& L : lines) out << C("36") << L << R() << "\n";

                out << "\n  Press Ctrl+C to quit.\n";
                std::cout << out.str() << std::flush;
                std::this_thread::sleep_for(frame_dt);
            }
        });
        ui_th.detach();

        // watch tip + network hps + last block + wallet totals + fallback scan
        std::thread watch([&](){
            uint64_t last_seen_h = 0;
            int tick=0;
            while(running.load()){
                TipInfo t;
                if(rpc_gettipinfo(rpc_host, rpc_port, token, t)){
                    ui.tip_height.store(t.height);
                    ui.tip_hash_hex = t.hash_hex;
                    ui.tip_bits.store(t.bits);
                    double hs=0.0;
                    if(!rpc_getminerstats(rpc_host, rpc_port, token, hs))
                        hs = estimate_network_hashps(rpc_host, rpc_port, token, t.height, t.bits);
                    ui.net_hashps.store(hs);

                    if(t.height && t.height != last_seen_h){
                        LastBlockInfo lb{};
                        if(rpc_getblock_overview(rpc_host, rpc_port, token, t.height, lb)){
                            rpc_getcoinbaserecipient(rpc_host, rpc_port, token, t.height, lb);
                            ui.lastblk = lb;
                            ui.last_seen_height.store(t.height);
                            if(!lb.coinbase_pkh.empty() && lb.coinbase_pkh == ui.my_pkh){
                                ui.last_tip_was_mine.store(true);
                                ui.last_winner_addr.clear();
                            } else {
                                ui.last_tip_was_mine.store(false);
                                ui.last_winner_addr = (!lb.coinbase_pkh.empty() ? pkh_to_address(lb.coinbase_pkh) : std::string());
                            }
                        }
                        last_seen_h = t.height;
                    }

                    // fallback scan
                    {
                        const uint64_t tip = ui.tip_height.load();
                        uint64_t next_h = ui.est_scanned_height.load();
                        if (next_h == 0) next_h = 1;
                        const uint64_t CHUNK = 128;
                        uint64_t end_h = (tip > 0) ? std::min(tip, next_h + CHUNK - 1) : 0;

                        if (end_h >= next_h) {
                            std::vector<std::pair<uint64_t,uint64_t>> newly_mined;
                            newly_mined.reserve(CHUNK);

                            for (uint64_t h = next_h; h <= end_h; ++h) {
                                LastBlockInfo lb{};
                                if (!rpc_getblock_overview(rpc_host, rpc_port, token, h, lb)) continue;
                                (void)rpc_getcoinbaserecipient(rpc_host, rpc_port, token, h, lb);

                                if (!lb.coinbase_pkh.empty() && lb.coinbase_pkh == ui.my_pkh) {
                                    uint64_t expected = GetBlockSubsidy((uint32_t)h);
                                    uint64_t reward_base = expected;
                                    if (lb.reward_value) reward_base = normalize_to_expected(lb.reward_value, expected);
                                    newly_mined.emplace_back(h, reward_base);
                                }
                            }

                            if (!newly_mined.empty()) {
                                std::lock_guard<std::mutex> lk(ui.myblks_mtx);
                                for (auto& p : newly_mined) {
                                    if (ui.my_block_heights.insert(p.first).second) {
                                        ui.my_blocks.push_back(p);
                                    }
                                }
                            }

                            ui.est_scanned_height.store(end_h + 1);

                            uint64_t est_total = 0, est_matured = 0;
                            {
                                std::lock_guard<std::mutex> lk(ui.myblks_mtx);
                                for (const auto& pr : ui.my_blocks) {
                                    est_total += pr.second;
                                    if (pr.first + kCoinbaseMaturity <= tip) est_matured += pr.second;
                                }
                            }
                            ui.est_total_base.store(est_total);
                            ui.est_matured_base.store(est_matured);
                        }
                    }
                }

                if((++tick % 10)==0){
                    uint64_t tot=0;
                    if(rpc_get_received_total_baseunits(rpc_host, rpc_port, token, pkh_to_address(ui.my_pkh), tot)){
                        ui.total_received_base.store(tot);
                    }
                }

                for(int i=0;i<10;i++) miq_sleep_ms(100);
            }
        });
        watch.detach();

        // per-thread counters
        std::vector<ThreadCounter> thr_counts(threads);
        for(auto& c: thr_counts) c.hashes.store(0);

        // metering thread (CPU + GPU)
        std::thread meter([&](){
            using clock = std::chrono::steady_clock;
            auto last = clock::now();
            uint64_t last_sum = 0;
            double ema_now = 0.0;
            double ema_smooth = 0.0;
            while(running.load()){
                uint64_t sum = 0;
                for(auto& c: thr_counts) sum += c.hashes.load(std::memory_order_relaxed);

                auto now = clock::now();
                double dt = std::chrono::duration<double>(now - last).count();
                if(dt <= 0.0) dt = 1e-3;

                uint64_t delta = (sum >= last_sum) ? (sum - last_sum) : sum;
                double hps = (double)delta / dt;

                double alpha_now    = 1.0 - std::exp(-dt / std::max(0.5, smooth_seconds*0.25));
                double alpha_smooth = 1.0 - std::exp(-dt / std::max(1.0, smooth_seconds));
                ema_now    = ema_now*(1.0-alpha_now)     + hps*alpha_now;
                ema_smooth = ema_smooth*(1.0-alpha_smooth)+ hps*alpha_smooth;

                ui.hps_now.store(ema_now);
                ui.hps_smooth.store(ema_smooth);

                uint64_t total = ui.tries_total.load();
                ui.tries_total.store(total + delta + (uint64_t) (ui.gpu_hps_now.load()*dt));

                {
                    std::lock_guard<std::mutex> lk(ui.spark_mtx);
                    ui.sparkline.push_back(ui.hps_smooth.load() + ui.gpu_hps_smooth.load());
                    if(ui.sparkline.size() > 48) ui.sparkline.erase(ui.sparkline.begin());
                }

                last_sum = sum; last = now;
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        });
        meter.detach();

        auto build_header_prefix80 = [](const BlockHeader& H, const std::vector<uint8_t>& merkle)->std::vector<uint8_t>{
            std::vector<uint8_t> p;
            p.reserve(80);
            put_u32_le(p, H.version);
            p.insert(p.end(), H.prev_hash.begin(), H.prev_hash.end());
            p.insert(p.end(), merkle.begin(), merkle.end());
            put_u64_le(p, (uint64_t)H.time);
            put_u32_le(p, H.bits);
            return p; // 80 bytes
        };

        auto make_gpu_prefix = [&](const std::vector<uint8_t>& prefix80)->std::vector<uint8_t>{
            std::vector<uint8_t> out;
            if(salt_pos == SaltPos::PRE && !salt_bytes.empty()){
                out.reserve(salt_bytes.size()+prefix80.size());
                out.insert(out.end(), salt_bytes.begin(), salt_bytes.end());
                out.insert(out.end(), prefix80.begin(), prefix80.end());
            } else if(salt_pos == SaltPos::POST && !salt_bytes.empty()){
                out.reserve(prefix80.size()+salt_bytes.size());
                out.insert(out.end(), prefix80.begin(), prefix80.end());
                out.insert(out.end(), salt_bytes.begin(), salt_bytes.end());
            } else {
                out = prefix80;
            }
            return out; // kernel appends nonce LE + padding
        };

        // ===== mining loop ===================================================
        while(true){
            MinerTemplate tpl;
            if(!rpc_getminertemplate(rpc_host, rpc_port, token, tpl)){
                std::fprintf(stderr,"getminertemplate failed, retrying...\n");
                miq_sleep_ms(1000);
                continue;
            }

            // coinbase & tx pack
            Transaction dummy_cb = make_coinbase(tpl.height, 0, pkh);
            size_t coinbase_sz = ser_tx(dummy_cb).size();

            std::vector<Transaction> txs; uint64_t fees=0; size_t used_bytes=0;
            pack_template(tpl, coinbase_sz, txs, fees, used_bytes);

            Transaction cb = make_coinbase(tpl.height, fees, pkh);
            std::vector<Transaction> txs_inc; txs_inc.reserve(1+txs.size());
            txs_inc.push_back(cb);
            for(auto& t: txs) txs_inc.push_back(std::move(t));

            // publish candidate stats
            {
                std::lock_guard<std::mutex> lk(ui.mtx);
                ui.cand.height = tpl.height;
                ui.cand.prev_hex = to_hex_s(tpl.prev_hash);
                ui.cand.bits = tpl.bits;
                ui.cand.time = tpl.time;
                ui.cand.txs = txs_inc.size();
                ui.cand.size_bytes = used_bytes + ser_tx(cb).size();
                ui.cand.fees = fees;
                ui.cand.coinbase = GetBlockSubsidy((uint32_t)tpl.height) + fees;
            }

            // reset round stats
            ui.round_start_tries.store(ui.tries_total.load());
            ui.round_expected_hashes.store(difficulty_from_bits(tpl.bits) * 4294967296.0);

            // header base
            BlockHeader hb;
            hb.version = 1;
            hb.prev_hash = tpl.prev_hash;
            hb.time = std::max<int64_t>((int64_t)time(nullptr), tpl.time);
            hb.bits = tpl.bits;
            hb.nonce = 0;

            Block b; b.header = hb; b.txs = txs_inc;
            b.header.merkle_root = merkle_from(b.txs);

            // CPU threads
            std::atomic<bool> found{false};
            std::vector<std::thread> thv;
            Block found_block;

            for(unsigned tid=0; tid<threads; ++tid){
                thv.emplace_back(
                    mine_worker_optimized, hb, txs_inc, hb.bits,
                    &found, &thr_counts[tid], pin_affinity, tid, threads, &found_block
                );
            }

            // GPU worker (optional)
            std::thread gpu_th;
            uint8_t target_be[32]; bits_to_target_be(sanitize_bits(hb.bits), target_be);
            std::vector<uint8_t> prefix80 = build_header_prefix80(b.header, b.header.merkle_root);
            std::vector<uint8_t> gpuprefix = make_gpu_prefix(prefix80);

#if defined(MIQ_ENABLE_OPENCL)
            if(gpu_enabled){
                std::string gerr;
                if(!gpu.set_job(gpuprefix, target_be, &gerr)){
                    std::fprintf(stderr,"[GPU] job set failed: %s\n", gerr.c_str());
                } else {
                    gpu_th = std::thread([&](){
                        uint64_t base_nonce =
                            (static_cast<uint64_t>(time(nullptr))<<32) ^ 0x9e3779b97f4a7c15ull ^ 0xa5a5a5a5ULL;
                        while(!found.load(std::memory_order_relaxed)){
                            uint64_t n=0; bool ok=false; double ghps=0.0;
                            if(!gpu.run_round(base_nonce, gpu_npi, n, ok, ghps, 0.25, 2.0)){
                                std::fprintf(stderr,"[GPU] run_round failed.\n");
                                break;
                            }
                            g_ui->gpu_hps_now.store(gpu.ema_now);
                            g_ui->gpu_hps_smooth.store(gpu.ema_smooth);

                            if(ok){
                                found_block = b;
                                found_block.header.nonce = n;
                                found.store(true);
                                break;
                            }
                            base_nonce += (uint64_t)gpu.gws * (uint64_t)gpu_npi;
                        }
                    });
                }
            }
#endif

            // wait CPU threads
            for(auto& th: thv) th.join();

            // stop GPU thread if running
#if defined(MIQ_ENABLE_OPENCL)
            if(gpu_th.joinable()){
                found.store(true);
                gpu_th.join();
            }
#endif

            // Recheck template staleness
            TipInfo tip_now{};
            if(rpc_gettipinfo(rpc_host, rpc_port, token, tip_now)){
                if(from_hex_s(tip_now.hash_hex) != tpl.prev_hash){
                    {
                        std::lock_guard<std::mutex> lk(ui.mtx);
                        ui.last_submit_msg = std::string("submit skipped: template stale (chain advanced)");
                        ui.last_submit_when = std::chrono::steady_clock::now();
                    }
                    continue;
                }
            }

            // safety: verify target using canonical block hash
            auto hchk = found_block.block_hash();
            if(!meets_target_be_raw(hchk.data(), hb.bits)){
                std::lock_guard<std::mutex> lk(ui.mtx);
                ui.last_submit_msg = "internal: solved header doesn't meet target (skipping)";
                ui.last_submit_when = std::chrono::steady_clock::now();
                continue;
            }

            // Submit
            auto raw = miq::ser_block(found_block);
            std::string hexblk = miq::to_hex(raw);

            std::string ok_body, err_body;
            bool ok = rpc_submitblock_any(rpc_host, rpc_port, token, ok_body, err_body, hexblk);

            if(ok){
                // Confirm acceptance (tip should move)
                bool confirmed = false;
                for(int i=0;i<40;i++){
                    TipInfo t2{};
                    if(rpc_gettipinfo(rpc_host, rpc_port, token, t2)){
                        if(t2.height == tpl.height && t2.hash_hex == miq::to_hex(found_block.block_hash())){
                            confirmed = true; break;
                        }
                    }
                    miq_sleep_ms(100);
                }

                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    if(confirmed){
                        ui.mined_blocks.fetch_add(1);
                        ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                        std::ostringstream m; m << C("32;1") << "submit accepted @ height=" << tpl.height
                                                << " hash=" << ui.last_found_block_hash << R();
                        ui.last_submit_msg = m.str();
                        ui.last_tip_was_mine.store(true);
                        ui.last_winner_addr.clear();

                        rpc_minerlog_best_effort(rpc_host, rpc_port, token,
                            std::string("miner: accepted block at height ")
                            + std::to_string(tpl.height) + " " + ui.last_found_block_hash);
                    }else{
                        ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                        std::ostringstream m; m << C("33;1") << "submit accepted (pending tip refresh) hash=" << ui.last_found_block_hash << R();
                        ui.last_submit_msg = m.str();
                    }
                    ui.last_submit_when = std::chrono::steady_clock::now();
                }
            } else {
                std::lock_guard<std::mutex> lk(ui.mtx);
                std::ostringstream m; m << C("31;1") << "submit REJECTED / RPC failed" << R();
                if(!err_body.empty()){
                    std::string msg;
                    if(json_find_string(err_body,"error",msg)) m << ": " << msg;
                }
                ui.last_submit_msg = m.str();
                ui.last_submit_when = std::chrono::steady_clock::now();
            }
        }

    } catch(const std::exception& ex){
        std::fprintf(stderr,"[FATAL] %s\n", ex.what());
        return 1;
    } catch(...){
        std::fprintf(stderr,"[FATAL] unknown\n");
        return 1;
    }
}
