// src/cli/miqminer_rpc.cpp
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
#include <fstream>
#include <unordered_map>
#include <signal.h>

#if defined(_WIN32)
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
  // Winsock must be included BEFORE windows.h to avoid winsock.h conflicts.
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #include <direct.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  using socket_t = SOCKET;
  #define miq_closesocket closesocket
  static void miq_sleep_ms(unsigned ms){ Sleep(ms); }
  static void set_socket_timeouts(socket_t s, int ms_send, int ms_recv){
    DWORD tvs = (DWORD)ms_send, tvr = (DWORD)ms_recv;
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tvs, sizeof(tvs));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tvr, sizeof(tvr));
  }
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
  #include <sys/ioctl.h>
  using socket_t = int;
  #define miq_closesocket ::close
  static void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
  static void set_socket_timeouts(socket_t s, int ms_send, int ms_recv){
    struct timeval tvs{ ms_send/1000, (int)((ms_send%1000)*1000) };
    struct timeval tvr{ ms_recv/1000, (int)((ms_recv%1000)*1000) };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tvs, sizeof(tvs));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tvr, sizeof(tvr));
  }
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
      #include <OpenCL/opencl.h>
    #else
      #include <CL/cl.h>
    #endif
  #endif
#endif

using namespace miq;

// ===== brand & color =========================================================
static bool g_use_ansi = true;
static inline std::string C(const char* code){ return g_use_ansi ? std::string("\x1b[")+code+"m" : std::string(); }
static inline std::string R(){ return g_use_ansi ? std::string("\x1b[0m") : std::string(); }
static inline const char* CLS(){ return g_use_ansi ? "\x1b[2J\x1b[H" : ""; }
static inline void set_title(const std::string& t){
    if(!g_use_ansi) return;
    std::cout << "\x1b]0;" << t << "\x07";
}

// BIG ASCII banner (kept minimal & clean; cyan). This spells MiQ.
static const char* kChronenMinerBanner[] = {
"  __  __ _                                                                                      ",
" |  \\/  |                                                                                       ",
" | \\  / |                                                                                       ",
" | |\\/| |                                                                                       ",
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

struct TermSize { int cols{120}; int rows{40}; };
static TermSize get_term_size(){
    TermSize ts{};
#if defined(_WIN32)
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if(GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi)){
        ts.cols = (int)(csbi.srWindow.Right - csbi.srWindow.Left + 1);
        ts.rows = (int)(csbi.srWindow.Bottom - csbi.srWindow.Top + 1);
    }
#else
    struct winsize w{};
    if(ioctl(1, TIOCGWINSZ, &w)==0){
        if(w.ws_col) ts.cols = (int)w.ws_col;
        if(w.ws_row) ts.rows = (int)w.ws_row;
    }
#endif
    if(ts.cols < 60) ts.cols = 60;
    if(ts.rows < 24) ts.rows = 24;
    return ts;
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
    // Match node's default (~/.miqrochain/.cookie) for consistency.
    const char* home = std::getenv("HOME");
    if(home && *home) return std::string(home) + "/.miqrochain/.cookie";
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
    std::string s; s.reserve(256);
    char buf[4096];
    while(true){ size_t n=fread(buf,1,sizeof(buf),f); if(!n) break; s.append(buf,n); }
    fclose(f);
    while(!s.empty() && (s.back()=='\r'||s.back()=='\n'||s.back()==' '||s.back()=='\t')) s.pop_back();
    out = std::move(s); return true;
}
static std::string to_hex_s(const std::vector<uint8_t>& v){ return miq::to_hex(v); }
static std::vector<uint8_t> from_hex_s(const std::string& h){ return miq::from_hex(h); }

// ===== minimal timed logger ==================================================
static std::mutex g_log_mtx;
static void log_line(const std::string& m){
    std::lock_guard<std::mutex> lk(g_log_mtx);
    std::ofstream f("miqminer.log", std::ios::app);
    if(!f.good()) return;
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
#if defined(_WIN32)
    struct tm tmv; localtime_s(&tmv, &now);
    char buf[64]; strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",&tmv);
#else
    struct tm tmv; localtime_r(&now, &tmv);
    char buf[64]; strftime(buf,sizeof(buf),"%Y-%m-%d %H:%M:%S",&tmv);
#endif
    f << "[" << buf << "] " << m << "\n";
}

// ===== JSON helpers ==========================================================
static inline bool json_has_error(const std::string& json){
    size_t e = json.find("\"error\"");
    if(e==std::string::npos) return false;
    size_t colon = json.find(':', e);
    if(colon != std::string::npos){
        size_t p = json.find_first_not_of(" \t\r\n", colon+1);
        if(p != std::string::npos && json.compare(p,4,"null")==0) return false;
    }
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
static bool json_find_hex_or_number_u32(const std::string& json, const std::string& key, uint32_t& out){
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if(p==std::string::npos) return false;
    p += pat.size();
    while(p<json.size() && std::isspace((unsigned char)json[p])) ++p;
    if(p>=json.size()) return false;
    if(json[p]=='"'){
        ++p;
        size_t q=p;
        while(q<json.size() && std::isxdigit((unsigned char)json[q])) ++q;
        if(q==p) return false;
        std::string hex = json.substr(p,q-p);
        out = (uint32_t)strtoul(hex.c_str(), nullptr, 16);
        return true;
    }else{
        long long v=0;
        if(!json_find_number(json, key, v)) return false;
        out = (uint32_t)v;
        return true;
    }
}
static bool json_find_bool(const std::string& json, const std::string& key, bool& out){
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if(p==std::string::npos) return false;
    p += pat.size();
    while(p<json.size() && std::isspace((unsigned char)json[p])) ++p;
    if(p+4 <= json.size() && (0==json.compare(p,4,"true"))){ out=true;  return true; }
    if(p+5 <= json.size() && (0==json.compare(p,5,"false"))){ out=false; return true; }
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

static inline void store_u32_le(uint8_t* p, uint32_t x){
    p[0]=uint8_t((x>>0 )&0xff);
    p[1]=uint8_t((x>>8 )&0xff);
    p[2]=uint8_t((x>>16)&0xff);
    p[3]=uint8_t((x>>24)&0xff);
}

// ===== minimal HTTP/JSON-RPC ================================================
struct HttpResp { int code{0}; std::string body; };

static inline std::string str_tolower(std::string s){
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return s;
}
static std::string dechunk_if_needed(const std::string& raw){
    // Very small & safe dechunker (only if Transfer-Encoding: chunked is present).
    size_t hdr_end = raw.find("\r\n\r\n");
    if(hdr_end==std::string::npos) return raw;
    std::string headers = raw.substr(0, hdr_end);
    std::string lower = str_tolower(headers);
    if(lower.find("transfer-encoding: chunked")==std::string::npos) return raw;
    std::string body = raw.substr(hdr_end+4);
    std::string out; out.reserve(body.size());
    size_t p=0;
    while(p<body.size()){
        size_t eol = body.find("\r\n", p);
        if(eol==std::string::npos) break;
        std::string nhex = body.substr(p, eol-p);
        size_t chunk = 0;
        try{ chunk = (size_t)std::stoul(nhex, nullptr, 16); }catch(...){ break; }
        p = eol + 2;
        if(chunk==0) break;
        if(p+chunk > body.size()) break;
        out.append(body, p, chunk);
        p += chunk;
        if(p+2 <= body.size()) p += 2; // skip CRLF
    }
    return raw.substr(0, hdr_end+4) + out;
}

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
        set_socket_timeouts(s, 7000, 10000);
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = INVALID_SOCKET;
#else
        if(s<0) continue;
        set_socket_timeouts(s, 7000, 10000);
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

    // Handle chunked transfer (harden)
    std::string resp2 = dechunk_if_needed(resp);

    size_t sp = resp2.find(' ');
    if(sp == std::string::npos) return false;
    int code = std::atoi(resp2.c_str()+sp+1);
    size_t hdr_end = resp2.find("\r\n\r\n");
    std::string body = (hdr_end==std::string::npos)? std::string() : resp2.substr(hdr_end+4);
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

static bool rpc_getblockhash(const std::string& host, uint16_t port, const std::string& auth,
                             uint64_t height, std::string& out);
static bool rpc_getblock_time_bits(const std::string& host, uint16_t port, const std::string& auth,
                                   const std::string& hh, long long& out_time, uint32_t& out_bits);

static bool rpc_gettipinfo(const std::string& host, uint16_t port, const std::string& auth, TipInfo& out){
    // Fast path: dedicated RPC (if present)
    {
        HttpResp r;
        if (http_post(host, port, "/", auth, rpc_build("gettipinfo","[]"), r)
            && r.code==200 && !json_has_error(r.body)) {
            long long h=0,b=0,t=0; std::string hh;
            if (json_find_number(r.body,"height",h) &&
                json_find_string(r.body,"hash",hh) &&
                json_find_number(r.body,"bits",b) &&
                json_find_number(r.body,"time",t)) {
                out.height = (uint64_t)h;
                out.hash_hex = hh;
                out.bits = sanitize_bits((uint32_t)b);
                out.time = (int64_t)t;
                return true;
            }
        }
    }
    // Fallback (portable): getblockchaininfo → bestblockhash/blocks → getblock
    {
        HttpResp r;
        if (!http_post(host, port, "/", auth, rpc_build("getblockchaininfo","[]"), r)
            || r.code!=200 || json_has_error(r.body)) return false;
        long long blocks=0; std::string besthash;
        (void)json_find_number(r.body, "blocks", blocks);
        (void)json_find_string(r.body, "bestblockhash", besthash);
        if (besthash.empty()) {
            if (blocks<=0) return false;
            if (!rpc_getblockhash(host, port, auth, (uint64_t)blocks, besthash)) return false;
        }
        long long t=0; uint32_t bits=0;
        if (!rpc_getblock_time_bits(host, port, auth, besthash, t, bits)) return false;
        out.height = (blocks>0)? (uint64_t)blocks : 0;
        out.hash_hex = besthash;
        out.bits = sanitize_bits(bits ? bits : miq::GENESIS_BITS);
        out.time = (int64_t)t;
        return true;
    }
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

static bool rpc_getblock_time_bits(const std::string& host, uint16_t port, const std::string& auth,
                                   const std::string& hh, long long& out_time, uint32_t& out_bits){
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    long long t=0; uint32_t b=0;
    (void)json_find_number(r.body, "time", t);
    (void)json_find_hex_or_number_u32(r.body, "bits", b);
    if(!t && !b) return false;
    out_time = t;
    out_bits = sanitize_bits(b ? b : miq::GENESIS_BITS);
    return true;
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
static void rpc_minerlog_best_effort(const std::string& host, uint16_t port, const std::string& auth,
                                     const std::string& msg){
    std::ostringstream ps;
    ps << "[\"" << msg << "\"]";
    HttpResp r;
    (void)http_post(host, port, "/", auth, rpc_build("minerlog", ps.str()), r);
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

static std::string fmt_miq_whole_dot(uint64_t base_units){
    uint64_t whole = base_units / MIQ_COIN_UNITS;
    std::ostringstream o; o << whole << '.';
    return o.str();
}

// ===== MinerTemplate types & parsing ========================================
struct MinerTemplateTx {
    std::string hex;   // raw tx hex (serialized)
    uint64_t    fee{0};
    size_t      size{0}; // bytes (estimate ok)
};
struct MinerTemplate {
    uint64_t height{0};
    uint32_t bits{miq::GENESIS_BITS};
    int64_t  time{0};
    int64_t  mintime{0};
    size_t   max_block_bytes{1000000};
    std::vector<uint8_t> prev_hash; // 32 bytes
    std::vector<MinerTemplateTx> txs;
};

static void gbt_parse_transactions(const std::string& body, std::vector<MinerTemplateTx>& out){
    out.clear();
    const std::string key = "\"transactions\":";
    size_t p = body.find(key);
    if(p==std::string::npos) return;
    p += key.size();
    p = body.find('[', p);
    if(p==std::string::npos) return;
    size_t end = body.find(']', p);
    if(end==std::string::npos) end = body.size();

    size_t cur = p;
    while(true){
        size_t obj_start = body.find('{', cur);
        if(obj_start==std::string::npos || obj_start>=end) break;
        size_t obj_end = body.find('}', obj_start);
        if(obj_end==std::string::npos) break;

        MinerTemplateTx xt{};
        {
            size_t d = body.find("\"data\":", obj_start);
            if(d!=std::string::npos && d<obj_end){
                d = body.find('"', d+7);
                if(d!=std::string::npos && d<obj_end){
                    size_t q = body.find('"', d+1);
                    if(q!=std::string::npos && q<=obj_end){
                        xt.hex = body.substr(d+1, q-(d+1));
                    }
                }
            }
        }
        {
            size_t f = body.find("\"fee\":", obj_start);
            if(f!=std::string::npos && f<obj_end){
                size_t s=f+6;
                while(s<obj_end && std::isspace((unsigned char)body[s])) ++s;
                size_t e=s;
                while(e<obj_end && (std::isdigit((unsigned char)body[e]) || body[e]=='-' || body[e]=='+' )) ++e;
                if(e>s){
                    long long v = std::strtoll(body.c_str()+s, nullptr, 10);
                    if(v>0) xt.fee = (uint64_t)v;
                }
            }
        }
        {
            size_t s = body.find("\"size\":", obj_start);
            if(s!=std::string::npos && s<obj_end){
                size_t a=s+7;
                while(a<obj_end && std::isspace((unsigned char)body[a])) ++a;
                size_t b=a;
                while(b<obj_end && std::isdigit((unsigned char)body[b])) ++b;
                if(b>a){
                    long long v = std::strtoll(body.c_str()+a, nullptr, 10);
                    if(v>0) xt.size = (size_t)v;
                }
            }
            size_t w = body.find("\"weight\":", obj_start);
            if(xt.size==0 && w!=std::string::npos && w<obj_end){
                size_t a=w+9;
                while(a<obj_end && std::isspace((unsigned char)body[a])) ++a;
                size_t b=a;
                while(b<obj_end && std::isdigit((unsigned char)body[b])) ++b;
                if(b>a){
                    long long v = std::strtoll(body.c_str()+a, nullptr, 10);
                    if(v>0) xt.size = (size_t)((v+3)/4);
                }
            }
        }
        if(xt.size==0 && !xt.hex.empty()){
            xt.size = xt.hex.size()/2;
        }
        if(!xt.hex.empty()){
            out.push_back(std::move(xt));
        }
        cur = obj_end+1;
    }
}

static void miq_parse_template_txs(const std::string& body, std::vector<MinerTemplateTx>& out){
    out.clear();
    const std::string key = "\"txs\":";
    size_t p = body.find(key);
    if(p==std::string::npos) return;
    p += key.size();
    p = body.find('[', p);
    if(p==std::string::npos) return;
    size_t end = body.find(']', p);
    if(end==std::string::npos) end = body.size();

    size_t cur = p;
    while(true){
        size_t obj_start = body.find('{', cur);
        if(obj_start==std::string::npos || obj_start>=end) break;
        size_t obj_end = body.find('}', obj_start);
        if(obj_end==std::string::npos) break;

        MinerTemplateTx xt{};
        {
            size_t h = body.find("\"hex\":", obj_start);
            if(h!=std::string::npos && h<obj_end){
                h = body.find('"', h+6);
                if(h!=std::string::npos && h<obj_end){
                    size_t q = body.find('"', h+1);
                    if(q!=std::string::npos && q<=obj_end){
                        xt.hex = body.substr(h+1, q-(h+1));
                    }
                }
            }
        }
        {
            size_t f = body.find("\"fee\":", obj_start);
            if(f!=std::string::npos && f<obj_end){
                size_t s=f+6;
                while(s<obj_end && std::isspace((unsigned char)body[s])) ++s;
                size_t e=s;
                while(e<obj_end && (std::isdigit((unsigned char)body[e]) || body[e]=='-' || body[e]=='+' )) ++e;
                if(e>s){
                    long long v = std::strtoll(body.c_str()+s, nullptr, 10);
                    if(v>0) xt.fee = (uint64_t)v;
                }
            }
        }
        {
            size_t s = body.find("\"vsize\":", obj_start);
            if(s!=std::string::npos && s<obj_end){
                size_t a=s+8;
                while(a<obj_end && std::isspace((unsigned char)body[a])) ++a;
                size_t b=a;
                while(b<obj_end && std::isdigit((unsigned char)body[b])) ++b;
                if(b>a){
                    long long v = std::strtoll(body.c_str()+a, nullptr, 10);
                    if(v>0) xt.size = (size_t)v;
                }
            }
        }
        if(xt.size==0 && !xt.hex.empty()) xt.size = xt.hex.size()/2;
        if(!xt.hex.empty()) out.push_back(std::move(xt));
        cur = obj_end+1;
    }
}

static bool rpc_getminertemplate(const std::string& host, uint16_t port, const std::string& auth, MinerTemplate& out){
    {
        HttpResp r;
        if(http_post(host, port, "/", auth, rpc_build("getminertemplate","[]"), r) && r.code==200 && !json_has_error(r.body)){
            uint32_t bits=0;
            std::string prev;
            long long height=0, curtime=0, mintime=0, mbs=0;

            (void)json_find_hex_or_number_u32(r.body, "bits", bits);
            json_find_string(r.body, "prev_hash", prev);
            (void)json_find_number(r.body, "height", height);
            (void)json_find_number(r.body, "time",   curtime);
            (void)json_find_number(r.body, "mintime", mintime);
            (void)json_find_number(r.body, "max_block_bytes", mbs);

            out.bits   = sanitize_bits(bits ? bits : miq::GENESIS_BITS);
            out.height = (uint64_t)((height>0)?height:0);
            out.time   = (int64_t)((curtime>0)?curtime:(long long)time(nullptr));
            out.mintime= (int64_t)((mintime>0)?mintime:0);
            out.prev_hash = prev.empty()? std::vector<uint8_t>(32,0) : from_hex_s(prev);
            out.txs.clear();
            miq_parse_template_txs(r.body, out.txs);
            out.max_block_bytes = (mbs>0)? (size_t)mbs : 900*1024;

            if(out.height==0){
                TipInfo t{};
                if(rpc_gettipinfo(host,port,auth,t)) out.height = t.height + 1;
            }
            if(out.time < out.mintime) out.time = out.mintime;
            return true;
        }
    }
    {
        HttpResp r;
        if(http_post(host, port, "/", auth, rpc_build("getblocktemplate","[{}]"), r) && r.code==200 && !json_has_error(r.body)){
            uint32_t bits=0;
            std::string prev;
            long long height=0, curtime=0;
            if(!json_find_hex_or_number_u32(r.body, "bits", bits)) bits = miq::GENESIS_BITS;
            json_find_string(r.body, "previousblockhash", prev);
            if(prev.empty()) json_find_string(r.body, "prevhash", prev);
            (void)json_find_number(r.body, "height", height);
            (void)json_find_number(r.body, "curtime", curtime);
            if(!curtime) (void)json_find_number(r.body, "time", curtime);

            out.bits   = sanitize_bits(bits);
            out.height = (uint64_t)((height>0)?height:0);
            out.time   = (int64_t)((curtime>0)?curtime:(long long)time(nullptr));
            out.mintime= 0;
            out.prev_hash = prev.empty()? std::vector<uint8_t>(32,0) : from_hex_s(prev);
            out.txs.clear();
            gbt_parse_transactions(r.body, out.txs);

            long long lim=0;
            if(json_find_number(r.body, "sizelimit", lim) ||
               json_find_number(r.body, "maxblocksize", lim) ||
               json_find_number(r.body, "max_block_bytes", lim) ||
               json_find_number(r.body, "max_block_size", lim))
            {
                if(lim>0) out.max_block_bytes = (size_t)lim;
                else out.max_block_bytes = 1000000;
            } else {
                out.max_block_bytes = 1000000;
            }

            if(out.height==0){
                TipInfo t{};
                if(rpc_gettipinfo(host,port,auth,t)) out.height = t.height + 1;
            }
            return true;
        }
    }
    TipInfo t{};
    if(!rpc_gettipinfo(host,port,auth,t)) return false;
    out.height = t.height + 1;
    out.bits   = t.bits ? t.bits : miq::GENESIS_BITS;
    out.time   = std::max<int64_t>((int64_t)time(nullptr), t.time + 1);
    out.mintime= 0;
    out.prev_hash = from_hex_s(t.hash_hex);
    out.max_block_bytes = 1000000;
    out.txs.clear();
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
    // rpc endpoint
    std::string rpc_host;
    uint16_t    rpc_port{0};

    // mining telemetry
    std::atomic<uint64_t> tries_total{0};
    std::atomic<uint64_t> mined_blocks{0};
    std::atomic<double>   net_hashps{0.0};
    std::atomic<double>   hps_now{0.0};
    std::atomic<double>   hps_smooth{0.0};

    // tip/candidate
    std::atomic<uint64_t> tip_height{0};
    std::string tip_hash_hex;
    std::atomic<uint32_t> tip_bits{0};
    CandidateStats cand{};
    std::mutex mtx;
    LastBlockInfo lastblk{};
    std::string last_found_block_hash;
    std::string last_submit_msg;
    std::chrono::steady_clock::time_point last_submit_when{};

    // address
    std::vector<uint8_t> my_pkh;

    // last winner
    std::atomic<uint64_t> last_seen_height{0};
    std::atomic<bool> last_tip_was_mine{false};
    std::string last_winner_addr;

    // sparkline
    std::mutex spark_mtx;
    std::vector<double> sparkline;

    // round stats
    std::atomic<uint64_t> round_start_tries{0};
    std::atomic<double>   round_expected_hashes{0.0};

    // wallet-ish estimations
    std::atomic<uint64_t> total_received_base{0};
    std::atomic<uint64_t> est_total_base{0};
    std::atomic<uint64_t> est_matured_base{0};
    std::atomic<uint64_t> est_scanned_height{0};
    std::mutex            myblks_mtx;
    std::set<uint64_t>    my_block_heights;
    std::vector<std::pair<uint64_t,uint64_t>> my_blocks;

    // hash preview
    std::array<uint8_t,32> next_hash_sample{};
    std::mutex next_hash_mtx;

    // GPU telemetry
    std::atomic<bool>   gpu_available{false};
    std::string         gpu_platform;
    std::string         gpu_device;
    std::string         gpu_driver;
    std::atomic<double> gpu_hps_now{0.0};
    std::atomic<double> gpu_hps_smooth{0.0};

    // node sync/health
    std::atomic<bool>   node_reachable{false};
    std::atomic<bool>   node_synced{false};
    std::atomic<int>    node_peers{0};
    std::atomic<uint64_t> node_headers{0};
    std::atomic<uint64_t> node_blocks{0};
    std::atomic<double>   node_verification{0.0};
    std::atomic<int>      rpc_errors{0};

    // shutdown
    std::atomic<bool>    running{true};
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
[[maybe_unused]] static std::string fmt_eta(double seconds){
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
static std::string progress_bar(double p, size_t width){
    if(p<0) { p=0; }
    if(p>1) { p=1; }
    size_t full = (size_t)std::floor(p*width);
    std::string s="["; 
    for(size_t i=0;i<width;i++) s.push_back(i<full? '#' : '-');
    s.push_back(']'); 
    std::ostringstream o; o<<s<<" "<<std::fixed<<std::setprecision(1)<<(p*100.0)<<"%";
    return o.str();
}

// ===== Intro splash & robust address prompt =================================
static void enable_virtual_terminal(){
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) { DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004); }
#endif
}
static bool prompt_address_until_valid(std::string& out_addr){
    for(;;){
        std::cout << "\n  Enter P2PKH Base58 address to mine to: " << std::flush;
        if(!std::getline(std::cin, out_addr)) return false;
        trim(out_addr);
        if(out_addr.empty()) continue;
        std::vector<uint8_t> tmp;
        if(parse_p2pkh(out_addr, tmp)) return true;
        std::cout << "  " << C("31;1") << "Invalid address." << R()
                  << " Expecting Base58Check P2PKH (version 0x"
                  << std::hex << std::setw(2) << std::setfill('0') << (unsigned)miq::VERSION_P2PKH
                  << std::dec << "). Try again.\n";
    }
}
static void show_intro(){
    using clock = std::chrono::steady_clock;
    auto t0 = clock::now();
    int spin = 0;
    while(std::chrono::duration<double>(clock::now()-t0).count() < 2.0){
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
        s << "\n  " << C("33;1") << "INITIALIZING" << R() << "\n";
        std::cout << s.str() << std::flush;
        miq_sleep_ms(1000/12);
    }
}

// ===== OpenCL GPU miner ======================================================
enum class SaltPos { NONE=0, PRE=1, POST=2 };

#if defined(MIQ_ENABLE_OPENCL)
// ----------------- START OpenCL kernel string --------------------------------
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
  s->h[4]=0x510e527f; s->h[5]=0x9b05688; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
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
  u64 L = (u64)prefix_len + 4u;
  u64 Lbits = L * 8u;

  for(int i=0;i<64;i++){
    u64 off = (u64)blk_idx*64u + (u64)i;
    u8 v = 0;
    if(off < (u64)prefix_len){
      v = prefix[off];
    } else if(off < (u64)prefix_len + 4u){
      uint j = (uint)(off - (u64)prefix_len);
      v = (u8)((nonce_le >> (8u*j)) & 0xffu);
    } else if(off == (u64)prefix_len + 4u){
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
  u64 L = (u64)prefix_len + 4u;
  uint nblks = (uint)((L + 1u + 8u + 63u)/64u);
  SHA256 S; sha256_init(&S);
  for(uint b=0;b<nblks;b++){
    u32 W16[16];
    build_block(W16, prefix, prefix_len, nonce_le, b, nblks);
    sha256_compress(&S, W16);
  }
  u8 H[32];
  for(int i=0;i<8;i++){
    H[i*4+0]=(u8)((S.h[i]>>24)&0xff);
    H[i*4+1]=(u8)((S.h[i]>>16)&0xff);
    H[i*4+2]=(u8)((S.h[i]>> 8)&0xff);
    H[i*4+3]=(u8)((S.h[i]>> 0)&0xff);
  }
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
// ----------------- END OpenCL kernel string ---------------------------------

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
#else
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
#elif defined(__linux__)
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(tid % CPU_SETSIZE, &set);
    sched_setaffinity(0, sizeof(set), &set);
#else
    (void)tid;
#endif
}

// ===== miner core (CPU) ======================================================
struct ThreadCounter { std::atomic<uint64_t> hashes{0}; };

static void mine_worker_optimized(const BlockHeader hdr_base,
                                  const std::vector<Transaction> txs_including_cb,
                                  uint32_t bits,
                                  std::atomic<bool>* found,
                                  std::atomic<bool>* abort_round,
                                  ThreadCounter* counter,
                                  bool pin_affinity,
                                  unsigned tid, unsigned stride,
                                  Block* out_block)
{
    if(pin_affinity) pin_thread_to_cpu(tid);

    Block b; b.header = hdr_base; b.txs = txs_including_cb;
    b.header.merkle_root = merkle_from(b.txs);

    std::vector<uint8_t> header_prefix;
    header_prefix.reserve(4+32+32+4+4);
    put_u32_le(header_prefix, b.header.version);
    header_prefix.insert(header_prefix.end(), b.header.prev_hash.begin(),   b.header.prev_hash.end());
    header_prefix.insert(header_prefix.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
    put_u32_le(header_prefix, (uint32_t)b.header.time);
    put_u32_le(header_prefix, b.header.bits);
    const size_t nonce_off = header_prefix.size();

    bits = sanitize_bits(bits);

#if !defined(MIQ_POW_SALT)
    FastSha256Ctx base1;
    fastsha_init(base1);
    fastsha_update(base1, header_prefix.data(), header_prefix.size());
#endif

    std::vector<uint8_t> hdr = header_prefix;
    hdr.resize(header_prefix.size() + 4);
    uint8_t* nonce_ptr = hdr.data() + nonce_off;
    (void)nonce_ptr;

    const uint64_t base_nonce =
        (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull;

    uint64_t nonce = base_nonce + (uint64_t)tid;
    const uint64_t step  = (uint64_t)stride;

    const uint64_t BATCH = (1ull<<15);
    uint64_t local_hashes = 0;

    while(!found->load(std::memory_order_relaxed) && !abort_round->load(std::memory_order_relaxed)){
        uint64_t todo = BATCH;
        while(todo && !found->load(std::memory_order_relaxed) && !abort_round->load(std::memory_order_relaxed)){
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
            uint8_t le4[8][4];
            store_u32_le(le4[0], (uint32_t)n0); dsha256_from_base(base1, le4[0], 4, h[0]);
            store_u32_le(le4[1], (uint32_t)n1); dsha256_from_base(base1, le4[1], 4, h[1]);
            store_u32_le(le4[2], (uint32_t)n2); dsha256_from_base(base1, le4[2], 4, h[2]);
            store_u32_le(le4[3], (uint32_t)n3); dsha256_from_base(base1, le4[3], 4, h[3]);
            store_u32_le(le4[4], (uint32_t)n4); dsha256_from_base(base1, le4[4], 4, h[4]);
            store_u32_le(le4[5], (uint32_t)n5); dsha256_from_base(base1, le4[5], 4, h[5]);
            store_u32_le(le4[6], (uint32_t)n6); dsha256_from_base(base1, le4[6], 4, h[6]);
            store_u32_le(le4[7], (uint32_t)n7); dsha256_from_base(base1, le4[7], 4, h[7]);
        #else
            store_u32_le(nonce_ptr, (uint32_t)n0); { auto hv = salted_header_hash(hdr); std::memcpy(h[0], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n1); { auto hv = salted_header_hash(hdr); std::memcpy(h[1], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n2); { auto hv = salted_header_hash(hdr); std::memcpy(h[2], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n3); { auto hv = salted_header_hash(hdr); std::memcpy(h[3], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n4); { auto hv = salted_header_hash(hdr); std::memcpy(h[4], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n5); { auto hv = salted_header_hash(hdr); std::memcpy(h[5], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n6); { auto hv = salted_header_hash(hdr); std::memcpy(h[6], hv.data(), 32); }
            store_u32_le(nonce_ptr, (uint32_t)n7); { auto hv = salted_header_hash(hdr); std::memcpy(h[7], hv.data(), 32); }
        #endif

            if(meets_target_be_raw(h[0], bits)){ b.header.nonce=n0; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[1], bits)){ b.header.nonce=n1; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[2], bits)){ b.header.nonce=n2; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[3], bits)){ b.header.nonce=n3; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[4], bits)){ b.header.nonce=n4; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[5], bits)){ b.header.nonce=n5; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[6], bits)){ b.header.nonce=n6; *out_block=b; found->store(true); break; }
            if(meets_target_be_raw(h[7], bits)){ b.header.nonce=n7; *out_block=b; found->store(true); break; }

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
        if(found->load(std::memory_order_relaxed) || abort_round->load(std::memory_order_relaxed)) break;
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
        size_t sz = xt.size ? xt.size : ser_tx(t).size();
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
    "Notes:\n"
    "  - Token from --token, MIQ_RPC_TOKEN, or datadir/.cookie\n"
    "  - Default threads: 6 (override with --threads)\n"
    "  - GPU requires build with -DMIQ_ENABLE_OPENCL and OpenCL runtime installed\n";
}

// ===== graceful shutdown =====================================================
static std::atomic<bool>* g_running_flag = nullptr;
#if defined(_WIN32)
static BOOL WINAPI ctrl_handler(DWORD type){
    if(type==CTRL_C_EVENT || type==CTRL_CLOSE_EVENT || type==CTRL_BREAK_EVENT){
        if(g_running_flag) g_running_flag->store(false);
        return TRUE;
    }
    return FALSE;
}
#else
static void sig_handler(int){
    if(g_running_flag) g_running_flag->store(false);
}
#endif

// ===== main ==================================================================
int main(int argc, char** argv){
    try{
        enable_virtual_terminal();
        set_title("Chronen Miner");

        std::string rpc_host = "127.0.0.1";
        uint16_t    rpc_port = (uint16_t)miq::RPC_PORT;
        std::string token;
        unsigned threads = 6;
        std::string address_cli;
        bool pin_affinity = false;
        bool high_priority = false;
        double smooth_seconds = 15.0;

#if defined(MIQ_ENABLE_OPENCL)
        bool   gpu_enabled = true;
        int    gpu_platform_index = 0;
        int    gpu_device_index   = -1;
        size_t gpu_gws = 131072;
        uint32_t gpu_npi = 512;
#else
        [[maybe_unused]] bool   gpu_enabled = false;
        [[maybe_unused]] int    gpu_platform_index = 0;
        [[maybe_unused]] int    gpu_device_index   = -1;
        [[maybe_unused]] size_t gpu_gws = 0;
        [[maybe_unused]] uint32_t gpu_npi = 0;
#endif

        std::vector<uint8_t> salt_bytes;
        SaltPos salt_pos = SaltPos::NONE;

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
#if defined(MIQ_ENABLE_OPENCL)
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
#endif
            } else if(a.rfind("--salt-hex=",0)==0){
                std::string hx = a.substr(11);
                try { salt_bytes = from_hex_s(hx); } catch(...) { std::fprintf(stderr,"Bad --salt-hex\n"); return 2; }
            } else if(a.rfind("--salt-pos=",0)==0){
                std::string p = a.substr(11);
                std::transform(p.begin(),p.end(),p.begin(),::tolower);
                if(p=="pre") salt_pos = SaltPos::PRE;
                else if(p=="post") salt_pos = SaltPos::POST;
                else salt_pos = SaltPos::NONE;
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
        if(const char* aenv = std::getenv("MIQ_ADDRESS")){
            if(address_cli.empty()) address_cli = aenv;
        }

        set_process_priority(high_priority);

        // ===== Splash & address
        show_intro();
        std::string addr = address_cli;

        if(!addr.empty()){
            std::vector<uint8_t> tmp;
            if(!parse_p2pkh(addr, tmp)) addr.clear();
        }
        if(addr.empty()){
            if(!prompt_address_until_valid(addr)){
                std::fprintf(stderr,"stdin closed\n"); return 1;
            }
        }

        std::vector<uint8_t> pkh;
        if(!parse_p2pkh(addr, pkh)){
            std::fprintf(stderr,"Invalid address (expected Base58Check P2PKH, version 0x%02x)\n",(unsigned)miq::VERSION_P2PKH);
            return 1;
        }

        // UI + shared state
        GpuMiner gpu;
        UIState ui;
        g_ui = &ui;
        g_running_flag = &ui.running;
        ui.my_pkh = pkh;
        ui.rpc_host = rpc_host;
        ui.rpc_port = rpc_port;

#if defined(_WIN32)
        SetConsoleCtrlHandler(ctrl_handler, TRUE);
#else
        signal(SIGINT, sig_handler);
        signal(SIGTERM, sig_handler);
#endif

#if defined(MIQ_ENABLE_OPENCL)
        if(gpu_enabled){
            std::string gerr;
            if(!gpu.init(gpu_platform_index, gpu_device_index, gpu_gws, gpu_npi, &gerr)){
                std::fprintf(stderr,"[GPU] init failed: %s\n", gerr.c_str());
                log_line(std::string("[GPU] init failed: ")+gerr);
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
                log_line("[GPU] platform: "+ui.gpu_platform+" device: "+ui.gpu_device+" driver: "+ui.gpu_driver);
            }
        }
#else
        if(gpu_enabled){
            std::fprintf(stderr,"[GPU] disabled: binary not built with -DMIQ_ENABLE_OPENCL\n");
            gpu_enabled = false;
        }
#endif

        // ===== UI thread (animated dashboard)
        std::thread ui_th([&](){
            using clock = std::chrono::steady_clock;
            const int FPS = 12;
            const auto frame_dt = std::chrono::milliseconds(1000/FPS);
            int spin_idx = 0;

            // Config card (one-time)
            {
                std::ostringstream s;
                s << CLS();
                s << C("36;1");
                const size_t kBannerN = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
                for(size_t i=0;i<kBannerN;i++) s << "  " << kChronenMinerBanner[i] << "\n";
                s << R() << "\n";
                s << "  " << C("1") << "Endpoint: " << R() << ui.rpc_host << ":" << ui.rpc_port << "\n";
                s << "  " << C("1") << "Address : " << R() << pkh_to_address(ui.my_pkh) << "\n";
                s << "  " << C("1") << "Threads : " << R() << (int)threads << (pin_affinity?"  (affinity)":"") << (high_priority?"  (high-priority)":"") << "\n";
#if defined(MIQ_ENABLE_OPENCL)
                s << "  " << C("1") << "GPU     : " << R() << (ui.gpu_available.load() ? (ui.gpu_platform+" / "+ui.gpu_device) : std::string("(disabled)")) << "\n";
#endif
                s << "\n  Preparing dashboard…\n";
                std::cout << s.str() << std::flush;
                miq_sleep_ms(650);
            }

            while(ui.running.load(std::memory_order_relaxed)){
                TermSize ts = get_term_size();
                std::ostringstream out;
                out << CLS();

                // Banner
                out << C("36;1");
                const size_t kBannerN = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
                for(size_t i=0;i<kBannerN;i++) out << "  " << kChronenMinerBanner[i] << "\n";
                out << R() << "\n";

                out << "  " << C("1") << "RPC: " << R() << ui.rpc_host << ":" << ui.rpc_port
                    << "   " << C(ui.node_reachable.load()? "32;1" : "31;1")
                    << (ui.node_reachable.load()? "[CONNECTED]" : "[UNREACHABLE]") << R() << "\n";

                // Tip / candidate
                uint64_t th = ui.tip_height.load();
                if(th){
                    out << "  " << C("1") << "Tip:  " << R() << "height=" << th
                        << "  hash=" << ui.tip_hash_hex << "\n";
                    uint32_t bits = ui.tip_bits.load();
                    out << "       " << "bits=0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)bits
                        << std::dec << "  (difficulty " << std::fixed << std::setprecision(2) << difficulty_from_bits(bits) << ")\n";
                }

                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    if(ui.cand.height){
                        out << "\n";
                        out << "  " << C("36;1") << "Job:" << R()
                            << " height=" << ui.cand.height
                            << " prev=" << ui.cand.prev_hex
                            << " bits=0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)ui.cand.bits << std::dec
                            << " txs=" << ui.cand.txs
                            << " size=" << ui.cand.size_bytes << "B"
                            << " fees=" << fmt_miq_amount(ui.cand.fees)
                            << " coinbase=" << C("32;1") << fmt_miq_amount(ui.cand.coinbase) << R() << "\n";

                        // live next-hash preview
                        std::string nxh;
                        {
                            std::lock_guard<std::mutex> lk2(ui.next_hash_mtx);
                            std::ostringstream hh;
                            for(int i=0;i<32;i++) hh << std::hex << std::setw(2) << std::setfill('0') << (unsigned)ui.next_hash_sample[i];
                            nxh = hh.str();
                        }
                        if(!nxh.empty()){
                            out << "       next-hash: " << C("2") << nxh.substr(0,64) << R() << "\n";
                        }
                    } else {
                        out << "\n  " << C("33;1") 
                            << (ui.node_synced.load()? "preparing job..." : "syncing… waiting for job") 
                            << R() << "\n";
                    }
                }

                // Last block
                if(ui.lastblk.height){
                    const auto& lb = ui.lastblk;
                    out << "\n";
                    out << "  " << C("33;1") << "Last block:" << R()
                        << " height=" << lb.height
                        << " hash=" << lb.hash_hex
                        << " txs=" << lb.txs << "\n";
                    if(!lb.coinbase_txid_hex.empty())
                        out << "              coinbase_txid=" << lb.coinbase_txid_hex << "\n";
                    if(!lb.coinbase_pkh.empty()){
                        const std::string winner = pkh_to_address(lb.coinbase_pkh);
                        out << "              paid to: " << winner
                            << "  (pkh=" << to_hex_s(lb.coinbase_pkh) << ")\n";
                        uint64_t expected = GetBlockSubsidy((uint32_t)lb.height);
                        if(lb.reward_value){
                            uint64_t normalized = (lb.reward_value ? lb.reward_value : expected);
                            out << "              reward: expected " << fmt_miq_amount(expected)
                                << " | node " << fmt_miq_amount(normalized) << "\n";
                        }else{
                            out << "              reward: expected " << fmt_miq_amount(expected) << "\n";
                        }
                    }
                }

                // Hashrates + wallet ests
                out << "\n";
                out << "  " << C("1") << "CPU: " << R() << C("36") << fmt_hs(ui.hps_smooth.load()) << R()
                    << "  " << C("2") << "(now " << fmt_hs(ui.hps_now.load()) << ")" << R() << "\n";
                if(ui.gpu_available.load()){
                    out << "  " << C("1") << "GPU: " << R()
                        << C("36") << fmt_hs(ui.gpu_hps_smooth.load()) << R()
                        << "  " << C("2") << "(now " << fmt_hs(ui.gpu_hps_now.load()) << ")" << R() << "\n";
                } else {
                    out << "  " << C("1") << "GPU: " << R() << C("2") << "(not available)" << R() << "\n";
                }
                out << "  " << C("1") << "Network: " << R() << fmt_hs(ui.net_hashps.load()) << "\n";
                out << "  " << C("1") << "Mined (session): " << R() << ui.mined_blocks.load() << "\n";

                uint64_t paid_base = ui.total_received_base.load();
                out << "  " << C("1") << "Payout addr: " << R() << pkh_to_address(ui.my_pkh) << "\n";
                out << "  " << C("1") << "Paid total : " << R()
                    << C("36;1") << fmt_miq_whole_dot(paid_base) << R()
                    << "  " << C("2") << "(" << fmt_miq_amount(paid_base) << ")" << R();
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

                if(ui.last_seen_height.load() == ui.tip_height.load()){
                    if(ui.last_tip_was_mine.load()){
                        out << "  " << C("32;1") << "YOU MINED THE LATEST BLOCK." << R() << "\n";
                    }else if(!ui.last_winner_addr.empty()){
                        out << "  " << C("31;1") << "Another miner won the latest block: " << ui.last_winner_addr << R() << "\n";
                    }
                }

                {
                    auto age = std::chrono::duration<double>(clock::now() - ui.last_submit_when).count();
                    if(!ui.last_submit_msg.empty() && age < 7.0){
                        out << "  " << ui.last_submit_msg << "\n";
                    }
                }

                {
                    std::lock_guard<std::mutex> lk(ui.spark_mtx);
                    if(!ui.sparkline.empty()){
                        out << "\n  " << C("2") << "h/s trend:" << R() << "        " << spark_ascii(ui.sparkline) << "\n";
                    }
                }

                // Animated cards
                std::array<std::string,5> spin_rows;
                spinner_circle_ascii(spin_idx, spin_rows);
                ++spin_idx;
                {
                    std::vector<std::string> lines;
                    lines.push_back("  ##############################   ##############################");
                    lines.push_back("  #                            #   #                            #");
                    lines.push_back("  #"+center_fit("MINER STATUS", 28)+"#   #"+center_fit("CHRONEN  MINER", 28)+"#");
                    lines.push_back("  #                            #   #                            #");
                    for(int r=0;r<5;r++){
                        lines.push_back("  #"+center_fit(spin_rows[r], 28)+"#   #"+center_fit("                    ", 28)+"#");
                    }
                    lines.push_back("  ##############################   ##############################");
                    for(const auto& L : lines) out << C("36") << L << R() << "\n";
                }

                out << "\n  Press Ctrl+C to quit.\n";
                std::cout << out.str() << std::flush;
                std::this_thread::sleep_for(frame_dt);
            }
        });
        ui_th.detach();

        // ===== watcher thread (sync, tip, stats, wallet-ish)
        std::thread watch([&](){
            uint64_t last_seen_h = 0;
            int tick=0;
            while(ui.running.load()){
                ui.node_reachable.store(false);

                // Tip + network hashps
                TipInfo t;
                if(rpc_gettipinfo(rpc_host, rpc_port, token, t)){
                    ui.node_reachable.store(true);
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

                    // fallback scan to estimate totals
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
                                    if (lb.reward_value) reward_base = lb.reward_value;
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
                            ui.total_received_base.store(est_matured);
                        }
                    }
                }

                if((++tick % 10)==0){
                    // best-effort payout total discovery (optional hook)
                    (void)ui.total_received_base.load();
                }

                for(int i=0;i<10 && ui.running.load();i++) miq_sleep_ms(100);
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
            while(ui.running.load()){
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
                for(int i=0;i<10 && ui.running.load(); ++i) miq_sleep_ms(20);
            }
        });
        meter.detach();

#if defined(MIQ_ENABLE_OPENCL)
        auto build_header_prefix80 = [](const BlockHeader& H, const std::vector<uint8_t>& merkle)->std::vector<uint8_t>{
            std::vector<uint8_t> p;
            p.reserve(76);
            put_u32_le(p, H.version);
            p.insert(p.end(), H.prev_hash.begin(), H.prev_hash.end());
            p.insert(p.end(), merkle.begin(), merkle.end());
            put_u32_le(p, (uint32_t)H.time);
            put_u32_le(p, H.bits);
            return p;
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
            return out;
        };
#endif

        // ===== mining loop with periodic refresh (prevents stale templates)
        std::fprintf(stderr, "[miner] starting mining loop (one job per tip; clean shutdown).\n");

        std::string last_job_prev_hex;
        while (ui.running.load()) {
            MinerTemplate tpl;
            if (!rpc_getminertemplate(rpc_host, rpc_port, token, tpl)) {
                std::ostringstream m; m << C("31;1") << "template error — check RPC token or node" << R();
                { std::lock_guard<std::mutex> lk(ui.mtx); ui.last_submit_msg = m.str(); ui.last_submit_when = std::chrono::steady_clock::now(); }
                log_line("template error (getminertemplate failed)");
                for(int i=0;i<20 && ui.running.load(); ++i) miq_sleep_ms(100);
                continue;
            }

            if (tpl.prev_hash.size() != 32) {
                log_line("template rejected: prev_hash size invalid");
                for(int i=0;i<10 && ui.running.load(); ++i) miq_sleep_ms(100);
                continue;
            }

            // Build coinbase & txs
            Transaction dummy_cb = make_coinbase(tpl.height, 0, pkh);
            size_t coinbase_sz = ser_tx(dummy_cb).size();

            std::vector<Transaction> txs;
            uint64_t fees = 0;
            size_t used_bytes = 0;
            pack_template(tpl, coinbase_sz, txs, fees, used_bytes);

            Transaction cb = make_coinbase(tpl.height, fees, pkh);
            std::vector<Transaction> txs_inc;
            txs_inc.reserve(1 + txs.size());
            txs_inc.push_back(cb);
            for (auto &t : txs) txs_inc.push_back(std::move(t));

            // Publish candidate to UI
            {
                const std::string cur_prev_hex = to_hex_s(tpl.prev_hash);
                std::lock_guard<std::mutex> lk(ui.mtx);
                ui.cand.height = tpl.height;
                ui.cand.prev_hex = cur_prev_hex;
                ui.cand.bits = tpl.bits;
                ui.cand.time = tpl.time;
                ui.cand.txs = txs_inc.size();
                ui.cand.size_bytes = used_bytes + ser_tx(cb).size();
                ui.cand.fees = fees;
                ui.cand.coinbase = GetBlockSubsidy((uint32_t)tpl.height) + fees;
                if (last_job_prev_hex != cur_prev_hex) {
                    std::ostringstream msg;
                    msg << C("36;1") << "job accepted: height=" << tpl.height
                        << " prev=" << ui.cand.prev_hex.substr(0,16) << "…"
                        << " diff=" << std::fixed << std::setprecision(2) << difficulty_from_bits(tpl.bits)
                        << " txs=" << ui.cand.txs << R();
                    ui.last_submit_msg = msg.str();
                    ui.last_submit_when = std::chrono::steady_clock::now();
                    last_job_prev_hex = cur_prev_hex;
                } else {
                    // Same prev_hash as previous job -> silently continue without re-announcing
                }
            }

            // Reset round stats/ETA
            ui.round_start_tries.store(ui.tries_total.load());
            ui.round_expected_hashes.store(difficulty_from_bits(tpl.bits) * 4294967296.0);

            // Header base
            BlockHeader hb;
            hb.version = 1;
            hb.prev_hash = tpl.prev_hash;

            int64_t now_ts = (int64_t)time(nullptr);
            hb.time = std::max<int64_t>(now_ts, std::max<int64_t>(tpl.time, tpl.mintime));
            hb.bits = tpl.bits;
            hb.nonce = 0;

            Block b;
            b.header = hb;
            b.txs = txs_inc;
            b.header.merkle_root = merkle_from(b.txs);

            // CPU mining threads
            std::atomic<bool> found{false};
            std::atomic<bool> abort_round{false};
            std::vector<std::thread> thv;
            Block found_block;

            for (unsigned tid = 0; tid < threads; ++tid) {
                thv.emplace_back(
                    mine_worker_optimized, hb, txs_inc, hb.bits,
                    &found, &abort_round, &thr_counts[tid], pin_affinity, tid, threads, &found_block
                );
            }

            // Prepare GPU job (optional)
            uint8_t target_be[32];
            bits_to_target_be(sanitize_bits(hb.bits), target_be);

            std::thread gpu_th;
#if defined(MIQ_ENABLE_OPENCL)
            if (gpu_enabled) {
                std::string gerr;
                std::vector<uint8_t> prefix76 = 
                    [&](){
                        std::vector<uint8_t> p; 
                        p.reserve(76);
                        put_u32_le(p, b.header.version);
                        p.insert(p.end(), b.header.prev_hash.begin(), b.header.prev_hash.end());
                        p.insert(p.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
                        put_u32_le(p, (uint32_t)b.header.time);
                        put_u32_le(p, b.header.bits);
                        return p;
                    }();
                std::vector<uint8_t> gpuprefix;
                if(salt_pos == SaltPos::PRE && !salt_bytes.empty()){
                    gpuprefix.reserve(salt_bytes.size()+prefix76.size());
                    gpuprefix.insert(gpuprefix.end(), salt_bytes.begin(), salt_bytes.end());
                    gpuprefix.insert(gpuprefix.end(), prefix76.begin(), prefix76.end());
                } else if(salt_pos == SaltPos::POST && !salt_bytes.empty()){
                    gpuprefix.reserve(prefix76.size()+salt_bytes.size());
                    gpuprefix.insert(gpuprefix.end(), prefix76.begin(), prefix76.end());
                    gpuprefix.insert(gpuprefix.end(), salt_bytes.begin(), salt_bytes.end());
                } else {
                    gpuprefix = prefix76;
                }

                if (!gpu.set_job(gpuprefix, target_be, &gerr)) {
                    std::fprintf(stderr, "[GPU] job set failed: %s\n", gerr.c_str());
                    log_line(std::string("[GPU] job set failed: ")+gerr);
                } else {
                    gpu_th = std::thread([&](){
                        uint64_t base_nonce =
                            (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull ^ 0xa5a5a5a5ULL;
                        while (!found.load(std::memory_order_relaxed) && !abort_round.load(std::memory_order_relaxed) && ui.running.load()) {
                            uint64_t n = 0; bool ok = false; double ghps = 0.0;
                            if (!gpu.run_round(base_nonce, gpu_npi, n, ok, ghps, 0.25, 2.0)) {
                                std::fprintf(stderr, "[GPU] run_round failed.\n");
                                log_line("[GPU] run_round failed (stopping GPU thread)");
                                break;
                            }
                            g_ui->gpu_hps_now.store(gpu.ema_now);
                            g_ui->gpu_hps_smooth.store(gpu.ema_smooth);

                            if (ok) {
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

            std::thread stale_mon([&](){
                while(!found.load(std::memory_order_relaxed) && ui.running.load()){
                    TipInfo tip_now{};
                    if(rpc_gettipinfo(rpc_host, rpc_port, token, tip_now)){
                        if(from_hex_s(tip_now.hash_hex) != tpl.prev_hash){
                            abort_round.store(true);
                            break;
                        }
                    }
                    for(int i=0;i<10 && !found.load(std::memory_order_relaxed) && !abort_round.load(std::memory_order_relaxed) && ui.running.load(); ++i){
                        miq_sleep_ms(50);
                    }
                }
            });
          
            // Wait for CPU workers
            for (auto &th : thv) th.join();

#if defined(MIQ_ENABLE_OPENCL)
            if (gpu_th.joinable()) {
                abort_round.store(true);
                gpu_th.join();
            }
#endif
            if(stale_mon.joinable()) stale_mon.join();

            if(!ui.running.load()) break;

            if(!found.load()) { continue; }

            // Check staleness vs tip
            TipInfo tip_now{};
            if (rpc_gettipinfo(rpc_host, rpc_port, token, tip_now)) {
                if (from_hex_s(tip_now.hash_hex) != tpl.prev_hash) {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    ui.last_submit_msg = std::string("submit skipped: template stale (chain advanced)");
                    ui.last_submit_when = std::chrono::steady_clock::now();
                    log_line("submit skipped: stale template");
                    continue;
                }
            }

            // Verify meets target
            auto hchk = found_block.block_hash();
            if (!meets_target_be_raw(hchk.data(), hb.bits)) {
                std::lock_guard<std::mutex> lk(ui.mtx);
                ui.last_submit_msg = "internal: solved header doesn't meet target (skipping)";
                ui.last_submit_when = std::chrono::steady_clock::now();
                log_line("internal mismatch: header doesn't meet target (skipped)");
                continue;
            }

            // Submit
            auto raw = miq::ser_block(found_block);
            std::string hexblk = miq::to_hex(raw);

            std::string ok_body, err_body;
            bool ok = rpc_submitblock_any(rpc_host, rpc_port, token, ok_body, err_body, hexblk);

            if (ok) {
                // Try confirm acceptance
                bool confirmed = false;
                for (int i = 0; i < 40 && ui.running.load(); ++i) {
                    TipInfo t2{};
                    if (rpc_gettipinfo(rpc_host, rpc_port, token, t2)) {
                        if (t2.height == tpl.height &&
                            t2.hash_hex == miq::to_hex(found_block.block_hash())) {
                            confirmed = true;
                            break;
                        }
                    }
                    miq_sleep_ms(100);
                }

                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                    if (confirmed) {
                        ui.mined_blocks.fetch_add(1);
                        std::ostringstream m; m << C("32;1") << "submit accepted @ height=" << tpl.height
                                                << " hash=" << ui.last_found_block_hash << R();
                        ui.last_submit_msg = m.str();
                        ui.last_tip_was_mine.store(true);
                        ui.last_winner_addr.clear();
                        rpc_minerlog_best_effort(
                            rpc_host, rpc_port, token,
                            std::string("miner: accepted block at height ")
                            + std::to_string(tpl.height) + " " + ui.last_found_block_hash
                        );
                        log_line("accepted block at height "+std::to_string(tpl.height)+" hash="+ui.last_found_block_hash);
                    } else {
                        std::ostringstream m; m << C("33;1")
                                                << "submit accepted (pending tip refresh) hash="
                                                << ui.last_found_block_hash << R();
                        ui.last_submit_msg = m.str();
                        log_line("submit accepted (awaiting tip confirm), hash="+ui.last_found_block_hash);
                    }
                    ui.last_submit_when = std::chrono::steady_clock::now();
                }
            } else {
                std::lock_guard<std::mutex> lk(ui.mtx);
                std::ostringstream m; m << C("31;1") << "submit REJECTED / RPC failed" << R();
                if (!err_body.empty()) {
                    std::string msg;
                    if (json_find_string(err_body, "error", msg)) m << ": " << msg;
                }
                ui.last_submit_msg = m.str();
                ui.last_submit_when = std::chrono::steady_clock::now();
                log_line("submit rejected / rpc failed");
            }
        }

        // Final clear/exit
        std::cout << "\n" << C("33;1") << "Exiting…" << R() << std::endl;
        log_line("miner exited cleanly");
        return 0;

    } catch(const std::exception& ex){
        std::fprintf(stderr,"[FATAL] %s\n", ex.what());
        log_line(std::string("[FATAL] ")+ex.what());
        return 1;
    } catch(...){
        std::fprintf(stderr,"[FATAL] unknown\n");
        log_line("[FATAL] unknown");
        return 1;
    }
}
