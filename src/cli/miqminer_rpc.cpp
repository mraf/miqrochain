// src/cli/miqminer_rpc.cpp
// Chronen Miner v1.0 Stable - Professional Cryptocurrency Mining Software
// Copyright (c) 2024 Miqrochain Developers

#define MIQMINER_VERSION "1.0.0"
#define MIQMINER_VERSION_STRING "Chronen Miner v1.0 Stable"

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
#include <condition_variable>

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
    // Enable TCP keepalive to prevent idle connection drops
    DWORD keepalive = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (const char*)&keepalive, sizeof(keepalive));
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
  #include <netinet/tcp.h>  // For TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
  #include <poll.h>         // For poll() in stratum recv_line
  using socket_t = int;
  #define miq_closesocket ::close
  static void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
  static void set_socket_timeouts(socket_t s, int ms_send, int ms_recv){
    struct timeval tvs{ ms_send/1000, (int)((ms_send%1000)*1000) };
    struct timeval tvr{ ms_recv/1000, (int)((ms_recv%1000)*1000) };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tvs, sizeof(tvs));
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tvr, sizeof(tvr));
    // Enable TCP keepalive to prevent idle connection drops
    int keepalive = 1;
    setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &keepalive, sizeof(keepalive));
    // Set aggressive keepalive parameters for mining stability
    #ifdef TCP_KEEPIDLE
    int keepidle = 10;  // Start sending keepalives after 10 seconds of idle
    setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &keepidle, sizeof(keepidle));
    #endif
    #ifdef TCP_KEEPINTVL
    int keepintvl = 5;  // Send keepalive every 5 seconds
    setsockopt(s, IPPROTO_TCP, TCP_KEEPINTVL, &keepintvl, sizeof(keepintvl));
    #endif
    #ifdef TCP_KEEPCNT
    int keepcnt = 3;  // Drop connection after 3 failed keepalives
    setsockopt(s, IPPROTO_TCP, TCP_KEEPCNT, &keepcnt, sizeof(keepcnt));
    #endif
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

// Detect if terminal supports ANSI escape codes
static bool detect_ansi_support() {
#if defined(_WIN32)
    // On Windows, check for ConEmu, Windows Terminal, or enable VT processing
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return false;

    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) return false;

    // Try to enable VT processing
    if (SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
        return true;
    }

    // Check for known terminals
    const char* term = std::getenv("TERM");
    const char* wt = std::getenv("WT_SESSION");
    const char* conemu = std::getenv("ConEmuANSI");
    if (wt || (conemu && std::strcmp(conemu, "ON") == 0)) return true;
    if (term && (std::strstr(term, "xterm") || std::strstr(term, "color"))) return true;

    return false;
#else
    // On Unix/Linux, check if stdout is a TTY and TERM is set
    if (!isatty(STDOUT_FILENO)) return false;

    const char* term = std::getenv("TERM");
    if (!term || !*term) return false;

    // Check for dumb terminal
    if (std::strcmp(term, "dumb") == 0) return false;

    // Most modern terminals support ANSI
    return true;
#endif
}

static inline std::string C(const char* code){ return g_use_ansi ? std::string("\x1b[")+code+"m" : std::string(); }
static inline std::string R(){ return g_use_ansi ? std::string("\x1b[0m") : std::string(); }
static inline const char* CLS(){ return g_use_ansi ? "\x1b[2J\x1b[H" : ""; }
static inline void set_title(const std::string& t){
    if(!g_use_ansi) return;
    std::cout << "\x1b]0;" << t << "\x07";
}

// Professional ASCII banner for Chronen Miner (ASCII-safe for PowerShell v5)
static const char* kChronenMinerBanner[] = {
"    _____ _    _ _____   ____  _   _ ______ _   _",
"   / ____| |  | |  __ \\ / __ \\| \\ | |  ____| \\ | |",
"  | |    | |__| | |__) | |  | |  \\| | |__  |  \\| |",
"  | |    |  __  |  _  /| |  | | . ` |  __| | . ` |",
"  | |____| |  | | | \\ \\| |__| | |\\  | |____| |\\  |",
"   \\_____|_|  |_|_|  \\_\\\\____/|_| \\_|______|_| \\_|",
"                  __  __ _____ _   _ ______ _____",
"                 |  \\/  |_   _| \\ | |  ____|  __ \\",
"                 | \\  / | | | |  \\| | |__  | |__) |",
"                 | |\\/| | | | | . ` |  __| |  _  /",
"                 | |  | |_| |_| |\\  | |____| | \\ \\",
"                 |_|  |_|_____|_| \\_|______|_|  \\_\\",
};

// UI Helper: Draw a horizontal line
[[maybe_unused]] static std::string ui_hline(int width, char c = '-') {
    return std::string(width, c);
}

// UI Helper: Draw a box top
[[maybe_unused]] static std::string ui_box_top(int width, const std::string& title = "") {
    std::string hline;
    for (int i = 0; i < width - 2; i++) hline += "-";
    if (title.empty()) {
        return "+" + hline + "+";
    }
    int padding = width - 4 - (int)title.size();
    int left = padding / 2;
    int right = padding - left;
    std::string lpad, rpad;
    for (int i = 0; i < left; i++) lpad += "-";
    for (int i = 0; i < right; i++) rpad += "-";
    return "+" + lpad + " " + title + " " + rpad + "+";
}

// UI Helper: Draw a box bottom
[[maybe_unused]] static std::string ui_box_bottom(int width) {
    std::string hline;
    for (int i = 0; i < width - 2; i++) hline += "-";
    return "+" + hline + "+";
}

// UI Helper: Draw a box row with content
[[maybe_unused]] static std::string ui_box_row(int width, const std::string& content) {
    int content_width = width - 4;
    std::string text = content;
    // Truncate if too long (accounting for ANSI codes which don't take visual space)
    // Simple approach: just pad/truncate
    if ((int)text.size() > content_width) {
        text = text.substr(0, content_width);
    }
    int padding = content_width - (int)text.size();
    return "| " + text + std::string(padding, ' ') + " |";
}

// Forward declaration for fmt_hs (defined later in file)
static std::string fmt_hs(double v);

// UI Helper: Format hash rate with visual bar
static std::string fmt_hs_bar(double v, double max_v, int bar_width = 20) {
    std::string hs_str = fmt_hs(v);
    if (max_v <= 0) max_v = v > 0 ? v : 1.0;
    double ratio = std::min(1.0, v / max_v);
    int filled = (int)(ratio * bar_width);
    std::string bar = "[";
    for (int i = 0; i < bar_width; i++) {
        bar += (i < filled) ? '#' : '.';
    }
    bar += "]";
    return bar + " " + hs_str;
}

// UI Helper: Status indicator with color
static std::string ui_status(bool ok, const std::string& ok_text, const std::string& fail_text) {
    if (ok) {
        return C("32;1") + "* " + ok_text + R();
    } else {
        return C("31;1") + "x " + fail_text + R();
    }
}

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
    // Linux: use lowercase .miqrochain to match node's data directory
    const char* xdg = std::getenv("XDG_DATA_HOME");
    if (xdg && *xdg) return std::string(xdg) + "/miqrochain/.cookie";
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
[[maybe_unused]] static bool json_find_bool(const std::string& json, const std::string& key, bool& out){
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
[[maybe_unused]] static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x){
    v.push_back(uint8_t((x>>0 )&0xff)); v.push_back(uint8_t((x>>8 )&0xff));
    v.push_back(uint8_t((x>>16)&0xff)); v.push_back(uint8_t((x>>24)&0xff));
    v.push_back(uint8_t((x>>32)&0xff)); v.push_back(uint8_t((x>>40)&0xff));
    v.push_back(uint8_t((x>>48)&0xff)); v.push_back(uint8_t((x>>56)&0xff));
}
[[maybe_unused]] static inline void store_u64_le(uint8_t* p, uint64_t x){
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

// HTTP POST with automatic retry and exponential backoff
static bool http_post_with_retry(const std::string& host, uint16_t port, const std::string& path,
                                  const std::string& auth_token, const std::string& json, HttpResp& out,
                                  int max_retries = 3);

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

// CRITICAL FIX: Initialize Winsock once at startup, not per-request
#if defined(_WIN32)
static void winsock_ensure() {
    static bool inited = false;
    if (!inited) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2), &wsa) == 0) inited = true;
    }
}
#else
static void winsock_ensure() {}
#endif

static bool http_post(const std::string& host, uint16_t port, const std::string& path,
                      const std::string& auth_token, const std::string& json, HttpResp& out)
{
    winsock_ensure();
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    addrinfo* res=nullptr; char ps[16]; std::snprintf(ps,sizeof(ps), "%u", (unsigned)port);
    int gai_err = getaddrinfo(host.c_str(), ps, &hints, &res);
    if(gai_err != 0) {
        if(res) freeaddrinfo(res);  // CRITICAL FIX: Free res even on error
        out.code = 0;
        out.body = "DNS resolution failed";
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
        set_socket_timeouts(s, 60000, 60000);  // CRITICAL FIX: Increased to 60s for mining stability
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = INVALID_SOCKET;
#else
        if(s<0) continue;
        set_socket_timeouts(s, 60000, 60000);  // CRITICAL FIX: Increased to 60s for mining stability
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = -1;
#endif
    }
    freeaddrinfo(res);
#if defined(_WIN32)
    if(s==INVALID_SOCKET) {
        out.code = 0;
        out.body = "Connection failed - node not reachable";
        return false;
    }
#else
    if(s<0) {
        out.code = 0;
        out.body = "Connection failed - node not reachable";
        return false;
    }
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
        if(n<=0){
            // CRITICAL FIX: Set error code before returning to enable proper retry logic
            out.code = 0;
            out.body = "Send failed - connection reset";
            miq_closesocket(s);
            return false;
        }
#else
        int n = ::send(s, data.data()+off, (int)(data.size()-off), 0);
        if(n<=0){
            // CRITICAL FIX: Set error code before returning to enable proper retry logic
            out.code = 0;
            out.body = "Send failed - connection reset";
            miq_closesocket(s);
            return false;
        }
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

    // CRITICAL FIX: Handle empty response (server closed connection without sending anything)
    if(resp.empty()){
        out.code = 0;
        out.body = "Empty response - server closed connection";
        return false;
    }

    // Handle chunked transfer (harden)
    std::string resp2 = dechunk_if_needed(resp);

    size_t sp = resp2.find(' ');
    if(sp == std::string::npos){
        // CRITICAL FIX: Set error code for malformed response
        out.code = 0;
        out.body = "Malformed HTTP response - no status line";
        return false;
    }
    int code = std::atoi(resp2.c_str()+sp+1);
    // CRITICAL FIX: Validate HTTP status code is reasonable (100-599)
    if(code < 100 || code >= 600){
        out.code = 0;
        out.body = "Invalid HTTP status code: " + std::to_string(code);
        return false;
    }
    size_t hdr_end = resp2.find("\r\n\r\n");
    std::string body = (hdr_end==std::string::npos)? std::string() : resp2.substr(hdr_end+4);
    out.code = code; out.body = std::move(body);
    return true;
}

// CRITICAL FIX: Fast HTTP POST with short timeout for lightweight polling operations
// This prevents connection buildup when the server is slow to respond.
// Uses 5-second timeout instead of 60 seconds - if a simple tip check takes longer,
// something is wrong and we should abort rather than pile up connections.
static bool http_post_fast(const std::string& host, uint16_t port, const std::string& path,
                           const std::string& auth_token, const std::string& json, HttpResp& out,
                           int timeout_ms = 5000)
{
    winsock_ensure();
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    addrinfo* res=nullptr; char ps[16]; std::snprintf(ps,sizeof(ps), "%u", (unsigned)port);
    int gai_err = getaddrinfo(host.c_str(), ps, &hints, &res);
    if(gai_err != 0) {
        if(res) freeaddrinfo(res);
        out.code = 0;
        out.body = "DNS resolution failed";
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
        // Use short timeout for fast polling operations
        set_socket_timeouts(s, timeout_ms, timeout_ms);
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = INVALID_SOCKET;
#else
        if(s<0) continue;
        // Use short timeout for fast polling operations
        set_socket_timeouts(s, timeout_ms, timeout_ms);
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) break;
        miq_closesocket(s); s = -1;
#endif
    }
    freeaddrinfo(res);
#if defined(_WIN32)
    if(s==INVALID_SOCKET) {
        out.code = 0;
        out.body = "Connection failed - node not reachable";
        return false;
    }
#else
    if(s<0) {
        out.code = 0;
        out.body = "Connection failed - node not reachable";
        return false;
    }
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
        if(n<=0){
            out.code = 0;
            out.body = "Send failed - connection reset";
            miq_closesocket(s);
            return false;
        }
#else
        int n = ::send(s, data.data()+off, (int)(data.size()-off), 0);
        if(n<=0){
            out.code = 0;
            out.body = "Send failed - connection reset";
            miq_closesocket(s);
            return false;
        }
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

    if(resp.empty()){
        out.code = 0;
        out.body = "Empty response - server closed connection";
        return false;
    }

    std::string resp2 = dechunk_if_needed(resp);

    size_t sp = resp2.find(' ');
    if(sp == std::string::npos){
        out.code = 0;
        out.body = "Malformed HTTP response - no status line";
        return false;
    }
    int code = std::atoi(resp2.c_str()+sp+1);
    if(code < 100 || code >= 600){
        out.code = 0;
        out.body = "Invalid HTTP status code: " + std::to_string(code);
        return false;
    }
    size_t hdr_end = resp2.find("\r\n\r\n");
    std::string body = (hdr_end==std::string::npos)? std::string() : resp2.substr(hdr_end+4);
    out.code = code; out.body = std::move(body);
    return true;
}

// HTTP POST with automatic retry and exponential backoff for network errors and server errors
// CRITICAL FIX: Improved retry logic with smarter backoff for different error types
static bool http_post_with_retry(const std::string& host, uint16_t port, const std::string& path,
                                  const std::string& auth_token, const std::string& json, HttpResp& out,
                                  int max_retries, bool retry_on_server_errors = false)
{
    int delay_ms = 500;  // Start with 500ms for quick recovery from transient issues
    int consecutive_503s = 0;

    for (int attempt = 0; attempt <= max_retries; ++attempt) {
        if (http_post(host, port, path, auth_token, json, out)) {
            // Success! Reset state for next call
            return true;
        }

        // Determine if we should retry based on error type
        bool should_retry = false;

        if(out.code == 0){
            // Network/connection error - always retry with normal backoff
            should_retry = true;
            consecutive_503s = 0;
        } else if(retry_on_server_errors && out.code == 503){
            // HTTP 503 Service Unavailable - server is overloaded
            // Use aggressive initial backoff to let the server recover
            should_retry = true;
            consecutive_503s++;
            // If we see multiple 503s in a row, the server is really struggling
            // Back off more aggressively: 2s, 4s, 6s, 8s for each consecutive 503
            if(consecutive_503s > 1){
                delay_ms = std::max(delay_ms, consecutive_503s * 2000);
            }
        } else if(retry_on_server_errors && out.code >= 500){
            // Other 5xx errors - retry with normal backoff
            should_retry = true;
            consecutive_503s = 0;
        }

        if (!should_retry || attempt == max_retries) {
            return false;
        }

        // Exponential backoff with longer delays for mining stability
        // Cap at 10 seconds (was 30s, but too long hurts mining responsiveness)
        miq_sleep_ms(delay_ms);
        delay_ms = std::min(delay_ms * 2, 10000);
    }
    return false;
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

// Diagnostic helper to identify RPC connection issues
// CRITICAL FIX: More specific error messages to help diagnose issues
static std::string diagnose_rpc_failure(const std::string& host, uint16_t port, const std::string& auth, const HttpResp& r){
    (void)host; (void)port;  // Reserved for future diagnostic enhancements
    if(r.code == 0){
        // Network-level failure - include body for more details
        if(!r.body.empty() && r.body.size() < 100){
            return "Connection failed: " + r.body;
        }
        return "Connection failed - node not running or wrong port";
    }
    if(r.code == 401 || r.code == 403) {
        if(auth.empty()) return "Auth required but no token provided - check cookie file or --token";
        return "Auth failed (401/403) - token may be incorrect or expired";
    }
    if(r.code == 404) return "RPC method not found - node may be outdated";
    if(r.code == 429) return "Rate limited (429) - too many requests, backing off";
    if(r.code == 503){
        // HTTP 503 is returned when server is at max connections
        return "Server overloaded (503) - node has too many connections, will retry";
    }
    if(r.code >= 500) return "Server error (" + std::to_string(r.code) + ") - node may have crashed";
    if(json_has_error(r.body)) {
        std::string errMsg;
        if(json_find_string(r.body, "error", errMsg)) return "RPC error: " + errMsg;
        return "RPC returned error in body";
    }
    return "Unexpected HTTP " + std::to_string(r.code);
}

static bool rpc_gettipinfo(const std::string& host, uint16_t port, const std::string& auth, TipInfo& out){
    // Fast path: dedicated RPC (if present) with retry for network and server errors
    // CRITICAL FIX: Reduced retries from 30 to 10 to prevent connection floods
    {
        HttpResp r;
        if (http_post_with_retry(host, port, "/", auth, rpc_build("gettipinfo","[]"), r, 10, true)
            && r.code==200 && !json_has_error(r.body)) {
            long long h=0,t=0; uint32_t b=0; std::string hh;
            // Use json_find_hex_or_number_u32 for bits since server returns it as hex string
            if (json_find_number(r.body,"height",h) &&
                json_find_string(r.body,"hash",hh) &&
                json_find_hex_or_number_u32(r.body,"bits",b) &&
                json_find_number(r.body,"time",t)) {
                out.height = (uint64_t)h;
                out.hash_hex = hh;
                out.bits = sanitize_bits(b);
                out.time = (int64_t)t;
                return true;
            }
        }
        // Log diagnostic info on failure (only log first failure to avoid spam)
        if(r.code != 200){
            static int diag_count = 0;
            static auto last_diag_time = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_diag_time).count();
            // Only log first 3 failures OR once every 60 seconds to avoid log spam
            if(diag_count < 3 || elapsed >= 60){
                log_line("RPC gettipinfo failed: " + diagnose_rpc_failure(host, port, auth, r));
                ++diag_count;
                last_diag_time = now;
            }
        }
    }
    // Fallback (portable): getblockchaininfo → bestblockhash/blocks → getblock
    {
        HttpResp r;
        if (!http_post_with_retry(host, port, "/", auth, rpc_build("getblockchaininfo","[]"), r, 15, true)
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

// CRITICAL FIX: Fast variant of rpc_gettipinfo with short timeout and NO retries
// Used for quick checks like block confirmation where we don't want to pile up connections.
// If the server can't respond in 5 seconds, we skip and try again rather than waiting 60s with retries.
static bool rpc_gettipinfo_fast(const std::string& host, uint16_t port, const std::string& auth, TipInfo& out){
    HttpResp r;
    // Single attempt with 5-second timeout - no retries, fail fast
    if (http_post_fast(host, port, "/", auth, rpc_build("gettipinfo","[]"), r, 5000)
        && r.code==200 && !json_has_error(r.body)) {
        long long h=0,t=0; uint32_t b=0; std::string hh;
        if (json_find_number(r.body,"height",h) &&
            json_find_string(r.body,"hash",hh) &&
            json_find_hex_or_number_u32(r.body,"bits",b) &&
            json_find_number(r.body,"time",t)) {
            out.height = (uint64_t)h;
            out.hash_hex = hh;
            out.bits = sanitize_bits(b);
            out.time = (int64_t)t;
            return true;
        }
    }
    return false;
}

static bool rpc_getminerstats(const std::string& host, uint16_t port, const std::string& auth, double& out_net_hs){
    HttpResp r;
    // Use retry for reliability during network monitoring
    if(!http_post_with_retry(host, port, "/", auth, rpc_build("getminerstats","[]"), r, 15, true) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    if(json_find_double(r.body, "hps", out_net_hs)) return true;
    if(json_find_double(r.body, "network_hash_ps", out_net_hs)) return true;
    return false;
}
static bool rpc_getblockhash(const std::string& host, uint16_t port, const std::string& auth, uint64_t height, std::string& out){
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    // Use retry for reliability - called frequently by stale monitoring
    if(!http_post_with_retry(host, port, "/", auth, rpc_build("getblockhash", ps.str()), r, 15, true) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    if(json_find_string(r.body, "result", out)) return true;
    if(json_extract_top_string(r.body, out)) return true;
    return false;
}

static bool rpc_getblock_header_time(const std::string& host, uint16_t port, const std::string& auth, const std::string& hh, long long& out_time){
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    // Use retry for reliability
    if(!http_post_with_retry(host, port, "/", auth, rpc_build("getblock", ps.str()), r, 15, true) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    long long t=0;
    if(json_find_number(r.body, "time", t)) { out_time=t; return true; }
    return false;
}

static bool rpc_getblock_time_bits(const std::string& host, uint16_t port, const std::string& auth,
                                   const std::string& hh, long long& out_time, uint32_t& out_bits){
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    // Use retry for reliability - called frequently by stale monitoring via gettipinfo fallback
    if(!http_post_with_retry(host, port, "/", auth, rpc_build("getblock", ps.str()), r, 15, true) || r.code != 200) return false;
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
    // Use retry for reliability during block scanning
    if(!http_post_with_retry(host, port, "/", auth, rpc_build("getblock", ps.str()), r, 15, true) || r.code!=200) return false;
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
    // Use retry for reliability during block scanning
    if(!http_post_with_retry(host, port, "/", auth, rpc_build("getcoinbaserecipient", ps.str()), r, 15, true) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    std::string pkh_hex, txid_hex;
    double val_dbl = 0.0;
    if(!json_find_string(r.body, "pkh", pkh_hex)) return false;
    (void)json_find_double(r.body, "value", val_dbl);
    if(json_find_string(r.body, "txid", txid_hex)) io.coinbase_txid_hex = txid_hex;
    io.coinbase_pkh = from_hex_s(pkh_hex);
    io.reward_value = (uint64_t)((val_dbl < 0.0) ? 0 : val_dbl);
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
    // CRITICAL FIX: Use retry for block submission to ensure blocks aren't lost due to transient network issues
    if(!http_post_with_retry(host, port, "/", auth, rpc_build(method, ps.str()), r, 15, true)) return false;
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

[[maybe_unused]] static std::string fmt_miq_whole_dot(uint64_t base_units){
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
        // CRITICAL FIX: Use retry mechanism to maintain stable RPC connection
        // Reduced retries from 30 to 10 to prevent connection floods during server load
        // Debug: Track template request attempts for troubleshooting
        static std::atomic<uint64_t> template_requests{0};
        static std::atomic<uint64_t> template_successes{0};
        uint64_t req_num = template_requests.fetch_add(1);
        (void)req_num;  // Reserved for future logging/debugging
        if(http_post_with_retry(host, port, "/", auth, rpc_build("getminertemplate","[]"), r, 10, true) && r.code==200 && !json_has_error(r.body)){
            template_successes.fetch_add(1);
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
        // CRITICAL FIX: Use retry mechanism for getblocktemplate fallback
        if(http_post_with_retry(host, port, "/", auth, rpc_build("getblocktemplate","[{}]"), r, 15, true) && r.code==200 && !json_has_error(r.body)){
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
    // MIQ coinbase convention: prev.vout = 0 (differs from Bitcoin's 0xffffffff)
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

    // Pool mining statistics
    std::atomic<bool>     pool_mode{false};
    std::atomic<uint64_t> shares_submitted{0};
    std::atomic<uint64_t> shares_accepted{0};
    std::atomic<uint64_t> shares_rejected{0};
    std::atomic<double>   pool_difficulty{1.0};
    std::string           pool_host;
    uint16_t              pool_port{0};
    std::string           pool_worker;
    std::atomic<uint64_t> pool_jobs_received{0};
    std::string           current_job_id;
    std::mutex            pool_mtx;

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
[[maybe_unused]] static inline std::string pad_fit(const std::string& s, size_t width){
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
[[maybe_unused]] static std::string progress_bar(double p, size_t width){
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
    // Set console output to UTF-8 for proper character display
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) { DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004); }
#endif
    // Detect terminal ANSI support and set global flag
    g_use_ansi = detect_ansi_support();

    // Also check for --no-color flag (will be processed later, but env check here)
    const char* no_color = std::getenv("NO_COLOR");
    if (no_color && *no_color) g_use_ansi = false;
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

// ===== Mining Mode Selection =================================================
enum class MiningMode { SOLO = 1, POOL = 2 };

// Professional mining mode selection menu
static MiningMode show_mining_mode_menu() {
    using clock = std::chrono::steady_clock;

    while (true) {
        std::ostringstream s;
        s << CLS();

        // Banner
        s << C("36;1");
        const size_t N = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
        for(size_t i=0;i<N;i++) s << kChronenMinerBanner[i] << "\n";
        s << R() << "\n";

        // Version info
        s << "  " << C("2") << MIQMINER_VERSION_STRING << " - Professional Mining Software" << R() << "\n\n";

        // Menu header
        s << C("36;1") << "  ======================================================================" << R() << "\n";
        s << C("1;4") << "   SELECT MINING MODE" << R() << "\n";
        s << C("36") << "  ----------------------------------------------------------------------" << R() << "\n\n";

        // Option 1: Solo Mining
        s << "  " << C("33;1") << "[1]" << R() << " " << C("1") << "SOLO MINING" << R() << "\n";
        s << "      " << C("2") << "Mine directly to your own node and receive full block rewards." << R() << "\n";
        s << "      " << C("31;1") << "!" << R() << " " << C("31") << "Running a full node is REQUIRED" << R() << "\n";
        s << "      " << C("2") << "- Direct RPC connection to local/remote node" << R() << "\n";
        s << "      " << C("2") << "- Full block reward (no pool fees)" << R() << "\n";
        s << "      " << C("2") << "- Requires synced blockchain" << R() << "\n\n";

        // Option 2: Pool Mining
        s << "  " << C("36;1") << "[2]" << R() << " " << C("1") << "POOL MINING" << R() << "\n";
        s << "      " << C("2") << "Connect to a mining pool for consistent payouts." << R() << "\n";
        s << "      " << C("32;1") << "*" << R() << " " << C("32") << "Running a full node is NOT required" << R() << "\n";
        s << "      " << C("2") << "- Stratum protocol (stratum+tcp://)" << R() << "\n";
        s << "      " << C("2") << "- Shared rewards with pool miners" << R() << "\n";
        s << "      " << C("2") << "- More consistent payouts" << R() << "\n\n";

        s << C("36") << "  ----------------------------------------------------------------------" << R() << "\n";
        s << "  " << C("1") << "Enter your choice [1/2]: " << R() << std::flush;

        std::cout << s.str();

        std::string input;
        if (!std::getline(std::cin, input)) {
            return MiningMode::SOLO; // Default to solo on EOF
        }

        trim(input);

        if (input == "1" || input == "solo" || input == "SOLO") {
            // Show confirmation animation
            std::cout << "\n  " << C("33;1") << ">>> SOLO MINING SELECTED <<<" << R() << "\n";
            miq_sleep_ms(500);
            return MiningMode::SOLO;
        } else if (input == "2" || input == "pool" || input == "POOL") {
            // Show confirmation animation
            std::cout << "\n  " << C("36;1") << ">>> POOL MINING SELECTED <<<" << R() << "\n";
            miq_sleep_ms(500);
            return MiningMode::POOL;
        } else {
            std::cout << "\n  " << C("31;1") << "Invalid choice. Please enter 1 or 2." << R() << "\n";
            miq_sleep_ms(1000);
        }
    }
}

// Pool configuration menu
struct PoolConfig {
    std::string host;
    uint16_t port{3333};
    std::string worker;
    std::string password{"x"};
};

static bool show_pool_config_menu(PoolConfig& cfg, const std::string& default_addr) {
    std::cout << CLS();

    // Banner (smaller)
    std::cout << C("36;1");
    const size_t N = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
    for(size_t i=0;i<N;i++) std::cout << kChronenMinerBanner[i] << "\n";
    std::cout << R() << "\n";

    std::cout << C("36;1") << "  ======================================================================" << R() << "\n";
    std::cout << C("1;4") << "   POOL CONFIGURATION" << R() << "\n";
    std::cout << C("36") << "  ----------------------------------------------------------------------" << R() << "\n\n";

    // Pool URL
    std::cout << "  " << C("1") << "Pool Address" << R() << " (e.g., pool.example.com:3333)\n";
    std::cout << "  " << C("2") << "Format: hostname:port" << R() << "\n";
    std::cout << "  > " << std::flush;

    std::string pool_url;
    if (!std::getline(std::cin, pool_url)) return false;
    trim(pool_url);

    if (pool_url.empty()) {
        std::cout << "\n  " << C("31;1") << "Error: Pool address is required." << R() << "\n";
        miq_sleep_ms(1500);
        return false;
    }

    // Parse host:port
    size_t colon = pool_url.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon == pool_url.size() - 1) {
        std::cout << "\n  " << C("31;1") << "Error: Invalid format. Use hostname:port" << R() << "\n";
        miq_sleep_ms(1500);
        return false;
    }

    cfg.host = pool_url.substr(0, colon);
    try {
        cfg.port = (uint16_t)std::stoi(pool_url.substr(colon + 1));
    } catch (...) {
        std::cout << "\n  " << C("31;1") << "Error: Invalid port number." << R() << "\n";
        miq_sleep_ms(1500);
        return false;
    }

    std::cout << "\n";

    // Worker name
    std::cout << "  " << C("1") << "Worker Name" << R() << "\n";
    std::cout << "  " << C("2") << "Usually: your_address.worker_name (default: " << default_addr.substr(0,8) << "..." << ".miner1)" << R() << "\n";
    std::cout << "  > " << std::flush;

    std::string worker;
    if (!std::getline(std::cin, worker)) return false;
    trim(worker);

    if (worker.empty()) {
        cfg.worker = default_addr + ".miner1";
    } else {
        cfg.worker = worker;
    }

    std::cout << "\n";

    // Password (optional)
    std::cout << "  " << C("1") << "Pool Password" << R() << " " << C("2") << "(press Enter for default 'x')" << R() << "\n";
    std::cout << "  > " << std::flush;

    std::string pass;
    if (!std::getline(std::cin, pass)) return false;
    trim(pass);

    if (!pass.empty()) {
        cfg.password = pass;
    }

    // Confirmation
    std::cout << "\n" << C("36") << "  ----------------------------------------------------------------------" << R() << "\n";
    std::cout << "  " << C("1") << "Configuration Summary:" << R() << "\n";
    std::cout << "    Pool   : " << C("36") << cfg.host << ":" << cfg.port << R() << "\n";
    std::cout << "    Worker : " << C("33") << cfg.worker << R() << "\n";
    std::cout << "    Pass   : " << C("2") << cfg.password << R() << "\n";
    std::cout << C("36") << "  ----------------------------------------------------------------------" << R() << "\n\n";

    std::cout << "  " << C("32;1") << "* Configuration complete! Starting pool mining..." << R() << "\n";
    miq_sleep_ms(1000);

    return true;
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
  u64 L = (u64)prefix_len + 8u;  // CRITICAL FIX: 8-byte nonce
  u64 Lbits = L * 8u;

  for(int i=0;i<64;i++){
    u64 off = (u64)blk_idx*64u + (u64)i;
    u8 v = 0;
    if(off < (u64)prefix_len){
      v = prefix[off];
    } else if(off < (u64)prefix_len + 8u){  // CRITICAL FIX: 8-byte nonce
      uint j = (uint)(off - (u64)prefix_len);
      v = (u8)((nonce_le >> (8u*j)) & 0xffu);
    } else if(off == (u64)prefix_len + 8u){  // CRITICAL FIX: padding after 8-byte nonce
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
  u64 L = (u64)prefix_len + 8u;  // CRITICAL FIX: 8-byte nonce
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
    header_prefix.reserve(4+32+32+8+4);  // FIXED: 8 bytes for time
    put_u32_le(header_prefix, b.header.version);
    header_prefix.insert(header_prefix.end(), b.header.prev_hash.begin(),   b.header.prev_hash.end());
    header_prefix.insert(header_prefix.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
    put_u64_le(header_prefix, (uint64_t)b.header.time);  // FIXED: use 8-byte time
    put_u32_le(header_prefix, b.header.bits);
    const size_t nonce_off = header_prefix.size();

    bits = sanitize_bits(bits);

#if !defined(MIQ_POW_SALT)
    FastSha256Ctx base1;
    fastsha_init(base1);
    fastsha_update(base1, header_prefix.data(), header_prefix.size());
#endif

    std::vector<uint8_t> hdr = header_prefix;
    hdr.resize(header_prefix.size() + 8);  // FIXED: 8 bytes for nonce
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
            // FIXED: Use 8-byte nonces to match main miner format
            uint8_t le8[8][8];
            store_u64_le(le8[0], n0); dsha256_from_base(base1, le8[0], 8, h[0]);
            store_u64_le(le8[1], n1); dsha256_from_base(base1, le8[1], 8, h[1]);
            store_u64_le(le8[2], n2); dsha256_from_base(base1, le8[2], 8, h[2]);
            store_u64_le(le8[3], n3); dsha256_from_base(base1, le8[3], 8, h[3]);
            store_u64_le(le8[4], n4); dsha256_from_base(base1, le8[4], 8, h[4]);
            store_u64_le(le8[5], n5); dsha256_from_base(base1, le8[5], 8, h[5]);
            store_u64_le(le8[6], n6); dsha256_from_base(base1, le8[6], 8, h[6]);
            store_u64_le(le8[7], n7); dsha256_from_base(base1, le8[7], 8, h[7]);
        #else
            // FIXED: Use 8-byte nonces for salted hash path
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

// ===== Stratum client for pool mining ========================================
struct StratumJob {
    std::string job_id;
    std::vector<uint8_t> prev_hash;
    std::string coinbase1;
    std::string coinbase2;
    std::vector<std::string> merkle_branch;
    uint32_t version;
    uint32_t bits;
    uint32_t time;
    bool clean;
};

class StratumClient {
public:
    std::string host;
    uint16_t port;
    std::string worker;
    std::string password;
#if defined(_WIN32)
    socket_t sock = INVALID_SOCKET;
#else
    socket_t sock = -1;
#endif
    std::atomic<bool> connected{false};
    std::mutex mtx;
    std::string extranonce1;
    uint32_t extranonce2_size = 4;
    StratumJob current_job;
    std::atomic<uint64_t> job_id_counter{0};
    uint64_t last_submit_id = 0;
    std::atomic<bool> has_job{false};
    std::atomic<double> difficulty{1.0};
    std::mutex job_mtx;

    // CRITICAL FIX: Read buffer for handling partial/multiple messages
    std::string read_buffer;

    bool connect_to_pool() {
        winsock_ensure();
        addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        char ps[16]; std::snprintf(ps, sizeof(ps), "%u", (unsigned)port);
        if (getaddrinfo(host.c_str(), ps, &hints, &res) != 0) {
            std::fprintf(stderr, "[stratum] DNS resolution failed for %s\n", host.c_str());
            return false;
        }

        for (addrinfo* ai = res; ai; ai = ai->ai_next) {
            sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#if defined(_WIN32)
            if (sock == INVALID_SOCKET) continue;
#else
            if (sock < 0) continue;
#endif
            set_socket_timeouts(sock, 15000, 30000);  // 15s send, 30s recv
            if (::connect(sock, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0) {
                freeaddrinfo(res);
                connected.store(true);
                return true;
            }
            miq_closesocket(sock);
#if defined(_WIN32)
            sock = INVALID_SOCKET;
#else
            sock = -1;
#endif
        }
        freeaddrinfo(res);
        std::fprintf(stderr, "[stratum] Connection refused by %s:%u\n", host.c_str(), port);
        return false;
    }

    bool send_json(const std::string& json) {
        std::string msg = json + "\n";
        return ::send(sock, msg.c_str(), static_cast<int>(msg.size()), 0) > 0;
    }

    // CRITICAL FIX: Improved recv_line with proper buffering
    std::string recv_line(int timeout_ms = 30000) {
        auto start = std::chrono::steady_clock::now();

        while (true) {
            // Check if we already have a complete line in the buffer
            size_t newline_pos = read_buffer.find('\n');
            if (newline_pos != std::string::npos) {
                std::string line = read_buffer.substr(0, newline_pos);
                read_buffer.erase(0, newline_pos + 1);
                // Remove trailing \r if present
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                return line;
            }

            // Check timeout
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            if (elapsed >= timeout_ms) break;

            // Read more data into buffer
            char buf[4096];
#if defined(_WIN32)
            // Set socket to non-blocking temporarily for poll-like behavior
            u_long mode = 1;
            ioctlsocket(sock, FIONBIO, &mode);
            int r = ::recv(sock, buf, sizeof(buf) - 1, 0);
            mode = 0;
            ioctlsocket(sock, FIONBIO, &mode);
            if (r == SOCKET_ERROR) {
                int err = WSAGetLastError();
                if (err == WSAEWOULDBLOCK) {
                    miq_sleep_ms(10);
                    continue;
                }
                connected.store(false);
                break;
            }
#else
            // Use poll for non-blocking check
            struct pollfd pfd;
            pfd.fd = sock;
            pfd.events = POLLIN;
            int poll_result = poll(&pfd, 1, 100); // 100ms poll timeout
            if (poll_result <= 0) {
                if (poll_result < 0) {
                    connected.store(false);
                    break;
                }
                continue; // timeout, loop again
            }
            int r = ::recv(sock, buf, sizeof(buf) - 1, 0);
#endif
            if (r > 0) {
                buf[r] = '\0';
                read_buffer.append(buf, r);
            } else if (r == 0) {
                // Connection closed
                connected.store(false);
                break;
            } else {
#if !defined(_WIN32)
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
#endif
                connected.store(false);
                break;
            }
        }

        // Return whatever we have (may be partial or empty)
        if (!read_buffer.empty()) {
            size_t newline_pos = read_buffer.find('\n');
            if (newline_pos != std::string::npos) {
                std::string line = read_buffer.substr(0, newline_pos);
                read_buffer.erase(0, newline_pos + 1);
                if (!line.empty() && line.back() == '\r') line.pop_back();
                return line;
            }
        }
        return "";
    }

    // Helper to extract string from JSON array by index
    static bool json_array_string(const std::string& json, int index, std::string& out) {
        int depth = 0;
        int current_idx = -1;
        bool in_string = false;
        size_t str_start = 0;

        for (size_t i = 0; i < json.size(); i++) {
            char c = json[i];
            if (c == '"' && (i == 0 || json[i-1] != '\\')) {
                in_string = !in_string;
                if (in_string && depth == 1) {
                    str_start = i + 1;
                } else if (!in_string && depth == 1 && current_idx == index) {
                    out = json.substr(str_start, i - str_start);
                    return true;
                }
            } else if (!in_string) {
                if (c == '[') {
                    depth++;
                    if (depth == 1) current_idx = 0;
                } else if (c == ']') {
                    depth--;
                } else if (c == ',' && depth == 1) {
                    current_idx++;
                }
            }
        }
        return false;
    }

    // Helper to extract number from JSON
    static bool json_array_number(const std::string& json, int index, uint32_t& out) {
        int depth = 0;
        int current_idx = -1;
        bool in_string = false;

        for (size_t i = 0; i < json.size(); i++) {
            char c = json[i];
            if (c == '"' && (i == 0 || json[i-1] != '\\')) {
                in_string = !in_string;
            } else if (!in_string) {
                if (c == '[') {
                    depth++;
                    if (depth == 1) current_idx = 0;
                } else if (c == ']') {
                    depth--;
                } else if (c == ',' && depth == 1) {
                    current_idx++;
                } else if (depth == 1 && current_idx == index && std::isdigit(c)) {
                    size_t end = i;
                    while (end < json.size() && (std::isdigit(json[end]) || json[end] == '.')) end++;
                    out = (uint32_t)std::stoul(json.substr(i, end - i));
                    return true;
                }
            }
        }
        return false;
    }

    bool subscribe() {
        std::ostringstream ss;
        ss << "{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"chronen-miner/1.0\"]}";
        if (!send_json(ss.str())) return false;

        // CRITICAL FIX: Read ALL pending messages after subscribe
        // Server sends: subscribe_response, set_difficulty, mining.notify
        bool got_subscribe_response = false;
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);

        while (std::chrono::steady_clock::now() < deadline) {
            std::string resp = recv_line(1000);
            if (resp.empty()) {
                if (!connected.load()) return false;
                if (got_subscribe_response) break; // Got response, no more data coming
                continue;
            }

            // Check for subscribe response
            if (resp.find("\"result\"") != std::string::npos && resp.find("\"id\":1") != std::string::npos) {
                // Parse result array: [[["mining.notify", "subscription_id"]], extranonce1, extranonce2_size]
                size_t result_pos = resp.find("\"result\"");
                if (result_pos == std::string::npos) continue;

                size_t arr_start = resp.find('[', result_pos);
                if (arr_start == std::string::npos) continue;

                // Find extranonce1 (first string after the nested array)
                int depth = 0;
                size_t i = arr_start;
                bool found_inner = false;

                for (; i < resp.size(); i++) {
                    if (resp[i] == '[') depth++;
                    else if (resp[i] == ']') {
                        depth--;
                        if (depth == 1 && !found_inner) {
                            found_inner = true;
                        }
                    }
                    else if (resp[i] == '"' && found_inner && depth == 1) {
                        // This should be extranonce1
                        size_t start = i + 1;
                        size_t end = resp.find('"', start);
                        if (end != std::string::npos) {
                            extranonce1 = resp.substr(start, end - start);
                            // Find extranonce2_size (number after extranonce1)
                            size_t num_start = end + 1;
                            while (num_start < resp.size() && !std::isdigit(resp[num_start])) num_start++;
                            if (num_start < resp.size()) {
                                size_t num_end = num_start;
                                while (num_end < resp.size() && std::isdigit(resp[num_end])) num_end++;
                                if (num_end > num_start) {
                                    extranonce2_size = (uint32_t)std::stoul(resp.substr(num_start, num_end - num_start));
                                }
                            }
                            got_subscribe_response = true;
                            break;
                        }
                    }
                }
            }

            // CRITICAL FIX: Also process difficulty and job notifications during subscribe
            if (resp.find("set_difficulty") != std::string::npos) {
                parse_difficulty(resp);
            }
            if (resp.find("mining.notify") != std::string::npos) {
                parse_job(resp);
            }

            // If we have the subscribe response and a job, we're done
            if (got_subscribe_response && has_job.load()) break;
        }

        return !extranonce1.empty();
    }

    bool authorize() {
        std::ostringstream ss;
        ss << "{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\""
           << worker << "\",\"" << password << "\"]}";
        if (!send_json(ss.str())) return false;

        // CRITICAL FIX: Read response with proper handling for additional messages
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(5000);
        while (std::chrono::steady_clock::now() < deadline) {
            std::string resp = recv_line(1000);
            if (resp.empty()) {
                if (!connected.load()) return false;
                continue;
            }

            // Check for authorize response
            if (resp.find("\"id\":2") != std::string::npos || resp.find("\"id\": 2") != std::string::npos) {
                return resp.find("true") != std::string::npos;
            }

            // Also process any difficulty/job notifications that come during authorize
            if (resp.find("set_difficulty") != std::string::npos) {
                parse_difficulty(resp);
            }
            if (resp.find("mining.notify") != std::string::npos) {
                parse_job(resp);
            }
        }
        return false;
    }

    // Helper to extract array of strings (for merkle_branch)
    static bool json_array_strings(const std::string& json, int index, std::vector<std::string>& out) {
        int depth = 0;
        int current_idx = -1;
        bool in_string = false;
        bool in_target_array = false;
        size_t target_start = 0;

        for (size_t i = 0; i < json.size(); i++) {
            char c = json[i];
            if (c == '"' && (i == 0 || json[i-1] != '\\')) {
                in_string = !in_string;
            } else if (!in_string) {
                if (c == '[') {
                    if (depth == 0) {
                        current_idx = 0;
                    } else if (depth == 1 && current_idx == index) {
                        in_target_array = true;
                        target_start = i;
                    }
                    depth++;
                } else if (c == ']') {
                    depth--;
                    if (in_target_array && depth == 1) {
                        // Extract the array content
                        std::string arr = json.substr(target_start, i - target_start + 1);
                        // Parse strings from this array
                        out.clear();
                        bool in_str = false;
                        size_t str_start = 0;
                        for (size_t j = 0; j < arr.size(); j++) {
                            if (arr[j] == '"' && (j == 0 || arr[j-1] != '\\')) {
                                in_str = !in_str;
                                if (in_str) {
                                    str_start = j + 1;
                                } else {
                                    out.push_back(arr.substr(str_start, j - str_start));
                                }
                            }
                        }
                        return true;
                    }
                } else if (c == ',' && depth == 1) {
                    current_idx++;
                }
            }
        }
        return false;
    }

    // Parse mining.notify job notification
    bool parse_job(const std::string& line) {
        if (line.find("mining.notify") == std::string::npos) return false;

        // Find params array
        size_t params_pos = line.find("\"params\"");
        if (params_pos == std::string::npos) return false;

        size_t arr_start = line.find('[', params_pos);
        if (arr_start == std::string::npos) return false;

        std::string params = line.substr(arr_start);

        std::lock_guard<std::mutex> lk(job_mtx);

        // Parse job parameters: [job_id, prevhash, coinbase1, coinbase2, merkle_branch[], version, nbits, ntime, clean]
        std::string job_id, prev_hash_hex, coinb1, coinb2, version_hex, bits_hex, time_hex;
        std::vector<std::string> merkle_branch;

        if (!json_array_string(params, 0, job_id)) return false;
        if (!json_array_string(params, 1, prev_hash_hex)) return false;
        if (!json_array_string(params, 2, coinb1)) return false;
        if (!json_array_string(params, 3, coinb2)) return false;

        // Parse merkle_branch array at index 4
        json_array_strings(params, 4, merkle_branch);

        if (!json_array_string(params, 5, version_hex)) return false;
        if (!json_array_string(params, 6, bits_hex)) return false;
        if (!json_array_string(params, 7, time_hex)) return false;

        current_job.job_id = job_id;
        current_job.coinbase1 = coinb1;
        current_job.coinbase2 = coinb2;
        current_job.merkle_branch = merkle_branch;

        // Parse hex values
        try {
            current_job.prev_hash = from_hex_s(prev_hash_hex);
            current_job.version = (uint32_t)std::stoul(version_hex, nullptr, 16);
            current_job.bits = (uint32_t)std::stoul(bits_hex, nullptr, 16);
            current_job.time = (uint32_t)std::stoul(time_hex, nullptr, 16);
        } catch (...) {
            return false;
        }

        // Check for clean flag
        current_job.clean = (line.find("true", params_pos + 100) != std::string::npos);

        has_job.store(true);
        return true;
    }

    // Parse mining.set_difficulty
    bool parse_difficulty(const std::string& line) {
        if (line.find("set_difficulty") == std::string::npos) return false;

        size_t params_pos = line.find("\"params\"");
        if (params_pos == std::string::npos) return false;

        size_t arr_start = line.find('[', params_pos);
        if (arr_start == std::string::npos) return false;

        // Find the difficulty number
        size_t num_start = arr_start + 1;
        while (num_start < line.size() && !std::isdigit(line[num_start]) && line[num_start] != '.') num_start++;

        if (num_start < line.size()) {
            size_t num_end = num_start;
            while (num_end < line.size() && (std::isdigit(line[num_end]) || line[num_end] == '.')) num_end++;
            try {
                difficulty.store(std::stod(line.substr(num_start, num_end - num_start)));
                return true;
            } catch (...) {}
        }
        return false;
    }

    // Get current job (thread-safe copy)
    StratumJob get_job() {
        std::lock_guard<std::mutex> lk(job_mtx);
        return current_job;
    }

    bool submit_share(const std::string& job_id, const std::string& extranonce2,
                      const std::string& ntime, const std::string& nonce) {
        std::lock_guard<std::mutex> lk(mtx);
        last_submit_id = ++job_id_counter;
        std::ostringstream ss;
        ss << "{\"id\":" << last_submit_id << ",\"method\":\"mining.submit\",\"params\":[\""
           << worker << "\",\"" << job_id << "\",\"" << extranonce2 << "\",\""
           << ntime << "\",\"" << nonce << "\"]}";
        return send_json(ss.str());
    }

    // Check if a response indicates share was accepted
    bool check_submit_response(const std::string& line, uint64_t submit_id) {
        // Look for {"id":submit_id,"result":true/false}
        std::string id_str = "\"id\":" + std::to_string(submit_id);
        if (line.find(id_str) == std::string::npos) return false;
        return line.find("true") != std::string::npos;
    }

    void disconnect() {
#if defined(_WIN32)
        if (sock != INVALID_SOCKET) {
            miq_closesocket(sock);
            sock = INVALID_SOCKET;
        }
#else
        if (sock >= 0) {
            miq_closesocket(sock);
            sock = -1;
        }
#endif
        connected.store(false);
        has_job.store(false);
        read_buffer.clear(); // CRITICAL FIX: Clear read buffer on disconnect
    }
};

// ===== usage =================================================================
static void usage(){
    std::cout <<
    "+============================================================================+\n"
    "|                    " << MIQMINER_VERSION_STRING << "                        |\n"
    "|              Professional Cryptocurrency Mining Software                  |\n"
    "+============================================================================+\n\n"
    "Usage:\n"
    "  miqminer [options]\n\n"
    "Mining Modes (interactive selection at startup if not specified):\n"
    "  [1] SOLO MINING  - Mine to your own node (requires running full node)\n"
    "  [2] POOL MINING  - Connect to mining pool (no full node required)\n\n"
    "Solo Mining Options:\n"
    "  --rpc=host:port       RPC endpoint (default: 127.0.0.1:9332)\n"
    "  --token=TOKEN         RPC authentication token\n"
    "  --address=ADDR        P2PKH payout address (Base58Check)\n\n"
    "Pool Mining Options:\n"
    "  --pool=host:port      Pool address (enables pool mode)\n"
    "  --worker=NAME         Worker name (default: address.miner1)\n"
    "  --pool-pass=PASS      Pool password (default: x)\n\n"
    "Performance Options:\n"
    "  --threads=N           CPU mining threads (default: 6)\n"
    "  --priority=high       Set high process priority\n"
    "  --affinity=on         Pin threads to CPU cores\n"
    "  --smooth=SECONDS      Hash rate smoothing window (default: 15)\n\n"
    "GPU Options:\n"
    "  --gpu=on|off          Enable/disable GPU mining\n"
    "  --gpu-platform=IDX    OpenCL platform index\n"
    "  --gpu-device=IDX      OpenCL device index\n"
    "  --gws=SIZE            Global work size\n"
    "  --gnpi=N              Nonces per GPU work item\n\n"
    "Advanced Options:\n"
    "  --salt-hex=HEX        Custom salt bytes\n"
    "  --salt-pos=pre|post   Salt position in header\n"
    "  --no-ansi             Disable ANSI colors\n\n"
    "Notes:\n"
    "  - Token can be provided via --token, MIQ_RPC_TOKEN env var, or .cookie file\n"
    "  - GPU requires build with -DMIQ_ENABLE_OPENCL and OpenCL runtime\n\n"
    "Version: " MIQMINER_VERSION "\n";
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

        // Pool mining options
        std::string pool_host;
        uint16_t pool_port = 0;
        std::string pool_worker;
        std::string pool_pass = "x";
        bool pool_mode = false;

        for(int i=1;i<argc;i++){
            std::string a(argv[i]);
            if(a=="--help"||a=="-h"){ usage(); return 0; }
            else if(a.rfind("--pool=",0)==0){
                std::string hp = a.substr(7); size_t c = hp.find(':');
                if(c==std::string::npos){ std::fprintf(stderr,"Bad --pool=host:port\n"); return 2; }
                pool_host = hp.substr(0,c); pool_port = (uint16_t)std::stoi(hp.substr(c+1));
                pool_mode = true;
            } else if(a.rfind("--worker=",0)==0){
                pool_worker = a.substr(9);
            } else if(a.rfind("--pool-pass=",0)==0){
                pool_pass = a.substr(12);
            } else if(a.rfind("--rpc=",0)==0){
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
                std::string cookie_path = default_cookie_path();
                std::string cookie;
                if(read_all_file(cookie_path, cookie)) {
                    token = cookie;
                    std::fprintf(stderr, "[auth] Using cookie from: %s\n", cookie_path.c_str());
                } else {
                    std::fprintf(stderr, "[auth] WARNING: Cookie not found at: %s\n", cookie_path.c_str());
                    std::fprintf(stderr, "[auth] Ensure node is running or use --token=TOKEN\n");
                }
            }
        }
        if(const char* aenv = std::getenv("MIQ_ADDRESS")){
            if(address_cli.empty()) address_cli = aenv;
        }

        set_process_priority(high_priority);

        // ===== Splash & address
        show_intro();

        // Get mining address first (needed for both modes)
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

        // ===== Mining Mode Selection (unless --pool was specified on command line)
        MiningMode mining_mode = MiningMode::SOLO;
        PoolConfig pool_cfg;

        if (pool_mode) {
            // Pool mode was set via command line
            mining_mode = MiningMode::POOL;
            pool_cfg.host = pool_host;
            pool_cfg.port = pool_port;
            pool_cfg.worker = pool_worker.empty() ? (addr + ".miner1") : pool_worker;
            pool_cfg.password = pool_pass;
        } else {
            // Show interactive mining mode selection
            mining_mode = show_mining_mode_menu();

            if (mining_mode == MiningMode::POOL) {
                // Get pool configuration
                if (!show_pool_config_menu(pool_cfg, addr)) {
                    std::fprintf(stderr, "Pool configuration cancelled.\n");
                    return 1;
                }
            }
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

        // ===== PRE-FLIGHT CONNECTION TEST =====
        // For solo mining: wait for the node to be ready
        // For pool mining: test pool connection
        if (mining_mode == MiningMode::SOLO) {
            const int MAX_RETRIES = 30;  // 30 seconds max wait
            const int RETRY_DELAY_MS = 1000;
            bool connected = false;

            std::fprintf(stderr, "\n[startup] Testing RPC connection to %s:%u...\n", rpc_host.c_str(), rpc_port);

            for (int attempt = 1; attempt <= MAX_RETRIES && !connected; ++attempt) {
                TipInfo tip{};
                if (rpc_gettipinfo(rpc_host, rpc_port, token, tip)) {
                    connected = true;
                    ui.node_reachable.store(true);
                    ui.tip_height.store(tip.height);
                    ui.tip_hash_hex = tip.hash_hex;
                    ui.tip_bits.store(tip.bits);
                    std::fprintf(stderr, "[startup] \x1b[32;1mRPC Connection SUCCEEDED & CONNECTED!\x1b[0m\n");
                    std::fprintf(stderr, "[startup] Tip height: %llu, Difficulty: %.2f\n",
                                (unsigned long long)tip.height, difficulty_from_bits(tip.bits));
                } else {
                    if (attempt == 1) {
                        std::fprintf(stderr, "[startup] Node not responding. Waiting for node to start...\n");
                        std::fprintf(stderr, "         (ensure miqrochain node is running with RPC on port %u)\n", rpc_port);
                    }
                    if (attempt % 5 == 0) {
                        std::fprintf(stderr, "[startup] Still waiting... (attempt %d/%d)\n", attempt, MAX_RETRIES);
                    }
                    for (int i = 0; i < 10; ++i) miq_sleep_ms(RETRY_DELAY_MS / 10);
                }
            }

            if (!connected) {
                std::fprintf(stderr, "\n\x1b[31;1m");
                std::fprintf(stderr, "[ERROR] Could not connect to node at %s:%u after %d seconds\n",
                            rpc_host.c_str(), rpc_port, MAX_RETRIES);
                std::fprintf(stderr, "\x1b[0m");
                std::fprintf(stderr, "\nPossible causes:\n");
                std::fprintf(stderr, "  1. Node is not running - start it with: miqrochain --daemon\n");
                std::fprintf(stderr, "  2. RPC server not enabled - check node configuration\n");
                std::fprintf(stderr, "  3. Wrong port - verify RPC_PORT=%u is correct\n", rpc_port);
                std::fprintf(stderr, "  4. Firewall blocking local connections\n");
                if (!token.empty()) {
                    std::fprintf(stderr, "  5. Auth token may be incorrect or expired\n");
                }
                std::fprintf(stderr, "\nRetrying with exponential backoff...\n\n");

                // Continue anyway but with warning - the mining loop will keep retrying
                log_line("[startup] Initial connection failed, continuing with retry loop");
            }
        } else {
            // Pool mining mode - test pool connection
            std::fprintf(stderr, "\n[startup] Testing pool connection to %s:%u...\n",
                        pool_cfg.host.c_str(), pool_cfg.port);

            StratumClient stratum;
            stratum.host = pool_cfg.host;
            stratum.port = pool_cfg.port;
            stratum.worker = pool_cfg.worker;
            stratum.password = pool_cfg.password;

            if (stratum.connect_to_pool()) {
                std::fprintf(stderr, "[startup] Pool connected! Subscribing...\n");
                if (stratum.subscribe()) {
                    std::fprintf(stderr, "[startup] Subscribed. Authorizing worker...\n");
                    if (stratum.authorize()) {
                        std::fprintf(stderr, "[startup] \x1b[32;1mPool Connection SUCCEEDED & CONNECTED!\x1b[0m\n");
                        std::fprintf(stderr, "[startup] Worker %s authorized successfully!\n", pool_cfg.worker.c_str());
                        ui.node_reachable.store(true);
                    } else {
                        std::fprintf(stderr, "[startup] WARNING: Worker authorization failed\n");
                    }
                } else {
                    std::fprintf(stderr, "[startup] WARNING: Pool subscription failed\n");
                }
                stratum.disconnect();
            } else {
                std::fprintf(stderr, "[startup] WARNING: Could not connect to pool %s:%u\n",
                            pool_cfg.host.c_str(), pool_cfg.port);
                std::fprintf(stderr, "         Will retry during mining...\n");
            }
        }

        // ===== UI thread (animated dashboard)
        std::thread ui_th([&](){
            using clock = std::chrono::steady_clock;
            const int FPS = 8;  // Slightly lower FPS for less CPU usage
            const auto frame_dt = std::chrono::milliseconds(1000/FPS);
            int spin_idx = 0;

            // Config card (one-time startup display)
            {
                std::ostringstream s;
                s << CLS();
                s << C("36;1");
                const size_t kBannerN = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
                for(size_t i=0;i<kBannerN;i++) s << kChronenMinerBanner[i] << "\n";
                s << R() << "\n";
                s << "  " << C("1") << "Initializing Chronen Miner..." << R() << "\n\n";
                s << "  " << C("36") << ">" << R() << " RPC Endpoint: " << C("1") << ui.rpc_host << ":" << ui.rpc_port << R() << "\n";
                s << "  " << C("36") << ">" << R() << " Payout Addr : " << C("33;1") << pkh_to_address(ui.my_pkh) << R() << "\n";
                s << "  " << C("36") << ">" << R() << " CPU Threads : " << C("1") << (int)threads << R();
                if(pin_affinity) s << C("2") << " [affinity]" << R();
                if(high_priority) s << C("2") << " [high-priority]" << R();
                s << "\n";
#if defined(MIQ_ENABLE_OPENCL)
                s << "  " << C("36") << ">" << R() << " GPU Mining  : " << (ui.gpu_available.load() ? (C("32;1") + "ENABLED" + R() + " - " + ui.gpu_device) : (C("2") + "disabled" + R())) << "\n";
#endif
                s << "\n  " << C("33") << "Loading dashboard..." << R() << "\n";
                std::cout << s.str() << std::flush;
                miq_sleep_ms(800);
            }

            // Track max hash rates for bar scaling
            double max_cpu_hs = 1000.0;
            double max_gpu_hs = 1000.0;
            double max_net_hs = 10000.0;

            while(ui.running.load(std::memory_order_relaxed)){
                [[maybe_unused]] TermSize ts = get_term_size();
                std::ostringstream out;
                out << CLS();

                // ═══════════════════════════════════════════════════════════════
                // HEADER - Banner
                // ═══════════════════════════════════════════════════════════════
                out << C("36;1");
                const size_t kBannerN = sizeof(kChronenMinerBanner)/sizeof(kChronenMinerBanner[0]);
                for(size_t i=0;i<kBannerN;i++) out << kChronenMinerBanner[i] << "\n";
                out << R();

                // ═══════════════════════════════════════════════════════════════
                // SECTION 1: NETWORK/POOL STATUS
                // ═══════════════════════════════════════════════════════════════
                out << "\n" << C("36;1") << "======================================================================" << R() << "\n";

                bool is_pool_mode = ui.pool_mode.load();

                if (is_pool_mode) {
                    out << C("1;4") << " POOL STATUS" << R() << "\n";
                    out << C("36") << "----------------------------------------------------------------------" << R() << "\n";

                    // Pool connection status
                    bool connected = ui.node_reachable.load();
                    out << "  " << C("1") << "Connection  :" << R() << " "
                        << ui_status(connected, "SUCCEEDED & CONNECTED", "DISCONNECTED")
                        << "  " << C("2") << "(" << ui.pool_host << ":" << ui.pool_port << ")" << R() << "\n";

                    out << "  " << C("1") << "Worker      :" << R() << " " << C("33") << ui.pool_worker << R() << "\n";

                    // Pool difficulty
                    double pool_diff = ui.pool_difficulty.load();
                    out << "  " << C("1") << "Pool Diff   :" << R() << " " << std::fixed << std::setprecision(4) << pool_diff << "\n";

                    // Jobs received
                    uint64_t jobs = ui.pool_jobs_received.load();
                    out << "  " << C("1") << "Jobs Recv'd :" << R() << " " << C("36") << jobs << R() << "\n";

                    // Current job ID
                    {
                        std::lock_guard<std::mutex> lk(ui.pool_mtx);
                        if (!ui.current_job_id.empty()) {
                            out << "  " << C("1") << "Current Job :" << R() << " " << C("2") << ui.current_job_id << R() << "\n";
                        }
                    }
                } else {
                    out << C("1;4") << " NETWORK STATUS" << R() << "\n";
                    out << C("36") << "----------------------------------------------------------------------" << R() << "\n";

                    // RPC connection status
                    bool connected = ui.node_reachable.load();
                    out << "  " << C("1") << "RPC Status  :" << R() << " "
                        << ui_status(connected, "SUCCEEDED & CONNECTED", "NOT CONNECTED")
                        << "  " << C("2") << "(" << ui.rpc_host << ":" << ui.rpc_port << ")" << R() << "\n";

                    // Blockchain tip
                    uint64_t tip_h = ui.tip_height.load();
                    uint32_t tip_bits = ui.tip_bits.load();
                    double difficulty = difficulty_from_bits(tip_bits);

                    out << "  " << C("1") << "Block Height:" << R() << " " << C("33;1") << tip_h << R() << "\n";
                    out << "  " << C("1") << "Difficulty  :" << R() << " " << std::fixed << std::setprecision(4) << difficulty
                        << "  " << C("2") << "(bits: 0x" << std::hex << std::setw(8) << std::setfill('0') << tip_bits << std::dec << ")" << R() << "\n";

                    // Network hashrate
                    double net_hs = ui.net_hashps.load();
                    if (net_hs > max_net_hs) max_net_hs = net_hs * 1.2;
                    out << "  " << C("1") << "Network H/s :" << R() << " " << C("36") << fmt_hs(net_hs) << R() << "\n";
                }

                // ═══════════════════════════════════════════════════════════════
                // SECTION 2: CURRENT MINING JOB
                // ═══════════════════════════════════════════════════════════════
                out << "\n" << C("33;1") << "======================================================================" << R() << "\n";
                out << C("1;4") << " CURRENT JOB" << R() << "\n";
                out << C("33") << "----------------------------------------------------------------------" << R() << "\n";

                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    if(ui.cand.height){
                        out << "  " << C("1") << "Mining Block:" << R() << " " << C("33;1") << "#" << ui.cand.height << R() << "\n";
                        out << "  " << C("1") << "Prev Hash   :" << R() << " " << C("2") << ui.cand.prev_hex.substr(0, 32) << "..." << R() << "\n";
                        out << "  " << C("1") << "Transactions:" << R() << " " << C("36") << ui.cand.txs << R() << " txs  (" << ui.cand.size_bytes << " bytes)\n";
                        out << "  " << C("1") << "Fees        :" << R() << " " << C("33") << fmt_miq_amount(ui.cand.fees) << R() << "\n";
                        out << "  " << C("1") << "Reward      :" << R() << " " << C("32;1") << fmt_miq_amount(ui.cand.coinbase) << R() << "\n";

                        // Live hash preview (animated)
                        std::string nxh;
                        {
                            std::lock_guard<std::mutex> lk2(ui.next_hash_mtx);
                            std::ostringstream hh;
                            for(int i=0;i<32;i++) hh << std::hex << std::setw(2) << std::setfill('0') << (unsigned)ui.next_hash_sample[i];
                            nxh = hh.str();
                        }
                        if(!nxh.empty()){
                            // Animated hash display
                            std::array<std::string,5> spin_rows;
                            spinner_circle_ascii(spin_idx, spin_rows);
                            out << "  " << C("1") << "Hash Preview:" << R() << " " << C("2;3") << nxh.substr(0,48) << "..." << R() << "\n";
                        }
                    } else {
                        bool conn = ui.node_reachable.load();
                        out << "  " << C("33") << "[...] " << (conn ? "Waiting for mining template..." : "Connecting to node...") << R() << "\n";
                    }
                }

                // ═══════════════════════════════════════════════════════════════
                // SECTION 3: PERFORMANCE METRICS
                // ═══════════════════════════════════════════════════════════════
                out << "\n" << C("32;1") << "======================================================================" << R() << "\n";
                out << C("1;4") << " PERFORMANCE" << R() << "\n";
                out << C("32") << "----------------------------------------------------------------------" << R() << "\n";

                // CPU hashrate with bar
                double cpu_smooth = ui.hps_smooth.load();
                double cpu_now = ui.hps_now.load();
                if (cpu_smooth > max_cpu_hs) max_cpu_hs = cpu_smooth * 1.2;

                out << "  " << C("1") << "CPU Hash/s  :" << R() << " " << fmt_hs_bar(cpu_smooth, max_cpu_hs, 15) << "\n";
                out << "               " << C("2") << "(instant: " << fmt_hs(cpu_now) << ")" << R() << "\n";

                // GPU hashrate with bar
                if(ui.gpu_available.load()){
                    double gpu_smooth = ui.gpu_hps_smooth.load();
                    double gpu_now = ui.gpu_hps_now.load();
                    if (gpu_smooth > max_gpu_hs) max_gpu_hs = gpu_smooth * 1.2;

                    out << "  " << C("1") << "GPU Hash/s  :" << R() << " " << fmt_hs_bar(gpu_smooth, max_gpu_hs, 15) << "\n";
                    out << "               " << C("2") << "(instant: " << fmt_hs(gpu_now) << ")" << R() << "\n";
                } else {
                    out << "  " << C("1") << "GPU Hash/s  :" << R() << " " << C("2") << "[disabled]" << R() << "\n";
                }

                // Combined stats
                double total_hs = cpu_smooth + (ui.gpu_available.load() ? ui.gpu_hps_smooth.load() : 0.0);
                out << "  " << C("1") << "Total H/s   :" << R() << " " << C("36;1") << fmt_hs(total_hs) << R() << "\n";

                // Sparkline trend
                {
                    std::lock_guard<std::mutex> lk(ui.spark_mtx);
                    if(!ui.sparkline.empty()){
                        out << "  " << C("1") << "Trend       :" << R() << " " << C("36") << spark_ascii(ui.sparkline) << R() << "\n";
                    }
                }

                // ═══════════════════════════════════════════════════════════════
                // SECTION 4: WALLET & REWARDS / POOL SHARES
                // ═══════════════════════════════════════════════════════════════
                out << "\n" << C("35;1") << "======================================================================" << R() << "\n";

                if (is_pool_mode) {
                    out << C("1;4") << " POOL SHARES" << R() << "\n";
                    out << C("35") << "----------------------------------------------------------------------" << R() << "\n";

                    out << "  " << C("1") << "Payout Addr :" << R() << " " << C("33") << pkh_to_address(ui.my_pkh) << R() << "\n";

                    // Share statistics
                    uint64_t submitted = ui.shares_submitted.load();
                    uint64_t accepted = ui.shares_accepted.load();
                    uint64_t rejected = ui.shares_rejected.load();

                    out << "  " << C("1") << "Submitted   :" << R() << " " << C("36;1") << submitted << R() << " shares\n";

                    // Accepted with success rate
                    double success_rate = (submitted > 0) ? (100.0 * accepted / submitted) : 0.0;
                    out << "  " << C("1") << "Accepted    :" << R() << " " << C("32;1") << accepted << R();
                    if (submitted > 0) {
                        out << "  " << C("2") << "(" << std::fixed << std::setprecision(1) << success_rate << "% success rate)" << R();
                    }
                    out << "\n";

                    // Rejected
                    out << "  " << C("1") << "Rejected    :" << R() << " ";
                    if (rejected > 0) {
                        out << C("31;1") << rejected << R() << "\n";
                    } else {
                        out << C("32") << "0" << R() << "\n";
                    }

                    // Share ratio bar
                    if (submitted > 0) {
                        int bar_width = 30;
                        int accepted_bar = (int)((double)accepted / submitted * bar_width);
                        out << "  " << C("1") << "Share Ratio :" << R() << " [";
                        for (int i = 0; i < bar_width; i++) {
                            if (i < accepted_bar) out << C("32") << "#" << R();
                            else out << C("31") << "." << R();
                        }
                        out << "]\n";
                    }
                } else {
                    out << C("1;4") << " WALLET & REWARDS" << R() << "\n";
                    out << C("35") << "----------------------------------------------------------------------" << R() << "\n";

                    out << "  " << C("1") << "Payout Addr :" << R() << " " << C("33") << pkh_to_address(ui.my_pkh) << R() << "\n";

                    uint64_t mined = ui.mined_blocks.load();
                    out << "  " << C("1") << "Blocks Mined:" << R() << " " << C("32;1") << mined << R() << " (this session)\n";

                    [[maybe_unused]] uint64_t paid_base = ui.total_received_base.load();
                    uint64_t est_total = ui.est_total_base.load();
                    uint64_t est_matured = ui.est_matured_base.load();

                    out << "  " << C("1") << "Est. Earned :" << R() << " " << C("36;1") << fmt_miq_amount(est_total) << R();
                    if (est_matured > 0 && est_matured != est_total) {
                        out << "  " << C("2") << "(matured: " << fmt_miq_amount(est_matured) << ")" << R();
                    }
                    out << "\n";

                    // Winner notification
                    if(ui.last_seen_height.load() == ui.tip_height.load() && ui.last_seen_height.load() > 0){
                        if(ui.last_tip_was_mine.load()){
                            out << "\n  " << C("32;1") << "*** YOU MINED THE LATEST BLOCK! ***" << R() << "\n";
                        }else if(!ui.last_winner_addr.empty()){
                            out << "\n  " << C("2") << "Latest block mined by: " << ui.last_winner_addr.substr(0,24) << "..." << R() << "\n";
                        }
                    }
                }

                // ═══════════════════════════════════════════════════════════════
                // SECTION 5: ACTIVITY LOG
                // ═══════════════════════════════════════════════════════════════
                out << "\n" << C("37;1") << "======================================================================" << R() << "\n";
                out << C("1;4") << " ACTIVITY" << R() << "\n";
                out << C("37") << "----------------------------------------------------------------------" << R() << "\n";

                {
                    auto age = std::chrono::duration<double>(clock::now() - ui.last_submit_when).count();
                    if(!ui.last_submit_msg.empty() && age < 15.0){
                        out << "  " << ui.last_submit_msg << "\n";
                    } else {
                        // Show animated spinner when no recent activity
                        std::array<std::string,5> spin_rows;
                        spinner_circle_ascii(spin_idx, spin_rows);
                        const char* spinners = "|/-\\";
                        char spinner = spinners[spin_idx % 4];
                        out << "  " << C("2") << spinner << " Mining in progress..." << R() << "\n";
                    }
                }

                // ═══════════════════════════════════════════════════════════════
                // FOOTER
                // ═══════════════════════════════════════════════════════════════
                out << "\n" << C("36") << "======================================================================" << R() << "\n";

                // Show uptime and version
                static auto start_time = clock::now();
                int uptime_secs = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(clock::now() - start_time).count());
                int hours = uptime_secs / 3600;
                int mins = (uptime_secs % 3600) / 60;
                int secs = uptime_secs % 60;

                out << "  " << C("2") << MIQMINER_VERSION_STRING << R();
                out << "  |  " << C("2") << "Mode: " << R() << C("1");
                out << (is_pool_mode ? "POOL" : "SOLO");
                out << R() << "  |  " << C("2") << "Uptime: " << R();
                if (hours > 0) out << hours << "h ";
                out << mins << "m " << secs << "s\n";
                out << "  " << C("2") << "Press " << C("1") << "Ctrl+C" << R() << C("2") << " to stop mining gracefully" << R() << "\n";

                ++spin_idx;
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
                } else {
                    // RPC call failed - mark node as unreachable
                    ui.node_reachable.store(false);
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
        // FIXED: Use 8-byte time to match main miner format (total 80 bytes)
        [[maybe_unused]] auto build_header_prefix80 = [](const BlockHeader& H, const std::vector<uint8_t>& merkle)->std::vector<uint8_t>{
            std::vector<uint8_t> p;
            p.reserve(80);  // 4+32+32+8+4 = 80 bytes
            put_u32_le(p, H.version);
            p.insert(p.end(), H.prev_hash.begin(), H.prev_hash.end());
            p.insert(p.end(), merkle.begin(), merkle.end());
            put_u64_le(p, (uint64_t)H.time);  // 8 bytes
            put_u32_le(p, H.bits);
            return p;
        };
        [[maybe_unused]] auto make_gpu_prefix = [&](const std::vector<uint8_t>& prefix80)->std::vector<uint8_t>{
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

        // ===== POOL MINING LOOP =====
        if (mining_mode == MiningMode::POOL) {
            std::fprintf(stderr, "[pool] Starting pool mining to %s:%u...\n", pool_cfg.host.c_str(), pool_cfg.port);
            log_line("Starting pool mining to " + pool_cfg.host + ":" + std::to_string(pool_cfg.port));

            // Set pool mode in UI
            ui.pool_mode.store(true);
            ui.pool_host = pool_cfg.host;
            ui.pool_port = pool_cfg.port;
            ui.pool_worker = pool_cfg.worker;

            StratumClient stratum;
            stratum.host = pool_cfg.host;
            stratum.port = pool_cfg.port;
            stratum.worker = pool_cfg.worker;
            stratum.password = pool_cfg.password;

            // Reconnection backoff
            int reconnect_delay_ms = 1000;
            const int max_reconnect_delay_ms = 30000;

            while (ui.running.load()) {
                // Connect to pool
                if (!stratum.connected.load()) {
                    std::fprintf(stderr, "[pool] Connecting to %s:%u...\n", stratum.host.c_str(), stratum.port);

                    if (!stratum.connect_to_pool()) {
                        std::fprintf(stderr, "[pool] Connection failed. Retrying in %d ms...\n", reconnect_delay_ms);
                        {
                            std::lock_guard<std::mutex> lk(ui.mtx);
                            ui.last_submit_msg = C("31;1") + "Pool connection failed - retrying..." + R();
                            ui.last_submit_when = std::chrono::steady_clock::now();
                        }
                        ui.node_reachable.store(false);
                        for (int i = 0; i < reconnect_delay_ms / 100 && ui.running.load(); ++i) miq_sleep_ms(100);
                        reconnect_delay_ms = std::min(reconnect_delay_ms * 2, max_reconnect_delay_ms);
                        continue;
                    }

                    // Subscribe
                    if (!stratum.subscribe()) {
                        std::fprintf(stderr, "[pool] Subscription failed. Reconnecting...\n");
                        stratum.disconnect();
                        for (int i = 0; i < 20 && ui.running.load(); ++i) miq_sleep_ms(100);
                        continue;
                    }

                    std::fprintf(stderr, "[pool] Subscribed. Extranonce1: %s, Size2: %u\n",
                                stratum.extranonce1.c_str(), stratum.extranonce2_size);

                    // Authorize
                    if (!stratum.authorize()) {
                        std::fprintf(stderr, "[pool] Authorization failed. Check worker name/password.\n");
                        {
                            std::lock_guard<std::mutex> lk(ui.mtx);
                            ui.last_submit_msg = C("31;1") + "Pool authorization failed - check credentials" + R();
                            ui.last_submit_when = std::chrono::steady_clock::now();
                        }
                        stratum.disconnect();
                        for (int i = 0; i < 50 && ui.running.load(); ++i) miq_sleep_ms(100);
                        continue;
                    }

                    ui.node_reachable.store(true);
                    reconnect_delay_ms = 1000; // Reset backoff on successful connection
                    {
                        std::lock_guard<std::mutex> lk(ui.mtx);
                        ui.last_submit_msg = C("32;1") + "Pool connection SUCCEEDED & CONNECTED - " + stratum.host + R();
                        ui.last_submit_when = std::chrono::steady_clock::now();
                    }
                    std::fprintf(stderr, "[pool] \x1b[32;1mSUCCEEDED & CONNECTED\x1b[0m - Authorized as %s. Waiting for jobs...\n", stratum.worker.c_str());
                }

                // Mining state
                std::atomic<bool> found_share{false};
                std::atomic<bool> new_job{false};
                std::atomic<uint64_t> found_nonce{0};
                std::string current_job_id;
                uint32_t current_extranonce2 = 0;

                // Wait for initial job
                while (!stratum.has_job.load() && stratum.connected.load() && ui.running.load()) {
                    std::string line = stratum.recv_line(1000);
                    if (line.empty()) {
                        if (!stratum.connected.load()) break;
                        continue;
                    }

                    if (stratum.parse_difficulty(line)) {
                        ui.pool_difficulty.store(stratum.difficulty.load());
                        std::fprintf(stderr, "[pool] Difficulty set to: %.4f\n", stratum.difficulty.load());
                    }

                    if (stratum.parse_job(line)) {
                        ui.pool_jobs_received.fetch_add(1);
                        StratumJob job = stratum.get_job();
                        current_job_id = job.job_id;

                        {
                            std::lock_guard<std::mutex> lk(ui.pool_mtx);
                            ui.current_job_id = job.job_id;
                        }
                        {
                            std::lock_guard<std::mutex> lk(ui.mtx);
                            ui.cand.height = ui.pool_jobs_received.load();
                            ui.cand.bits = job.bits;
                            ui.cand.time = job.time;
                            if (!job.prev_hash.empty()) {
                                ui.cand.prev_hex = to_hex_s(job.prev_hash);
                            }
                            std::ostringstream msg;
                            msg << C("36;1") << "New Pool Job | ID: " << job.job_id
                                << " | Diff: " << std::fixed << std::setprecision(2) << difficulty_from_bits(job.bits) << R();
                            ui.last_submit_msg = msg.str();
                            ui.last_submit_when = std::chrono::steady_clock::now();
                        }
                        std::fprintf(stderr, "[pool] Job received: %s (diff: %.2f)\n",
                                    job.job_id.c_str(), difficulty_from_bits(job.bits));
                    }
                }

                if (!stratum.connected.load() || !ui.running.load()) {
                    stratum.disconnect();
                    continue;
                }

                // Main mining loop - mine shares for current job
                while (stratum.has_job.load() && stratum.connected.load() && ui.running.load()) {
                    StratumJob job = stratum.get_job();
                    current_job_id = job.job_id;
                    current_extranonce2++;

                    // Build coinbase transaction
                    // coinbase = coinbase1 + extranonce1 + extranonce2 + coinbase2
                    std::string extranonce2_hex;
                    {
                        std::ostringstream ss;
                        ss << std::hex << std::setw(stratum.extranonce2_size * 2)
                           << std::setfill('0') << current_extranonce2;
                        extranonce2_hex = ss.str();
                    }

                    std::vector<uint8_t> coinbase_raw;
                    try {
                        std::string coinbase_hex = job.coinbase1 + stratum.extranonce1 + extranonce2_hex + job.coinbase2;
                        coinbase_raw = from_hex_s(coinbase_hex);
                    } catch (...) {
                        std::fprintf(stderr, "[pool] Invalid coinbase hex\n");
                        miq_sleep_ms(100);
                        continue;
                    }

                    // Hash coinbase to get coinbase txid (double SHA256)
                    std::array<uint8_t, 32> coinbase_hash;
                    {
                        std::vector<uint8_t> hash_result = dsha256(coinbase_raw);
                        std::memcpy(coinbase_hash.data(), hash_result.data(), 32);
                    }

                    // Build merkle root from coinbase_hash and merkle_branch
                    std::array<uint8_t, 32> merkle_root = coinbase_hash;
                    for (const auto& branch_hex : job.merkle_branch) {
                        try {
                            std::vector<uint8_t> branch = from_hex_s(branch_hex);
                            if (branch.size() != 32) continue;

                            std::vector<uint8_t> concat;
                            concat.reserve(64);
                            concat.insert(concat.end(), merkle_root.begin(), merkle_root.end());
                            concat.insert(concat.end(), branch.begin(), branch.end());

                            std::vector<uint8_t> hash_result = dsha256(concat);
                            std::memcpy(merkle_root.data(), hash_result.data(), 32);
                        } catch (...) {
                            continue;
                        }
                    }

                    // Build block header: version + prev_hash + merkle_root + time + bits
                    std::vector<uint8_t> header_prefix;
                    header_prefix.reserve(80);

                    // Version (4 bytes LE)
                    put_u32_le(header_prefix, job.version);

                    // Previous hash (32 bytes) - needs to be reversed for internal use
                    if (job.prev_hash.size() == 32) {
                        // Stratum sends prev_hash in a specific byte order
                        header_prefix.insert(header_prefix.end(), job.prev_hash.begin(), job.prev_hash.end());
                    } else {
                        header_prefix.resize(header_prefix.size() + 32, 0);
                    }

                    // Merkle root (32 bytes)
                    header_prefix.insert(header_prefix.end(), merkle_root.begin(), merkle_root.end());

                    // Time (8 bytes for Miqrochain's 8-byte time)
                    put_u64_le(header_prefix, (uint64_t)job.time);

                    // Bits (4 bytes LE)
                    put_u32_le(header_prefix, job.bits);

                    // Calculate share target from pool difficulty
                    double pool_diff = stratum.difficulty.load();
                    ui.pool_difficulty.store(pool_diff);

                    // Convert pool difficulty to bits for share validation
                    // Pool difficulty 1 = 0xFFFF * 2^208 / difficulty
                    // For shares, we use a target that's pool_diff times easier than block target
                    uint32_t share_bits = job.bits;
                    if (pool_diff > 0 && pool_diff < 65535) {
                        // Adjust target for pool difficulty
                        // This is simplified - actual implementation depends on pool
                        double block_diff = difficulty_from_bits(job.bits);
                        double share_target_diff = pool_diff;
                        (void)block_diff; // Use pool difficulty directly
                        (void)share_target_diff;
                    }

                    // Setup for CPU mining
                    found_share.store(false);
                    new_job.store(false);

                    // Create base context for fast hashing
                    FastSha256Ctx base1;
                    fastsha_init(base1);
                    fastsha_update(base1, header_prefix.data(), header_prefix.size());

                    // CPU mining threads for shares
                    std::vector<std::thread> thv;
                    const uint64_t base_nonce = (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull;

                    for (unsigned tid = 0; tid < threads; ++tid) {
                        thv.emplace_back([&, tid]() {
                            if (pin_affinity) pin_thread_to_cpu(tid);

                            uint64_t nonce = base_nonce + (uint64_t)tid;
                            const uint64_t step = (uint64_t)threads;
                            const uint64_t BATCH = (1ull << 14);
                            uint64_t local_hashes = 0;

                            while (!found_share.load(std::memory_order_relaxed) &&
                                   !new_job.load(std::memory_order_relaxed) &&
                                   ui.running.load()) {

                                for (uint64_t i = 0; i < BATCH && !found_share.load(std::memory_order_relaxed); i++) {
                                    uint8_t le8[8];
                                    store_u64_le(le8, nonce);

                                    uint8_t hash[32];
                                    dsha256_from_base(base1, le8, 8, hash);

                                    // Check if hash meets share target
                                    if (meets_target_be_raw(hash, share_bits)) {
                                        found_nonce.store(nonce);
                                        found_share.store(true);
                                        break;
                                    }

                                    // Publish hash preview periodically
                                    if ((local_hashes & 0x3FF) == 0) {
                                        publish_next_hash_sample(hash);
                                    }

                                    nonce += step;
                                    local_hashes++;
                                }

                                // Update global hash counter
                                thr_counts[tid].hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                                local_hashes = 0;
                            }
                        });
                    }

                    // Monitor for new jobs while mining
                    std::thread job_monitor([&]() {
                        while (!found_share.load() && stratum.connected.load() && ui.running.load()) {
                            std::string line = stratum.recv_line(500);
                            if (line.empty()) continue;

                            if (stratum.parse_difficulty(line)) {
                                ui.pool_difficulty.store(stratum.difficulty.load());
                            }

                            if (stratum.parse_job(line)) {
                                ui.pool_jobs_received.fetch_add(1);
                                new_job.store(true);

                                StratumJob new_job_data = stratum.get_job();
                                {
                                    std::lock_guard<std::mutex> lk(ui.mtx);
                                    ui.cand.bits = new_job_data.bits;
                                    ui.cand.time = new_job_data.time;
                                    if (!new_job_data.prev_hash.empty()) {
                                        ui.cand.prev_hex = to_hex_s(new_job_data.prev_hash);
                                    }
                                    std::ostringstream msg;
                                    msg << C("36") << "New Pool Job | ID: " << new_job_data.job_id
                                        << " | Diff: " << std::fixed << std::setprecision(2) << difficulty_from_bits(new_job_data.bits) << R();
                                    ui.last_submit_msg = msg.str();
                                    ui.last_submit_when = std::chrono::steady_clock::now();
                                }
                                break;
                            }

                            // Check for share responses
                            if (line.find("\"result\"") != std::string::npos) {
                                if (line.find("true") != std::string::npos) {
                                    ui.shares_accepted.fetch_add(1);
                                } else if (line.find("false") != std::string::npos ||
                                          line.find("\"error\"") != std::string::npos) {
                                    ui.shares_rejected.fetch_add(1);
                                }
                            }
                        }
                    });

                    // Wait for mining threads
                    for (auto& th : thv) th.join();
                    new_job.store(true); // Signal job monitor to exit
                    if (job_monitor.joinable()) job_monitor.join();

                    // Submit share if found
                    if (found_share.load() && stratum.connected.load()) {
                        uint64_t nonce = found_nonce.load();

                        // Format nonce as hex (8 bytes = 16 hex chars)
                        std::ostringstream nonce_ss;
                        nonce_ss << std::hex << std::setw(16) << std::setfill('0') << nonce;
                        std::string nonce_hex = nonce_ss.str();

                        // Format time as hex
                        std::ostringstream time_ss;
                        time_ss << std::hex << std::setw(8) << std::setfill('0') << job.time;
                        std::string time_hex = time_ss.str();

                        // Submit share
                        if (stratum.submit_share(current_job_id, extranonce2_hex, time_hex, nonce_hex)) {
                            ui.shares_submitted.fetch_add(1);
                            {
                                std::lock_guard<std::mutex> lk(ui.mtx);
                                std::ostringstream msg;
                                msg << C("32;1") << "Share submitted #" << ui.shares_submitted.load()
                                    << " (accepted: " << ui.shares_accepted.load()
                                    << ", rejected: " << ui.shares_rejected.load() << ")" << R();
                                ui.last_submit_msg = msg.str();
                                ui.last_submit_when = std::chrono::steady_clock::now();
                            }
                        } else {
                            std::fprintf(stderr, "[pool] Failed to submit share\n");
                        }
                    }

                    // Small delay before next round
                    if (!new_job.load() && ui.running.load()) {
                        miq_sleep_ms(50);
                    }
                }

                // Disconnected or no job
                if (!stratum.connected.load()) {
                    stratum.disconnect();
                    ui.node_reachable.store(false);
                }
            }

            stratum.disconnect();
            std::fprintf(stderr, "[pool] Pool mining stopped.\n");
            std::fprintf(stderr, "[pool] Final stats - Submitted: %llu, Accepted: %llu, Rejected: %llu\n",
                        (unsigned long long)ui.shares_submitted.load(),
                        (unsigned long long)ui.shares_accepted.load(),
                        (unsigned long long)ui.shares_rejected.load());
        }
        // ===== SOLO MINING LOOP =====
        else {
            // ===== mining loop with periodic refresh (prevents stale templates)
            std::fprintf(stderr, "[miner] starting solo mining loop (one job per tip; clean shutdown).\n");

            std::string last_job_prev_hex;
            bool was_disconnected = false;
            int reconnect_backoff_ms = 2000;  // Start with 2 second backoff
            const int kMinBackoffMs = 2000;
            const int kMaxBackoffMs = 30000;   // Max 30 seconds between reconnect attempts
            while (ui.running.load()) {
                MinerTemplate tpl;
            if (!rpc_getminertemplate(rpc_host, rpc_port, token, tpl)) {
                ui.node_reachable.store(false);
                std::ostringstream m;
                m << C("31;1") << "*** RPC CONNECTION LOST *** "
                  << "Node not responding at " << rpc_host << ":" << rpc_port << " - Retrying in "
                  << (reconnect_backoff_ms/1000) << "s..." << R();
                { std::lock_guard<std::mutex> lk(ui.mtx); ui.last_submit_msg = m.str(); ui.last_submit_when = std::chrono::steady_clock::now(); }

                // Only log connection lost message periodically to avoid spam (once every 30 seconds)
                static auto last_lost_log = std::chrono::steady_clock::now();
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_lost_log).count();
                if(!was_disconnected || elapsed >= 30){
                    log_line("RPC connection lost: node not responding at " + rpc_host + ":" + std::to_string(rpc_port));
                    last_lost_log = now;
                }
                was_disconnected = true;

                // PRODUCTION FIX: Exponential backoff to prevent flooding the server
                // Start at 2s, double each time up to 30s max
                for(int i=0; i < reconnect_backoff_ms/50 && ui.running.load(); ++i){
                    miq_sleep_ms(50);
                }
                reconnect_backoff_ms = std::min(kMaxBackoffMs, reconnect_backoff_ms * 3 / 2);  // 1.5x increase
                continue;
            }

            // Successfully got template - node is reachable
            ui.node_reachable.store(true);

            // PRODUCTION FIX: Reset backoff on successful connection
            reconnect_backoff_ms = kMinBackoffMs;

            // Debug: Log when connection is restored after a failure
            if (was_disconnected) {
                std::ostringstream m;
                m << C("32;1") << "*** RPC CONNECTION RESTORED *** "
                  << "Successfully reconnected to " << rpc_host << ":" << rpc_port << R();
                { std::lock_guard<std::mutex> lk(ui.mtx); ui.last_submit_msg = m.str(); ui.last_submit_when = std::chrono::steady_clock::now(); }
                log_line("RPC connection restored: successfully reconnected to " + rpc_host + ":" + std::to_string(rpc_port));
                std::fprintf(stderr, "[miner] RPC connection restored to %s:%u\n", rpc_host.c_str(), rpc_port);
                was_disconnected = false;
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
                    msg << C("36;1") << "New Mining Job | "
                        << "Height: " << tpl.height
                        << " | Diff: " << std::fixed << std::setprecision(2) << difficulty_from_bits(tpl.bits)
                        << " | TXs: " << ui.cand.txs << R();
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
                // FIXED: Use 8-byte time to match main miner format (80 bytes total)
                std::vector<uint8_t> prefix80 =
                    [&](){
                        std::vector<uint8_t> p;
                        p.reserve(80);  // 4+32+32+8+4 = 80
                        put_u32_le(p, b.header.version);
                        p.insert(p.end(), b.header.prev_hash.begin(), b.header.prev_hash.end());
                        p.insert(p.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
                        put_u64_le(p, (uint64_t)b.header.time);  // 8 bytes
                        put_u32_le(p, b.header.bits);
                        return p;
                    }();
                std::vector<uint8_t> gpuprefix;
                if(salt_pos == SaltPos::PRE && !salt_bytes.empty()){
                    gpuprefix.reserve(salt_bytes.size()+prefix80.size());
                    gpuprefix.insert(gpuprefix.end(), salt_bytes.begin(), salt_bytes.end());
                    gpuprefix.insert(gpuprefix.end(), prefix80.begin(), prefix80.end());
                } else if(salt_pos == SaltPos::POST && !salt_bytes.empty()){
                    gpuprefix.reserve(prefix80.size()+salt_bytes.size());
                    gpuprefix.insert(gpuprefix.end(), prefix80.begin(), prefix80.end());
                    gpuprefix.insert(gpuprefix.end(), salt_bytes.begin(), salt_bytes.end());
                } else {
                    gpuprefix = prefix80;
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
                // Template refresh timeout: abort round after 30 seconds to get fresh template
                // This ensures timestamps stay valid and new transactions can be included
                const int kTemplateRefreshMs = 30000;
                // PRODUCTION FIX: Adaptive polling with exponential backoff on server overload
                int poll_interval_ms = 1500;  // Start at 1.5 seconds
                const int kMinPollIntervalMs = 1500;
                const int kMaxPollIntervalMs = 10000;  // Max 10 seconds between polls
                auto round_start = std::chrono::steady_clock::now();
                int consecutive_failures = 0;
                int consecutive_503s = 0;

                while(!found.load(std::memory_order_relaxed) && ui.running.load()){
                    // Check for timeout - force template refresh periodically
                    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - round_start).count();
                    if(elapsed >= kTemplateRefreshMs){
                        abort_round.store(true);
                        break;
                    }

                    // PRODUCTION FIX: Use lightweight tip check with SHORT timeout
                    // Single quick attempt - fail fast for stale checks
                    HttpResp r;
                    bool got_tip = false;
                    bool is_server_overloaded = false;

                    if(http_post_fast(rpc_host, rpc_port, "/", token, rpc_build("gettipinfo","[]"), r, 5000)){
                        if(r.code == 200){
                            TipInfo tip_now{};
                            long long h=0; uint32_t b=0; std::string hh;
                            if (json_find_number(r.body,"height",h) &&
                                json_find_string(r.body,"hash",hh) &&
                                json_find_hex_or_number_u32(r.body,"bits",b)) {
                                tip_now.height = (uint64_t)h;
                                tip_now.hash_hex = hh;
                                tip_now.bits = b;
                                got_tip = true;
                                consecutive_failures = 0;
                                consecutive_503s = 0;
                                // PRODUCTION FIX: Gradually reduce poll interval on success
                                poll_interval_ms = std::max(kMinPollIntervalMs, poll_interval_ms - 200);

                                // Check if tip has changed (new block found by network)
                                if(from_hex_s(tip_now.hash_hex) != tpl.prev_hash){
                                    abort_round.store(true);
                                    break;
                                }
                            }
                        } else if(r.code == 503){
                            // Server overloaded - back off aggressively
                            is_server_overloaded = true;
                            consecutive_503s++;
                        }
                    }

                    // PRODUCTION FIX: Adaptive throttling based on server health
                    if(!got_tip){
                        consecutive_failures++;

                        if(is_server_overloaded){
                            // Server returned 503 - exponential backoff
                            poll_interval_ms = std::min(kMaxPollIntervalMs,
                                kMinPollIntervalMs + (consecutive_503s * 1500));
                            // Extra backoff for severe overload
                            if(consecutive_503s >= 3){
                                int backoff_ms = std::min(5000, consecutive_503s * 1000);
                                for(int i=0; i < backoff_ms/50 && !found.load(std::memory_order_relaxed) &&
                                    !abort_round.load(std::memory_order_relaxed) && ui.running.load(); ++i){
                                    miq_sleep_ms(50);
                                }
                            }
                        } else if(consecutive_failures >= 5){
                            // Network issues - moderate backoff
                            poll_interval_ms = std::min(kMaxPollIntervalMs, poll_interval_ms + 500);
                            for(int i=0; i<40 && !found.load(std::memory_order_relaxed) &&
                                !abort_round.load(std::memory_order_relaxed) && ui.running.load(); ++i){
                                miq_sleep_ms(50);
                            }
                        }
                    }

                    // Sleep for adaptive polling interval (chunked for responsive shutdown)
                    for(int i=0; i < poll_interval_ms/50 && !found.load(std::memory_order_relaxed) &&
                        !abort_round.load(std::memory_order_relaxed) && ui.running.load(); ++i){
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
            // CRITICAL FIX: Use fast variant for quick staleness check before submission
            TipInfo tip_now{};
            if (rpc_gettipinfo_fast(rpc_host, rpc_port, token, tip_now)) {
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
                // PRODUCTION FIX: Use rpc_gettipinfo_fast to prevent connection flood
                // Reduced iterations from 40 to 20, increased delay from 100ms to 250ms
                // This gives 5 seconds total confirmation window with only 20 max connections
                bool confirmed = false;
                for (int i = 0; i < 20 && ui.running.load(); ++i) {
                    TipInfo t2{};
                    if (rpc_gettipinfo_fast(rpc_host, rpc_port, token, t2)) {
                        if (t2.height == tpl.height &&
                            t2.hash_hex == miq::to_hex(found_block.block_hash())) {
                            confirmed = true;
                            break;
                        }
                    }
                    // PRODUCTION FIX: Longer delay between confirmation checks
                    miq_sleep_ms(250);
                }

                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                    if (confirmed) {
                        ui.mined_blocks.fetch_add(1);
                        std::ostringstream m; m << C("32;1") << "*** BLOCK FOUND & ACCEPTED *** "
                                                << "Height: " << tpl.height << " | Hash: "
                                                << ui.last_found_block_hash.substr(0, 16) << "..." << R();
                        ui.last_submit_msg = m.str();
                        ui.last_tip_was_mine.store(true);
                        ui.last_winner_addr.clear();
                        rpc_minerlog_best_effort(
                            rpc_host, rpc_port, token,
                            std::string("miner: accepted block at height ")
                            + std::to_string(tpl.height) + " " + ui.last_found_block_hash
                        );
                        log_line("*** BLOCK FOUND & ACCEPTED *** height="+std::to_string(tpl.height)+" hash="+ui.last_found_block_hash);
                    } else {
                        std::ostringstream m; m << C("33;1")
                                                << "Block submitted (confirming...) | Hash: "
                                                << ui.last_found_block_hash.substr(0, 16) << "..." << R();
                        ui.last_submit_msg = m.str();
                        log_line("block submitted (awaiting confirmation), hash="+ui.last_found_block_hash);
                    }
                    ui.last_submit_when = std::chrono::steady_clock::now();
                }
            } else {
                // Submission failed - log and add delay before retrying
                {
                    std::lock_guard<std::mutex> lk(ui.mtx);
                    std::ostringstream m; m << C("31;1") << "submit REJECTED / RPC failed" << R();
                    if (!err_body.empty()) {
                        std::string msg;
                        if (json_find_string(err_body, "error", msg)) m << ": " << msg;
                        else m << " body=" << err_body.substr(0, 200);
                    }
                    ui.last_submit_msg = m.str();
                    ui.last_submit_when = std::chrono::steady_clock::now();
                    log_line("submit rejected / rpc failed: " + err_body.substr(0, 200));
                }

                // CRITICAL: Delay before retrying to prevent spinning on same block
                // This gives the network time to propagate and prevents CPU burn
                for(int i = 0; i < 30 && ui.running.load(); ++i) miq_sleep_ms(100);

                // Increment RPC error counter for diagnostics
                ui.rpc_errors.fetch_add(1);
            }
        }
        } // end of solo mining else block

        // Final clear/exit
        std::cout << "\n" << C("33;1") << "Exiting " << MIQMINER_VERSION_STRING << "..." << R() << std::endl;
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
