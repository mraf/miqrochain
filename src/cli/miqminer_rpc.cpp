// src/cli/miqminer_rpc.cpp  — Professional RPC solo miner for Miqrochain
// - Pro terminal UI with stable metering, sparkline & clear status lines
// - Exact-consensus mining via getminertemplate (epoch bits)
// - High-priority worker threads, optional CPU affinity
// - Time-based EMA hashrate smoothing with per-thread cumulative counters
// - Clean RPC path; robust stale-template checks; detailed submit feedback
//
// Build target: miqminer_rpc
// Usage:
//   miqminer_rpc [--rpc=host:port] [--token=...] [--threads=N]
//                 [--address=Base58P2PKH] [--no-ansi]
//                 [--priority=high|normal] [--affinity=on|off]
//                 [--smooth=SECONDS]
// Notes:
//   - Token auto-loads from MIQ_RPC_TOKEN or datadir cookie if not provided.
//   - Default smoothing time-constant is 15s; increase for steadier H/s.
//
// (c) Miqrochain contributors

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
  #include <sched.h>
  using socket_t = int;
  #define miq_closesocket ::close
  static void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
#endif

using namespace miq;

// ===== small helpers =========================================================
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

// ===== tiny JSON helpers =====================================================
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

// ===== difficulty/target helpers ============================================
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

// ===== minimal HTTP/JSON-RPC =================================================
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

// submit helpers
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

// ===== miner template ========================================================
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

// ===== address helpers =======================================================
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

// ===== last-block info =======================================================
struct LastBlockInfo {
    uint64_t height{0};
    std::string hash_hex;
    uint64_t txs{0};
    std::string coinbase_txid_hex;
    std::vector<uint8_t> coinbase_pkh;
    uint64_t reward_value{0};
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
    if(json_find_number(r.body, "value", val)) io.reward_value = (uint64_t)val;
    if(json_find_string(r.body, "txid", txid_hex)) io.coinbase_txid_hex = txid_hex;
    io.coinbase_pkh = from_hex_s(pkh_hex);
    return true;
}

// ===== UI & metering =========================================================
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
    // totals/metering
    std::atomic<uint64_t> tries_total{0};   // session-wide total hashes
    std::atomic<uint64_t> mined_blocks{0};
    std::atomic<double>   net_hashps{0.0};

    // hashrate display (EMA smoothed)
    std::atomic<double>   hps_now{0.0};     // short-term EMA
    std::atomic<double>   hps_smooth{0.0};  // long-term EMA

    // tip
    std::atomic<uint64_t> tip_height{0};
    std::string tip_hash_hex;
    std::atomic<uint32_t> tip_bits{0};

    // candidate
    CandidateStats cand{};
    std::mutex mtx;

    // last network block + last accepted
    LastBlockInfo lastblk{};
    std::string last_found_block_hash;    // set only on accepted
    std::string last_submit_msg;          // transient status
    std::chrono::steady_clock::time_point last_submit_when{};

    // sparkline buffer (last 48 samples ~ display-only)
    std::mutex spark_mtx;
    std::vector<double> sparkline; // newest at back
};
static std::string fmt_hs(double v){
    const char* u[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s"};
    int i=0; while(v>=1000.0 && i<5){ v/=1000.0; ++i; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i]; return o.str();
}
static std::string spark_from_series(const std::vector<double>& xs){
    static const char* bars = " ▁▂▃▄▅▆▇█";
    if(xs.empty()) return "";
    double mn=xs[0], mx=xs[0];
    for(double v: xs){ mn = std::min(mn,v); mx = std::max(mx,v); }
    double span = (mx>mn)? (mx-mn) : 1.0;
    std::string s;
    for(double v: xs){
        int idx = (int)std::round( (v-mn)/span * 7.0 );
        if(idx<0) idx=0; if(idx>7) idx=7;
        s.push_back(bars[idx]);
    }
    return s;
}

// ANSI helpers
static bool g_use_ansi = true;
static inline std::string C(const char* code){ return g_use_ansi ? std::string("\x1b[")+code+"m" : std::string(); }
static inline std::string R(){ return g_use_ansi ? std::string("\x1b[0m") : std::string(); }
static inline const char* CLS(){ return g_use_ansi ? "\x1b[2J\x1b[H" : ""; }

// draw loop
static void draw_ui_loop(const std::string& addr, unsigned threads, UIState* ui, const std::atomic<bool>* running){
    using clock = std::chrono::steady_clock;
    const int FPS = 12;
    const auto frame_dt = std::chrono::milliseconds(1000/FPS);
    size_t frame = 0;

    while(running->load(std::memory_order_relaxed)){
        std::ostringstream out;
        out << CLS();
        out << "  " << C("1") << "MIQ Miner (RPC)" << R() << "  —  address: " << addr << "     threads: " << threads << "\n\n";

        uint64_t th = ui->tip_height.load();
        if(th){
            out << "  tip height:      " << th << "\n";
            out << "  tip hash:        " << ui->tip_hash_hex << "  " << C("2") << "(last accepted)" << R() << "\n";
            uint32_t bits = ui->tip_bits.load();
            out << "  tip bits:        0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)bits
                << std::dec << "  (difficulty " << std::fixed << std::setprecision(2) << difficulty_from_bits(bits) << ")\n";
        } else {
            out << "  (waiting for template)\n";
        }

        {
            std::lock_guard<std::mutex> lk(ui->mtx);
            if(ui->cand.height){
                out << "\n";
                out << "  mining candidate:  height=" << ui->cand.height
                    << "  prev=" << ui->cand.prev_hex << "  " << C("2") << "(prev=tip)" << R() << "\n";
                out << "                     bits=0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)ui->cand.bits
                    << std::dec << "  (difficulty " << std::fixed << std::setprecision(2) << difficulty_from_bits(ui->cand.bits) << ")\n";
                out << "                     txs=" << ui->cand.txs
                    << "  size=" << ui->cand.size_bytes << " bytes"
                    << "  fees=" << ui->cand.fees
                    << "  coinbase=" << ui->cand.coinbase << "\n";
            }
        }

        if(ui->lastblk.height){
            const auto& lb = ui->lastblk;
            out << "\n";
            out << "  last block:       height=" << lb.height
                << "  hash=" << lb.hash_hex
                << "  txs=" << lb.txs << "\n";
            if(!lb.coinbase_txid_hex.empty())
                out << "                     coinbase_txid=" << lb.coinbase_txid_hex << "\n";
            if(!lb.coinbase_pkh.empty()){
                out << "                     paid to: " << pkh_to_address(lb.coinbase_pkh)
                    << "  (pkh=" << to_hex_s(lb.coinbase_pkh) << ", value=" << lb.reward_value << ")\n";
            }
        }

        out << "\n";
        out << "  local hashrate:   " << C("36") << fmt_hs(ui->hps_smooth.load()) << R()
            << "  " << C("2") << "(now " << fmt_hs(ui->hps_now.load()) << ")" << R() << "\n";
        out << "  network hashrate: " << fmt_hs(ui->net_hashps.load()) << "\n";
        out << "  mined (session):  " << ui->mined_blocks.load() << "\n";
        if(!ui->last_found_block_hash.empty())
            out << "  last found:       " << ui->last_found_block_hash << "  " << C("2") << "(accepted)" << R() << "\n";

        // transient submit status (5s)
        {
            auto age = std::chrono::duration<double>(clock::now() - ui->last_submit_when).count();
            if(!ui->last_submit_msg.empty() && age < 5.0){
                out << "  " << ui->last_submit_msg << "\n";
            }
        }

        // sparkline
        {
            std::lock_guard<std::mutex> lk(ui->spark_mtx);
            if(!ui->sparkline.empty()){
                out << "\n  h/s trend:        " << spark_from_series(ui->sparkline) << "\n";
            }
        }

        // small decorative frame
        out << "\n";
        static const char* box[8] = {
            "  ##############################",
            "  #                            #",
            "  #      MINING IN PROGRESS    #",
            "  #                            #",
            "  #         ▒▒▒▒▒▒▒▒           #",
            "  #                            #",
            "  #                            #",
            "  ##############################",
        };
        for(auto& L: box) out << "  " << C("36") << L << R() << "\n";

        out << "\n  Press Ctrl+C to quit.\n";

        std::cout << out.str() << std::flush;
        std::this_thread::sleep_for(frame_dt);
        (void)frame++;
    }
}

// ===== Platform priority/affinity ===========================================
static void set_process_priority(bool high){
#if defined(_WIN32)
    if(high) SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    else     SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
#else
    if(high){
        // best effort: negative nice improves priority
        setpriority(PRIO_PROCESS, 0, -10);
    }
#endif
}
static void pin_thread_to_cpu(unsigned tid){
#if defined(_WIN32)
    // pin to logical CPU (best-effort)
    DWORD_PTR mask = (DWORD_PTR)1 << (tid % (8*sizeof(DWORD_PTR)));
    SetThreadAffinityMask(GetCurrentThread(), mask);
#else
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(tid % CPU_SETSIZE, &set);
    sched_setaffinity(0, sizeof(set), &set);
#endif
}

// ===== mining worker =========================================================
// Each worker writes to a per-thread cumulative counter; the meter thread reads sums.
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
    b.header.merkle_root = merkle_from(b.txs); // fixed per candidate

    // Build header prefix: 4|32|32|8|4
    std::vector<uint8_t> header_prefix;
    header_prefix.reserve(4+32+32+8+4);
    put_u32_le(header_prefix, b.header.version);
    header_prefix.insert(header_prefix.end(), b.header.prev_hash.begin(),   b.header.prev_hash.end());
    header_prefix.insert(header_prefix.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
    put_u64_le(header_prefix, (uint64_t)b.header.time);
    put_u32_le(header_prefix, b.header.bits);
    const size_t nonce_off = header_prefix.size();

    // Target
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

    const uint64_t BATCH = (1ull<<15); // 32768 attempts per outer loop
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

            local_hashes += 8;
            todo = (todo>=8)? (todo-8) : 0;

            // light-touch publishing to reduce jitter in metering
            if((local_hashes & ((1u<<12)-1)) == 0){ // every 4096 hashes
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

// ===== tx packer (size-first) ===============================================
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
    "miqminer_rpc — Professional solo miner for MIQ (RPC)\n"
    "Usage:\n"
    "  miqminer_rpc [--rpc=host:port] [--token=TOKEN] [--threads=N]\n"
    "               [--address=Base58P2PKH] [--no-ansi]\n"
    "               [--priority=high|normal] [--affinity=on|off]\n"
    "               [--smooth=SECONDS]\n"
    "Notes:\n"
    "  - Token from --token, MIQ_RPC_TOKEN, or datadir/.cookie\n"
    "  - Default smoothing: 15s   (use --smooth=30 for extra stable H/s)\n";
}

// ===== main ==================================================================
int main(int argc, char** argv){
    try{
#if defined(_WIN32)
        // enable ANSI if available
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004);
        }
#endif
        std::string rpc_host = "127.0.0.1";
        uint16_t    rpc_port = (uint16_t)miq::RPC_PORT;
        std::string token;
        unsigned threads = std::max(1u, std::thread::hardware_concurrency());
        std::string address_cli;
        bool pin_affinity = false;
        bool high_priority = false;
        double smooth_seconds = 15.0;

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

        // Address input
        std::string addr = address_cli;
        if(addr.empty()){
            std::cout << "Enter P2PKH Base58 address to mine to: ";
            if(!std::getline(std::cin, addr)){ std::fprintf(stderr,"stdin closed\n"); return 1; }
            trim(addr);
        }
        std::vector<uint8_t> pkh;
        if(!parse_p2pkh(addr, pkh)){
            std::fprintf(stderr,"Invalid address (expected Base58Check P2PKH, version 0x%02x)\n",(unsigned)miq::VERSION_P2PKH);
            return 1;
        }

        // UI + global state
        UIState ui;
        std::atomic<bool> running{true};
        std::thread ui_th([&](){ draw_ui_loop(addr, threads, &ui, &running); });
        ui_th.detach();

        // watch tip + network hps + last block
        std::thread watch([&](){
            uint64_t last_seen_h = 0;
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
                        }
                        last_seen_h = t.height;
                    }
                }
                for(int i=0;i<10;i++) miq_sleep_ms(100); // ~1s
            }
        });
        watch.detach();

        // per-thread cumulative counters live across all candidates (monotonic)
        std::vector<ThreadCounter> thr_counts(threads);
        for(auto& c: thr_counts) c.hashes.store(0);

        // metering thread (time-constant EMA: alpha = 1 - exp(-dt/τ))
        std::thread meter([&](){
            using clock = std::chrono::steady_clock;
            auto last = clock::now();
            uint64_t last_sum = 0;
            std::vector<double> spark;
            spark.reserve(64);

            // initialize smooth to 0; it will converge
            double ema_now = 0.0;
            double ema_smooth = 0.0;

            while(running.load()){
                // sum per-thread counters
                uint64_t sum = 0;
                for(auto& c: thr_counts) sum += c.hashes.load(std::memory_order_relaxed);

                auto now = clock::now();
                double dt = std::chrono::duration<double>(now - last).count();
                if(dt <= 0.0) { dt = 1e-3; }

                uint64_t delta = (sum >= last_sum) ? (sum - last_sum) : sum; // handle wrap/reset safely
                double hps = (double)delta / dt;

                // two-tier EMA (fast + slow)
                double alpha_now    = 1.0 - std::exp(-dt / std::max(0.5, smooth_seconds*0.25)); // faster
                double alpha_smooth = 1.0 - std::exp(-dt / std::max(1.0, smooth_seconds));      // main τ

                ema_now    = ema_now*(1.0-alpha_now)     + hps*alpha_now;
                ema_smooth = ema_smooth*(1.0-alpha_smooth)+ hps*alpha_smooth;

                ui.hps_now.store(ema_now);
                ui.hps_smooth.store(ema_smooth);

                // session total
                uint64_t total = ui.tries_total.load();
                ui.tries_total.store(total + delta);

                // sparkline (48 samples, ~3–5s history depending on cadence)
                {
                    std::lock_guard<std::mutex> lk(ui.spark_mtx);
                    ui.sparkline.push_back(ema_smooth);
                    if(ui.sparkline.size() > 48) ui.sparkline.erase(ui.sparkline.begin());
                }

                last_sum = sum; last = now;
                std::this_thread::sleep_for(std::chrono::milliseconds(200));
            }
        });
        meter.detach();

        // ===== mining loop (template → build → mine → submit) =====
        while(true){
            // template
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
            pack_template(tpl, coinbase_sz, txs, used_bytes, used_bytes); // output bytes twice? keep consistent
            fees = 0; for (auto& xt : tpl.txs) fees += xt.fee;

            Transaction cb = make_coinbase(tpl.height, fees, pkh);
            std::vector<Transaction> txs_inc; txs_inc.reserve(1+txs.size());
            txs_inc.push_back(cb);
            for(auto& t: txs) txs_inc.push_back(std::move(t));

            // publish candidate stats
            {
                std::lock_guard<std::mutex> lk(ui.mtx);
                ui.cand.height = tpl.height;
                ui.cand.prev_hex = to_hex_s(tpl.prev_hash);
                ui.cand.bits = tpl.bits;        // exact bits to mine with
                ui.cand.time = tpl.time;
                ui.cand.txs = txs_inc.size();
                ui.cand.size_bytes = used_bytes + ser_tx(cb).size();
                ui.cand.fees = fees;
                ui.cand.coinbase = GetBlockSubsidy((uint32_t)tpl.height) + fees;
            }

            // header base (nonce later)
            BlockHeader hb;
            hb.version = 1;
            hb.prev_hash = tpl.prev_hash;
            hb.time = std::max<int64_t>((int64_t)time(nullptr), tpl.time);
            hb.bits = tpl.bits;   // authoritative
            hb.nonce = 0;

            // Mine
            std::atomic<bool> found{false};
            std::vector<std::thread> thv;
            Block found_block;

            for(unsigned tid=0; tid<threads; ++tid){
                thv.emplace_back(
                    mine_worker_optimized, hb, txs_inc, hb.bits,
                    &found, &thr_counts[tid], pin_affinity, tid, threads, &found_block
                );
            }

            for(auto& th: thv) th.join();

            // Stale check
            TipInfo tip_now{};
            if(rpc_gettipinfo(rpc_host, rpc_port, token, tip_now)){
                if(from_hex_s(tip_now.hash_hex) != tpl.prev_hash){
                    {
                        std::lock_guard<std::mutex> lk(ui.mtx);
                        ui.last_submit_msg = "submit skipped: template stale (chain advanced)";
                        ui.last_submit_when = std::chrono::steady_clock::now();
                    }
                    continue;
                }
            }

            // safety: check target match
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
                for(int i=0;i<40;i++){ // ~4s
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
                        std::ostringstream m; m << "submit accepted @ height=" << tpl.height
                                                << " hash=" << ui.last_found_block_hash;
                        ui.last_submit_msg = m.str();
                    }else{
                        ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                        std::ostringstream m; m << "submit accepted (pending tip refresh) hash=" << ui.last_found_block_hash;
                        ui.last_submit_msg = m.str();
                    }
                    ui.last_submit_when = std::chrono::steady_clock::now();
                }
            } else {
                std::lock_guard<std::mutex> lk(ui.mtx);
                std::ostringstream m; m << "submit REJECTED / RPC failed";
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
