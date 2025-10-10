// miqminer_rpc.cpp — mainnet-grade solo miner (JSON-RPC), fee-aware, non-empty blocks
// Shows live chain/tip/last-block details + who got paid (coinbase recipient).
// Requires node RPCs: getminertemplate, gettipinfo, getblock, getcoinbaserecipient, getblockcount, getblockhash
//
// Build (GCC/Clang):
//   g++ -std=c++17 -O3 -DNDEBUG -march=native -mtune=native -fno-exceptions -fno-rtti miqminer_rpc.cpp -o miqminer_rpc
//
// Build (MSVC Developer Prompt):
//   cl /std:c++17 /O2 /GL /DNDEBUG miqminer_rpc.cpp ws2_32.lib
//
// Runtime:
//   ./miqminer_rpc --threads=8 --rpc=127.0.0.1:8332
//   (token auto-loaded from MIQ_RPC_TOKEN or datadir .cookie; you can also pass --token=...)
//

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
#include <condition_variable>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <map>
#include <set>
#include <cmath>

#if defined(_WIN32)
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
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
  using socket_t = int;
  #define miq_closesocket ::close
  static void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
#endif

using namespace miq;

// -------- small utils --------------------------------------------------------
static inline std::string lc(std::string s){ for(char& c: s) c=(char)std::tolower((unsigned char)c); return s; }
static inline void trim(std::string& s){
    size_t i=0,j=s.size();
    while(i<j && std::isspace((unsigned char)s[i])) ++i;
    while(j>i && std::isspace((unsigned char)s[j-1])) --j;
    s.assign(s.data()+i, j-i);
}

static std::string default_cookie_path(){
#ifdef _WIN32
    // %APPDATA%\Miqrochain\.cookie
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
    std::string s;
    char buf[4096];
    while(true){
        size_t n = fread(buf,1,sizeof(buf),f);
        if(n==0) break;
        s.append(buf,n);
    }
    fclose(f);
    while(!s.empty() && (s.back()=='\r'||s.back()=='\n'||s.back()==' '||s.back()=='\t')) s.pop_back();
    out = std::move(s);
    return true;
}

static std::string to_hex_s(const std::vector<uint8_t>& v){ return miq::to_hex(v); }
static std::vector<uint8_t> from_hex_s(const std::string& h){ return miq::from_hex(h); }

// === target compare (same as node) ===========================================
static void bits_to_target_be(uint32_t bits, uint8_t out[32]) {
    std::memset(out, 0, 32);
    const uint32_t exp = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;
    if (mant == 0) return;
    if (exp <= 3) {
        uint32_t mant2 = mant >> (8 * (3 - exp));
        out[29] = uint8_t((mant2 >> 16) & 0xff);
        out[30] = uint8_t((mant2 >>  8) & 0xff);
        out[31] = uint8_t((mant2 >>  0) & 0xff);
    } else {
        int pos = int(32) - int(exp);
        if (pos < 0) { out[0]=out[1]=out[2]=0xff; return; }
        if (pos > 29) pos = 29;
        out[pos+0] = uint8_t((mant >> 16) & 0xff);
        out[pos+1] = uint8_t((mant >>  8) & 0xff);
        out[pos+2] = uint8_t((mant >>  0) & 0xff);
    }
}
static inline bool meets_target_be(const std::vector<uint8_t>& hash32, uint32_t bits) {
    if (hash32.size() != 32) return false;
    uint8_t target[32]; bits_to_target_be(bits, target);
    return std::memcmp(hash32.data(), target, 32) <= 0;
}

// === simple HTTP client ======================================================

struct HttpResp { int code{0}; std::string body; };

static bool http_post(const std::string& host, uint16_t port,
                      const std::string& path,
                      const std::string& auth_header,
                      const std::string& json,
                      HttpResp& out)
{
#if defined(_WIN32)
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    // resolve
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    addrinfo* res=nullptr; char ps[16]; std::snprintf(ps,sizeof(ps), "%u", (unsigned)port);
    if(getaddrinfo(host.c_str(), ps, &hints, &res)!=0) {
#if defined(_WIN32)
        WSACleanup();
#endif
        return false;
    }

    socket_t s = (socket_t)(~(socket_t)0);
    for(addrinfo* ai=res; ai; ai=ai->ai_next){
        s = (socket_t)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#if defined(_WIN32)
        if(s==INVALID_SOCKET) continue;
#else
        if(s<0) continue;
#endif
        if(connect(s, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0) { break; }
        miq_closesocket(s);
#if defined(_WIN32)
        s = INVALID_SOCKET;
#else
        s = -1;
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
    if(!auth_header.empty()) req << "X-Auth-Token: " << auth_header << "\r\n"
                                 << "Authorization: Bearer " << auth_header << "\r\n";
    req << "Connection: close\r\n\r\n" << json;

    std::string data = req.str();
    size_t off=0;
    while(off < data.size()){
#if defined(_WIN32)
        int n = send(s, data.data()+off, (int)(data.size()-off), 0);
#else
        int n = ::send(s, data.data()+off, (int)(data.size()-off), 0);
#endif
        if(n<=0) { miq_closesocket(s); 
#if defined(_WIN32)
            WSACleanup();
#endif
            return false; }
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

    // parse very lightly
    size_t sp = resp.find(' ');
    if(sp == std::string::npos) return false;
    int code = std::atoi(resp.c_str()+sp+1);
    size_t hdr_end = resp.find("\r\n\r\n");
    std::string body = (hdr_end==std::string::npos)? std::string() : resp.substr(hdr_end+4);
    out.code = code; out.body = std::move(body);
    return true;
}

// Minimal JSON helpers (good enough for fixed-shaped RPC)
static std::string json_escape(const std::string& s){
    std::ostringstream o; o << '"';
    for(unsigned char c : s){
        if(c=='"'||c=='\\') { o << '\\' << c; }
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
static bool json_has_error(const std::string& json){
    // Very light check for error field without result
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
    if(q==std::string::npos || q<=p) return false;
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
    while(q<json.size() && (std::isdigit((unsigned char)json[q])||json[q]=='-'||json[q]=='+'||json[q]=='.'||json[q]=='e'||json[q]=='E')) ++q;
    if(q==p) return false;
    out = std::strtod(json.c_str()+p, nullptr);
    return true;
}

// === RPC wrappers ============================================================

struct TipInfo { uint64_t height{0}; std::string hash_hex; uint32_t bits{0}; int64_t time{0}; };

static bool rpc_gettipinfo(const std::string& host, uint16_t port, const std::string& auth, TipInfo& out){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("gettipinfo", "[]"), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    long long h=0, b=0, t=0; std::string hh;
    if(!json_find_number(r.body, "height", h)) return false;
    if(!json_find_string(r.body, "hash", hh)) return false;
    if(!json_find_number(r.body, "bits", b)) return false;
    if(!json_find_number(r.body, "time", t)) return false;
    out.height = (uint64_t)h; out.hash_hex = hh; out.bits = (uint32_t)b; out.time = (int64_t)t;
    return true;
}

static bool rpc_submitblock_try(const std::string& host, uint16_t port, const std::string& auth,
                                const char* method, const std::string& hexblk)
{
    std::ostringstream ps; ps << "[\"" << hexblk << "\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build(method, ps.str()), r)) return false;
    if(r.code != 200) return false;
    return !json_has_error(r.body);
}
static bool rpc_submitblock(const std::string& host, uint16_t port, const std::string& auth, const std::string& hexblk){
    // Try a few common method names
    if(rpc_submitblock_try(host,port,auth,"submitblock",hexblk)) return true;
    if(rpc_submitblock_try(host,port,auth,"submitrawblock",hexblk)) return true;
    if(rpc_submitblock_try(host,port,auth,"sendrawblock",hexblk)) return true;
    return false;
}

static bool rpc_getminerstats(const std::string& host, uint16_t port, const std::string& auth, double& out_net_hs){
    // Prefer direct if node provides (optional)
    HttpResp r;
    if(http_post(host, port, "/", auth, rpc_build("getminerstats","[]"), r) && r.code==200 && !json_has_error(r.body)){
        if(json_find_double(r.body, "network_hash_ps", out_net_hs)) return true;
    }
    return false;
}

// ---- miner template ----
struct TxTpl {
    std::string id;
    std::string hex;
    uint64_t fee{0};
    std::vector<std::string> deps;
};
struct MinerTemplate {
    uint64_t height{0};
    std::vector<uint8_t> prev_hash;
    uint32_t bits{0};
    int64_t  time{0};
    size_t   max_block_bytes{900*1024};
    std::vector<TxTpl> txs;
};

static bool parse_dep_list(const std::string& json, size_t start, std::vector<std::string>& out){
    // expects json[start] == '['
    size_t i = start;
    if(i>=json.size() || json[i]!='[') return false;
    ++i;
    while(i<json.size()){
        while(i<json.size() && std::isspace((unsigned char)json[i])) ++i;
        if(i>=json.size()) return false;
        if(json[i]==']'){ ++i; return true; }
        if(json[i]!='"') return false;
        size_t j = json.find('"', i+1);
        if(j==std::string::npos) return false;
        out.push_back(json.substr(i+1, j-(i+1)));
        i = j+1;
        while(i<json.size() && std::isspace((unsigned char)json[i])) ++i;
        if(i<json.size() && json[i]==','){ ++i; continue; }
    }
    return false;
}

static bool rpc_getminertemplate(const std::string& host, uint16_t port, const std::string& auth, MinerTemplate& out){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getminertemplate","[]"), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;

    long long h=0, b=0, t=0, maxb=0; std::string ph;
    if(!json_find_number(r.body, "height", h)) return false;
    if(!json_find_string(r.body, "prev_hash", ph)) return false;
    if(!json_find_number(r.body, "bits", b)) return false;
    if(!json_find_number(r.body, "time", t)) return false;
    if(json_find_number(r.body, "max_block_bytes", maxb)) out.max_block_bytes = (size_t)maxb;
    out.height = (uint64_t)h; out.prev_hash = from_hex_s(ph); out.bits=(uint32_t)b; out.time=(int64_t)t;
    if(out.prev_hash.size()!=32) return false;

    // Extract txs array region
    size_t p = r.body.find("\"txs\"");
    if(p==std::string::npos) return true; // allowed: no txs
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

    // Scan objects in array (look for {"hex": ...})
    size_t pos = 0;
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

        TxTpl x;
        json_find_string(obj, "id",  x.id);
        json_find_string(obj, "hex", x.hex);
        long long fee=0; json_find_number(obj, "fee", fee); x.fee = (uint64_t)(fee<0?0:fee);

        size_t dp = obj.find("\"depends\"");
        if(dp != std::string::npos){
            size_t br = obj.find('[', dp);
            if(br != std::string::npos){
                std::vector<std::string> deps;
                if(parse_dep_list(obj, br, deps)) x.deps = std::move(deps);
            }
        }
        if(!x.hex.empty() && !x.id.empty())
            out.txs.push_back(std::move(x));
        pos = oe;
    }
    return true;
}

// fallbacks to estimate network hashrate: look back N blocks and use difficulty & spacing
static bool rpc_getblockcount(const std::string& host, uint16_t port, const std::string& auth, long long& out){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblockcount","[]"), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    return json_find_number(r.body, "result", out);
}
static bool rpc_getblockhash(const std::string& host, uint16_t port, const std::string& auth, uint64_t height, std::string& out){
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblockhash", ps.str()), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    return json_find_string(r.body, "result", out);
}
static bool rpc_getblock_header_time(const std::string& host, uint16_t port, const std::string& auth, const std::string& hh, long long& out_time){
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    long long t=0;
    if(json_find_number(r.body, "time", t)) { out_time=t; return true; }
    size_t ph = r.body.find("\"header\"");
    if(ph != std::string::npos && json_find_number(r.body.substr(ph), "time", t)) { out_time=t; return true; }
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

    auto work_from_bits = [](uint32_t bits)->long double {
        uint32_t exp  = bits >> 24;
        uint32_t mant = bits & 0x007fffff;
        if (mant == 0) return 0.0L;
        uint32_t bexp  = miq::GENESIS_BITS >> 24;
        uint32_t bmant = miq::GENESIS_BITS & 0x007fffff;
        long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
        long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
        if (target <= 0.0L) return 0.0L;
        long double D = base_target / target;
        if (D < 0.0L) D = 0.0L;
        return D;
    };

    long double D = work_from_bits(bits);
    double blocks = (double)(tip_height - start_h);
    double avg_spacing = dt / std::max(1.0, blocks);
    if (avg_spacing <= 0.0) return 0.0;
    const double two32 = 4294967296.0;
    return (double)D * (two32 / avg_spacing);
}

// === block assembly helpers ==================================================

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

static Transaction make_coinbase(uint64_t height, uint64_t fees, const std::vector<uint8_t>& pkh){
    Transaction cbt;
    // vin: null prev
    TxIn in; in.prev.txid = std::vector<uint8_t>(32,0); in.prev.vout = 0;

    // uniqueness tag (height, time, random)
    uint64_t rnd = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    uint32_t now = (uint32_t)time(nullptr);
    std::vector<uint8_t> tag; tag.reserve(1+4+4+8);
    tag.push_back(0x01);
    for(int i=0;i<4;i++) tag.push_back(uint8_t((height>>(8*i))&0xff));
    for(int i=0;i<4;i++) tag.push_back(uint8_t((now   >>(8*i))&0xff));
    for(int i=0;i<8;i++) tag.push_back(uint8_t((rnd   >>(8*i))&0xff));
    in.sig = std::move(tag);
    cbt.vin.push_back(in);

    // vout: subsidy + fees
    TxOut out; out.value = GetBlockSubsidy((uint32_t)height) + fees; out.pkh = pkh;
    cbt.vout.push_back(out);

    // lock_time hint (optional)
    cbt.lock_time = (uint32_t)height;
    return cbt;
}

static std::vector<uint8_t> merkle_from(const std::vector<Transaction>& txs){
    std::vector<std::vector<uint8_t>> ids; ids.reserve(txs.size());
    for(const auto& t : txs) ids.push_back(t.txid());
    return miq::merkle_root(ids);
}

// === extra RPCs for last-block detail ========================================

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

// === UI (cyan “3D block” + stats) ===========================================

static std::vector<std::string> make_block_art(uint64_t frame){
    static const char* frames[4][7] = {
      {
        "    _______        ",
        "   / ____ /\\       ",
        "  / /___/ / \\      ",
        " / /___/ /\\  \\     ",
        "/_______/ /\\  \\    ",
        "\\_______\\ \\ \\  \\   ",
        " \\_______\\_\\ \\__\\  "
      },{
        "    _______        ",
        "   / ____ /\\       ",
        "  / /___/ / \\      ",
        " / /___/ /  /      ",
        "/_______/  /       ",
        "\\_______\\ /        ",
        " \\_______\\         "
      },{
        "  _______          ",
        " /\\ ____ \\         ",
        "/ / /___\\ \\        ",
        "\\ \\ \\___/ /        ",
        " \\ \\_____\\ \\       ",
        "  \\/_____/ /       ",
        "         \\/        "
      },{
        "  _______          ",
        " /\\ ____ \\         ",
        "/ / /___\\ \\        ",
        "\\ \\ \\___/ /\\       ",
        " \\ \\_____\\ \\ \\     ",
        "  \\/_____/ / /     ",
        "          \\/      "
      }
    };
    uint64_t f = frame & 3;
    return std::vector<std::string>(frames[f], frames[f]+7);
}

struct UIState {
    std::atomic<uint64_t> hash_tries{0};
    std::atomic<uint64_t> last_hash_tries{0};
    std::atomic<uint64_t> mined_blocks{0};
    std::atomic<double>   net_hashps{0.0};
    std::string last_found_block_hash;
    std::mutex  mtx;

    // chain/tip/last-block info
    std::atomic<uint64_t> tip_height{0};
    std::string tip_hash_hex;
    std::atomic<uint32_t> tip_bits{0};
    LastBlockInfo lastblk{};
};

static void draw_ui_loop(const std::string& addr, unsigned threads, UIState* ui, const std::atomic<bool>* running)
{
    using namespace std::chrono;
    uint64_t frame = 0;
    while(running->load(std::memory_order_relaxed)){
        uint64_t tries = ui->hash_tries.load();
        uint64_t last  = ui->last_hash_tries.exchange(tries);
        double inst = (double)(tries - last) / 1.0; // ~1s
        double net  = ui->net_hashps.load();
        uint64_t mined = ui->mined_blocks.load();

        std::ostringstream os;
        os << "\x1b[2J\x1b[H"; // clear screen
        os << "  \x1b[1mMIQ Miner (RPC)\x1b[0m  —  address: " << addr
           << "     threads: " << threads << "\n\n";

        uint64_t th = ui->tip_height.load();
        if(th>0){
            os << "  tip height:  " << th << "\n";
            os << "  tip hash:    " << ui->tip_hash_hex << "\n";
            os << "  tip bits:    0x" << std::hex << std::setw(8) << std::setfill('0')
               << (unsigned)ui->tip_bits.load() << std::dec << "\n";
        } else {
            os << "  (waiting for template)\n";
        }

        // Last network block (who mined it)
        if(ui->lastblk.height){
            const auto& lb = ui->lastblk;
            os << "\n";
            os << "  last block:  height=" << lb.height
               << "  hash=" << lb.hash_hex
               << "  txs=" << lb.txs << "\n";
            if(!lb.coinbase_txid_hex.empty()){
                os << "               coinbase_txid=" << lb.coinbase_txid_hex << "\n";
            }
            if(!lb.coinbase_pkh.empty()){
                std::string addrR = pkh_to_address(lb.coinbase_pkh);
                os << "               paid to: " << addrR
                   << "  (pkh=" << to_hex_s(lb.coinbase_pkh) << ")\n";
            }
        }

        auto fmt_hs = [](double v)->std::string{
            const char* u[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s"};
            int i=0; while(v>=1000.0 && i<5){ v/=1000.0; ++i; }
            std::ostringstream o; o<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i]; return o.str();
        };
        os << "\n";
        os << "  local hashrate:   " << fmt_hs(inst) << "\n";
        os << "  network hashrate: " << fmt_hs(net)  << "\n";
        os << "  mined (session):  " << mined << "\n";
        if(!ui->last_found_block_hash.empty()){
            os << "  last found:       " << ui->last_found_block_hash << "\n";
        }

        // Cyan 3D block on the right
        auto art = make_block_art(frame++);
        os << "\n";
        for(const auto& line : art){
            os << "  \x1b[36m" << line << "\x1b[0m\n";
        }

        os << "\n  Press Ctrl+C to quit.\n";

        std::cout << os.str() << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// === mining worker ===========================================================

static void nonce_worker(const BlockHeader hdr_base,
                         const std::vector<Transaction> txs_including_cb,
                         uint32_t bits,
                         std::atomic<bool>* found,
                         std::atomic<uint64_t>* tries,
                         unsigned tid, unsigned stride,
                         Block* out_block)
{
    Block b; b.header = hdr_base; b.txs = txs_including_cb;
    // Precompute merkle root once (coinbase fixed here)
    b.header.merkle_root = merkle_from(b.txs);
    uint32_t nonce = tid;
    while(!found->load(std::memory_order_relaxed)){
        b.header.nonce = nonce;
        auto h = b.block_hash();
        tries->fetch_add(1, std::memory_order_relaxed);
        if(meets_target_be(h, bits)){
            *out_block = b;
            found->store(true, std::memory_order_relaxed);
            return;
        }
        nonce += stride;
    }
}

// --- topo packer: obey dependencies + byte limit -----------------------------

static bool topo_pack_and_sum_fees(const MinerTemplate& tpl,
                                   std::vector<Transaction>& out_txs, // without coinbase
                                   uint64_t& out_fees,
                                   size_t coinbase_bytes)
{
    out_txs.clear(); out_fees = 0;

    // Build map: id -> tpl index
    std::map<std::string, size_t> idx;
    for(size_t i=0;i<tpl.txs.size();++i) idx[tpl.txs[i].id] = i;

    // in-degree count & graph
    std::map<std::string, int> indeg;
    std::map<std::string, std::vector<std::string>> G;

    for(const auto& x : tpl.txs){
        indeg.emplace(x.id, 0);
    }
    for(const auto& x : tpl.txs){
        for(const auto& d : x.deps){
            auto it = indeg.find(x.id);
            if(it!=indeg.end()){
                it->second++;
                G[d].push_back(x.id);
            }
        }
    }

    // Kahn’s algorithm
    std::vector<std::string> Q;
    for(const auto& kv : indeg){
        if(kv.second==0) Q.push_back(kv.first);
    }

    size_t used = coinbase_bytes;
    const size_t limit = tpl.max_block_bytes;

    while(!Q.empty()){
        std::string id = Q.back(); Q.pop_back();
        auto it = idx.find(id);
        if(it==idx.end()) continue;
        const TxTpl& xt = tpl.txs[it->second];

        // decode & size
        std::vector<uint8_t> raw = from_hex_s(xt.hex);
        Transaction t;
        if(!deser_tx(raw, t)) {
            // skip malformed
        } else {
            size_t sz = ser_tx(t).size();
            if(used + sz <= limit){
                out_txs.push_back(std::move(t));
                used += sz;
                out_fees += xt.fee;
            } else {
                // stop packing once over the limit budget
                // (we still dequeue graph nodes to keep topo traversal correct)
            }
        }
        // relax
        auto git = G.find(id);
        if(git != G.end()){
            for(const auto& v : git->second){
                auto i2 = indeg.find(v);
                if(i2!=indeg.end()){
                    if(--(i2->second) == 0) Q.push_back(v);
                }
            }
        }
    }

    return true;
}

// === main ====================================================================

static void usage(){
    std::cout <<
    "miqminer_rpc — Solo miner for MIQ (JSON-RPC, fee-aware, non-empty blocks)\n"
    "Usage: miqminer_rpc [--rpc=host:port] [--token=<TOKEN>] [--threads=N]\n"
    "Notes:\n"
    "  * Node must be running. Auth token is taken from --token, MIQ_RPC_TOKEN, or datadir/.cookie\n"
    "  * Miner will prompt for a P2PKH Base58 address to receive rewards.\n";
}

int main(int argc, char** argv){
    try{
#if defined(_WIN32)
        // enable ANSI colors on Windows 10+ terminals
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/);
        }
#endif
        std::string rpc_host = "127.0.0.1";
        uint16_t    rpc_port = (uint16_t)miq::RPC_PORT;
        std::string token; // raw token (we’ll send in both X-Auth-Token and Bearer for compatibility)
        unsigned threads = std::max(1u, std::thread::hardware_concurrency());

        for(int i=1;i<argc;i++){
            std::string a(argv[i]);
            if(a=="--help"||a=="-h"){ usage(); return 0; }
            if(a.rfind("--rpc=",0)==0){
                std::string hp = a.substr(6); size_t c = hp.find(':');
                if(c==std::string::npos){ std::fprintf(stderr,"Bad --rpc=host:port\n"); return 2; }
                rpc_host = hp.substr(0,c);
                rpc_port = (uint16_t)std::stoi(hp.substr(c+1));
            } else if(a.rfind("--token=",0)==0){
                token = a.substr(8);
            } else if(a.rfind("--threads=",0)==0){
                long v = std::strtol(a.c_str()+10,nullptr,10);
                if(v>0 && v<=256) threads = (unsigned)v;
            } else {
                std::fprintf(stderr, "Unknown arg: %s\n", argv[i]);
                return 2;
            }
        }

        // Resolve token: CLI > env > cookie file
        if(token.empty()){
            if(const char* t = std::getenv("MIQ_RPC_TOKEN")) token = t;
            if(token.empty()){
                std::string cookie;
                if(read_all_file(default_cookie_path(), cookie)) token = cookie;
            }
        }

        // Prompt for mining address
        std::string addr;
        std::cout << "Enter P2PKH Base58 address to mine to: ";
        if(!std::getline(std::cin, addr)){ std::fprintf(stderr,"stdin closed\n"); return 1; }
        trim(addr);
        std::vector<uint8_t> pkh;
        if(!parse_p2pkh(addr, pkh)){
            std::fprintf(stderr, "Invalid address (expected Base58Check P2PKH, version 0x%02x)\n", (unsigned)miq::VERSION_P2PKH);
            return 1;
        }

        // UI + miner state
        UIState ui;
        std::atomic<bool> running{true};

        // UI thread
        std::thread ui_th([&](){ draw_ui_loop(addr, threads, &ui, &running); });
        ui_th.detach();

        // Chain watcher: refresh tip + last block details + net hashrate
        std::thread chain_watch([&](){
            uint64_t last_seen_h = 0;
            while(running.load()){
                TipInfo t;
                if(rpc_gettipinfo(rpc_host, rpc_port, token, t)){
                    ui.tip_height.store(t.height);
                    ui.tip_hash_hex = t.hash_hex;
                    ui.tip_bits.store(t.bits);

                    // network hashrate: direct or estimate fallback
                    double hs = 0.0;
                    if(!rpc_getminerstats(rpc_host, rpc_port, token, hs)){
                        hs = estimate_network_hashps(rpc_host, rpc_port, token, t.height, t.bits);
                    }
                    ui.net_hashps.store(hs);

                    // On new height, fetch last block data + coinbase recipient
                    if(t.height != 0 && t.height != last_seen_h){
                        LastBlockInfo lb{};
                        if(rpc_getblock_overview(rpc_host, rpc_port, token, t.height, lb)){
                            // also coinbase recipient (who got paid)
                            rpc_getcoinbaserecipient(rpc_host, rpc_port, token, t.height, lb);
                            ui.lastblk = lb;
                        }
                        last_seen_h = t.height;
                    }
                }
                for(int i=0;i<10;i++) miq_sleep_ms(100); // ~1s
            }
        });
        chain_watch.detach();

        // Mining loop: fetch template → pack → mine → submit → repeat
        while(true){
            MinerTemplate tpl;
            if(!rpc_getminertemplate(rpc_host, rpc_port, token, tpl)){
                std::fprintf(stderr, "RPC getminertemplate failed, retrying...\n");
                miq_sleep_ms(1000);
                continue;
            }

            // PACK: topo + size limit
            // First create a dummy coinbase to know its size without fees
            Transaction dummy_cb = make_coinbase(tpl.height, /*fees=*/0, pkh);
            size_t coinbase_sz = ser_tx(dummy_cb).size();

            std::vector<Transaction> txs; // non-coinbase
            uint64_t fees=0;
            topo_pack_and_sum_fees(tpl, txs, fees, coinbase_sz);

            // Now build real coinbase with fees
            Transaction cb = make_coinbase(tpl.height, fees, pkh);

            // Assemble block header
            BlockHeader hb;
            hb.prev_hash = tpl.prev_hash;
            hb.time = std::max<int64_t>((int64_t)time(nullptr), tpl.time);
            hb.bits = tpl.bits;
            hb.nonce = 0;

            // Prepare full tx vector (coinbase first)
            std::vector<Transaction> txs_inc; txs_inc.reserve(1+txs.size());
            txs_inc.push_back(cb);
            for(auto& t : txs) txs_inc.push_back(std::move(t));

            // Mine across threads
            std::atomic<bool> found{false};
            std::atomic<uint64_t> tries{0};
            std::vector<std::thread> thv;
            Block found_block;

            for(unsigned tid=0; tid<threads; ++tid){
                thv.emplace_back(nonce_worker, hb, txs_inc, tpl.bits,
                                 &found, &tries, tid, threads, &found_block);
            }

            // metering -> UI
            std::thread meter([&](){
                while(!found.load(std::memory_order_relaxed)){
                    ui.hash_tries.store(tries.load(std::memory_order_relaxed));
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                ui.hash_tries.store(tries.load(std::memory_order_relaxed));
            });
            meter.join();

            for(auto& th : thv) th.join();

            // Submit found block
            auto raw = miq::ser_block(found_block);
            std::string hexblk = miq::to_hex(raw);
            bool ok = rpc_submitblock(rpc_host, rpc_port, token, hexblk);
            if(ok){
                ui.mined_blocks.fetch_add(1);
                ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
            } else {
                std::fprintf(stderr, "submitblock rejected or RPC error (ensure node exposes submitblock/submitrawblock)\n");
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
