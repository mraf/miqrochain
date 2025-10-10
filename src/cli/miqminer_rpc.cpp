// miqminer_rpc.cpp — solo miner (JSON-RPC), fee-aware, non-empty blocks, crash-safe submissions
// Defaults to 6 threads, smooth live hashrate (inst + EWMA), richer 3D block animation (24 frames),
// and an optimized inner loop (batched nonce steps + batched atomic updates).
//
// Stats: tip height/hash/bits/difficulty, candidate size/txs/fees/coinbase,
//        last network block hash/txid/paid-to, local & estimated network hashrate.
//
// Requires node RPCs: getminertemplate, gettipinfo, getblock, getcoinbaserecipient,
//                     getblockcount, getblockhash. (submitblock/submitrawblock optional)
//
// Build (GCC/Clang):
//   g++ -std=c++17 -O3 -DNDEBUG -march=native -mtune=native -flto -funroll-loops \
//       -fomit-frame-pointer miqminer_rpc.cpp -o miqminer_rpc
//
// Build (MSVC):
//   cl /std:c++17 /O2 /GL /DNDEBUG miqminer_rpc.cpp ws2_32.lib
//
// Run:
//   ./miqminer_rpc --threads=6 --rpc=127.0.0.1:8332
//   (token from --token, MIQ_RPC_TOKEN, or datadir .cookie)

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
  using socket_t = int;
  #define miq_closesocket ::close
  static void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
#endif

using namespace miq;

// ---------- tiny utils ----------
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

// ---------- target/difficulty ----------
static void bits_to_target_be(uint32_t bits, uint8_t out[32]){
    std::memset(out,0,32);
    const uint32_t exp = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;
    if (!mant) return;
    if (exp <= 3){
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
static inline bool meets_target_be(const std::vector<uint8_t>& hash32, uint32_t bits){
    if (hash32.size()!=32) return false;
    uint8_t target[32]; bits_to_target_be(bits, target);
    return std::memcmp(hash32.data(), target, 32) <= 0;
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

// ---------- minimal HTTP/JSON ----------
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
        // Accept both header styles (node may check either)
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
static bool json_has_error(const std::string& json){
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
    while(q<json.size() && (std::isdigit((unsigned char)json[q])||json[q]=='-'||json[q]=='+'||json[q]=='.'||json[q]=='e'||json[q]=='E')) ++q;
    if(q==p) return false;
    out = std::strtod(json.c_str()+p, nullptr);
    return true;
}

// ---------- RPC wrappers ----------
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
    out.height=(uint64_t)h; out.hash_hex=hh; out.bits=(uint32_t)b; out.time=(int64_t)t;
    return true;
}

static bool rpc_getminertemplate(const std::string& host, uint16_t port, const std::string& auth,
                                 uint64_t& out_height, std::vector<uint8_t>& out_prev,
                                 uint32_t& out_bits, int64_t& out_time,
                                 size_t& out_maxb,
                                 std::vector<std::string>& txhex,
                                 std::vector<uint64_t>& txfee,
                                 std::vector<std::vector<std::string>>& txdeps)
{
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getminertemplate","[]"), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;

    long long h=0,b=0,t=0, maxb=0; std::string ph;
    if(!json_find_number(r.body,"height",h)) return false;
    if(!json_find_string(r.body,"prev_hash",ph)) return false;
    if(!json_find_number(r.body,"bits",b)) return false;
    if(!json_find_number(r.body,"time",t)) return false;
    out_height=(uint64_t)h; out_prev=from_hex_s(ph); out_bits=(uint32_t)b; out_time=(int64_t)t;
    if(out_prev.size()!=32) return false;
    if(json_find_number(r.body,"max_block_bytes",maxb)) out_maxb=(size_t)maxb; else out_maxb=900*1024;

    // Parse txs (ids/hex/fee/depends). We only need hex & fee; deps are optionally honored.
    size_t p = r.body.find("\"txs\"");
    if(p==std::string::npos) return true;
    p = r.body.find('[', p);
    if(p==std::string::npos) return false;
    size_t q=p; int depth=0; bool ok=false;
    while(q<r.body.size()){
        if(r.body[q]=='[') depth++;
        else if(r.body[q]==']'){ depth--; if(depth==0){ ok=true; ++q; break; } }
        ++q;
    }
    if(!ok) return false;
    std::string arr = r.body.substr(p,q-p);
    size_t pos=0;
    while(true){
        size_t ob = arr.find('{',pos); if(ob==std::string::npos) break;
        size_t oe=ob; int d=0; bool ok2=false;
        while(oe<arr.size()){
            if(arr[oe]=='{') d++;
            else if(arr[oe]=='}'){ d--; if(d==0){ ok2=true; ++oe; break; } }
            ++oe;
        }
        if(!ok2) break;
        std::string obj = arr.substr(ob,oe-ob);
        std::string hx; long long fee=0;
        json_find_string(obj,"hex",hx);
        json_find_number(obj,"fee",fee);
        if(!hx.empty()){ txhex.push_back(hx); txfee.push_back((uint64_t)(fee<0?0:fee)); }

        // deps (optional)
        std::vector<std::string> deps;
        size_t dp = obj.find("\"depends\"");
        if(dp!=std::string::npos){
            size_t br = obj.find('[',dp);
            if(br!=std::string::npos){
                size_t i=br+1;
                while(i<obj.size()){
                    while(i<obj.size() && std::isspace((unsigned char)obj[i])) ++i;
                    if(i>=obj.size()||obj[i]==']'){ ++i; break; }
                    if(obj[i]!='"') break;
                    size_t j=obj.find('"',i+1); if(j==std::string::npos) break;
                    deps.push_back(obj.substr(i+1,j-i-1));
                    i=j+1;
                    while(i<obj.size() && std::isspace((unsigned char)obj[i])) ++i;
                    if(i<obj.size()&&obj[i]==',') ++i;
                }
            }
        }
        txdeps.push_back(std::move(deps));
        pos=oe;
    }
    return true;
}

static bool rpc_getblock_overview(const std::string& host, uint16_t port, const std::string& auth,
                                  uint64_t height, std::string& hash_out, uint64_t& txs_out)
{
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    std::string hh; long long txs=0;
    if(!json_find_string(r.body,"hash",hh)) return false;
    if(!json_find_number(r.body,"txs",txs)) return false;
    hash_out=hh; txs_out=(uint64_t)txs; return true;
}

static bool rpc_getcoinbaserecipient(const std::string& host, uint16_t port, const std::string& auth,
                                     uint64_t height, std::string& cb_txid_hex,
                                     std::vector<uint8_t>& paid_pkh, uint64_t& reward_value)
{
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getcoinbaserecipient", ps.str()), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    std::string pkh_hex, txid_hex; long long val=0;
    if(!json_find_string(r.body,"pkh",pkh_hex)) return false;
    json_find_string(r.body,"txid",txid_hex);
    json_find_number(r.body,"value",val);
    paid_pkh = from_hex_s(pkh_hex);
    cb_txid_hex = txid_hex;
    reward_value = (uint64_t)val;
    return true;
}

static bool rpc_getblockhash(const std::string& host, uint16_t port, const std::string& auth,
                             uint64_t height, std::string& out)
{
    std::ostringstream ps; ps<<"["<<height<<"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblockhash", ps.str()), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    return json_find_string(r.body,"result", out);
}

static bool rpc_getblock_header_time(const std::string& host, uint16_t port, const std::string& auth,
                                     const std::string& hh, long long& out_time)
{
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code!=200) return false;
    if(json_has_error(r.body)) return false;
    long long t=0;
    if(json_find_number(r.body,"time",t)){ out_time=t; return true; }
    size_t ph = r.body.find("\"header\"");
    if(ph!=std::string::npos && json_find_number(r.body.substr(ph),"time",t)){ out_time=t; return true; }
    return false;
}

static double estimate_network_hashps(const std::string& host, uint16_t port, const std::string& auth,
                                      uint64_t tip_height, uint32_t bits)
{
    const int LOOKBACK = 64;
    if(tip_height<=1) return 0.0;
    uint64_t start_h = (tip_height> (uint64_t)LOOKBACK) ? (tip_height-LOOKBACK) : 1;
    long long t_first=0, t_last=0;
    std::string hh_first, hh_last;
    if(!rpc_getblockhash(host, port, auth, start_h, hh_first)) return 0.0;
    if(!rpc_getblockhash(host, port, auth, tip_height, hh_last)) return 0.0;
    if(!rpc_getblock_header_time(host, port, auth, hh_first, t_first)) return 0.0;
    if(!rpc_getblock_header_time(host, port, auth, hh_last, t_last)) return 0.0;
    double dt = (double)(t_last - t_first);
    if(dt<=0.0) return 0.0;

    double D = difficulty_from_bits(bits);
    double blocks = (double)(tip_height - start_h);
    double avg_spacing = dt / std::max(1.0, blocks);
    if(avg_spacing<=0.0) return 0.0;
    const double two32 = 4294967296.0;
    return D * (two32 / avg_spacing);
}

// ---------- assemble helpers ----------
static bool parse_p2pkh(const std::string& addr, std::vector<uint8_t>& out_pkh){
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!miq::base58check_decode(addr, ver, payload)) return false;
    if(ver!=miq::VERSION_P2PKH || payload.size()!=20) return false;
    out_pkh = std::move(payload); return true;
}
static std::string pkh_to_address(const std::vector<uint8_t>& pkh){
    return miq::base58check_encode(miq::VERSION_P2PKH, pkh);
}
static Transaction make_coinbase(uint64_t height, uint64_t fees, const std::vector<uint8_t>& pkh){
    Transaction cbt;
    TxIn in; in.prev.txid = std::vector<uint8_t>(32,0); in.prev.vout=0;
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
    for(const auto& t: txs) ids.push_back(t.txid());
    return miq::merkle_root(ids);
}

// ---------- UI (24-frame animation + EWMA hashrate) ----------
static const int kAnimLines = 8;
static const int kAnimFrames = 24;
static const char* kFrames[kAnimFrames][kAnimLines] = {
// (24 frames; same width so it doesn't jitter)
{
"      _________       ",
"     / _______ \\      ",
"    / / _____ \\ \\     ",
"   / / / ___ \\ \\ \\    ",
"  /_/ / /___\\ \\ \\_\\   ",
"  \\ \\ \\_____/_/ / /   ",
"   \\ \\_______/ / /    ",
"    \\__________/      "
},{
"      _________       ",
"     / ________\\      ",
"    / / _____ \\ \\     ",
"   / / / ___ \\ \\ \\    ",
"  /_/ / /___\\ \\ \\_\\   ",
"  \\ \\ \\______/ / /    ",
"   \\ \\_______/ /      ",
"    \\_________/       "
},{
"     _________        ",
"    / ________\\       ",
"   / /  ___  \\ \\      ",
"  / /  / _ \\  \\ \\     ",
" /_/  / /_\\ \\  \\_\\    ",
" \\ \\  \\___/ /  / /    ",
"  \\ \\_______/  /      ",
"   \\__________/       "
},{
"     _________        ",
"    / ________\\       ",
"   / /  ___  \\ \\      ",
"  / /  / _ \\  \\ \\     ",
" /_/  / /_\\ \\  \\_\\    ",
" \\ \\  \\___/ /  /      ",
"  \\ \\_______/         ",
"   \\_________         "
},{
"    _________         ",
"   / ________\\        ",
"  / /  ___  \\ \\       ",
" / /  / _ \\  \\ \\      ",
"/_/  / /_\\ \\  \\_\\     ",
"\\ \\  \\___/ /  / /     ",
" \\ \\_______/  /       ",
"  \\__________/        "
},{
"    _________         ",
"   / ________\\        ",
"  / /  ___  \\ \\       ",
" / /  / _ \\  \\ \\      ",
"/_/  / /_\\ \\  \\_\\     ",
"\\ \\  \\___/ /  /       ",
" \\ \\_______/          ",
"  \\_________          "
},{
"   _________          ",
"  / ________\\         ",
" / /  ___  \\ \\        ",
"/ /  / _ \\  \\ \\       ",
"\\_\\ / /_\\ \\  \\_\\      ",
" \\ \\\\___/ /  / /      ",
"  \\ \\_____/  /        ",
"   \\________/         "
},{
"   _________          ",
"  / ________\\         ",
" / /  ___  \\ \\        ",
"/ /  / _ \\  \\ \\       ",
"\\_\\ / /_\\ \\  \\_\\      ",
" \\ \\\\___/ /  /        ",
"  \\ \\_____/           ",
"   \\_______           "
},{
"  _________           ",
" / ________\\          ",
"/ /  ___  \\ \\         ",
"\\ \\ / _ \\  \\ \\        ",
" \\ / /_\\ \\  \\_\\       ",
"  \\\\___/ /  / /       ",
"   \\_____/_/ /        ",
"    \\_______/         "
},{
"  _________           ",
" / ________\\          ",
"/ /  ___  \\ \\         ",
"\\ \\ / _ \\  \\ \\        ",
" \\ / /_\\ \\  \\_\\       ",
"  \\\\___/ /  /         ",
"   \\_____/_/          ",
"    \\______/          "
},{
" _________            ",
"/ ________\\           ",
"\\ \\  ___  \\ \\         ",
" \\ \\/ _ \\  \\ \\        ",
"  \\ / /_\\ \\  \\_\\      ",
"   \\\\___/ /  / /      ",
"    \\_____/_/ /       ",
"     \\_______/        "
},{
" _________            ",
"/ ________\\           ",
"\\ \\  ___  \\ \\         ",
" \\ \\/ _ \\  \\ \\        ",
"  \\ / /_\\ \\  \\_\\      ",
"   \\\\___/ /  /        ",
"    \\_____/_/         ",
"     \\______/         "
},{
"__________            ",
"\\ ________\\           ",
" \\ \\  ___  \\ \\        ",
"  \\ \\/ _ \\  \\ \\       ",
"   \\ / /_\\ \\  \\_\\     ",
"    \\\\___/ /  / /     ",
"     \\_____/_/ /      ",
"      \\_______/       "
},{
"__________            ",
"\\ ________\\           ",
" \\ \\  ___  \\ \\        ",
"  \\ \\/ _ \\  \\ \\       ",
"   \\ / /_\\ \\  \\_\\     ",
"    \\\\___/ /  /       ",
"     \\_____/_/        ",
"      \\______/        "
},{
" _________            ",
"/ ________ /          ",
"\\ \\  ___  \\ \\         ",
" \\ \\/ _ \\  \\ \\        ",
"  \\ / /_\\ \\  \\_\\      ",
"   \\\\___/ /  / /      ",
"    \\_____/_/ /       ",
"     \\_______/        "
},{
" _________            ",
"/ ________ /          ",
"\\ \\  ___  \\ \\         ",
" \\ \\/ _ \\  \\ \\        ",
"  \\ / /_\\ \\  \\_\\      ",
"   \\\\___/ /  /        ",
"    \\_____/_/         ",
"     \\______/         "
},{
"  _________           ",
" / ________\\          ",
"/ /  ___  \\ \\         ",
"\\ \\ / _ \\  \\ \\        ",
" \\ / /_\\ \\  \\_\\       ",
"  \\\\___/ /  /         ",
"   \\_____/_/          ",
"    \\______/          "
},{
"  _________           ",
" / ________\\          ",
"/ /  ___  \\ \\         ",
"\\ \\ / _ \\  \\ \\        ",
" \\ / /_\\ \\  \\_\\       ",
"  \\\\___/ /  / /       ",
"   \\_____/_/ /        ",
"    \\_______/         "
},{
"   _________          ",
"  / ________\\         ",
" / /  ___  \\ \\        ",
"/ /  / _ \\  \\ \\       ",
"\\_\\ / /_\\ \\  \\_\\      ",
" \\ \\\\___/ /  /        ",
"  \\ \\_____/           ",
"   \\_______           "
},{
"   _________          ",
"  / ________\\         ",
" / /  ___  \\ \\        ",
"/ /  / _ \\  \\ \\       ",
"\\_\\ / /_\\ \\  \\_\\      ",
" \\ \\\\___/ /  / /      ",
"  \\ \\_____/  /        ",
"   \\________/         "
},{
"    _________         ",
"   / ________\\        ",
"  / /  ___  \\ \\       ",
" / /  / _ \\  \\ \\      ",
"/_/  / /_\\ \\  \\_\\     ",
"\\ \\  \\___/ /  /       ",
" \\ \\_______/          ",
"  \\_________          "
},{
"    _________         ",
"   / ________\\        ",
"  / /  ___  \\ \\       ",
" / /  / _ \\  \\ \\      ",
"/_/  / /_\\ \\  \\_\\     ",
"\\ \\  \\___/ /  / /     ",
" \\ \\_______/  /       ",
"  \\__________/        "
},{
"     _________        ",
"    / ________\\       ",
"   / /  ___  \\ \\      ",
"  / /  / _ \\  \\ \\     ",
" /_/  / /_\\ \\  \\_\\    ",
" \\ \\  \\___/ /  /      ",
"  \\ \\_______/         ",
"   \\_________         "
},{
"      _________       ",
"     / _______ \\      ",
"    / / _____ \\ \\     ",
"   / / / ___ \\ \\ \\    ",
"  /_/ / /___\\ \\ \\_\\   ",
"  \\ \\ \\_____/_/ /     ",
"   \\ \\_______/ /      ",
"    \\__________/      "
}
};

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

struct LastBlockInfo {
    uint64_t height{0};
    std::string hash_hex;
    uint64_t txs{0};
    std::string coinbase_txid_hex;
    std::vector<uint8_t> coinbase_pkh;
    uint64_t reward_value{0};
};

struct UIState {
    // hash metering
    std::atomic<uint64_t> tries{0};
    std::atomic<uint64_t> tries_last{0};
    std::atomic<uint64_t> mined_blocks{0};
    std::atomic<double>   net_hashps{0.0};
    std::atomic<double>   local_ewma{0.0};

    // tip
    std::atomic<uint64_t> tip_height{0};
    std::string tip_hash_hex;
    std::atomic<uint32_t> tip_bits{0};

    // candidate (protected)
    CandidateStats cand{};
    std::mutex mtx;

    // last network block + our last found
    LastBlockInfo lastblk{};
    std::string last_found_block_hash;
};

static std::string fmt_hs(double v){
    const char* u[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s"};
    int i=0; while(v>=1000.0 && i<5){ v/=1000.0; ++i; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i]; return o.str();
}

static void draw_ui_loop(const std::string& addr, unsigned threads, UIState* ui, const std::atomic<bool>* running){
#if defined(_WIN32)
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004);
    }
#endif
    using clock = std::chrono::steady_clock;
    auto prev_ts = clock::now();
    uint64_t frame = 0;
    while(running->load(std::memory_order_relaxed)){
        auto now = clock::now();
        double dt = std::chrono::duration<double>(now - prev_ts).count();
        if(dt <= 0.0) dt = 1e-3;
        prev_ts = now;

        uint64_t cur = ui->tries.load(std::memory_order_relaxed);
        uint64_t prev = ui->tries_last.exchange(cur, std::memory_order_relaxed);
        double local_inst = (double)(cur - prev) / dt;

        // EWMA (half-life ~5s): alpha = 1 - exp(-dt/5)
        double alpha = 1.0 - std::exp(-dt / 5.0);
        double ewma_prev = ui->local_ewma.load(std::memory_order_relaxed);
        double ewma = (1.0 - alpha) * ewma_prev + alpha * local_inst;
        ui->local_ewma.store(ewma, std::memory_order_relaxed);

        std::ostringstream os;
        os << "\x1b[2J\x1b[H"; // clear
        os << "  \x1b[1mMIQ Miner (RPC)\x1b[0m  —  address: " << addr << "     threads: " << threads << "\n\n";

        uint64_t th = ui->tip_height.load();
        if(th){
            os << "  tip height:      " << th << "\n";
            os << "  tip hash:        " << ui->tip_hash_hex << "\n";
            uint32_t bits = ui->tip_bits.load();
            os << "  tip bits:        0x" << std::hex << std::setw(8) << std::setfill('0') << (unsigned)bits
               << std::dec << "  (difficulty " << std::fixed << std::setprecision(2) << difficulty_from_bits(bits) << ")\n";
        } else {
            os << "  (waiting for template)\n";
        }

        // Candidate section
        {
            std::lock_guard<std::mutex> lk(ui->mtx);
            if(ui->cand.height){
                os << "\n";
                os << "  mining candidate:  height=" << ui->cand.height
                   << "  prev=" << ui->cand.prev_hex << "\n";
                os << "                     txs=" << ui->cand.txs
                   << "  size=" << ui->cand.size_bytes << " bytes"
                   << "  fees=" << ui->cand.fees
                   << "  coinbase=" << ui->cand.coinbase << "\n";
            }
        }

        // Last block on-chain (who got paid)
        if(ui->lastblk.height){
            const auto& lb = ui->lastblk;
            os << "\n";
            os << "  last block:       height=" << lb.height
               << "  hash=" << lb.hash_hex
               << "  txs=" << lb.txs << "\n";
            if(!lb.coinbase_txid_hex.empty())
                os << "                     coinbase_txid=" << lb.coinbase_txid_hex << "\n";
            if(!lb.coinbase_pkh.empty()){
                os << "                     paid to: " << pkh_to_address(lb.coinbase_pkh)
                   << "  (pkh=" << to_hex_s(lb.coinbase_pkh) << ", value=" << lb.reward_value << ")\n";
            }
        }

        os << "\n";
        os << "  local hashrate:   " << fmt_hs(local_inst) << "  (avg " << fmt_hs(ui->local_ewma.load()) << ")\n";
        os << "  network hashrate: " << fmt_hs(ui->net_hashps.load()) << "\n";
        os << "  mined (session):  " << ui->mined_blocks.load() << "\n";
        if(!ui->last_found_block_hash.empty())
            os << "  last found:       " << ui->last_found_block_hash << "\n";

        // animation (update every frame)
        os << "\n";
        const char** f = kFrames[frame % kAnimFrames];
        for(int i=0;i<kAnimLines;i++)
            os << "  \x1b[36m" << f[i] << "\x1b[0m\n";
        os << "\n  Press Ctrl+C to quit.\n";

        std::cout << os.str() << std::flush;

        // ~5 FPS UI (smoother than 1 Hz)
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        ++frame;
    }
}

// ---------- mining worker (optimized inner loop) ----------
static void nonce_worker(const BlockHeader hdr_base,
                         const std::vector<Transaction> txs_including_cb,
                         uint32_t bits,
                         std::atomic<bool>* found,
                         std::atomic<uint64_t>* tries,
                         unsigned tid, unsigned stride,
                         Block* out_block)
{
    Block b; b.header = hdr_base; b.txs = txs_including_cb;
    b.header.merkle_root = merkle_from(b.txs); // fixed per candidate

    // Local batching to reduce atomic contention
    const uint32_t STEP_BATCH = 4096; // update global counter every 4k nonces
    uint64_t local_steps = 0;

    uint32_t nonce = tid;

    while(!found->load(std::memory_order_relaxed)){
        // Unroll 8 attempts per small loop
        for(int k=0; k<8; ++k){
            b.header.nonce = nonce;
            auto h = b.block_hash(); // relies on project’s fast serializer/hash
            if(meets_target_be(h, bits)){
                *out_block = b;
                // flush any outstanding local steps
                if(local_steps) tries->fetch_add(local_steps, std::memory_order_relaxed);
                found->store(true, std::memory_order_relaxed);
                return;
            }
            nonce += stride;
        }
        local_steps += 8;
        if(local_steps >= STEP_BATCH){
            tries->fetch_add(local_steps, std::memory_order_relaxed);
            local_steps = 0;
        }
        // Periodically check stop flag (already happens above), keep loop tight
    }

    if(local_steps) tries->fetch_add(local_steps, std::memory_order_relaxed);
}

// ---------- packing (size-first; deps optional) ----------
static bool pack_template(const std::vector<std::string>& txhex,
                          const std::vector<uint64_t>& txfee,
                          const std::vector<std::vector<std::string>>& /*deps*/,
                          size_t max_block_bytes,
                          size_t coinbase_bytes,
                          std::vector<Transaction>& out_txs,
                          uint64_t& out_fees,
                          size_t& out_bytes)
{
    out_txs.clear(); out_fees=0; out_bytes=coinbase_bytes;
    for(size_t i=0;i<txhex.size();++i){
        std::vector<uint8_t> raw;
        try{ raw = from_hex_s(txhex[i]); }catch(...){ continue; }
        Transaction t; if(!deser_tx(raw, t)) continue;
        size_t sz = ser_tx(t).size();
        if(out_bytes + sz > max_block_bytes) continue;
        out_txs.push_back(std::move(t));
        out_bytes += sz;
        out_fees += txfee[i];
    }
    return true;
}

// ---------- submit (optional) ----------
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
    if(rpc_submitblock_try(host,port,auth,"submitblock",hexblk)) return true;
    if(rpc_submitblock_try(host,port,auth,"submitrawblock",hexblk)) return true;
    if(rpc_submitblock_try(host,port,auth,"sendrawblock",hexblk)) return true;
    return false;
}

// ---------- main ----------
static void usage(){
    std::cout <<
    "miqminer_rpc — Solo miner for MIQ (JSON-RPC)\n"
    "Usage: miqminer_rpc [--rpc=host:port] [--token=<TOKEN>] [--threads=N]\n"
    "Notes: token taken from --token, MIQ_RPC_TOKEN, or datadir/.cookie\n";
}

int main(int argc, char** argv){
    try{
#if defined(_WIN32)
        // enable ANSI color
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004);
        }
#endif
        std::string rpc_host = "127.0.0.1";
        uint16_t    rpc_port = (uint16_t)miq::RPC_PORT;
        std::string token;
        unsigned threads = 6; // default to 6 as requested

        for(int i=1;i<argc;i++){
            std::string a(argv[i]);
            if(a=="--help"||a=="-h"){ usage(); return 0; }
            if(a.rfind("--rpc=",0)==0){
                std::string hp = a.substr(6); size_t c = hp.find(':');
                if(c==std::string::npos){ std::fprintf(stderr,"Bad --rpc=host:port\n"); return 2; }
                rpc_host = hp.substr(0,c); rpc_port = (uint16_t)std::stoi(hp.substr(c+1));
            } else if(a.rfind("--token=",0)==0){
                token = a.substr(8);
            } else if(a.rfind("--threads=",0)==0){
                long v = std::strtol(a.c_str()+10,nullptr,10);
                if(v>0 && v<=256) threads = (unsigned)v;
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

        // Address prompt
        std::string addr;
        std::cout << "Enter P2PKH Base58 address to mine to: ";
        if(!std::getline(std::cin, addr)){ std::fprintf(stderr,"stdin closed\n"); return 1; }
        trim(addr);
        std::vector<uint8_t> pkh;
        if(!parse_p2pkh(addr, pkh)){
            std::fprintf(stderr,"Invalid address (expected Base58Check P2PKH, version 0x%02x)\n",(unsigned)miq::VERSION_P2PKH);
            return 1;
        }

        // state + UI
        UIState ui;
        std::atomic<bool> running{true};
        std::thread ui_th([&](){ draw_ui_loop(addr, threads, &ui, &running); });
        ui_th.detach();

        // chain watcher (tip + last block + net hashrate)
        std::thread watch([&](){
            uint64_t last_seen_h = 0;
            while(running.load()){
                TipInfo t;
                if(rpc_gettipinfo(rpc_host, rpc_port, token, t)){
                    ui.tip_height.store(t.height);
                    ui.tip_hash_hex = t.hash_hex;
                    ui.tip_bits.store(t.bits);
                    ui.net_hashps.store(estimate_network_hashps(rpc_host, rpc_port, token, t.height, t.bits));
                    if(t.height && t.height != last_seen_h){
                        LastBlockInfo lb{};
                        lb.height = t.height;
                        rpc_getblock_overview(rpc_host, rpc_port, token, t.height, lb.hash_hex, lb.txs);
                        rpc_getcoinbaserecipient(rpc_host, rpc_port, token, t.height, lb.coinbase_txid_hex, lb.coinbase_pkh, lb.reward_value);
                        ui.lastblk = lb;
                        last_seen_h = t.height;
                    }
                }
                for(int i=0;i<10;i++) miq_sleep_ms(100); // ~1s
            }
        });
        watch.detach();

        // mining loop
        while(true){
            // get fresh template
            uint64_t height=0; std::vector<uint8_t> prev; uint32_t bits=0; int64_t ntime=0; size_t maxb=0;
            std::vector<std::string> txhex; std::vector<uint64_t> txfee; std::vector<std::vector<std::string>> txdeps;
            if(!rpc_getminertemplate(rpc_host, rpc_port, token, height, prev, bits, ntime, maxb, txhex, txfee, txdeps)){
                std::fprintf(stderr,"getminertemplate failed, retrying...\n");
                miq_sleep_ms(1000);
                continue;
            }

            // candidate TX packing
            Transaction dummy_cb = make_coinbase(height, 0, pkh);
            size_t coinbase_sz = ser_tx(dummy_cb).size();

            std::vector<Transaction> txs; uint64_t fees=0; size_t used_bytes=0;
            pack_template(txhex, txfee, txdeps, maxb, coinbase_sz, txs, fees, used_bytes);

            Transaction cb = make_coinbase(height, fees, pkh);
            std::vector<Transaction> txs_inc; txs_inc.reserve(1+txs.size());
            txs_inc.push_back(cb);
            for(auto& t: txs) txs_inc.push_back(std::move(t));

            // publish candidate stats to UI
            {
                std::lock_guard<std::mutex> lk(ui.mtx);
                ui.cand.height = height;
                ui.cand.prev_hex = to_hex_s(prev);
                ui.cand.bits = bits;
                ui.cand.time = ntime;
                ui.cand.txs = txs_inc.size();
                ui.cand.size_bytes = used_bytes + ser_tx(cb).size(); // upper-bound
                ui.cand.fees = fees;
                ui.cand.coinbase = GetBlockSubsidy((uint32_t)height) + fees;
            }

            // build header
            BlockHeader hb;
            hb.prev_hash = prev;
            hb.time = std::max<int64_t>((int64_t)time(nullptr), ntime);
            hb.bits = bits;
            hb.nonce = 0;

            // mine
            std::atomic<bool> found{false};
            std::atomic<uint64_t> tries{0};
            std::vector<std::thread> thv;
            Block found_block;

            for(unsigned tid=0; tid<threads; ++tid){
                thv.emplace_back(nonce_worker, hb, txs_inc, bits, &found, &tries, tid, threads, &found_block);
            }

            // meter to UI (100ms updates)
            std::thread meter([&](){
                using clock = std::chrono::steady_clock;
                while(!found.load(std::memory_order_relaxed)){
                    ui.tries.store(tries.load(std::memory_order_relaxed), std::memory_order_relaxed);
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                ui.tries.store(tries.load(std::memory_order_relaxed), std::memory_order_relaxed);
            });

            meter.join();
            for(auto& th: thv) th.join();

            // stale tip check before submit
            TipInfo tip_now{};
            bool have_tip = rpc_gettipinfo(rpc_host, rpc_port, token, tip_now);
            if(have_tip){
                // if tip hash changed from our prev, likely stale — discard to avoid stressing node
                if(to_hex_s(tip_now.hash_hex.size()?from_hex_s(tip_now.hash_hex):std::vector<uint8_t>()) != to_hex_s(prev)){
                    std::fprintf(stderr,"stale template detected, discarding solved block (chain advanced)\n");
                    continue;
                }
            }

            // submit (best-effort; safe if RPC not present)
            auto raw = miq::ser_block(found_block);
            std::string hexblk = miq::to_hex(raw);

            // Double-check meets target locally
            if(!meets_target_be(found_block.block_hash(), bits)){
                std::fprintf(stderr,"internal: solved header doesn't meet target, skipping\n");
                continue;
            }

            bool ok = rpc_submitblock(rpc_host, rpc_port, token, hexblk);
            if(ok){
                ui.mined_blocks.fetch_add(1, std::memory_order_relaxed);
                ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                miq_sleep_ms(250);
            } else {
                // If node has no submit RPC, print hex for manual relay if desired.
                std::fprintf(stderr, "[info] block candidate solved (no/failed submit RPC); hash=%s height=%llu\n",
                             miq::to_hex(found_block.block_hash()).c_str(),
                             (unsigned long long)height);
                ui.last_found_block_hash = miq::to_hex(found_block.block_hash());
                miq_sleep_ms(300);
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
