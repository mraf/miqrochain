// src/cli/miqminer_rpc.cpp
//
// Standalone MIQ miner that talks to the local node via JSON-RPC over HTTP.
// - Prompts for mining address at startup (Base58 P2PKH).
// - Pretty terminal UI: height, bits, difficulty, local H/s, network H/s, found blocks.
// - Uses all logical cores by default (or --threads=N).
// - Mines coinbase-only blocks (no mempool txs), exactly like Bitcoin solo miners can do.
// - RPC auth: Bearer token via MIQ_RPC_TOKEN or datadir/.cookie.
// - Requires the node (miqrod) running.
//
// Build target name suggestion: miqminer_rpc
//
// NOTE: This miner relies on the node providing:
//   - "gettipinfo" -> {"height":..., "hash":"...", "bits":..., "time":...}
//   - "submitblock" -> params: ["<hex block>"] returns null or {"result":null}
//   - "getminerstats" (optional) -> {"network_hash_ps": <double>} (if unavailable, we self-estimate)
//   - "getblockcount","getblockhash","getblock" (fallback for net hashrate estimation)
//
// If getminerstats is not implemented, we’ll derive network H/s from the last ~64 blocks.
//
// src/cli/miqminer_rpc.cpp
//
// RPC solo miner for MIQ. Connects to a running node's JSON-RPC,
// pulls tip info, mines an empty block (coinbase only) and submits it.
// Includes a live cyan "3D block" TUI next to the hashrate.
//
// Safe-by-default: lots of best-effort try/catch and bounds checks so a bad RPC
// reply or peer hiccup won't crash the miner.
//
// Build target name (in CMakeLists.txt): miqminer_rpc

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
#include <cmath>       // std::pow

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

using namespace miq;   // allow VERSION_P2PKH, GENESIS_BITS, Transaction, Block, etc.

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
    // %APPDATA%\miqrochain\.cookie
    char* v=nullptr; size_t len=0;
    if (_dupenv_s(&v,&len,"APPDATA")==0 && v && len){
        std::string p(v); free(v);
        return p + "\\miqrochain\\.cookie";
    }
    return "C:\\miqrochain-data\\.cookie";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if(home && *home) return std::string(home) + "/Library/Application Support/miqrochain/.cookie";
    return "./.cookie";
#else
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
    std::string s;
    char buf[4096];
    while(true){
        size_t n = fread(buf,1,sizeof(buf),f);
        if(n==0) break;
        s.append(buf,n);
    }
    fclose(f);
    // trim trailing whitespace
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
    if(getaddrinfo(host.c_str(), ps, &hints, &res)!=0) { return false; }

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
    if(s==INVALID_SOCKET) return false;
#else
    if(s<0) return false;
#endif

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << json.size() << "\r\n";
    if(!auth_header.empty()) req << "Authorization: " << auth_header << "\r\n";
    req << "Connection: close\r\n\r\n" << json;

    std::string data = req.str();
    size_t off=0;
    while(off < data.size()){
#if defined(_WIN32)
        int n = send(s, data.data()+off, (int)(data.size()-off), 0);
#else
        int n = ::send(s, data.data()+off, (int)(data.size()-off), 0);
#endif
        if(n<=0) { miq_closesocket(s); return false; }
        off += (size_t)n;
    }

    std::string resp; char buf[4096];
    while(true){
#if defined(_WIN32)
        int n = recv(s, buf, (int)sizeof(buf), 0);
#else
        int n = ::recv(s, buf, (int)sizeof(buf), 0);
#endif
        if (n <= 0) break;
        resp.append(buf, buf + n);
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

// Minimal JSON helpers (enough for our fixed-shaped RPC)
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
    o << "{\"jsonrpc\":\"2.0\",\"id\":" << g_id.fetch_add(1) << ",\"method\":" << json_escape(method)
      << ",\"params\":" << (params_json.empty()?"[]":params_json) << "}";
    return o.str();
}

static bool json_find_string(const std::string& json, const std::string& key, std::string& out){
    // naive search: "key":"...."
    std::string pat = "\"" + key + "\":";
    size_t p = json.find(pat);
    if(p==std::string::npos) return false;
    p += pat.size();
    while(p<json.size() && std::isspace((unsigned char)json[p])) ++p;
    if(p>=json.size() || json[p]!='"') return false;
    ++p;
    size_t q = json.find('"', p);
    if(q==std::string::npos) return false;
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
    while(q<json.size() && (std::isdigit((unsigned char)json[q])||json[q]=='-'||json[q]=='+')) ++q;
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
static bool json_has_error(const std::string& json){ return json.find("\"error\"") != std::string::npos && json.find("\"result\"")==std::string::npos; }

// === RPC wrappers ============================================================

struct TipInfo { uint64_t height{0}; std::string hash_hex; uint32_t bits{0}; int64_t time{0}; };

static bool rpc_gettipinfo(const std::string& host, uint16_t port, const std::string& auth, TipInfo& out){
    HttpResp r;
    std::string req = rpc_build("gettipinfo", "[]");
    if(!http_post(host, port, "/", auth, req, r) || r.code != 200) return false;
    // Expect: {"result":{"height":..., "hash":"...", "bits":..., "time":...}, "id":..., "jsonrpc":"2.0"}
    if(json_has_error(r.body)) return false;
    long long h=0, b=0, t=0; std::string hh;
    if(!json_find_number(r.body, "height", h)) return false;
    if(!json_find_string(r.body, "hash", hh)) return false;
    if(!json_find_number(r.body, "bits", b)) return false;
    if(!json_find_number(r.body, "time", t)) return false;
    out.height = (uint64_t)h; out.hash_hex = hh; out.bits = (uint32_t)b; out.time = (int64_t)t;
    return true;
}

static bool rpc_submitblock(const std::string& host, uint16_t port, const std::string& auth, const std::string& hexblk){
    std::ostringstream ps; ps << "[\"" << hexblk << "\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("submitblock", ps.str()), r)) return false;
    if(r.code != 200) return false;
    // Accept both {"result":null} and {"result":"..."} ok-ish, but ensure no {"error":...}
    return !json_has_error(r.body);
}

static bool rpc_getminerstats(const std::string& host, uint16_t port, const std::string& auth, double& out_net_hs){
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getminerstats","[]"), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    double hs = 0.0;
    if(!json_find_double(r.body, "network_hash_ps", hs)) return false;
    out_net_hs = hs;
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
    // Assume getblock returns {"result":{"header":{"time":...}, ...}} or {"result":{"time":...}}
    std::ostringstream ps; ps<<"[\""<<hh<<"\"]";
    HttpResp r;
    if(!http_post(host, port, "/", auth, rpc_build("getblock", ps.str()), r) || r.code != 200) return false;
    if(json_has_error(r.body)) return false;
    long long t=0;
    if(json_find_number(r.body, "time", t)) { out_time=t; return true; }
    // try nested
    size_t ph = r.body.find("\"header\"");
    if(ph != std::string::npos && json_find_number(r.body.substr(ph), "time", t)) { out_time=t; return true; }
    return false;
}

static double estimate_network_hashps(const std::string& host, uint16_t port, const std::string& auth, uint64_t tip_height, uint32_t bits){
    // D ≈ base_target/target; network_hashps ≈ D * 2^32 / avg_spacing
    // We’ll measure avg_spacing from last ~64 blocks (or fewer if chain short).
    const int LOOKBACK = 64;
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
        uint32_t bexp  = GENESIS_BITS >> 24;
        uint32_t bmant = GENESIS_BITS & 0x007fffff;
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
    // 2^32 per “difficulty 1” for SHA256d target convention
    const double two32 = 4294967296.0;
    return (double)D * (two32 / avg_spacing);
}

// === coinbase + block build ==================================================

static bool parse_p2pkh(const std::string& addr, std::vector<uint8_t>& out_pkh){
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!miq::base58check_decode(addr, ver, payload)) return false;
    if(ver != VERSION_P2PKH) return false;
    if(payload.size() != 20) return false;
    out_pkh = std::move(payload);
    return true;
}

static Transaction make_coinbase(uint64_t height, const std::vector<uint8_t>& pkh){
    Transaction cbt;
    // vin: null prev
    TxIn in; in.prev.txid = std::vector<uint8_t>(32,0); in.prev.vout = 0;
    // add a uniqueness tag (height, time, random)
    uint64_t rnd = (uint64_t)std::chrono::high_resolution_clock::now().time_since_epoch().count();
    uint32_t now = (uint32_t)time(nullptr);
    std::vector<uint8_t> tag; tag.reserve(1+4+4+8);
    tag.push_back(0x01);
    for(int i=0;i<4;i++) tag.push_back(uint8_t((height>>(8*i))&0xff));
    for(int i=0;i<4;i++) tag.push_back(uint8_t((now   >>(8*i))&0xff));
    for(int i=0;i<8;i++) tag.push_back(uint8_t((rnd   >>(8*i))&0xff));
    in.sig = std::move(tag);
    cbt.vin.push_back(in);

    // vout: subsidy only (fees=0 because we mine empty block template here)
    TxOut out; out.value = GetBlockSubsidy((uint32_t)height); out.pkh = pkh;
    cbt.vout.push_back(out);

    // lock_time hint (optional)
    cbt.lock_time = (uint32_t)height;
    return cbt;
}

static std::vector<uint8_t> merkle_root_coinbase_only(const Transaction& cb){
    std::vector<std::vector<uint8_t>> ids; ids.push_back(cb.txid());
    return miq::merkle_root(ids);
}

struct Job {
    uint64_t height{0};
    std::vector<uint8_t> prev_hash; // 32
    uint32_t bits{0};
    int64_t  prev_time{0};
};

static bool fetch_job(const std::string& host, uint16_t port, const std::string& auth, Job& j){
    TipInfo t;
    if(!rpc_gettipinfo(host, port, auth, t)) return false;
    j.height = t.height + 1;
    j.prev_hash = from_hex_s(t.hash_hex);
    j.bits = t.bits;
    j.prev_time = t.time;
    if(j.prev_hash.size()!=32) return false;
    return true;
}

// === miner core =============================================================

struct UIState {
    std::atomic<uint64_t> hash_tries{0};
    std::atomic<uint64_t> last_hash_tries{0};
    std::atomic<uint64_t> mined_blocks{0};
    std::atomic<double>   net_hashps{0.0};
    std::string last_block_hash;
    std::mutex  mtx;
};

// Make a little cyan "3D" ASCII block that fills/animates with work.
// We render faces with progressive shading using the tries counter.
static std::vector<std::string> make_block_art(uint64_t frame){
    // base outlines (ASCII for portability)
    std::vector<std::string> a = {
        "   +----------+      ",
        "  /##########/|      ",
        " /##########/ |      ",
        "+----------+  |      ",
        "|##########|  +      ",
        "|##########| /       ",
        "|##########|/        ",
        "+----------+         "
    };
    // Progressive fill pattern across '#' based on frame
    static const char shades[] = {'.','░','▒','▓','█'};
    size_t shade_idx = (size_t)((frame / 2) % (sizeof(shades)-1)) + 1; // 1..4
    char ch = shades[shade_idx];

    for (auto& s : a){
        for(char& c : s) if (c=='#') c = ch;
    }
    // Cyan colorize each line
    const std::string C = "\x1b[36m";
    const std::string Z = "\x1b[0m";
    for (auto& s : a) s = C + s + Z;
    return a;
}

static void draw_ui_loop(const std::string& addr, unsigned threads,
                         const Job* job, const std::atomic<bool>* have_job,
                         UIState* ui)
{
    using namespace std::chrono;
    (void)addr; (void)threads;

    while(true){
        // compute local H/s
        uint64_t tries_now = ui->hash_tries.load(std::memory_order_relaxed);
        uint64_t last      = ui->last_hash_tries.load(std::memory_order_relaxed);
        double inst = (double)(tries_now - last);
        ui->last_hash_tries.store(tries_now, std::memory_order_relaxed);

        double net  = ui->net_hashps.load(std::memory_order_relaxed);
        uint64_t mined = ui->mined_blocks.load(std::memory_order_relaxed);

        // Build the block art from a slow-moving frame number
        uint64_t frame = tries_now / 5000; // smooth animation at human scale
        auto art = make_block_art(frame);

        std::ostringstream os;
        os << "\x1b[2J\x1b[H"; // clear screen, home
        os << "  \x1b[1mMIQ Miner (RPC)\x1b[0m  —  address: " << addr
           << "     threads: " << threads << "\n\n";

        if(have_job->load(std::memory_order_relaxed) && job){
            os << "  height:      " << job->height << "\n";
            os << "  prev hash:   " << miq::to_hex(job->prev_hash) << "\n";
            std::ostringstream bhex; bhex<<std::hex<<std::setw(8)<<std::setfill('0')<<(unsigned)job->bits;
            os << "  bits:        0x" << bhex.str() << "\n";

            // Approx difficulty (relative to genesis)
            uint32_t bits = job->bits;
            uint32_t exp  = bits >> 24;
            uint32_t mant = bits & 0x007fffff;
            uint32_t bexp  = GENESIS_BITS >> 24;
            uint32_t bmant = GENESIS_BITS & 0x007fffff;
            long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
            long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
            long double D = (target>0.0L) ? (base_target/target) : 0.0L;
            os << "  difficulty:  " << std::fixed << std::setprecision(4) << (double)D << "\n";
        } else {
            os << "  (no job yet)\n";
        }

        auto fmt_hs = [](double v)->std::string{
            const char* u[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s"};
            int i=0; while(v>=1000.0 && i<5){ v/=1000.0; ++i; }
            std::ostringstream o; o<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i]; return o.str();
        };
        os << "\n";

        // Print hashrate and put art "beside" it, line by line
        const std::string left_label = "  local hashrate:   ";
        os << left_label << fmt_hs(inst) << "   " << art[0] << "\n";
        // Subsequent art lines aligned under the art column
        std::string pad(left_label.size() + 14, ' '); // 14 ~= max size of fmt_hs(inst)
        for(size_t i=1;i<art.size();++i){
            os << pad << "   " << art[i] << "\n";
        }

        os << "  network hashrate: " << fmt_hs(net)  << "\n";
        os << "  mined (session):  " << mined << "\n";
        if(!ui->last_block_hash.empty()){
            os << "  last block:       " << ui->last_block_hash << "\n";
        }
        os << "\n";
        os << "  Press Ctrl+C to quit.\n";

        std::cout << os.str() << std::flush;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

static void nonce_worker(const BlockHeader hdr_base,
                         const Transaction cb,
                         const std::vector<Transaction> txs,
                         uint32_t bits,
                         std::atomic<bool>* found,
                         std::atomic<uint64_t>* tries,
                         unsigned tid, unsigned stride,
                         Block* out_block)
{
    Block b; b.header = hdr_base; b.txs = txs;
    // Precompute merkle root (cb + txs)
    std::vector<std::vector<uint8_t>> ids; ids.reserve(1+txs.size());
    ids.push_back(cb.txid()); for(const auto& t : txs) ids.push_back(t.txid());
    b.header.merkle_root = miq::merkle_root(ids);

    // Each thread starts at a different nonce and strides by thread count
    uint32_t nonce = tid;
    while(!found->load(std::memory_order_relaxed)){
        b.header.nonce = nonce;
        auto h = b.block_hash();
        tries->fetch_add(1, std::memory_order_relaxed);
        if(meets_target_be(h, bits)){
            // winner
            *out_block = b;
            found->store(true, std::memory_order_relaxed);
            return;
        }
        nonce += stride;
    }
}

// === main ====================================================================

static void usage(){
    std::cout <<
    "miqminer_rpc — Solo miner for MIQ (JSON-RPC)\n"
    "Usage: miqminer_rpc [--rpc=host:port] [--token=<Bearer>] [--threads=N]\n"
    "Notes:\n"
    "  * Node must be running. Auth token is taken from MIQ_RPC_TOKEN or datadir/.cookie\n"
    "  * Miner will prompt for a P2PKH Base58 address to receive rewards.\n";
}

int main(int argc, char** argv){
    try{
#if defined(_WIN32)
        // Enable ANSI colors on Windows 10+ consoles
        HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode=0; if (GetConsoleMode(h,&mode)) SetConsoleMode(h, mode | 0x0004 /*ENABLE_VIRTUAL_TERMINAL_PROCESSING*/);
        }
#endif
        std::string rpc_host = "127.0.0.1";
        uint16_t    rpc_port = (uint16_t)RPC_PORT;
        std::string token; // Bearer token
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
        std::string auth_header;
        if(!token.empty()) auth_header = std::string("Bearer ") + token;

        // Prompt for mining address
        std::string addr;
        std::cout << "Enter P2PKH Base58 address to mine to: ";
        if(!std::getline(std::cin, addr)){ std::fprintf(stderr,"stdin closed\n"); return 1; }
        trim(addr);
        std::vector<uint8_t> pkh;
        if(!parse_p2pkh(addr, pkh)){
            std::fprintf(stderr, "Invalid address (expected Base58Check P2PKH, version 0x%02x)\n", (unsigned)VERSION_P2PKH);
            return 1;
        }

        // UI + miner state
        UIState ui;
        Job job;
        std::atomic<bool> got_job{false};

        // UI thread
        std::thread ui_th([&](){
            draw_ui_loop(addr, threads, &job, &got_job, &ui);
        });
        ui_th.detach();

        // Net hash updater thread (every ~5s)
        std::thread nh_th([&](){
            while(true){
                TipInfo t;
                if(rpc_gettipinfo(rpc_host, rpc_port, auth_header, t)){
                    double hs = 0.0;
                    if(!rpc_getminerstats(rpc_host, rpc_port, auth_header, hs)){
                        hs = estimate_network_hashps(rpc_host, rpc_port, auth_header, t.height, t.bits);
                    }
                    ui.net_hashps.store(hs, std::memory_order_relaxed);
                }
                for(int i=0;i<5;i++) miq_sleep_ms(200);
            }
        });
        nh_th.detach();

        // Mining loop: fetch job → mine → submit → repeat
        while(true){
            if(!fetch_job(rpc_host, rpc_port, auth_header, job)){
                std::fprintf(stderr, "RPC gettipinfo failed, retrying...\n");
                miq_sleep_ms(1000);
                continue;
            }
            got_job.store(true, std::memory_order_relaxed);

            // Build coinbase & block header base
            Transaction cb = make_coinbase(job.height, pkh);
            BlockHeader hb;
            hb.version = 1;
            hb.prev_hash = job.prev_hash;
            hb.time = std::max<int64_t>((int64_t)time(nullptr), job.prev_time + 1);
            hb.bits = job.bits;
            hb.nonce = 0;

            // Mine across threads
            std::atomic<bool> found{false};
            std::atomic<uint64_t> tries{0};
            std::vector<std::thread> thv;
            Block found_block;

            // we mine empty block (cb only)
            std::vector<Transaction> txs; txs.push_back(cb);

            for(unsigned tid=0; tid<threads; ++tid){
                thv.emplace_back(nonce_worker, hb, cb, txs, job.bits,
                                 &found, &tries, tid, threads, &found_block);
            }

            // meter: forward tries to UI once per second
            std::thread meter([&](){
                while(!found.load(std::memory_order_relaxed)){
                    ui.hash_tries.store(tries.load(std::memory_order_relaxed), std::memory_order_relaxed);
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
                ui.hash_tries.store(tries.load(std::memory_order_relaxed), std::memory_order_relaxed);
            });
            meter.join();

            for(auto& th : thv) th.join();

            // Submit found block
            auto raw = miq::ser_block(found_block);
            std::string hexblk = miq::to_hex(raw);
            bool ok = rpc_submitblock(rpc_host, rpc_port, auth_header, hexblk);
            if(ok){
                ui.mined_blocks.fetch_add(1, std::memory_order_relaxed);
                ui.last_block_hash = miq::to_hex(found_block.block_hash());
            } else {
                std::fprintf(stderr, "submitblock rejected or RPC error\n");
                // continue anyway (chain may have advanced; next loop will refresh job)
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
