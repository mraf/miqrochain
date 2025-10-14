// src/wallet/p2p_light.cpp
#include "wallet/p2p_light.h"
#include "sha256.h"
#include "constants.h"

#include <cstring>
#include <chrono>
#include <random>
#include <vector>
#include <string>
#include <algorithm>
#include <unordered_set>
#include <thread>   // pacing safeguard
#include <sstream>
#include <cstdlib>
#include <set>

#if defined(__has_include)
#  if __has_include("addrman.h")
#    include "addrman.h"
#    ifndef MIQ_ENABLE_ADDRMAN
#      define MIQ_ENABLE_ADDRMAN 1
#    endif
#  else
#    ifndef MIQ_ENABLE_ADDRMAN
#      define MIQ_ENABLE_ADDRMAN 0
#    endif
#  endif
#else
#  ifndef MIQ_ENABLE_ADDRMAN
#    define MIQ_ENABLE_ADDRMAN 0
#  endif
#endif

#ifndef MIQ_ADDRMAN_FILE
#define MIQ_ADDRMAN_FILE "peers2.dat"
#endif

// hard cap for wallet-side frame sizes (prevents OOM/DoS)
#ifndef MAX_MSG_SIZE
#define MIQ_LIGHT_MAX_MSG_SIZE (2u * 1024u * 1024u)  // 2 MiB fallback
#else
#define MIQ_LIGHT_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  static inline void closesock(uintptr_t s){ if(s!=(uintptr_t)-1) closesocket((SOCKET)s); }
  static inline void set_timeouts(uintptr_t s, int ms){
      if(ms <= 0) return;
      DWORD t = (DWORD)ms;
      setsockopt((SOCKET)s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
      setsockopt((SOCKET)s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
  }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <signal.h>
  static inline void closesock(int s){ if(s>=0) ::close(s); }
  static inline void set_timeouts(int s, int ms){
      if(ms <= 0) return;
      timeval tv{};
      tv.tv_sec  = ms / 1000;
      tv.tv_usec = (ms % 1000) * 1000;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
#endif

namespace miq {

// tiny env helpers
static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v || !*v) return false;
    if(std::strcmp(v,"0")==0) return false;
    if(std::strcmp(v,"false")==0) return false;
    if(std::strcmp(v,"False")==0) return false;
    return true;
}
static std::string env_str(const char* name){
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string();
}

// endian utils
static inline void put_u32_le(std::vector<uint8_t>& b, uint32_t v){
    b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8));
    b.push_back(uint8_t(v>>16)); b.push_back(uint8_t(v>>24));
}
static inline void put_u64_le(std::vector<uint8_t>& b, uint64_t v){
    for(int i=0;i<8;i++) b.push_back(uint8_t(v>>(8*i)));
}
static inline void put_i64_le(std::vector<uint8_t>& b, int64_t v){ put_u64_le(b, (uint64_t)v); }
static inline void put_u16_be(std::vector<uint8_t>& b, uint16_t v){
    b.push_back(uint8_t(v>>8)); b.push_back(uint8_t(v));
}
static void put_varint(std::vector<uint8_t>& b, uint64_t v){
    if (v < 0xFD) { b.push_back(uint8_t(v)); }
    else if (v <= 0xFFFF) { b.push_back(0xFD); b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8)); }
    else if (v <= 0xFFFFFFFFULL) { b.push_back(0xFE); put_u32_le(b, (uint32_t)v); }
    else { b.push_back(0xFF); put_u64_le(b, v); }
}
static bool get_varint(const uint8_t* p, size_t n, uint64_t& v, size_t& used){
    if(n==0) return false;
    uint8_t x = p[0]; used = 1;
    if(x < 0xFD){ v = x; return true; }
    if(x == 0xFD){ if(n<3) return false; v = (uint64_t)p[1] | ((uint64_t)p[2]<<8); used = 3; return true; }
    if(x == 0xFE){ if(n<5) return false; v = (uint64_t)p[1] | ((uint64_t)p[2]<<8) | ((uint64_t)p[3]<<16) | ((uint64_t)p[4]<<24); used = 5; return true; }
    if(x == 0xFF){ if(n<9) return false; uint64_t r=0; for(int i=0;i<8;i++) r |= ((uint64_t)p[1+i]<<(8*i)); v=r; used=9; return true; }
    return false;
}
static std::vector<uint8_t> dsha256_bytes(const uint8_t* data, size_t len){
    std::vector<uint8_t> v(data, data+len);
    return dsha256(v);
}
static uint32_t checksum4(const std::vector<uint8_t>& payload){
    auto d = dsha256(payload);
    return (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
}
static std::string default_port_str(const std::string& port){
    if(!port.empty()) return port;
#ifdef P2P_PORT
    return std::to_string((uint16_t)P2P_PORT);
#else
    return "9833";
#endif
}

// ---- DNS + connect -----------------------------------------------------------

#if MIQ_ENABLE_ADDRMAN
namespace {
    static miq::AddrMan g_addrman;
    static miq::FastRand g_am_rng{0xC0FFEEULL};
    static std::string  g_addrman_path;
    static int64_t      g_last_addrman_save_ms = 0;

    static int64_t now_ms(){
        using namespace std::chrono;
        return (int64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
    }
    static std::string wallet_datadir(){
        std::string d = env_str("MIQ_WALLET_DATADIR");
        if (!d.empty()) return d;
        d = env_str("MIQ_DATADIR");
        if (!d.empty()) return d;
        return std::string(".");
    }
    static void addrman_load_once(){
        if (!g_addrman_path.empty()) return; // already set up
        g_addrman_path = wallet_datadir() + "/" + std::string(MIQ_ADDRMAN_FILE);
        std::string err;
        (void)g_addrman.load(g_addrman_path, err);
        g_last_addrman_save_ms = now_ms();
    }
    static void addrman_save_maybe(){
        int64_t t = now_ms();
        if (t - g_last_addrman_save_ms < 60000) return;
        g_last_addrman_save_ms = t;
        std::string err;
        (void)g_addrman.save(g_addrman_path, err);
    }
    static void addrman_force_save(){
        g_last_addrman_save_ms = 0;
        addrman_save_maybe();
    }
}
#endif // MIQ_ENABLE_ADDRMAN

static std::string peer_ip_string(
#ifdef _WIN32
    uintptr_t fd
#else
    int fd
#endif
){
    char buf[128] = {0};
    sockaddr_storage ss{};
#ifdef _WIN32
    int slen = (int)sizeof(ss);
#else
    socklen_t slen = sizeof(ss);
#endif
    if (getpeername(
#ifdef _WIN32
        (SOCKET)fd,
#else
        fd,
#endif
        (sockaddr*)&ss, &slen) != 0) return "";
    if (ss.ss_family == AF_INET) {
        const sockaddr_in* a = (const sockaddr_in*)&ss;
#ifdef _WIN32
        InetNtopA(AF_INET, (void*)&a->sin_addr, buf, (int)sizeof(buf));
#else
        inet_ntop(AF_INET, (void*)&a->sin_addr, buf, sizeof(buf));
#endif
        return std::string(buf);
    }
    return "";
}

static std::vector<std::string> gather_default_candidates(const std::string& cli_host,
                                                          const std::string& cli_port)
{
    std::vector<std::string> seeds;

    // user-provided host:port first (if any)
    if(!cli_host.empty()){
        if(!cli_port.empty()) seeds.push_back(cli_host + ":" + cli_port);
        else seeds.push_back(cli_host);
    }

#if MIQ_ENABLE_ADDRMAN
    // 1) anchors (sticky last-good peers)
    for (const auto& na : g_addrman.get_anchors()) {
        if (!na.host.empty()) seeds.push_back(na.host + ":" + std::to_string(na.port));
    }
    // 2) try a few outbound selections to diversify
    std::set<std::string> seen;
    for (auto& s : seeds) seen.insert(s);
    for (int i=0; i<8; ++i) {
        auto pick = g_addrman.select_for_outbound(g_am_rng, /*prefer_tried=*/true);
        if (!pick.has_value()) break;
        const auto& na = *pick;
        std::string hp = na.host + ":" + std::to_string(na.port);
        if (seen.insert(hp).second) seeds.push_back(hp);
    }
#endif

    // default fallback
    if(seeds.empty()){
        seeds.push_back("127.0.0.1");
    }
    return seeds;
}

static bool is_public_ipv4_literal(const std::string& s){
    unsigned a,b,c,d; char dot;
    std::istringstream ss(s);
    if(!(ss>>a>>dot>>b>>dot>>c>>dot>>d)) return false;
    if(a==10) return false;
    if(a==127) return false;
    if(a==192 && b==168) return false;
    if(a==172 && (b>=16 && b<=31)) return false;
    if(a==0 || a>=224) return false;
    return true;
}
static bool is_public_ipv6_literal(const std::string& s){
    (void)s; return false; // keep simple
}

static bool resolves_to_public_ip(const std::string& host, const std::string& port){
    if (is_public_ipv4_literal(host) || is_public_ipv6_literal(host)) return true;

    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) return false;
    bool ok = false;
    for (auto p = res; p; p = p->ai_next){
        if (p->ai_family == AF_INET){
            const sockaddr_in* a = (const sockaddr_in*)p->ai_addr;
            uint32_t be = a->sin_addr.s_addr;
            uint8_t A = uint8_t(be>>24), B = uint8_t(be>>16);
            if (A==127) { ok=false; continue; }
            if (A==10)  { ok=false; continue; }
            if (A==192 && B==168) { ok=false; continue; }
            if (A==172 && ((uint8_t(be>>20)&0x0F)>=1 && (uint8_t(be>>20)&0x0F)<=15)) { ok=false; continue; }
            if (A==0 || A>=224) { ok=false; continue; }
            ok = true; break;
        }
    }
    if (res) freeaddrinfo(res);
    return ok;
}

static std::vector<std::string> build_seed_candidates(const std::string& cli_host,
                                                      const std::string& cli_port)
{
    std::vector<std::string> seeds = gather_default_candidates(cli_host, cli_port);
    std::vector<std::string> out; out.reserve(seeds.size());
    const std::string port = default_port_str(cli_port);

    for (auto& hp : seeds){
        auto pos = hp.find(':');
        std::string h = (pos==std::string::npos) ? hp : hp.substr(0,pos);
        std::string p = (pos==std::string::npos) ? port : hp.substr(pos+1);

        // explicit numeric literals always allowed
        if (is_public_ipv4_literal(h) || is_public_ipv6_literal(h)) { out.push_back(h+":"+p); continue; }
        if (h == "127.0.0.1" || h == "localhost") { out.push_back(h+":"+p); continue; }

        if (resolves_to_public_ip(h, p)) out.push_back(h+":"+p);
    }
    if (out.empty()) return seeds;
    return out;
}

static
#ifdef _WIN32
uintptr_t
#else
int
#endif
resolve_and_connect_best(const std::vector<std::string>& candidates,
                         const std::string& port,
                         int timeout_ms,
                         std::string& err,
                         std::string* connected_host=nullptr)
{
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    for (const auto& hp : candidates){
        auto pos = hp.find(':');
        std::string h = (pos==std::string::npos) ? hp : hp.substr(0,pos);
        std::string p = (pos==std::string::npos) ? port : hp.substr(pos+1);

        addrinfo* res=nullptr;
        if (getaddrinfo(h.c_str(), p.c_str(), &hints, &res) != 0) continue;

        for (auto rp = res; rp; rp = rp->ai_next){
#ifdef _WIN32
            SOCKET fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd == INVALID_SOCKET) continue;
            set_timeouts((uintptr_t)fd, timeout_ms);
            if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
                if (connected_host) *connected_host = h;
                if (res) freeaddrinfo(res);
                return (uintptr_t)fd;
            }
            closesocket(fd);
#else
            int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            set_timeouts(fd, timeout_ms);
            if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) {
                if (connected_host) *connected_host = h;
                if (res) freeaddrinfo(res);
                return fd;
            }
            ::close(fd);
#endif
        }
        if (res) freeaddrinfo(res);
    }
    err = "connect failed";
    return
#ifdef _WIN32
        (uintptr_t)-1
#else
        -1
#endif
    ;
}

static
#ifdef _WIN32
uintptr_t
#else
int
#endif
try_local_fallback(const std::string& port, int timeout_ms, std::string* used_host){
    // Try loopback explicitly if everything else fails
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res=nullptr;
    if (getaddrinfo("127.0.0.1", port.c_str(), &hints, &res) != 0) return
#ifdef _WIN32
        (uintptr_t)-1
#else
        -1
#endif
    ;
    for (auto p = res; p; p = p->ai_next){
#ifdef _WIN32
        SOCKET fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCKET) continue;
        set_timeouts((uintptr_t)fd, timeout_ms);
        if (connect(fd, p->ai_addr, (int)p->ai_addrlen) == 0) {
            if (used_host) *used_host = "127.0.0.1";
            if (res) freeaddrinfo(res);
            return (uintptr_t)fd;
        }
        closesocket(fd);
#else
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        set_timeouts(fd, timeout_ms);
        if (connect(fd, p->ai_addr, (int)p->ai_addrlen) == 0) {
            if (used_host) *used_host = "127.0.0.1";
            if (res) freeaddrinfo(res);
            return fd;
        }
        ::close(fd);
#endif
    }
    if (res) freeaddrinfo(res);
    return
#ifdef _WIN32
        (uintptr_t)-1
#else
        -1
#endif
    ;
}

// ---- class -------------------------------------------------------------------
P2PLight::P2PLight(){}
P2PLight::~P2PLight(){ close(); }

bool P2PLight::connect_and_handshake(const P2POpts& opts, std::string& err){
    o_ = opts;

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

#if MIQ_ENABLE_ADDRMAN
    addrman_load_once();
#endif

#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    // Build candidate list (public first, then local)
    auto candidates = build_seed_candidates(o_.host, o_.port);
    const std::string port = default_port_str(o_.port);

    // 1) Try public/DNS/addrman seeds first
    std::string used_host;
    sock_ = resolve_and_connect_best(candidates, port, o_.io_timeout_ms, err, &used_host);

    // 2) Smart local fallback
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1 && !env_truthy("MIQ_NO_LOCAL_FALLBACK")) {
        auto fd_local = try_local_fallback(port, o_.io_timeout_ms, &used_host);
        if (fd_local != (uintptr_t)-1) { sock_ = fd_local; err.clear(); }
    }
    if (sock_ == (uintptr_t)-1) return false;
#else
    if (sock_ < 0 && !env_truthy("MIQ_NO_LOCAL_FALLBACK")) {
        auto fd_local = try_local_fallback(port, o_.io_timeout_ms, &used_host);
        if (fd_local >= 0) { sock_ = fd_local; err.clear(); }
    }
    if (sock_ < 0) return false;
#endif

#if MIQ_ENABLE_ADDRMAN
    // mark as good/anchor
    {
        std::string ip = peer_ip_string(sock_);
        if (ip.empty()) ip = used_host;
        if (!ip.empty()) {
            NetAddr na; na.host = ip; na.port = (uint16_t)std::stoi(port); na.tried = true;
            g_addrman.add(na, /*from_dns=*/false);
            addrman_force_save();
        }
    }
#endif

    // Version/verack handshake (with fallback)
    if(!send_version(err))      { close(); return false; }

    if (o_.send_verack) {
        std::vector<uint8_t> empty;
        if(!send_msg("verack", empty, err)) { close(); return false; }
    }

    if(!read_until_verack(err)) {
        // Fallback path: some nodes accept empty "version" first; try once.
        std::vector<uint8_t> empty;
        std::string e2;
        (void)send_msg("version", empty, e2);
        if (o_.send_verack) (void)send_msg("verack", empty, e2);
        if(!read_until_verack(err)) { close(); return false; }
    }

    // Opportunistic getaddr (let node trickle peers to wallet addrman)
    { std::string e2; (void)send_getaddr(e2); }

    header_hashes_le_.clear();
    return true;
}

void P2PLight::close(){
#ifdef _WIN32
    if (sock_ != (uintptr_t)-1){
        closesock(sock_);
        sock_ = (uintptr_t)-1;
    }
    WSACleanup();
#else
    if (sock_ >= 0){
        closesock(sock_);
        sock_ = -1;
    }
#endif
#if MIQ_ENABLE_ADDRMAN
    addrman_force_save();
#endif
}

// ---- headers sync ------------------------------------------------------------
bool P2PLight::get_best_header(uint32_t& tip_height, std::vector<uint8_t>& tip_hash_le, std::string& err){
    tip_height = 0; tip_hash_le.clear();
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1){ err = "not connected"; return false; }
#else
    if (sock_ < 0){ err = "not connected"; return false; }
#endif

    // Cached?
    if(!header_hashes_le_.empty()){
        tip_height = (uint32_t)(header_hashes_le_.size() - 1);
        tip_hash_le = header_hashes_le_.back();
        return true;
    }

    // Start from genesis locator (daemon format): u8 count + hashes + stop(32x00)
    std::vector<std::vector<uint8_t>> locator;
    locator.emplace_back(32, 0x00);
    std::vector<uint8_t> stop(32, 0x00);

    while(true){
        if(!request_headers_from_locator(locator, stop, err)) return false;

        std::vector<std::vector<uint8_t>> batch;
        if(!read_headers_batch(batch, err)) return false;

        if(batch.empty()){
            // No more headers; at tip.
            break;
        }

        // Append
        for(auto& h : batch) header_hashes_le_.push_back(std::move(h));

        // New locator = last hash (simple)
        locator.clear();
        locator.push_back(header_hashes_le_.back());
    }

    if(header_hashes_le_.empty()){
        err = "headers sync returned none";
        return false;
    }

    tip_height = (uint32_t)(header_hashes_le_.size() - 1);
    tip_hash_le = header_hashes_le_.back();
    return true;
}

// Daemon getheaders: [u8 count][count*32 hashes][32 stop]
bool P2PLight::request_headers_from_locator(
    const std::vector<std::vector<uint8_t>>& locator_hashes_le,
    std::vector<uint8_t>& stop_le,
    std::string& err)
{
    // our node expects: [u8 count] [32*count hashes (LE)] [32 stop hash]
    uint8_t n = (uint8_t)std::min<size_t>(locator_hashes_le.size(), 255);
    if (n == 0) {
        // if none provided, send just the all-zero genesis stop as a locator of size 1
        n = 1;
    }

    std::vector<uint8_t> payload;
    payload.reserve(1 + 32 * n + 32);
    payload.push_back(n);

    if (locator_hashes_le.empty()) {
        // push one zero hash as a minimal locator
        payload.insert(payload.end(), 32, 0x00);
    } else {
        for (size_t i = 0; i < n; ++i) {
            const auto& h = locator_hashes_le[i];
            if (h.size() != 32) { err = "bad locator hash size"; return false; }
            payload.insert(payload.end(), h.begin(), h.end()); // LE on wire
        }
    }

    // stop hash (32 bytes; zero means "no stop")
    if (stop_le.size() != 32) {
        stop_le.assign(32, 0x00);
    }
    payload.insert(payload.end(), stop_le.begin(), stop_le.end());

    if (!send_msg("getheaders", payload, err)) return false;
    return true;
}

// Accepts daemon-style headers (u16 + count*88 bytes) and Bitcoin-style (varint + 80 + varint txcount=0).
bool P2PLight::read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le, std::string& err){
    out_hashes_le.clear();
    for(;;){
        std::string cmd; uint32_t len=0, csum=0;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        // hard cap to avoid huge allocations/DoS
        if (len > MIQ_LIGHT_MAX_MSG_SIZE) { err = "frame too large"; return false; }

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd == "ping"){
            std::string e; send_msg("pong", payload, e);
#if MIQ_ENABLE_ADDRMAN
            addrman_save_maybe();
#endif
            continue;
        }

        if(cmd == "addr"){
#if MIQ_ENABLE_ADDRMAN
            // payload: 4*N IPv4s (daemon compact form)
            if (!payload.empty() && (payload.size() % 4) == 0){
                size_t n = payload.size()/4;
                int added = 0;
                for(size_t i=0;i<n;i++){
                    uint32_t be_ip =
                        (uint32_t(payload[4*i+0])<<24) |
                        (uint32_t(payload[4*i+1])<<16) |
                        (uint32_t(payload[4*i+2])<<8 ) |
                        (uint32_t(payload[4*i+3])<<0 );
                    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip;
                    char buf[64]={0};
#ifdef _WIN32
                    InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
                    inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
                    if (buf[0]) {
                        NetAddr na;
                        na.host = buf;
                        na.port = (uint16_t)std::stoi(default_port_str(o_.port));
                        na.is_ipv6 = false;
                        na.tried = false;
                        g_addrman.add(na, /*from_dns=*/false);
                        ++added;
                    }
                }
                if (added) addrman_force_save();
            }
#endif
            continue;
        }

        if(cmd != "headers"){
            // unrelated message during headers phase; ignore
            continue;
        }

        // Two supported shapes:

        // (A) daemon compact headers: u16 count; count * 88-byte headers (no txcount)
        if (payload.size() >= 2) {
            uint16_t count = (uint16_t)payload[0] | ((uint16_t)payload[1]<<8);

            size_t need80 = 2 + (size_t)count * 80;
            if (payload.size() == need80) {
                out_hashes_le.reserve(count);
                const uint8_t* p = payload.data() + 2;
                for (uint16_t i=0;i<count;i++){
                    auto h = dsha256_bytes(p, 80);     // legacy 80-byte compact (if ever used)
                    out_hashes_le.push_back(std::move(h));
                    p += 80;
                }
                return true;
            }

            size_t need88 = 2 + (size_t)count * 88;
            if (payload.size() == need88) {
                out_hashes_le.reserve(count);
                const uint8_t* p = payload.data() + 2;
                for (uint16_t i=0;i<count;i++){
                    auto h = dsha256_bytes(p, 88);     // **FIX** hash full 88-byte header
                    out_hashes_le.push_back(std::move(h)); // keep LE
                    p += 88; // skip padded segment
                }
                return true;
            }
        }

        // (B) Bitcoin headers: varint count; for each: 80 byte header + varint(0) for txn count
        if (!payload.empty()){
            uint64_t count=0; size_t used=0;
            if (get_varint(payload.data(), payload.size(), count, used)){
                size_t need = used + (size_t)count*(80 + 1); // each header + txcount=0 (varint)
                if (payload.size() >= need){
                    out_hashes_le.reserve((size_t)count);
                    const uint8_t* p = payload.data() + used;
                    for (uint64_t i=0;i<count;i++){
                        auto h = dsha256_bytes(p, 80);   // Bitcoin 80-byte header
                        out_hashes_le.push_back(std::move(h)); // keep LE
                        // skip 80-byte header
                        p += 80;
                        // skip varint (we expect 0x00)
                        if (*p == 0x00) { p += 1; } else {
                            uint64_t dummy=0; size_t u2=0; if(!get_varint(p, (payload.data()+payload.size())-p, dummy, u2)) break; p += u2;
                        }
                    }
                    return true;
                }
            }
        }

        err = "unrecognized headers payload shape";
        return false;
    }
}

// ---- recent blocks listing (no filters) --------------------------------------
bool P2PLight::match_recent_blocks(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                                   uint32_t from_height,
                                   uint32_t to_height,
                                   std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& matched,
                                   std::string& err)
{
    matched.clear();
    (void)err;

    // Ensure we have headers
    uint32_t tip=0; std::vector<uint8_t> tip_hash;
    if(!get_best_header(tip, tip_hash, err)) return false;

    if(to_height > tip) to_height = tip;
    if(from_height > to_height) return true; // empty window

    for(uint32_t h = from_height; h <= to_height; ++h){
        matched.emplace_back(header_hashes_le_[h], h);
    }
    return true;
}

// ---- block fetch (daemon uses `getb`) ----------------------------------------
bool P2PLight::get_block_by_hash(const std::vector<uint8_t>& hash_le,
                                 std::vector<uint8_t>& raw_block,
                                 std::string& err)
{
    raw_block.clear();
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1){ err = "not connected"; return false; }
#else
    if (sock_ < 0){ err = "not connected"; return false; }
#endif
    if (hash_le.size()!=32){ err = "hash_le must be 32 bytes"; return false; }

    if(!send_msg("getb", hash_le, err)) return false;

    // read messages until we get "block"
    for(;;){
        std::string cmd; uint32_t len=0, csum=0;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        // cap again in this loop
        if (len > MIQ_LIGHT_MAX_MSG_SIZE) { err = "frame too large"; return false; }

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd=="ping"){
            std::string e; send_msg("pong", payload, e);
#if MIQ_ENABLE_ADDRMAN
            addrman_save_maybe();
#endif
            continue;
        }
        if(cmd=="addr"){
#if MIQ_ENABLE_ADDRMAN
            if (!payload.empty() && (payload.size() % 4) == 0){
                size_t n = payload.size()/4;
                int added = 0;
                for(size_t i=0;i<n;i++){
                    uint32_t be_ip =
                        (uint32_t(payload[4*i+0])<<24) |
                        (uint32_t(payload[4*i+1])<<16) |
                        (uint32_t(payload[4*i+2])<<8 ) |
                        (uint32_t(payload[4*i+3])<<0 );
                    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip;
                    char buf[64]={0};
#ifdef _WIN32
                    InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
                    inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
                    if (buf[0]) {
                        NetAddr na;
                        na.host = buf;
                        na.port = (uint16_t)std::stoi(default_port_str(o_.port));
                        na.is_ipv6 = false;
                        na.tried = false;
                        g_addrman.add(na, /*from_dns=*/false);
                        ++added;
                    }
                }
                if (added) addrman_force_save();
            }
#endif
            continue;
        }
        if(cmd=="block"){
            // pacing: avoid tight loops when peers stream responses quickly
            static uint32_t s_cnt = 0;
            if((++s_cnt % 64) == 0){
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }

            raw_block = std::move(payload);
#if MIQ_ENABLE_ADDRMAN
            addrman_save_maybe();
#endif
            return true;
        }
        // ignore others
    }
}

// ---- internals: version/verack and IO ----------------------------------------
bool P2PLight::send_version(std::string& err){
    // Build a Bitcoin-like "version" payload; daemon ignores extras.
    std::vector<uint8_t> p;

    const int32_t  version   = 70015;
    const uint64_t services  = 0;
    const int64_t  timestamp = (int64_t) (std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1));

    // remote addr (ignored by most)
    const uint64_t srv_recv = 0;
    uint8_t ip_zero[16]{}; // ::0
    const uint16_t port_recv = (uint16_t)std::stoi(default_port_str(o_.port));

    // local addr
    const uint64_t srv_from = 0;
    const uint16_t port_from = 0;

    // random nonce
    std::mt19937_64 rng{std::random_device{}()};
    uint64_t nonce = rng();

    // version
    put_u32_le(p, (uint32_t)version);
    put_u64_le(p, services);
    put_i64_le(p, timestamp);
    put_u64_le(p, srv_recv);
    p.insert(p.end(), ip_zero, ip_zero+16);
    put_u16_be(p, port_recv);

    put_u64_le(p, srv_from);
    p.insert(p.end(), ip_zero, ip_zero+16);
    put_u16_be(p, port_from);

    put_u64_le(p, nonce);
    // user agent
    {
        std::string ua = o_.user_agent.empty() ? "/miqwallet:0.1/" : o_.user_agent;
        if (ua.size() < 0xFD) { p.push_back((uint8_t)ua.size()); }
        else { put_varint(p, (uint64_t)ua.size()); }
        p.insert(p.end(), ua.begin(), ua.end());
    }
    put_u32_le(p, o_.start_height);
    p.push_back(1); // relay = true

    return send_msg("version", p, err);
}

bool P2PLight::read_until_verack(std::string& err){
    // Read a few messages, stop when we see verack.
    for (int i=0;i<50;i++){
        std::string cmd; uint32_t len=0, csum=0;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        // cap to avoid allocating attacker-chosen size during handshake
        if (len > MIQ_LIGHT_MAX_MSG_SIZE) { err = "frame too large"; return false; }

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd=="verack") return true;
        if(cmd=="ping"){ std::string e; send_msg("pong", payload, e); }
#if MIQ_ENABLE_ADDRMAN
        if(cmd=="addr"){
            if (!payload.empty() && (payload.size() % 4) == 0){
                size_t n = payload.size()/4;
                int added = 0;
                for(size_t i=0;i<n;i++){
                    uint32_t be_ip =
                        (uint32_t(payload[4*i+0])<<24) |
                        (uint32_t(payload[4*i+1])<<16) |
                        (uint32_t(payload[4*i+2])<<8 ) |
                        (uint32_t(payload[4*i+3])<<0 );
                    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip;
                    char buf[64]={0};
#ifdef _WIN32
                    InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
                    inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
                    if (buf[0]) {
                        NetAddr na; na.host=buf; na.port=(uint16_t)std::stoi(default_port_str(o_.port)); na.is_ipv6=false; na.tried=false;
                        g_addrman.add(na, /*from_dns=*/false);
                        ++added;
                    }
                }
                if (added) addrman_force_save();
            }
        }
#endif
        // ignore other msgs in handshake window
    }
    err = "no verack from peer";
    return false;
}

bool P2PLight::send_tx(const std::vector<uint8_t>& tx_bytes, std::string& err){
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1) { err = "not connected"; return false; }
#else
    if (sock_ < 0) { err = "not connected"; return false; }
#endif
    return send_msg("tx", tx_bytes, err);
}

bool P2PLight::send_getaddr(std::string& err){
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1) { err = "not connected"; return false; }
#else
    if (sock_ < 0) { err = "not connected"; return false; }
#endif
    std::vector<uint8_t> empty;
    return send_msg("getaddr", empty, err);
}

bool P2PLight::send_msg(const char cmd12[12], const std::vector<uint8_t>& payload, std::string& err){
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1) { err = "not connected"; return false; }
#else
    if (sock_ < 0) { err = "not connected"; return false; }
#endif

    uint8_t header[24]{};
    // MAGIC: write canonical big-endian wire bytes
    header[0] = miq::MAGIC_BE[0];
    header[1] = miq::MAGIC_BE[1];
    header[2] = miq::MAGIC_BE[2];
    header[3] = miq::MAGIC_BE[3];

    // command (null-padded to 12)
    for (int i=0;i<12 && cmd12[i]; ++i) header[4+i] = (uint8_t)cmd12[i];

    // length
    uint32_t L = (uint32_t)payload.size();
    header[16]=uint8_t(L); header[17]=uint8_t(L>>8); header[18]=uint8_t(L>>16); header[19]=uint8_t(L>>24);

    // checksum
    uint32_t c = checksum4(payload);
    header[20]=uint8_t(c); header[21]=uint8_t(c>>8); header[22]=uint8_t(c>>16); header[23]=uint8_t(c>>24);

#ifdef _WIN32
    int n1 = send((SOCKET)sock_, (const char*)header, (int)sizeof(header), 0);
    if(n1 != (int)sizeof(header)) { err = "send failed"; return false; }
    if(L>0){
        int n2 = send((SOCKET)sock_, (const char*)payload.data(), (int)L, 0);
        if(n2 != (int)L){ err = "send failed"; return false; }
    }
#else
    std::string e;
    if(!write_all(header, sizeof(header), e)) { err = e; return false; }
    if(L>0 && !write_all(payload.data(), L, e)) { err = e; return false; }
#endif
    return true;
}

bool P2PLight::read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err){
    uint8_t h[24];
    if(!read_exact(h, 24, err)) return false;

    // MAGIC: compare exactly to canonical big-endian wire bytes
    if (std::memcmp(h, miq::MAGIC_BE, 4) != 0) { err = "bad magic"; return false; }

    char cmd[13]; std::memset(cmd, 0, sizeof(cmd));
    std::memcpy(cmd, h+4, 12);
    cmd_out = std::string(cmd);

    len_out  = (uint32_t)h[16] | ((uint32_t)h[17]<<8) | ((uint32_t)h[18]<<16) | ((uint32_t)h[19]<<24);
    csum_out = (uint32_t)h[20] | ((uint32_t)h[21]<<8) | ((uint32_t)h[22]<<16) | ((uint32_t)h[23]<<24);
    return true;
}

bool P2PLight::read_exact(void* buf, size_t len, std::string& err){
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len){
#ifdef _WIN32
        int n = recv((SOCKET)sock_, (char*)p + (int)got, (int)(len - (int)got), 0);
#else
        ssize_t n = recv(sock_, p + got, len - got, 0);
#endif
        if (n <= 0) { err = "recv failed"; return false; }
        got += (size_t)n;
    }
    return true;
}

bool P2PLight::write_all(const void* buf, size_t len, std::string& err){
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len){
#ifdef _WIN32
        int n = send((SOCKET)sock_, (const char*)p + (int)sent, (int)(len - (int)sent), 0);
#else
        ssize_t n = send(sock_, p + sent, len - sent, 0);
#endif
        if (n <= 0) { err = "send failed"; return false; }
        sent += (size_t)n;
    }
    return true;
}

}
