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
#include <iostream> // for debug output
#include <atomic>   // for WSA reference counting

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

// extra safety: verify header checksums on receive (when present)
#ifndef MIQ_LIGHT_VERIFY_CSUM
#define MIQ_LIGHT_VERIFY_CSUM 1
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
  // Connect with timeout on Windows
  static inline bool connect_with_timeout(uintptr_t s, const sockaddr* addr, int addrlen, int timeout_ms) {
      if (timeout_ms <= 0) {
          return connect((SOCKET)s, addr, addrlen) == 0;
      }
      // Set non-blocking
      u_long mode = 1;
      ioctlsocket((SOCKET)s, FIONBIO, &mode);

      int res = connect((SOCKET)s, addr, addrlen);
      if (res == 0) {
          mode = 0; ioctlsocket((SOCKET)s, FIONBIO, &mode);
          return true;
      }
      if (WSAGetLastError() != WSAEWOULDBLOCK) {
          mode = 0; ioctlsocket((SOCKET)s, FIONBIO, &mode);
          return false;
      }

      // Wait for connection with timeout
      fd_set writefds;
      FD_ZERO(&writefds);
      FD_SET((SOCKET)s, &writefds);
      timeval tv;
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;

      if (select(0, nullptr, &writefds, nullptr, &tv) <= 0) {
          mode = 0; ioctlsocket((SOCKET)s, FIONBIO, &mode);
          return false;
      }

      // Check if connection succeeded
      int err = 0;
      int len = sizeof(err);
      getsockopt((SOCKET)s, SOL_SOCKET, SO_ERROR, (char*)&err, &len);
      mode = 0; ioctlsocket((SOCKET)s, FIONBIO, &mode);
      return err == 0;
  }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <signal.h>
  #include <fcntl.h>
  #include <errno.h>
  #include <sys/select.h>
  static inline void closesock(int s){ if(s>=0) ::close(s); }
  static inline void set_timeouts(int s, int ms){
      if(ms <= 0) return;
      timeval tv{};
      tv.tv_sec  = ms / 1000;
      tv.tv_usec = (ms % 1000) * 1000;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
  // Connect with timeout on Unix
  static inline bool connect_with_timeout(int s, const sockaddr* addr, socklen_t addrlen, int timeout_ms) {
      if (timeout_ms <= 0) {
          return connect(s, addr, addrlen) == 0;
      }
      // Set non-blocking
      int flags = fcntl(s, F_GETFL, 0);
      fcntl(s, F_SETFL, flags | O_NONBLOCK);

      int res = connect(s, addr, addrlen);
      if (res == 0) {
          fcntl(s, F_SETFL, flags);
          return true;
      }
      if (errno != EINPROGRESS) {
          fcntl(s, F_SETFL, flags);
          return false;
      }

      // Wait for connection with timeout
      fd_set writefds;
      FD_ZERO(&writefds);
      FD_SET(s, &writefds);
      timeval tv;
      tv.tv_sec = timeout_ms / 1000;
      tv.tv_usec = (timeout_ms % 1000) * 1000;

      if (select(s + 1, nullptr, &writefds, nullptr, &tv) <= 0) {
          fcntl(s, F_SETFL, flags);
          return false;
      }

      // Check if connection succeeded
      int err = 0;
      socklen_t len = sizeof(err);
      getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len);
      fcntl(s, F_SETFL, flags);
      return err == 0;
  }
#endif

namespace miq {

static constexpr uint32_t CSUM_NONE = 0xFFFFFFFFu; // sentinel: legacy header (no checksum)

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
    return std::to_string((uint16_t)miq::P2P_PORT);
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

    // No default localhost fallback - the caller's seed list should be used
    // If empty, connection will fail with a clear error
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
            // Extract bytes in network order (first octet at lowest address)
            const uint8_t* b = (const uint8_t*)&a->sin_addr;
            uint8_t A = b[0], B = b[1];
            if (A==127) { continue; }  // loopback - skip but don't fail
            if (A==10)  { continue; }  // private 10/8
            if (A==192 && B==168) { continue; }  // private 192.168/16
            if (A==172 && B>=16 && B<=31) { continue; }  // private 172.16-31
            if (A==0 || A>=224) { continue; }  // invalid/multicast
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
    std::vector<std::string> out; out.reserve(seeds.size() + 2);
    const std::string port = default_port_str(cli_port);

    // Always include CLI-provided host first without filtering
    // This ensures explicit user-specified hosts are tried
    if (!cli_host.empty()) {
        std::string p = cli_port.empty() ? port : cli_port;
        out.push_back(cli_host + ":" + p);
    }

    for (auto& hp : seeds){
        auto pos = hp.find(':');
        std::string h = (pos==std::string::npos) ? hp : hp.substr(0,pos);
        std::string p = (pos==std::string::npos) ? port : hp.substr(pos+1);

        // Skip if already added as CLI host
        if (!cli_host.empty() && h == cli_host) continue;

        // explicit numeric literals always allowed
        if (is_public_ipv4_literal(h) || is_public_ipv6_literal(h)) { out.push_back(h+":"+p); continue; }
        if (h == "127.0.0.1" || h == "localhost") { out.push_back(h+":"+p); continue; }

        if (resolves_to_public_ip(h, p)) out.push_back(h+":"+p);
    }

    // ALWAYS add localhost as final fallback for same-machine operation
    // This ensures wallet works when running alongside the node
    bool has_localhost = false;
    for (const auto& hp : out) {
        if (hp.find("127.0.0.1") != std::string::npos || hp.find("localhost") != std::string::npos) {
            has_localhost = true;
            break;
        }
    }
    if (!has_localhost && !env_truthy("MIQ_NO_LOCAL_FALLBACK")) {
        out.push_back("127.0.0.1:" + port);
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
    if (candidates.empty()) {
        err = "no seed nodes available";
        return
#ifdef _WIN32
            (uintptr_t)-1
#else
            -1
#endif
        ;
    }
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
            if (connect_with_timeout((uintptr_t)fd, rp->ai_addr, (int)rp->ai_addrlen, timeout_ms)) {
                set_timeouts((uintptr_t)fd, timeout_ms);
                if (connected_host) *connected_host = h;
                if (res) freeaddrinfo(res);
                return (uintptr_t)fd;
            }
            closesocket(fd);
#else
            int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
            if (fd < 0) continue;
            if (connect_with_timeout(fd, rp->ai_addr, rp->ai_addrlen, timeout_ms)) {
                set_timeouts(fd, timeout_ms);
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
        if (connect_with_timeout((uintptr_t)fd, p->ai_addr, (int)p->ai_addrlen, timeout_ms)) {
            set_timeouts((uintptr_t)fd, timeout_ms);
            if (used_host) *used_host = "127.0.0.1";
            if (res) freeaddrinfo(res);
            return (uintptr_t)fd;
        }
        closesocket(fd);
#else
        int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) continue;
        if (connect_with_timeout(fd, p->ai_addr, p->ai_addrlen, timeout_ms)) {
            set_timeouts(fd, timeout_ms);
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
    // Use static reference counting for WSAStartup/Cleanup
    static std::atomic<int> wsa_refcount{0};
    if (wsa_refcount.fetch_add(1) == 0) {
        WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
    }
#endif

    // Build candidate list (public first, then local)
    auto candidates = build_seed_candidates(o_.host, o_.port);
    const std::string port = default_port_str(o_.port);

    // 1) Try public/DNS/addrman seeds first
    std::string used_host;
    sock_ = resolve_and_connect_best(candidates, port, o_.io_timeout_ms, err, &used_host);

    // 2) Local fallback - ALWAYS try localhost if connection failed
    // This enables wallet to work on the same machine as the node
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

    // Version/verack handshake (with tolerance + fallback)
    // Debug: show socket descriptor for diagnostics
    bool verbose_debug = (std::getenv("MIQ_DEBUG_P2P") != nullptr);
    if (verbose_debug) {
#ifdef _WIN32
        std::cerr << "[DEBUG] Socket fd=" << sock_ << ", timeout=" << o_.io_timeout_ms << "ms\n";
#else
        std::cerr << "[DEBUG] Socket fd=" << sock_ << ", timeout=" << o_.io_timeout_ms << "ms\n";
#endif
    }

    if(!send_version(err)) {
        if (verbose_debug) std::cerr << "[DEBUG] send_version failed: " << err << "\n";
        close(); return false;
    }
    if (verbose_debug) std::cerr << "[DEBUG] sent version message\n";

    if (o_.send_verack) {
        std::vector<uint8_t> empty;
        if(!send_msg("verack", empty, err)) {
            if (verbose_debug) std::cerr << "[DEBUG] send verack failed: " << err << "\n";
            close(); return false;
        }
        if (verbose_debug) std::cerr << "[DEBUG] sent verack message\n";
    }

    if (verbose_debug) std::cerr << "[DEBUG] waiting for peer verack...\n";
    if(!read_until_verack(err)) {
        if (verbose_debug) std::cerr << "[DEBUG] first read_until_verack failed: " << err << "\n";
        // Fallback path: try once with an empty "version" for quirky peers.
        std::vector<uint8_t> empty;
        std::string e2;
        (void)send_msg("version", empty, e2);
        if (o_.send_verack) (void)send_msg("verack", empty, e2);
        if(!read_until_verack(err)) {
            if (verbose_debug) std::cerr << "[DEBUG] fallback read_until_verack failed: " << err << "\n";
            close(); return false;
        }
    }
    if (verbose_debug) std::cerr << "[DEBUG] handshake completed successfully\n";

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
    // Match the static refcount from connect_and_handshake
    // Note: We don't call WSACleanup here to avoid process-wide issues.
    // WSA will be cleaned up when the process exits.
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

    // Progress guards to stop "endless getheaders" loops
    const size_t kMaxLoops = 2048;
    size_t loops = 0;

    // Track progress to detect stalls
    size_t last_count = 0;
    int stall_count = 0;
    const int kMaxStalls = 5;

    while(true){
        if (++loops > kMaxLoops) {
            err = "headers sync aborted (too many rounds without convergence)";
            return false;
        }

        if(!request_headers_from_locator(locator, stop, err)) return false;

        // small pacing to avoid hammering peers (helps interop with slow links)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

        std::vector<std::vector<uint8_t>> batch;
        if(!read_headers_batch(batch, err)) return false;

        // If peer signals "no more" (count==0), we're at tip.
        if(batch.empty()){
            break;
        }

        // If peer repeated the same last hash as previous round, treat as tip (prevents endless churn)
        if(!header_hashes_le_.empty() && !batch.empty()){
            const auto& prev = header_hashes_le_.back();
            const auto& now  = batch.back();
            if (prev.size()==32 && now.size()==32 && std::equal(prev.begin(), prev.end(), now.begin())) {
                break;
            }
        }

        // Append (dedupe within this batch as a courtesy)
        for(auto& h : batch){
            if(header_hashes_le_.empty() || !std::equal(header_hashes_le_.back().begin(), header_hashes_le_.back().end(), h.begin())){
                header_hashes_le_.push_back(std::move(h));
            }
        }

        // Check for stalls (no progress)
        if(header_hashes_le_.size() == last_count){
            if(++stall_count >= kMaxStalls){
                err = "headers sync stalled (no progress after " + std::to_string(kMaxStalls) + " attempts)";
                return false;
            }
        } else {
            stall_count = 0;
            last_count = header_hashes_le_.size();
        }

        // New locator = last hash (simple linear advance)
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
        n = 1;
    }

    std::vector<uint8_t> payload;
    payload.reserve(1 + 32 * n + 32);
    payload.push_back(n);

    if (locator_hashes_le.empty()) {
        payload.insert(payload.end(), 32, 0x00);
    } else {
        for (size_t i = 0; i < n; ++i) {
            const auto& h = locator_hashes_le[i];
            if (h.size() != 32) { err = "bad locator hash size"; return false; }
            payload.insert(payload.end(), h.begin(), h.end()); // LE on wire
        }
    }

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
        std::string cmd; uint32_t len=0, csum=CSUM_NONE;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        if (len > MIQ_LIGHT_MAX_MSG_SIZE) { err = "frame too large"; return false; }

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

#if MIQ_LIGHT_VERIFY_CSUM
        if (csum != CSUM_NONE) {
            if (checksum4(payload) != csum) { err = "bad checksum"; return false; }
        }
#endif

        if(cmd == "ping"){
            std::string e; send_msg("pong", payload, e);
#if MIQ_ENABLE_ADDRMAN
            addrman_save_maybe();
#endif
            continue;
        }

        if(cmd == "addr"){
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

        if(cmd != "headers"){
            continue;
        }

        // Two supported shapes:

        // (A) daemon compact headers: u16 count; count * 88-byte headers (no txcount)
        if (payload.size() >= 2) {
            uint16_t count = (uint16_t)payload[0] | ((uint16_t)payload[1]<<8);

            // exact 2 + 80*N (legacy) support
            size_t need80 = 2 + (size_t)count * 80;
            if (payload.size() == need80) {
                out_hashes_le.reserve(count);
                const uint8_t* p = payload.data() + 2;
                for (uint16_t i=0;i<count;i++){
                    auto h = dsha256_bytes(p, 80);
                    out_hashes_le.push_back(std::move(h));
                    p += 80;
                }
                return true;
            }

            // preferred 2 + 88*N (current daemon wire)
            size_t need88 = 2 + (size_t)count * 88;
            if (payload.size() == need88) {
                out_hashes_le.reserve(count);
                const uint8_t* p = payload.data() + 2;
                for (uint16_t i=0;i<count;i++){
                    auto h = dsha256_bytes(p, 88);
                    out_hashes_le.push_back(std::move(h));
                    p += 88;
                }
                return true;
            }
        }

        // (B) Bitcoin headers: varint count; for each: 80 byte header + varint(0)
        if (!payload.empty()){
            uint64_t count=0; size_t used=0;
            if (get_varint(payload.data(), payload.size(), count, used)){
                size_t need = used + (size_t)count*(80 + 1); // each header + txcount=0
                if (payload.size() >= need){
                    out_hashes_le.reserve((size_t)count);
                    const uint8_t* p = payload.data() + used;
                    for (uint64_t i=0;i<count;i++){
                        auto h = dsha256_bytes(p, 80);
                        out_hashes_le.push_back(std::move(h));
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

    // Ensure we have headers
    uint32_t tip=0; std::vector<uint8_t> tip_hash;
    if(!get_best_header(tip, tip_hash, err)) return false;

    // Validate header cache is populated
    if(header_hashes_le_.empty()){
        err = "header cache is empty after sync";
        return false;
    }

    // Clamp range to available headers
    if(to_height > tip) to_height = tip;
    if(from_height > to_height) return true; // empty window

    // Additional safety: ensure we don't exceed vector bounds
    size_t max_idx = header_hashes_le_.size() - 1;
    if(to_height > (uint32_t)max_idx) to_height = (uint32_t)max_idx;
    if(from_height > to_height) return true;

    // Reserve space for efficiency
    matched.reserve(to_height - from_height + 1);

    for(uint32_t h = from_height; h <= to_height; ++h){
        if(h < header_hashes_le_.size()){
            matched.emplace_back(header_hashes_le_[h], h);
        } else {
            // Should not happen due to bounds check above, but be safe
            err = "internal error: height " + std::to_string(h) + " exceeds header cache";
            return false;
        }
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
        std::string cmd; uint32_t len=0, csum=CSUM_NONE;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        if (len > MIQ_LIGHT_MAX_MSG_SIZE) { err = "frame too large"; return false; }

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

#if MIQ_LIGHT_VERIFY_CSUM
        if (csum != CSUM_NONE) {
            if (checksum4(payload) != csum) { err = "bad checksum"; return false; }
        }
#endif

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
        std::string cmd; uint32_t len=0, csum=CSUM_NONE;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        if (len > MIQ_LIGHT_MAX_MSG_SIZE) { err = "frame too large"; return false; }

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

#if MIQ_LIGHT_VERIFY_CSUM
        if (csum != CSUM_NONE) {
            if (checksum4(payload) != csum) { err = "bad checksum"; return false; }
        }
#endif

        if(cmd=="verack") return true;
        if(cmd=="ping"){ std::string e; send_msg("pong", payload, e); }
#if MIQ_ENABLE_ADDRMAN
        if(cmd=="addr"){
            if (!payload.empty() && (payload.size() % 4) == 0){
                size_t n = payload.size()/4;
                int added = 0;
                for(size_t j=0;j<n;j++){
                    uint32_t be_ip =
                        (uint32_t(payload[4*j+0])<<24) |
                        (uint32_t(payload[4*j+1])<<16) |
                        (uint32_t(payload[4*j+2])<<8 ) |
                        (uint32_t(payload[4*j+3])<<0 );
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

// ----- Wire I/O (send/recv): tolerate legacy, prefer modern on send -----------

bool P2PLight::send_msg(const char cmd12[12], const std::vector<uint8_t>& payload, std::string& err){
#ifdef _WIN32
    if (sock_ == (uintptr_t)-1) { err = "not connected"; return false; }
#else
    if (sock_ < 0) { err = "not connected"; return false; }
#endif

#if MIQ_WIRE_LEGACY_SEND
    // LEGACY: [ cmd(12) | len(4 le) | payload ]
    uint8_t hdr[16]{};
    // command (null-padded to 12)
    for (int i=0;i<12 && cmd12[i]; ++i) hdr[i] = (uint8_t)cmd12[i];
    // length
    uint32_t L = (uint32_t)payload.size();
    hdr[12]=uint8_t(L); hdr[13]=uint8_t(L>>8); hdr[14]=uint8_t(L>>16); hdr[15]=uint8_t(L>>24);

    if(!write_all(hdr, sizeof(hdr), err)) return false;
    if(L>0 && !write_all(payload.data(), L, err)) return false;
    return true;
#else
    // MODERN: [ magic(4) | cmd(12) | len(4 le) | checksum(4) | payload ]
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

    if(!write_all(header, sizeof(header), err)) return false;
    if(L>0 && !write_all(payload.data(), L, err)) return false;
    return true;
#endif
}

// Accept BOTH modern (MAGIC+cmd+len+csum) and legacy (cmd+len) headers.
// On legacy, csum_out is set to CSUM_NONE to signal "no checksum present".
bool P2PLight::read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err){
    // Peek first 4 bytes to check magic or start of legacy cmd.
    uint8_t pfx[4];
    if(!read_exact(pfx, 4, err)) return false;

    auto read_u32_le = [](const uint8_t* b)->uint32_t {
        return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
    };

    if (std::memcmp(pfx, miq::MAGIC_BE, 4) == 0) {
        // MODERN: read the rest (cmd[12] + len[4] + csum[4])
        uint8_t rest[20];
        if (!read_exact(rest, 20, err)) return false;

        char cmd[13]; std::memset(cmd, 0, sizeof(cmd));
        std::memcpy(cmd, rest, 12);
        cmd_out = std::string(cmd);

        len_out  = read_u32_le(rest + 12);
        csum_out = read_u32_le(rest + 16);
        return true;
    } else {
        // LEGACY: we already consumed 4 bytes of the 12-byte cmd.
        uint8_t rest[12];
        if (!read_exact(rest, 12, err)) return false;

        uint8_t cmd12[12]{};
        std::memcpy(cmd12, pfx, 4);
        std::memcpy(cmd12 + 4, rest, 8);

        char cmd[13]; std::memset(cmd, 0, sizeof(cmd));
        std::memcpy(cmd, cmd12, 12);
        cmd_out = std::string(cmd);

        len_out  = read_u32_le(rest + 8);
        csum_out = CSUM_NONE; // no checksum field in legacy header
        return true;
    }
}

bool P2PLight::read_exact(void* buf, size_t len, std::string& err){
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len){
#ifdef _WIN32
        int n = recv((SOCKET)sock_, (char*)p + (int)got, (int)(len - (int)got), 0);
        if (n == 0) {
            err = "recv failed (connection closed by peer)";
            return false;
        }
        if (n < 0) {
            int e = WSAGetLastError();
            if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) {
                err = "recv failed (timeout)";
            } else {
                err = "recv failed (WSA error " + std::to_string(e) + ")";
            }
            return false;
        }
#else
        ssize_t n = recv(sock_, p + got, len - got, 0);
        if (n == 0) {
            err = "recv failed (connection closed by peer)";
            return false;
        }
        if (n < 0) {
            int e = errno;
            if (e == EAGAIN || e == EWOULDBLOCK) {
                err = "recv failed (timeout)";
            } else if (e == ECONNRESET) {
                err = "recv failed (connection reset)";
            } else if (e == ENOTCONN) {
                err = "recv failed (not connected)";
            } else {
                err = "recv failed (errno " + std::to_string(e) + ")";
            }
            return false;
        }
#endif
        got += (size_t)n;
    }
    return true;
}

bool P2PLight::write_all(const void* buf, size_t len, std::string& err){
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    int retry_count = 0;
    const int max_retries = 3;

    while (sent < len){
#ifdef _WIN32
        int n = send((SOCKET)sock_, (const char*)p + (int)sent, (int)(len - (int)sent), 0);
        if (n == 0) {
            err = "send failed (connection closed)";
            return false;
        }
        if (n < 0) {
            int e = WSAGetLastError();
            if ((e == WSAEWOULDBLOCK || e == WSAETIMEDOUT) && retry_count++ < max_retries) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            err = "send failed (WSA error " + std::to_string(e) + ")";
            return false;
        }
#else
        ssize_t n = send(sock_, p + sent, len - sent, 0);
        if (n == 0) {
            err = "send failed (connection closed)";
            return false;
        }
        if (n < 0) {
            int e = errno;
            if ((e == EAGAIN || e == EWOULDBLOCK) && retry_count++ < max_retries) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            err = "send failed (errno " + std::to_string(e) + ")";
            return false;
        }
#endif
        sent += (size_t)n;
        retry_count = 0; // Reset on success
    }
    return true;
}

}
