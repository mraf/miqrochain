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

#ifndef _WIN32
  #include <signal.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <sys/time.h>
  #include <arpa/inet.h>
#else
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#endif

// === Optional persisted addrman ==============================================
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

// ---- hard cap for wallet-side frame sizes (prevents OOM/DoS) ----------------
#ifndef MAX_MSG_SIZE
#define MIQ_LIGHT_MAX_MSG_SIZE (2u * 1024u * 1024u)  // 2 MiB fallback
#else
#define MIQ_LIGHT_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

namespace miq {

// ---- tiny env helpers --------------------------------------------------------
static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v) return false;
    std::string s = v;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    return (s=="1"||s=="true"||s=="yes"||s=="on");
}
static std::string env_str(const char* name, const char* defv = ""){
    const char* v = std::getenv(name);
    return (v && *v) ? std::string(v) : std::string(defv);
}

// ---- network magic from chain constants --------------------------------------
#ifndef MIQ_P2P_MAGIC
static constexpr uint32_t MIQ_P2P_MAGIC =
    (uint32_t(MAGIC_BE[0])      ) |
    (uint32_t(MAGIC_BE[1]) <<  8) |
    (uint32_t(MAGIC_BE[2]) << 16) |
    (uint32_t(MAGIC_BE[3]) << 24);
#endif

// ---- time helper -------------------------------------------------------------
static inline int64_t now_ms(){
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ---- platform shims ----------------------------------------------------------
#ifdef _WIN32
  static inline void closesock(int s){ closesocket(s); }
  static inline void set_timeouts(int s, int ms){
      if(ms <= 0) return;
      DWORD t = (DWORD)ms;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
  }
#else
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

// ---- helpers -----------------------------------------------------------------
static void put_u32_le(std::vector<uint8_t>& b, uint32_t v){
    b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8));
    b.push_back(uint8_t(v>>16)); b.push_back(uint8_t(v>>24));
}
static void put_u64_le(std::vector<uint8_t>& b, uint64_t v){
    for(int i=0;i<8;i++) b.push_back(uint8_t(v>>(8*i)));
}
static void put_i64_le(std::vector<uint8_t>& b, int64_t v){
    put_u64_le(b, (uint64_t)v);
}
static void put_u16_be(std::vector<uint8_t>& b, uint16_t v){ // network order port
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
static std::vector<uint8_t> to_le32(const std::vector<uint8_t>& h){
    std::vector<uint8_t> r = h; std::reverse(r.begin(), r.end()); return r;
}
static uint32_t checksum4(const std::vector<uint8_t>& payload){
    auto d = dsha256(payload);
    return (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
}
static std::string default_port_str(const std::string& override_port){
    if (!override_port.empty()) return override_port;
    return std::to_string(P2P_PORT);
}

// ---- seed/candidate helpers --------------------------------------------------
static std::string strip_port_if_present(const std::string& host){
    // If it's bracketed IPv6 like "[::1]:9833" leave as-is (we expect plain "::1" in practice).
    if (!host.empty() && host.front()=='[') return host;
    // Otherwise strip "host:port" (wallet passes port separately).
    auto pos = host.find(':');
    if (pos == std::string::npos) return host;
    return host.substr(0, pos);
}

static void gather_default_candidates(std::vector<std::string>& out){
    std::unordered_set<std::string> seen;

    auto add = [&](const std::string& h){
        if (h.empty()) return;
        std::string s = strip_port_if_present(h);
        if (s == "127.0.0.1" || s == "::1" || s == "localhost") return; // no auto-local by default
        if (seen.insert(s).second) out.push_back(std::move(s));
    };

    // Primary single seed (can be IP)
    add(miq::DNS_SEED);

    // Additional seeds array
    for (size_t i=0; i<miq::DNS_SEEDS_COUNT; ++i) {
        add(miq::DNS_SEEDS[i]);
    }

    // Shuffle global seeds to distribute load
    std::mt19937 rng{std::random_device{}()};
    std::shuffle(out.begin(), out.end(), rng);
}

// ---- local-interface discovery (for anti-hairpin fallback) -------------------
static void collect_local_ipv4(std::vector<std::string>& out){
#ifdef _WIN32
    char host[256] = {0};
    if (gethostname(host, (int)sizeof(host)) != 0) return;
    ADDRINFOA hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    PADDRINFOA res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (!sa) continue;
        char buf[64] = {0};
        InetNtopA(AF_INET, &sa->sin_addr, buf, (int)sizeof(buf));
        if (buf[0]) {
            std::string s(buf);
            if (s != "127.0.0.1") out.push_back(s);
        }
    }
    freeaddrinfo(res);
#else
    char host[256] = {0};
    if (gethostname(host, sizeof(host)) != 0) return;
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (!sa) continue;
        char buf[64] = {0};
        inet_ntop(AF_INET, &sa->sin_addr, buf, (socklen_t)sizeof(buf));
        if (buf[0]) {
            std::string s(buf);
            if (s != "127.0.0.1") out.push_back(s);
        }
    }
    freeaddrinfo(res);
#endif
}

// ---- AddrMan (optional) ------------------------------------------------------
#if MIQ_ENABLE_ADDRMAN
namespace {
    static miq::AddrMan g_addrman;
    static miq::FastRand g_am_rng{0xC0FFEEULL};
    static std::string  g_addrman_path;
    static int64_t      g_last_addrman_save_ms = 0;

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
        if (!g_addrman.load(g_addrman_path, err)) {
            // silent; will be populated as we learn peers
        }
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
        std::string err;
        (void)g_addrman.save(g_addrman_path, err);
        g_last_addrman_save_ms = now_ms();
    }
}
#endif

// ---- connection helper: try many hosts (IPv4 first), random order -----------
static std::string peer_ip_string(int fd){
    sockaddr_storage ss{};
#ifdef _WIN32
    int slen = (int)sizeof(ss);
#else
    socklen_t slen = sizeof(ss);
#endif
    if (getpeername(fd, (sockaddr*)&ss, &slen) != 0) return std::string();
    char buf[128] = {0};
    if (ss.ss_family == AF_INET) {
#ifdef _WIN32
        InetNtopA(AF_INET, &((sockaddr_in*)&ss)->sin_addr, buf, (int)sizeof(buf));
#else
        inet_ntop(AF_INET, &((sockaddr_in*)&ss)->sin_addr, buf, (socklen_t)sizeof(buf));
#endif
    } else if (ss.ss_family == AF_INET6) {
#ifdef _WIN32
        InetNtopA(AF_INET6, &((sockaddr_in6*)&ss)->sin6_addr, buf, (int)sizeof(buf));
#else
        inet_ntop(AF_INET6, &((sockaddr_in6*)&ss)->sin6_addr, buf, (socklen_t)sizeof(buf));
#endif
    }
    return std::string(buf);
}

static int resolve_and_connect_best(const std::vector<std::string>& hosts,
                                    const std::string& port,
                                    int timeout_ms,
                                    std::string& err,
                                    std::string* connected_host /*optional out*/)
{
    if (hosts.empty()) { err = "no hosts"; return -1; }

    for (const auto& raw : hosts) {
        const std::string host = strip_port_if_present(raw);

        // Skip malformed host strings like "host:port" (non-bracketed)
        if (host.find(':') != std::string::npos && host.find("]:") == std::string::npos) {
            continue;
        }

        addrinfo hints{};
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_family   = AF_UNSPEC;
#ifdef AI_ADDRCONFIG
        hints.ai_flags    = AI_ADDRCONFIG;
#endif
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
            continue;
        }

        // Prefer IPv4, then IPv6
        std::vector<addrinfo*> v4, v6;
        for (auto p = res; p; p = p->ai_next) {
            if (p->ai_family == AF_INET) v4.push_back(p);
            else                         v6.push_back(p);
        }
        auto try_list = [&](const std::vector<addrinfo*>& lst)->int {
            for (auto p : lst) {
#ifdef _WIN32
                int fd = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
#else
                int fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
#endif
                if (fd < 0) continue;
                set_timeouts(fd, timeout_ms);
                if (connect(fd, p->ai_addr, (int)p->ai_addrlen) == 0) {
                    if (connected_host) *connected_host = host;
                    freeaddrinfo(res);
                    return fd;
                }
                closesock(fd);
            }
            return -1;
        };

        int fd = try_list(v4);
        if (fd < 0) fd = try_list(v6);
        freeaddrinfo(res);
        if (fd >= 0) return fd;
    }

    err = "connect failed";
    return -1;
}

// ---- smart local fallback when remote seeds fail (hairpin-safe) --------------
static int try_local_fallback(const std::string& port, int timeout_ms, std::string* connected_host){
    // Loopback first (fast path if node is on the same box)
    {
        std::vector<std::string> loop = {"127.0.0.1", "::1", "localhost"};
        std::string e;
        int fd = resolve_and_connect_best(loop, port, timeout_ms, e, connected_host);
        if (fd >= 0) return fd;
    }
    // Then any local interface IPv4s (e.g., 192.168.x.x)
    std::vector<std::string> locals;
    collect_local_ipv4(locals);
    if (!locals.empty()) {
        std::string e;
        int fd = resolve_and_connect_best(locals, port, timeout_ms, e, connected_host);
        if (fd >= 0) return fd;
    }
    return -1;
}

// ---- class -------------------------------------------------------------------
P2PLight::P2PLight(){}
P2PLight::~P2PLight(){ close(); }

bool P2PLight::connect_and_handshake(const P2POpts& opts, std::string& err){
    o_ = opts;

#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif

#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

#if MIQ_ENABLE_ADDRMAN
    addrman_load_once();
#endif

    // Build candidate list
    std::vector<std::string> candidates;
    if (!o_.host.empty()) {
        // Respect explicit host, including localhost if the user asked for it.
        candidates.push_back(strip_port_if_present(o_.host));
    } else {
#if MIQ_ENABLE_ADDRMAN
        // Ask addrman for some candidates first (prefer tried); then global defaults.
        {
            std::unordered_set<std::string> seen;
            for (int attempts=0; attempts<12; ++attempts){
                auto cand = g_addrman.select_for_outbound(g_am_rng, /*prefer_tried=*/true);
                if (!cand) break;
                std::string h = strip_port_if_present(cand->host);
                if (seen.insert(h).second) candidates.push_back(h);
            }
        }
#endif
        // Use constants.h global seeds too (no localhost here).
        std::vector<std::string> global;
        gather_default_candidates(global);
        // Prefer addrman candidates first, then add globals we don't have yet
        std::unordered_set<std::string> have(candidates.begin(), candidates.end());
        for (auto& g : global) if (have.insert(g).second) candidates.push_back(g);
    }

    const std::string port = default_port_str(o_.port);

    // 1) Try public/DNS/addrman seeds first
    std::string used_host;
    sock_ = resolve_and_connect_best(candidates, port, o_.io_timeout_ms, err, &used_host);

    // 2) Smart local fallback (handles NAT hairpin / loopback routers)
    if (sock_ < 0 && !env_truthy("MIQ_NO_LOCAL_FALLBACK")) {
        std::string e2;
        int fd_local = try_local_fallback(port, o_.io_timeout_ms, &used_host);
        if (fd_local >= 0) {
            sock_ = fd_local;
            err.clear(); // connected via local fallback
        }
    }

    if (sock_ < 0) return false;

#if MIQ_ENABLE_ADDRMAN
    // Mark connected peer as good/anchor (by real peer IP if available)
    {
        std::string ip = peer_ip_string(sock_);
        if (ip.empty()) ip = used_host;
        if (!ip.empty()) {
            NetAddr na;
            na.host = ip;
            na.port = (uint16_t)std::stoi(port);
            na.tried = true;
            na.is_ipv6 = (ip.find(':') != std::string::npos);
            g_addrman.mark_good(na);
            g_addrman.add_anchor(na);
            addrman_force_save();
        }
    }
#endif

    if(!send_version(err))      { close(); return false; }

    // Always send verack (node expects one from us)
    {
        std::vector<uint8_t> empty;
        if(!send_msg("verack", empty, err)) { close(); return false; }
    }

    if(!read_until_verack(err)) { close(); return false; }

    // Best-effort getaddr (to grow addrman if enabled)
    { std::string e2; (void)send_getaddr(e2); }

    header_hashes_le_.clear();
    return true;
}

bool P2PLight::send_tx(const std::vector<uint8_t>& tx_bytes, std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }
    return send_msg("tx", tx_bytes, err);
}

bool P2PLight::send_getaddr(std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }
    std::vector<uint8_t> empty;
    return send_msg("getaddr", empty, err);
}

void P2PLight::close(){
    if (sock_ >= 0){ closesock(sock_); sock_ = -1; }
#ifdef _WIN32
    WSACleanup();
#endif
#if MIQ_ENABLE_ADDRMAN
    addrman_force_save();
#endif
}

// ---- headers sync ------------------------------------------------------------
bool P2PLight::get_best_header(uint32_t& tip_height, std::vector<uint8_t>& tip_hash_le, std::string& err){
    tip_height = 0; tip_hash_le.clear();
    if (sock_ < 0){ err = "not connected"; return false; }

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
bool P2PLight::request_headers_from_locator(const std::vector<std::vector<uint8_t>>& locator_hashes_le,
                                            std::vector<uint8_t>& stop_le,
                                            std::string& err)
{
    std::vector<uint8_t> p;
    const uint8_t n = (uint8_t)std::min<size_t>(locator_hashes_le.size(), 32);
    p.push_back(n);
    for (size_t i=0;i<n;i++){
        if(locator_hashes_le[i].size()!=32){ err="bad locator hash size"; return false; }
        p.insert(p.end(), locator_hashes_le[i].begin(), locator_hashes_le[i].end());
    }
    if(stop_le.size()!=32) stop_le.assign(32, 0x00);
    p.insert(p.end(), stop_le.begin(), stop_le.end());
    return send_msg("getheaders", p, err);
}

// Accepts daemon-style headers (u16 + count*88 bytes) and Bitcoin-style (varint + 80 + varint txcount).
bool P2PLight::read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le, std::string& err){
    out_hashes_le.clear();
    for(;;){
        std::string cmd; uint32_t len=0, csum=0;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        // NEW: hard cap to avoid huge allocations/DoS
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
            // swallow unrelated messages (inv, getaddr reply seen above, etc.)
#if MIQ_ENABLE_ADDRMAN
            addrman_save_maybe();
#endif
            continue;
        }

        // Try daemon format first: [u16 count][count * 88 bytes]
        if(payload.size() >= 2){
            uint16_t count = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
            size_t pos = 2;
            const size_t HBYTES = 88;
            if (payload.size() == pos + (size_t)count * HBYTES){
                out_hashes_le.reserve(count);
                for (uint16_t i=0;i<count;i++){
                    const uint8_t* hdr = payload.data()+pos;
                    auto h  = dsha256_bytes(hdr, HBYTES);
                    auto hl = to_le32(h);
                    out_hashes_le.push_back(std::move(hl));
                    pos += HBYTES;
                }
#if MIQ_ENABLE_ADDRMAN
                addrman_save_maybe();
#endif
                return true;
            }
        }

        // Fallback: Bitcoin-style [varint count][count*(80-byte header + varint txcount)]
        if(!payload.empty()){
            size_t pos = 0; uint64_t count=0, used=0;
            if(get_varint(payload.data(), payload.size(), count, used)){
                pos += used;
                std::vector<std::vector<uint8_t>> tmp;
                tmp.reserve((size_t)count);
                bool ok = true;
                for(uint64_t i=0;i<count;i++){
                    if(pos + 80 > payload.size()){ ok=false; break; }
                    const uint8_t* hdr = payload.data()+pos;
                    auto h  = dsha256_bytes(hdr, 80);
                    auto hl = to_le32(h);
                    tmp.push_back(std::move(hl));
                    pos += 80;
                    if(pos < payload.size()){
                        uint64_t tcnt=0, u2=0;
                        if(get_varint(payload.data()+pos, payload.size()-pos, tcnt, u2)) pos += u2;
                    }
                }
                if(ok){
                    out_hashes_le.swap(tmp);
#if MIQ_ENABLE_ADDRMAN
                    addrman_save_maybe();
#endif
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
    if (sock_ < 0){ err = "not connected"; return false; }

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
    if (sock_ < 0){ err = "not connected"; return false; }
    if (hash_le.size()!=32){ err = "hash_le must be 32 bytes"; return false; }

    if(!send_msg("getb", hash_le, err)) return false;

    // read messages until we get "block"
    for(;;){
        std::string cmd; uint32_t len=0, csum=0;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        // NEW: cap again in this loop
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
    // Build a Bitcoin-like "version" payload; daemon is permissive and ignores extras.
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

        // NEW: cap to avoid allocating attacker-chosen size during handshake
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
        }
#endif
        // ignore other msgs in handshake window
    }
    err = "no verack from peer";
    return false;
}

bool P2PLight::send_msg(const char cmd12[12], const std::vector<uint8_t>& payload, std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }

    uint8_t header[24]{};
    // magic
    uint32_t m = MIQ_P2P_MAGIC;
    header[0]=uint8_t(m); header[1]=uint8_t(m>>8); header[2]=uint8_t(m>>16); header[3]=uint8_t(m>>24);

    // command (null-padded to 12)
    for (int i=0;i<12 && cmd12[i]; ++i) header[4+i] = (uint8_t)cmd12[i];

    // length
    uint32_t L = (uint32_t)payload.size();
    header[16]=uint8_t(L); header[17]=uint8_t(L>>8); header[18]=uint8_t(L>>16); header[19]=uint8_t(L>>24);

    // checksum
    uint32_t c = checksum4(payload);
    header[20]=uint8_t(c); header[21]=uint8_t(c>>8); header[22]=uint8_t(c>>16); header[23]=uint8_t(c>>24);

    if(!write_all(header, sizeof(header), err)) return false;
    if(L>0 && !write_all(payload.data(), payload.size(), err)) return false;
    return true;
}

bool P2PLight::read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err){
    uint8_t h[24];
    if(!read_exact(h, 24, err)) return false;

    uint32_t m = (uint32_t)h[0] | ((uint32_t)h[1]<<8) | ((uint32_t)h[2]<<16) | ((uint32_t)h[3]<<24);
    if(m != MIQ_P2P_MAGIC){ err = "bad magic"; return false; }

    char cmd[13]; std::memset(cmd, 0, sizeof(cmd));
    std::memcpy(cmd, h+4, 12);
    cmd_out = std::string(cmd);

    len_out  = (uint32_t)h[16] | ((uint32_t)h[17]<<8) | ((uint32_t)h[18]<<16) | ((uint32_t)h[19]<<24);
    csum_out = (uint32_t)h[20] | ((uint32_t)h[21]<<8) | ((uint32_t)h[22]<<16) | ((uint32_t)h[23]<<24);
    (void)csum_out; // not enforced here
    return true;
}

bool P2PLight::read_exact(void* buf, size_t len, std::string& err){
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len){
#ifdef _WIN32
        int n = recv(sock_, (char*)p + (int)got, (int)(len - (int)got), 0);
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
        int n = send(sock_, (const char*)p + (int)sent, (int)(len - (int)sent), 0);
#else
        ssize_t n = send(sock_, p + sent, len - sent, 0);
#endif
        if (n <= 0) { err = "send failed"; return false; }
        sent += (size_t)n;
    }
    return true;
}

}
