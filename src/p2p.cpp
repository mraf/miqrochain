// src/p2p.cpp  (strict-filter profile, Windows SOCKET-safe)
#include "p2p.h"
#include "nat.h"
#include "seeds.h"
#include "log.h"
#include "netmsg.h"
#include "serialize.h"
#include "chain.h"
#include "constants.h"
#include "utxo.h"           // fee calc (UTXOEntry)
#include "base58check.h"    // Base58Check address display (miner logs)

#include <chrono>
#include <tuple>
#include <cstring>
#include <fstream>
#include <algorithm>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <cstdio>
#include <random>
#include <cstdlib>  // getenv
#include <mutex>
#include <type_traits>

#ifndef _WIN32
#include <signal.h>
#endif

// ----- lightweight trace toggle ------------------------------------------------
#ifndef MIQ_P2P_TRACE
#define MIQ_P2P_TRACE 1
#endif
#if MIQ_P2P_TRACE
  #define P2P_TRACE(msg) do { miq::log_info(std::string("[TRACE] ") + (msg)); } while(0)
#else
  #define P2P_TRACE(msg) do {} while(0)
#endif

#if !defined(MIQ_MAYBE_UNUSED)
  #if defined(__GNUC__) || defined(__clang__)
    #define MIQ_MAYBE_UNUSED __attribute__((unused))
  #else
    #define MIQ_MAYBE_UNUSED
  #endif
#endif

// === Optional persisted addrman =============================================
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

// ===== STRICT FILTER PROFILE (central knobs) ================================
#ifndef MIQ_FILTER_PROFILE_STRICT
#define MIQ_FILTER_PROFILE_STRICT 1
#endif

// Handshake & pacing
#if MIQ_FILTER_PROFILE_STRICT
  #ifndef MIQ_P2P_VERACK_TIMEOUT_MS
  #define MIQ_P2P_VERACK_TIMEOUT_MS 7000
  #endif
  #ifndef MIQ_P2P_PING_EVERY_MS
  #define MIQ_P2P_PING_EVERY_MS     20000
  #endif
  #ifndef MIQ_P2P_PONG_TIMEOUT_MS
  #define MIQ_P2P_PONG_TIMEOUT_MS   10000
  #endif
  #ifndef MIQ_PREVERACK_QUEUE_MAX
  #define MIQ_PREVERACK_QUEUE_MAX   6
  #endif
#else
  #ifndef MIQ_P2P_VERACK_TIMEOUT_MS
  #define MIQ_P2P_VERACK_TIMEOUT_MS 10000
  #endif
  #ifndef MIQ_P2P_PING_EVERY_MS
  #define MIQ_P2P_PING_EVERY_MS     30000
  #endif
  #ifndef MIQ_P2P_PONG_TIMEOUT_MS
  #define MIQ_P2P_PONG_TIMEOUT_MS   15000
  #endif
  #ifndef MIQ_PREVERACK_QUEUE_MAX
  #define MIQ_PREVERACK_QUEUE_MAX   8
  #endif
#endif

#ifndef MIQ_ADDRMAN_FILE
#define MIQ_ADDRMAN_FILE "peers2.dat"
#endif
#ifndef MIQ_FEELER_INTERVAL_MS
#define MIQ_FEELER_INTERVAL_MS 60000
#endif
#ifndef MIQ_GROUP_OUTBOUND_MAX
#define MIQ_GROUP_OUTBOUND_MAX 2
#endif

#ifndef MIQ_ENABLE_HEADERS_FIRST
  #ifdef MIQ_ENABLE_HEADERS_FIRST_WIP
    #define MIQ_ENABLE_HEADERS_FIRST MIQ_ENABLE_HEADERS_FIRST_WIP
  #else
    #define MIQ_ENABLE_HEADERS_FIRST 1
  #endif
#endif

#ifdef __has_include
#  if __has_include("constants.h")
#    include "constants.h"
#  endif
#endif

#ifndef MAX_MSG_SIZE
#define MIQ_FALLBACK_MAX_MSG_SIZE (2u * 1024u * 1024u)
#else
#define MIQ_FALLBACK_MAX_MSG_SIZE (MAX_MSG_SIZE)
#endif

#ifndef MAX_BLOCK_SIZE
#define MIQ_FALLBACK_MAX_BLOCK_SZ (1u * 1024u * 1024u)
#else
#define MIQ_FALLBACK_MAX_BLOCK_SZ (MAX_BLOCK_SIZE)
#endif

#ifndef MIQ_P2P_MAX_BUFSZ
#define MIQ_P2P_MAX_BUFSZ (MIQ_FALLBACK_MAX_MSG_SIZE + (512u * 1024u))
#endif

#ifndef MIQ_RATE_BLOCK_BPS
#define MIQ_RATE_BLOCK_BPS (1024u * 1024u)
#endif
#ifndef MIQ_RATE_TX_BPS
#define MIQ_RATE_TX_BPS    (256u * 1024u)
#endif
#ifndef MIQ_RATE_BLOCK_BURST
#define MIQ_RATE_BLOCK_BURST (MIQ_RATE_BLOCK_BPS * 2u)
#endif
#ifndef MIQ_RATE_TX_BURST
#define MIQ_RATE_TX_BURST    (MIQ_RATE_TX_BPS * 2u)
#endif

#if MIQ_FILTER_PROFILE_STRICT
  #ifndef MIQ_ADDR_MAX_BATCH
  #define MIQ_ADDR_MAX_BATCH 800
  #endif
  #ifndef MIQ_ADDR_MIN_INTERVAL_MS
  #define MIQ_ADDR_MIN_INTERVAL_MS 150000
  #endif
  #ifndef MIQ_ADDR_RESPONSE_MAX
  #define MIQ_ADDR_RESPONSE_MAX 150
  #endif
#else
  #ifndef MIQ_ADDR_MAX_BATCH
  #define MIQ_ADDR_MAX_BATCH 1000
  #endif
  #ifndef MIQ_ADDR_MIN_INTERVAL_MS
  #define MIQ_ADDR_MIN_INTERVAL_MS 120000
  #endif
  #ifndef MIQ_ADDR_RESPONSE_MAX
  #define MIQ_ADDR_RESPONSE_MAX 200
  #endif
#endif

#ifndef MIQ_ADDR_SAVE_INTERVAL_MS
#define MIQ_ADDR_SAVE_INTERVAL_MS 60000
#endif
#ifndef MIQ_ADDR_MAX_STORE
#define MIQ_ADDR_MAX_STORE 10000
#endif

#ifndef MIQ_OUTBOUND_TARGET
#define MIQ_OUTBOUND_TARGET 4
#endif
#ifndef MIQ_DIAL_INTERVAL_MS
#define MIQ_DIAL_INTERVAL_MS 15000
#endif

#ifndef MIQ_ORPHAN_MAX_BYTES
#define MIQ_ORPHAN_MAX_BYTES (32u * 1024u * 1024u)
#endif
#ifndef MIQ_ORPHAN_MAX_COUNT
#define MIQ_ORPHAN_MAX_COUNT (4096u)
#endif

#ifndef MIQ_TX_STORE_MAX
#define MIQ_TX_STORE_MAX 10000
#endif

#ifndef MIQ_P2P_GETADDR_INTERVAL_MS
#define MIQ_P2P_P2P_GETADDR_INTERVAL_MS_SHADOW 120000
#define MIQ_P2P_GETADDR_INTERVAL_MS 120000
#endif
#if MIQ_FILTER_PROFILE_STRICT
  #ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
  #define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 40
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_MS
  #define MIQ_P2P_INV_WINDOW_MS 10000
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_CAP
  #define MIQ_P2P_INV_WINDOW_CAP 300
  #endif
  #ifndef MIQ_P2P_TRICKLE_MS
  #define MIQ_P2P_TRICKLE_MS 250
  #endif
  #ifndef MIQ_P2P_TRICKLE_BATCH
  #define MIQ_P2P_TRICKLE_BATCH 48
  #endif
  #ifndef MIQ_P2P_STALL_RETRY_MS
  #define MIQ_P2P_STALL_RETRY_MS 60000
  #endif
#else
  #ifndef MIQ_P2P_NEW_INBOUND_CAP_PER_MIN
  #define MIQ_P2P_NEW_INBOUND_CAP_PER_MIN 60
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_MS
  #define MIQ_P2P_INV_WINDOW_MS 10000
  #endif
  #ifndef MIQ_P2P_INV_WINDOW_CAP
  #define MIQ_P2P_INV_WINDOW_CAP 500
  #endif
  #ifndef MIQ_P2P_TRICKLE_MS
  #define MIQ_P2P_TRICKLE_MS 200
  #endif
  #ifndef MIQ_P2P_TRICKLE_BATCH
  #define MIQ_P2P_TRICKLE_BATCH 64
  #endif
  #ifndef MIQ_P2P_STALL_RETRY_MS
  #define MIQ_P2P_STALL_RETRY_MS 60000
  #endif
#endif

#ifndef MIQ_STRICT_HANDSHAKE
#define MIQ_STRICT_HANDSHAKE 1
#endif

// ----- banscore (compile fix for mixed uses) --------------------------------
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE 100
#endif

// ===== Platform networking glue: socket/close/poll types ====================
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #ifdef min
  #undef min
  #endif
  #ifdef max
  #undef max
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using Sock   = SOCKET;
  using PollFD = WSAPOLLFD;
  static const short POLL_RD = POLLRDNORM;
  #define MIQ_INVALID_SOCK INVALID_SOCKET
  #define CLOSESOCK(s) closesocket(s)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <poll.h>
  using Sock   = int;
  using PollFD = pollfd;
  static const short POLL_RD = POLLIN;
  #define MIQ_INVALID_SOCK (-1)
  #define CLOSESOCK(s) close(s)
#endif

// ----- IPv6/IPv4 literal + hostname resolver (drop-in, no new files) -------
struct MiqEndpoint {
    sockaddr_storage ss{};
#ifdef _WIN32
    int len = 0;
#else
    socklen_t len = 0;
#endif
};

static inline std::string miq_trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (unsigned char)s[a] <= ' ') ++a;
    while (b > a && (unsigned char)s[b-1] <= ' ') --b;
    return s.substr(a, b - a);
}

// Parse host[:port], [v6]:port, [v6], v6, v4, hostname → (host,port)
static bool miq_parse_host_port(const std::string& in_raw, std::string& host, uint16_t& port_out, uint16_t default_port) {
    std::string in = miq_trim(in_raw);
    host.clear(); port_out = default_port;
    if (in.empty()) return false;

    if (in.front() == '[') { // [v6] or [v6]:port
        auto rb = in.find(']');
        if (rb == std::string::npos) return false;
        host = in.substr(1, rb - 1);
        if (rb + 1 < in.size() && in[rb + 1] == ':') {
            std::string p = in.substr(rb + 2);
            if (!p.empty()) port_out = static_cast<uint16_t>(std::stoi(p));
        }
        return true;
    }

    // More than one ':' => bare IPv6 literal (no port)
    size_t colons = std::count(in.begin(), in.end(), ':');
    if (colons > 1) { host = in; return true; }

    // hostname/v4 or host:port
    auto pos = in.rfind(':');
    if (pos != std::string::npos) {
        host = in.substr(0, pos);
        std::string p = in.substr(pos + 1);
        if (!p.empty()) port_out = static_cast<uint16_t>(std::stoi(p));
    } else {
        host = in;
    }
    return true;
}

static bool miq_try_numeric_v6(const std::string& h, uint16_t port, MiqEndpoint& out) {
    sockaddr_in6 a6{}; a6.sin6_family = AF_INET6; a6.sin6_port = htons(port);
    if (inet_pton(AF_INET6, h.c_str(), &a6.sin6_addr) == 1) {
        memcpy(&out.ss, &a6, sizeof(a6)); out.len =
#ifdef _WIN32
            (int)
#endif
            sizeof(a6);
        return true;
    }
    return false;
}
static bool miq_try_numeric_v4(const std::string& h, uint16_t port, MiqEndpoint& out) {
    sockaddr_in a4{}; a4.sin_family = AF_INET; a4.sin_port = htons(port);
    if (inet_pton(AF_INET, h.c_str(), &a4.sin_addr) == 1) {
        memcpy(&out.ss, &a4, sizeof(a4)); out.len =
#ifdef _WIN32
            (int)
#endif
            sizeof(a4);
        return true;
    }
    return false;
}

static std::string miq_ntop_sockaddr(const sockaddr_storage& ss) {
    char buf[128] = {0};
    if (ss.ss_family == AF_INET6) {
        const sockaddr_in6* a6 = reinterpret_cast<const sockaddr_in6*>(&ss);
    #ifdef _WIN32
        InetNtopA(AF_INET6, (void*)&a6->sin6_addr, buf, (int)sizeof(buf));
    #else
        inet_ntop(AF_INET6, (void*)&a6->sin6_addr, buf, (socklen_t)sizeof(buf));
    #endif
    } else if (ss.ss_family == AF_INET) {
        const sockaddr_in* a4 = reinterpret_cast<const sockaddr_in*>(&ss);
    #ifdef _WIN32
        InetNtopA(AF_INET, (void*)&a4->sin_addr, buf, (int)sizeof(buf));
    #else
        inet_ntop(AF_INET, (void*)&a4->sin_addr, buf, (socklen_t)sizeof(buf));
    #endif
    }
    return std::string(buf[0] ? buf : "unknown");
}

static bool miq_resolve_endpoints_from_string(const std::string& input, uint16_t default_port,
                                              std::vector<MiqEndpoint>& out_eps)
{
    out_eps.clear();
    std::string host; uint16_t port = default_port;
    if (!miq_parse_host_port(input, host, port, default_port)) return false;

    // Fast-path numeric literals
    MiqEndpoint ep{};
    if (miq_try_numeric_v6(host, port, ep)) { out_eps.push_back(ep); return true; }
    if (miq_try_numeric_v4(host, port, ep)) { out_eps.push_back(ep); return true; }

    // Hostname → both AAAA and A
#ifdef _WIN32
    ADDRINFOA hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_ADDRCONFIG;
    PADDRINFOA res = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
    if (rc != 0 || !res) return false;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET6 && p->ai_addrlen >= (int)sizeof(sockaddr_in6)) {
            sockaddr_in6 a6{}; memcpy(&a6, p->ai_addr, sizeof(a6)); a6.sin6_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a6, sizeof(a6)); ne.len = (int)sizeof(a6); out_eps.push_back(ne);
        } else if (p->ai_family == AF_INET && p->ai_addrlen >= (int)sizeof(sockaddr_in)) {
            sockaddr_in a4{}; memcpy(&a4, p->ai_addr, sizeof(a4)); a4.sin_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a4, sizeof(a4)); ne.len = (int)sizeof(a4); out_eps.push_back(ne);
        }
    }
    freeaddrinfo(res);
#else
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM; hints.ai_flags = AI_ADDRCONFIG;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET6 && p->ai_addrlen >= (socklen_t)sizeof(sockaddr_in6)) {
            sockaddr_in6 a6{}; memcpy(&a6, p->ai_addr, sizeof(a6)); a6.sin6_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a6, sizeof(a6)); ne.len = (socklen_t)sizeof(a6); out_eps.push_back(ne);
        } else if (p->ai_family == AF_INET && p->ai_addrlen >= (socklen_t)sizeof(sockaddr_in)) {
            sockaddr_in a4{}; memcpy(&a4, p->ai_addr, sizeof(a4)); a4.sin_port = htons(port);
            MiqEndpoint ne{}; memcpy(&ne.ss, &a4, sizeof(a4)); ne.len = (socklen_t)sizeof(a4); out_eps.push_back(ne);
        }
    }
    freeaddrinfo(res);
#endif

    return !out_eps.empty();
}

// p2p.h uses int for PeerState::sock and for map keys; we cast to Sock
// where needed on Windows to avoid narrowing and keep WSAPOLLFD happy.

namespace {
// === lightweight handshake/size gate ========================================
using Clock = std::chrono::steady_clock;

struct PeerGate {
    bool got_version{false};
    bool sent_verack{false};
    bool got_verack{false};
    bool is_loopback{false};   // mark if this fd belongs to 127.0.0.1 peer
    int  banscore{0};
    size_t rx_bytes{0};
    Clock::time_point t_conn{Clock::now()};
    Clock::time_point t_last{Clock::now()};
};

// Keyed by per-connection socket fd/handle
static std::unordered_map<Sock, PeerGate> g_gate;

// Tunables (local to this TU)
static const size_t MAX_MSG_BYTES = 2 * 1024 * 1024; // 2 MiB per message (soft)
static const int    MAX_BANSCORE  = MIQ_P2P_MAX_BANSCORE;
static const int    HANDSHAKE_MS  = 10000;

// IBD phase logging flags
static bool g_logged_headers_started = false;
static bool g_logged_headers_done    = false;

// Global listen port for outbound dials (set in start())
static uint16_t g_listen_port = 0;

// Stall/progress trackers
static int64_t g_last_progress_ms = 0;
static size_t  g_last_progress_height = 0;
static int64_t g_next_stall_probe_ms = 0;

// Simple trickle queues per-peer (sock -> txid queue and last flush ms)
static std::unordered_map<Sock, std::vector<std::vector<uint8_t>>> g_trickle_q;
static std::unordered_map<Sock, int64_t> g_trickle_last_ms;

// Per-peer sliding-window message counters
static std::unordered_map<Sock,
    std::unordered_map<std::string, std::pair<int64_t,uint32_t>>> g_cmd_rl;

// Per-socket parse deadlines for partial frames
static std::unordered_map<Sock, int64_t> g_rx_started_ms;
static inline void rx_track_start(Sock fd){
    if (g_rx_started_ms.find(fd)==g_rx_started_ms.end())
        g_rx_started_ms[fd] = [](){
            using namespace std::chrono;
            return std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
        }();
}
static inline void rx_clear_start(Sock fd){
    g_rx_started_ms.erase(fd);
}

// --- small Windows-safe send/recv helpers -----------------------------------
// Hardened: loop on partial sends
static inline bool miq_send(Sock s, const uint8_t* data, size_t len) {
    if (!data || len == 0) return true;
    size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        int n = send(s, reinterpret_cast<const char*>(data + sent), (int)std::min<size_t>(INT32_MAX, len - sent), 0);
        if (n == SOCKET_ERROR) {
            int e = WSAGetLastError();
            if (e == WSAEWOULDBLOCK) { // spin briefly; sockets are blocking in our usage
                continue;
            }
            char buf[96]; sprintf_s(buf, "send() failed WSAE=%d", e);
            miq::log_warn(std::string("P2P: ") + buf);
            return false;
        }
        if (n == 0) return false;
        sent += (size_t)n;
#else
        ssize_t n = send(s, data + sent, len - sent, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            miq::log_warn("P2P: send() failed");
            return false;
        }
        if (n == 0) return false;
        sent += (size_t)n;
#endif
    }
    return true;
}
static inline bool miq_send(Sock s, const std::vector<uint8_t>& v){
    if (v.empty()) return true;
    return miq_send(s, v.data(), v.size());
}
static inline int miq_recv(Sock s, uint8_t* buf, size_t bufsz) {
#ifdef _WIN32
    int n = recv(s, reinterpret_cast<char*>(buf), (int)bufsz, 0);
    if (n == SOCKET_ERROR) {
        int e = WSAGetLastError();
        if (e == WSAEWOULDBLOCK) return 0;
        char tmp[96]; sprintf_s(tmp, "recv() failed WSAE=%d", e);
        miq::log_warn(std::string("P2P: ") + tmp);
        return -1;
    }
    return n;
#else
    ssize_t n = recv(s, buf, bufsz, 0);
    if (n < 0) return -1;
    return (int)n;
#endif
}

// --- helper to send gettx using existing encode_msg path ----------
static inline void send_gettx(Sock sock, const std::vector<uint8_t>& txid) {
    if (txid.size() != 32) return;
    auto m = miq::encode_msg("gettx", txid);
    (void)miq_send(sock, m);
}

static inline uint64_t env_u64(const char* name, uint64_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; unsigned long long x = std::strtoull(v, &end, 10);
    if(end==v) return defv;
    return (uint64_t)x;
}

// ---- Fee filter state (miqron/kB) ------------------------------------------
static inline uint64_t local_min_relay_kb(){
    static uint64_t v = env_u64("MIQ_MIN_RELAY_FEE_RATE", 1000ULL);
    return v;
}
static std::unordered_map<Sock, uint64_t> g_peer_minrelay_kb;
static std::unordered_map<Sock, int64_t>  g_peer_last_ff_ms;

static inline void set_peer_feefilter(Sock fd, uint64_t kb){
    g_peer_minrelay_kb[fd] = kb;
    g_peer_last_ff_ms[fd]  = std::chrono::duration_cast<std::chrono::milliseconds>(
                                Clock::now().time_since_epoch()).count();
}
static inline uint64_t peer_feefilter_kb(Sock fd){
    auto it = g_peer_minrelay_kb.find(fd);
    return (it==g_peer_minrelay_kb.end()) ? 0ULL : it->second;
}

// ---- DNS seed backoff (per-host) -------------------------------------------
static std::unordered_map<std::string, std::pair<int64_t,int64_t>> g_seed_backoff;

// ---- Header zero-progress tracker (socket -> consecutive empty batches) ----
static std::unordered_map<Sock,int> g_zero_hdr_batches;

// ---- NEW: pre-verack safe allow-list & counters ----------------------------
static std::unordered_map<Sock,int> g_preverack_counts;  // socket -> early safe msg count
static inline bool miq_safe_preverack_cmd(const std::string& cmd) {
    static const char* k[] = {
        "verack","ping","pong","getheaders","headers",
        "addr","getaddr","invb","getb","getbi","invtx","gettx","tx","feefilter"
    };
    for (auto* s : k) if (cmd == s) return true;
    return false;
}

static inline int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
static inline int64_t seed_backoff_base_ms(){
    return (int64_t)env_u64("MIQ_SEED_BACKOFF_MS_BASE", 15000ULL);
}
static inline int64_t seed_backoff_max_ms(){
    return (int64_t)env_u64("MIQ_SEED_BACKOFF_MS_MAX", 300000ULL);
}
static inline int64_t jitter_ms(int64_t max_jitter){
    static thread_local std::mt19937 gen{std::random_device{}()};
    std::uniform_int_distribution<int64_t> d(0, max_jitter);
    return d(gen);
}

static inline void gate_on_connect(Sock fd){
    PeerGate pg;
    pg.t_conn = Clock::now();
    pg.t_last = pg.t_conn;
    pg.is_loopback = false; // default; set after we learn the IP
    g_gate[fd] = pg;
    g_trickle_last_ms[fd] = 0;
}
// NEW: mark the fd as loopback once we know the peer's IP.
static inline void gate_set_loopback(Sock fd, bool is_lb){
    auto it = g_gate.find(fd);
    if (it != g_gate.end()) it->second.is_loopback = is_lb;
}

static inline void gate_on_close(Sock fd){
    g_gate.erase(fd);
    g_trickle_q.erase(fd);
    g_trickle_last_ms.erase(fd);
    g_peer_minrelay_kb.erase(fd);
    g_peer_last_ff_ms.erase(fd);
    rx_clear_start(fd);
    g_zero_hdr_batches.erase(fd);
    g_preverack_counts.erase(fd);
    g_cmd_rl.erase(fd); // NEW: clean up per-socket rate-limiter windows
}
static inline bool gate_on_bytes(Sock fd, size_t add){
    auto it = g_gate.find(fd);
    if (it == g_gate.end()) return false;
    it->second.rx_bytes += add;
    it->second.t_last = Clock::now();
    if (it->second.rx_bytes > MAX_MSG_BYTES){
        it->second.banscore += 20;
        return it->second.banscore >= MAX_BANSCORE;
    }
    return false;
}
static inline bool gate_on_command(Sock fd, const std::string& cmd,
                                   /*out*/ bool& should_send_verack,
                                   /*out*/ int& close_code)
{
    should_send_verack = false;
    close_code = 0;

    auto it = g_gate.find(fd);
    if (it == g_gate.end()) return false;
    auto& g = it->second;

    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - g.t_conn).count();
    if (!g.got_verack && ms > HANDSHAKE_MS){
        // Loopback is lenient: extend instead of closing
        if (g.is_loopback) {
            g.t_conn = Clock::now();
        } else {
            close_code = 408;
            P2P_TRACE("close fd=" + std::to_string((uintptr_t)fd) + " reason=handshake-timeout");
            return true;
        }
    }

    if (!cmd.empty()){
        if (cmd == "version"){
            if (!g.got_version){
                g.got_version = true;
                should_send_verack = true;
                g_preverack_counts.erase(fd);
            }
        } else if (cmd == "verack"){
            g.got_verack = true;
            g_preverack_counts.erase(fd);
        } else {
            if (!g.got_version) {
                if (miq_safe_preverack_cmd(cmd)) {
                    return false;
                } else {
                    g.banscore += 10;
                    if (g.banscore >= MAX_BANSCORE) { close_code = 400; P2P_TRACE("close fd="+std::to_string((uintptr_t)fd)+" reason=pre-version-bad"); return true; }
                    return false;
                }
            }
            if (!g.got_verack){
                if (!miq_safe_preverack_cmd(cmd)) return false;
                // Do NOT count safe pre-verack from local wallet (127.0.0.1)
                if (!g.is_loopback) {
                    int &cnt = g_preverack_counts[fd];
                    if (++cnt > MIQ_PREVERACK_QUEUE_MAX) {
                        g.banscore += 5;
                        if (g.banscore >= MAX_BANSCORE) { close_code = 402; P2P_TRACE("close fd="+std::to_string((uintptr_t)fd)+" reason=pre-verack-overflow"); return true; }
                        return false;
                    }
                }
            }
        }
    }

    if (g.banscore >= MAX_BANSCORE){ close_code = 400; P2P_TRACE("close fd="+std::to_string((uintptr_t)fd)+" reason=banscore"); return true; }
    return false;
}

// === legacy persisted IPv4 addr set (kept for backward compat) ==============
static void save_addrs_to_disk(const std::string& datadir,
                               const std::unordered_set<uint32_t>& addrv4){
    std::string path = datadir + "/peers.dat";
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if(!f) return;
    f.write("MIQA", 4);
    uint32_t cnt = (uint32_t)std::min<size_t>(addrv4.size(), MIQ_ADDR_MAX_STORE);
    f.write(reinterpret_cast<const char*>(&cnt), sizeof(cnt));
    size_t written = 0;
    for (uint32_t ip : addrv4){
        if (written >= MIQ_ADDR_MAX_STORE) break;
        f.write(reinterpret_cast<const char*>(&ip), sizeof(uint32_t));
        ++written;
    }
}

static bool is_private_be(uint32_t be_ip){
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    if (A == 0 || A == 10 || A == 127) return true;
    if (A == 169 && B == 254) return true;
    if (A == 192 && B == 168) return true;
    if (A == 172 && (uint8_t(be_ip>>20) & 0x0F) >= 1 && (uint8_t(be_ip>>20) & 0x0F) <= 15) return true;
    if (A >= 224) return true;
    return false;
}

static void load_addrs_from_disk(const std::string& datadir,
                                 std::unordered_set<uint32_t>& addrv4){
    std::string path = datadir + "/peers.dat";
    std::ifstream f(path, std::ios::binary);
    if(!f) return;
    char magic[4]; if(!f.read(magic,4)) return;
    if(std::memcmp(magic,"MIQA",4)!=0) return;
    uint32_t cnt=0;
    if(!f.read(reinterpret_cast<char*>(&cnt), sizeof(cnt))) return;
    for (uint32_t i=0; i<cnt; ++i){
        uint32_t ip=0;
        if(!f.read(reinterpret_cast<char*>(&ip), sizeof(ip))) break;
        if (!is_private_be(ip)) addrv4.insert(ip);
    }
}

static std::string be_ip_to_string(uint32_t be_ip){
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip;
    char buf[64] = {0};
#ifdef _WIN32
    InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
    inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
    return std::string(buf[0]?buf:"0.0.0.0");
}

// ---- NEVER DIAL LOOPBACK/SELF: guard state & helpers -----------------------
static std::unordered_set<uint32_t> g_self_v4; // network byte order (BE)

static bool parse_ipv4_dotted(const std::string& dotted, uint32_t& be_ip){
    sockaddr_in tmp{};
#ifdef _WIN32
    if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#else
    if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#endif
    be_ip = tmp.sin_addr.s_addr;
    return true;
}

static inline bool is_loopback_be(uint32_t be_ip){
    return (uint8_t)(be_ip >> 24) == 127;
}
static inline bool is_self_be(uint32_t be_ip){
    return g_self_v4.find(be_ip) != g_self_v4.end();
}
static MIQ_MAYBE_UNUSED void self_add_be(uint32_t be_ip){
    g_self_v4.insert(be_ip);
}
static void self_add_dotted(const std::string& ip){
    uint32_t be_ip=0;
    if (parse_ipv4_dotted(ip, be_ip)) g_self_v4.insert(be_ip);
}
static void gather_self_ipv4_basic(){
    char host[256] = {0};
#ifdef _WIN32
    if (gethostname(host, (int)sizeof(host)) != 0) return;
    ADDRINFOA hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    PADDRINFOA res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (!sa) continue;
        uint32_t be_ip = sa->sin_addr.s_addr;
        if (be_ip) g_self_v4.insert(be_ip);
    }
    freeaddrinfo(res);
#else
    if (gethostname(host, sizeof(host)) != 0) return;
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host, nullptr, &hints, &res) != 0 || !res) return;
    for (auto p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET) continue;
        auto sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (!sa) continue;
        uint32_t be_ip = sa->sin_addr.s_addr;
        if (be_ip) g_self_v4.insert(be_ip);
    }
    freeaddrinfo(res);
#endif
}
static void gather_self_from_env(){
    const char* a = std::getenv("MIQ_SELF_IP");
    const char* b = std::getenv("MIQ_SELF_IPV4");
    auto take = [&](const char* s){
        if (!s || !*s) return;
        std::string v(s);
        size_t i=0;
        while (i < v.size()) {
            while (i < v.size() && (v[i]==' '||v[i]==','||v[i]==';'||v[i]=='\t')) ++i;
            size_t j=i;
            while (j < v.size() && v[j]!=',' && v[j]!=';' && v[j]!=' ' && v[j]!='\t') ++j;
            if (j>i) self_add_dotted(v.substr(i,j-i));
            i=j;
        }
    };
    take(a); take(b);
}
static std::string self_list_for_log(){
    std::string out;
    bool first = true;
    for (uint32_t be_ip : g_self_v4){
        if (!first) out += ",";
        out += be_ip_to_string(be_ip);
        first = false;
    }
    if (out.empty()) out = "(none)";
    return out;
}

static inline uint16_t v4_group16(uint32_t be_ip){
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    return (uint16_t(A) << 8) | uint16_t(B);
}

// Dial a single IPv4 (be order) at supplied port; returns socket or MIQ_INVALID_SOCK
static Sock dial_be_ipv4(uint32_t be_ip, uint16_t port){
    if (is_loopback_be(be_ip) || is_self_be(be_ip)) {
        return MIQ_INVALID_SOCK;
    }
#ifdef _WIN32
    Sock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    Sock s = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (s == MIQ_INVALID_SOCK) return MIQ_INVALID_SOCK;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = be_ip; a.sin_port = htons(port);
    if (connect(s, (sockaddr*)&a, sizeof(a)) != 0) {
        CLOSESOCK(s);
        return MIQ_INVALID_SOCK;
    }
    return s;
}

// v6 loopback helper
static inline bool is_loopback_v6(const in6_addr& a) {
    static const uint8_t loop[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1}; // ::1
    return std::memcmp(&a, loop, 16) == 0;
}

// Detect if an accepted fd is a clear self-hairpin (we dialed ourselves).
static bool is_self_endpoint(Sock fd, uint16_t listen_port){
    sockaddr_storage peer{}, local{};
#ifdef _WIN32
    int alen = (int)sizeof(peer), blen = (int)sizeof(local);
#else
    socklen_t alen = sizeof(peer), blen = sizeof(local);
#endif
    if (getpeername(fd, (sockaddr*)&peer, &alen) != 0) return false;
    if (getsockname(fd, (sockaddr*)&local, &blen) != 0) return false;

    if (peer.ss_family == AF_INET && local.ss_family == AF_INET) {
        auto* p = (sockaddr_in*)&peer;
        auto* l = (sockaddr_in*)&local;

        const uint32_t peer_be = p->sin_addr.s_addr;
        const uint16_t peer_port = ntohs(p->sin_port);
        (void)l;

        // explicit: loopback inbound is allowed; only reject if hairpin on same port
        if ((ntohl(peer_be) >> 24) == 127) return false;

        if (is_self_be(peer_be)) {
            if (peer_port == listen_port) {
                return true;
            }
            return false;
        }
    } else if (peer.ss_family == AF_INET6 && local.ss_family == AF_INET6) {
        auto* p6 = (sockaddr_in6*)&peer;
        auto* l6 = (sockaddr_in6*)&local;
        if (is_loopback_v6(p6->sin6_addr)) return false; // allow ::1
        // Conservative hairpin detect: same v6 address AND same port as our listener.
        if (std::memcmp(&p6->sin6_addr, &l6->sin6_addr, sizeof(in6_addr)) == 0) {
            if (ntohs(p6->sin6_port) == listen_port) {
                return true;
            }
        }
    }
    return false;
}

static std::string miq_addr_from_pkh(const std::vector<uint8_t>& pkh) {
    if (pkh.size() != 20) return "(unknown)";
    return miq::base58check_encode(miq::VERSION_P2PKH, pkh);
}
static std::string miq_miner_from_block(const miq::Block& b) {
    if (b.txs.empty()) return "(unknown)";
    const miq::Transaction& cb = b.txs[0];
    if (cb.vout.empty()) return "(unknown)";
    return miq_addr_from_pkh(cb.vout[0].pkh);
}

// --- NEW: version payload helper (send a real version+services) -------------
static inline uint32_t miq_local_proto_version() {
#if defined(MIQ_PROTOCOL_VERSION)
    return (uint32_t)MIQ_PROTOCOL_VERSION;
#elif defined(PROTOCOL_VERSION)
    return (uint32_t)PROTOCOL_VERSION;
#else
    return 1u;
#endif
}
static inline void miq_put_u32le(std::vector<uint8_t>& v, uint32_t x){
    v.push_back((uint8_t)((x>>0)&0xff));
    v.push_back((uint8_t)((x>>8)&0xff));
    v.push_back((uint8_t)((x>>16)&0xff));
    v.push_back((uint8_t)((x>>24)&0xff));
}
static inline void miq_put_u64le(std::vector<uint8_t>& v, uint64_t x){
    for (int i=0;i<8;i++) v.push_back((uint8_t)((x>>(8*i))&0xff));
}
static inline std::vector<uint8_t> miq_build_version_payload() {
    std::vector<uint8_t> v; v.reserve(12);
    miq_put_u32le(v, miq_local_proto_version());
    uint64_t svc = 0;
#if MIQ_ENABLE_HEADERS_FIRST
    svc |= (1ull<<0);   // headers-first
#endif
    svc |= (1ull<<1);   // tx relay supported
    miq_put_u64le(v, svc);
    return v;
}

} // anon

namespace miq {

bool P2P::check_rate(PeerState& ps, const char* key) {
    if (!key) return true;

    struct Map { const char* key; const char* family; };
    static const Map kTable[] = {
        {"invb",   "inv"},
        {"invtx",  "inv"},
        {"getb",   "get"},
        {"getbi",  "get"},
        {"gettx",  "get"},
        {"gethdr", "get"},
        {"addr",   "addr"},
        {"getaddr","addr"},
    };

    for (const auto& e : kTable) {
        if (std::strcmp(e.key, key) == 0) {
            return check_rate(ps, e.family, 1.0, now_ms());
        }
    }
    return check_rate(ps, "misc", 1.0, now_ms());
}

// === Per-family token bucket (cost tokens per event) ========================
bool P2P::check_rate(PeerState& ps, const char* family, double cost, int64_t now_ms)
{
    if (!family) family = "misc";
    if (cost < 0) cost = 0;
    const std::string fam(family);

    // Look up per-family config: default if missing.
    double per_sec = 10.0;
    double burst   = 20.0;
    auto it_cfg = rate_cfg_.find(fam);
    if (it_cfg != rate_cfg_.end()) {
        per_sec = it_cfg->second.per_sec;
        burst   = it_cfg->second.burst;
    }

    // Refill and charge tokens.
    auto& rc = ps.rate;
    if (rc.last_ms == 0) rc.last_ms = now_ms;
    const double elapsed = (now_ms - rc.last_ms) / 1000.0;
    double tokens = rc.buckets[fam]; // 0 if missing

    if (elapsed > 0) {
        tokens = std::min(burst, tokens + per_sec * elapsed);
    }
    rc.last_ms = now_ms;

    if (tokens + 1e-9 < cost) {
        if (ps.banscore < MIQ_P2P_MAX_BANSCORE) ps.banscore += 1;
        rc.buckets[fam] = tokens;
        return false;
    }

    tokens -= cost;
    rc.buckets[fam] = tokens;
    return true;
}


bool P2P::check_rate(PeerState& ps,
                     const char* family,
                     const char* name,
                     uint32_t burst,
                     uint32_t window_ms)
{
    const char* fam = family ? family : "misc";
    const char* nam = name   ? name   : "";

    std::string k;
    k.reserve(std::strlen(fam) + 1 + std::strlen(nam));
    k.append(fam);
    k.push_back(':');
    k.append(nam);

    const int64_t t = now_ms();

    static_assert(std::is_same<decltype(g_cmd_rl),
        std::unordered_map<Sock, std::unordered_map<std::string, std::pair<int64_t,uint32_t>>>>::value,
        "g_cmd_rl type changed");

    auto& perPeer = g_cmd_rl[(Sock)ps.sock];
    auto& slot    = perPeer[k];
    int64_t&  win_start = slot.first;
    uint32_t& count     = slot.second;

    if (win_start == 0 || (t - win_start) >= (int64_t)window_ms) {
        win_start = t;
        count = 0;
    }

    if (count >= burst) {
        if (ps.banscore < MIQ_P2P_MAX_BANSCORE) ps.banscore += 1;
        return false;
    }

    ++count;
    return true;
}

#if MIQ_ENABLE_HEADERS_FIRST
namespace {
    static constexpr size_t HEADER_WIRE_BYTES = 88;

    static inline void put_u32le(std::vector<uint8_t>& v, uint32_t x){
        v.push_back((uint8_t)((x>>0)&0xff));
        v.push_back((uint8_t)((x>>8)&0xff));
        v.push_back((uint8_t)((x>>16)&0xff));
        v.push_back((uint8_t)((x>>24)&0xff));
    }
    static inline void put_u64le(std::vector<uint8_t>& v, uint64_t x){
        for(int i=0;i<8;i++) v.push_back((uint8_t)((x>>(8*i))&0xff));
    }
    static inline void put_i64le(std::vector<uint8_t>& v, int64_t x){
        put_u64le(v, (uint64_t)x);
    }
    static inline uint32_t get_u32le(const uint8_t* p){ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
    static inline uint64_t get_u64le(const uint8_t* p){ uint64_t z=0; for(int i=0;i<8;i++) z|=((uint64_t)p[i])<<(8*i); return z; }
    static inline int64_t  get_i64le(const uint8_t* p){ return (int64_t)get_u64le(p); }

    static std::vector<uint8_t> ser_header(const BlockHeader& h){
        std::vector<uint8_t> v; v.reserve(HEADER_WIRE_BYTES);
        put_u32le(v, h.version);
        v.insert(v.end(), h.prev_hash.begin(),   h.prev_hash.end());
        v.insert(v.end(), h.merkle_root.begin(), h.merkle_root.end());
        put_i64le(v, h.time);
        put_u32le(v, h.bits);
        put_u64le(v, h.nonce);
        return v;
    }
    static bool deser_header(const uint8_t* p, size_t n, BlockHeader& h){
        if (n < HEADER_WIRE_BYTES) return false;
        h.version = get_u32le(p+0);
        h.prev_hash.assign(p+4,   p+4+32);
        h.merkle_root.assign(p+36, p+36+32);
        h.time = get_i64le(p+68);
        h.bits = get_u32le(p+76);
        h.nonce= get_u64le(p+80);
        return true;
    }

    static std::vector<uint8_t> build_getheaders_payload(const std::vector<std::vector<uint8_t>>& locator,
                                                         const std::vector<uint8_t>& stop){
        const uint8_t n = (uint8_t)std::min<size_t>(locator.size(), 32);
        std::vector<uint8_t> v; v.reserve(1 + n*32 + 32);
        v.push_back(n);
        for (size_t i=0;i<n;i++) v.insert(v.end(), locator[i].begin(), locator[i].end());
        if (stop.size()==32) v.insert(v.end(), stop.begin(), stop.end());
        else v.insert(v.end(), 32, 0);
        return v;
    }
    static bool parse_getheaders_payload(const std::vector<uint8_t>& p,
                                         std::vector<std::vector<uint8_t>>& locator,
                                         std::vector<uint8_t>& stop){
        if (p.size() < 1+32) return false;
        uint8_t n = p[0];
        size_t need = 1 + (size_t)n*32 + 32;
        if (p.size() < need) return false;
        locator.clear();
        size_t off = 1;
        for (uint8_t i=0;i<n;i++){ locator.emplace_back(p.begin()+off, p.begin()+off+32); off+=32; }
        stop.assign(p.begin()+off, p.begin()+off+32);
        return true;
    }

    static std::vector<uint8_t> build_headers_payload(const std::vector<BlockHeader>& hs){
        const uint16_t n = (uint16_t)std::min<size_t>(hs.size(), 2000);
        std::vector<uint8_t> v; v.reserve(2 + (size_t)n*HEADER_WIRE_BYTES);
        v.push_back((uint8_t)(n & 0xff));
        v.push_back((uint8_t)((n >> 8) & 0xff));
        for (size_t i=0;i<n;i++){
            auto h = ser_header(hs[i]);
            v.insert(v.end(), h.begin(), h.end());
        }
        return v;
    }
    static bool parse_headers_payload(const std::vector<uint8_t>& p, std::vector<BlockHeader>& out){
        if (p.size() < 2) return false;
        uint16_t n = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
        size_t need = 2 + (size_t)n*HEADER_WIRE_BYTES;
        if (p.size() < need) return false;
        out.clear(); out.reserve(n);
        size_t off = 2;
        for (uint16_t i=0;i<n;i++){
            BlockHeader h;
            if (!deser_header(p.data()+off, p.size()-off, h)) return false;
            out.push_back(std::move(h));
            off += HEADER_WIRE_BYTES;
        }
        return true;
    }
}
#endif // MIQ_ENABLE_HEADERS_FIRST

#if MIQ_ENABLE_ADDRMAN
namespace {
    static miq::AddrMan g_addrman;
    static std::string  g_addrman_path;
    static int64_t      g_last_addrman_save = 0;
    static int64_t      g_next_feeler_ms    = 0;
    static miq::FastRand g_am_rng{0xC0FFEEULL};
}
#endif

// ---- server creation: IPv4 and IPv6 ----------------------------------------
static Sock create_server(uint16_t port){
#ifdef _WIN32
    Sock s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    Sock s = socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (s == MIQ_INVALID_SOCK) return MIQ_INVALID_SOCK;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    if (listen(s, SOMAXCONN) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    return s;
}
static Sock create_server_v6(uint16_t port){
#ifdef _WIN32
    Sock s = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
#else
    Sock s = socket(AF_INET6, SOCK_STREAM, 0);
#endif
    if (s == MIQ_INVALID_SOCK) return MIQ_INVALID_SOCK;
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    // Prefer v6-only (we already have a v4 listener)
    int v6only = 1;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&v6only, sizeof(v6only));
    sockaddr_in6 a6{}; a6.sin6_family = AF_INET6; a6.sin6_addr = in6addr_any; a6.sin6_port = htons(port);
    if (bind(s, (sockaddr*)&a6, sizeof(a6)) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    if (listen(s, SOMAXCONN) != 0) { CLOSESOCK(s); return MIQ_INVALID_SOCK; }
    return s;
}

std::string P2P::hexkey(const std::vector<uint8_t>& h) {
    static const char* kHex = "0123456789abcdef";
    std::string s; s.resize(h.size()*2);
    for (size_t i=0;i<h.size();++i) {
        s[2*i+0] = kHex[(h[i]>>4) & 0xF];
        s[2*i+1] = kHex[(h[i]    ) & 0xF];
    }
    return s;
}

// IPv4 helpers
bool P2P::parse_ipv4(const std::string& dotted, uint32_t& be_ip){
    sockaddr_in tmp{};
#ifdef _WIN32
    if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#else
    if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#endif
    be_ip = tmp.sin_addr.s_addr;
    return true;
}
static inline uint32_t be(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
    return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|uint32_t(d);
}
bool P2P::ipv4_is_public(uint32_t be_ip){
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    if (A == 0 || A == 10 || A == 127) return false;
    if (A == 169 && B == 254) return false;
    if (A == 192 && B == 168) return false;
    if (A == 172 && (uint8_t(be_ip>>20) & 0x0F) >= 1 && (uint8_t(be_ip>>20) & 0x0F) <= 15) return false;
    if (A >= 224) return false;
    return true;
}

P2P::P2P(Chain& c) : chain_(c) {
    orphan_bytes_limit_ = (size_t)MIQ_ORPHAN_MAX_BYTES;
    orphan_count_limit_ = (size_t)MIQ_ORPHAN_MAX_COUNT;
}
P2P::~P2P(){ stop(); }

void P2P::load_bans(){
    std::ifstream f(datadir_ + "/bans.txt");
    std::string ip;
    while (f >> ip) banned_.insert(ip);
}
void P2P::save_bans(){
    std::ofstream f(datadir_ + "/bans.txt", std::ios::trunc);
    for (auto& ip : banned_) f << ip << "\n";
}

void P2P::bump_ban(PeerState& ps, const std::string& ip, const char* reason, int64_t now_ms)
{
    // Do not ban localhost or whitelisted peers (never hairpin-ban loopback).
    if (is_loopback(ip) || is_whitelisted_ip(ip)) {
        P2P_TRACE(std::string("skip-ban loopback/whitelist ip=") + ip + " reason=" + (reason?reason:""));
        return;
    }
    // Timed ban record
    timed_bans_[ip] = now_ms + default_ban_ms_;
    banned_.insert(ip);

    // Close socket to enforce the ban immediately.
    Sock s = ps.sock;
    if (s != MIQ_INVALID_SOCK) {
        P2P_TRACE(std::string("ban-close ip=") + ip + " reason=" + (reason?reason:""));
        CLOSESOCK(s);
        ps.sock = MIQ_INVALID_SOCK;
    }
    (void)reason;
}

// Global IPv6 server socket for this TU (keeps p2p.h untouched)
static Sock g_srv6_ = MIQ_INVALID_SOCK;

bool P2P::start(uint16_t port){
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    load_bans();
    load_addrs_from_disk(datadir_, addrv4_);

#if MIQ_ENABLE_ADDRMAN
    g_addrman_path = datadir_ + "/" + std::string(MIQ_ADDRMAN_FILE);
    {
        std::string err;
        if (g_addrman.load(g_addrman_path, err)) {
            log_info("P2P: addrman loaded (" + std::to_string(g_addrman.size()) + " addrs)");
        } else {
            log_info("P2P: addrman load: " + err);
        }
        g_last_addrman_save = now_ms();
        g_next_feeler_ms    = now_ms() + MIQ_FEELER_INTERVAL_MS;
    }
#endif

    // NOTE: srv_ is Sock; Windows-safe
    srv_ = create_server(port);
    if (srv_ == MIQ_INVALID_SOCK) { log_error("P2P: failed to create IPv4 server"); return false; }
    // New: IPv6 server as well
    g_srv6_ = create_server_v6(port);
    if (g_srv6_ == MIQ_INVALID_SOCK) {
        log_warn("P2P: IPv6 server not created (continuing with IPv4 only)");
    }
    g_listen_port = port;

    g_last_progress_ms = now_ms();
    g_last_progress_height = chain_.height();
    g_next_stall_probe_ms = g_last_progress_ms + MIQ_P2P_STALL_RETRY_MS;

    std::string ext_ip;
    {
        miq::TryOpenP2PPort(port, &ext_ip);
        if (!ext_ip.empty()) log_info("P2P: external IP (UPnP): " + ext_ip);
    }

    gather_self_ipv4_basic();
    if (!ext_ip.empty()) self_add_dotted(ext_ip);
    gather_self_from_env();
    if (!g_self_v4.empty()) {
        log_info("P2P: self-ip guard active: " + self_list_for_log());
    }

    {
        size_t dropped = 0;
        for (auto it = addrv4_.begin(); it != addrv4_.end(); ) {
            uint32_t be_ip = *it;
            if (!ipv4_is_public(be_ip) || is_loopback_be(be_ip) || is_self_be(be_ip)) {
                it = addrv4_.erase(it);
                ++dropped;
            } else {
                ++it;
            }
        }
        if (dropped) {
            log_warn("P2P: pruned " + std::to_string(dropped) +
                     " non-public/loopback/self addrs from legacy store");
        }
    }

    {
        std::vector<miq::SeedEndpoint> seeds;
        if (miq::resolve_dns_seeds(seeds, port, /*include_single_dns_seed=*/true)) {
            size_t added = 0;
            for (const auto& s : seeds) {
                uint32_t be_ip;
                if (parse_ipv4(s.ip, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip)) {
                    added += addrv4_.insert(be_ip).second ? 1 : 0;
#if MIQ_ENABLE_ADDRMAN
                    miq::NetAddr na;
                    na.host = s.ip; na.port = port; na.is_ipv6 = false; na.tried = false;
                    g_addrman.add(na, /*from_dns=*/true);
#endif
                }
            }
            if (added) log_info("P2P: loaded " + std::to_string(added) + " seed addrs");
            size_t boots = std::min<size_t>(seeds.size(), 3);
            for (size_t i = 0; i < boots; ++i) {
                (void)connect_seed(seeds[i].ip, port);
            }
        } else {
            log_warn("P2P: no seeds resolved");
        }
    }

    running_ = true;

    th_ = std::thread([this]{
        for(;;){
            try {
                loop();
                break;
            } catch (const std::exception& e) {
                log_error(std::string("P2P: loop exception: ") + e.what());
            } catch (...) {
                log_error("P2P: loop exception (unknown)");
            }
            if(!running_) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    return true;
}

void P2P::stop(){
    if (!running_) return;
    running_ = false;
    if (srv_ != MIQ_INVALID_SOCK) { CLOSESOCK(srv_); srv_ = MIQ_INVALID_SOCK; }
    if (g_srv6_ != MIQ_INVALID_SOCK) { CLOSESOCK(g_srv6_); g_srv6_ = MIQ_INVALID_SOCK; }
    for (auto& kv : peers_) {
        if (kv.first != MIQ_INVALID_SOCK) {
            gate_on_close(kv.first);
            CLOSESOCK(kv.first);
        }
    }
    peers_.clear();
    if (th_.joinable()) th_.join();
#ifdef _WIN32
    WSACleanup();
#endif
    save_bans();
    save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
    {
        std::string err;
        if (!g_addrman.save(g_addrman_path, err)) {
            log_warn("P2P: addrman save failed: " + err);
        }
    }
#endif
}

// === outbound connect helpers ===============================================

// REVISED: dual-stack + literal-safe resolver
bool P2P::connect_seed(const std::string& host, uint16_t port){
    {
        int64_t now = now_ms();
        auto it = g_seed_backoff.find(host);
        if (it != g_seed_backoff.end() && it->second.first > now) {
            return false;
        }
    }

    std::vector<MiqEndpoint> eps;
    if (!miq_resolve_endpoints_from_string(host, port, eps)) {
        int64_t now = now_ms();
        auto &st = g_seed_backoff[host];
        int64_t cur = st.second > 0 ? st.second : seed_backoff_base_ms();
        cur = std::min<int64_t>(cur * 2, seed_backoff_max_ms());
        cur += jitter_ms(5000);
        st = { now + cur, cur };
        log_warn(std::string("P2P: DNS resolve failed: ") + host + " (backoff " + std::to_string(cur) + "ms)");
        return false;
    }

    Sock s = MIQ_INVALID_SOCK;
    std::string peer_ip = "unknown";

    for (const auto& ne : eps) {
        // Skip obvious self/hairpin for IPv4 candidates
        if (ne.ss.ss_family == AF_INET) {
            const sockaddr_in* a4 = reinterpret_cast<const sockaddr_in*>(&ne.ss);
            uint32_t be_ip = a4->sin_addr.s_addr;
            if (is_loopback_be(be_ip) || is_self_be(be_ip)) continue;
            if (banned_.count(be_ip_to_string(be_ip))) continue;
        }

#ifdef _WIN32
        Sock ts = socket(ne.ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
#else
        Sock ts = socket(ne.ss.ss_family, SOCK_STREAM, 0);
#endif
        if (ts == MIQ_INVALID_SOCK) continue;

        if (connect(ts, (const sockaddr*)&ne.ss, ne.len) != 0) {
            CLOSESOCK(ts);
            continue;
        }

        // Connected
        s = ts;
        peer_ip = miq_ntop_sockaddr(ne.ss);

        // Reject obvious hairpin on same port
        if (is_self_endpoint(s, g_listen_port)) {
            P2P_TRACE("reject hairpin outbound (seed)");
            CLOSESOCK(s);
            s = MIQ_INVALID_SOCK;
            continue;
        }
        break;
    }

    if (s == MIQ_INVALID_SOCK) {
        int64_t now = now_ms();
        auto &st = g_seed_backoff[host];
        int64_t cur = st.second > 0 ? st.second : seed_backoff_base_ms();
        cur = std::min<int64_t>(cur * 2, seed_backoff_max_ms());
        cur += jitter_ms(5000);
        st = { now + cur, cur };
        return false;
    }

    g_seed_backoff.erase(host);

    PeerState ps;
    ps.sock = s;
    ps.ip   = peer_ip;
    ps.mis  = 0;
    ps.last_ms = now_ms();
    ps.blk_tokens = MIQ_RATE_BLOCK_BURST;
    ps.tx_tokens  = MIQ_RATE_TX_BURST;
    ps.last_refill_ms = ps.last_ms;
    ps.inflight_hdr_batches = 0;
    ps.rate.last_ms = ps.last_ms;
    ps.banscore = 0;
    ps.version = 0;
    ps.features = 0;
    ps.whitelisted = false;
    peers_[s] = ps;

    g_trickle_last_ms[s] = 0;

    uint32_t be_ip;
    if (parse_ipv4(ps.ip, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip)) {
        addrv4_.insert(be_ip);
#if MIQ_ENABLE_ADDRMAN
        miq::NetAddr na; na.host = ps.ip; na.port = port; na.tried = true; na.is_ipv6=false;
        g_addrman.mark_good(na);
        g_addrman.add_anchor(na);
#endif
    }

    log_info("P2P: connected seed " + peers_[s].ip);

    // Gate first, then mark loopback (so flag actually sticks)
    gate_on_connect(s);
    if (parse_ipv4(ps.ip, be_ip)) {
        gate_set_loopback(s, is_loopback_be(be_ip));
    }

    auto msg = encode_msg("version", miq_build_version_payload());
    (void)miq_send(s, msg);

    return true;
}

static std::mt19937& rng(){
    static thread_local std::mt19937 gen{std::random_device{}()};
    return gen;
}

static bool violates_group_diversity(const std::unordered_map<Sock, miq::PeerState>& peers,
                                     uint32_t candidate_be_ip)
{
    // Count per /16 among current peers; cap outbounds per group to reduce eclipse risk.
    std::unordered_map<uint16_t,int> group_counts;

    auto parse_be_ipv4 = [](const std::string& dotted, uint32_t& be_ip)->bool{
        sockaddr_in tmp{};
    #ifdef _WIN32
        if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
    #else
        if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
    #endif
        be_ip = tmp.sin_addr.s_addr; // network byte order
        return true;
    };

    for (const auto& kv : peers){
        const auto& ps = kv.second;
        uint32_t be_ip2 = 0;
        if (!parse_be_ipv4(ps.ip, be_ip2)) continue;
        uint16_t g = (uint16_t(uint8_t(be_ip2>>24)) << 8) | uint16_t(uint8_t(be_ip2>>16));
        group_counts[g]++;
    }

    uint16_t cg = (uint16_t(uint8_t(candidate_be_ip>>24)) << 8) | uint16_t(uint8_t(candidate_be_ip>>16));
    auto it = group_counts.find(cg);
    return (it != group_counts.end() && it->second >= MIQ_GROUP_OUTBOUND_MAX);
}

void P2P::handle_new_peer(Sock c, const std::string& ip){
    PeerState ps;
    ps.sock = c;
    ps.ip   = ip;
    ps.mis  = 0;
    ps.last_ms = now_ms();
    ps.blk_tokens = MIQ_RATE_BLOCK_BURST;
    ps.tx_tokens  = MIQ_RATE_TX_BURST;
    ps.last_refill_ms = ps.last_ms;
    ps.inflight_hdr_batches = 0;
    ps.rate.last_ms = ps.last_ms;
    ps.banscore = 0;
    ps.version = 0;
    ps.features = 0;
    ps.whitelisted = false;
    peers_[c] = ps;

    g_trickle_last_ms[c] = 0;

    uint32_t be_ip;
    if (parse_ipv4(ip, be_ip) && ipv4_is_public(be_ip)) {
        addrv4_.insert(be_ip);
    #if MIQ_ENABLE_ADDRMAN
        miq::NetAddr na; na.host=ip; na.port=g_listen_port; na.is_ipv6=false; na.tried=false;
        g_addrman.add(na, /*from_dns=*/false);
    #endif
    }

    log_info("P2P: inbound peer " + ip);

    // Gate first, then mark loopback (critical for localhost wallet)
    gate_on_connect(c);
    if (parse_ipv4(ip, be_ip)) {
        gate_set_loopback(c, is_loopback_be(be_ip));
    }

    auto msg = encode_msg("version", miq_build_version_payload());
    (void)miq_send(c, msg);
}

void P2P::broadcast_inv_block(const std::vector<uint8_t>& h){
   announce_block_async(h);
}

void P2P::announce_block_async(const std::vector<uint8_t>& h) {
    if (h.size() != 32) return;
    std::lock_guard<std::mutex> lk(announce_mu_);
    if (announce_blocks_q_.size() < 1024) {
        announce_blocks_q_.push_back(h);
    }
}

// =================== helpers for sync / serving ===================

static inline void trickle_enqueue(Sock sock, const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    auto& q = g_trickle_q[sock];
    if (q.size() < 4096) q.push_back(txid);
}

void P2P::broadcast_inv_tx(const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    // queue for loop thread so only the loop touches peers_
    std::lock_guard<std::mutex> lk(announce_tx_mu_);
    if (announce_tx_q_.size() < 8192) announce_tx_q_.push_back(txid);
}

static void trickle_flush(){
    int64_t tnow = now_ms();
    for (auto& kv : g_trickle_q) {
        Sock s = kv.first;
        auto& q = kv.second;

        int64_t last = 0;
        auto it_last = g_trickle_last_ms.find(s);
        if (it_last != g_trickle_last_ms.end()) last = it_last->second;

        if (tnow - last < MIQ_P2P_TRICKLE_MS) continue;

        size_t n_send = 0;
        while (!q.empty() && n_send < MIQ_P2P_TRICKLE_BATCH) {
            const auto& txid = q.back();
            auto m = miq::encode_msg("invtx", txid);
            (void)miq_send(s, m);
            q.pop_back();
            ++n_send;
        }
        g_trickle_last_ms[s] = tnow;
    }
}

void P2P::request_tx(PeerState& ps, const std::vector<uint8_t>& txid){
    if (txid.size()!=32) return;
    if (!check_rate(ps, "get", 1.0, now_ms())) return;
    if (ps.inflight_tx.size() >= caps_.max_txs) return;
    auto m = encode_msg("gettx", txid);
    (void)miq_send(ps.sock, m);
    ps.inflight_tx.insert(hexkey(txid));
}

void P2P::send_tx(Sock sock, const std::vector<uint8_t>& raw){
    if (raw.empty()) return;
    auto m = encode_msg("tx", raw);
    (void)miq_send(sock, m);
}

void P2P::start_sync_with_peer(PeerState& ps){
    ps.syncing = true;
    ps.next_index = chain_.height() + 1;
    request_block_index(ps, ps.next_index);
}

void P2P::request_block_index(PeerState& ps, uint64_t index){
    uint8_t p[8];
    for (int i=0;i<8;i++) p[i] = (uint8_t)((index >> (8*i)) & 0xFF);
    auto msg = encode_msg("getbi", std::vector<uint8_t>(p, p+8));
    (void)miq_send(ps.sock, msg);
}

void P2P::request_block_hash(PeerState& ps, const std::vector<uint8_t>& h){
    if (h.size()!=32) return;
    if (!check_rate(ps, "get", 1.0, now_ms())) return;
    if (ps.inflight_blocks.size() >= caps_.max_blocks) return;
    auto msg = encode_msg("getb", h);
    (void)miq_send(ps.sock, msg);
    ps.inflight_blocks.insert(hexkey(h));
}

void P2P::send_block(Sock s, const std::vector<uint8_t>& raw){
    if (raw.empty()) return;
    auto msg = encode_msg("block", raw);
    (void)miq_send(s, msg);
}

// === rate-limit helpers ======================================================

void P2P::rate_refill(PeerState& ps, int64_t now){
    int64_t dt = now - ps.last_refill_ms;
    if (dt <= 0) return;
    uint64_t add_blk = (uint64_t)((MIQ_RATE_BLOCK_BPS * (uint64_t)dt) / 1000ull);
    uint64_t add_tx  = (uint64_t)((MIQ_RATE_TX_BPS    * (uint64_t)dt) / 1000ull);
    ps.blk_tokens = std::min<uint64_t>(MIQ_RATE_BLOCK_BURST, ps.blk_tokens + add_blk);
    ps.tx_tokens  = std::min<uint64_t>(MIQ_RATE_TX_BURST,   ps.tx_tokens  + add_tx);
    ps.last_refill_ms = now;
}

bool P2P::rate_consume_block(PeerState& ps, size_t nbytes){
    int64_t n = now_ms();
    rate_refill(ps, n);
    if (ps.blk_tokens < nbytes) return false;
    ps.blk_tokens -= (uint64_t)nbytes;
    return true;
}
bool P2P::rate_consume_tx(PeerState& ps, size_t nbytes){
    int64_t n = now_ms();
    rate_refill(ps, n);
    if (ps.tx_tokens < nbytes) return false;
    ps.tx_tokens -= (uint64_t)nbytes;
    return true;
}

// === addr handling ===========================================================

void P2P::maybe_send_getaddr(PeerState& ps){
    int64_t t = now_ms();
    if (t - ps.last_getaddr_ms < (int64_t)MIQ_P2P_GETADDR_INTERVAL_MS) return;
    ps.last_getaddr_ms = t;
    auto msg = encode_msg("getaddr", {});
    if (check_rate(ps, "get", 1.0, t)) {
        (void)miq_send(ps.sock, msg);
    }
}

void P2P::send_addr_snapshot(PeerState& ps){
    if (!check_rate(ps, "addr", 1.0, now_ms())) return;
    std::vector<uint8_t> payload;
    payload.reserve(MIQ_ADDR_RESPONSE_MAX * 4);
    size_t cnt = 0;

#if MIQ_ENABLE_ADDRMAN
    {
        std::unordered_set<uint32_t> emitted;
        for (int tries = 0; tries < (int)(MIQ_ADDR_RESPONSE_MAX * 3) && cnt < MIQ_ADDR_RESPONSE_MAX; ++tries) {
            auto cand = g_addrman.select_for_outbound(g_am_rng, /*prefer_tried=*/true);
            if (!cand) break;
            uint32_t be_ip;
            if (!parse_ipv4(cand->host, be_ip) || !ipv4_is_public(be_ip)) continue;

            if (!emitted.insert(be_ip).second) continue;

            payload.push_back((uint8_t)(be_ip >> 24));
            payload.push_back((uint8_t)(be_ip >> 16));
            payload.push_back((uint8_t)(be_ip >> 8));
            payload.push_back((uint8_t)(be_ip >> 0));
            ++cnt;
        }
    }
#endif

    for (uint32_t be_ip : addrv4_) {
        if (cnt >= MIQ_ADDR_RESPONSE_MAX) break;
        if (!ipv4_is_public(be_ip)) continue;
        payload.push_back((uint8_t)(be_ip >> 24));
        payload.push_back((uint8_t)(be_ip >> 16));
        payload.push_back((uint8_t)(be_ip >> 8));
        payload.push_back((uint8_t)(be_ip >> 0));
        ++cnt;
    }
    auto msg = encode_msg("addr", payload);
    (void)miq_send(ps.sock, msg);
}
void P2P::handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload){
    int64_t t = now_ms();
    if (t - ps.last_addr_ms < MIQ_ADDR_MIN_INTERVAL_MS) {
        if (++ps.mis > 20) { bump_ban(ps, ps.ip, "addr-interval", t); }
        return;
    }
    ps.last_addr_ms = t;

    if (!check_rate(ps, "addr", std::max(1.0, (double)(payload.size()/64u)), t)) {
        bump_ban(ps, ps.ip, "addr-flood", t);
        return;
    }

    if (payload.size() % 4 != 0) return;
    size_t n = payload.size() / 4;
    if (n > MIQ_ADDR_MAX_BATCH) n = MIQ_ADDR_MAX_BATCH;

    size_t accepted = 0;
    for (size_t i=0;i<n;i++){
        uint32_t be_ip =
            (uint32_t(payload[4*i+0])<<24) |
            (uint32_t(payload[4*i+1])<<16) |
            (uint32_t(payload[4*i+2])<<8 ) |
            (uint32_t(payload[4*i+3])<<0 );
        if (!ipv4_is_public(be_ip)) continue;
        addrv4_.insert(be_ip);
#if MIQ_ENABLE_ADDRMAN
        char buf[64]={0};
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=be_ip;
#ifdef _WIN32
        InetNtopA(AF_INET, &a.sin_addr, buf, (int)sizeof(buf));
#else
        inet_ntop(AF_INET, &a.sin_addr, buf, (socklen_t)sizeof(buf));
#endif
        miq::NetAddr na; na.host=buf; na.port=g_listen_port; na.is_ipv6=false; na.tried=false;
        g_addrman.add(na, /*from_dns=*/false);
#endif
        ++accepted;
    }
    if (accepted == 0) {
        if (++ps.mis > 30) bump_ban(ps, ps.ip, "addr-empty", now_ms());
    }
}

// =================== Orphan manager =========================================

void P2P::evict_orphans_if_needed(){
    while ( (orphan_bytes_ > orphan_bytes_limit_) ||
            (orphans_.size() > orphan_count_limit_) ) {
        if (orphan_order_.empty()) break;
        const std::string victim = orphan_order_.front();
        orphan_order_.pop_front();

        auto it = orphans_.find(victim);
        if (it == orphans_.end()) continue;

        const std::string parent_hex = hexkey(it->second.prev);
        orphan_bytes_ -= it->second.raw.size();
        orphans_.erase(it);

        auto pit = orphan_children_.find(parent_hex);
        if (pit != orphan_children_.end()){
            auto& vec = pit->second;
            vec.erase(std::remove(vec.begin(), vec.end(), victim), vec.end());
            if (vec.empty()) orphan_children_.erase(pit);
        }
        log_warn("P2P: evicted orphan " + victim);
    }
}

void P2P::remove_orphan_by_hex(const std::string& child_hex){
    auto it = orphans_.find(child_hex);
    if (it == orphans_.end()) return;
    const std::string parent_hex = hexkey(it->second.prev);
    if (orphan_bytes_ >= it->second.raw.size())
        orphan_bytes_ -= it->second.raw.size();
    else
        orphan_bytes_ = 0;

    orphans_.erase(it);

    auto pit = orphan_children_.find(parent_hex);
    if (pit != orphan_children_.end()){
        auto& vec = pit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), child_hex), vec.end());
        if (vec.empty()) orphan_children_.erase(pit);
    }

    auto dit = std::find(orphan_order_.begin(), orphan_order_.end(), child_hex);
    if (dit != orphan_order_.end()) orphan_order_.erase(dit);
}

void P2P::handle_incoming_block(Sock sock, const std::vector<uint8_t>& raw){
    if (raw.empty() || raw.size() > MIQ_FALLBACK_MAX_BLOCK_SZ) return;

    Block b;
    if (!deser_block(raw, b)) return;

    const auto bh = b.block_hash();
    if (chain_.have_block(bh)) return;

    bool have_parent = chain_.have_block(b.header.prev_hash);

    if (!have_parent) {
        OrphanRec rec{ bh, b.header.prev_hash, raw };
        const std::string child_hex  = hexkey(bh);
        const std::string parent_hex = hexkey(b.header.prev_hash);

        if (orphans_.find(child_hex) == orphans_.end()) {
            orphans_.emplace(child_hex, std::move(rec));
            orphan_children_[parent_hex].push_back(child_hex);
            orphan_order_.push_back(child_hex);
            orphan_bytes_ += raw.size();
            evict_orphans_if_needed();
            log_info("P2P: stored orphan block child=" + child_hex + " parent=" + parent_hex);
        }

        auto pit = peers_.find(sock);
        if (pit != peers_.end()) {
            request_block_hash(pit->second, b.header.prev_hash);
        }
        return;
    }

    std::string err;
    if (chain_.submit_block(b, err)) {
        const std::string miner = miq_miner_from_block(b);
        std::string src_ip = "?";
        auto pit = peers_.find(sock);
        if (pit != peers_.end()) src_ip = pit->second.ip;

        log_info("P2P: accepted block height=" + std::to_string(chain_.height())
                 + " miner=" + miner
                 + " from=" + src_ip);

        broadcast_inv_block(bh);
        try_connect_orphans(hexkey(bh));
        g_last_progress_ms = now_ms();
        g_last_progress_height = chain_.height();
    } else {
        log_warn("P2P: reject block (" + err + ")");
    }
}

void P2P::try_connect_orphans(const std::string& parent_hex){
    std::vector<std::string> q;
    auto it = orphan_children_.find(parent_hex);
    if (it != orphan_children_.end()) {
        q.assign(it->second.begin(), it->second.end());
        orphan_children_.erase(it);
    }

    while (!q.empty()){
        std::string child_hex = q.back();
        q.pop_back();

        auto oit = orphans_.find(child_hex);
        if (oit == orphans_.end()) continue;

        Block ob;
        if (!deser_block(oit->second.raw, ob)) {
            remove_orphan_by_hex(child_hex);
            continue;
        }

        if (chain_.have_block(oit->second.hash)) {
            remove_orphan_by_hex(child_hex);
            continue;
        }

        std::string err;
        if (chain_.submit_block(ob, err)) {
            const std::string miner = miq_miner_from_block(ob);
            log_info("P2P: accepted orphan as block height=" + std::to_string(chain_.height())
                     + " miner=" + miner);

            broadcast_inv_block(oit->second.hash);
            const std::string new_parent_hex = child_hex;
            remove_orphan_by_hex(child_hex);

            auto cit = orphan_children_.find(new_parent_hex);
            if (cit != orphan_children_.end()) {
                for (const auto& g : cit->second) q.push_back(g);
                orphan_children_.erase(cit);
            }
            g_last_progress_ms = now_ms();
            g_last_progress_height = chain_.height();
        } else {
            log_warn("P2P: orphan child rejected (" + err + "), dropping orphan " + child_hex);
            remove_orphan_by_hex(child_hex);
        }
    }
}

// ============================================================================

void P2P::loop(){
    int64_t last_addr_save_ms = now_ms();
    int64_t last_dial_ms = now_ms();

    while (running_) {
        if ((int)peers_.size() < MIQ_OUTBOUND_TARGET && g_listen_port != 0) {
            int64_t tnow = now_ms();
            if (tnow - last_dial_ms > MIQ_DIAL_INTERVAL_MS) {
                last_dial_ms = tnow;

#if MIQ_ENABLE_ADDRMAN
                bool dialed = false;
                for (int attempts=0; attempts<8 && !dialed; ++attempts){
                    auto cand = g_addrman.select_for_outbound(g_am_rng, /*prefer_tried=*/true);
                    if (!cand) break;
                    uint32_t be_ip;
                    if (!parse_ipv4(cand->host, be_ip) || !ipv4_is_public(be_ip)) {
                        g_addrman.mark_attempt(*cand);
                        continue;
                    }
                    if (is_self_be(be_ip)) { g_addrman.mark_attempt(*cand); continue; }
                    if (violates_group_diversity(peers_, be_ip)) {
                        g_addrman.mark_attempt(*cand);
                        continue;
                    }
                    std::string dotted = be_ip_to_string(be_ip);
                    if (banned_.count(dotted)) { g_addrman.mark_attempt(*cand); continue; }
                    bool connected = false;
                    for (auto& kv : peers_) if (kv.second.ip == dotted) { connected = true; break; }
                    if (connected) { g_addrman.mark_attempt(*cand); continue; }

                    Sock s = dial_be_ipv4(be_ip, g_listen_port);
                    if (s != MIQ_INVALID_SOCK) {
                        PeerState ps; ps.sock = s; ps.ip = dotted; ps.mis=0; ps.last_ms=now_ms();
                        ps.blk_tokens = MIQ_RATE_BLOCK_BURST; ps.tx_tokens=MIQ_RATE_TX_BURST; ps.last_refill_ms=ps.last_ms;
                        ps.inflight_hdr_batches = 0; ps.rate.last_ms=ps.last_ms; ps.banscore=0; ps.version=0; ps.features=0; ps.whitelisted=false;
                        peers_[s] = ps;
                        g_trickle_last_ms[s] = 0;
                        log_info("P2P: outbound (addrman) " + ps.ip);
                        gate_on_connect(s);
                        gate_set_loopback(s, is_loopback_be(be_ip));
                        auto msg = encode_msg("version", miq_build_version_payload());
                        (void)miq_send(s, msg);
                        dialed = true;
                    } else {
                        g_addrman.mark_attempt(*cand);
                    }
                }

                if (!dialed && !addrv4_.empty()) {
#endif
                    std::vector<uint32_t> candidates;
                    candidates.reserve(addrv4_.size());
                    for (uint32_t ip : addrv4_) {
                        if (is_self_be(ip)) continue;
                        if (is_loopback_be(ip)) continue;
                        std::string dotted = be_ip_to_string(ip);
                        if (banned_.count(dotted)) continue;
                        bool connected = false;
                        for (auto& kv : peers_) {
                            if (kv.second.ip == dotted) { connected = true; break; }
                        }
                        if (connected) continue;
                        if (violates_group_diversity(peers_, ip)) continue;
                        candidates.push_back(ip);
                    }
                    if (!candidates.empty()) {
                        std::uniform_int_distribution<size_t> dist(0, candidates.size()-1);
                        uint32_t pick = candidates[dist(rng())];

                        if (!is_loopback_be(pick)) {
                            Sock s = dial_be_ipv4(pick, g_listen_port);
                            if (s != MIQ_INVALID_SOCK) {
                                PeerState ps;
                                ps.sock = s;
                                ps.ip   = be_ip_to_string(pick);
                                ps.mis  = 0;
                                ps.last_ms = now_ms();
                                ps.blk_tokens = MIQ_RATE_BLOCK_BURST;
                                ps.tx_tokens  = MIQ_RATE_TX_BURST;
                                ps.last_refill_ms = ps.last_ms;
                                ps.inflight_hdr_batches = 0; ps.rate.last_ms=ps.last_ms; ps.banscore=0; ps.version=0; ps.features=0; ps.whitelisted=false;
                                peers_[s] = ps;
                                g_trickle_last_ms[s] = 0;

                                log_info("P2P: outbound to known " + ps.ip);
                                gate_on_connect(s);
                                gate_set_loopback(s, is_loopback_be(pick));
                                auto msg = encode_msg("version", miq_build_version_payload());
                                (void)miq_send(s, msg);
                            }
                        }
                    }
#if MIQ_ENABLE_ADDRMAN
                }
#endif
            }
        }

#if MIQ_ENABLE_ADDRMAN
        {
            int64_t tnow = now_ms();
            if (tnow >= g_next_feeler_ms) {
                g_next_feeler_ms = tnow + MIQ_FEELER_INTERVAL_MS + (int)(g_am_rng.next()%5000);
                auto cand = g_addrman.select_feeler(g_am_rng);
                if (cand) {
                    uint32_t be_ip;
                    if (parse_ipv4(cand->host, be_ip) && ipv4_is_public(be_ip) && !is_self_be(be_ip) && !violates_group_diversity(peers_, be_ip)) {
                        std::string dotted = be_ip_to_string(be_ip);
                        if (!banned_.count(dotted)) {
                            bool connected=false; for (auto& kv:peers_) if (kv.second.ip==dotted) { connected=true; break; }
                            if (!connected) {
                                Sock s = dial_be_ipv4(be_ip, g_listen_port);
                                if (s != MIQ_INVALID_SOCK) {
                                    PeerState ps; ps.sock=s; ps.ip=dotted; ps.mis=0; ps.last_ms=now_ms();
                                    ps.blk_tokens = MIQ_RATE_BLOCK_BURST; ps.tx_tokens=MIQ_RATE_TX_BURST; ps.last_refill_ms=ps.last_ms;
                                    ps.inflight_hdr_batches = 0; ps.rate.last_ms=ps.last_ms; ps.banscore=0; ps.version=0; ps.features=0; ps.whitelisted=false;
                                    peers_[s]=ps;
                                    g_trickle_last_ms[s] = 0;
                                    log_info("P2P: feeler " + dotted);
                                    gate_on_connect(s);
                                    gate_set_loopback(s, is_loopback_be(be_ip));
                                    auto msg = encode_msg("version", miq_build_version_payload());
                                    (void)miq_send(s, msg);
                                }
                            }
                        }
                    }
                }
            }
        }
#endif

        {
            int64_t tnow = now_ms();
            size_t h = chain_.height();
            if (h > g_last_progress_height) {
                g_last_progress_height = h;
                g_last_progress_ms = tnow;
                g_next_stall_probe_ms = tnow + MIQ_P2P_STALL_RETRY_MS;
            } else if (tnow >= g_next_stall_probe_ms && !peers_.empty()) {
#if MIQ_ENABLE_HEADERS_FIRST
                std::vector<std::vector<uint8_t>> locator;
                chain_.build_locator(locator);
                std::vector<uint8_t> stop(32, 0);
                auto pl = build_getheaders_payload(locator, stop);
                auto m  = encode_msg("getheaders", pl);
                int probes = 0;
                for (auto& kv : peers_) {
                    if (kv.second.verack_ok &&
                        can_accept_hdr_batch(kv.second, now_ms()) &&
                        check_rate(kv.second, "get", 1.0, now_ms())) {
                        kv.second.sent_getheaders = true;
                        (void)miq_send(kv.first, m);
                        kv.second.inflight_hdr_batches++;
                        if (++probes >= 2) break;
                    }
                }
#endif
                g_next_stall_probe_ms = tnow + MIQ_P2P_STALL_RETRY_MS;
            }
        }

        // --- build pollfd list (SNAPSHOT of peers_) ---
        std::vector<PollFD> fds;
        std::vector<Sock>   peer_fd_order;
        size_t srv_idx_v4 = (size_t)-1, srv_idx_v6 = (size_t)-1;
        size_t base = 0;

        if (srv_ != MIQ_INVALID_SOCK) {
#ifdef _WIN32
            WSAPOLLFD pf{}; pf.fd = srv_; pf.events = POLL_RD; pf.revents = 0;
            fds.push_back(pf);
#else
            fds.push_back(pollfd{ (int)srv_, POLL_RD, 0 });
#endif
            srv_idx_v4 = fds.size() - 1;
        }
        if (g_srv6_ != MIQ_INVALID_SOCK) {
#ifdef _WIN32
            WSAPOLLFD pf{}; pf.fd = g_srv6_; pf.events = POLL_RD; pf.revents = 0;
            fds.push_back(pf);
#else
            fds.push_back(pollfd{ (int)g_srv6_, POLL_RD, 0 });
#endif
            srv_idx_v6 = fds.size() - 1;
        }

        base = fds.size();
        for (auto& kv : peers_) {
            Sock fd = kv.first;
            peer_fd_order.push_back(fd);
#ifdef _WIN32
            WSAPOLLFD pf{};
            pf.fd = fd;
            pf.events = POLL_RD;
            pf.revents = 0;
            fds.push_back(pf);
#else
            fds.push_back(pollfd{ (int)fd, POLL_RD, 0 });
#endif
        }

#ifdef _WIN32
        int rc = WSAPoll(fds.data(), (ULONG)fds.size(), 200);
#else
        int rc = poll(fds.data(), fds.size(), 200);
#endif
        if (rc < 0) continue;

        // Accept new peers (with soft inbound rate cap) - IPv4
        if (srv_ != MIQ_INVALID_SOCK && srv_idx_v4 < fds.size() && (fds[srv_idx_v4].revents & POLL_RD)) {
            sockaddr_in ca{};
#ifdef _WIN32
            int clen = (int)sizeof(ca);
#else
            socklen_t clen = sizeof(ca);
#endif
            Sock c = accept(srv_, (sockaddr*)&ca, &clen);
            if (c != MIQ_INVALID_SOCK) {
                if (is_self_endpoint(c, g_listen_port)) {
                    P2P_TRACE("reject hairpin inbound");
                    CLOSESOCK(c);
                } else {
                    int64_t tnow = now_ms();
                    if (tnow - inbound_win_start_ms_ > 60000) {
                        inbound_win_start_ms_ = tnow;
                        inbound_accepts_in_window_ = 0;
                    }
                    if (inbound_accepts_in_window_ >= MIQ_P2P_NEW_INBOUND_CAP_PER_MIN) {
                        P2P_TRACE("reject inbound: per-minute cap");
                        CLOSESOCK(c);
                    } else {
                        inbound_accepts_in_window_++;

                        char ipbuf[64] = {0};
#ifdef _WIN32
                        InetNtopA(AF_INET, &ca.sin_addr, ipbuf, (int)sizeof(ipbuf));
#else
                        inet_ntop(AF_INET, &ca.sin_addr, ipbuf, (socklen_t)sizeof(ipbuf));
#endif
                        if (banned_.count(ipbuf) || is_ip_banned(ipbuf, now_ms())) {
                            P2P_TRACE(std::string("reject inbound banned ip=") + ipbuf);
                            CLOSESOCK(c);
                        } else {
                            handle_new_peer(c, ipbuf);
                        }
                    }
                }
            }
        }

        // Accept new peers (with soft inbound rate cap) - IPv6
        if (g_srv6_ != MIQ_INVALID_SOCK && srv_idx_v6 < fds.size() && (fds[srv_idx_v6].revents & POLL_RD)) {
            sockaddr_in6 ca6{};
#ifdef _WIN32
            int clen6 = (int)sizeof(ca6);
#else
            socklen_t clen6 = sizeof(ca6);
#endif
            Sock c = accept(g_srv6_, (sockaddr*)&ca6, &clen6);
            if (c != MIQ_INVALID_SOCK) {
                if (is_self_endpoint(c, g_listen_port)) {
                    P2P_TRACE("reject hairpin inbound v6");
                    CLOSESOCK(c);
                } else {
                    int64_t tnow = now_ms();
                    if (tnow - inbound_win_start_ms_ > 60000) {
                        inbound_win_start_ms_ = tnow;
                        inbound_accepts_in_window_ = 0;
                    }
                    if (inbound_accepts_in_window_ >= MIQ_P2P_NEW_INBOUND_CAP_PER_MIN) {
                        P2P_TRACE("reject inbound v6: per-minute cap");
                        CLOSESOCK(c);
                    } else {
                        inbound_accepts_in_window_++;

                        char ipbuf[128] = {0};
#ifdef _WIN32
                        InetNtopA(AF_INET6, &ca6.sin6_addr, ipbuf, (int)sizeof(ipbuf));
#else
                        inet_ntop(AF_INET6, &ca6.sin6_addr, ipbuf, (socklen_t)sizeof(ipbuf));
#endif
                        std::string ip(ipbuf[0] ? ipbuf : "unknown");
                        if (banned_.count(ip) || is_ip_banned(ip, now_ms())) {
                            P2P_TRACE(std::string("reject inbound banned ip6=") + ip);
                            CLOSESOCK(c);
                        } else {
                            handle_new_peer(c, ip);
                        }
                    }
                }
            }
        }

        // Read/process peers
        std::vector<Sock> dead;
        for (size_t i = 0; i < peer_fd_order.size(); ++i) {
            if (base + i >= fds.size()) continue;
            Sock s = peer_fd_order[i];

            auto it = peers_.find(s);
            if (it == peers_.end()) continue;

            auto &ps = it->second;

            bool ready = (fds[base + i].revents & POLL_RD) != 0;

            if (ready) {
                uint8_t buf[65536];
                int n = miq_recv(s, buf, sizeof(buf));
                if (n <= 0) { P2P_TRACE("close read<=0"); dead.push_back(s); continue; }

                if (gate_on_bytes(s, (size_t)n)) {
                    P2P_TRACE("close RX over MAX_MSG_BYTES");
                    dead.push_back(s);
                    continue;
                }

                ps.last_ms = now_ms();

                ps.rx.insert(ps.rx.end(), buf, buf + n);
                if (!ps.rx.empty()) rx_track_start(s);
                if (ps.rx.size() > MIQ_P2P_MAX_BUFSZ) {
                    log_warn("P2P: oversize buffer from " + ps.ip + " -> banning & dropping");
                    bump_ban(ps, ps.ip, "oversize-buffer", now_ms());
                    dead.push_back(s);
                    continue;
                }

                size_t off = 0;
                miq::NetMsg m;
                while (true) {
                    size_t off_before = off;
                    bool ok = decode_msg(ps.rx, off, m);
                    if (!ok) break;

                    // FIXED: only drop if decoder made no forward progress (0 bytes).
                    size_t advanced = (off > off_before) ? (off - off_before) : 0;
                    if (advanced == 0) {
                        miq::log_warn("P2P: decoded frame made no progress; dropping peer defensively");
                        dead.push_back(s);
                        break;
                    }

                    std::string cmd(m.cmd, m.cmd + 12);
                    size_t z = cmd.find('\0');
                    if (z != std::string::npos) {
                        cmd.resize(z);
                    } else {
                        bool bad = false;
                        for (unsigned char ch : cmd) { if (ch < 32 || ch > 126) { bad = true; break; } }
                        if (bad) { ++ps.mis; continue; }
                    }

                    P2P_TRACE("RX " + ps.ip + " cmd=" + cmd + " len=" + std::to_string(m.payload.size()));

                    bool send_verack = false; int close_code = 0;
                    if (gate_on_command(s, cmd, send_verack, close_code)) {
                        if (close_code) { /* traced in gate_on_command */ }
                        dead.push_back(s);
                        break;
                    }
                    if (send_verack) {
                        auto verack = encode_msg("verack", {});
                        (void)miq_send(s, verack);
                    }

                    auto inv_tick = [&](unsigned add)->bool{
                        int64_t tnow = now_ms();
                        if (tnow - ps.inv_win_start_ms > (int64_t)MIQ_P2P_INV_WINDOW_MS) {
                            ps.inv_win_start_ms = tnow;
                            ps.inv_in_window = 0;
                        }
                        // clamp to avoid accidental wrap
                        uint64_t next = (uint64_t)ps.inv_in_window + (uint64_t)add;
                        if (next > (uint64_t)MIQ_P2P_INV_WINDOW_CAP + 1) next = (uint64_t)MIQ_P2P_INV_WINDOW_CAP + 1;
                        ps.inv_in_window = (uint32_t)next;
                        if (ps.inv_in_window > MIQ_P2P_INV_WINDOW_CAP) {
                            if ((ps.banscore += 5) >= MIQ_P2P_MAX_BANSCORE) bump_ban(ps, ps.ip, "inv-window-overflow", tnow);
                            return false;
                        }
                        return true;
                    };
                    auto remember_inv = [&](const std::string& key)->bool{
                        if (!ps.recent_inv_keys.insert(key).second) return false;
                        if (ps.recent_inv_keys.size() > 4096) {
                            ps.recent_inv_keys.clear();
                        }
                        return true;
                    };

                    if (cmd == "version") {
                        int32_t peer_ver = 0; uint64_t peer_services = 0;
                        if (m.payload.size() >= 4) {
                            peer_ver = (int32_t)((uint32_t)m.payload[0] | ((uint32_t)m.payload[1]<<8) | ((uint32_t)m.payload[2]<<16) | ((uint32_t)m.payload[3]<<24));
                        }
                        if (m.payload.size() >= 12) {
                            for(int i=0;i<8;i++) peer_services |= ((uint64_t)m.payload[4+i]) << (8*i);
                        }
                        ps.version = peer_ver;
                        ps.features = 0;
#if MIQ_ENABLE_HEADERS_FIRST
                        ps.features |= (1ull<<0);
#endif
                        ps.features |= (1ull<<1);

                        if (ps.version > 0 && ps.version < min_peer_version_) {
                            log_warn(std::string("P2P: dropping old peer ") + ps.ip);
                            dead.push_back(s);
                            break;
                        }
                        if ((ps.features & required_features_mask_) != required_features_mask_) {
                            log_warn(std::string("P2P: dropping peer missing required features ") + ps.ip);
                            dead.push_back(s);
                            break;
                        }

                    } else if (cmd == "verack") {
                        ps.verack_ok = true;
                        g_preverack_counts.erase(s);
#if MIQ_ENABLE_ADDRMAN
                        uint32_t be_ip;
                        if (parse_ipv4(ps.ip, be_ip)) {
                            miq::NetAddr na; na.host = ps.ip; na.port = g_listen_port; na.is_ipv6=false; na.tried=true;
                            g_addrman.mark_good(na);
                            g_addrman.add_anchor(na);
                        }
#endif
                        ps.whitelisted = is_loopback(ps.ip) || is_whitelisted_ip(ps.ip);

#if MIQ_ENABLE_HEADERS_FIRST
                        {
                            std::vector<std::vector<uint8_t>> locator;
                            chain_.build_locator(locator);
                            std::vector<uint8_t> stop(32, 0);
                            auto pl = build_getheaders_payload(locator, stop);
                            auto msg = encode_msg("getheaders", pl);
                            if (can_accept_hdr_batch(ps, now_ms()) && check_rate(ps, "get", 1.0, now_ms())) {
                                ps.sent_getheaders = true;
                                (void)miq_send(s, msg);
                                ps.inflight_hdr_batches++;
                            }
                        }

                        if (!g_logged_headers_started) {
                            g_logged_headers_started = true;
                            log_info("[IBD] headers phase started");
                        }
#else
                        ps.syncing = true;
                        ps.next_index = chain_.height() + 1;
                        request_block_index(ps, ps.next_index);
#endif
                        maybe_send_getaddr(ps);

                        {
                            uint64_t mrf = local_min_relay_kb();
                            std::vector<uint8_t> pl(8);
                            for(int i=0;i<8;i++) pl[i] = (uint8_t)((mrf >> (8*i)) & 0xFF);
                            auto ff = encode_msg("feefilter", pl);
                            (void)miq_send(s, ff);
                        }

                    } else if (cmd == "ping") {
                        auto pong = encode_msg("pong", m.payload);
                        (void)miq_send(s, pong);

                    } else if (cmd == "pong") {
                        ps.awaiting_pong = false;

                    } else if (cmd == "invb") {
                        if (!check_rate(ps, "inv", 0.5, now_ms())) {
                            bump_ban(ps, ps.ip, "inv-flood", now_ms());
                            continue;
                        }
                        if (m.payload.size() == 32) {
                            if (!inv_tick(1)) { continue; }
                            auto k = hexkey(m.payload);
                            if (!remember_inv(k)) { continue; }
                            if (!chain_.have_block(m.payload)) {
                                request_block_hash(ps, m.payload);
                            }
                        }

                    } else if (cmd == "getb") {
                        if (m.payload.size() == 32) {
                            Block b;
                            if (chain_.get_block_by_hash(m.payload, b)) {
                                auto raw = ser_block(b);
                                if (raw.size() <= MIQ_FALLBACK_MAX_BLOCK_SZ) send_block(s, raw);
                            }
                        }

                    } else if (cmd == "getbi") {
                        if (m.payload.size() == 8) {
                            uint64_t idx64 = 0;
                            for (int i=0;i<8;i++) idx64 |= ((uint64_t)m.payload[i]) << (8*i);
                            Block b;
                            if (chain_.get_block_by_index((size_t)idx64, b)) {
                                auto raw = ser_block(b);
                                if (raw.size() <= MIQ_FALLBACK_MAX_BLOCK_SZ) send_block(s, raw);
                            }
                        }

                    } else if (cmd == "block") {
                        if (!rate_consume_block(ps, m.payload.size())) {
                            if ((ps.banscore += 5) >= MIQ_P2P_MAX_BANSCORE) bump_ban(ps, ps.ip, "block-rate", now_ms());
                            continue;
                        }
                        if (m.payload.size() > 0 && m.payload.size() <= MIQ_FALLBACK_MAX_BLOCK_SZ) {
                            Block hb;
                            if (!deser_block(m.payload, hb)) { if (++ps.mis > 10) { dead.push_back(s); } continue; }
                            const std::string bh = hexkey(hb.block_hash());
                            if (unsolicited_drop(ps, "block", bh)) {
                                bump_ban(ps, ps.ip, "unsolicited-block", now_ms());
                                continue;
                            }
                            ps.inflight_blocks.erase(bh);
                            handle_incoming_block(s, m.payload);
                        }

                    } else if (cmd == "invtx") {
                        if (!check_rate(ps, "inv", 0.25, now_ms())) {
                            bump_ban(ps, ps.ip, "inv-flood", now_ms());
                            continue;
                        }
                        if (m.payload.size() == 32) {
                            if (!inv_tick(1)) { continue; }
                            auto key = hexkey(m.payload);
                            if (!remember_inv(key)) { continue; }
                            if (!seen_txids_.count(key)) {
                                seen_txids_.insert(key);
                                request_tx(ps, m.payload);
                            }
                        }

                    } else if (cmd == "gettx") {
                        if (m.payload.size() == 32) {
                            auto key = hexkey(m.payload);
                            auto itx = tx_store_.find(key);
                            if (itx != tx_store_.end()) {
                                if (rate_consume_tx(ps, itx->second.size())) {
                                    send_tx(s, itx->second);
                                }
                            }
                        }

                    } else if (cmd == "tx") {
                        if (!rate_consume_tx(ps, m.payload.size())) {
                            if ((ps.banscore += 3) >= MIQ_P2P_MAX_BANSCORE) bump_ban(ps, ps.ip, "tx-rate", now_ms());
                            continue;
                        }
                        Transaction tx;
                        if (!deser_tx(m.payload, tx)) continue;
                        auto key = hexkey(tx.txid());

                        ps.inflight_tx.erase(key);
                        if (unsolicited_drop(ps, "tx", key)) {
                            bump_ban(ps, ps.ip, "unsolicited-tx", now_ms());
                            continue;
                        }

                        if (seen_txids_.insert(key).second) {
                            std::string err;
                            bool accepted = true;
                            if (mempool_) {
                                accepted = mempool_->accept(tx, chain_.utxo(), chain_.height(), err);
                            }
                            bool in_mempool = mempool_ && mempool_->exists(tx.txid());

                            if (accepted && !in_mempool) {
                                for (const auto& in : tx.vin) {
                                    UTXOEntry e;
                                    if (!chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                                        send_gettx(s, in.prev.txid);
                                    }
                                }
                                continue;
                            }

                            if (tx_store_.find(key) == tx_store_.end()) {
                                tx_store_[key] = m.payload;
                                tx_order_.push_back(key);
                                if (tx_store_.size() > MIQ_TX_STORE_MAX) {
                                    auto victim = tx_order_.front();
                                    tx_order_.pop_front();
                                    tx_store_.erase(victim);
                                }
                            }
                            if (accepted) {
                                uint64_t in_sum = 0, out_sum = 0;
                                for (const auto& o : tx.vout) out_sum += o.value;
                                bool inputs_ok = true;
                                for (const auto& in : tx.vin) {
                                    UTXOEntry e;
                                    if (!chain_.utxo().get(in.prev.txid, in.prev.vout, e)) { inputs_ok = false; break; }
                                    in_sum += e.value;
                                }
                                if (inputs_ok && in_sum >= out_sum) {
                                    uint64_t fee = in_sum - out_sum;
                                    size_t sz = m.payload.size(); if (sz == 0) sz = 1;
                                    uint64_t feerate_kb = (fee * 1000ULL + (sz - 1)) / sz;

                                    const std::vector<uint8_t> txidv = tx.txid();
                                    for (auto& kvp : peers_) {
                                        Sock psock = kvp.first;
                                        uint64_t peer_min = peer_feefilter_kb(psock);
                                        if (peer_min && feerate_kb < peer_min) continue;
                                        trickle_enqueue(psock, txidv);
                                    }
                                } else {
                                    // no complete inputs: still advertise to help fetch deps
                                    const std::vector<uint8_t> txidv = tx.txid();
                                    for (auto& kvp : peers_) trickle_enqueue(kvp.first, txidv);
                                }
                            } else if (!err.empty()) {
                                if (++ps.mis > 25) bump_ban(ps, ps.ip, "tx-invalid", now_ms());
                            }
                        }

                    } else if (cmd == "getaddr") {
                        send_addr_snapshot(ps);

                    } else if (cmd == "addr") {
                        handle_addr_msg(ps, m.payload);

                    } else if (cmd == "feefilter") {
                        if (m.payload.size() == 8) {
                            uint64_t kb = 0;
                            for(int i=0;i<8;i++) kb |= (uint64_t)m.payload[i] << (8*i);
                            set_peer_feefilter(s, kb);
                        } else {
                            if (++ps.mis > 10) { dead.push_back(s); }
                        }

#if MIQ_ENABLE_HEADERS_FIRST
                    } else if (cmd == "getheaders") {
                        // Parse incoming locator/stop
                        std::vector<std::vector<uint8_t>> locator;
                        std::vector<uint8_t> stop;
                        if (!parse_getheaders_payload(m.payload, locator, stop)) {
                            if (++ps.mis > 10) { dead.push_back(s); }
                            continue;
                        }

                        // Try native orientation first (BE as our chain stores it).
                        std::vector<BlockHeader> hs;
                        chain_.get_headers_from_locator(locator, 2000, hs);

                        // **Bulletproof fix**: if no progress, retry with each 32B hash reversed (LE<->BE)
                        if (hs.empty() && !locator.empty()) {
                            std::vector<std::vector<uint8_t>> loc_rev = locator;
                            for (auto& h : loc_rev) std::reverse(h.begin(), h.end());
                            std::vector<BlockHeader> hs2;
                            chain_.get_headers_from_locator(loc_rev, 2000, hs2);
                            if (!hs2.empty()) hs.swap(hs2);
                        }

                        auto out = build_headers_payload(hs);
                        auto msg = encode_msg("headers", out);
                        (void)miq_send(s, msg);

                    } else if (cmd == "headers") {
                        if (unsolicited_drop(ps, "headers", "")) {
                            P2P_TRACE("drop unsolicited headers (no ban)");
                            continue;
                        }
                        std::vector<BlockHeader> hs;
                        if (!parse_headers_payload(m.payload, hs)) {
                            if (++ps.mis > 10) { dead.push_back(s); }
                            continue;
                        }
                        size_t accepted = 0;
                        std::string herr;
                        for (const auto& h : hs) {
                            if (chain_.accept_header(h, herr)) accepted++;
                        }

                        if (accepted > 0) {
                            g_last_progress_ms = now_ms();
                        }

                        {
                            bool zero_progress = hs.empty() || (accepted == 0);
                            if (zero_progress) {
                                int &z = g_zero_hdr_batches[s];
                                z++;
                                if (z >= 3) {
                                    log_warn("P2P: headers made no progress after 3 batches; falling back to by-index sync");
                                    ps.banscore = std::min(ps.banscore + 1, MIQ_P2P_MAX_BANSCORE);
                                    ps.syncing = true;
                                    ps.next_index = chain_.height() + 1;
                                    request_block_index(ps, ps.next_index);
                                    z = 0;
                                }
                            } else {
                                g_zero_hdr_batches[s] = 0;
                            }
                        }

                        std::vector<std::vector<uint8_t>> want;
                        chain_.next_block_fetch_targets(want, /*max*/32);
                        for (const auto& w : want) request_block_hash(ps, w);

                        if (!g_logged_headers_done && !want.empty()) {
                            g_logged_headers_done = true;
                            log_info("[IBD] headers phase complete; switching to blocks");
                        }

                        if (ps.inflight_hdr_batches > 0) ps.inflight_hdr_batches--;
                        ps.last_hdr_batch_done_ms = now_ms();
                        if (ps.inflight_hdr_batches == 0) ps.sent_getheaders = false;

                        if (ps.inflight_hdr_batches == 0) {
                            std::vector<std::vector<uint8_t>> locator2;
                            chain_.build_locator(locator2);
                            std::vector<uint8_t> stop2(32, 0);
                            auto pl2 = build_getheaders_payload(locator2, stop2);
                            auto m2  = encode_msg("getheaders", pl2);
                            if (can_accept_hdr_batch(ps, now_ms()) && check_rate(ps, "get", 1.0, now_ms())) {
                                 ps.sent_getheaders = true;
                                 (void)miq_send(s, m2);
                                 ps.inflight_hdr_batches++;
                            }
                        }
#endif

                    } else {
                        if (++ps.mis > 10) { dead.push_back(s); }
                    }
                }

                if (off > 0 && off <= ps.rx.size()) {
                    ps.rx.erase(ps.rx.begin(), ps.rx.begin() + (ptrdiff_t)off);
                    if (ps.rx.empty()) rx_clear_start(s);
                }

                if (!ps.rx.empty()) {
                    auto it0 = g_rx_started_ms.find(s);
                    if (it0 != g_rx_started_ms.end()) {
                        if (now_ms() - it0->second > msg_deadline_ms_) {
                            bump_ban(ps, ps.ip, "slowloris/parse-timeout", now_ms());
                            dead.push_back(s);
                            continue;
                        }
                    }
                }
            }

            int64_t tnow = now_ms();

            // Loopback leniency + defer pings until after verack
            bool is_lb = false;
            auto itg = g_gate.find(s);
            if (itg != g_gate.end()) is_lb = itg->second.is_loopback;

            if (!ps.verack_ok && (tnow - ps.last_ms) > MIQ_P2P_VERACK_TIMEOUT_MS) {
                if (is_lb) {
                    // extend the timer for localhost tools/wallets
                    ps.last_ms = tnow;
                } else {
                    P2P_TRACE("close verack-timeout");
                    dead.push_back(s);
                    continue;
                }
            }

            if (ps.verack_ok) {
                if (!ps.awaiting_pong && (tnow - ps.last_ping_ms) > MIQ_P2P_PING_EVERY_MS) {
                    auto ping = encode_msg("ping", {});
                    (void)miq_send(s, ping);
                    ps.last_ping_ms = tnow;
                    ps.awaiting_pong = true;
                } else if (ps.awaiting_pong && (tnow - ps.last_ping_ms) > MIQ_P2P_PONG_TIMEOUT_MS) {
                    if (!is_lb) {
                        P2P_TRACE("close pong-timeout");
                        bump_ban(ps, ps.ip, "pong-timeout", now_ms());
                        dead.push_back(s);
                    } else {
                        // loopback: clear awaiting state but keep the socket
                        ps.awaiting_pong = false;
                        ps.last_ping_ms = tnow;
                    }
                }
            }
        }

        // ---- Guarded removals (single, consistent path) --------------------
        for (Sock s : dead) {
            gate_on_close(s);
            CLOSESOCK(s);
            peers_.erase(s);
            g_zero_hdr_batches.erase(s);
            g_preverack_counts.erase(s);
            g_trickle_last_ms.erase(s);
            g_cmd_rl.erase(s); // mirror cleanup in case gate_on_close wasn't hit
        }

        // trickle any queued invtx payloads (enqueued by broadcast_inv_tx)
        {
            std::vector<std::vector<uint8_t>> todos;
            {
                std::lock_guard<std::mutex> lk(announce_tx_mu_);
                if (!announce_tx_q_.empty()) { todos.swap(announce_tx_q_); }
            }
            if (!todos.empty()) {
                for (const auto& txid : todos) {
                    for (auto& kv : peers_) trickle_enqueue(kv.first, txid);
                }
            }
        }

        trickle_flush();

        {
            std::vector<std::vector<uint8_t>> todo;
            {
                std::lock_guard<std::mutex> lk(announce_mu_);
                if (!announce_blocks_q_.empty()) {
                    todo.swap(announce_blocks_q_);
                }
            }
            for (const auto& h : todo) {
                auto m = encode_msg("invb", h);
                for (auto& kv : peers_) {
                    (void)miq_send(kv.first, m);
                }
            }
        }

        if (now_ms() - last_addr_save_ms > MIQ_ADDR_SAVE_INTERVAL_MS) {
            last_addr_save_ms = now_ms();
            save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
            std::string err;
            if (!g_addrman.save(g_addrman_path, err)) {
                log_warn("P2P: addrman autosave failed: " + err);
            }
#endif
        }
    }

    save_bans();
    save_addrs_to_disk(datadir_, addrv4_);
#if MIQ_ENABLE_ADDRMAN
    {
        std::string err;
        if (!g_addrman.save(g_addrman_path, err)) {
            log_warn("P2P: addrman final save failed: " + err);
        }
    }
#endif
}

std::vector<PeerSnapshot> P2P::snapshot_peers() const {
    std::vector<PeerSnapshot> out;
    out.reserve(peers_.size());
    for (const auto& kv : peers_) {
        const auto& ps = kv.second;
        PeerSnapshot s;
        s.ip            = ps.ip;
        s.verack_ok     = ps.verack_ok;
        s.awaiting_pong = ps.awaiting_pong;
        s.mis           = ps.mis;
        s.next_index    = ps.next_index;
        s.syncing       = ps.syncing;
        s.last_seen_ms  = static_cast<double>(now_ms() - ps.last_ms);
        s.blk_tokens    = ps.blk_tokens;
        s.tx_tokens     = ps.tx_tokens;
        s.rx_buf        = ps.rx.size();
        s.inflight      = ps.inflight_tx.size();
        out.push_back(std::move(s));
    }
    return out;
}
}
