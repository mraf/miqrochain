#include "http.h"
#include "log.h"

#include <thread>
#include <mutex>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <stdexcept>
#include <cstdlib>   // getenv, rand
#include <cstdio>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <atomic>
#include <memory>
#include <array>     // for std::array

// --- platform sockets + sleep -----------------------------------------------
#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  using sock_t = SOCKET;
  // Windows has closesocket()
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
  using sock_t = int;
  #define closesocket ::close
#endif

static inline void miq_sleep_ms(unsigned ms){
#ifdef _WIN32
  Sleep(ms);
#else
  usleep(ms * 1000);
#endif
}

namespace miq {

// ====================== helpers =============================================

static inline bool env_truthy(const char* v){
    if(!v || !*v) return false;
    return (*v=='1'||*v=='t'||*v=='T'||*v=='y'||*v=='Y');
}

static inline int env_int(const char* name, int defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; long x = std::strtol(v, &end, 10);
    if(end==v) return defv;
    if(x < 0) x = 0;
    if(x > 1000000) x = 1000000;
    return (int)x;
}

static inline size_t env_szt(const char* name, size_t defv){
    const char* v = std::getenv(name);
    if(!v || !*v) return defv;
    char* end=nullptr; long long x = std::strtoll(v, &end, 10);
    if(end==v || x < 0) return defv;
    return (size_t)x;
}

static inline bool is_loopback_sockaddr(const sockaddr* sa){
    if(!sa) return true;
    if(sa->sa_family == AF_INET){
        const sockaddr_in* s4 = reinterpret_cast<const sockaddr_in*>(sa);
        unsigned long a = ntohl(s4->sin_addr.s_addr);
        return ((a >> 24) == 127); // 127.0.0.0/8
    }
#ifdef AF_INET6
    if(sa->sa_family == AF_INET6){
        const sockaddr_in6* s6 = reinterpret_cast<const sockaddr_in6*>(sa);
        static const uint8_t loop6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return std::memcmp(s6->sin6_addr.s6_addr, loop6, 16) == 0;
    }
#endif
    return false;
}

static inline std::string sock_ntop(const sockaddr_storage& sa){
    char buf[128] = {0};
    if(sa.ss_family == AF_INET){
        const sockaddr_in* s4 = reinterpret_cast<const sockaddr_in*>(&sa);
        inet_ntop(AF_INET, &s4->sin_addr, buf, sizeof(buf));
        return std::string(buf);
    }
#ifdef AF_INET6
    if(sa.ss_family == AF_INET6){
        const sockaddr_in6* s6 = reinterpret_cast<const sockaddr_in6*>(&sa);
        inet_ntop(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
        return std::string(buf);
    }
#endif
    return "unknown";
}

// lowercase ASCII
static inline std::string lc(std::string s){
    for(char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

// trim spaces/tabs
static inline void trim(std::string& s){
    size_t i=0, j=s.size();
    while(i<j && (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n')) ++i;
    while(j>i && (s[j-1]==' '||s[j-1]=='\t'||s[j-1]=='\r'||s[j-1]=='\n')) --j;
    s.assign(s.data()+i, j-i);
}

static inline std::string get_header(const std::vector<std::pair<std::string,std::string>>& headers,
                                     const std::string& key_lc){
    for(const auto& kv : headers){
        if(lc(kv.first) == key_lc) return kv.second;
    }
    return {};
}

// Extract "method":"..." (tiny extractor; ok for alnum/underscore names)
static std::string extract_json_method(const std::string& body){
    size_t mpos = body.find("\"method\"");
    if(mpos == std::string::npos) return {};
    size_t cpos = body.find(':', mpos);
    if(cpos == std::string::npos) return {};
    size_t i = cpos+1; while(i<body.size() && (body[i]==' '||body[i]=='\t'||body[i]=='\r'||body[i]=='\n')) ++i;
    if(i>=body.size() || body[i] != '\"') return {};
    ++i;
    size_t j = i;
    while(j<body.size() && body[j] != '\"') ++j;
    if(j>=body.size()) return {};
    return body.substr(i, j-i);
}

// Default safe (read-only) allowlist
static std::unordered_set<std::string> default_safe_methods(){
    return {
        "getblockcount","gettipinfo","getblockhash","getblock","getrawblock",
        "getrawmempool","getpeerinfo","getminerstats","getconnectioncount",
        "validateaddress","decoderawtx","estimatemediantime","getdifficulty",
        "getchaintips","ping","uptime","help","version","getblockchaininfo"
    };
}

// Extend safe allowlist via env
static void load_env_allowlist(std::unordered_set<std::string>& allow){
    const char* env = std::getenv("MIQ_RPC_SAFE_METHODS");
    if(!env || !*env) return;
    std::string s(env);
    size_t p=0;
    while(p < s.size()){
        size_t q = s.find(',', p);
        if(q == std::string::npos) q = s.size();
        std::string item = s.substr(p, q-p);
        trim(item);
        if(!item.empty()) allow.insert(item);
        p = q + 1;
    }
}

// ================= Rate limit state =========================================

struct TokenBucket {
    double tokens{0.0};
    double rate_per_sec{1.0};
    double burst{10.0};
    std::chrono::steady_clock::time_point last = std::chrono::steady_clock::now();
};

static std::unordered_map<std::string, TokenBucket> g_buckets;
static std::mutex g_buckets_mtx; // FIX: protect map + cleanup against data races
static std::chrono::steady_clock::time_point g_last_cleanup = std::chrono::steady_clock::now();
static std::atomic<int> g_live_conns{0};

// Refill & check token bucket
static bool rl_allow(const std::string& ip, int rps, int burst){
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lk(g_buckets_mtx);

    // First time: prefill and allow the first request (consume 1 token).
    auto it = g_buckets.find(ip);
    if (it == g_buckets.end()) {
        TokenBucket nb;
        nb.rate_per_sec = (double)rps;
        nb.burst        = (double)burst;
        nb.tokens       = std::max(0.0, nb.burst - 1.0);
        nb.last         = now;
        g_buckets.emplace(ip, nb);

        if(now - g_last_cleanup > std::chrono::minutes(5)){
            for(auto it2 = g_buckets.begin(); it2 != g_buckets.end();){
                if(now - it2->second.last > std::chrono::minutes(10)) it2 = g_buckets.erase(it2);
                else ++it2;
            }
            g_last_cleanup = now;
        }
        return true;
    }

    // Existing bucket
    TokenBucket& b = it->second;
    double dt = std::chrono::duration<double>(now - b.last).count();
    b.last = now;
    if (b.rate_per_sec <= 0.0) b.rate_per_sec = (double)rps;
    if (b.burst       <= 0.0) b.burst        = (double)burst;
    b.tokens = std::min(b.burst, b.tokens + dt * b.rate_per_sec);
    if (b.tokens >= 1.0){
        b.tokens -= 1.0;
        if(now - g_last_cleanup > std::chrono::minutes(5)){
            for(auto it2 = g_buckets.begin(); it2 != g_buckets.end();){
                if(now - it2->second.last > std::chrono::minutes(10)) it2 = g_buckets.erase(it2);
                else ++it2;
            }
            g_last_cleanup = now;
        }
        return true;
    }
    return false;
}

// ================= Simple metrics ===========================================

struct Metrics {
    std::atomic<uint64_t> http_requests_total{0};
    std::atomic<uint64_t> http_rate_limited_total{0};
    std::atomic<uint64_t> http_unauthorized_total{0};
    std::atomic<uint64_t> http_forbidden_total{0};
    std::atomic<uint64_t> http_method_not_allowed_total{0};
    std::atomic<uint64_t> http_bytes_in_total{0};
    std::atomic<uint64_t> http_bytes_out_total{0};

    // Duration histogram buckets (ms)
    const std::vector<int> buckets{5,10,25,50,100,250,500,1000,2500,5000,10000};
    std::vector<std::atomic<uint64_t>> bucket_counts;
    std::atomic<uint64_t> duration_sum_ms{0};
    std::atomic<uint64_t> duration_count{0};

    // Per-method counters
    std::mutex pm_mtx;
    std::unordered_map<std::string,uint64_t> rpc_method_calls;
    std::unordered_map<std::string,uint64_t> rpc_method_errors;

    Metrics() : bucket_counts(buckets.size()) {}

    void observe_duration_ms(uint64_t ms){
        for(size_t i=0;i<buckets.size();++i){
            if(ms <= (uint64_t)buckets[i]){ ++bucket_counts[i]; break; }
            if(i+1==buckets.size()) ++bucket_counts[i];
        }
        duration_sum_ms += ms;
        duration_count  += 1;
    }

    void add_method_call(const std::string& m, bool is_error){
        std::lock_guard<std::mutex> lk(pm_mtx);
        rpc_method_calls[m]  += 1;
        if(is_error) rpc_method_errors[m] += 1;
    }

    std::string render_prom() {
        std::ostringstream os;
        os << "# HELP miq_http_requests_total Total HTTP requests\n"
           << "# TYPE miq_http_requests_total counter\n"
           << "miq_http_requests_total " << http_requests_total.load() << "\n";

        os << "# HELP miq_http_rate_limited_total Requests rejected due to rate limit\n"
           << "# TYPE miq_http_rate_limited_total counter\n"
           << "miq_http_rate_limited_total " << http_rate_limited_total.load() << "\n";

        os << "# HELP miq_http_unauthorized_total 401 responses\n"
           << "# TYPE miq_http_unauthorized_total counter\n"
           << "miq_http_unauthorized_total " << http_unauthorized_total.load() << "\n";

        os << "# HELP miq_http_forbidden_total 403 responses\n"
           << "# TYPE miq_http_forbidden_total counter\n"
           << "miq_http_forbidden_total " << http_forbidden_total.load() << "\n";

        os << "# HELP miq_http_method_not_allowed_total 405 responses\n"
           << "# TYPE miq_http_method_not_allowed_total counter\n"
           << "miq_http_method_not_allowed_total " << http_method_not_allowed_total.load() << "\n";

        os << "# HELP miq_http_bytes_in_total Total request body bytes\n"
           << "# TYPE miq_http_bytes_in_total counter\n"
           << "miq_http_bytes_in_total " << http_bytes_in_total.load() << "\n";

        os << "# HELP miq_http_bytes_out_total Total response body bytes\n"
           << "# TYPE miq_http_bytes_out_total counter\n"
           << "miq_http_bytes_out_total " << http_bytes_out_total.load() << "\n";

        os << "# HELP miq_http_live_conns Current in-flight connections\n"
           << "# TYPE miq_http_live_conns gauge\n"
           << "miq_http_live_conns " << g_live_conns.load() << "\n";

        os << "# HELP miq_http_request_duration_ms Request duration\n"
           << "# TYPE miq_http_request_duration_ms histogram\n";
        uint64_t cum = 0;
        for(size_t i=0;i<buckets.size();++i){
            cum += bucket_counts[i].load();
            os << "miq_http_request_duration_ms_bucket{le=\"" << buckets[i] << "\"} " << cum << "\n";
        }
        os << "miq_http_request_duration_ms_bucket{le=\"+Inf\"} " << duration_count.load() << "\n";
        os << "miq_http_request_duration_ms_sum "  << duration_sum_ms.load() << "\n";
        os << "miq_http_request_duration_ms_count " << duration_count.load() << "\n";

        // Per-method (best-effort)
        {
            std::lock_guard<std::mutex> lk(pm_mtx);
            os << "# HELP miq_rpc_method_calls_total RPC method calls\n"
               << "# TYPE miq_rpc_method_calls_total counter\n";
            for(const auto& kv : rpc_method_calls){
                os << "miq_rpc_method_calls_total{method=\"" << kv.first << "\"} " << kv.second << "\n";
            }
            os << "# HELP miq_rpc_method_errors_total RPC method errors (top-level {\"error\":...})\n"
               << "# TYPE miq_rpc_method_errors_total counter\n";
            for(const auto& kv : rpc_method_errors){
                os << "miq_rpc_method_errors_total{method=\"" << kv.first << "\"} " << kv.second << "\n";
            }
        }

        return os.str();
    }
};

static Metrics g_metrics;

// ================= HTTP parsing & response ==================================

static bool parse_http_request(sock_t fd,
                               std::string& method, std::string& path, std::string& body,
                               std::vector<std::pair<std::string,std::string>>& headers,
                               size_t max_header_bytes,
                               size_t max_body_bytes,
                               int recv_timeout_ms)
{
    std::string buf;
    char tmp[4096];
    size_t header_end_pos = std::string::npos;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(recv_timeout_ms);

    // Read until we have headers or timeout/limits reached
    for(;;){
        if(std::chrono::steady_clock::now() > deadline) return false;
#ifdef _WIN32
        // Set small recv timeout (slowloris guard)
        DWORD tv = 200; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
        timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
        int n = recv(fd, tmp, (int)sizeof(tmp), 0);
        if(n <= 0) return false;
        buf.append(tmp, tmp+n);
        if(buf.size() > max_header_bytes) return false;
        size_t pos = buf.find("\r\n\r\n");
        if(pos != std::string::npos){ header_end_pos = pos + 4; break; }
    }

    // Parse request line
    size_t l0 = buf.find("\r\n");
    if(l0 == std::string::npos) return false;
    std::string reqline = buf.substr(0, l0);
    {
        size_t sp1 = reqline.find(' ');
        size_t sp2 = (sp1==std::string::npos? std::string::npos : reqline.find(' ', sp1+1));
        if(sp1==std::string::npos || sp2==std::string::npos) return false;
        method = reqline.substr(0, sp1);
        path   = reqline.substr(sp1+1, sp2-sp1-1);
    }

    // Parse headers
    size_t pos = l0 + 2;
    while(pos < header_end_pos-2){
        size_t nl = buf.find("\r\n", pos);
        if(nl == std::string::npos || nl > header_end_pos) break;
        std::string line = buf.substr(pos, nl-pos);
        pos = nl + 2;
        size_t colon = line.find(':');
        if(colon != std::string::npos){
            std::string k = line.substr(0, colon);
            std::string v = line.substr(colon+1);
            trim(k); trim(v);
            headers.emplace_back(k, v);
        }
    }

    // Handle Expect: 100-continue (PowerShell/.NET commonly send this)
    {
        std::string expect = lc(get_header(headers, "expect"));
        if (!expect.empty() && expect.find("100-continue") != std::string::npos) {
            static const char k100[] = "HTTP/1.1 100 Continue\r\n\r\n";
#ifdef _WIN32
            send(fd, k100, (int)sizeof(k100)-1, 0);
#else
            ::send(fd, k100, sizeof(k100)-1, 0);
#endif
        }
    }

    // Determine body length
    size_t content_len = 0;
    for(auto& kv : headers){
        if(lc(kv.first) == "content-length"){
            content_len = (size_t)std::strtoull(kv.second.c_str(), nullptr, 10);
        }
    }
    if(content_len > max_body_bytes) return false;

    // Consume body: may already include part after header_end_pos
    if(content_len > 0){
        body.reserve(content_len);
        size_t already = buf.size() - header_end_pos;
        if(already >= content_len){
            body.assign(buf.data() + header_end_pos, content_len);
        } else {
            body.assign(buf.data() + header_end_pos, already);
            size_t remain = content_len - already;
            while(remain > 0){
#ifdef _WIN32
                DWORD tv = 200; setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));
#else
                timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
                int n = recv(fd, tmp, (int)std::min(remain, sizeof(tmp)), 0);
                if(n <= 0){ return false; }
                body.append(tmp, tmp+n);
                remain -= (size_t)n;
                if(body.size() > max_body_bytes) return false;
            }
        }
    } else {
        body.clear();
    }

    return true;
}

static void send_http_simple(sock_t fd, int code, const char* status,
                             const std::string& content_type,
                             const std::string& body,
                             const std::vector<std::pair<std::string,std::string>>& extra_headers = {}){
    std::string resp;
    resp.reserve(128 + body.size());
    resp += "HTTP/1.1 " + std::to_string(code) + " " + status + "\r\n";
    resp += "Content-Type: " + content_type + "\r\n";
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    for(const auto& h : extra_headers){
        resp += h.first; resp += ": "; resp += h.second; resp += "\r\n";
    }
    resp += "Connection: close\r\n\r\n";
    resp += body;
    g_metrics.http_bytes_out_total += body.size();
#ifdef _WIN32
    send(fd, resp.data(), (int)resp.size(), 0);
#else
    // Best-effort send all
    const char* p = resp.data(); size_t left = resp.size();
    while(left){
        ssize_t n = ::send(fd, p, left, 0);
        if(n <= 0) break;
        p += n; left -= (size_t)n;
    }
#endif
}

// ================= HttpServer ===============================================

// NEW headers-aware start()
void HttpServer::start(
    uint16_t port,
    std::function<std::string(
        const std::string&,
        const std::vector<std::pair<std::string,std::string>>&)> on_json)
{
    if(running_.exchange(true)) return;

#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    // Tunables (with sane defaults)
    const int max_conn          = env_int("MIQ_RPC_MAX_CONN", 64);         // global simultaneous connections
    const int ip_rps            = env_int("MIQ_RPC_RPS", 10);              // requests/sec per IP
    const int ip_burst          = env_int("MIQ_RPC_BURST", 30);            // burst size
    const size_t max_hdr_bytes  = env_szt("MIQ_RPC_MAX_HEADER", 16*1024);  // 16 KiB
    const size_t max_body_bytes = env_szt("MIQ_RPC_MAX_BODY",   2*1024*1024); // 2 MiB
    const int recv_timeout_ms   = env_int("MIQ_RPC_RECV_TIMEOUT_MS", 5000);   // header+body total window
    const bool allow_cors       = env_truthy(std::getenv("MIQ_RPC_CORS"));

    // Observability toggles
    const bool enable_metrics   = env_truthy(std::getenv("MIQ_RPC_METRICS"));
    const bool metrics_public   = env_truthy(std::getenv("MIQ_RPC_METRICS_PUBLIC"));
    const bool enable_healthz   = env_truthy(std::getenv("MIQ_RPC_HEALTHZ"));
    const bool access_log       = !std::getenv("MIQ_RPC_ACCESS_LOG") || env_truthy(std::getenv("MIQ_RPC_ACCESS_LOG"));

    // Binding logic
    const char* env_bind_any = std::getenv("MIQ_RPC_BIND_ANY");
    const char* env_bind     = std::getenv("MIQ_RPC_BIND");
    const char* env_token    = std::getenv("MIQ_RPC_TOKEN");
    const char* env_req      = std::getenv("MIQ_RPC_REQUIRE_TOKEN");

    std::string host = "127.0.0.1";
    if(env_truthy(env_bind_any)) host = "0.0.0.0";
    if(env_bind && *env_bind) host = env_bind;

    // Resolve address with getaddrinfo (IPv4/IPv6)
    addrinfo hints{}; std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char port_str[16]; std::snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    addrinfo* res = nullptr;
    if(getaddrinfo(host.c_str(), port_str, &hints, &res) != 0){
        // Fallback to IPv4 loopback
        host = "127.0.0.1";
        if(getaddrinfo(host.c_str(), port_str, &hints, &res) != 0){
            running_.store(false);
#ifdef _WIN32
            WSACleanup();
#endif
            return;
        }
    }

    // Create socket, bind, listen
    sock_t s = (sock_t)(~(sock_t)0);
    sockaddr_storage bound_sa{}; socklen_t bound_len = 0;
    for(addrinfo* ai = res; ai; ai = ai->ai_next){
        s = (sock_t)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef _WIN32
        if(s == INVALID_SOCKET) continue;
#else
        if(s < 0) continue;
#endif

        int yes = 1;
#ifdef _WIN32
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
#else
        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#endif

#ifndef _WIN32
        // Small listen socket timeouts to help with slowloris on accept socket
        timeval tvl; tvl.tv_sec = 0; tvl.tv_usec = 200000;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tvl, sizeof(tvl));
#endif

        if(bind(s, ai->ai_addr, (socklen_t)ai->ai_addrlen) == 0){
            if(listen(s, 64) == 0){
                if(ai->ai_addrlen <= sizeof(bound_sa)){
                    std::memcpy(&bound_sa, ai->ai_addr, ai->ai_addrlen);
                    bound_len = (socklen_t)ai->ai_addrlen;
                }
                break;
            }
        }
        closesocket(s);
#ifdef _WIN32
        s = INVALID_SOCKET;
#else
        s = -1;
#endif
    }
    freeaddrinfo(res);
#ifdef _WIN32
    if(s == INVALID_SOCKET){ running_.store(false); WSACleanup(); return; }
#else
    if(s < 0){ running_.store(false); return; }
#endif

    // Main accept loop
    auto thread_fn = [this, s, bound_sa, bound_len, on_json, env_token, env_req, allow_cors,
                      max_conn, ip_rps, ip_burst, max_hdr_bytes, max_body_bytes, recv_timeout_ms,
                      enable_metrics, metrics_public, enable_healthz, access_log](){
        bool bound_loopback = is_loopback_sockaddr((const sockaddr*)&bound_sa);
        bool require_always = env_truthy(env_req); // keep backward-compat default

        // Build allowlist for unauthenticated access
        std::unordered_set<std::string> safe = default_safe_methods();
        load_env_allowlist(safe);

        for(;;){
            if(!running_.load()){
                break;
            }
            fd_set rfds;
            FD_ZERO(&rfds);
#ifdef _WIN32
            FD_SET(s, &rfds);
            timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000; // 200ms
            int sel = select(0, &rfds, nullptr, nullptr, &tv);
#else
            FD_SET(s, &rfds);
            timeval tv; tv.tv_sec = 0; tv.tv_usec = 200000;
            int sel = select((int)s+1, &rfds, nullptr, nullptr, &tv);
#endif
            if(sel <= 0) {
                continue;
            }
            sockaddr_storage cli{}; socklen_t clen = sizeof(cli);
#ifdef _WIN32
            sock_t fd = accept(s, (sockaddr*)&cli, &clen);
            if(fd == INVALID_SOCKET){ continue; }
#else
            sock_t fd = accept(s, (sockaddr*)&cli, &clen);
            if(fd < 0){ continue; }
#endif
            // Hard connection cap
            int live = ++g_live_conns;
            if(live > max_conn){
                const std::string body_rlc = "{\"error\":\"too many connections\"}";
                send_http_simple(fd, 503, "Service Unavailable", "application/json", body_rlc);
                closesocket(fd);
                --g_live_conns;
                continue;
            }

            std::thread([fd, on_json, env_token, bound_loopback, require_always, safe,
                         ip_rps, ip_burst, max_hdr_bytes, max_body_bytes, recv_timeout_ms,
                         cli, allow_cors, enable_metrics, metrics_public, enable_healthz, access_log]() {
                auto guard = std::unique_ptr<void, void(*)(void*)>(nullptr, [](void*){ --g_live_conns; });

                auto t_start = std::chrono::steady_clock::now();

                // simple reqid + access log
                auto gen_reqid = [](){
                    std::array<unsigned char,8> r{}; for(auto& b: r) b = (unsigned char)std::rand();
                    std::ostringstream os; os << std::hex << std::setw(2) << std::setfill('0');
                    for(unsigned char b: r){ os << std::setw(2) << (int)b; }
                    return os.str();
                };

                auto access_logf = [&](int code, const std::string& ip, const std::string& method,
                                       const std::string& path, const std::string& rpc_method,
                                       size_t in_bytes, size_t out_bytes, const std::string& reqid){
                    if(!access_log) return;
                    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::steady_clock::now() - t_start).count();
                    log_info("http " + std::to_string(code) + " ip=" + ip +
                             " method=" + method + " path=" + path +
                             " rpc=" + (rpc_method.empty()?"-":rpc_method) +
                             " in=" + std::to_string(in_bytes) +
                             " out=" + std::to_string(out_bytes) +
                             " dur_ms=" + std::to_string(ms) +
                             " reqid=" + reqid);
                    g_metrics.observe_duration_ms((uint64_t)ms);
                };

                // Per-IP token bucket
                std::string ip = sock_ntop(cli);
                if(!rl_allow(ip, ip_rps, ip_burst)){
                    g_metrics.http_rate_limited_total += 1;
                    std::string reqid = gen_reqid();
                    const std::string body_rl = "{\"error\":\"rate limit\"}";
                    send_http_simple(fd, 429, "Too Many Requests", "application/json",
                                     body_rl,
                                     {{"Retry-After","1"},{"X-Request-Id", reqid}});
                    access_logf(429, ip, "?", "?", "", 0, body_rl.size(), reqid);
                    closesocket(fd);
                    return;
                }

                // Parse one request (with time/size caps)
                std::string method, path, body;
                std::vector<std::pair<std::string,std::string>> headers;
                if(!parse_http_request(fd, method, path, body, headers, max_hdr_bytes, max_body_bytes, recv_timeout_ms)){
                    closesocket(fd);
                    return;
                }

                std::string reqid = get_header(headers, "x-request-id");
                if(reqid.empty()) reqid = gen_reqid();

                g_metrics.http_requests_total += 1;
                g_metrics.http_bytes_in_total += body.size();

                // Collect headers
                std::string auth  = get_header(headers, "authorization");
                std::string xauth = get_header(headers, "x-auth-token");
                std::string content_type = get_header(headers, "content-type");
                if(content_type.empty()) content_type = "application/json";

                // =================== EARLY HANDLERS (no auth gate) ===================
                // CORS preflight
                if(lc(method) == "options"){
                    std::vector<std::pair<std::string,std::string>> hdrs = {
                        {"X-Request-Id", reqid}
                    };
                    if(allow_cors){
                        hdrs.emplace_back("Access-Control-Allow-Origin","*");
                        hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type, X-Request-Id");
                        hdrs.emplace_back("Access-Control-Allow-Methods","POST, OPTIONS");
                        hdrs.emplace_back("Access-Control-Max-Age","600");
                    }
                    send_http_simple(fd, 204, "No Content", "text/plain", "", hdrs);
                    access_logf(204, ip, method, path, "", 0, 0, reqid);
                    closesocket(fd);
                    return;
                }

                // /healthz
                if(lc(method) == "get" && enable_healthz && path == "/healthz"){
                    std::string resp = std::string("{\"ok\":true,\"live_conns\":") +
                                       std::to_string(g_live_conns.load()) + "}";
                    std::vector<std::pair<std::string,std::string>> hdrs = {{"X-Request-Id", reqid}};
                    if(allow_cors){
                        hdrs.emplace_back("Access-Control-Allow-Origin","*");
                        hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type, X-Request-Id");
                    }
                    send_http_simple(fd, 200, "OK", "application/json", resp, hdrs);
                    access_logf(200, ip, method, path, "", 0, resp.size(), reqid);
                    closesocket(fd);
                    return;
                }

                // /metrics
                if(lc(method) == "get" && enable_metrics && path == "/metrics"){
                    bool ok = true;
                    if(!bound_loopback && !metrics_public){
                        std::string token = env_token ? std::string(env_token) : std::string();
                        // Very small check: bearer or x-auth-token must match token
                        auto auth_hdr = get_header(headers,"authorization");
                        std::string auth_trim = auth_hdr;
                        trim(auth_trim);
                        bool bearer_ok=false;
                        if(auth_trim.size() >= 7 && lc(auth_trim.substr(0,6)) == "bearer"){
                            size_t sp = auth_trim.find(' ');
                            if(sp != std::string::npos){
                                std::string presented = auth_trim.substr(sp+1);
                                trim(presented);
                                bearer_ok = (!token.empty() && presented == token);
                            }
                        }
                        ok = bearer_ok || (!get_header(headers,"x-auth-token").empty() && get_header(headers,"x-auth-token")==token);
                    }
                    if(!ok){
                        g_metrics.http_unauthorized_total += 1;
                        std::vector<std::pair<std::string,std::string>> hdrs = {{"WWW-Authenticate","Bearer"}, {"X-Request-Id", reqid}};
                        const std::string body_u = "{\"error\":\"unauthorized\"}";
                        send_http_simple(fd, 401, "Unauthorized", "application/json", body_u, hdrs);
                        access_logf(401, ip, method, path, "", body.size(), body_u.size(), reqid);
                        closesocket(fd);
                        return;
                    }
                    std::string prom = g_metrics.render_prom();
                    std::vector<std::pair<std::string,std::string>> hdrs = {{"X-Request-Id", reqid}};
                    send_http_simple(fd, 200, "OK", "text/plain; version=0.0.4", prom, hdrs);
                    access_logf(200, ip, method, path, "", 0, prom.size(), reqid);
                    closesocket(fd);
                    return;
                }
                // =====================================================================

                // Token policy (legacy env-based gate; OK to disable by leaving env unset)
                bool token_required = require_always || !bound_loopback;
                std::string token = env_token ? std::string(env_token) : std::string();

                auto unauthorized = [&](const char* why){
                    g_metrics.http_unauthorized_total += 1;
                    std::vector<std::pair<std::string,std::string>> hdrs = {{"WWW-Authenticate","Bearer"},{"X-Request-Id",reqid}};
                    if(allow_cors){
                        hdrs.emplace_back("Access-Control-Allow-Origin","*");
                        hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type, X-Request-Id");
                    }
                    const std::string body_u = std::string("{\"error\":\"unauthorized\",\"reason\":\"") + why + "\"}";
                    send_http_simple(fd, 401, "Unauthorized", "application/json", body_u, hdrs);
                    access_logf(401, ip, method, path, "", body.size(), body_u.size(), reqid);
                    closesocket(fd);
                };

                bool token_present = false;

                auto check_bearer = [&](const std::string& a)->bool{
                    std::string s = a; trim(s);
                    if(s.size() >= 7 && lc(s.substr(0,6)) == "bearer"){
                        size_t sp = s.find(' ');
                        if(sp != std::string::npos){
                            std::string presented = s.substr(sp+1); trim(presented);
                            return (!token.empty() && presented == token);
                        }
                    }
                    return false;
                };

                if(token_required){
                    if(token.empty()){
                        // If no env token configured, skip this legacy gate
                        // (RPC will enforce cookie-based Authorization itself).
                    } else {
                        if(!(check_bearer(auth) || (!xauth.empty() && xauth == token))){
                            unauthorized("invalid-token");
                            return;
                        }
                        token_present = true;
                    }
                } else {
                    // Not required (loopback), but if provided and matches env token, mark present
                    if(check_bearer(auth) || (!xauth.empty() && xauth == token)) token_present = true;
                }

                // Method check for unauthenticated *per the legacy gate only*.
                // NOTE: RPC still gets headers and will do its own cookie-based auth.
                if(!token_present){
                    std::string m = extract_json_method(body);
                    if(m.empty() || safe.find(m) == safe.end()){
                        g_metrics.http_forbidden_total += 1;
                        std::vector<std::pair<std::string,std::string>> hdrs;
                        if(allow_cors){
                            hdrs.emplace_back("Access-Control-Allow-Origin","*");
                            hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type, X-Request-Id");
                        }
                        hdrs.emplace_back("X-Request-Id", reqid);
                        const std::string body_f = "{\"error\":\"forbidden\",\"reason\":\"method requires token\"}";
                        send_http_simple(fd, 403, "Forbidden", "application/json", body_f, hdrs);
                        access_logf(403, ip, method, path, m, body.size(), body_f.size(), reqid);
                        closesocket(fd);
                        return;
                    }
                }

                // Only POST (we already handled OPTIONS above)
                if(lc(method) != "post"){
                    g_metrics.http_method_not_allowed_total += 1;
                    std::vector<std::pair<std::string,std::string>> hdrs;
                    if(allow_cors){
                        hdrs.emplace_back("Access-Control-Allow-Origin","*");
                        hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type, X-Request-Id");
                        hdrs.emplace_back("Access-Control-Allow-Methods","POST, OPTIONS");
                    }
                    hdrs.emplace_back("X-Request-Id", reqid);
                    const std::string body_405 = "{\"error\":\"only POST\"}";
                    send_http_simple(fd, 405, "Method Not Allowed", "application/json", body_405, hdrs);
                    access_logf(405, ip, method, path, "", body.size(), body_405.size(), reqid);
                    closesocket(fd);
                    return;
                }

                // Invoke headers-aware handler
                std::string rpc_method_name = extract_json_method(body);
                std::string resp_body;
                int code = 200;
                try{
                    resp_body = on_json(body, headers);
                    if(resp_body.empty()) resp_body = "{\"result\":null}";
                } catch(...){
                    resp_body = "{\"error\":\"internal error\"}";
                }

                bool is_error = false;
                {
                    // best-effort: starts with {"error":
                    std::string s = resp_body;
                    size_t i=0; while(i<s.size() && (s[i]==' '||s[i]=='\n'||s[i]=='\r'||s[i]=='\t')) ++i;
                    is_error = (s.size() >= i+8 && s.compare(i,8,"{\"error\"")==0);
                }
                if(!rpc_method_name.empty()){
                    g_metrics.add_method_call(rpc_method_name, is_error);
                }

                std::vector<std::pair<std::string,std::string>> out_hdrs = {
                    {"X-RateLimit-Limit", std::to_string(ip_rps)},
                    {"X-RateLimit-Policy", "token-bucket"},
                    {"X-Request-Id", reqid},
                };
                if(allow_cors){
                    out_hdrs.emplace_back("Access-Control-Allow-Origin","*");
                    out_hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type, X-Request-Id");
                }
                send_http_simple(fd, code, "OK", "application/json", resp_body, out_hdrs);
                access_logf(code, ip, method, path, rpc_method_name, body.size(), resp_body.size(), reqid);
                closesocket(fd);
            }).detach();
        }
        closesocket(s);
#ifdef _WIN32
        WSACleanup();
#endif
    };

    std::thread(thread_fn).detach();
}

// Back-compat wrapper: ignores headers for the callback
void HttpServer::start(uint16_t port, std::function<std::string(const std::string&)> on_json){
    // Wrap the old callback into headers-aware form.
    auto wrapper = [on_json](const std::string& body,
                             const std::vector<std::pair<std::string,std::string>>& /*headers*/)->std::string {
        return on_json(body);
    };
    this->start(port, wrapper);
}

void HttpServer::stop(){
    running_.store(false);
}

}
