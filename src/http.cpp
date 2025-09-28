// src/http.cpp  (hardened, backward-compatible)
#include "http.h"
#include <thread>
#include <string>
#include <vector>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <stdexcept>
#include <cstdlib>   // getenv
#include <cstdio>
#include <unordered_set>
#include <unordered_map>
#include <chrono>
#include <atomic>

#ifdef _WIN32
  // Prevent Windows headers from defining min/max macros that break std::min/std::max
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  using sock_t = SOCKET;
  static inline void miq_sleep_ms(unsigned ms){ Sleep(ms); }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
  using sock_t = int;
  static inline void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
  #define closesocket ::close
#endif


#ifdef _WIN32
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socklen_t = int;
  using sock_t = SOCKET;
  static inline void miq_sleep_ms(unsigned ms){ Sleep(ms); }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
  using sock_t = int;
  static inline void miq_sleep_ms(unsigned ms){ usleep(ms*1000); }
  #define closesocket ::close
#endif

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
                if(std::chrono::steady_clock::now() > deadline) return false;
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
static std::chrono::steady_clock::time_point g_last_cleanup = std::chrono::steady_clock::now();
static std::atomic<int> g_live_conns{0};

// Refill & check token bucket
static bool rl_allow(const std::string& ip, int rps, int burst){
    auto now = std::chrono::steady_clock::now();
    TokenBucket& b = g_buckets[ip];
    double dt = std::chrono::duration<double>(now - b.last).count();
    b.last = now;
    if(b.rate_per_sec <= 0.0){ b.rate_per_sec = (double)rps; }
    if(b.burst <= 0.0){ b.burst = (double)burst; }
    b.tokens = std::min(b.burst, b.tokens + dt * b.rate_per_sec);
    if(b.tokens >= 1.0){
        b.tokens -= 1.0;
        // periodic cleanup
        if(now - g_last_cleanup > std::chrono::minutes(5)){
            for(auto it = g_buckets.begin(); it != g_buckets.end();){
                if(now - it->second.last > std::chrono::minutes(10)) it = g_buckets.erase(it);
                else ++it;
            }
            g_last_cleanup = now;
        }
        return true;
    }
    return false;
}

// ================= HttpServer ===============================================

void HttpServer::start(uint16_t port, std::function<std::string(const std::string&)> on_json){
    if(running_.exchange(true)) return;

#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    // Tunables (with sane defaults)
    const int max_conn          = env_int("MIQ_RPC_MAX_CONN", 64);      // global simultaneous connections
    const int ip_rps            = env_int("MIQ_RPC_RPS", 10);           // requests/sec per IP
    const int ip_burst          = env_int("MIQ_RPC_BURST", 30);         // burst size
    const size_t max_hdr_bytes  = env_szt("MIQ_RPC_MAX_HEADER", 16*1024); // 16 KiB (safer default)
    const size_t max_body_bytes = env_szt("MIQ_RPC_MAX_BODY",   2*1024*1024); // 2 MiB
    const int recv_timeout_ms   = env_int("MIQ_RPC_RECV_TIMEOUT_MS", 5000); // header+body total window
    const bool allow_cors       = env_truthy(std::getenv("MIQ_RPC_CORS"));

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
                      max_conn, ip_rps, ip_burst, max_hdr_bytes, max_body_bytes, recv_timeout_ms](){
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
                send_http_simple(fd, 503, "Service Unavailable", "application/json",
                                 std::string("{\"error\":\"too many connections\"}"));
                closesocket(fd);
                --g_live_conns;
                continue;
            }

            std::thread([fd, on_json, env_token, bound_loopback, require_always, safe,
                         ip_rps, ip_burst, max_hdr_bytes, max_body_bytes, recv_timeout_ms, cli, allow_cors]() {
                auto guard = std::unique_ptr<void, void(*)(void*)>(nullptr, [](void*){ --g_live_conns; });

                // Per-IP token bucket
                std::string ip = sock_ntop(cli);
                if(!rl_allow(ip, ip_rps, ip_burst)){
                    send_http_simple(fd, 429, "Too Many Requests", "application/json",
                                     std::string("{\"error\":\"rate limit\"}"),
                                     {{"Retry-After","1"}});
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

                // Collect headers
                std::string auth = get_header(headers, "authorization");
                std::string xauth = get_header(headers, "x-auth-token");
                std::string content_type = get_header(headers, "content-type");
                if(content_type.empty()) content_type = "application/json";

                // Token policy
                bool token_required = require_always || !bound_loopback;
                std::string token = env_token ? std::string(env_token) : std::string();
                auto unauthorized = [&](const char* why){
                    std::vector<std::pair<std::string,std::string>> hdrs = {{"WWW-Authenticate","Bearer"}};
                    if(allow_cors){
                        hdrs.emplace_back("Access-Control-Allow-Origin","*");
                        hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type");
                    }
                    send_http_simple(fd, 401, "Unauthorized", "application/json",
                        std::string("{\"error\":\"unauthorized\",\"reason\":\"") + why + "\"}", hdrs);
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
                        unauthorized("token-required");
                        return;
                    }
                    if(!(check_bearer(auth) || (!xauth.empty() && xauth == token))){
                        unauthorized("invalid-token");
                        return;
                    }
                    token_present = true;
                } else {
                    // Not required (loopback), but if provided and valid, mark present
                    if(check_bearer(auth) || (!xauth.empty() && xauth == token)) token_present = true;
                }

                // Method check
                if(lc(method) != "post"){
                    std::vector<std::pair<std::string,std::string>> hdrs;
                    if(allow_cors){
                        hdrs.emplace_back("Access-Control-Allow-Origin","*");
                        hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type");
                        hdrs.emplace_back("Access-Control-Allow-Methods","POST, OPTIONS");
                    }
                    if(lc(method) == "options"){
                        // CORS preflight (no body)
                        send_http_simple(fd, 204, "No Content", "text/plain", "", hdrs);
                        closesocket(fd);
                        return;
                    }
                    send_http_simple(fd, 405, "Method Not Allowed", "application/json",
                        std::string("{\"error\":\"only POST\"}"), hdrs);
                    closesocket(fd);
                    return;
                }

                // If unauthenticated (no valid token), enforce allowlist:
                if(!token_present){
                    std::string m = extract_json_method(body);
                    if(m.empty() || safe.find(m) == safe.end()){
                        std::vector<std::pair<std::string,std::string>> hdrs;
                        if(allow_cors){
                            hdrs.emplace_back("Access-Control-Allow-Origin","*");
                            hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type");
                        }
                        send_http_simple(fd, 403, "Forbidden", "application/json",
                            std::string("{\"error\":\"forbidden\",\"reason\":\"method requires token\"}"), hdrs);
                        closesocket(fd);
                        return;
                    }
                }

                // Invoke handler
                std::string resp_body;
                try{
                    resp_body = on_json(body);
                    if(resp_body.empty()) resp_body = "{\"result\":null}";
                } catch(...){
                    resp_body = "{\"error\":\"internal error\"}";
                }

                std::vector<std::pair<std::string,std::string>> out_hdrs = {
                    {"X-RateLimit-Limit", std::to_string(ip_rps)},
                    {"X-RateLimit-Policy", "token-bucket"},
                };
                if(allow_cors){
                    out_hdrs.emplace_back("Access-Control-Allow-Origin","*");
                    out_hdrs.emplace_back("Access-Control-Allow-Headers","Authorization, X-Auth-Token, Content-Type");
                }
                send_http_simple(fd, 200, "OK", "application/json", resp_body, out_hdrs);
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

void HttpServer::stop(){
    running_.store(false);
}

}
