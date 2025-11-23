#include "seeds.h"
#include "constants.h"

#include <set>
#include <string>
#include <vector>
#include <cstring>

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <unistd.h>
#endif

namespace miq {

// CRITICAL FIX: Initialize Winsock once at startup, not per-call
#if defined(_WIN32)
static void winsock_ensure() {
    static bool inited = false;
    if (!inited) {
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2,2), &wsa) == 0) inited = true;
    }
}
#else
static void winsock_ensure() {}
#endif

static bool ga(const char* host,
               uint16_t port,
               std::vector<SeedEndpoint>& out,
               std::set<std::string>& seen)
{
    if (!host || !*host) return false;

    winsock_ensure();

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; // TCP
    hints.ai_family   = AF_UNSPEC;   // v4 or v6

    char port_str[16];
#if defined(_WIN32)
    _snprintf_s(port_str, sizeof(port_str), _TRUNCATE, "%u", (unsigned)port);
#else
    std::snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);
#endif

    struct addrinfo* res = nullptr;
    int rc = ::getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res) {
        return false;
    }

    bool any=false;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        char ipstr[INET6_ADDRSTRLEN] = {0};

        if (ai->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<struct sockaddr_in*>(ai->ai_addr);
#if defined(_WIN32)
            InetNtopA(AF_INET, &sa->sin_addr, ipstr, sizeof(ipstr));
#else
            inet_ntop(AF_INET, &sa->sin_addr, ipstr, sizeof(ipstr));
#endif
        } else if (ai->ai_family == AF_INET6) {
            auto* sa6 = reinterpret_cast<struct sockaddr_in6*>(ai->ai_addr);
#if defined(_WIN32)
            InetNtopA(AF_INET6, &sa6->sin6_addr, ipstr, sizeof(ipstr));
#else
            inet_ntop(AF_INET6, &sa6->sin6_addr, ipstr, sizeof(ipstr));
#endif
        } else {
            continue;
        }

        if (ipstr[0] == '\0') continue;
        std::string key = std::string(ipstr) + ":" + std::to_string(port);
        if (seen.insert(key).second) {
            out.push_back(SeedEndpoint{host, ipstr, port});
            any = true;
        }
    }

    ::freeaddrinfo(res);
    return any;
}

bool resolve_dns_seeds(std::vector<SeedEndpoint>& out,
                       uint16_t port,
                       bool include_single_dns_seed)
{
    out.clear();
    std::set<std::string> seen;

    // Multi-seed list from constants.h
    for (size_t i = 0; i < DNS_SEEDS_COUNT; ++i) {
        const char* host = DNS_SEEDS[i]; // array is const char* const
        (void)ga(host, port, out, seen);
    }

    // Optional single seed (std::string) — can be hostname or IP literal
    if (include_single_dns_seed && !DNS_SEED.empty()) {
        (void)ga(DNS_SEED.c_str(), port, out, seen);
    }

    return !out.empty();
}

}
