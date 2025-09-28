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

static bool ga(const char* host,
               uint16_t port,
               std::vector<SeedEndpoint>& out,
               std::set<std::string>& seen)
{
    if (!host || !*host) return false;

#if defined(_WIN32)
    WSADATA wsa;
    bool wsa_ok = (WSAStartup(MAKEWORD(2,2), &wsa) == 0);
#endif

    struct addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM; // we’ll connect TCP
    hints.ai_family   = AF_UNSPEC;   // v4 or v6

    char port_str[16];
    std::snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    struct addrinfo* res = nullptr;
    int rc = ::getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0 || !res) {
#if defined(_WIN32)
        if (wsa_ok) WSACleanup();
#endif
        return false;
    }

    bool any=false;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        char ipstr[INET6_ADDRSTRLEN] = {0};
        void* addr = nullptr;

        if (ai->ai_family == AF_INET) {
            addr = &((struct sockaddr_in*)ai->ai_addr)->sin_addr;
            inet_ntop(AF_INET, addr, ipstr, sizeof(ipstr));
        } else if (ai->ai_family == AF_INET6) {
            addr = &((struct sockaddr_in6*)ai->ai_addr)->sin6_addr;
            inet_ntop(AF_INET6, addr, ipstr, sizeof(ipstr));
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
#if defined(_WIN32)
    if (wsa_ok) WSACleanup();
#endif
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
        const char* host = DNS_SEEDS[i];
        (void)ga(host, port, out, seen);
    }

    // Optional single seed (can be IP literal)
    if (include_single_dns_seed && DNS_SEED && *DNS_SEED) {
        (void)ga(DNS_SEED, port, out, seen);
    }

    return !out.empty();
}

}
