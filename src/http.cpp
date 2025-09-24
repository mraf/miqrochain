// src/http.cpp
#include "http.h"
#include <thread>
#include <string>
#include <cstring>
#include <cctype>
#include <algorithm>
#include <stdexcept>   // <-- existing
#include <cstdlib>     // <-- ADDED (getenv)

// ADDED: tiny helpers
static inline bool env_truthy(const char* v) {
    if (!v || !*v) return false;
    return (*v=='1' || *v=='t' || *v=='T' || *v=='y' || *v=='Y');
}

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef socklen_t
using socklen_t = int;
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define closesocket close
#endif

namespace miq {

static size_t parse_content_length(const std::string& headers, size_t cap = (1u<<20)) {
    std::string hay = headers;
    std::transform(hay.begin(), hay.end(), hay.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    size_t p = hay.find("content-length:");
    if (p == std::string::npos) return 0; // no body
    p = headers.find(':', p);
    if (p == std::string::npos) throw std::runtime_error("bad Content-Length header");
    ++p;
    while (p < headers.size() && std::isspace((unsigned char)headers[p])) ++p;
    size_t q = p;
    while (q < headers.size() && std::isdigit((unsigned char)headers[q])) ++q;
    if (q == p) throw std::runtime_error("Content-Length not a number");
    unsigned long long n = std::stoull(headers.substr(p, q - p));
    if (n > cap) throw std::runtime_error("Content-Length too large");
    return (size_t)n;
}

// ADDED: case-insensitive header fetcher (returns empty string if not found)
static std::string get_header_ci(const std::string& headers, const std::string& key) {
    std::string hay = headers;
    std::string k = key;
    std::transform(hay.begin(), hay.end(), hay.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c){ return (char)std::tolower(c); });
    size_t p = hay.find(k + ":");
    if (p == std::string::npos) return {};
    size_t colon = headers.find(':', p);
    if (colon == std::string::npos) return {};
    size_t v = colon + 1;
    while (v < headers.size() && std::isspace((unsigned char)headers[v])) ++v;
    size_t e = headers.find("\r\n", v);
    if (e == std::string::npos) e = headers.size();
    return headers.substr(v, e - v);
}

void HttpServer::start(uint16_t port, std::function<std::string(const std::string&)> on_json){
    if (running_.load()) return;
    running_.store(true);

    std::thread([=](){
    #ifdef _WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
    #endif
        int s= (int)socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(s<0){ running_.store(false); 
        #ifdef _WIN32
            WSACleanup();
        #endif
            return;
        }
        sockaddr_in a{}; a.sin_family=AF_INET; a.sin_addr.s_addr=htonl(INADDR_ANY); a.sin_port=htons(port);

        // ADDED: allow opting into loopback bind only, without removing original default
        {
            const char* loop_env = std::getenv("MIQ_RPC_BIND_LOOPBACK");
            if (env_truthy(loop_env)) {
                a.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
            }
        }

        int y=1; setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&y,sizeof(y));
        if(bind(s,(sockaddr*)&a,sizeof(a))<0){ closesocket(s); running_.store(false);
        #ifdef _WIN32
            WSACleanup();
        #endif
            return;
        }
        listen(s,64);
        while(running_.load()){
            sockaddr_in c{}; socklen_t cl=sizeof(c);
            #ifdef _WIN32
	    SOCKET fd = accept(s,(sockaddr*)&c,&cl);
	    #else
	    int fd = accept(s,(sockaddr*)&c,&cl);
	    #endif
            if(fd<0) continue;

            // ADDED: optional local-only enforcement (reject non-loopback peers)
            {
                const char* loc_env = std::getenv("MIQ_RPC_LOCALONLY");
                if (env_truthy(loc_env)) {
                    // Check if remote address is loopback (127.0.0.1)
                    uint32_t rip = ntohl(c.sin_addr.s_addr);
                    if (rip != 0x7f000001) {
                        const char* body = "{\"error\":\"forbidden - local only\"}";
                        std::string resp = std::string("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: ")
                                         + std::to_string(std::strlen(body))
                                         + "\r\nConnection: close\r\n\r\n" + body;
                        send(fd, resp.c_str(), (int)resp.size(), 0);
                        closesocket(fd);
                        continue;
                    }
                }
            }

            // read request (headers first)
            std::string req;
            char buf[4096];
            for(;;){
                int n = recv(fd, buf, sizeof(buf), 0);
                if(n<=0) break;
                req.append(buf, buf+n);
                auto pos = req.find("\r\n\r\n");
                if(pos != std::string::npos){
                    size_t header_end = pos + 4;
                    std::string headers = req.substr(0, header_end);

                    // content length (optional)
                    size_t body_len = 0;
                    try { body_len = parse_content_length(headers); }
                    catch(...) { /* malformed; treat as 0 */ }

                    size_t have_body = req.size() - header_end;
                    while(have_body < body_len){
                        int m = recv(fd, buf, sizeof(buf), 0);
                        if(m<=0) break;
                        req.append(buf, buf+m);
                        have_body += m;
                    }

                    std::string method_line = req.substr(0, req.find("\r\n"));
                    bool is_post = method_line.size()>=4 && method_line.rfind("POST",0)==0;
                    std::string body = req.substr(header_end, body_len);

                    // ADDED: Optional bearer-token auth via env MIQ_RPC_TOKEN
                    const char* tok_env = std::getenv("MIQ_RPC_TOKEN");
                    bool need_auth = (tok_env && *tok_env);
                    if (need_auth) {
                        std::string auth = get_header_ci(headers, "Authorization");
                        std::string want = std::string("Bearer ") + tok_env;
                        if (auth != want) {
                            const char* b = "{\"error\":\"unauthorized\"}";
                            std::string resp = std::string("HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: ")
                                             + std::to_string(std::strlen(b))
                                             + "\r\nConnection: close\r\n\r\n" + b;
                            send(fd, resp.c_str(), (int)resp.size(), 0);
                            break; // close fd below
                        }
                    }

                    std::string resp_body;
                    if(is_post){
                        try { resp_body = on_json(body); }
                        catch(...) { resp_body = "{\"error\":\"internal error\"}"; }
                    } else {
                        resp_body = "{\"error\":\"only POST\"}";
                    }

                    std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                                     + std::to_string(resp_body.size()) + "\r\nConnection: close\r\n\r\n" + resp_body;
                    send(fd, resp.c_str(), (int)resp.size(), 0);
                    break;
                }
            }
            closesocket(fd);
        }
        closesocket(s);
    #ifdef _WIN32
        WSACleanup();
    #endif
    }).detach();
}

void HttpServer::stop(){ running_.store(false); }

} // namespace miq

