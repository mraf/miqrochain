#include "http_client.h"

#include <cstring>
#include <string>
#include <vector>
#include <algorithm>

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
  static bool wsa_inited = false;
  static void wsa_ensure(){ if(!wsa_inited){ WSADATA w; WSAStartup(MAKEWORD(2,2), &w); wsa_inited=true; } }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <arpa/inet.h>
  using sock_t = int;
  #define closesocket ::close
#endif

namespace miq {

static inline std::string lc(std::string s){
    for(char& c : s) c = (char)std::tolower((unsigned char)c);
    return s;
}

static bool set_timeout(sock_t fd, int ms){
#ifdef _WIN32
    DWORD tv = (DWORD)ms;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv))==0
        && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv))==0;
#else
    timeval tv; tv.tv_sec = ms/1000; tv.tv_usec = (ms%1000)*1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv))==0
        && setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv))==0;
#endif
}

bool http_post(const std::string& host,
               uint16_t port,
               const std::string& path,
               const std::string& body,
               const std::vector<std::pair<std::string,std::string>>& headers,
               HttpResponse& out,
               int timeout_ms)
{
#ifdef _WIN32
    wsa_ensure();
#endif

    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    char portbuf[16]; std::snprintf(portbuf, sizeof(portbuf), "%u", (unsigned)port);
    addrinfo* res=nullptr;
    if(getaddrinfo(host.c_str(), portbuf, &hints, &res)!=0) return false;

    sock_t fd = (sock_t)(~(sock_t)0);
    for(addrinfo* ai=res; ai; ai=ai->ai_next){
        fd = (sock_t)socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
#ifdef _WIN32
        if(fd==INVALID_SOCKET) continue;
#else
        if(fd<0) continue;
#endif
        if(!set_timeout(fd, timeout_ms)){ closesocket(fd); continue; }
        if(connect(fd, ai->ai_addr, (socklen_t)ai->ai_addrlen)==0){
            break;
        }
        closesocket(fd);
#ifdef _WIN32
        fd = INVALID_SOCKET;
#else
        fd = -1;
#endif
    }
    freeaddrinfo(res);
#ifdef _WIN32
    if(fd==INVALID_SOCKET) return false;
#else
    if(fd<0) return false;
#endif

    std::string req;
    req.reserve(256 + body.size());
    req += "POST " + (path.empty()?std::string("/") : path) + " HTTP/1.1\r\n";
    req += "Host: " + host + "\r\n";
    req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    for(const auto& h: headers){
        req += h.first; req += ": "; req += h.second; req += "\r\n";
    }
    req += "Connection: close\r\n\r\n";
    req += body;

    const char* p = req.data(); size_t left = req.size();
    while(left){
#ifdef _WIN32
        int n = send(fd, p, (int)left, 0);
#else
        ssize_t n = ::send(fd, p, left, 0);
#endif
        if(n<=0){ closesocket(fd); return false; }
        p += n; left -= (size_t)n;
    }

    std::string buf; buf.reserve(4096);
    char tmp[4096];
    for(;;){
#ifdef _WIN32
        int n = recv(fd, tmp, (int)sizeof(tmp), 0);
#else
        ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
#endif
        if(n<=0) break;
        buf.append(tmp, tmp+n);
    }
    closesocket(fd);

    size_t pos = buf.find("\r\n");
    if(pos==std::string::npos) return false;
    std::string status = buf.substr(0,pos);
    int code = 0; {
        size_t sp = status.find(' ');
        if(sp!=std::string::npos){
            code = std::atoi(status.c_str()+sp+1);
        }
    }
    size_t hdr_end = buf.find("\r\n\r\n");
    if(hdr_end==std::string::npos) return false;
    std::map<std::string,std::string> hdrs;
    size_t cur = pos+2;
    while(cur < hdr_end){
        size_t nl = buf.find("\r\n", cur);
        if(nl==std::string::npos || nl>hdr_end) break;
        std::string line = buf.substr(cur, nl-cur);
        cur = nl+2;
        size_t c = line.find(':');
        if(c!=std::string::npos){
            std::string k = line.substr(0,c);
            std::string v = line.substr(c+1);
            while(!v.empty() && (v.front()==' '||v.front()=='\t')) v.erase(v.begin());
            while(!v.empty() && (v.back()==' '||v.back()=='\t')) v.pop_back();
            std::transform(k.begin(), k.end(), k.begin(), [](unsigned char x){return std::tolower(x);});
            hdrs[k] = v;
        }
    }
    std::string body_out = buf.substr(hdr_end+4);

    out.code = code;
    out.body = std::move(body_out);
    out.headers = std::move(hdrs);
    return true;
}

}
