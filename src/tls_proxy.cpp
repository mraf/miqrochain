#include "tls_proxy.h"
#include <vector>
#include <cstring>

#ifdef _WIN32
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

#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace miq;

namespace {

static void split_host_port(const std::string& s, std::string& host, int& port){
    auto p = s.find(':');
    if(p==std::string::npos){ host=s; port=0; return; }
    host = s.substr(0,p);
    port = std::stoi(s.substr(p+1));
}

static int make_listener(const std::string& host, int port){
#ifdef _WIN32
    WSADATA wsa; if(WSAStartup(MAKEWORD(2,2), &wsa)!=0) return -1;
#endif
    struct addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM; hints.ai_flags=AI_PASSIVE;
    struct addrinfo* res=nullptr; char ps[16]; snprintf(ps,sizeof(ps), "%d", port);
    if(getaddrinfo(host.empty()?nullptr:host.c_str(), ps, &hints, &res)!=0) return -1;

    int s=-1;
    for(auto* p=res; p; p=p->ai_next){
        s = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s<0) continue;
        int yes=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
        if(bind(s, p->ai_addr, (int)p->ai_addrlen)==0 && listen(s, 64)==0){
            freeaddrinfo(res); return s;
        }
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }
    freeaddrinfo(res);
    return -1;
}

static int connect_plain(const std::string& host, int port){
    struct addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    struct addrinfo* res=nullptr; char ps[16]; snprintf(ps,sizeof(ps), "%d", port);
    if(getaddrinfo(host.c_str(), ps, &hints, &res)!=0) return -1;
    int s=-1;
    for(auto* p=res; p; p=p->ai_next){
        s = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s<0) continue;
        if(connect(s, p->ai_addr, (int)p->ai_addrlen)==0){ freeaddrinfo(res); return s; }
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }
    freeaddrinfo(res);
    return -1;
}

static void proxy_once(SSL* ssl, int plain_sock){
    std::vector<unsigned char> buf(16*1024);

    // Read HTTPS request
    int r = SSL_read(ssl, buf.data(), (int)buf.size());
    if(r<=0) return;

    // Forward to RPC
    int off=0;
    while(off<r){
        int w=(int)send(plain_sock, (const char*)buf.data()+off, r-off, 0);
        if(w<=0) return;
        off+=w;
    }

    // Read RPC response
    int rr = recv(plain_sock, (char*)buf.data(), (int)buf.size(), 0);
    if(rr<=0) return;

    // Send back over TLS
    off=0;
    while(off<rr){
        int ww=SSL_write(ssl, (const char*)buf.data()+off, rr-off);
        if(ww<=0) return;
        off+=ww;
    }
}

} // anon

TlsProxy::TlsProxy(const std::string& bind_hp,
                   const std::string& cert,
                   const std::string& key,
                   const std::string& ca,
                   const std::string& fwd_host,
                   int fwd_port)
: cert_(cert), key_(key), ca_(ca), fwd_host_(fwd_host), fwd_port_(fwd_port)
{
    split_host_port(bind_hp, bind_host_, bind_port_);
}

TlsProxy::~TlsProxy(){ stop(); }

bool TlsProxy::start(std::string& err){
    if(run_.load()) return true;
    if(bind_port_==0){ err="rpc_tls_bind missing port"; return false; }
    if(cert_.empty()||key_.empty()){ err="rpc_tls_cert/key required"; return false; }

    run_ = true;
    th_ = std::thread([this](){
        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD* method = TLS_server_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        if(!ctx) return;

        if(SSL_CTX_use_certificate_chain_file(ctx, cert_.c_str())<=0){ SSL_CTX_free(ctx); return; }
        if(SSL_CTX_use_PrivateKey_file(ctx, key_.c_str(), SSL_FILETYPE_PEM)<=0){ SSL_CTX_free(ctx); return; }
        if(!ca_.empty()){
            if(SSL_CTX_load_verify_locations(ctx, ca_.c_str(), nullptr)<=0){ SSL_CTX_free(ctx); return; }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        }

        int ls = make_listener(bind_host_, bind_port_);
        if(ls<0){ SSL_CTX_free(ctx); return; }

        while(run_.load()){
            sockaddr_storage ss{}; socklen_t slen=sizeof(ss);
            int cs = (int)accept(ls, (sockaddr*)&ss, &slen);
            if(cs<0) continue;

            SSL* ssl = SSL_new(ctx);
            SSL_set_fd(ssl, cs);
            if(SSL_accept(ssl)<=0){
                SSL_free(ssl);
#ifdef _WIN32
                closesocket(cs);
#else
                close(cs);
#endif
                continue;
            }

            int plain = connect_plain("127.0.0.1", fwd_port_);
            if(plain<0){
                SSL_shutdown(ssl); SSL_free(ssl);
#ifdef _WIN32
                closesocket(cs);
#else
                close(cs);
#endif
                continue;
            }

            proxy_once(ssl, plain);

#ifdef _WIN32
            closesocket(plain);
            closesocket(cs);
#else
            close(plain);
            close(cs);
#endif
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }

#ifdef _WIN32
        closesocket(ls);
#else
        close(ls);
#endif
        SSL_CTX_free(ctx);
    });
    return true;
}

void TlsProxy::stop(){
    if(!run_.load()) return;
    run_ = false;
    if(th_.joinable()) th_.join();
}
