#include "tls_proxy.h"
#include <cstring>
#include <vector>
#include <string>
#include <stdexcept>

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

namespace {

static void split_host_port(const std::string& hp, std::string& host, int& port){
    auto pos = hp.find(':');
    if(pos==std::string::npos){ host = hp; port = 0; return; }
    host = hp.substr(0,pos);
    port = std::stoi(hp.substr(pos+1));
}

static int create_listen_socket(const std::string& host, int port, std::string& err){
#ifdef _WIN32
    WSADATA wsa; if(WSAStartup(MAKEWORD(2,2), &wsa)!=0){ err="WSAStartup failed"; return -1; }
#endif
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM; hints.ai_flags=AI_PASSIVE;
    addrinfo* res=nullptr; char portstr[32]; snprintf(portstr,sizeof(portstr), "%d", port);
    if(getaddrinfo(host.empty()?nullptr:host.c_str(), portstr, &hints, &res)!=0){ err="getaddrinfo failed"; return -1; }
    int sock=-1;
    for(addrinfo* p=res;p;p=p->ai_next){
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(sock<0) continue;
        int yes=1; setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
        if(bind(sock, p->ai_addr, (int)p->ai_addrlen)==0){
            if(listen(sock, 64)==0){ freeaddrinfo(res); return sock; }
        }
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
    }
    freeaddrinfo(res);
    err="bind/listen failed";
    return -1;
}

static int connect_plain(const std::string& host, int port){
    addrinfo hints{}; hints.ai_family=AF_UNSPEC; hints.ai_socktype=SOCK_STREAM;
    addrinfo* res=nullptr; char portstr[32]; snprintf(portstr,sizeof(portstr), "%d", port);
    if(getaddrinfo(host.c_str(), portstr, &hints, &res)!=0) return -1;
    int s=-1;
    for(addrinfo* p=res;p;p=p->ai_next){
        s = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
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

static void proxy_loop_once(SSL* ssl, int plain_sock){
    std::vector<unsigned char> buf(16*1024);
    // Simple half-duplex alternation; good enough for JSON-RPC.
    // You can evolve to select()/poll() bidirectional if needed.
    int r = SSL_read(ssl, buf.data(), (int)buf.size());
    if(r<=0) return;
    int sent = 0;
    while(sent<r){
        int w = (int)send(plain_sock, (const char*)buf.data()+sent, r-sent, 0);
        if(w<=0) return;
        sent += w;
    }
    // Read response
    int rr = recv(plain_sock, (char*)buf.data(), (int)buf.size(), 0);
    if(rr<=0) return;
    int ws = 0;
    while(ws<rr){
        int ww = SSL_write(ssl, (const char*)buf.data()+ws, rr-ws);
        if(ww<=0) return;
        ws += ww;
    }
}

}

using namespace miq;

TlsProxy::TlsProxy(const std::string& tls_bind_addr,
                   const std::string& tls_cert_pem,
                   const std::string& tls_key_pem,
                   const std::string& tls_client_ca_pem,
                   const std::string& forward_host,
                   int forward_port)
: cert_path_(tls_cert_pem), key_path_(tls_key_pem), ca_path_(tls_client_ca_pem),
  fwd_host_(forward_host), fwd_port_(forward_port)
{
    split_host_port(tls_bind_addr, bind_host_, bind_port_);
}

TlsProxy::~TlsProxy(){ stop(); }

bool TlsProxy::start(std::string& err){
    if(run_.load()) return true;
    if(bind_port_==0){ err="invalid rpc_tls_bind (missing port)"; return false; }
    if(cert_path_.empty()||key_path_.empty()){ err="rpc_tls_cert/rpc_tls_key required"; return false; }
    run_ = true;
    th_ = std::thread([this](){
        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD* method = TLS_server_method();
        SSL_CTX* ctx = SSL_CTX_new(method);
        if(!ctx) return;

        // Load server keypair
        if(SSL_CTX_use_certificate_chain_file(ctx, cert_path_.c_str())<=0) { SSL_CTX_free(ctx); return; }
        if(SSL_CTX_use_PrivateKey_file(ctx, key_path_.c_str(), SSL_FILETYPE_PEM)<=0) { SSL_CTX_free(ctx); return; }
        if(!ca_path_.empty()){
            if(SSL_CTX_load_verify_locations(ctx, ca_path_.c_str(), nullptr)<=0) { SSL_CTX_free(ctx); return; }
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
        }

        std::string err2;
        int lsock = create_listen_socket(bind_host_, bind_port_, err2);
        if(lsock<0){ SSL_CTX_free(ctx); return; }

        while(run_.load()){
            sockaddr_storage ss{}; socklen_t slen=sizeof(ss);
            int cs = (int)accept(lsock, (sockaddr*)&ss, &slen);
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

            int plain = connect_plain(fwd_host_, fwd_port_);
            if(plain<0){
                SSL_shutdown(ssl); SSL_free(ssl);
#ifdef _WIN32
                closesocket(cs);
#else
                close(cs);
#endif
                continue;
            }

            // Single request/response per connection (JSON-RPC typical).
            proxy_loop_once(ssl, plain);

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
        closesocket(lsock);
#else
        close(lsock);
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
