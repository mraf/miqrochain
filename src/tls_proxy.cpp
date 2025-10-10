// src/tls_proxy.cpp
#include "tls_proxy.h"
#include "log.h"
#include <vector>
#include <string>
#include <cstring>
#include <atomic>
#include <thread>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  using socket_len_t = int;
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <unistd.h>
  #include <sys/select.h>
  using socket_len_t = socklen_t;
  #define closesocket ::close
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
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    struct addrinfo* res=nullptr; char ps[32];
    std::snprintf(ps, sizeof(ps), "%d", port);
    if(getaddrinfo(host.empty()?nullptr:host.c_str(), ps, &hints, &res)!=0) return -1;

    int s=-1;
    for(auto* p=res; p; p=p->ai_next){
        s = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s<0) continue;
        int yes=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));
#ifdef SO_REUSEPORT
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (char*)&yes, sizeof(yes));
#endif
        if(bind(s, p->ai_addr, (socket_len_t)p->ai_addrlen)==0 && listen(s, 64)==0){
            freeaddrinfo(res); return s;
        }
        closesocket(s);
        s = -1;
    }
    freeaddrinfo(res);
    return -1;
}

static int connect_plain(const std::string& host, int port){
    struct addrinfo hints{};
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res=nullptr; char ps[32];
    std::snprintf(ps, sizeof(ps), "%d", port);
    if(getaddrinfo(host.c_str(), ps, &hints, &res)!=0) return -1;

    int s=-1;
    for(auto* p=res; p; p=p->ai_next){
        s = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if(s<0) continue;
        if(connect(s, p->ai_addr, (socket_len_t)p->ai_addrlen)==0){ freeaddrinfo(res); return s; }
        closesocket(s);
        s = -1;
    }
    freeaddrinfo(res);
    return -1;
}

static bool send_all_plain(int fd, const unsigned char* data, int len){
    int off = 0;
    while(off < len){
        int w = (int)send(fd, (const char*)data + off, len - off, 0);
        if(w <= 0) return false;
        off += w;
    }
    return true;
}

static bool ssl_write_all(SSL* ssl, const unsigned char* data, int len){
    int off = 0;
    while(off < len){
        int w = SSL_write(ssl, data + off, len - off);
        if(w > 0){
            off += w;
            continue;
        }
        int e = SSL_get_error(ssl, w);
        if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE){
            // let caller select() again
            continue;
        }
        return false;
    }
    return true;
}

// Pump bytes in both directions until either side closes.
// Uses select() on the underlying FDs with a small timeout so stop() can join promptly.
static void proxy_bidi(SSL* ssl, int plain_fd){
    const int tls_fd = SSL_get_fd(ssl);
    std::vector<unsigned char> buf(16*1024);

    // small inactivity timeout to avoid hanging forever on half-open connections
    const int SELECT_TIMEOUT_MS = 250;

    for(;;){
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(tls_fd, &rfds);
        FD_SET(plain_fd, &rfds);

        int maxfd = (tls_fd > plain_fd) ? tls_fd : plain_fd;

        struct timeval tv;
        tv.tv_sec  = SELECT_TIMEOUT_MS / 1000;
        tv.tv_usec = (SELECT_TIMEOUT_MS % 1000) * 1000;

        int rv = select(maxfd+1, &rfds, nullptr, nullptr, &tv);
        if(rv < 0){
            // interrupted or error; tear down
            break;
        }
        if(rv == 0){
            // timeout; loop to allow stop() to be responsive
            continue;
        }

        // TLS -> plain
        if(FD_ISSET(tls_fd, &rfds)){
            int r = SSL_read(ssl, buf.data(), (int)buf.size());
            if(r <= 0){
                int e = SSL_get_error(ssl, r);
                if(e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE){
                    // try again on next select
                } else {
                    // closed or fatal
                    break;
                }
            } else {
                if(!send_all_plain(plain_fd, buf.data(), r)){
                    break;
                }
            }
        }

        // plain -> TLS
        if(FD_ISSET(plain_fd, &rfds)){
            int r = (int)recv(plain_fd, (char*)buf.data(), (int)buf.size(), 0);
            if(r <= 0){
                // peer closed or error
                break;
            }
            if(!ssl_write_all(ssl, buf.data(), r)){
                break;
            }
        }
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
        try {
            SSL_library_init();
            SSL_load_error_strings();
            const SSL_METHOD* method = TLS_server_method();
            SSL_CTX* ctx = SSL_CTX_new(method);
            if(!ctx){
                log_error("TLS: SSL_CTX_new failed");
                return;
            }

            // Harden context a bit
#ifdef TLS1_2_VERSION
            SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
#endif
            SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS | SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
            SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);

            if(SSL_CTX_use_certificate_chain_file(ctx, cert_.c_str())<=0){
                log_error("TLS: failed to load certificate chain");
                SSL_CTX_free(ctx); return;
            }
            if(SSL_CTX_use_PrivateKey_file(ctx, key_.c_str(), SSL_FILETYPE_PEM)<=0){
                log_error("TLS: failed to load private key");
                SSL_CTX_free(ctx); return;
            }
            if(!ca_.empty()){
                if(SSL_CTX_load_verify_locations(ctx, ca_.c_str(), nullptr)<=0){
                    log_error("TLS: failed to load CA file");
                    SSL_CTX_free(ctx); return;
                }
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
            }

            int ls = make_listener(bind_host_, bind_port_);
            if(ls<0){
                log_error("TLS: listen failed");
                SSL_CTX_free(ctx); return;
            }
            log_info(std::string("TLS proxy listening on ") + (bind_host_.empty()?"0.0.0.0":bind_host_) + ":" + std::to_string(bind_port_)
                     + " -> " + fwd_host_ + ":" + std::to_string(fwd_port_));

            // Use select() around accept to allow responsive shutdown.
            while(run_.load()){
                fd_set rfds;
                FD_ZERO(&rfds);
                FD_SET(ls, &rfds);
                struct timeval tv{0, 250*1000}; // 250ms
                int rv = select(ls+1, &rfds, nullptr, nullptr, &tv);
                if(rv <= 0){
                    // timeout or interrupted; loop again (check run_)
                    continue;
                }

                sockaddr_storage ss{}; socket_len_t slen=(socket_len_t)sizeof(ss);
                int cs = (int)accept(ls, (sockaddr*)&ss, &slen);
                if(cs<0) continue;

                // For each client, handle in its own detached thread so accept loop isn't blocked.
                std::thread([this, ctx, cs](){
                    SSL* ssl = SSL_new(ctx);
                    if(!ssl){
                        log_error("TLS: SSL_new failed");
                        closesocket(cs);
                        return;
                    }
                    SSL_set_fd(ssl, cs);
                    if(SSL_accept(ssl)<=0){
                        log_warn("TLS: SSL_accept failed");
                        SSL_free(ssl);
                        closesocket(cs);
                        return;
                    }

                    // Connect to the upstream plain RPC
                    int plain = connect_plain(fwd_host_.empty() ? std::string("127.0.0.1") : fwd_host_, fwd_port_);
                    if(plain<0){
                        log_warn("TLS: upstream connect failed");
                        SSL_shutdown(ssl);
                        SSL_free(ssl);
                        closesocket(cs);
                        return;
                    }

                    // Bidirectional relay until one side closes
                    proxy_bidi(ssl, plain);

                    // Cleanup this client
                    closesocket(plain);
                    SSL_shutdown(ssl);
                    SSL_free(ssl);
                    closesocket(cs);
                }).detach();
            }

            closesocket(ls);
            SSL_CTX_free(ctx);
        } catch (const std::exception& e) {
            log_error(std::string("TLS proxy thread exception: ") + e.what());
        } catch (...) {
            log_error("TLS proxy thread exception (unknown)");
        }
    });
    return true;
}

void TlsProxy::stop(){
    if(!run_.load()) return;
    run_ = false;
    if(th_.joinable()) th_.join();
}
