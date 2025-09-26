#include "p2p.h"
#include "log.h"
#include "netmsg.h"
#include "serialize.h"
#include "chain.h"
#include "constants.h"

#include <chrono>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <vector>
#include <unordered_set>

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

// NEW: gentle timeouts
#ifndef MIQ_P2P_VERACK_TIMEOUT_MS
#define MIQ_P2P_VERACK_TIMEOUT_MS 10000
#endif
#ifndef MIQ_P2P_PING_EVERY_MS
#define MIQ_P2P_PING_EVERY_MS     30000
#endif
#ifndef MIQ_P2P_PONG_TIMEOUT_MS
#define MIQ_P2P_PONG_TIMEOUT_MS   15000
#endif
#ifndef MIQ_P2P_MAX_BANSCORE
#define MIQ_P2P_MAX_BANSCORE      100
#endif

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  #define CLOSESOCK(s) closesocket(s)
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <arpa/inet.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <poll.h>
  #define CLOSESOCK(s) close(s)
#endif

namespace miq {

static int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

static int create_server(uint16_t port){
#ifdef _WIN32
    int s = (int)socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
#else
    int s = (int)socket(AF_INET, SOCK_STREAM, 0);
#endif
    if (s < 0) return -1;
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_ANY); a.sin_port = htons(port);
    int yes = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*)&yes, sizeof(yes));
    if (bind(s, (sockaddr*)&a, sizeof(a)) != 0) { CLOSESOCK(s); return -1; }
    if (listen(s, SOMAXCONN) != 0) { CLOSESOCK(s); return -1; }
    return s;
}

P2P::P2P(Chain& c) : chain_(c) {}
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

bool P2P::start(uint16_t port){
    if (running_) return true;
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    load_bans();
    srv_ = create_server(port);
    if (srv_ < 0) { log_error("P2P: failed to create server"); return false; }
    running_ = true;
    th_ = std::thread([this]{ loop(); });
    return true;
}

void P2P::stop(){
    if (!running_) return;
    running_ = false;
    if (srv_ >= 0) { CLOSESOCK(srv_); srv_ = -1; }
    for (auto& kv : peers_) { if (kv.first >= 0) CLOSESOCK(kv.first); }
    peers_.clear();
    if (th_.joinable()) th_.join();
#ifdef _WIN32
    WSACleanup();
#endif
    save_bans();
}

bool P2P::connect_seed(const std::string& host, uint16_t port){
#ifdef _WIN32
    ADDRINFOA hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    PADDRINFOA res = nullptr;
    char portstr[16]; sprintf_s(portstr, "%u", (unsigned)port);
    int rc = getaddrinfo(host.c_str(), portstr, &hints, &res);
    if (rc != 0 || !res) { log_warn("P2P: DNS resolve failed: " + host); return false; }
    int s = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { freeaddrinfo(res); return false; }
    if (connect(s, res->ai_addr, (int)res->ai_addrlen) != 0) { CLOSESOCK(s); freeaddrinfo(res); return false; }
    freeaddrinfo(res);
#else
    addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    char portstr[16]; snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    if (getaddrinfo(host.c_str(), portstr, &hints, &res) != 0 || !res) { log_warn(std::string("P2P: DNS resolve failed: ") + host); return false; }
    int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) { freeaddrinfo(res); return false; }
    if (connect(s, res->ai_addr, res->ai_addrlen) != 0) { CLOSESOCK(s); freeaddrinfo(res); return false; }
    freeaddrinfo(res);
#endif
    char ipbuf[64] = {0};
    sockaddr_in a{};
#ifdef _WIN32
    int alen = (int)sizeof(a);
#else
    socklen_t alen = static_cast<socklen_t>(sizeof(a));
#endif
    if (getpeername(s, (sockaddr*)&a, &alen) == 0) {
#ifdef _WIN32
        InetNtopA(AF_INET, &a.sin_addr, ipbuf, (int)sizeof(ipbuf));
#else
        inet_ntop(AF_INET, &a.sin_addr, ipbuf, (socklen_t)sizeof(ipbuf));
#endif
    }
    peers_[s] = PeerState{s, ipbuf[0] ? std::string(ipbuf) : std::string("unknown"), 0, now_ms()};
    log_info("P2P: connected seed " + peers_[s].ip);

    // Kick off handshake for outbound too
    auto msg = encode_msg("version", {});
    send(s, (const char*)msg.data(), (int)msg.size(), 0);

    return true;
}

void P2P::handle_new_peer(int c, const std::string& ip){
    peers_[c] = PeerState{c, ip, 0, now_ms()};
    log_info("P2P: inbound peer " + ip);
    auto msg = encode_msg("version", {});
    send(c, (const char*)msg.data(), (int)msg.size(), 0);
}

void P2P::broadcast_inv_block(const std::vector<uint8_t>& h){
    auto msg = encode_msg("invb", h);
    for (auto& kv : peers_) {
        int s = kv.first;
        send(s, (const char*)msg.data(), (int)msg.size(), 0);
    }
}

// =================== helpers for sync / serving ===================

void P2P::start_sync_with_peer(PeerState& ps){
    ps.syncing = true;
    ps.next_index = chain_.height() + 1;
    request_block_index(ps, ps.next_index);
}

void P2P::request_block_index(PeerState& ps, uint64_t index){
    uint8_t p[8];
    for (int i=0;i<8;i++) p[i] = (uint8_t)((index >> (8*i)) & 0xFF);
    auto msg = encode_msg("getbi", std::vector<uint8_t>(p, p+8));
    send(ps.sock, (const char*)msg.data(), (int)msg.size(), 0);
}

void P2P::request_block_hash(PeerState& ps, const std::vector<uint8_t>& h){
    if (h.size()!=32) return;
    auto msg = encode_msg("getb", h);
    send(ps.sock, (const char*)msg.data(), (int)msg.size(), 0);
}

void P2P::send_block(int s, const std::vector<uint8_t>& raw){
    if (raw.empty()) return;
    auto msg = encode_msg("block", raw);
    send(s, (const char*)msg.data(), (int)msg.size(), 0);
}

// ========================================================================

void P2P::loop(){
#ifdef _WIN32
    using PollFD = WSAPOLLFD;
    auto POLL_RD = POLLRDNORM;
#else
    using PollFD = pollfd;
    auto POLL_RD = POLLIN;
#endif

    while (running_) {
        std::vector<PollFD> fds;
        size_t base = 0;
#ifdef _WIN32
        if (srv_ >= 0) fds.push_back(PollFD{ (SOCKET)srv_, POLL_RD, 0 });
#else
        if (srv_ >= 0) fds.push_back(PollFD{ srv_, POLL_RD, 0 });
#endif
        base = fds.size();
        for (auto& kv : peers_) {
#ifdef _WIN32
            fds.push_back(PollFD{ (SOCKET)kv.first, POLL_RD, 0 });
#else
            fds.push_back(PollFD{ kv.first, POLL_RD, 0 });
#endif
        }

#ifdef _WIN32
        int rc = WSAPoll(fds.data(), (ULONG)fds.size(), 200);
#else
        int rc = poll(fds.data(), fds.size(), 200);
#endif
        if (rc < 0) continue;

        // Accept new peers
        if (srv_ >= 0) {
#ifdef _WIN32
            if (fds[0].revents & POLLRDNORM) {
#else
            if (fds[0].revents & POLLIN) {
#endif
                sockaddr_in ca{}; socklen_t clen = sizeof(ca);
                int c = (int)accept(srv_, (sockaddr*)&ca, &clen);
                if (c >= 0) {
                    char ipbuf[64] = {0};
#ifdef _WIN32
                    InetNtopA(AF_INET, &ca.sin_addr, ipbuf, (int)sizeof(ipbuf));
#else
                    inet_ntop(AF_INET, &ca.sin_addr, ipbuf, (socklen_t)sizeof(ipbuf));
#endif
                    if (banned_.count(ipbuf)) { CLOSESOCK(c); }
                    else handle_new_peer(c, ipbuf);
                }
            }
        }

        // Read/process peers
        std::vector<int> dead;
        size_t p = 0;
        for (auto it = peers_.begin(); it != peers_.end(); ++it, ++p) {
            int s = it->first;
            auto &ps = it->second;

            // readiness?
            if (!(fds[base + p].revents & (POLL_RD))) goto timers;

            // recv
            uint8_t buf[65536];
#ifdef _WIN32
            int n = recv(s, (char*)buf, (int)sizeof(buf), 0);
#else
            ssize_t n = recv(s, (char*)buf, sizeof(buf), 0);
#endif
            if (n <= 0) { dead.push_back(s); continue; }
            ps.last_ms = now_ms();

            ps.rx.insert(ps.rx.end(), buf, buf + n);
            if (ps.rx.size() > MIQ_P2P_MAX_BUFSZ) {
                log_warn("P2P: oversize buffer from " + ps.ip + " -> banning & dropping");
                banned_.insert(ps.ip);
                dead.push_back(s);
                continue;
            }

            // parse all messages
            size_t off = 0;
            miq::NetMsg m;
            while (decode_msg(ps.rx, off, m)) {
                std::string cmd(m.cmd, m.cmd + 12);
                cmd.erase(cmd.find_first_of('\0'));

                if (cmd == "version") {
                    auto verack = encode_msg("verack", {});
                    send(s, (const char*)verack.data(), (int)verack.size(), 0);

                } else if (cmd == "verack") {
                    ps.verack_ok = true;
                    ps.syncing = true;
                    ps.next_index = chain_.height() + 1;
                    request_block_index(ps, ps.next_index);

                } else if (cmd == "ping") {
                    auto pong = encode_msg("pong", m.payload);
                    send(s, (const char*)pong.data(), (int)pong.size(), 0);

                } else if (cmd == "pong") {
                    ps.awaiting_pong = false;

                } else if (cmd == "invb") {
                    if (m.payload.size() == 32) {
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
                    if (m.payload.size() > 0 && m.payload.size() <= MIQ_FALLBACK_MAX_BLOCK_SZ) {
                        Block b;
                        if (deser_block(m.payload, b)) {
                            std::string err;
                            if (!chain_.have_block(b.block_hash())) {
                                if (chain_.submit_block(b, err)) {
                                    log_info("P2P: accepted block via peer " + ps.ip);
                                    if (ps.syncing) {
                                        ps.next_index++;
                                        request_block_index(ps, ps.next_index);
                                    }
                                    broadcast_inv_block(b.block_hash());
                                } else {
                                    log_warn("P2P: reject block (" + err + ")");
                                    ps.syncing = false;
                                }
                            }
                        }
                    }
                } else {
                    // unknown -> small mis score
                    if (++ps.mis > 10) { dead.push_back(s); }
                }
            }
            // drop consumed prefix
            if (off > 0) {
                std::vector<uint8_t> rest(ps.rx.begin() + off, ps.rx.end());
                ps.rx.swap(rest);
            }

        timers:
            // --- timeouts / pings ---
            int64_t now = now_ms();
            if (!ps.verack_ok && (now - ps.last_ms) > MIQ_P2P_VERACK_TIMEOUT_MS) {
                dead.push_back(s);
                continue;
            }
            if (!ps.awaiting_pong && (now - ps.last_ping_ms) > MIQ_P2P_PING_EVERY_MS) {
                auto ping = encode_msg("ping", {});
                send(s, (const char*)ping.data(), (int)ping.size(), 0);
                ps.last_ping_ms = now;
                ps.awaiting_pong = true;
            } else if (ps.awaiting_pong && (now - ps.last_ping_ms) > MIQ_P2P_PONG_TIMEOUT_MS) {
                if ((ps.banscore += 20) >= MIQ_P2P_MAX_BANSCORE) banned_.insert(ps.ip);
                dead.push_back(s);
            }
        }

        for (int s : dead) { CLOSESOCK(s); peers_.erase(s); }
    }
    save_bans();
}

} // namespace miq
