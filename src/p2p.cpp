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

// timeouts
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

// --- rate limits (bytes/sec) and burst caps ---
#ifndef MIQ_RATE_BLOCK_BPS
#define MIQ_RATE_BLOCK_BPS (1024u * 1024u)   // 1 MB/s per peer for blocks
#endif
#ifndef MIQ_RATE_TX_BPS
#define MIQ_RATE_TX_BPS    (256u * 1024u)    // 256 KB/s per peer for txs
#endif
#ifndef MIQ_RATE_BLOCK_BURST
#define MIQ_RATE_BLOCK_BURST (MIQ_RATE_BLOCK_BPS * 2u) // 2s burst
#endif
#ifndef MIQ_RATE_TX_BURST
#define MIQ_RATE_TX_BURST    (MIQ_RATE_TX_BPS * 2u)
#endif

// --- addr filtering knobs ---
#ifndef MIQ_ADDR_MAX_BATCH
#define MIQ_ADDR_MAX_BATCH 1000
#endif
#ifndef MIQ_ADDR_MIN_INTERVAL_MS
#define MIQ_ADDR_MIN_INTERVAL_MS 120000  // 2 minutes between accepted batches per peer
#endif
#ifndef MIQ_ADDR_RESPONSE_MAX
#define MIQ_ADDR_RESPONSE_MAX 200        // max addrs we return to getaddr
#endif

// Orphan pool caps (can be overridden at compile time)
#ifndef MIQ_ORPHAN_MAX_BYTES
#define MIQ_ORPHAN_MAX_BYTES (32u * 1024u * 1024u)
#endif
#ifndef MIQ_ORPHAN_MAX_COUNT
#define MIQ_ORPHAN_MAX_COUNT (4096u)
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

// tiny, local and fast hex for keys
std::string P2P::hexkey(const std::vector<uint8_t>& h) {
    static const char* kHex = "0123456789abcdef";
    std::string s; s.resize(h.size()*2);
    for (size_t i=0;i<h.size();++i) {
        s[2*i+0] = kHex[(h[i]>>4) & 0xF];
        s[2*i+1] = kHex[(h[i]    ) & 0xF];
    }
    return s;
}

// IPv4 helpers
bool P2P::parse_ipv4(const std::string& dotted, uint32_t& be_ip){
    sockaddr_in tmp{};
#ifdef _WIN32
    if (InetPtonA(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#else
    if (inet_pton(AF_INET, dotted.c_str(), &tmp.sin_addr) != 1) return false;
#endif
    be_ip = tmp.sin_addr.s_addr; // already network byte order
    return true;
}
static inline uint32_t be(uint8_t a, uint8_t b, uint8_t c, uint8_t d){
    return (uint32_t(a)<<24)|(uint32_t(b)<<16)|(uint32_t(c)<<8)|uint32_t(d);
}
bool P2P::ipv4_is_public(uint32_t be_ip){
    // drop: 0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16, 224/4 (multicast), 240/4 (reserved)
    uint8_t A = uint8_t(be_ip>>24), B = uint8_t(be_ip>>16);
    if (A == 0 || A == 10 || A == 127) return false;
    if (A == 169 && B == 254) return false;
    if (A == 192 && B == 168) return false;
    if (A == 172 && (uint8_t(be_ip>>20) & 0x0F) >= 1 && (uint8_t(be_ip>>20) & 0x0F) <= 15) return false; // 172.16/12
    if (A >= 224) return false;
    return true;
}

P2P::P2P(Chain& c) : chain_(c) {
    orphan_bytes_limit_ = (size_t)MIQ_ORPHAN_MAX_BYTES;
    orphan_count_limit_ = (size_t)MIQ_ORPHAN_MAX_COUNT;
}
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
    // init RL buckets
    peers_[s].blk_tokens = MIQ_RATE_BLOCK_BURST;
    peers_[s].tx_tokens  = MIQ_RATE_TX_BURST;
    peers_[s].last_refill_ms = now_ms();

    // add addr if public
    uint32_t be_ip;
    if (ipbuf[0] && parse_ipv4(ipbuf, be_ip) && ipv4_is_public(be_ip)) addrv4_.insert(be_ip);

    log_info("P2P: connected seed " + peers_[s].ip);

    // Kick off handshake for outbound too
    auto msg = encode_msg("version", {});
    send(s, (const char*)msg.data(), (int)msg.size(), 0);

    return true;
}

void P2P::handle_new_peer(int c, const std::string& ip){
    peers_[c] = PeerState{c, ip, 0, now_ms()};
    peers_[c].blk_tokens = MIQ_RATE_BLOCK_BURST;
    peers_[c].tx_tokens  = MIQ_RATE_TX_BURST;
    peers_[c].last_refill_ms = now_ms();

    // learn addr
    uint32_t be_ip;
    if (parse_ipv4(ip, be_ip) && ipv4_is_public(be_ip)) addrv4_.insert(be_ip);

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

// === rate-limit helpers ======================================================

void P2P::rate_refill(PeerState& ps, int64_t now){
    int64_t dt = now - ps.last_refill_ms;
    if (dt <= 0) return;
    uint64_t add_blk = (uint64_t)((MIQ_RATE_BLOCK_BPS * (uint64_t)dt) / 1000ull);
    uint64_t add_tx  = (uint64_t)((MIQ_RATE_TX_BPS    * (uint64_t)dt) / 1000ull);
    ps.blk_tokens = std::min<uint64_t>(MIQ_RATE_BLOCK_BURST, ps.blk_tokens + add_blk);
    ps.tx_tokens  = std::min<uint64_t>(MIQ_RATE_TX_BURST,   ps.tx_tokens  + add_tx);
    ps.last_refill_ms = now;
}
bool P2P::rate_consume_block(PeerState& ps, size_t nbytes){
    int64_t n = now_ms();
    rate_refill(ps, n);
    if (ps.blk_tokens < nbytes) return false;
    ps.blk_tokens -= (uint64_t)nbytes;
    return true;
}
bool P2P::rate_consume_tx(PeerState& ps, size_t nbytes){
    int64_t n = now_ms();
    rate_refill(ps, n);
    if (ps.tx_tokens < nbytes) return false;
    ps.tx_tokens -= (uint64_t)nbytes;
    return true;
}

// === addr handling ===========================================================

void P2P::maybe_send_getaddr(PeerState& ps){
    auto msg = encode_msg("getaddr", {});
    send(ps.sock, (const char*)msg.data(), (int)msg.size(), 0);
}

void P2P::send_addr_snapshot(PeerState& ps){
    std::vector<uint8_t> payload;
    payload.reserve(MIQ_ADDR_RESPONSE_MAX * 4);
    size_t cnt = 0;
    for (uint32_t be_ip : addrv4_) {
        if (cnt >= MIQ_ADDR_RESPONSE_MAX) break;
        if (!ipv4_is_public(be_ip)) continue;
        payload.push_back((uint8_t)(be_ip >> 24));
        payload.push_back((uint8_t)(be_ip >> 16));
        payload.push_back((uint8_t)(be_ip >> 8));
        payload.push_back((uint8_t)(be_ip >> 0));
        ++cnt;
    }
    auto msg = encode_msg("addr", payload);
    send(ps.sock, (const char*)msg.data(), (int)msg.size(), 0);
}

void P2P::handle_addr_msg(PeerState& ps, const std::vector<uint8_t>& payload){
    int64_t t = now_ms();
    if (t - ps.last_addr_ms < MIQ_ADDR_MIN_INTERVAL_MS) {
        if (++ps.mis > 20) { banned_.insert(ps.ip); }
        return;
    }
    ps.last_addr_ms = t;

    if (payload.size() % 4 != 0) return;
    size_t n = payload.size() / 4;
    if (n > MIQ_ADDR_MAX_BATCH) n = MIQ_ADDR_MAX_BATCH;

    size_t accepted = 0;
    for (size_t i=0;i<n;i++){
        uint32_t be_ip =
            (uint32_t(payload[4*i+0])<<24) |
            (uint32_t(payload[4*i+1])<<16) |
            (uint32_t(payload[4*i+2])<<8 ) |
            (uint32_t(payload[4*i+3])<<0 );
        if (!ipv4_is_public(be_ip)) continue;
        addrv4_.insert(be_ip);
        ++accepted;
    }
    if (accepted == 0) {
        if (++ps.mis > 30) banned_.insert(ps.ip);
    }
}

// =================== Orphan manager =========================================

void P2P::evict_orphans_if_needed(){
    while ( (orphan_bytes_ > orphan_bytes_limit_) ||
            (orphans_.size() > orphan_count_limit_) ) {
        if (orphan_order_.empty()) break;
        const std::string victim = orphan_order_.front();
        orphan_order_.pop_front();

        auto it = orphans_.find(victim);
        if (it == orphans_.end()) continue;

        const std::string parent_hex = hexkey(it->second.prev);
        orphan_bytes_ -= it->second.raw.size();
        orphans_.erase(it);

        auto pit = orphan_children_.find(parent_hex);
        if (pit != orphan_children_.end()){
            auto& vec = pit->second;
            vec.erase(std::remove(vec.begin(), vec.end(), victim), vec.end());
            if (vec.empty()) orphan_children_.erase(pit);
        }
        log_warn("P2P: evicted orphan " + victim);
    }
}

void P2P::remove_orphan_by_hex(const std::string& child_hex){
    auto it = orphans_.find(child_hex);
    if (it == orphans_.end()) return;
    const std::string parent_hex = hexkey(it->second.prev);
    if (orphan_bytes_ >= it->second.raw.size())
        orphan_bytes_ -= it->second.raw.size();
    else
        orphan_bytes_ = 0;

    orphans_.erase(it);

    auto pit = orphan_children_.find(parent_hex);
    if (pit != orphan_children_.end()){
        auto& vec = pit->second;
        vec.erase(std::remove(vec.begin(), vec.end(), child_hex), vec.end());
        if (vec.empty()) orphan_children_.erase(pit);
    }

    auto dit = std::find(orphan_order_.begin(), orphan_order_.end(), child_hex);
    if (dit != orphan_order_.end()) orphan_order_.erase(dit);
}

void P2P::handle_incoming_block(int sock, const std::vector<uint8_t>& raw){
    if (raw.empty() || raw.size() > MIQ_FALLBACK_MAX_BLOCK_SZ) return;

    Block b;
    if (!deser_block(raw, b)) return;

    const auto bh = b.block_hash();
    if (chain_.have_block(bh)) return;

    // parent present?
    bool have_parent = chain_.have_block(b.header.prev_hash);

    if (!have_parent) {
        OrphanRec rec{ bh, b.header.prev_hash, raw };
        const std::string child_hex  = hexkey(bh);
        const std::string parent_hex = hexkey(b.header.prev_hash);

        if (orphans_.find(child_hex) == orphans_.end()) {
            orphans_.emplace(child_hex, std::move(rec));
            orphan_children_[parent_hex].push_back(child_hex);
            orphan_order_.push_back(child_hex);
            orphan_bytes_ += raw.size();
            evict_orphans_if_needed();
            log_info("P2P: stored orphan block child=" + child_hex + " parent=" + parent_hex);
        }

        auto pit = peers_.find(sock);
        if (pit != peers_.end()) {
            request_block_hash(pit->second, b.header.prev_hash);
        }
        return;
    }

    std::string err;
    if (chain_.submit_block(b, err)) {
        log_info("P2P: accepted block (child of known parent)");
        broadcast_inv_block(bh);
        try_connect_orphans(hexkey(bh));
    } else {
        log_warn("P2P: reject block (" + err + ")");
    }
}

void P2P::try_connect_orphans(const std::string& parent_hex){
    std::vector<std::string> q;
    auto it = orphan_children_.find(parent_hex);
    if (it != orphan_children_.end()) {
        q.assign(it->second.begin(), it->second.end());
        orphan_children_.erase(it);
    }

    while (!q.empty()){
        std::string child_hex = q.back();
        q.pop_back();

        auto oit = orphans_.find(child_hex);
        if (oit == orphans_.end()) continue;

        Block ob;
        if (!deser_block(oit->second.raw, ob)) {
            remove_orphan_by_hex(child_hex);
            continue;
        }

        if (chain_.have_block(oit->second.hash)) {
            remove_orphan_by_hex(child_hex);
            continue;
        }

        std::string err;
        if (chain_.submit_block(ob, err)) {
            broadcast_inv_block(oit->second.hash);
            const std::string new_parent_hex = child_hex;
            remove_orphan_by_hex(child_hex);

            auto cit = orphan_children_.find(new_parent_hex);
            if (cit != orphan_children_.end()) {
                for (const auto& g : cit->second) q.push_back(g);
                orphan_children_.erase(cit);
            }
        } else {
            log_warn("P2P: orphan child rejected (" + err + "), dropping orphan " + child_hex);
            remove_orphan_by_hex(child_hex);
        }
    }
}

// ============================================================================

void P2P::loop(){
#ifdef _WIN32
    using PollFD = WSAPOLLFD;
    static const short POLL_RD = POLLRDNORM;
#else
    using PollFD = pollfd;
    static const short POLL_RD = POLLIN;
#endif

    while (running_) {
        std::vector<PollFD> fds;
        size_t base = 0;
#ifdef _WIN32
        if (srv_ >= 0) fds.push_back(PollFD{ (SOCKET)srv_, (short)POLL_RD, 0 });
#else
        if (srv_ >= 0) fds.push_back(PollFD{ srv_, (short)POLL_RD, 0 });
#endif
        base = fds.size();
        for (auto& kv : peers_) {
#ifdef _WIN32
            fds.push_back(PollFD{ (SOCKET)kv.first, (short)POLL_RD, 0 });
#else
            fds.push_back(PollFD{ kv.first, (short)POLL_RD, 0 });
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

            bool ready = (fds[base + p].revents & POLL_RD) != 0;

            if (ready) {
                uint8_t buf[65536];
#ifdef _WIN32
                int n = recv(s, (char*)buf, (int)sizeof(buf), 0);
                if (n <= 0) { dead.push_back(s); goto timers_section; }
#else
                ssize_t n = recv(s, (char*)buf, sizeof(buf), 0);
                if (n <= 0) { dead.push_back(s); goto timers_section; }
#endif
                ps.last_ms = now_ms();

                ps.rx.insert(ps.rx.end(), buf, buf + n);
                if (ps.rx.size() > MIQ_P2P_MAX_BUFSZ) {
                    log_warn("P2P: oversize buffer from " + ps.ip + " -> banning & dropping");
                    banned_.insert(ps.ip);
                    dead.push_back(s);
                    goto timers_section;
                }

                // parse all messages
                {
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
                            // ask for addresses once
                            maybe_send_getaddr(ps);

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
                            // inbound block rate limiting
                            if (!rate_consume_block(ps, m.payload.size())) {
                                if ((ps.banscore += 5) >= MIQ_P2P_MAX_BANSCORE) banned_.insert(ps.ip);
                                continue;
                            }
                            if (m.payload.size() > 0 && m.payload.size() <= MIQ_FALLBACK_MAX_BLOCK_SZ) {
                                // Route through orphan-aware path
                                handle_incoming_block(s, m.payload);
                            }

                        } else if (cmd == "tx") {
                            if (!rate_consume_tx(ps, m.payload.size())) {
                                if ((ps.banscore += 3) >= MIQ_P2P_MAX_BANSCORE) banned_.insert(ps.ip);
                                continue;
                            }
                            // TX relay not wired yet.

                        } else if (cmd == "getaddr") {
                            send_addr_snapshot(ps);

                        } else if (cmd == "addr") {
                            handle_addr_msg(ps, m.payload);

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
                }
            }

        timers_section:
            // --- timeouts / pings (run regardless of readability) ---
            int64_t tnow = now_ms();
            if (!ps.verack_ok && (tnow - ps.last_ms) > MIQ_P2P_VERACK_TIMEOUT_MS) {
                dead.push_back(s);
                continue;
            }
            if (!ps.awaiting_pong && (tnow - ps.last_ping_ms) > MIQ_P2P_PING_EVERY_MS) {
                auto ping = encode_msg("ping", {});
                send(s, (const char*)ping.data(), (int)ping.size(), 0);
                ps.last_ping_ms = tnow;
                ps.awaiting_pong = true;
            } else if (ps.awaiting_pong && (tnow - ps.last_ping_ms) > MIQ_P2P_PONG_TIMEOUT_MS) {
                if ((ps.banscore += 20) >= MIQ_P2P_MAX_BANSCORE) banned_.insert(ps.ip);
                dead.push_back(s);
            }
        }

        for (int s : dead) { CLOSESOCK(s); peers_.erase(s); }
    }
    save_bans();
}

} // namespace miq
