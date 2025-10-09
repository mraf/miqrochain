#include "wallet/p2p_light.h"
#include "sha256.h"
#include "constants.h"

#include <cstring>
#include <chrono>
#include <random>
#include <sstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  static inline void closesock(int s){ closesocket(s); }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <fcntl.h>
  static inline void closesock(int s){ if(s>=0) ::close(s); }
#endif

namespace miq {

// ---- choose network magic ----------------------------------------------------
#ifndef MIQ_P2P_MAGIC
// If your repo already defines one, add it in constants.h, e.g.:
//   static constexpr uint32_t MIQ_P2P_MAGIC = 0x4d495121; // "MIQ!" little-endian
// Adjust here if needed to match daemon/netmsg.
static constexpr uint32_t MIQ_P2P_MAGIC = 0xD9B4BEF9; // Bitcoin mainnet style fallback
#endif

// ---- varint / varstr ---------------------------------------------------------
static void put_u32_le(std::vector<uint8_t>& b, uint32_t v){
    b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8));
    b.push_back(uint8_t(v>>16)); b.push_back(uint8_t(v>>24));
}
static void put_u64_le(std::vector<uint8_t>& b, uint64_t v){
    for(int i=0;i<8;i++) b.push_back(uint8_t(v>>(8*i)));
}
static void put_i64_le(std::vector<uint8_t>& b, int64_t v){
    put_u64_le(b, (uint64_t)v);
}
static void put_u16_be(std::vector<uint8_t>& b, uint16_t v){ // network byte-order port
    b.push_back(uint8_t(v>>8)); b.push_back(uint8_t(v));
}
static void put_varint(std::vector<uint8_t>& b, uint64_t v){
    if (v < 0xFD) { b.push_back(uint8_t(v)); }
    else if (v <= 0xFFFF) { b.push_back(0xFD); b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8)); }
    else if (v <= 0xFFFFFFFFULL) { b.push_back(0xFE); put_u32_le(b, (uint32_t)v); }
    else { b.push_back(0xFF); put_u64_le(b, v); }
}
static void put_varstr(std::vector<uint8_t>& b, const std::string& s){
    put_varint(b, s.size());
    b.insert(b.end(), s.begin(), s.end());
}

// ---- checksum ----------------------------------------------------------------
static uint32_t checksum4(const std::vector<uint8_t>& payload){
    auto d = dsha256(payload);
    return (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
}

// ---- P2PLight ----------------------------------------------------------------
P2PLight::P2PLight(){}
P2PLight::~P2PLight(){ close(); }

bool P2PLight::connect_and_handshake(const P2POpts& opts, std::string& err){
    o_ = opts;

#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res=nullptr;
    if (getaddrinfo(o_.host.c_str(), o_.port.c_str(), &hints, &res) != 0) {
        err = "getaddrinfo failed";
        return false;
    }
    int fd = -1; addrinfo* rp=res;
    for (; rp; rp = rp->ai_next) {
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
        closesock(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { err = "connect failed"; return false; }
    sock_ = fd;

    if(!send_version(err)) { close(); return false; }
    if(!read_until_verack(err)) { close(); return false; }

    std::string e2;
    (void)send_getaddr(e2); // best-effort

    return true;
}

bool P2PLight::send_tx(const std::vector<uint8_t>& tx_bytes, std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }
    return send_msg("tx", tx_bytes, err);
}

bool P2PLight::send_getaddr(std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }
    std::vector<uint8_t> empty;
    return send_msg("getaddr", empty, err);
}

void P2PLight::close(){
    if (sock_ >= 0){ closesock(sock_); sock_ = -1; }
#ifdef _WIN32
    WSACleanup();
#endif
}

// ---- internals ---------------------------------------------------------------
bool P2PLight::send_version(std::string& err){
    // Build "version" payload (Bitcoin-like)
    std::vector<uint8_t> p;

    const int32_t  version   = 70015;
    const uint64_t services  = 0;
    const int64_t  timestamp = (int64_t) (std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1));

    // remote addr (ignored by most)
    const uint64_t srv_recv = 0;
    uint8_t ip_zero[16]{}; // ::0
    const uint16_t port_recv = 9833;

    // local addr
    const uint64_t srv_from = 0;
    const uint16_t port_from = 0;

    // random nonce
    std::mt19937_64 rng{std::random_device{}()};
    uint64_t nonce = rng();

    // version
    put_u32_le(p, (uint32_t)version);
    put_u64_le(p, services);
    put_i64_le(p, timestamp);

    put_u64_le(p, srv_recv);
    p.insert(p.end(), ip_zero, ip_zero+16);
    put_u16_be(p, port_recv);

    put_u64_le(p, srv_from);
    p.insert(p.end(), ip_zero, ip_zero+16);
    put_u16_be(p, port_from);

    put_u64_le(p, nonce);
    put_varstr(p, o_.user_agent);
    put_u32_le(p, o_.start_height);
    p.push_back(1); // relay = true

    if(!send_msg("version", p, err)) return false;

    if(o_.send_verack){
        std::vector<uint8_t> empty;
        if(!send_msg("verack", empty, err)) return false;
    }
    return true;
}

bool P2PLight::read_until_verack(std::string& err){
    // Read a few messages, stop when we see verack.
    for (int i=0;i<20;i++){
        std::string cmd; uint32_t len=0, csum=0;
        if(!read_msg_header(cmd, len, csum, err)) return false;

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd=="verack") return true;
        // Ignore other messages in handshake window
    }
    err = "no verack from peer";
    return false;
}

bool P2PLight::send_msg(const char cmd12[12], const std::vector<uint8_t>& payload, std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }

    uint8_t header[24]{};
    // magic
    uint32_t m = MIQ_P2P_MAGIC;
    header[0]=uint8_t(m); header[1]=uint8_t(m>>8); header[2]=uint8_t(m>>16); header[3]=uint8_t(m>>24);

    // command (null-padded to 12)
    for (int i=0;i<12 && cmd12[i]; ++i) header[4+i] = (uint8_t)cmd12[i];

    // length
    uint32_t L = (uint32_t)payload.size();
    header[16]=uint8_t(L); header[17]=uint8_t(L>>8); header[18]=uint8_t(L>>16); header[19]=uint8_t(L>>24);

    // checksum
    uint32_t c = checksum4(payload);
    header[20]=uint8_t(c); header[21]=uint8_t(c>>8); header[22]=uint8_t(c>>16); header[23]=uint8_t(c>>24);

    if(!write_all(header, sizeof(header), err)) return false;
    if(L>0 && !write_all(payload.data(), payload.size(), err)) return false;
    return true;
}

bool P2PLight::read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, std::string& err){
    uint8_t h[24];
    if(!read_exact(h, 24, err)) return false;

    uint32_t m = (uint32_t)h[0] | ((uint32_t)h[1]<<8) | ((uint32_t)h[2]<<16) | ((uint32_t)h[3]<<24);
    if(m != MIQ_P2P_MAGIC){ err = "bad magic"; return false; }

    char cmd[13]; std::memset(cmd, 0, sizeof(cmd));
    std::memcpy(cmd, h+4, 12);
    cmd_out = std::string(cmd);

    len_out  = (uint32_t)h[16] | ((uint32_t)h[17]<<8) | ((uint32_t)h[18]<<16) | ((uint32_t)h[19]<<24);
    csum_out = (uint32_t)h[20] | ((uint32_t)h[21]<<8) | ((uint32_t)h[22]<<16) | ((uint32_t)h[23]<<24);
    return true;
}

bool P2PLight::read_exact(void* buf, size_t len, std::string& err){
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len){
#ifdef _WIN32
        int n = recv(sock_, (char*)p + got, (int)(len - got), 0);
#else
        ssize_t n = recv(sock_, p + got, len - got, 0);
#endif
        if (n <= 0) { err = "recv failed"; return false; }
        got += (size_t)n;
    }
    return true;
}

bool P2PLight::write_all(const void* buf, size_t len, std::string& err){
    const uint8_t* p = (const uint8_t*)buf;
    size_t sent = 0;
    while (sent < len){
#ifdef _WIN32
        int n = send(sock_, (const char*)p + sent, (int)(len - sent), 0);
#else
        ssize_t n = send(sock_, p + sent, len - sent, 0);
#endif
        if (n <= 0) { err = "send failed"; return false; }
        sent += (size_t)n;
    }
    return true;
}

}
