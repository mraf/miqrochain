// src/wallet/p2p_light.cpp
#include "wallet/p2p_light.h"
#include "sha256.h"
#include "constants.h"

#include <cstring>
#include <chrono>
#include <random>
#include <vector>
#include <algorithm>

#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  static inline void closesock(int s){ closesocket(s); }
  static inline void set_timeouts(int s, int ms){
      if(ms <= 0) return;
      DWORD t = (DWORD)ms;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
  }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <sys/time.h>
  static inline void closesock(int s){ if(s>=0) ::close(s); }
  static inline void set_timeouts(int s, int ms){
      if(ms <= 0) return;
      timeval tv{};
      tv.tv_sec  = ms / 1000;
      tv.tv_usec = (ms % 1000) * 1000;
      setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
      setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
  }
#endif

namespace miq {

// ---- network magic from chain constants --------------------------------------
#ifndef MIQ_P2P_MAGIC
static constexpr uint32_t MIQ_P2P_MAGIC =
    (uint32_t(MAGIC_BE[0])      ) |
    (uint32_t(MAGIC_BE[1]) <<  8) |
    (uint32_t(MAGIC_BE[2]) << 16) |
    (uint32_t(MAGIC_BE[3]) << 24);
#endif

// ---- helpers -----------------------------------------------------------------
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
static void put_u16_be(std::vector<uint8_t>& b, uint16_t v){ // network order port
    b.push_back(uint8_t(v>>8)); b.push_back(uint8_t(v));
}
static void put_varint(std::vector<uint8_t>& b, uint64_t v){
    if (v < 0xFD) { b.push_back(uint8_t(v)); }
    else if (v <= 0xFFFF) { b.push_back(0xFD); b.push_back(uint8_t(v)); b.push_back(uint8_t(v>>8)); }
    else if (v <= 0xFFFFFFFFULL) { b.push_back(0xFE); put_u32_le(b, (uint32_t)v); }
    else { b.push_back(0xFF); put_u64_le(b, v); }
}
static bool get_varint(const uint8_t* p, size_t n, uint64_t& v, size_t& used){
    if(n==0) return false;
    uint8_t x = p[0]; used = 1;
    if(x < 0xFD){ v = x; return true; }
    if(x == 0xFD){ if(n<3) return false; v = (uint64_t)p[1] | ((uint64_t)p[2]<<8); used = 3; return true; }
    if(x == 0xFE){ if(n<5) return false; v = (uint64_t)p[1] | ((uint64_t)p[2]<<8) | ((uint64_t)p[3]<<16) | ((uint64_t)p[4]<<24); used = 5; return true; }
    if(x == 0xFF){ if(n<9) return false; uint64_t r=0; for(int i=0;i<8;i++) r |= ((uint64_t)p[1+i]<<(8*i)); v=r; used=9; return true; }
    return false;
}
static std::vector<uint8_t> dsha256_bytes(const uint8_t* data, size_t len){
    std::vector<uint8_t> v(data, data+len);
    return dsha256(v);
}
static std::vector<uint8_t> to_le32(const std::vector<uint8_t>& h){
    std::vector<uint8_t> r = h; std::reverse(r.begin(), r.end()); return r;
}
static uint32_t checksum4(const std::vector<uint8_t>& payload){
    auto d = dsha256(payload);
    return (uint32_t)d[0] | ((uint32_t)d[1]<<8) | ((uint32_t)d[2]<<16) | ((uint32_t)d[3]<<24);
}

// ---- class -------------------------------------------------------------------
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
    int fd = -1;
    for (auto rp = res; rp; rp = rp->ai_next) {
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        set_timeouts(fd, o_.io_timeout_ms);
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

    header_hashes_le_.clear();
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

// ---- headers sync ------------------------------------------------------------
bool P2PLight::get_best_header(uint32_t& tip_height, std::vector<uint8_t>& tip_hash_le, std::string& err){
    tip_height = 0; tip_hash_le.clear();
    if (sock_ < 0){ err = "not connected"; return false; }

    // Cached?
    if(!header_hashes_le_.empty()){
        tip_height = (uint32_t)(header_hashes_le_.size() - 1);
        tip_hash_le = header_hashes_le_.back();
        return true;
    }

    // Start from "null" locator to get headers from genesis (daemon expects u8 count + hashes + stop).
    std::vector<std::vector<uint8_t>> locator;
    locator.emplace_back(32, 0x00);
    std::vector<uint8_t> stop(32, 0x00);

    while(true){
        if(!request_headers_from_locator(locator, stop, err)) return false;

        std::vector<std::vector<uint8_t>> batch;
        if(!read_headers_batch(batch, err)) return false;

        if(batch.empty()){
            // No more headers; at tip.
            break;
        }

        // Append
        for(auto& h : batch) header_hashes_le_.push_back(std::move(h));

        // New locator = last hash (simple)
        locator.clear();
        locator.push_back(header_hashes_le_.back());
    }

    if(header_hashes_le_.empty()){
        err = "headers sync returned none";
        return false;
    }

    tip_height = (uint32_t)(header_hashes_le_.size() - 1);
    tip_hash_le = header_hashes_le_.back();
    return true;
}

// Your daemon's getheaders: [u8 count][count*32 hashes][32 stop]
bool P2PLight::request_headers_from_locator(const std::vector<std::vector<uint8_t>>& locator_hashes_le,
                                            std::vector<uint8_t>& stop_le,
                                            std::string& err)
{
    std::vector<uint8_t> p;
    const uint8_t n = (uint8_t)std::min<size_t>(locator_hashes_le.size(), 32);
    p.push_back(n);
    for (size_t i=0;i<n;i++){
        if(locator_hashes_le[i].size()!=32){ err="bad locator hash size"; return false; }
        p.insert(p.end(), locator_hashes_le[i].begin(), locator_hashes_le[i].end());
    }
    if(stop_le.size()!=32) stop_le.assign(32, 0x00);
    p.insert(p.end(), stop_le.begin(), stop_le.end());
    return send_msg("getheaders", p, err);
}

// Accepts both daemon-style headers (u16 + count*88 bytes) and Bitcoin-style (varint + 80 + varint txcount).
bool P2PLight::read_headers_batch(std::vector<std::vector<uint8_t>>& out_hashes_le, std::string& err){
    out_hashes_le.clear();
    for(;;){
        std::string cmd; uint32_t len=0, csum=0; bool legacy=false;
        if(!read_msg_header(cmd, len, csum, legacy, err)) return false;

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd == "ping"){
            std::string e; send_msg("pong", payload, e);
            continue;
        }

        if(cmd != "headers"){
            // swallow unrelated messages (inv, addr, sendcmpct, etc.)
            continue;
        }

        // Try daemon format first: [u16 count][count * 88 bytes]
        if(payload.size() >= 2){
            uint16_t count = (uint16_t)payload[0] | ((uint16_t)payload[1] << 8);
            size_t pos = 2;
            const size_t HBYTES = 88;
            if (payload.size() == pos + (size_t)count * HBYTES){
                out_hashes_le.reserve(count);
                for (uint16_t i=0;i<count;i++){
                    const uint8_t* hdr = payload.data()+pos;
                    auto h  = dsha256_bytes(hdr, HBYTES);
                    auto hl = to_le32(h);
                    out_hashes_le.push_back(std::move(hl));
                    pos += HBYTES;
                }
                return true;
            }
        }

        // Fallback: Bitcoin-style [varint count][count*(80-byte header + varint txcount)]
        if(!payload.empty()){
            size_t pos = 0; uint64_t count=0, used=0;
            if(get_varint(payload.data(), payload.size(), count, used)){
                pos += used;
                std::vector<std::vector<uint8_t>> tmp;
                tmp.reserve((size_t)count);
                bool ok = true;
                for(uint64_t i=0;i<count;i++){
                    if(pos + 80 > payload.size()){ ok=false; break; }
                    const uint8_t* hdr = payload.data()+pos;
                    auto h  = dsha256_bytes(hdr, 80);
                    auto hl = to_le32(h);
                    tmp.push_back(std::move(hl));
                    pos += 80;
                    // txcount varint may be present; if parse fails, treat as absent (0)
                    if(pos < payload.size()){
                        uint64_t tcnt=0, u2=0;
                        if(get_varint(payload.data()+pos, payload.size()-pos, tcnt, u2)) pos += u2;
                    }
                }
                if(ok){ out_hashes_le.swap(tmp); return true; }
            }
        }

        err = "unrecognized headers payload shape";
        return false;
    }
}

// ---- recent blocks listing (no filters) --------------------------------------
bool P2PLight::match_recent_blocks(const std::vector<std::vector<uint8_t>>& /*pkhs*/,
                                   uint32_t from_height,
                                   uint32_t to_height,
                                   std::vector<std::pair<std::vector<uint8_t>, uint32_t>>& matched,
                                   std::string& err)
{
    matched.clear();
    if (sock_ < 0){ err = "not connected"; return false; }

    // Ensure we have headers
    uint32_t tip=0; std::vector<uint8_t> tip_hash;
    if(!get_best_header(tip, tip_hash, err)) return false;

    if(to_height > tip) to_height = tip;
    if(from_height > to_height) return true; // empty window

    for(uint32_t h = from_height; h <= to_height; ++h){
        matched.emplace_back(header_hashes_le_[h], h);
    }
    return true;
}

// ---- block fetch (your daemon uses `getb`) -----------------------------------
bool P2PLight::get_block_by_hash(const std::vector<uint8_t>& hash_le,
                                 std::vector<uint8_t>& raw_block,
                                 std::string& err)
{
    raw_block.clear();
    if (sock_ < 0){ err = "not connected"; return false; }
    if (hash_le.size()!=32){ err = "hash_le must be 32 bytes"; return false; }

    if(!send_msg("getb", hash_le, err)) return false;

    // read messages until we get "block"
    for(;;){
        std::string cmd; uint32_t len=0, csum=0; bool legacy=false;
        if(!read_msg_header(cmd, len, csum, legacy, err)) return false;

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd=="ping"){
            std::string e; send_msg("pong", payload, e);
            continue;
        }
        if(cmd=="block"){
            raw_block = std::move(payload);
            return true;
        }
        // ignore others
    }
}

// ---- internals: version/verack and IO ----------------------------------------
bool P2PLight::send_version(std::string& err){
    // Build Bitcoin-like "version" payload; daemon is permissive and ignores extras.
    std::vector<uint8_t> p;

    const int32_t  version   = 70015;
    const uint64_t services  = 0;
    const int64_t  timestamp = (int64_t) (std::chrono::system_clock::now().time_since_epoch() / std::chrono::seconds(1));

    // remote addr (ignored by most)
    const uint64_t srv_recv = 0;
    uint8_t ip_zero[16]{}; // ::0
    const uint16_t port_recv = P2P_PORT;

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
    // user agent
    {
        // If daemon expects a short UA, this still works (varstr).
        std::string ua = o_.user_agent;
        if(ua.empty()) ua = "/miqwallet:0.1/";
        // varstr
        if (ua.size() < 0xFD) { p.push_back((uint8_t)ua.size()); }
        else { put_varint(p, ua.size()); }
        p.insert(p.end(), ua.begin(), ua.end());
    }
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
    for (int i=0;i<50;i++){
        std::string cmd; uint32_t len=0, csum=0; bool legacy=false;
        if(!read_msg_header(cmd, len, csum, legacy, err)) return false;

        std::vector<uint8_t> payload(len);
        if(len>0 && !read_exact(payload.data(), len, err)) return false;

        if(cmd=="verack") return true;
        if(cmd=="ping"){ std::string e; send_msg("pong", payload, e); }
        // ignore other msgs in handshake window
    }
    err = "no verack from peer";
    return false;
}

// Encode and send one message (Bitcoin-style or legacy, per opt)
bool P2PLight::send_msg(const char cmd12[12], const std::vector<uint8_t>& payload, std::string& err){
    if (sock_ < 0) { err = "not connected"; return false; }

    if (o_.prefer_new_frame){
        // Bitcoin-style: [magic(4)|cmd(12)|len(4)|chk(4)] + payload
        uint8_t header[24]{};
        uint32_t m = MIQ_P2P_MAGIC;
        header[0]=uint8_t(m); header[1]=uint8_t(m>>8); header[2]=uint8_t(m>>16); header[3]=uint8_t(m>>24);
        for (int i=0;i<12 && cmd12[i]; ++i) header[4+i] = (uint8_t)cmd12[i];
        uint32_t L = (uint32_t)payload.size();
        header[16]=uint8_t(L); header[17]=uint8_t(L>>8); header[18]=uint8_t(L>>16); header[19]=uint8_t(L>>24);
        uint32_t c = checksum4(payload);
        header[20]=uint8_t(c); header[21]=uint8_t(c>>8); header[22]=uint8_t(c>>16); header[23]=uint8_t(c>>24);
        if(!write_all(header, sizeof(header), err)) return false;
        if(L>0 && !write_all(payload.data(), payload.size(), err)) return false;
        return true;
    } else {
        // Legacy: [cmd(12)|len(4)] + payload
        uint8_t header[16]{};
        for (int i=0;i<12 && cmd12[i]; ++i) header[0+i] = (uint8_t)cmd12[i];
        uint32_t L = (uint32_t)payload.size();
        header[12]=uint8_t(L); header[13]=uint8_t(L>>8); header[14]=uint8_t(L>>16); header[15]=uint8_t(L>>24);
        if(!write_all(header, sizeof(header), err)) return false;
        if(L>0 && !write_all(payload.data(), payload.size(), err)) return false;
        return true;
    }
}

// Read message header; auto-detect framing. Returns len and sets legacy_out.
bool P2PLight::read_msg_header(std::string& cmd_out, uint32_t& len_out, uint32_t& csum_out, bool& legacy_out, std::string& err){
    cmd_out.clear(); len_out=0; csum_out=0; legacy_out=false;

    // Peek first 4 bytes to check magic
    uint8_t first4[4];
    if(!read_exact(first4, 4, err)) return false;

    uint32_t m = (uint32_t)first4[0] | ((uint32_t)first4[1]<<8) | ((uint32_t)first4[2]<<16) | ((uint32_t)first4[3]<<24);
    if(m == MIQ_P2P_MAGIC){
        // Bitcoin-style header: read remaining 20 bytes
        uint8_t rest[20];
        if(!read_exact(rest, 20, err)) return false;
        char cmd[13]{}; std::memcpy(cmd, rest+0, 12);
        cmd_out = std::string(cmd);
        len_out  = (uint32_t)rest[12] | ((uint32_t)rest[13]<<8) | ((uint32_t)rest[14]<<16) | ((uint32_t)rest[15]<<24);
        csum_out = (uint32_t)rest[16] | ((uint32_t)rest[17]<<8) | ((uint32_t)rest[18]<<16) | ((uint32_t)rest[19]<<24);
        legacy_out = false;
        return true;
    }

    // Legacy header (we already consumed 4 bytes of cmd)
    uint8_t rest_legacy[12]; // remaining cmd bytes (8) + len (4) → but we need total 12 to complete 16
    if(!read_exact(rest_legacy, 12, err)) return false;

    char cmd[13]{};
    // First 4 bytes are part of cmd (they are not guaranteed printable, but your daemon uses printable cmds)
    std::memcpy(cmd+0, first4, 4);
    std::memcpy(cmd+4, rest_legacy+0, 8);
    cmd_out = std::string(cmd);

    len_out  = (uint32_t)rest_legacy[8] | ((uint32_t)rest_legacy[9]<<8) | ((uint32_t)rest_legacy[10]<<16) | ((uint32_t)rest_legacy[11]<<24);
    csum_out = 0;
    legacy_out = true;
    return true;
}

bool P2PLight::read_exact(void* buf, size_t len, std::string& err){
    uint8_t* p = (uint8_t*)buf;
    size_t got = 0;
    while (got < len){
#ifdef _WIN32
        int n = recv(sock_, (char*)p + (int)got, (int)(len - (int)got), 0);
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
        int n = send(sock_, (const char*)p + (int)sent, (int)(len - (int)sent), 0);
#else
        ssize_t n = send(sock_, p + sent, len - sent, 0);
#endif
        if (n <= 0) { err = "send failed"; return false; }
        sent += (size_t)n;
    }
    return true;
}

}
