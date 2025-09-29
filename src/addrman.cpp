#include "addrman.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <algorithm>

namespace miq {

static constexpr uint32_t CRC32_POLY = 0xEDB88320u;
static uint32_t crc32(const uint8_t* data, size_t len){
    uint32_t c = 0xFFFFFFFFu;
    for(size_t i=0;i<len;i++){
        c ^= data[i];
        for(int k=0;k<8;k++) c = (c >> 1) ^ (CRC32_POLY & (-(int)(c & 1)));
    }
    return ~c;
}

static uint64_t read64(const std::vector<uint8_t>& v, size_t& o){
    uint64_t x=0; for(int i=0;i<8;i++) x |= (uint64_t)v[o++] << (8*i); return x;
}
static uint32_t read32(const std::vector<uint8_t>& v, size_t& o){
    uint32_t x=0; for(int i=0;i<4;i++) x |= (uint32_t)v[o++] << (8*i); return x;
}
static uint16_t read16(const std::vector<uint8_t>& v, size_t& o){
    uint16_t x=0; for(int i=0;i<2;i++) x |= (uint16_t)v[o++] << (8*i); return x;
}
static std::string readstr(const std::vector<uint8_t>& v, size_t& o){
    uint32_t n = read32(v,o);
    std::string s; s.resize(n);
    for(uint32_t i=0;i<n;i++) s[i] = char(v[o++]);
    return s;
}
static void write64(std::vector<uint8_t>& v, uint64_t x){ for(int i=0;i<8;i++) v.push_back(uint8_t((x>>(8*i))&0xFF)); }
static void write32(std::vector<uint8_t>& v, uint32_t x){ for(int i=0;i<4;i++) v.push_back(uint8_t((x>>(8*i))&0xFF)); }
static void write16(std::vector<uint8_t>& v, uint16_t x){ for(int i=0;i<2;i++) v.push_back(uint8_t((x>>(8*i))&0xFF)); }
static void writestr(std::vector<uint8_t>& v, const std::string& s){ write32(v,(uint32_t)s.size()); v.insert(v.end(), s.begin(), s.end()); }

uint32_t AddrMan::now_unix(){
    using namespace std::chrono;
    return (uint32_t)duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

uint64_t AddrMan::group_key_from_ip(const std::string& host, bool is_ipv6){
    // Very simple: for IPv4 "a.b.c.d" use /16 (a,b). For IPv6 use first 32 bits.
    // If parsing fails, hash-ish fallback on string bytes.
    if(!is_ipv6){
        unsigned a,b,c,d;
        if(sscanf(host.c_str(), "%u.%u.%u.%u", &a,&b,&c,&d) == 4){
            return ((uint64_t)(a & 0xFF) << 8) | (uint64_t)(b & 0xFF);
        }
    } else {
        // Parse first 4 hex bytes roughly; this is conservative and fine for grouping.
        // Example "[2001:0db8::1]" or "2001:db8::1"
        std::string s = host;
        if(!s.empty() && s.front()=='[' && s.back()==']') s = s.substr(1, s.size()-2);
        unsigned part0=0, part1=0;
        if(sscanf(s.c_str(), "%x:%x", &part0, &part1) >= 1){
            return ((uint64_t)(part0 & 0xFFFF) << 16) | (uint64_t)(part1 & 0xFFFF);
        }
    }
    // Fallback: xor bytes
    uint64_t g=0; for(char ch: host) g = (g*131) ^ (uint8_t)ch; return g & 0xFFFF;
}

AddrMan::AddrMan(){
    // Non-zero seed; in production we’ll randomize once and persist via serialize().
    secret_ = 0x9e3779b97f4a7c15ULL;
    rng_.s  = 0xC0FFEEULL ^ secret_;
    tried_.resize(tried_buckets_);
    new_.resize(new_buckets_);
}

void AddrMan::set_limits(size_t tb, size_t nb, size_t per){
    tried_buckets_ = tb ? tb : tried_buckets_;
    new_buckets_   = nb ? nb : new_buckets_;
    addrs_per_bucket_ = per ? per : addrs_per_bucket_;
    tried_.assign(tried_buckets_, Bucket{});
    new_.assign(new_buckets_, Bucket{});
}

size_t AddrMan::find_in_bucket(const Bucket& b, const NetAddr& a){
    for(size_t i=0;i<b.v.size();++i){
        if(b.v[i].port==a.port && b.v[i].host==a.host) return i;
    }
    return (size_t)-1;
}

size_t AddrMan::map_to_bucket(const NetAddr& a, bool tried) const{
    // Salted mapping. Keep simple: (group_key ^ secret_) % buckets
    uint64_t g = a.group_key ? a.group_key : group_key_from_ip(a.host, a.is_ipv6);
    uint64_t h = g ^ secret_;
    size_t mod = tried ? tried_buckets_ : new_buckets_;
    return (size_t)(h % (mod ? mod : 1));
}

bool AddrMan::maybe_evict(Bucket& b, const NetAddr& incoming){
    if(b.v.size() < addrs_per_bucket_) return false;
    // Evict policy: prefer evicting stale/high-attempts/same-group older entries.
    size_t victim = 0;
    int score_best = -1;
    for(size_t i=0;i<b.v.size();++i){
        const auto& e = b.v[i];
        int stale = (int)(now_unix() - std::max(e.last_seen, e.last_success));
        int attempts = (int)e.attempts;
        int score = stale/3600 + attempts*10;
        if(score > score_best){ score_best = score; victim = i; }
    }
    b.v[victim] = incoming;
    return true;
}

void AddrMan::add(const NetAddr& a_in, bool /*from_dns*/){
    NetAddr a = a_in;
    a.group_key = a.group_key ? a.group_key : group_key_from_ip(a.host, a.is_ipv6);
    a.last_seen = a.last_seen ? a.last_seen : now_unix();
    auto& buckets = a.tried ? tried_ : new_;
    size_t idx = map_to_bucket(a, a.tried);
    auto& b = buckets[idx];
    if(find_in_bucket(b, a) != (size_t)-1) return; // already present
    if(!maybe_evict(b, a)) b.v.push_back(a);
}

void AddrMan::mark_attempt(const NetAddr& a){
    NetAddr key = a; key.group_key = group_key_from_ip(a.host, a.is_ipv6);
    auto scan = [&](std::vector<Bucket>& space){
        size_t idx = map_to_bucket(key, &space==&tried_);
        auto& b = space[idx];
        size_t j = find_in_bucket(b, key);
        if(j!=(size_t)-1){ b.v[j].attempts++; b.v[j].last_seen = now_unix(); }
    };
    scan(tried_); scan(new_);
}

void AddrMan::mark_good(const NetAddr& a){
    // Move/ensure entry sits in TRIED with reset attempts and updated last_success
    NetAddr key = a; key.group_key = group_key_from_ip(a.host, a.is_ipv6);
    // Remove from NEW if present
    {
        size_t idx = map_to_bucket(key, /*tried=*/false);
        auto& b = new_[idx];
        size_t j = find_in_bucket(b, key);
        if(j!=(size_t)-1) b.v.erase(b.v.begin()+j);
    }
    // Insert into TRIED
    NetAddr t = key;
    t.tried = true; t.attempts = 0; t.last_success = now_unix();
    size_t idx = map_to_bucket(t, /*tried=*/true);
    auto& b = tried_[idx];
    size_t j = find_in_bucket(b, t);
    if(j!=(size_t)-1){ b.v[j] = t; return; }
    if(!maybe_evict(b, t)) b.v.push_back(t);
}

std::optional<NetAddr> AddrMan::select_for_outbound(FastRand& r, bool prefer_tried){
    auto pick_from = [&](std::vector<Bucket>& space)->std::optional<NetAddr>{
        // Uniform bucket, then random entry
        if(space.empty()) return std::nullopt;
        size_t start = (size_t)(r.next() % space.size());
        for(size_t k=0;k<space.size();++k){
            auto& b = space[(start + k) % space.size()];
            if(b.v.empty()) continue;
            auto i = (size_t)(r.next() % b.v.size());
            return b.v[i];
        }
        return std::nullopt;
    };
    if(prefer_tried){
        if(auto t = pick_from(tried_)) return t;
        return pick_from(new_);
    } else {
        if(auto n = pick_from(new_)) return n;
        return pick_from(tried_);
    }
}

std::optional<NetAddr> AddrMan::select_feeler(FastRand& r){
    // Prefer NEW buckets for feelers
    return select_for_outbound(r, /*prefer_tried=*/false);
}

void AddrMan::add_anchor(const NetAddr& a){
    // Deduplicate by host:port (small list)
    for(const auto& x : anchors_) if(x.host==a.host && x.port==a.port) return;
    anchors_.push_back(a);
    if(anchors_.size() > 8) anchors_.erase(anchors_.begin()); // simple rotate
}

std::vector<NetAddr> AddrMan::get_anchors() const { return anchors_; }

void AddrMan::prune_stale(uint32_t now_unix_ts, uint32_t stale_days){
    const uint32_t stale_sec = stale_days * 86400u;
    auto prune_space = [&](std::vector<Bucket>& space){
        for(auto& b : space){
            b.v.erase(std::remove_if(b.v.begin(), b.v.end(), [&](const NetAddr& n){
                uint32_t last = std::max(n.last_seen, n.last_success);
                return (now_unix_ts - last) > stale_sec && n.attempts > 3;
            }), b.v.end());
        }
    };
    prune_space(tried_);
    prune_space(new_);
}

size_t AddrMan::size() const {
    size_t s=0; for(const auto& b: tried_) s+=b.v.size();
    for(const auto& b: new_) s+=b.v.size();
    return s;
}

bool AddrMan::serialize(std::vector<uint8_t>& out, std::string& /*err*/) const{
    // Format: "MIQ1" magic | version u32 | secret u64 | TB u32 | NB u32 | PER u32 | anchors u32 | CRC placeholders...
    const uint32_t version = 1;
    std::vector<uint8_t> body;
    body.insert(body.end(), {'M','I','Q','1'});
    write32(body, version);
    // secret & params
    write64(body, secret_);
    write32(body, (uint32_t)tried_buckets_);
    write32(body, (uint32_t)new_buckets_);
    write32(body, (uint32_t)addrs_per_bucket_);

    // Write buckets
    auto dump_space = [&](const std::vector<Bucket>& sp){
        write32(body, (uint32_t)sp.size());
        for(const auto& b : sp){
            write32(body, (uint32_t)b.v.size());
            for(const auto& e : b.v){
                writestr(body, e.host);
                write16(body, e.port);
                body.push_back(uint8_t(e.is_ipv6));
                body.push_back(uint8_t(e.is_tor));
                write32(body, e.last_seen);
                write32(body, e.last_success);
                write32(body, e.attempts);
                body.push_back(uint8_t(e.tried));
                write64(body, e.group_key);
            }
        }
    };
    dump_space(tried_);
    dump_space(new_);

    // Anchors
    write32(body, (uint32_t)anchors_.size());
    for(const auto& a: anchors_){
        writestr(body, a.host); write16(body, a.port);
        body.push_back(uint8_t(a.is_ipv6)); body.push_back(uint8_t(a.is_tor));
    }

    // CRC
    uint32_t c = crc32(body.data(), body.size());
    write32(body, c);

    out.swap(body);
    return true;
}

bool AddrMan::deserialize(const std::vector<uint8_t>& in, std::string& err){
    if(in.size() < 16){ err = "addrman: file too small"; return false; }
    // Check CRC
    uint32_t want = (uint32_t)in[in.size()-4] | ((uint32_t)in[in.size()-3]<<8) | ((uint32_t)in[in.size()-2]<<16) | ((uint32_t)in[in.size()-1]<<24);
    if(crc32(in.data(), in.size()-4) != want){ err = "addrman: bad checksum"; return false; }

    size_t o=0;
    if(!(in[o++]=='M' && in[o++]=='I' && in[o++]=='Q' && in[o++]=='1')){ err="addrman: bad magic"; return false; }
    uint32_t ver = read32(in,o); (void)ver;

    secret_ = read64(in,o);
    tried_buckets_ = read32(in,o);
    new_buckets_   = read32(in,o);
    addrs_per_bucket_ = read32(in,o);

    tried_.assign(tried_buckets_, Bucket{});
    new_.assign(new_buckets_, Bucket{});

    auto load_space = [&](std::vector<Bucket>& sp){
        uint32_t nb = read32(in,o);
        if(nb != sp.size()) sp.assign(nb, Bucket{});
        for(uint32_t bi=0; bi<nb; ++bi){
            uint32_t m = read32(in,o);
            auto& b = sp[bi];
            b.v.clear(); b.v.reserve(m);
            for(uint32_t j=0;j<m;++j){
                NetAddr e;
                e.host = readstr(in,o);
                e.port = read16(in,o);
                e.is_ipv6 = bool(in[o++]);
                e.is_tor  = bool(in[o++]);
                e.last_seen = read32(in,o);
                e.last_success = read32(in,o);
                e.attempts = read32(in,o);
                e.tried = bool(in[o++]);
                e.group_key = read64(in,o);
                b.v.push_back(e);
            }
        }
    };
    load_space(tried_);
    load_space(new_);

    uint32_t anc = read32(in,o);
    anchors_.clear(); anchors_.reserve(anc);
    for(uint32_t i=0;i<anc;++i){
        NetAddr a;
        a.host = readstr(in,o);
        a.port = read16(in,o);
        a.is_ipv6 = bool(in[o++]);
        a.is_tor  = bool(in[o++]);
        anchors_.push_back(a);
    }
    // skip CRC already verified
    return true;
}

bool AddrMan::load(const std::string& path, std::string& err){
    std::ifstream f(path, std::ios::binary);
    if(!f.good()){ err = "addrman: file not found (ok on first run)"; return false; }
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), {});
    return deserialize(buf, err);
}

bool AddrMan::save(const std::string& path, std::string& err) const{
    std::vector<uint8_t> buf;
    if(!serialize(buf, err)) return false;
    std::string tmp = path + ".tmp";
    {
        std::ofstream of(tmp, std::ios::binary|std::ios::trunc);
        if(!of.good()){ err = "addrman: cannot open tmp for write"; return false; }
        of.write((const char*)buf.data(), (std::streamsize)buf.size());
        if(!of.good()){ err = "addrman: write failed"; return false; }
        of.flush();
    }
    // Atomic-ish replace
    std::remove(path.c_str()); // ignore error
    if(std::rename(tmp.c_str(), path.c_str()) != 0){ err = "addrman: rename failed"; return false; }
    return true;
}

}
