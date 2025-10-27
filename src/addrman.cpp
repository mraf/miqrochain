#include "addrman.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <limits>
#include <random>
#include <unordered_set>
#include <utility>

// Simple CRC32 (IEEE 802.3) for file integrity
namespace {
static uint32_t crc32_table[256];
static bool     crc32_init_done = false;

static void crc32_init() {
    if (crc32_init_done) return;
    for (uint32_t i = 0; i < 256; ++i) {
        uint32_t c = i;
        for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320U ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_init_done = true;
}
static uint32_t crc32(const uint8_t* data, size_t len) {
    crc32_init();
    uint32_t c = 0xFFFFFFFFU;
    for (size_t i = 0; i < len; ++i) c = crc32_table[(c ^ data[i]) & 0xFFU] ^ (c >> 8);
    return c ^ 0xFFFFFFFFU;
}
} // namespace

namespace miq {

// -------------------- helpers --------------------
static inline uint16_t read_u16le(const uint8_t* p) {
    return (uint16_t)p[0] | (uint16_t(p[1]) << 8);
}
static inline void write_u16le(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(uint8_t(v & 0xFF));
    out.push_back(uint8_t((v >> 8) & 0xFF));
}
static inline uint32_t read_u32le(const uint8_t* p) {
    return (uint32_t)p[0] | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
static inline void write_u32le(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(uint8_t(v & 0xFF));
    out.push_back(uint8_t((v >> 8) & 0xFF));
    out.push_back(uint8_t((v >> 16) & 0xFF));
    out.push_back(uint8_t((v >> 24) & 0xFF));
}
static inline uint64_t read_u64le(const uint8_t* p) {
    uint64_t z = 0;
    for (int i = 0; i < 8; ++i) z |= (uint64_t)p[i] << (8 * i);
    return z;
}
static inline void write_u64le(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(uint8_t((v >> (8 * i)) & 0xFF));
}

static inline bool is_ipv6_literal(const std::string& host) {
    // very light heuristic
    return host.find(':') != std::string::npos;
}

static inline uint64_t fnv1a64(const void* data, size_t n, uint64_t seed = 1469598103934665603ULL) {
    const uint8_t* p = (const uint8_t*)data;
    uint64_t h = seed;
    for (size_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

[[maybe_unused]] static inline uint32_t clamp_u32(uint64_t v) {
    return v > std::numeric_limits<uint32_t>::max() ? std::numeric_limits<uint32_t>::max() : (uint32_t)v;
}

// -------------------- AddrMan --------------------

AddrMan::AddrMan() {
    // Random-ish secret; stable for a given process, persisted across save/load.
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    secret_ = (uint64_t)now ^ 0x91E10DA5C79BEE3FULL ^ (uint64_t)(uintptr_t)this;
    rng_.s   = secret_ ^ 0xC0FFEEULL;

    tried_.resize(tried_buckets_);
    new_.resize(new_buckets_);
}

uint32_t AddrMan::now_unix() {
    using namespace std::chrono;
    return (uint32_t)duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

void AddrMan::set_limits(size_t tried_buckets, size_t new_buckets, size_t addrs_per_bucket) {
    if (tried_buckets == 0) tried_buckets = 64;
    if (new_buckets == 0) new_buckets = 256;
    if (addrs_per_bucket == 0) addrs_per_bucket = 64;

    // Gather everything and re-bucket
    std::vector<NetAddr> all;
    for (auto& b : tried_) for (auto& a : b.v) all.push_back(a);
    for (auto& b : new_)   for (auto& a : b.v) all.push_back(a);

    tried_buckets_ = tried_buckets;
    new_buckets_   = new_buckets;
    addrs_per_bucket_ = addrs_per_bucket;

    tried_.clear(); tried_.resize(tried_buckets_);
    new_.clear();   new_.resize(new_buckets_);

    for (auto& a : all) {
        a.group_key = group_key_from_ip(a.host, a.is_ipv6);
        size_t b = map_to_bucket(a, a.tried);
        auto& vec = (a.tried ? tried_[b].v : new_[b].v);
        if (vec.size() < addrs_per_bucket_) vec.push_back(a);
        else (void)maybe_evict(a.tried ? tried_[b] : new_[b], a);
    }
}

size_t AddrMan::size() const {
    size_t n = 0;
    for (const auto& b : tried_) n += b.v.size();
    for (const auto& b : new_)   n += b.v.size();
    return n;
}

uint64_t AddrMan::group_key_from_ip(const std::string& host, bool is_ipv6) {
    if (!is_ipv6) {
        // IPv4 dotted decimal → /16 grouping: (A.B.*.*)
        int A=0,B=0,C=0,D=0;
        if (std::sscanf(host.c_str(), "%d.%d.%d.%d", &A, &B, &C, &D) == 4) {
            return (uint64_t(((A & 0xFF) << 8) | (B & 0xFF)));
        }
        // fallback hash
        return fnv1a64(host.data(), host.size());
    }
    // IPv6: group by first 32 bits (rough /32). Strip brackets if present.
    std::string h = host;
    if (!h.empty() && h.front() == '[' && h.back() == ']') h = h.substr(1, h.size() - 2);
    // hash of first 4 hextets (very rough but deterministic)
    size_t cut = 0;
    int colons = 0;
    for (size_t i = 0; i < h.size(); ++i) { if (h[i] == ':') { colons++; if (colons == 4) { cut = i; break; } } }
    std::string prefix = cut ? h.substr(0, cut) : h;
    return fnv1a64(prefix.data(), prefix.size());
}

size_t AddrMan::map_to_bucket(const NetAddr& a, bool tried) const {
    const size_t buckets = tried ? tried_buckets_ : new_buckets_;
    // Mix secret, group key, and (host,port)
    uint64_t mix = secret_;
    mix ^= a.group_key;
    mix ^= fnv1a64(a.host.data(), a.host.size(), 0x9E3779B185EBCA87ULL);
    mix ^= (uint64_t(a.port) << 32);
    return (size_t)(mix % (buckets ? buckets : 1));
}

size_t AddrMan::find_in_bucket(const Bucket& b, const NetAddr& a) {
    for (size_t i = 0; i < b.v.size(); ++i) {
        if (b.v[i].host == a.host && b.v[i].port == a.port) return i;
    }
    return (size_t)-1;
}

bool AddrMan::maybe_evict(Bucket& b, const NetAddr& incoming) {
    if (b.v.size() < addrs_per_bucket_) return true;

    // Choose a "worst" entry to evict:
    //   - Prefer evicting entries with many attempts and no recent success.
    //   - Otherwise evict the oldest last_success / last_seen.
    size_t victim = 0;
    auto score = [](const NetAddr& x)->uint64_t {
        // Higher score = worse (more likely to evict)
        uint64_t s = 0;
        // failed attempts weigh heavily
        s += (uint64_t)x.attempts * 1000ULL;
        // prefer those with no success
        s += (x.last_success == 0 ? 5000ULL : (uint64_t)(now_unix() - x.last_success) / 60ULL);
        // and stale last_seen
        s += (uint64_t)(now_unix() - x.last_seen) / 60ULL;
        return s;
    };
    uint64_t worst = 0;
    for (size_t i = 0; i < b.v.size(); ++i) {
        uint64_t s = score(b.v[i]);
        if (i == 0 || s > worst) { worst = s; victim = i; }
    }

    // If incoming is better (i.e., lower score), replace victim
    if (score(incoming) + 100 < worst) { // small hysteresis
        b.v[victim] = incoming;
        return true;
    }
    return false;
}

void AddrMan::add(const NetAddr& ain, bool from_dns) {
    NetAddr a = ain;
    a.is_ipv6   = a.is_ipv6 || is_ipv6_literal(a.host);
    a.is_tor    = a.is_tor; // not auto-detected here
    a.group_key = group_key_from_ip(a.host, a.is_ipv6);

    if (a.port == 0) return; // ignore invalid

    if (a.last_seen == 0) a.last_seen = now_unix();
    // from DNS seeds: don't trust last_success; keep tried=false
    if (from_dns) { a.tried = false; a.last_success = 0; a.attempts = 0; }

    // Try to find & update if already present in tried or new
    auto update_if_found = [&](std::vector<Bucket>& tbl)->bool{
        for (auto& b : tbl) {
            size_t idx = find_in_bucket(b, a);
            if (idx != (size_t)-1) {
                auto& cur = b.v[idx];
                // refresh basic fields
                cur.last_seen = std::max(cur.last_seen, a.last_seen);
                cur.is_ipv6   = a.is_ipv6;
                cur.is_tor    = a.is_tor;
                // keep better success info
                if (a.last_success > cur.last_success) cur.last_success = a.last_success;
                if (!a.tried && cur.tried) return true; // already in tried
                return true;
            }
        }
        return false;
    };
    if (update_if_found(tried_)) return;
    if (update_if_found(new_))   return;

    // Insert in appropriate table
    size_t bidx = map_to_bucket(a, a.tried);
    Bucket& b = a.tried ? tried_[bidx] : new_[bidx];
    if (b.v.size() < addrs_per_bucket_) {
        b.v.push_back(a);
    } else {
        (void)maybe_evict(b, a);
    }
}

void AddrMan::mark_good(const NetAddr& ain) {
    NetAddr a = ain;
    a.is_ipv6   = a.is_ipv6 || is_ipv6_literal(a.host);
    a.group_key = group_key_from_ip(a.host, a.is_ipv6);

    a.last_success = now_unix();
    a.attempts = 0;
    a.tried = true;

    // If exists in tried already, update in-place
    {
        size_t bidx = map_to_bucket(a, /*tried=*/true);
        Bucket& b = tried_[bidx];
        size_t i = find_in_bucket(b, a);
        if (i != (size_t)-1) {
            b.v[i].last_success = a.last_success;
            b.v[i].last_seen    = std::max(b.v[i].last_seen, a.last_seen ? a.last_seen : a.last_success);
            b.v[i].attempts     = 0;
            b.v[i].tried        = true;
            return;
        }
    }

    // Remove from NEW if present there
    {
        size_t nb = map_to_bucket(a, /*tried=*/false);
        Bucket& b = new_[nb];
        size_t i = find_in_bucket(b, a);
        if (i != (size_t)-1) {
            // promote: erase from new_
            b.v.erase(b.v.begin() + (ptrdiff_t)i);
        } else {
            // Not in NEW at computed bucket — it might be in another bucket due to param changes.
            // Do a slow scan to be sure we don't duplicate.
            for (auto& bb : new_) {
                size_t j = find_in_bucket(bb, a);
                if (j != (size_t)-1) { bb.v.erase(bb.v.begin() + (ptrdiff_t)j); break; }
            }
        }
    }

    // Insert into TRIED (with eviction if needed)
    {
        size_t tb = map_to_bucket(a, /*tried=*/true);
        Bucket& b = tried_[tb];
        if (b.v.size() < addrs_per_bucket_) b.v.push_back(a);
        else (void)maybe_evict(b, a);
    }
}

void AddrMan::mark_attempt(const NetAddr& ain) {
    NetAddr a = ain;
    a.is_ipv6   = a.is_ipv6 || is_ipv6_literal(a.host);
    a.group_key = group_key_from_ip(a.host, a.is_ipv6);

    auto inc_if_found = [&](std::vector<Bucket>& tbl)->bool{
        for (auto& b : tbl) {
            size_t i = find_in_bucket(b, a);
            if (i != (size_t)-1) {
                // Don't overflow attempts
                if (b.v[i].attempts < std::numeric_limits<uint32_t>::max())
                    b.v[i].attempts++;
                return true;
            }
        }
        return false;
    };
    if (inc_if_found(tried_)) return;
    (void)inc_if_found(new_);
}

std::optional<NetAddr> AddrMan::select_for_outbound(FastRand& r, bool prefer_tried) {
    auto choose_from = [&](std::vector<Bucket>& tbl)->std::optional<NetAddr>{
        // Try up to a few random buckets/elements to find a reasonable candidate
        for (int attempt = 0; attempt < 16; ++attempt) {
            if (tbl.empty()) return std::nullopt;
            size_t bidx = (size_t)(r.next() % tbl.size());
            auto& b = tbl[bidx].v;
            if (b.empty()) continue;
            size_t eidx = (size_t)(r.next() % b.size());
            NetAddr cand = b[eidx];

            // lightweight backoff: if too many attempts with no success recently, skip
            uint32_t now = now_unix();
            if (cand.attempts >= 3 && cand.last_success != 0 && now - cand.last_success < 60) continue;
            if (cand.attempts >= 6 && now - cand.last_seen < 300) continue;

            return cand;
        }
        return std::nullopt;
    };

    if (prefer_tried) {
        if (auto x = choose_from(tried_)) return x;
        return choose_from(new_);
    } else {
        if (auto x = choose_from(new_)) return x;
        return choose_from(tried_);
    }
}

std::optional<NetAddr> AddrMan::select_feeler(FastRand& r) {
    // Prefer NEW addresses with zero attempts
    std::vector<std::pair<size_t,size_t>> candidates; // (bucket, index)
    for (size_t bi = 0; bi < new_.size(); ++bi) {
        const auto& vec = new_[bi].v;
        for (size_t i = 0; i < vec.size(); ++i) {
            if (!vec[i].tried && vec[i].attempts == 0) candidates.emplace_back(bi, i);
        }
    }
    if (!candidates.empty()) {
        auto pick = candidates[(size_t)(r.next() % candidates.size())];
        return new_[pick.first].v[pick.second];
    }
    // Fallback to any NEW, else TRIED
    if (auto x = select_for_outbound(rng_, /*prefer_tried=*/false)) return x;
    return std::nullopt;
}

void AddrMan::add_anchor(const NetAddr& a) {
    // Avoid duplicates
    auto it = std::find_if(anchors_.begin(), anchors_.end(), [&](const NetAddr& x){
        return x.host == a.host && x.port == a.port;
    });
    if (it == anchors_.end()) {
        anchors_.push_back(a);
        // modest cap to keep file small
        if (anchors_.size() > 64) anchors_.erase(anchors_.begin());
    }
}

std::vector<NetAddr> AddrMan::get_anchors() const {
    return anchors_;
}

void AddrMan::prune_stale(uint32_t now, uint32_t stale_days) {
    const uint32_t stale_secs = stale_days * 24u * 60u * 60u;
    auto prune_tbl = [&](std::vector<Bucket>& tbl){
        for (auto& b : tbl) {
            auto& v = b.v;
            v.erase(std::remove_if(v.begin(), v.end(), [&](const NetAddr& x){
                bool very_stale = (now > x.last_seen && (now - x.last_seen) > stale_secs);
                bool never_ok   = (x.last_success == 0);
                bool many_fail  = (x.attempts >= 10);
                return (very_stale && never_ok) || many_fail;
            }), v.end());
        }
    };
    prune_tbl(new_);
    prune_tbl(tried_);
}

// -------------------- Serialization --------------------

bool AddrMan::serialize(std::vector<uint8_t>& out, std::string& err) const {
    out.clear();
    // header: magic + version
    const char MAGIC[4] = {'A','M','N','2'};
    out.insert(out.end(), MAGIC, MAGIC + 4);
    write_u32le(out, 1); // version

    // parameters
    write_u32le(out, (uint32_t)tried_buckets_);
    write_u32le(out, (uint32_t)new_buckets_);
    write_u32le(out, (uint32_t)addrs_per_bucket_);
    write_u64le(out, secret_);

    // anchors
    write_u32le(out, (uint32_t)anchors_.size());
    for (const auto& a : anchors_) {
        uint8_t len = (uint8_t)std::min<size_t>(255, a.host.size());
        out.push_back(len);
        out.insert(out.end(), a.host.begin(), a.host.begin() + len);
        write_u16le(out, a.port);
        out.push_back(a.is_ipv6 ? 1u : 0u);
        out.push_back(a.is_tor  ? 1u : 0u);
    }

    auto dump_table = [&](const std::vector<Bucket>& tbl){
        write_u32le(out, (uint32_t)tbl.size());
        for (const auto& b : tbl) {
            write_u32le(out, (uint32_t)b.v.size());
            for (const auto& a : b.v) {
                uint8_t len = (uint8_t)std::min<size_t>(255, a.host.size());
                out.push_back(len);
                out.insert(out.end(), a.host.begin(), a.host.begin() + len);
                write_u16le(out, a.port);
                out.push_back(a.is_ipv6 ? 1u : 0u);
                out.push_back(a.is_tor  ? 1u : 0u);
                write_u32le(out, a.last_seen);
                write_u32le(out, a.last_success);
                write_u32le(out, a.attempts);
                out.push_back(a.tried ? 1u : 0u);
            }
        }
    };
    dump_table(tried_);
    dump_table(new_);

    // checksum
    uint32_t c = crc32(out.data(), out.size());
    write_u32le(out, c);
    (void)err;
    return true;
}

bool AddrMan::deserialize(const std::vector<uint8_t>& in, std::string& err) {
    if (in.size() < 4 + 4 + 4) { err = "addrman: file too short"; return false; }

    // verify checksum
    if (in.size() < 4) { err = "addrman: no checksum"; return false; }
    uint32_t stored = read_u32le(&in[in.size() - 4]);
    uint32_t calc   = crc32(in.data(), in.size() - 4);
    if (stored != calc) { err = "addrman: checksum mismatch"; return false; }

    size_t off = 0;
    auto need = [&](size_t n)->bool{ return (off + n) <= (in.size() - 4); };

    // header
    if (!need(4)) { err = "addrman: truncated header"; return false; }
    if (std::memcmp(&in[off], "AMN2", 4) != 0) { err = "addrman: bad magic"; return false; }
    off += 4;

    if (!need(4)) { err = "addrman: missing version"; return false; }
    uint32_t ver = read_u32le(&in[off]); off += 4;
    if (ver != 1) { err = "addrman: unsupported version"; return false; }

    // params
    if (!need(4*3 + 8)) { err = "addrman: truncated params"; return false; }
    uint32_t tried_b = read_u32le(&in[off]); off += 4;
    uint32_t new_b   = read_u32le(&in[off]); off += 4;
    uint32_t per_b   = read_u32le(&in[off]); off += 4;
    uint64_t secret  = read_u64le(&in[off]); off += 8;

    if (tried_b == 0 || new_b == 0 || per_b == 0) { err = "addrman: bad table sizes"; return false; }

    tried_buckets_     = tried_b;
    new_buckets_       = new_b;
    addrs_per_bucket_  = per_b;
    secret_            = secret;
    rng_.s             = secret_ ^ 0xC0FFEEULL;

    tried_.clear(); tried_.resize(tried_buckets_);
    new_.clear();   new_.resize(new_buckets_);

    // anchors
    if (!need(4)) { err = "addrman: no anchors count"; return false; }
    uint32_t anc_cnt = read_u32le(&in[off]); off += 4;
    anchors_.clear(); anchors_.reserve(anc_cnt);
    for (uint32_t i = 0; i < anc_cnt; ++i) {
        if (!need(1)) { err = "addrman: bad anchor len"; return false; }
        uint8_t len = in[off++];

        if (!need(len + 2 + 1 + 1)) { err = "addrman: bad anchor record"; return false; }
        NetAddr a;
        a.host.assign((const char*)&in[off], (size_t)len); off += len;
        a.port   = read_u16le(&in[off]); off += 2;
        a.is_ipv6= in[off++] != 0;
        a.is_tor = in[off++] != 0;
        anchors_.push_back(std::move(a));
    }

    auto load_table = [&](std::vector<Bucket>& tbl)->bool{
        if (!need(4)) { err = "addrman: no table bucket count"; return false; }
        uint32_t bcnt = read_u32le(&in[off]); off += 4;
        if (bcnt != tbl.size()) { err = "addrman: bucket size mismatch"; return false; }
        for (uint32_t bi = 0; bi < bcnt; ++bi) {
            if (!need(4)) { err = "addrman: no bucket entry count"; return false; }
            uint32_t ecnt = read_u32le(&in[off]); off += 4;
            tbl[bi].v.clear(); tbl[bi].v.reserve(ecnt);
            for (uint32_t ei = 0; ei < ecnt; ++ei) {
                if (!need(1)) { err = "addrman: entry host len"; return false; }
                uint8_t len = in[off++];

                if (!need(len + 2 + 1 + 1 + 4 + 4 + 4 + 1)) { err = "addrman: entry truncated"; return false; }
                NetAddr a;
                a.host.assign((const char*)&in[off], (size_t)len); off += len;
                a.port        = read_u16le(&in[off]); off += 2;
                a.is_ipv6     = in[off++] != 0;
                a.is_tor      = in[off++] != 0;
                a.last_seen   = read_u32le(&in[off]); off += 4;
                a.last_success= read_u32le(&in[off]); off += 4;
                a.attempts    = read_u32le(&in[off]); off += 4;
                a.tried       = in[off++] != 0;
                a.group_key   = group_key_from_ip(a.host, a.is_ipv6);

                // Respect bucket capacity
                if (tbl[bi].v.size() < addrs_per_bucket_) tbl[bi].v.push_back(std::move(a));
            }
        }
        return true;
    };

    if (!load_table(tried_)) return false;
    if (!load_table(new_))   return false;

    return true;
}

bool AddrMan::save(const std::string& path, std::string& err) const {
    std::vector<uint8_t> buf;
    if (!serialize(buf, err)) return false;

    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) { err = "addrman: cannot open for write"; return false; }
    f.write((const char*)buf.data(), (std::streamsize)buf.size());
    if (!f.good()) { err = "addrman: write failed"; return false; }
    f.flush();
    return true;
}

bool AddrMan::load(const std::string& path, std::string& err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { err.clear(); return false; } // not fatal: first run
    f.seekg(0, std::ios::end);
    std::streamsize n = f.tellg();
    f.seekg(0, std::ios::beg);
    if (n <= 0) { err = "addrman: empty file"; return false; }
    std::vector<uint8_t> buf((size_t)n);
    if (!f.read((char*)buf.data(), n)) { err = "addrman: read failed"; return false; }
    return deserialize(buf, err);
}

}
