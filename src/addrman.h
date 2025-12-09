#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <optional>
#include <chrono>

namespace miq {

// Minimal network address record used by AddrMan.
// You can adapt/bridge to your existing socket/address types when wiring in p2p.
struct NetAddr {
    std::string host;      // "1.2.3.4" or "[2001:db8::1]"
    uint16_t    port{0};
    bool        is_ipv6{false};
    bool        is_tor{false};
    uint32_t    last_seen{0};     // unix seconds (when we learned it)
    uint32_t    last_success{0};  // unix seconds (last successful connect)
    uint32_t    attempts{0};      // failed dial attempts
    bool        tried{false};     // currently in "tried" table
    uint64_t    group_key{0};     // cached /16 (IPv4) or /32 (IPv6) grouping key
};

struct FastRand {
    uint64_t s;
    uint64_t next() {
        // xorshift64*
        s ^= s >> 12; s ^= s << 25; s ^= s >> 27;
        return s * 2685821657736338717ULL;
    }
};

// Simple bucketed Address Manager with tried/new tables.
// Serialization is stable and includes a header+checksum.
class AddrMan {
public:
    AddrMan();

    // Persistence
    bool load(const std::string& path, std::string& err);
    bool save(const std::string& path, std::string& err) const;

    // Insert/update
    void add(const NetAddr& a, bool from_dns);
    void mark_good(const NetAddr& a);
    void mark_attempt(const NetAddr& a);

    // Selection
    std::optional<NetAddr> select_for_outbound(FastRand& r, bool prefer_tried);
    std::optional<NetAddr> select_feeler(FastRand& r);

    // Anchors (last-good peers we try early)
    void add_anchor(const NetAddr& a);
    std::vector<NetAddr> get_anchors() const;

    // Maintenance
    void prune_stale(uint32_t now_unix, uint32_t stale_days = 30);
    size_t size() const;

    // Tuning knobs (optional to call)
    void set_limits(size_t tried_buckets, size_t new_buckets, size_t addrs_per_bucket);

private:
    struct Bucket { std::vector<NetAddr> v; };

    std::vector<Bucket> tried_;
    std::vector<Bucket> new_;
    std::vector<NetAddr> anchors_;

    // Parameters
    size_t tried_buckets_ = 64;
    size_t new_buckets_   = 256;
    size_t addrs_per_bucket_ = 64;

    uint64_t secret_; // salt for bucket mapping
    mutable FastRand rng_;

    // Helpers
    static uint64_t group_key_from_ip(const std::string& host, bool is_ipv6);
    size_t map_to_bucket(const NetAddr& a, bool tried) const;
    bool maybe_evict(Bucket& b, const NetAddr& incoming);

    // Find by (host,port) inside a bucket; return index or npos
    static size_t find_in_bucket(const Bucket& b, const NetAddr& a);

    // Serialization
    bool serialize(std::vector<uint8_t>& out, std::string& err) const;
    bool deserialize(const std::vector<uint8_t>& in, std::string& err);

    // Utility
    static uint32_t now_unix();
};

}
