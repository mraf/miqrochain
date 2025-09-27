#pragma once
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>
#include <cstdint>
#include <functional>

namespace miq {

// 32-byte hash as raw bytes
using HashBytes = std::vector<uint8_t>;

// A tiny header view we need for chainwork ranking.
struct HeaderView {
    HashBytes hash;
    HashBytes prev;
    uint32_t  bits{0};
    int64_t   time{0};
    uint32_t  height{0};
};

class ReorgManager {
public:
    // Initialize with genesis (must be called once, on startup/init).
    void init_genesis(const HashBytes& genesis_hash, uint32_t bits, int64_t time);

    // Register a new, fully-validated block header (after you validated PoW+rules).
    // Returns true if header was linked to known parent; false if parent is unknown (store as orphan elsewhere if you like).
    bool on_validated_header(const HeaderView& h);

    // Compute the path difference from current active tip to the best chain (by total chainwork).
    // You provide the current active tip (hash). We return the hashes to DISCONNECT (from tip backwards) and CONNECT (forward from fork).
    // Returns false if no better chain exists. Returns true and fills vectors if a reorg is needed.
    bool plan_reorg(const HashBytes& current_active_tip,
                    std::vector<HashBytes>& out_disconnect,
                    std::vector<HashBytes>& out_connect) const;

    // The best-known tip by chainwork among all known headers.
    HashBytes best_tip() const;

    // (Optional) Clear all in-memory headers (e.g., before full reindex).
    void reset();

private:
    struct Node {
        HashBytes hash;
        HashBytes prev;
        uint32_t  bits{0};
        int64_t   time{0};
        uint32_t  height{0};
        long double chainwork{0.0L};
        std::shared_ptr<Node> parent;
    };

    // Map by hex-string key for simplicity.
    std::unordered_map<std::string, std::shared_ptr<Node>> map_;
    std::shared_ptr<Node> best_;

    static std::string hexkey(const HashBytes& h);
    static long double work_from_bits(uint32_t bits);
};

} // namespace miq
