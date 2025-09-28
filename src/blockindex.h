#pragma once
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include "block.h"

namespace miq {

// Header record stored in-memory for headers-first sync and chain selection.
struct HeaderRec {
    std::vector<uint8_t> hash;     // 32-byte block header hash (little-endian bytes as used in your codebase)
    std::vector<uint8_t> prev;     // 32-byte prev hash
    int64_t  time{0};              // header timestamp
    uint32_t bits{0};              // nBits compact target
    uint64_t height{0};            // header height (0 = genesis)
    long double chainwork{0};      // cumulative work (monotonic on best header chain)
    std::shared_ptr<HeaderRec> parent;

    // True once the full block body has been received/validated/connected.
    bool have_body{false};
};

// In-memory index for block headers (and which headers already have bodies).
class BlockIndex {
public:
    // Initialize with genesis header info.
    // genesis_hash: 32-byte hash; time/bits from the genesis header.
    void reset(const std::vector<uint8_t>& genesis_hash, int64_t time, uint32_t bits);

    // Add a new header that links to a known parent.
    // Returns the created HeaderRec, or nullptr if parent is unknown.
    std::shared_ptr<HeaderRec> add_header(const BlockHeader& h,
                                          const std::vector<uint8_t>& real_hash);

    // Mark that we have validated/connected the full block body for hash 'h'.
    void set_have_body(const std::vector<uint8_t>& h);

    // Best header by cumulative work (tip of the headers chain).
    std::shared_ptr<HeaderRec> tip() const { return tip_; }

    // Best connected block body (tip of the fully-connected chain).
    std::shared_ptr<HeaderRec> best_connected_body() const { return best_body_; }

    // Build a classic "locator" (back by powers of two) from best header tip.
    std::vector<std::vector<uint8_t>> locator() const;

    // Given a peer's locator, find our first known HeaderRec on that path.
    // Falls back to our genesis (root) if nothing matches.
    std::shared_ptr<HeaderRec> find_fork(const std::vector<std::vector<uint8_t>>& locator) const;

    // Find the next header **towards the best header chain** from 'cur'.
    // Returns nullptr if no child exists on (or toward) the best-work path.
    std::shared_ptr<HeaderRec> next_on_best_header_chain(const std::shared_ptr<HeaderRec>& cur) const;

private:
    // hash(hex) -> HeaderRec
    std::unordered_map<std::string, std::shared_ptr<HeaderRec>> map_;

    // Parent->children adjacency for forward walking.
    std::unordered_map<std::string, std::vector<std::shared_ptr<HeaderRec>>> children_;

    // Best header by chainwork.
    std::shared_ptr<HeaderRec> tip_;

    // Best fully-connected block (body) tip.
    std::shared_ptr<HeaderRec> best_body_;
};

}
