#pragma once
#include <cstdint>
#include <vector>
#include <utility>
#include <unordered_map>
#include <string>        // added

#include "block.h"
#include "serialize.h"
#include "storage.h"
#include "utxo.h"
#include "mempool.h"
#include "difficulty.h"
#include "constants.h"
#include "blockindex.h"

namespace miq {

struct HeaderMeta {
    std::vector<uint8_t> hash;
    std::vector<uint8_t> prev;
    uint32_t bits;
    int64_t  time;
    uint64_t height;
    long double work_sum;   // cumulative relative work (deterministic enough for now)
    bool have_block;        // do we have the block body on disk?
};

struct Tip {
    uint64_t             height;
    std::vector<uint8_t> hash;
    uint32_t             bits;
    int64_t              time;
    uint64_t             issued;
};

class Chain {
public:
    const std::vector<uint8_t>& tip_hash() const { return tip_.hash; }
    bool read_block_any(const std::vector<uint8_t>& h, Block& out) const;
    bool validate_header(const BlockHeader& h, std::string& err) const;
    bool accept_header(const BlockHeader& h, std::string& err);
    bool reconsider_best_chain(std::string& err);  
    void orphan_put(const std::vector<uint8_t>& h, const std::vector<uint8_t>& raw);
    std::vector<uint8_t> best_header_hash() const;
    bool header_exists(const std::vector<uint8_t>& h) const;
    void next_block_fetch_targets(std::vector<std::vector<uint8_t>>& out, size_t max) const;
    bool get_hash_by_index(size_t idx, std::vector<uint8_t>& out) const;
    void build_locator(std::vector<std::vector<uint8_t>>& out) const;
    bool get_headers_from_locator(const std::vector<std::vector<uint8_t>>& locators,
                              size_t max,
                              std::vector<BlockHeader>& out) const;
    bool disconnect_tip_once(std::string& err);
    bool accept_block_for_reorg(const Block& b, std::string& err);
    bool open(const std::string& dir);
    bool init_genesis(const Block& genesis);
    bool verify_block(const Block& b, std::string& err) const;
    bool submit_block(const Block& b, std::string& err);

    Tip tip() const { return tip_; }

    std::vector<std::pair<int64_t,uint32_t>> last_headers(size_t n) const;

    UTXOSet& utxo(){ return utxo_; }
    const UTXOSet& utxo() const { return utxo_; }

    uint64_t height() const { return tip_.height; }
    uint64_t subsidy_for_height(uint64_t height) const;

    bool get_block_by_index(size_t idx, Block& out) const;
    bool get_block_by_hash(const std::vector<uint8_t>& h, Block& out) const;
    bool have_block(const std::vector<uint8_t>& h) const;

private:
    Storage  storage_;
    std::string datadir_;
    UTXOSet  utxo_;
    Tip      tip_{0, std::vector<uint8_t>(32,0), GENESIS_BITS, GENESIS_TIME, 0};
    BlockIndex index_;

    bool save_state();
    bool load_state();
        std::unordered_map<std::string, HeaderMeta> header_index_; // key = hk(hash)
    std::string best_header_key_; // hk(hash) of best header by work_sum

    // Orphan raw blocks keyed by block-hash (hk)
    std::unordered_map<std::string, std::vector<uint8_t>> orphan_blocks_;

    // Map child->parent for walking up the header tree
    inline static std::string keyh(const std::vector<uint8_t>& h) {
        return std::string(reinterpret_cast<const char*>(h.data()), h.size());
    }

    // Utility: compute cumulative-work increment from bits (relative, deterministic)
    static long double work_from_bits(uint32_t bits);

    // Utility: walk up from a header to find common ancestor with current tip header
    bool find_header_fork(const std::vector<uint8_t>& a,
                          const std::vector<uint8_t>& b,
                          std::vector<std::vector<uint8_t>>& path_up_from_b,
                          std::vector<std::vector<uint8_t>>& path_down_from_a) const;

    bool read_block_any(const std::vector<uint8_t>& h, Block& out) const; // you already have this
};

}
