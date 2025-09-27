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
    bool accept_block_for_reorg(const Block& b, std::string& err);
    bool disconnect_tip_once(std::string& err);
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
    UTXOSet  utxo_;
    Tip      tip_{0, std::vector<uint8_t>(32,0), GENESIS_BITS, GENESIS_TIME, 0};
    BlockIndex index_;

    bool save_state();
    bool load_state();
};

} // namespace miq
