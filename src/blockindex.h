
#pragma once
#include <vector>
#include <unordered_map>
#include <memory>
#include "block.h"
namespace miq {
struct HeaderRec{
    std::vector<uint8_t> hash;
    std::vector<uint8_t> prev;
    int64_t time{0};
    uint32_t bits{0};
    uint64_t height{0};
    long double chainwork{0};
    std::shared_ptr<HeaderRec> parent;
};
class BlockIndex {
public:
    void reset(const std::vector<uint8_t>& genesis_hash, int64_t time, uint32_t bits);
    std::shared_ptr<HeaderRec> add_header(const BlockHeader& h, const std::vector<uint8_t>& real_hash);
    std::shared_ptr<HeaderRec> tip() const { return tip_; }
    std::vector<std::vector<uint8_t>> locator() const;
private:
    std::unordered_map<std::string,std::shared_ptr<HeaderRec>> map_;
    std::shared_ptr<HeaderRec> tip_;
};
}
