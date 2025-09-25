#pragma once
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>

namespace miq {
class Storage {
public:
    bool open(const std::string& dir);
    bool append_block(const std::vector<uint8_t>& raw, const std::vector<uint8_t>& hash);
    bool read_block_by_index(size_t index, std::vector<uint8_t>& out) const;
    bool read_block_by_hash(const std::vector<uint8_t>& hash, std::vector<uint8_t>& out) const;
    size_t count() const { return offsets_.size(); }
    bool write_state(const std::vector<uint8_t>& b);
    bool read_state(std::vector<uint8_t>& b) const;
private:
    std::string path_blocks_, path_state_, path_index_, path_hashmap_;
    mutable std::vector<uint64_t> offsets_;
    mutable std::unordered_map<std::string, uint32_t> hash_to_index_;
};
}
