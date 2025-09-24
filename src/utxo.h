#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <unordered_map>
#include <tuple>

namespace miq {

struct UTXOEntry {
    uint64_t value;
    std::vector<uint8_t> pkh;
    uint64_t height;
    bool coinbase;
};

class UTXOSet {
public:
    bool open(const std::string& dir);
    bool add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e);
    bool spend(const std::vector<uint8_t>& txid, uint32_t vout);
    bool get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const;
    size_t size() const { return map_.size(); }

    // Enumerate live UTXOs for a given PKH. Returns (txid, vout, entry).
    std::vector<std::tuple<std::vector<uint8_t>, uint32_t, UTXOEntry>>
    list_for_pkh(const std::vector<uint8_t>& pkh) const;

private:
    std::string log_path_;
    std::unordered_map<std::string, UTXOEntry> map_; // key = hex(txid)+":"+vout

    bool append_log(char op, const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry* e);
    std::string key(const std::vector<uint8_t>& txid, uint32_t vout) const;
    bool load_log();
};

} // namespace miq
