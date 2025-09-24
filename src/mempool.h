
#pragma once
#include <unordered_map>
#include <vector>
#include "tx.h"
#include "utxo.h"
#include "constants.h"
namespace miq {
struct MempoolEntry { Transaction tx; uint64_t fee; size_t size; double feerate; };
class Mempool {
public:
    explicit Mempool(size_t max_entries = 5000): max_(max_entries) {}
    bool accept(const Transaction& tx, const UTXOSet& utxo, uint64_t height, std::string& err);
    std::vector<Transaction> collect(size_t max_count) const;
    size_t size() const { return map_.size(); }
    std::vector<std::vector<uint8_t>> txids() const;
private:
    std::unordered_map<std::string, MempoolEntry> map_;
    size_t max_;
    std::string key(const std::vector<uint8_t>& txid) const;
    void maybe_evict();
};
}
