// =============================================================================
// TRANSACTION INDEX - Implementation
// =============================================================================

#include "txindex.h"
#include "hex.h"
#include "log.h"
#include <filesystem>
#include <algorithm>

namespace miq {

static const uint32_t TXINDEX_MAGIC = 0x54584958;  // "TXIX"
static const uint32_t TXINDEX_VERSION = 1;

std::string TxIndex::key_from_txid(const std::vector<uint8_t>& txid) {
    return std::string(reinterpret_cast<const char*>(txid.data()), txid.size());
}

bool TxIndex::open(const std::string& datadir) {
    std::lock_guard<std::mutex> lk(mtx_);

    path_ = datadir + "/txindex.dat";

    // Try to load existing index
    if (std::filesystem::exists(path_)) {
        if (!load_from_disk()) {
            MIQ_LOG_WARN(LogCategory::CHAIN, "Failed to load txindex, starting fresh");
            index_.clear();
        }
    }

    MIQ_LOG_INFO(LogCategory::CHAIN, "TxIndex opened with " + std::to_string(index_.size()) + " entries");
    return true;
}

bool TxIndex::add(const std::vector<uint8_t>& txid, uint64_t block_height, uint32_t tx_position) {
    if (txid.size() != 32) return false;

    std::lock_guard<std::mutex> lk(mtx_);

    std::string key = key_from_txid(txid);
    TxLocation loc;
    loc.block_height = block_height;
    loc.tx_position = tx_position;
    loc.valid = true;

    index_[key] = loc;
    dirty_ = true;

    return true;
}

bool TxIndex::remove_block(uint64_t block_height) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Remove all entries for this block height
    for (auto it = index_.begin(); it != index_.end(); ) {
        if (it->second.block_height == block_height) {
            it = index_.erase(it);
            dirty_ = true;
        } else {
            ++it;
        }
    }

    return true;
}

bool TxIndex::get(const std::vector<uint8_t>& txid, TxLocation& out) const {
    if (txid.size() != 32) return false;

    std::lock_guard<std::mutex> lk(mtx_);

    std::string key = key_from_txid(txid);
    auto it = index_.find(key);
    if (it == index_.end()) {
        out.valid = false;
        return false;
    }

    out = it->second;
    return true;
}

bool TxIndex::contains(const std::vector<uint8_t>& txid) const {
    if (txid.size() != 32) return false;

    std::lock_guard<std::mutex> lk(mtx_);
    return index_.find(key_from_txid(txid)) != index_.end();
}

bool TxIndex::flush() {
    std::lock_guard<std::mutex> lk(mtx_);

    if (!dirty_) return true;

    if (save_to_disk()) {
        dirty_ = false;
        return true;
    }

    return false;
}

size_t TxIndex::size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return index_.size();
}

bool TxIndex::load_from_disk() {
    try {
        std::ifstream f(path_, std::ios::binary);
        if (!f) return false;

        uint32_t magic = 0, version = 0;
        f.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        if (magic != TXINDEX_MAGIC) return false;

        f.read(reinterpret_cast<char*>(&version), sizeof(version));
        if (version != TXINDEX_VERSION) return false;

        uint64_t count = 0;
        f.read(reinterpret_cast<char*>(&count), sizeof(count));

        index_.clear();
        index_.reserve(count);

        for (uint64_t i = 0; i < count; ++i) {
            // Read 32-byte txid key
            char key[32];
            f.read(key, 32);
            if (!f) break;

            TxLocation loc;
            f.read(reinterpret_cast<char*>(&loc.block_height), sizeof(loc.block_height));
            f.read(reinterpret_cast<char*>(&loc.tx_position), sizeof(loc.tx_position));
            loc.valid = true;

            index_[std::string(key, 32)] = loc;
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool TxIndex::save_to_disk() const {
    try {
        std::string temp_path = path_ + ".tmp";
        std::ofstream f(temp_path, std::ios::binary | std::ios::trunc);
        if (!f) return false;

        f.write(reinterpret_cast<const char*>(&TXINDEX_MAGIC), sizeof(TXINDEX_MAGIC));
        f.write(reinterpret_cast<const char*>(&TXINDEX_VERSION), sizeof(TXINDEX_VERSION));

        uint64_t count = index_.size();
        f.write(reinterpret_cast<const char*>(&count), sizeof(count));

        for (const auto& kv : index_) {
            // Write 32-byte txid key
            if (kv.first.size() != 32) continue;
            f.write(kv.first.data(), 32);

            f.write(reinterpret_cast<const char*>(&kv.second.block_height), sizeof(kv.second.block_height));
            f.write(reinterpret_cast<const char*>(&kv.second.tx_position), sizeof(kv.second.tx_position));
        }

        f.flush();
        f.close();

        // Atomic rename
        std::filesystem::rename(temp_path, path_);

        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace miq
