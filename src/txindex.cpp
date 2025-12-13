// =============================================================================
// TRANSACTION INDEX - Implementation
// =============================================================================

#include "txindex.h"
#include "hex.h"
#include "log.h"
#include "assume_valid.h"  // For is_ibd_mode()
#include <filesystem>
#include <algorithm>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <unistd.h>
  #include <fcntl.h>
#endif

// Fast sync mode - skip fsync during IBD or near-tip for speed
// CRITICAL FIX: Also check near-tip mode for <1s warm datadir completion
static bool fast_sync_enabled() {
    // Always skip fsync during IBD for 10-100x faster sync
    if (miq::is_ibd_mode()) return true;
    // CRITICAL: Also skip fsync in near-tip mode for sub-second warm datadir sync
    if (miq::is_near_tip_mode()) return true;
    // Manual override via environment variable
    const char* e = std::getenv("MIQ_FAST_SYNC");
    return e && (e[0]=='1' || e[0]=='t' || e[0]=='T' || e[0]=='y' || e[0]=='Y');
}

// DURABILITY: Platform-specific fsync
static inline void fsync_path(const std::string& p) {
    if (fast_sync_enabled()) return;  // Skip in fast sync mode
#if defined(_WIN32)
    HANDLE h = CreateFileA(p.c_str(), GENERIC_WRITE,
                           FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        FlushFileBuffers(h);
        CloseHandle(h);
    }
#else
    int fd = ::open(p.c_str(), O_RDWR | O_CLOEXEC);
    if (fd >= 0) { ::fsync(fd); ::close(fd); }
#endif
}

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
            log_warn("Failed to load txindex, starting fresh");
            index_.clear();
        }
    }

    log_info("TxIndex opened with " + std::to_string(index_.size()) + " entries");
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

        // CRITICAL FIX: Validate count to prevent segfault on corrupted txindex
        // A corrupted file could have count = 0xFFFFFFFFFFFFFFFF
        static constexpr uint64_t MAX_TX_COUNT = 500000000; // 500M txs max
        if (count > MAX_TX_COUNT) {
            log_warn("TxIndex corrupted (invalid count " + std::to_string(count) +
                     "), will rebuild");
            return false;
        }

        index_.clear();
        index_.reserve(static_cast<size_t>(count));

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

        // DURABILITY: fsync before rename to ensure data is on disk
        fsync_path(temp_path);

        // Atomic rename
        std::filesystem::rename(temp_path, path_);

        return true;
    } catch (...) {
        return false;
    }
}

}  // namespace miq
