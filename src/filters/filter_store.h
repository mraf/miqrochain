#pragma once
// Minimal on-disk store for BIP158-like block filters + rolling headers.
// Header-only to avoid build system changes.

#include <array>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>

#ifdef _WIN32
  #include <direct.h>
  #define MIQ_MKDIR(path, mode) _mkdir(path)
#else
  #include <sys/stat.h>
  #include <sys/types.h>
  #include <errno.h>
  #define MIQ_MKDIR(path, mode) ::mkdir(path, mode)
#endif

#include "sha256.h"   // dsha256(std::vector<uint8_t>)
#include "hex.h"      // hex helpers (only for logs if you use them elsewhere)

namespace miq {
namespace gcs {

class FilterStore {
public:
    bool open(const std::string& dir) {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        dir_ = dir;
        // create directory (best-effort; ignore EEXIST)
        (void)MIQ_MKDIR(dir_.c_str(), 0755);
        return load();
    }

    // Append or set the filter for height; computes and stores rolling header.
    bool put(uint32_t height,
             const std::vector<uint8_t>& block_hash_le,
             const std::vector<uint8_t>& filter_bytes)
    {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        if (block_hash_le.size() != 32) return false;

        if (headers_.size() <= height) {
            headers_.resize(height + 1);
            hashes_.resize(height + 1);
            filters_.resize(height + 1);
        }

        // filter hash = dsha256(filter_bytes)
        const auto fh_vec = dsha256(filter_bytes);
        std::array<uint8_t,32> fh{};
        for (int i = 0; i < 32; ++i) fh[i] = fh_vec[i];

        // prev header = header at (height-1) if present, else zeros
        std::array<uint8_t,32> prev{};
        if (height > 0 && height - 1 < headers_.size() && !is_zero(headers_[height - 1])) {
            prev = headers_[height - 1];
        }

        // header = dsha256( fh || prev )
        std::vector<uint8_t> buf; buf.reserve(64);
        buf.insert(buf.end(), fh.begin(), fh.end());
        buf.insert(buf.end(), prev.begin(), prev.end());
        const auto hdr_vec = dsha256(buf);
        std::array<uint8_t,32> hdr{};
        for (int i = 0; i < 32; ++i) hdr[i] = hdr_vec[i];

        hashes_[height]  = to_arr32(block_hash_le);
        headers_[height] = hdr;
        filters_[height] = filter_bytes;

        return persist_append(height, hashes_[height], headers_[height], filters_[height]);
    }

    bool get_headers(uint32_t start, uint32_t count,
                     std::vector<std::array<uint8_t,32>>& out) const
    {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        out.clear();
        if (count == 0 || start >= headers_.size()) return true;
        const uint32_t end = (uint32_t)std::min<size_t>(headers_.size(), (size_t)start + count);
        for (uint32_t h = start; h < end; ++h) {
            if (is_zero(headers_[h])) break;
            out.push_back(headers_[h]);
        }
        return true;
    }

    // Returns pairs (block_hash_le, filter_bytes)
    bool get_filters(uint32_t start, uint32_t count,
                     std::vector<std::pair<std::array<uint8_t,32>, std::vector<uint8_t>>>& out) const
    {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        out.clear();
        if (count == 0 || start >= filters_.size()) return true;
        const uint32_t end = (uint32_t)std::min<size_t>(filters_.size(), (size_t)start + count);
        for (uint32_t h = start; h < end; ++h) {
            if (filters_[h].empty() || is_zero(hashes_[h])) break;
            out.emplace_back(hashes_[h], filters_[h]);
        }
        return true;
    }

    // Rollback filter chain to specified height (delete filters above this height)
    // This is critical for reorg handling - filters must stay consistent with chain tip
    bool rollback_to(uint32_t new_tip_height) {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        if (new_tip_height >= headers_.size()) return true; // Nothing to rollback

        // Clear entries above new_tip_height
        for (size_t h = new_tip_height + 1; h < headers_.size(); ++h) {
            headers_[h] = std::array<uint8_t,32>{};
            hashes_[h] = std::array<uint8_t,32>{};
            filters_[h].clear();
        }

        // Resize vectors to new height + 1
        headers_.resize(new_tip_height + 1);
        hashes_.resize(new_tip_height + 1);
        filters_.resize(new_tip_height + 1);

        // Rewrite the entire file (could be optimized with truncate but this is safer)
        return persist_full();
    }

    // Get the current filter chain tip height
    uint32_t tip_height() const {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        if (headers_.empty()) return 0;
        // Find highest non-zero entry
        for (size_t h = headers_.size(); h-- > 0; ) {
            if (!is_zero(headers_[h])) return (uint32_t)h;
        }
        return 0;
    }

private:
    mutable std::recursive_mutex mtx_;
    std::string dir_;
    std::vector<std::array<uint8_t,32>> headers_;
    std::vector<std::array<uint8_t,32>> hashes_;
    std::vector<std::vector<uint8_t>>   filters_;

    static inline bool is_zero(const std::array<uint8_t,32>& a){
        for (auto b : a) { if (b) return false; }
        return true;
    }
    static inline std::array<uint8_t,32> to_arr32(const std::vector<uint8_t>& v){
        std::array<uint8_t,32> a{};
        if (v.size() >= 32) for (int i = 0; i < 32; ++i) a[i] = v[i];
        return a;
    }

    // persistent layout: repeated records
    // [u32 height][32 hashLE][u32 flen][flen bytes][32 header]
    bool load(){
        headers_.clear(); hashes_.clear(); filters_.clear();
        std::ifstream in(path().c_str(), std::ios::binary);
        if (!in.good()) return true; // first run or no file yet
        for (;;) {
            uint32_t h = 0, fl = 0;
            if (!in.read((char*)&h, 4)) break;
            std::array<uint8_t,32> hash{}, hdr{};
            if (!in.read((char*)hash.data(), 32)) break;
            if (!in.read((char*)&fl, 4)) break;
            std::vector<uint8_t> fb;
            if (fl > 0) {
                fb.resize(fl);
                if (!in.read((char*)fb.data(), fl)) break;
            }
            if (!in.read((char*)hdr.data(), 32)) break;

            if (headers_.size() <= h) {
                headers_.resize(h + 1);
                hashes_.resize(h + 1);
                filters_.resize(h + 1);
            }
            headers_[h] = hdr;
            hashes_[h]  = hash;
            filters_[h] = std::move(fb);
        }
        return true;
    }

    bool persist_append(uint32_t h,
                        const std::array<uint8_t,32>& hash,
                        const std::array<uint8_t,32>& header,
                        const std::vector<uint8_t>& fb)
    {
        std::ofstream out(path().c_str(), std::ios::binary | std::ios::app);
        if (!out.good()) return false;
        const uint32_t fl = (uint32_t)fb.size();
        out.write((const char*)&h, 4);
        out.write((const char*)hash.data(), 32);
        out.write((const char*)&fl, 4);
        if (fl) out.write((const char*)fb.data(), fl);
        out.write((const char*)header.data(), 32);
        return out.good();
    }

    // Rewrite entire filter store (used after rollback)
    bool persist_full() {
        std::ofstream out(path().c_str(), std::ios::binary | std::ios::trunc);
        if (!out.good()) return false;
        for (uint32_t h = 0; h < headers_.size(); ++h) {
            if (is_zero(headers_[h])) continue; // Skip empty entries
            const uint32_t fl = (uint32_t)filters_[h].size();
            out.write((const char*)&h, 4);
            out.write((const char*)hashes_[h].data(), 32);
            out.write((const char*)&fl, 4);
            if (fl) out.write((const char*)filters_[h].data(), fl);
            out.write((const char*)headers_[h].data(), 32);
        }
        return out.good();
    }

    std::string path() const { return dir_ + "/store.dat"; }
};

}
}
