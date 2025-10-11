#pragma once
// Minimal on-disk store for BIP158-like block filters + rolling headers.
// Header-only to avoid build system changes.

#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <mutex>
#include <fstream>

#include "sha256.h"   // dsha256(std::vector<uint8_t>)
#include "hex.h"      // hex helpers (only for logs if you use them elsewhere)

namespace miq {
namespace gcs {

class FilterStore {
public:
    bool open(const std::string& dir) {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        dir_ = dir;
#ifdef _WIN32
        _mkdir(dir_.c_str());
#else
        ::mkdir(dir_.c_str(), 0755);
#endif
        return load();
    }

    // Append or set the filter for height; computes and stores rolling header.
    bool put(uint32_t height,
             const std::vector<uint8_t>& block_hash_le,
             const std::vector<uint8_t>& filter_bytes)
    {
        std::lock_guard<std::recursive_mutex> lk(mtx_);
        if(block_hash_le.size()!=32) return false;

        if (headers_.size() <= height) {
            headers_.resize(height+1);
            hashes_.resize(height+1);
            filters_.resize(height+1);
        }

        // filter hash = dsha256(filter_bytes)
        auto fh_vec = dsha256(filter_bytes);
        std::array<uint8_t,32> fh{};
        for (int i=0;i<32;i++) fh[i] = fh_vec[i];

        // prev header (zeros for 0 or missing)
        std::array<uint8_t,32> prev{};
        if (height>0 && headers_.size()>height && !is_zero(headers_[height-1])) {
            prev = headers_[height-1];
        } else if (height>0 && headers_.size()>0 && !is_zero(headers_.back())) {
            prev = headers_.back(); // typical append
        } // else zeros

        // header = dsha256( fh || prev )
        std::vector<uint8_t> buf; buf.reserve(64);
        buf.insert(buf.end(), fh.begin(), fh.end());
        buf.insert(buf.end(), prev.begin(), prev.end());
        auto hdr_vec = dsha256(buf);
        std::array<uint8_t,32> hdr{};
        for (int i=0;i<32;i++) hdr[i] = hdr_vec[i];

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
        if (start >= headers_.size() || count==0) return true;
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
        if (start >= filters_.size() || count==0) return true;
        const uint32_t end = (uint32_t)std::min<size_t>(filters_.size(), (size_t)start + count);
        for (uint32_t h = start; h < end; ++h) {
            if (filters_[h].empty() || is_zero(hashes_[h])) break;
            out.emplace_back(hashes_[h], filters_[h]);
        }
        return true;
    }

private:
    mutable std::recursive_mutex mtx_;
    std::string dir_;
    std::vector<std::array<uint8_t,32>> headers_;
    std::vector<std::array<uint8_t,32>> hashes_;
    std::vector<std::vector<uint8_t>>   filters_;

    static inline bool is_zero(const std::array<uint8_t,32>& a){
        for (auto b: a) if (b) return false; return true;
    }
    static inline std::array<uint8_t,32> to_arr32(const std::vector<uint8_t>& v){
        std::array<uint8_t,32> a{}; for(int i=0;i<32;i++) a[i]=v[i]; return a;
    }

    // persistent layout: repeated records
    // [u32 height][32 hashLE][u32 flen][flen bytes][32 header]
    bool load(){
        headers_.clear(); hashes_.clear(); filters_.clear();
        std::ifstream in(path().c_str(), std::ios::binary);
        if(!in.good()) return true; // first run
        while(true){
            uint32_t h=0, fl=0;
            if(!in.read((char*)&h, 4)) break;
            std::array<uint8_t,32> hash{}, hdr{};
            if(!in.read((char*)hash.data(), 32)) break;
            if(!in.read((char*)&fl, 4)) break;
            std::vector<uint8_t> fb(fl);
            if(fl>0 && !in.read((char*)fb.data(), fl)) break;
            if(!in.read((char*)hdr.data(), 32)) break;

            if(headers_.size() <= h){
                headers_.resize(h+1);
                hashes_.resize(h+1);
                filters_.resize(h+1);
            }
            headers_[h]=hdr; hashes_[h]=hash; filters_[h]=std::move(fb);
        }
        return true;
    }

    bool persist_append(uint32_t h,
                        const std::array<uint8_t,32>& hash,
                        const std::array<uint8_t,32>& header,
                        const std::vector<uint8_t>& fb)
    {
        std::ofstream out(path().c_str(), std::ios::binary | std::ios::app);
        if(!out.good()) return false;
        uint32_t fl = (uint32_t)fb.size();
        out.write((const char*)&h, 4);
        out.write((const char*)hash.data(), 32);
        out.write((const char*)&fl, 4);
        if(fl) out.write((const char*)fb.data(), fl);
        out.write((const char*)header.data(), 32);
        return out.good();
    }

    std::string path() const { return dir_ + "/store.dat"; }
};

}
}
