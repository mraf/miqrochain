#include "blockindex.h"
#include "util.h"      // hex(), to_hex helpers consistent with your codebase
#include <cmath>
#include <algorithm>

namespace miq {

// Convert 32-byte hash vector to hex key for maps.
static std::string K(const std::vector<uint8_t>& h){ return hex(h); }

// Convert compact 'bits' to an approximate "work" measure.
// work ≈ 2^256 / (target + 1)
static long double work_from_bits(uint32_t bits){
    // bits = (exp << 24) | mant (23 bits)
    const uint32_t exp  = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;

    // target ≈ mant * 2^(8*(exp-3))
    long double target = static_cast<long double>(mant);
    int shift = 8 * (static_cast<int>(exp) - 3);
    target = std::ldexp(target, shift); // target *= 2^shift

    long double two256 = std::ldexp(1.0L, 256);
    long double w = two256 / (target + 1.0L);
    return w;
}

void BlockIndex::reset(const std::vector<uint8_t>& genesis_hash, int64_t time, uint32_t bits){
    map_.clear();
    children_.clear();
    tip_.reset();
    best_body_.reset();

    auto g = std::make_shared<HeaderRec>();
    g->hash  = genesis_hash;
    g->prev  = std::vector<uint8_t>(32, 0);
    g->time  = time;
    g->bits  = bits;
    g->height = 0;
    g->chainwork = work_from_bits(bits);
    g->parent.reset();
    g->have_body = false; // set to true by caller after connecting genesis

    map_[K(g->hash)] = g;
    tip_ = g;
}

std::shared_ptr<HeaderRec> BlockIndex::add_header(const BlockHeader& h,
                                                  const std::vector<uint8_t>& real_hash){
    // Parent must be known for a well-formed extension.
    auto pit = map_.find(K(h.prev_hash));
    if(pit == map_.end()){
        return nullptr; // unknown parent; caller can queue for later
    }

    auto rec = std::make_shared<HeaderRec>();
    rec->hash   = real_hash;
    rec->prev   = h.prev_hash;
    rec->time   = h.time;
    rec->bits   = h.bits;
    rec->parent = pit->second;
    rec->height = rec->parent->height + 1;
    rec->chainwork = rec->parent->chainwork + work_from_bits(h.bits);
    rec->have_body = false;

    // Insert into maps.
    map_[K(rec->hash)] = rec;
    children_[K(rec->parent->hash)].push_back(rec);

    // Update best header tip by cumulative work.
    if(!tip_ || rec->chainwork > tip_->chainwork){
        tip_ = rec;
    }
    return rec;
}

void BlockIndex::set_have_body(const std::vector<uint8_t>& h){
    auto it = map_.find(K(h));
    if(it == map_.end()) return;

    auto& rec = it->second;
    rec->have_body = true;

    // Track best connected body tip by height (you could also compare chainwork).
    if(!best_body_ || rec->height > best_body_->height){
        best_body_ = rec;
    }
}

std::vector<std::vector<uint8_t>> BlockIndex::locator() const{
    std::vector<std::vector<uint8_t>> v;
    auto cur = tip_;
    int step = 1;
    int count = 0;

    while(cur && count < 32){
        v.push_back(cur->hash);

        // Walk back 'step' times if possible
        for(int i=0; i<step && cur->parent; ++i){
            cur = cur->parent;
        }
        if(count >= 10) step <<= 1; // powers of two after the first 10
        ++count;
    }

    // Optionally include genesis (root)
    // Find root by walking up from tip_
    if(tip_){
        auto root = tip_;
        while(root->parent) root = root->parent;
        if(v.empty() || K(v.back()) != K(root->hash)){
            v.push_back(root->hash);
        }
    }

    return v;
}

std::shared_ptr<HeaderRec> BlockIndex::find_fork(const std::vector<std::vector<uint8_t>>& locator) const{
    // Return the first locator hash we know about; otherwise fall back to root.
    for(const auto& h : locator){
        auto it = map_.find(K(h));
        if(it != map_.end()){
            return it->second;
        }
    }
    // Fallback: return root (walk parents from tip_)
    if(!tip_) return nullptr;
    auto cur = tip_;
    while(cur->parent) cur = cur->parent;
    return cur;
}

std::shared_ptr<HeaderRec> BlockIndex::next_on_best_header_chain(const std::shared_ptr<HeaderRec>& cur) const{
    if(!cur) return nullptr;
    auto it = children_.find(K(cur->hash));
    if(it == children_.end() || it->second.empty()) return nullptr;

    // Heuristic: pick the child with the greatest chainwork.
    // Since tip_ is the highest chainwork header, repeatedly choosing the
    // greatest chainwork child walks toward tip_ along a best-work path.
    const auto& kids = it->second;
    auto best = kids.front();
    for(const auto& c : kids){
        if(c->chainwork > best->chainwork){
            best = c;
        }
    }
    return best;
}

}
