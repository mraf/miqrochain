#include "reorg_manager.h"
#include <algorithm>
#include <cmath>

namespace miq {

// --------- small helpers ---------
static inline char hexch(unsigned x){ return (char)(x<10 ? '0'+x : 'a'+(x-10)); }

std::string ReorgManager::hexkey(const HashBytes& h){
    std::string s; s.resize(h.size()*2);
    for(size_t i=0;i<h.size();++i){ unsigned v=h[i]; s[2*i]=hexch(v>>4); s[2*i+1]=hexch(v&0xF); }
    return s;
}

// Approx chainwork from compact 'bits' (adequate for ordering).
long double ReorgManager::work_from_bits(uint32_t bits){
    // bits: exponent in high byte, mantissa in low 23 bits (Bitcoin-style "compact")
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if(mant == 0 || exp < 3) return 0.0L;

    // target ≈ mant * 2^(8*(exp-3))
    // work   ≈ 2^256 / (target+1)
    // We compute log-space friendly approximation with long double.
    // Equivalent to: work ≈ 2^(256) / (mant * 2^(8*(exp-3)))
    // => work ≈ 2^(256 - 8*(exp-3)) / mant
    int power = 256 - 8 * ((int)exp - 3);
    // ldexp(1.0L, power) gives 2^power
    long double num = std::ldexp(1.0L, power);
    return (mant ? (num / (long double)mant) : 0.0L);
}

// --------- public API ---------

void ReorgManager::reset(){
    map_.clear();
    best_.reset();
}

void ReorgManager::init_genesis(const HashBytes& genesis_hash, uint32_t bits, int64_t time){
    map_.clear();
    best_.reset();
    auto g = std::make_shared<Node>();
    g->hash = genesis_hash;
    g->prev = HashBytes(genesis_hash.size(), 0);
    g->bits = bits;
    g->time = time;
    g->height = 0;
    g->chainwork = work_from_bits(bits);
    map_[hexkey(g->hash)] = g;
    best_ = g;
}

bool ReorgManager::on_validated_header(const HeaderView& h){
    auto itp = map_.find(hexkey(h.prev));
    if(itp == map_.end()) return false; // parent unknown
    // If already have this header, ignore
    if(map_.find(hexkey(h.hash)) != map_.end()) return true;

    auto n = std::make_shared<Node>();
    n->hash = h.hash;
    n->prev = h.prev;
    n->bits = h.bits;
    n->time = h.time;
    n->parent = itp->second;
    n->height = n->parent->height + 1;
    n->chainwork = n->parent->chainwork + work_from_bits(h.bits);

    map_[hexkey(n->hash)] = n;
    if(!best_ || n->chainwork > best_->chainwork) best_ = n;
    return true;
}

HashBytes ReorgManager::best_tip() const{
    return best_ ? best_->hash : HashBytes{};
}

bool ReorgManager::plan_reorg(const HashBytes& current_active_tip,
                              std::vector<HashBytes>& out_disconnect,
                              std::vector<HashBytes>& out_connect) const
{
    out_disconnect.clear();
    out_connect.clear();
    if(!best_) return false;

    // Find current node & best node in index
    auto find_node = [&](const HashBytes& h)->std::shared_ptr<Node>{
        auto it = map_.find(hexkey(h)); return (it==map_.end()? nullptr : it->second);
    };
    auto cur = find_node(current_active_tip);
    auto bst = best_;
    if(!cur || !bst) return false;
    if(cur->hash == bst->hash) return false; // already on best chain

    // Walk back until common ancestor; collect paths
    std::vector<std::shared_ptr<Node>> a_path, b_path;
    auto a = cur; auto b = bst;
    while(a && b && a->hash != b->hash){
        if(a->height >= b->height){ a_path.push_back(a); a = a->parent; }
        else { b_path.push_back(b); b = b->parent; }
    }
    // If we ran off either, no common ancestor (shouldn't happen with init_genesis)
    if(!a || !b) return false;

    // a is common ancestor now
    // Disconnect A path (from tip down to but excluding ancestor)
    for(auto& n : a_path){ out_disconnect.push_back(n->hash); }
    // Connect B path (from ancestor->child up to best)
    std::reverse(b_path.begin(), b_path.end());
    for(auto& n : b_path){ out_connect.push_back(n->hash); }

    return !out_disconnect.empty() || !out_connect.empty();
}

}
