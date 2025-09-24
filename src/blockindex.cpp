
#include "blockindex.h"
#include "util.h"
#include <cmath>
namespace miq {
static std::string K(const std::vector<uint8_t>& h){ return hex(h); }
static long double work_from_bits(uint32_t bits){
    // Approximate chainwork: 2^(256) / (target+1) -> approximate via exponent/mantissa
    uint32_t exp = bits>>24; uint32_t mant = bits & 0x007fffff; long double t = (long double)mant * std::pow((long double)2.0, (int)8*(int)(exp-3));
    long double w = std::pow((long double)2.0, 256) / (t + 1.0L);
    return w;
}
void BlockIndex::reset(const std::vector<uint8_t>& genesis_hash, int64_t time, uint32_t bits){
    map_.clear(); tip_.reset();
    auto g = std::make_shared<HeaderRec>(); g->hash=genesis_hash; g->prev=std::vector<uint8_t>(32,0); g->time=time; g->bits=bits; g->height=0; g->chainwork=work_from_bits(bits); map_[K(g->hash)]=g; tip_=g;
}
std::shared_ptr<HeaderRec> BlockIndex::add_header(const BlockHeader& h, const std::vector<uint8_t>& real_hash){
    auto it = map_.find(K(h.prev_hash)); if(it==map_.end()) return nullptr;
    auto rec = std::make_shared<HeaderRec>(); rec->hash = real_hash; rec->prev = h.prev_hash; rec->time=h.time; rec->bits=h.bits; rec->parent=it->second; rec->height=rec->parent->height+1;
    rec->chainwork = rec->parent->chainwork + work_from_bits(h.bits);
    map_[K(rec->hash)]=rec; if(!tip_ || rec->chainwork > tip_->chainwork) tip_=rec; return rec;
}
std::vector<std::vector<uint8_t>> BlockIndex::locator() const{
    std::vector<std::vector<uint8_t>> v; auto cur=tip_; int step=1; int count=0;
    while(cur && count<32){ v.push_back(cur->hash); for(int i=0;i<step && cur->parent;i++) cur=cur->parent; if(count>=10) step*=2; ++count; }
    return v;
}
}
