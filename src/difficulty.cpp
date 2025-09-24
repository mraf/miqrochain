
#include "difficulty.h"
namespace miq {
static inline uint32_t compact_from_target(const unsigned char* t){ int i=0; while(i<32 && t[i]==0) ++i; if(i==32) return 0; uint32_t exp=32-i; uint32_t mant=(t[i]<<16)|(t[i+1]<<8)|t[i+2]; return (exp<<24)|(mant&0x007fffff); }
static inline void target_from_compact(uint32_t bits, unsigned char* out){ for(int i=0;i<32;i++) out[i]=0; uint32_t exp=bits>>24; uint32_t mant=bits&0x007fffff; if(exp<=3){ uint32_t v=mant>>(8*(3-exp)); out[29]=(v>>16)&0xff; out[30]=(v>>8)&0xff; out[31]=v&0xff; } else { int idx=32-exp; out[idx]=(mant>>16)&0xff; out[idx+1]=(mant>>8)&0xff; out[idx+2]=mant&0xff; } }
uint32_t lwma_next_bits(const std::vector<std::pair<int64_t,uint32_t>>& last, int64_t target_spacing, uint32_t min_bits){
    if(last.size()<2) return min_bits; size_t window = last.size()<90?last.size():90; int64_t sum=0;
    for(size_t i=last.size()-window+1;i<last.size();++i){ int64_t dt=last[i].first-last[i-1].first; if(dt<1) dt=1; if(dt>target_spacing*10) dt=target_spacing*10; sum+=dt; }
    int64_t avg=sum/(int64_t(window-1)); unsigned char t[32]; target_from_compact(last.back().second, t);
    for(int i=31;i>=0;--i){ unsigned int v=t[i]; v=(unsigned int)((uint64_t)v*(uint64_t)avg/(uint64_t)target_spacing); if(v>255) v=255; t[i]=(unsigned char)v; }
    return compact_from_target(t);
}
}
