
#include "ripemd160.h"
#include <cstring>
namespace miq {
// Compact public-domain style RIPEMD-160 implementation (non-optimized)
static inline uint32_t rotl(uint32_t x, int n){ return (x<<n) | (x>>(32-n)); }
static inline uint32_t f1(uint32_t x,uint32_t y,uint32_t z){ return x ^ y ^ z; }
static inline uint32_t f2(uint32_t x,uint32_t y,uint32_t z){ return (x & y) | (~x & z); }
static inline uint32_t f3(uint32_t x,uint32_t y,uint32_t z){ return (x | ~y) ^ z; }
static inline uint32_t f4(uint32_t x,uint32_t y,uint32_t z){ return (x & z) | (y & ~z); }
static inline uint32_t f5(uint32_t x,uint32_t y,uint32_t z){ return x ^ (y | ~z); }
static const int r1[16]={11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8};
static const int r2[16]={12,13,11,15,6,7,9,8,13,12,11,15,6,7,9,8};
static const int r3[16]={11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5};
static const int r4[16]={11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12};
static const int r5[16]={9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6};
static const int rr1[16]={8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6};
static const int rr2[16]={9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11};
static const int rr3[16]={9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5};
static const int rr4[16]={15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8};
static const int rr5[16]={8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11};
static const int idx1[16]={0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const int idx2[16]={7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8};
static const int idx3[16]={3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12};
static const int idx4[16]={1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2};
static const int idx5[16]={4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13};
std::vector<uint8_t> ripemd160(const std::vector<uint8_t>& data){
    uint32_t h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
    std::vector<uint8_t> msg = data;
    uint64_t ml = (uint64_t)msg.size()*8;
    msg.push_back(0x80);
    while((msg.size()%64)!=56) msg.push_back(0);
    for(int i=0;i<8;i++) msg.push_back((ml>>(8*i))&0xff);
    for(size_t off=0; off<msg.size(); off+=64){
        uint32_t x[16];
        for(int i=0;i<16;i++){
            x[i]= msg[off+i*4] | (msg[off+i*4+1]<<8) | (msg[off+i*4+2]<<16) | (msg[off+i*4+3]<<24);
        }
        uint32_t al=h0, bl=h1, cl=h2, dl=h3, el=h4;
        uint32_t ar=h0, br=h1, cr=h2, dr=h3, er=h4;
        // rounds
        for(int i=0;i<16;i++){ al=rotl(al+f1(bl,cl,dl)+x[idx1[i]], r1[i]); std::swap(al,el); std::swap(el,dl); std::swap(dl,cl); std::swap(cl,bl); }
        for(int i=0;i<16;i++){ ar=rotl(ar+f5(br,cr,dr)+x[idx5[i]]+0x50a28be6, rr1[i]); std::swap(ar,er); std::swap(er,dr); std::swap(dr,cr); std::swap(cr,br); }
        for(int i=0;i<16;i++){ al=rotl(al+f2(bl,cl,dl)+x[idx2[i]]+0x5a827999, r2[i]); std::swap(al,el); std::swap(el,dl); std::swap(dl,cl); std::swap(cl,bl); }
        for(int i=0;i<16;i++){ ar=rotl(ar+f4(br,cr,dr)+x[idx4[i]]+0x5c4dd124, rr2[i]); std::swap(ar,er); std::swap(er,dr); std::swap(dr,cr); std::swap(cr,br); }
        for(int i=0;i<16;i++){ al=rotl(al+f3(bl,cl,dl)+x[idx3[i]]+0x6ed9eba1, r3[i]); std::swap(al,el); std::swap(el,dl); std::swap(dl,cl); std::swap(cl,bl); }
        for(int i=0;i<16;i++){ ar=rotl(ar+f3(br,cr,dr)+x[idx3[i]]+0x6d703ef3, rr3[i]); std::swap(ar,er); std::swap(er,dr); std::swap(dr,cr); std::swap(cr,br); }
        for(int i=0;i<16;i++){ al=rotl(al+f4(bl,cl,dl)+x[idx4[i]]+0x8f1bbcdc, r4[i]); std::swap(al,el); std::swap(el,dl); std::swap(dl,cl); std::swap(cl,bl); }
        for(int i=0;i<16;i++){ ar=rotl(ar+f2(br,cr,dr)+x[idx2[i]]+0x7a6d76e9, rr4[i]); std::swap(ar,er); std::swap(er,dr); std::swap(dr,cr); std::swap(cr,br); }
        for(int i=0;i<16;i++){ al=rotl(al+f5(bl,cl,dl)+x[idx5[i]]+0xa953fd4e, r5[i]); std::swap(al,el); std::swap(el,dl); std::swap(dl,cl); std::swap(cl,bl); }
        for(int i=0;i<16;i++){ ar=rotl(ar+f1(br,cr,dr)+x[idx1[i]], rr5[i]); std::swap(ar,er); std::swap(er,dr); std::swap(dr,cr); std::swap(cr,br); }
        uint32_t t=h1 + cl + dr;
        h1 = h2 + dl + er;
        h2 = h3 + el + ar;
        h3 = h4 + al + br;
        h4 = h0 + bl + cr;
        h0 = t;
    }
    std::vector<uint8_t> out(20);
    uint32_t hs[5]={h0,h1,h2,h3,h4};
    for(int i=0;i<5;i++){ out[i*4]=hs[i]&0xff; out[i*4+1]=(hs[i]>>8)&0xff; out[i*4+2]=(hs[i]>>16)&0xff; out[i*4+3]=(hs[i]>>24)&0xff; }
    return out;
}
}
