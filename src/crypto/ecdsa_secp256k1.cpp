#include "ecdsa_secp256k1.h"
#include "../sha256.h"
#include <array>
#include <random>
#include <cstring>
#include <cassert>
#include <vector>

#if defined(_MSC_VER)
#include <intrin.h>
static inline void mul128_u64(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi){ *lo = _umul128(a,b,hi); }
static inline uint64_t addc_u64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out){
    unsigned __int64 out; unsigned char c = _addcarry_u64((unsigned char)carry_in, a, b, &out); *carry_out = (uint64_t)c; return (uint64_t)out;
}
static inline uint64_t subb_u64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out){
    unsigned __int64 out; unsigned char c = _subborrow_u64((unsigned char)borrow_in, a, b, &out); *borrow_out = (uint64_t)c; return (uint64_t)out;
}
#else
static inline void mul128_u64(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi){ unsigned __int128 t=(unsigned __int128)a*b; *lo=(uint64_t)t; *hi=(uint64_t)(t>>64); }
static inline uint64_t addc_u64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out){ unsigned __int128 t=(unsigned __int128)a+b+carry_in; *carry_out=(uint64_t)(t>>64); return (uint64_t)t; }
static inline uint64_t subb_u64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out){ unsigned __int128 t=(unsigned __int128)a - b - borrow_in; *borrow_out=(uint64_t)((t>>127)&1); return (uint64_t)t; }
#endif


namespace miq { namespace crypto {

// ----- Simple 256-bit integer and field arithmetic over secp256k1 -----
struct U256{ uint64_t v[4]{}; };
static inline U256 U256_from_be(const uint8_t b[32]){ U256 x; for(int i=0;i<4;i++){ x.v[3-i]= ((uint64_t)b[i*8+0]<<56)|((uint64_t)b[i*8+1]<<48)|((uint64_t)b[i*8+2]<<40)|((uint64_t)b[i*8+3]<<32)|((uint64_t)b[i*8+4]<<24)|((uint64_t)b[i*8+5]<<16)|((uint64_t)b[i*8+6]<<8)|((uint64_t)b[i*8+7]); } return x; }
static inline void U256_to_be(const U256& x, uint8_t b[32]){ for(int i=0;i<4;i++){ uint64_t w=x.v[3-i]; b[i*8+0]=(w>>56)&0xff; b[i*8+1]=(w>>48)&0xff; b[i*8+2]=(w>>40)&0xff; b[i*8+3]=(w>>32)&0xff; b[i*8+4]=(w>>24)&0xff; b[i*8+5]=(w>>16)&0xff; b[i*8+6]=(w>>8)&0xff; b[i*8+7]=w&0xff; } }
static inline bool U256_is_zero(const U256& a){ return !(a.v[0]|a.v[1]|a.v[2]|a.v[3]); }
static inline int U256_cmp(const U256& a,const U256& b){ for(int i=3;i>=0;--i){ if(a.v[i]<b.v[i]) return -1; if(a.v[i]>b.v[i]) return 1; } return 0; }

// --- fixed bracing (from previous step) ---
static inline U256 U256_add(const U256& a,const U256& b,uint64_t*carry){
    U256 r{}; uint64_t c=0;
    for(int i=0;i<4;i++){ r.v[i]=addc_u64(a.v[i], b.v[i], c, &c); }
    if(carry) *carry=c;
    return r;
}
static inline U256 U256_sub(const U256& a,const U256& b,uint64_t*borrow){
    U256 r{}; uint64_t br=0;
    for(int i=0;i<4;i++){ r.v[i]=subb_u64(a.v[i], b.v[i], br, &br); }
    if(borrow) *borrow=br;
    return r;
}
struct U512{ uint64_t w[8]{}; };
static inline U512 U256_mul(const U256& a,const U256& b){
    U512 r{};
    for(int i=0;i<4;i++){
        uint64_t c=0;
        for(int j=0;j<4;j++){
            uint64_t lo, hi; mul128_u64(a.v[i], b.v[j], &lo, &hi);
            uint64_t sum = r.w[i+j];
            uint64_t carry1; sum = addc_u64(sum, lo, 0, &carry1);
            uint64_t carry2; r.w[i+j] = addc_u64(sum, c, 0, &carry2);
            c = hi + carry1 + carry2;
        }
        r.w[i+4] += c;
    }
    return r;
}
// -----------------------------------------

static inline U256 U512_mod(const U512& x,const U256& m){ U512 r=x; auto ge=[&](const U512&A,const U256&B,int s){ for(int i=7;i>=0;--i){ uint64_t a=A.w[i]; uint64_t b=(i-s>=0 && i-s<4)?B.v[i-s]:0; if(a<b) return false; if(a>b) return true; } return true; }; auto sub=[&](U512&A,const U256&B,int s){ __int128 c=0; for(int i=0;i<8;i++){ int bi=i-s; unsigned __int128 b=(bi>=0&&bi<4)?B.v[bi]:0; __int128 t=(__int128)A.w[i]-b-c; A.w[i]=(uint64_t)t; c=t<0; } }; for(int s=7;s>=0;--s){ while(ge(r,m,s)) sub(r,m,s); } U256 o; for(int i=0;i<4;i++) o.v[i]=r.w[i]; return o; }
static inline U256 U256_mod_add(const U256&a,const U256&b,const U256&m){ uint64_t c; U256 s=U256_add(a,b,&c); if(c||U256_cmp(s,m)>=0) s=U256_sub(s,m,nullptr); return s; }
static inline U256 U256_mod_sub(const U256&a,const U256&b,const U256&m){ uint64_t br; U256 s=U256_sub(a,b,&br); if(br) s=U256_add(s,m,nullptr); return s; }
static inline U256 U256_mod_mul(const U256&a,const U256&b,const U256&m){ return U512_mod(U256_mul(a,b),m); }
static U256 U256_mod_inv(U256 a, U256 m){
    U256 lm{{1,0,0,0}}, hm{{0,0,0,0}};
    U256 low=a, high=m;
    auto isz=[&](const U256&x){return U256_is_zero(x);};
    auto divmod=[&](const U256&num,const U256&den,U256&q,U256&r){
        q={{0,0,0,0}}; r=num;
        for(int i=255;i>=0;--i){
            // den<<i
            U256 d{{0,0,0,0}}; int limb=i/64,b=i%64; unsigned __int128 carry=0;
            for(int j=3;j>=0;--j){
                unsigned __int128 val=(j-limb>=0)?(unsigned __int128)den.v[j-limb]:0; val=(val<<b)|carry; d.v[j]=(uint64_t)val; carry=val>>64;
            }
            if(U256_cmp(r,d)>=0){
                r=U256_sub(r,d,nullptr);
                q.v[i/64]|=(uint64_t)1<<(i%64);
            }
        }
    };
    while(!isz(low)){
        U256 q,nr; divmod(high,low,q,nr);
        U256 tmp=U256_mod_mul(q,lm,m);
        U256 nm=U256_mod_sub(hm,tmp,m);
        hm=lm; high=low; lm=nm; low=nr;
    }
    return hm;
}

// Curve constants
static const U256 P = U256_from_be((const uint8_t*)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xfc\x2f");
static const U256 N = U256_from_be((const uint8_t*)"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41");
static const U256 Gx= U256_from_be((const uint8_t*)"\x79\xbe\x66\x7e\xf9\xdc\xbb\xac\x55\xa0\x62\x95\xce\x87\x0b\x07\x02\x9b\xfc\xdb\x2d\xce\x28\xd9\x59\xf2\x81\x5b\x16\xf8\x17\x98");
static const U256 Gy= U256_from_be((const uint8_t*)"\x48\x3a\xda\x77\x26\xa3\xc4\x65\x5d\xa4\xfb\xfc\x0e\x11\x08\xa8\xfd\x17\xb4\x48\xa6\x85\x54\x19\x9c\x47\xd0\x8f\xfb\x10\xd4\xb8");

struct Fp{ U256 n; };
static inline Fp Fp_fromU(const U256&a){ Fp r; r.n = (U256_cmp(a,P)>=0) ? U256_mod_sub(a,P,P) : a; return r; }
static inline Fp Fp_add(const Fp&a,const Fp&b){ return Fp_fromU(U256_mod_add(a.n,b.n,P)); }
static inline Fp Fp_sub(const Fp&a,const Fp&b){ return Fp_fromU(U256_mod_sub(a.n,b.n,P)); }
static inline Fp Fp_mul(const Fp&a,const Fp&b){ return Fp_fromU(U256_mod_mul(a.n,b.n,P)); }
static inline Fp Fp_inv(const Fp&a){ Fp r; r.n=U256_mod_inv(a.n,P); return r; }
static inline Fp Fp_sqr(const Fp&a){ return Fp_mul(a,a); }

struct Point{ Fp X,Y,Z; bool inf; };
static inline Point Inf(){ Point p; p.inf=true; p.Z=Fp_fromU(U256{{0,0,0,0}}); return p; }
static inline bool isInf(const Point&p){ return p.inf || (p.Z.n.v[0]==0 && p.Z.n.v[1]==0 && p.Z.n.v[2]==0 && p.Z.n.v[3]==0); }
static inline Point G(){ Point p; p.X=Fp_fromU(Gx); p.Y=Fp_fromU(Gy); p.Z=Fp_fromU(U256{{1,0,0,0}}); p.inf=false; return p; }

static Point dbl(const Point&P){
    if(isInf(P)) return P;
    Fp XX=Fp_sqr(P.X);
    Fp YY=Fp_sqr(P.Y);
    Fp YYYY=Fp_sqr(YY);
    Fp S = Fp_mul(Fp_mul(P.X, YY), Fp_fromU(U256{{4,0,0,0}}));
    Fp M = Fp_add(Fp_add(XX,XX),XX); // 3*XX
    Fp X3=Fp_sub(Fp_sqr(M), Fp_add(S,S));
    Fp Y3=Fp_sub(Fp_mul(M, Fp_sub(S, X3)), Fp_mul(Fp_fromU(U256{{8,0,0,0}}), YYYY));
    Fp Z3=Fp_mul(Fp_add(P.Y,P.Y), P.Z);
    Point R{X3,Y3,Z3,false}; return R;
}

static Point add(const Point&P,const Point&Q){
    if(isInf(P)) return Q; if(isInf(Q)) return P;
    Fp Z1Z1=Fp_sqr(P.Z);
    Fp Z2Z2=Fp_sqr(Q.Z);
    Fp U1=Fp_mul(P.X, Z2Z2);
    Fp U2=Fp_mul(Q.X, Z1Z1);
    Fp S1=Fp_mul(Fp_mul(P.Y,Q.Z), Z2Z2);
    Fp S2=Fp_mul(Fp_mul(Q.Y,P.Z), Z1Z1);

    // disambiguate the curve prime P from the parameter P
    U256 H_=U256_mod_sub(U2.n, U1.n, ::miq::crypto::P); Fp H=Fp_fromU(H_);
    U256 r_=U256_mod_sub(S2.n, S1.n, ::miq::crypto::P); r_=U256_mod_add(r_, r_, ::miq::crypto::P); Fp r=Fp_fromU(r_);

    if(U256_is_zero(H.n)){ if(U256_is_zero(r.n)) return dbl(P); return Inf(); }
    Fp I = Fp_sqr(Fp_fromU(U256_mod_add(H.n, H.n, ::miq::crypto::P)));
    Fp J = Fp_mul(H, I);
    Fp V = Fp_mul(U1, I);
    Fp X3 = Fp_sub(Fp_sub(Fp_sqr(r), J), Fp_add(V,V));
    Fp Y3 = Fp_sub(Fp_mul(r, Fp_sub(V, X3)), Fp_mul(Fp_fromU(U256_mod_add(S1.n,S1.n, ::miq::crypto::P)), J));
    Fp Z3 = Fp_mul(Fp_mul(Fp_sub(Fp_add(P.Z,Q.Z), Fp_add(Z1Z1,Z2Z2)), Fp_fromU(U256{{1,0,0,0}})), H); // (Z1+Z2)^2 - Z1Z1 - Z2Z2 = 2*Z1*Z2 ; then * H
    Point R{X3,Y3,Z3,false}; return R;
}

static Point mul(const U256& k,const Point&P){
    Point R=Inf();
    for(int i=255;i>=0;--i){
        R=dbl(R);
        if( (k.v[i/64]>>(i%64)) & 1 ) R=add(R,P);
    }
    return R;
}

static Point to_affine(const Point&P){
    if(isInf(P)) return P;
    Fp Zi = Fp_inv(P.Z); Fp Zi2=Fp_sqr(Zi); Fp Zi3=Fp_mul(Zi2,Zi);
    Point A{Fp_mul(P.X,Zi2), Fp_mul(P.Y,Zi3), Fp_fromU(U256{{1,0,0,0}}), false};
    return A;
}

static void HMAC_SHA256(const uint8_t*key,size_t key_len,const uint8_t*msg,size_t msg_len,uint8_t out[32]){
    using namespace miq;
    std::vector<uint8_t> k(64,0);
    if(key_len>64){ auto t=sha256(std::vector<uint8_t>(key,key+key_len)); std::copy(t.begin(),t.end(),k.begin()); }
    else std::copy(key,key+key_len,k.begin());
    std::vector<uint8_t> o(64,0x5c), i(64,0x36);
    for(size_t j=0;j<64;j++){ o[j]^=k[j]; i[j]^=k[j]; }
    auto i_b = sha256(i); i_b.insert(i_b.end(), msg, msg+msg_len); i_b = sha256(i_b);
    auto o_b = sha256(o); o_b.insert(o_b.end(), i_b.begin(), i_b.end()); auto h = sha256(o_b);
    std::copy(h.begin(),h.end(),out);
}

static U256 rfc6979(const U256& x, const U256& z, const U256& n){
    uint8_t K[32]={0}; uint8_t V[32]; for(int i=0;i<32;i++) V[i]=0x01;
    uint8_t bx[32], bz[32]; U256_to_be(x,bx); U256_to_be(z,bz);
    std::vector<uint8_t> m; m.insert(m.end(), V, V+32); m.push_back(0x00); m.insert(m.end(), bx, bx+32); m.insert(m.end(), bz, bz+32);
    HMAC_SHA256(K,32,m.data(),m.size(),K); HMAC_SHA256(K,32,V,32,V);
    m.clear(); m.insert(m.end(), V, V+32); m.push_back(0x01); m.insert(m.end(), bx, bx+32); m.insert(m.end(), bz, bz+32);
    HMAC_SHA256(K,32,m.data(),m.size(),K); HMAC_SHA256(K,32,V,32,V);
    while(true){ HMAC_SHA256(K,32,V,32,V); U256 k=U256_from_be(V); // reduce
        U512 prod{}; prod.w[0]=k.v[0]; prod.w[1]=k.v[1]; prod.w[2]=k.v[2]; prod.w[3]=k.v[3]; U256 kk=U512_mod(prod,n); if(U256_is_zero(kk)||U256_cmp(kk,n)>=0) continue; return kk; }
}

bool Secp256k1::generate_priv(std::vector<uint8_t>& out32){
    std::random_device rd; out32.resize(32); for(auto&i:out32) i=(uint8_t)rd(); if(out32[0]==0) out32[0]=1; return true;
}

bool Secp256k1::derive_pub_uncompressed(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out64){
    if(priv.size()!=32) return false; U256 d=U256_from_be(priv.data()); if(U256_is_zero(d) || U256_cmp(d,N)>=0) return false;
    Point Q = to_affine(mul(d, G())); uint8_t xb[32], yb[32]; U256_to_be(Q.X.n, xb); U256_to_be(Q.Y.n, yb);
    out64.assign(xb, xb+32); out64.insert(out64.end(), yb, yb+32); return true;
}

bool Secp256k1::compress_pub(const std::vector<uint8_t>& pub64, std::vector<uint8_t>& out33){
    if(pub64.size()!=64) return false; out33.resize(33); out33[0] = (pub64[63]&1)?0x03:0x02; std::copy(pub64.begin(), pub64.begin()+32, out33.begin()+1); return true;
}

bool Secp256k1::decompress_pub(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64){
    if(in33.size()!=33) return false; uint8_t prefix=in33[0]; if(prefix!=0x02 && prefix!=0x03) return false;
    U256 X=U256_from_be(&in33[1]);
    Fp x = Fp_fromU(X); Fp rhs = Fp_add(Fp_mul(Fp_sqr(x), x), Fp_fromU(U256_from_be((const uint8_t*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07")));
    // (p+1)/4
    U256 e = U256_from_be((const uint8_t*)"\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfb");
    // pow via square-and-multiply
    auto pow = [&](Fp a, U256 ee){ Fp r=Fp_fromU(U256{{1,0,0,0}}); for(int i=0;i<256;i++){ if( (ee.v[i/64]>>(i%64)) & 1 ) r=Fp_mul(r,a); a=Fp_sqr(a); } return r; };
    Fp y = pow(rhs, e);
    uint8_t yb[32]; U256_to_be(y.n, yb);
    if( (yb[31]&1) != (prefix&1) ){ // y = p - y
        U256 yy = U256_mod_sub(U256_from_be(yb), P, P); y.n = yy;
    }
    uint8_t xb[32]; U256_to_be(x.n, xb);
    out64.assign(xb, xb+32); out64.insert(out64.end(), yb, yb+32); return true;
}

bool Secp256k1::sign_rfc6979(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){
    if(priv.size()!=32 || msg32.size()!=32) return false; U256 d=U256_from_be(priv.data()); if(U256_is_zero(d)||U256_cmp(d,N)>=0) return false; U256 z=U256_from_be(msg32.data());
    for(int tries=0; tries<32; ++tries){
        U256 k = rfc6979(d,z,N);
        Point R = to_affine(mul(k, G()));
        U256 r = R.X.n; U512 rr{}; rr.w[0]=r.v[0]; rr.w[1]=r.v[1]; rr.w[2]=r.v[2]; rr.w[3]=r.v[3]; U256 rN=U512_mod(rr,N);
        if(U256_is_zero(rN)) continue;
        U256 kinv = U256_mod_inv(k,N);
        U256 rd = U256_mod_mul(rN,d,N);
        U256 s = U256_mod_mul(kinv, U256_mod_add(z, rd, N), N);
        // low-s
        U256 halfN = U256_sub(N, U256{{0,0,0,1}}, nullptr); // rough
        if(U256_cmp(s, halfN)>0) s = U256_mod_sub(N, s, N);
        uint8_t rb[32], sb[32]; U256_to_be(rN, rb); U256_to_be(s, sb);
        sig64.assign(rb, rb+32); sig64.insert(sig64.end(), sb, sb+32); return true;
    }
    return false;
}

bool Secp256k1::verify(const std::vector<uint8_t>& pub64, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){
    if(pub64.size()!=64 || msg32.size()!=32 || sig64.size()!=64) return false;
    U256 r=U256_from_be(sig64.data()), s=U256_from_be(sig64.data()+32); if(U256_is_zero(r)||U256_is_zero(s)||U256_cmp(r,N)>=0||U256_cmp(s,N)>=0) return false;
    U256 z=U256_from_be(msg32.data());
    U256 w=U256_mod_inv(s,N); U256 u1=U256_mod_mul(z,w,N); U256 u2=U256_mod_mul(r,w,N);
    U256 X=U256_from_be(pub64.data()), Y=U256_from_be(pub64.data()+32);
    Point Q; Q.X=Fp_fromU(X); Q.Y=Fp_fromU(Y); Q.Z=Fp_fromU(U256{{1,0,0,0}}); Q.inf=false;
    Point Xp = add(mul(u1,G()), mul(u2,Q)); if(isInf(Xp)) return false; Xp=to_affine(Xp);
    U512 xr{}; xr.w[0]=Xp.X.n.v[0]; xr.w[1]=Xp.X.n.v[1]; xr.w[2]=Xp.X.n.v[2]; xr.w[3]=Xp.X.n.v[3]; U256 xrn=U512_mod(xr,N);
    return U256_cmp(xrn,r)==0;
}

std::string Secp256k1::name(){ return "secp256k1 (built-in, RFC6979)"; }

}} // ns

// -------- C bridge for vendor/microecc/uECC.c ---------
extern "C" {
int miq_secp_make_key(uint8_t *pub64, uint8_t *priv32){
    std::vector<uint8_t> priv; if(!miq::crypto::Secp256k1::generate_priv(priv)) return 0;
    std::vector<uint8_t> pub64v; if(!miq::crypto::Secp256k1::derive_pub_uncompressed(priv, pub64v)) return 0;
    std::memcpy(priv32, priv.data(), 32); std::memcpy(pub64, pub64v.data(), 64); return 1;
}
int miq_secp_sign_det(const uint8_t *priv32, const uint8_t *msg32, uint8_t *sig64){
    std::vector<uint8_t> p(priv32, priv32+32), m(msg32, msg32+32), s;
    if(!miq::crypto::Secp256k1::sign_rfc6979(p,m,s)) return 0;
    std::memcpy(sig64, s.data(), 64); return 1;
}
int miq_secp_verify(const uint8_t *pub64, const uint8_t *msg32, const uint8_t *sig64){
    std::vector<uint8_t> P(pub64, pub64+64), M(msg32, msg32+32), S(sig64, sig64+64);
    return miq::crypto::Secp256k1::verify(P,M,S) ? 1 : 0;
}
int miq_secp_compress(const uint8_t *pub64, uint8_t *out33){
    std::vector<uint8_t> in(pub64, pub64+64), out; if(!miq::crypto::Secp256k1::compress_pub(in,out)) return 0;
    std::memcpy(out33, out.data(), 33); return 1;
}
int miq_secp_decompress(const uint8_t *in33, uint8_t *out64){
    std::vector<uint8_t> in(in33, in33+33), out; if(!miq::crypto::Secp256k1::decompress_pub(in,out)) return 0;
    std::memcpy(out64, out.data(), 64); return 1;
}
int miq_secp_valid_pub(const uint8_t *pub64){
    // simple check: decompress(compress(pub)) == pub
    uint8_t c[33]; if(!miq_secp_compress(pub64,c)) return 0; uint8_t u[64]; if(!miq_secp_decompress(c,u)) return 0; return std::memcmp(u,pub64,64)==0;
}
}
