#ifdef MIQ_USE_SECP256K1

#include "crypto/ecdsa_secp256k1.h"
#include "crypto/ecdsa_iface.h"
#include "sha256.h"

#include <array>
#include <random>
#include <cstring>
#include <vector>
#include <algorithm>
#include <cstdint>

// Keep the optional C bridge off by default.
#ifndef MIQ_SECP256K1_C_BRIDGE
#define MIQ_SECP256K1_C_BRIDGE 0
#endif

// =====================================================================================
// Cross-platform 64-bit helpers (single, consistent API used everywhere in this file)
//   - mul128_u64(a,b,&lo,&hi) -> 128-bit product split into lo/hi 64-bit
//   - addc_u64(a,b,carry_in,&carry_out) -> returns sum (64-bit), carry_out is 0/1
//   - subb_u64(a,b,borrow_in,&borrow_out) -> returns diff (64-bit), borrow_out is 0/1
// =====================================================================================

#if defined(_MSC_VER) && defined(_M_X64)
  #include <intrin.h>
  #pragma intrinsic(_umul128)
  #pragma intrinsic(_addcarry_u64)
  #pragma intrinsic(_subborrow_u64)
  static inline void mul128_u64(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi){
      *lo = _umul128(a, b, hi);
  }
  static inline uint64_t addc_u64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out){
      unsigned __int64 out64;
      unsigned char c = _addcarry_u64((unsigned char)carry_in, a, b, &out64);
      if (carry_out) *carry_out = (uint64_t)c;
      return (uint64_t)out64;
  }
  static inline uint64_t subb_u64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out){
      unsigned __int64 out64;
      unsigned char c = _subborrow_u64((unsigned char)borrow_in, a, b, &out64);
      if (borrow_out) *borrow_out = (uint64_t)c;
      return (uint64_t)out64;
  }
#else
  static inline void mul128_u64(uint64_t a, uint64_t b, uint64_t* lo, uint64_t* hi){
      unsigned __int128 t = (unsigned __int128)a * (unsigned __int128)b;
      *lo = (uint64_t)t;
      *hi = (uint64_t)(t >> 64);
  }
  static inline uint64_t addc_u64(uint64_t a, uint64_t b, uint64_t carry_in, uint64_t* carry_out){
      unsigned __int128 t = (unsigned __int128)a + b + carry_in;
      if (carry_out) *carry_out = (uint64_t)(t >> 64);
      return (uint64_t)t;
  }
  static inline uint64_t subb_u64(uint64_t a, uint64_t b, uint64_t borrow_in, uint64_t* borrow_out){
      // Compute a - b - borrow_in
      unsigned __int128 A = (unsigned __int128)a;
      unsigned __int128 B = (unsigned __int128)b + borrow_in;
      unsigned __int128 D = A - B;
      if (borrow_out) *borrow_out = (uint64_t)(A < B); // 1 if borrow
      return (uint64_t)D;
  }
#endif

namespace miq { namespace crypto {

// ===== basic 256-bit helpers =====
struct U256{ uint64_t v[4]{}; }; // v[0] = least significant limb
struct U512{ uint64_t w[8]{}; }; // w[0] = least significant limb

static inline U256 U256_from_be(const uint8_t b[32]){
    U256 x{};
    for(int i=0;i<4;i++){
        x.v[3-i]= ((uint64_t)b[i*8+0]<<56)|((uint64_t)b[i*8+1]<<48)|((uint64_t)b[i*8+2]<<40)|((uint64_t)b[i*8+3]<<32)
                |((uint64_t)b[i*8+4]<<24)|((uint64_t)b[i*8+5]<<16)|((uint64_t)b[i*8+6]<<8)|((uint64_t)b[i*8+7]);
    }
    return x;
}
static inline void U256_to_be(const U256& x, uint8_t b[32]){
    for(int i=0;i<4;i++){
        uint64_t w=x.v[3-i];
        b[i*8+0]=(uint8_t)((w>>56)&0xff); b[i*8+1]=(uint8_t)((w>>48)&0xff);
        b[i*8+2]=(uint8_t)((w>>40)&0xff); b[i*8+3]=(uint8_t)((w>>32)&0xff);
        b[i*8+4]=(uint8_t)((w>>24)&0xff); b[i*8+5]=(uint8_t)((w>>16)&0xff);
        b[i*8+6]=(uint8_t)((w>>8)&0xff);  b[i*8+7]=(uint8_t)(w&0xff);
    }
}
static inline bool U256_is_zero(const U256& a){ return !(a.v[0]|a.v[1]|a.v[2]|a.v[3]); }
static inline int  U256_cmp(const U256& a,const U256& b){
    for(int i=3;i>=0;--i){ if(a.v[i]<b.v[i]) return -1; if(a.v[i]>b.v[i]) return 1; } return 0;
}
static inline U256 U256_add(const U256& a,const U256& b,uint64_t*carry){
    U256 r{}; uint64_t c=0;
    for(int i=0;i<4;i++){ r.v[i]=addc_u64(a.v[i], b.v[i], c, &c); }
    if (carry) *carry = c;
    return r;
}
static inline U256 U256_sub(const U256& a,const U256& b,uint64_t*borrow){
    U256 r{}; uint64_t br=0;
    for(int i=0;i<4;i++){ r.v[i]=subb_u64(a.v[i], b.v[i], br, &br); }
    if (borrow) *borrow = br;
    return r;
}
static inline U256 U256_shl_bits(const U256& x, int bits){
    // Shift left by 0..63 bits
    if (bits <= 0) return x;
    if (bits >= 64) { U256 z{}; return z; }
    U256 r{}; uint64_t carry = 0;
    for (int i=0;i<4;i++){
        uint64_t w = x.v[i];
        r.v[i] = (w << bits) | carry;
        carry = (bits == 0 ? 0 : (w >> (64 - bits)));
    }
    return r;
}
static inline U256 U256_shl(const U256& x, int shift){
    // Shift left by 0..255 bits
    if (shift <= 0) return x;
    if (shift >= 256) { U256 z{}; return z; }
    int limb = shift / 64;
    int bits = shift % 64;
    U256 r{};
    for (int i=3;i>=0;--i){
        uint64_t lo = 0, hi = 0;
        int src = i - limb;
        if (src >= 0){
            uint64_t cur = x.v[src];
            uint64_t nxt = (src-1 >= 0) ? x.v[src-1] : 0;
            if (bits == 0){
                r.v[i] = cur;
            } else {
                r.v[i] = (cur << bits) | (nxt >> (64 - bits));
            }
        } else {
            r.v[i] = 0;
        }
        (void)lo; (void)hi;
    }
    return r;
}
static inline U512 U256_mul(const U256& a,const U256& b){
    U512 r{};
    for(int i=0;i<4;i++){
        uint64_t c=0;
        for(int j=0;j<4;j++){
            uint64_t lo, hi; mul128_u64(a.v[i], b.v[j], &lo, &hi);
            uint64_t carry1=0, carry2=0;
            uint64_t sum = addc_u64(r.w[i+j], lo, 0, &carry1);
            r.w[i+j] = addc_u64(sum, c, 0, &carry2);
            c = hi + carry1 + carry2;
        }
        r.w[i+4] = addc_u64(r.w[i+4], c, 0, nullptr);
    }
    return r;
}

static inline U256 U512_mod(const U512& x,const U256& m){
    U512 r = x;

    auto ge = [&](const U512& A, const U256& B, int s)->bool{
        // Compare A >= (B << (64*s)) where 's' is limb shift (0..7)
        for (int i=7;i>=0;--i){
            uint64_t a = A.w[i];
            uint64_t b = 0;
            int bi = i - s;
            if (bi >= 0 && bi < 4) b = B.v[bi];
            if (a < b) return false;
            if (a > b) return true;
        }
        return true; // equal
    };

    auto sub_shifted = [&](U512& A, const U256& B, int s){
        uint64_t borrow = 0;
        for (int i=0;i<8;i++){
            uint64_t b = 0;
            int bi = i - s;
            if (bi >= 0 && bi < 4) b = B.v[bi];
            A.w[i] = subb_u64(A.w[i], b, borrow, &borrow);
        }
    };

    // Long reduction: subtract (m << s) where possible
    for (int s=7; s>=0; --s){
        while (ge(r, m, s)) sub_shifted(r, m, s);
    }
    U256 o{};
    for (int i=0;i<4;i++) o.v[i]=r.w[i];
    return o;
}

static inline U256 U256_mod_add(const U256&a,const U256&b,const U256&m){
    uint64_t c=0; U256 s=U256_add(a,b,&c);
    if (c || U256_cmp(s,m)>=0) s=U256_sub(s,m,nullptr);
    return s;
}
static inline U256 U256_mod_sub(const U256&a,const U256&b,const U256&m){
    uint64_t br=0; U256 s=U256_sub(a,b,&br);
    if (br) s=U256_add(s,m,nullptr);
    return s;
}
static inline U256 U256_mod_mul(const U256&a,const U256&b,const U256&m){ return U512_mod(U256_mul(a,b),m); }

static U256 U256_mod_inv(U256 a, U256 m){
    // Extended Euclid over 256-bit ints (schoolbook, but portable)
    U256 lm{{1,0,0,0}}, hm{{0,0,0,0}};
    U256 low=a, high=m;

    auto isz=[&](const U256&x){return U256_is_zero(x);};

    auto divmod=[&](const U256&num,const U256&den,U256&q,U256&r){
        // Binary restoring division, bit by bit: r = num, q = 0
        q = U256{{0,0,0,0}};
        r = num;
        for(int i=255;i>=0;--i){
            U256 d = U256_shl(den, i);
            if (U256_cmp(r, d) >= 0){
                r = U256_sub(r, d, nullptr);
                q.v[i/64] |= (uint64_t)1ULL << (i%64);
            }
        }
    };

    while(!isz(low)){
        U256 q,nr;
        divmod(high,low,q,nr);
        U256 tmp=U256_mod_mul(q,lm,m);
        U256 nm=U256_mod_sub(hm,tmp,m);
        hm=lm; high=low; lm=nm; low=nr;
    }
    return hm;
}

// ===== curve constants (secp256k1) =====
static const U256 P  = U256_from_be((const uint8_t*)
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
    "\xff\xff\xfc\x2f");

static const U256 N  = U256_from_be((const uint8_t*)
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe"
    "\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41");

static const U256 N_HALF = U256_from_be((const uint8_t*)
    "\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
    "\x5d\x57\x6e\x73\x57\xa4\x50\x1d\xdf\xe9\x2f\x46\x68\x1b\x20\xa0");

static const U256 Gx = U256_from_be((const uint8_t*)
    "\x79\xbe\x66\x7e\xf9\xdc\xbb\xac\x55\xa0\x62\x95\xce\x87\x0b\x07"
    "\x02\x9b\xfc\xdb\x2d\xce\x28\xd9\x59\xf2\x81\x5b\x16\xf8\x17\x98");

static const U256 Gy = U256_from_be((const uint8_t*)
    "\x48\x3a\xda\x77\x26\xa3\xc4\x65\x5d\xa4\xfb\xfc\x0e\x11\x08\xa8"
    "\xfd\x17\xb4\x48\xa6\x85\x54\x19\x9c\x47\xd0\x8f\xfb\x10\xd4\xb8");

// ===== field & point =====
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

static Point dbl(const Point&Pt){
    if(isInf(Pt)) return Pt;
    Fp XX=Fp_sqr(Pt.X);
    Fp YY=Fp_sqr(Pt.Y);
    Fp YYYY=Fp_sqr(YY);
    Fp S = Fp_mul(Fp_mul(Pt.X, YY), Fp_fromU(U256{{4,0,0,0}}));
    Fp M = Fp_add(Fp_add(XX,XX),XX); // 3*XX
    Fp X3=Fp_sub(Fp_sqr(M), Fp_add(S,S));
    Fp Y3=Fp_sub(Fp_mul(M, Fp_sub(S, X3)), Fp_mul(Fp_fromU(U256{{8,0,0,0}}), YYYY));
    Fp Z3=Fp_mul(Fp_add(Pt.Y,Pt.Y), Pt.Z);
    Point R{X3,Y3,Z3,false}; return R;
}

static Point add(const Point& Pp, const Point& Qp){
    if (isInf(Pp)) return Qp;
    if (isInf(Qp)) return Pp;
    Fp Z1Z1=Fp_sqr(Pp.Z);
    Fp Z2Z2=Fp_sqr(Qp.Z);
    Fp U1=Fp_mul(Pp.X, Z2Z2);
    Fp U2=Fp_mul(Qp.X, Z1Z1);
    Fp S1=Fp_mul(Fp_mul(Pp.Y,Qp.Z), Z2Z2);
    Fp S2=Fp_mul(Fp_mul(Qp.Y,Pp.Z), Z1Z1);

    // H = U2 - U1
    U256 H_ = U256_mod_sub(U2.n, U1.n, P);
    Fp H=Fp_fromU(H_);

    // r = 2*(S2 - S1)
    U256 r_ = U256_mod_sub(S2.n, S1.n, P);
    r_ = U256_mod_add(r_, r_, P);
    Fp r=Fp_fromU(r_);

    if(U256_is_zero(H.n)){ if(U256_is_zero(r.n)) return dbl(Pp); return Inf(); }
    Fp I = Fp_sqr(Fp_fromU(U256_mod_add(H.n, H.n, P)));
    Fp J = Fp_mul(H, I);
    Fp V = Fp_mul(U1, I);
    Fp X3 = Fp_sub(Fp_sub(Fp_sqr(r), J), Fp_add(V,V));
    Fp Y3 = Fp_sub(Fp_mul(r, Fp_sub(V, X3)), Fp_mul(Fp_fromU(U256_mod_add(S1.n,S1.n, P)), J));
    Fp Z3 = Fp_mul(Fp_sub(Fp_add(Pp.Z,Qp.Z), Fp_add(Z1Z1,Z2Z2)), H);
    Point R{X3,Y3,Z3,false}; return R;
}

static Point mul(const U256& k,const Point&Pt){
    Point R=Inf();
    for(int i=255;i>=0;--i){
        R=dbl(R);
        if( (k.v[i/64]>>(i%64)) & 1ULL ) R=add(R,Pt);
    }
    return R;
}

static Point to_affine(const Point&Pt){
    if(isInf(Pt)) return Pt;
    Fp Zi = Fp_inv(Pt.Z); Fp Zi2=Fp_sqr(Zi); Fp Zi3=Fp_mul(Zi2,Zi);
    Point A{Fp_mul(Pt.X,Zi2), Fp_mul(Pt.Y,Zi3), Fp_fromU(U256{{1,0,0,0}}), false};
    return A;
}

// ===== HMAC-SHA256 (uses our sha256) =====
static void HMAC_SHA256(const uint8_t*key,size_t key_len,const uint8_t*msg,size_t msg_len,uint8_t out[32]){
    std::vector<uint8_t> k(64,0);
    if(key_len>64){
        auto t = miq::sha256(std::vector<uint8_t>(key,key+key_len));
        std::copy(t.begin(),t.end(),k.begin());
    } else {
        std::copy(key,key+key_len,k.begin());
    }
    std::vector<uint8_t> opad(64,0x5c), ipad(64,0x36);
    for(size_t j=0;j<64;j++){ opad[j]^=k[j]; ipad[j]^=k[j]; }
    auto ib = miq::sha256(ipad); ib.insert(ib.end(), msg, msg+msg_len); ib = miq::sha256(ib);
    auto ob = miq::sha256(opad); ob.insert(ob.end(), ib.begin(), ib.end()); auto h = miq::sha256(ob);
    std::copy(h.begin(),h.end(),out);
}

static U256 rfc6979(const U256& x, const U256& z, const U256& n){
    uint8_t K[32]={0}; uint8_t V[32]; for(int i=0;i<32;i++) V[i]=0x01;
    uint8_t bx[32], bz[32]; U256_to_be(x,bx); U256_to_be(z,bz);

    std::vector<uint8_t> m; m.reserve(2+32+32);
    // Step: V = 0x01..01, K = 0x00..00 (already)
    // K = HMAC(K, V || 0x00 || x || z)
    m.insert(m.end(), V, V+32); m.push_back(0x00); m.insert(m.end(), bx, bx+32); m.insert(m.end(), bz, bz+32);
    HMAC_SHA256(K,32,m.data(),m.size(),K); HMAC_SHA256(K,32,V,32,V);

    // K = HMAC(K, V || 0x01 || x || z)
    m.clear(); m.insert(m.end(), V, V+32); m.push_back(0x01); m.insert(m.end(), bx, bx+32); m.insert(m.end(), bz, bz+32);
    HMAC_SHA256(K,32,m.data(),m.size(),K); HMAC_SHA256(K,32,V,32,V);

    // generate
    while(true){
        HMAC_SHA256(K,32,V,32,V);
        U256 k=U256_from_be(V);
        // reduce mod n (simple)
        U512 prod{}; prod.w[0]=k.v[0]; prod.w[1]=k.v[1]; prod.w[2]=k.v[2]; prod.w[3]=k.v[3];
        U256 kk=U512_mod(prod,n);
        if(U256_is_zero(kk) || U256_cmp(kk,n)>=0) continue;
        return kk;
    }
}

// HIGH FIX: Secure memory clearing helper
static void secure_clear(void* ptr, size_t len) {
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) *p++ = 0;
}

// ===== built-in Secp256k1 (deterministic signatures) =====
bool Secp256k1::generate_priv(std::vector<uint8_t>& out32){
    std::random_device rd;
    out32.resize(32);

    // HIGH FIX: Retry until we get a valid private key (0 < d < N)
    // This ensures cryptographic validity, not just non-zero first byte
    for (int attempts = 0; attempts < 256; ++attempts) {
        for (auto& i : out32) i = (uint8_t)rd();

        U256 d = U256_from_be(out32.data());

        // Check: private key must be in range (0, N)
        // d must not be zero and must be less than N
        if (!U256_is_zero(d) && U256_cmp(d, N) < 0) {
            return true;
        }
        // Invalid key generated, retry
    }

    // Failed to generate valid key after 256 attempts (astronomically unlikely)
    secure_clear(out32.data(), out32.size());
    out32.clear();
    return false;
}

bool Secp256k1::derive_pub_uncompressed(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out64){
    if (priv.size() != 32) return false;
    U256 d = U256_from_be(priv.data());
    if (U256_is_zero(d) || U256_cmp(d, N) >= 0) return false;

    Point Q = to_affine(mul(d, G()));
    uint8_t xb[32], yb[32]; U256_to_be(Q.X.n, xb); U256_to_be(Q.Y.n, yb);
    out64.assign(xb, xb+32); out64.insert(out64.end(), yb, yb+32); return true;
}

bool Secp256k1::compress_pub(const std::vector<uint8_t>& pub64, std::vector<uint8_t>& out33){
    if (pub64.size() != 64) return false;
    out33.resize(33);
    out33[0] = (pub64[63] & 1) ? 0x03 : 0x02;
    std::copy(pub64.begin(), pub64.begin()+32, out33.begin()+1);
    return true;
}

bool Secp256k1::decompress_pub(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64){
    if (in33.size() != 33) return false;
    uint8_t prefix = in33[0];
    if (prefix != 0x02 && prefix != 0x03) return false;

    U256 X=U256_from_be(&in33[1]);
    Fp x = Fp_fromU(X);
    // rhs = x^3 + 7
    Fp rhs = Fp_add(Fp_mul(Fp_sqr(x), x), Fp_fromU(U256_from_be((const uint8_t*)
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07")));

    // exponent (p+1)/4
    U256 e = U256_from_be((const uint8_t*)
        "\x3f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
        "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfb");

    auto pow = [&](Fp a, U256 ee){
        Fp r=Fp_fromU(U256{{1,0,0,0}});
        for(int i=0;i<256;i++){ if( (ee.v[i/64]>>(i%64)) & 1ULL ) r=Fp_mul(r,a); a=Fp_sqr(a); }
        return r;
    };
    Fp y = pow(rhs, e);

    uint8_t yb[32]; U256_to_be(y.n, yb);
    if( (yb[31]&1) != (prefix&1) ){ // use the other root
        U256 yy = U256_mod_sub(U256_from_be(yb), P, P);
        y.n = yy;
    }
    uint8_t xb[32]; U256_to_be(x.n, xb);
    out64.assign(xb, xb+32); out64.insert(out64.end(), yb, yb+32); return true;
}

bool Secp256k1::sign_rfc6979(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){
    if (priv.size()!=32 || msg32.size()!=32) return false;
    U256 d = U256_from_be(priv.data());
    if (U256_is_zero(d) || U256_cmp(d, N) >= 0) return false;
    U256 z = U256_from_be(msg32.data());

    for(int tries=0; tries<32; ++tries){
        U256 k = rfc6979(d,z,N);
        Point R = to_affine(mul(k, G()));
        U256 r = R.X.n;
        U512 rr{}; rr.w[0]=r.v[0]; rr.w[1]=r.v[1]; rr.w[2]=r.v[2]; rr.w[3]=r.v[3];
        U256 rN=U512_mod(rr,N);
        if(U256_is_zero(rN)) continue;

        U256 kinv = U256_mod_inv(k,N);
        U256 rd   = U256_mod_mul(rN,d,N);
        U256 s    = U256_mod_mul(kinv, U256_mod_add(z, rd, N), N);

        // low-s
        if(U256_cmp(s, N_HALF)>0) s = U256_mod_sub(N, s, N);

        uint8_t rb[32], sb[32]; U256_to_be(rN, rb); U256_to_be(s, sb);
        sig64.assign(rb, rb+32); sig64.insert(sig64.end(), sb, sb+32); return true;
    }
    return false;
}

bool Secp256k1::verify(const std::vector<uint8_t>& pub64, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){
    if(pub64.size()!=64 || msg32.size()!=32 || sig64.size()!=64) return false;
    U256 r=U256_from_be(sig64.data()), s=U256_from_be(sig64.data()+32);
    if(U256_is_zero(r)||U256_is_zero(s)||U256_cmp(r,N)>=0||U256_cmp(s,N)>=0) return false;

    U256 z=U256_from_be(msg32.data());
    U256 w=U256_mod_inv(s,N);
    U256 u1=U256_mod_mul(z,w,N); U256 u2=U256_mod_mul(r,w,N);

    U256 X=U256_from_be(pub64.data()), Y=U256_from_be(pub64.data()+32);
    Point Q; Q.X=Fp_fromU(X); Q.Y=Fp_fromU(Y); Q.Z=Fp_fromU(U256{{1,0,0,0}}); Q.inf=false;

    Point Xp = add(mul(u1,G()), mul(u2,Q));
    if(isInf(Xp)) return false;
    Xp=to_affine(Xp);

    U512 xr{}; xr.w[0]=Xp.X.n.v[0]; xr.w[1]=Xp.X.n.v[1]; xr.w[2]=Xp.X.n.v[2]; xr.w[3]=Xp.X.n.v[3];
    U256 xrn=U512_mod(xr,N);
    return U256_cmp(xrn,r)==0;
}

std::string Secp256k1::name(){ return "secp256k1 (built-in, RFC6979)"; }

// ---------- ECDSA iface wrappers (so callers use miq::crypto::ECDSA) ----------
bool ECDSA::generate_priv(std::vector<uint8_t>& out32){
    return Secp256k1::generate_priv(out32);
}

bool ECDSA::derive_pub(const std::vector<uint8_t>& priv32, std::vector<uint8_t>& out_pub33){
    std::vector<uint8_t> un64;
    if(!Secp256k1::derive_pub_uncompressed(priv32, un64)) return false;
    return Secp256k1::compress_pub(un64, out_pub33);
}

bool ECDSA::sign(const std::vector<uint8_t>& priv32,
                 const std::vector<uint8_t>& msg32,
                 std::vector<uint8_t>& out_sig64){
    return Secp256k1::sign_rfc6979(priv32, msg32, out_sig64);
}

bool ECDSA::verify(const std::vector<uint8_t>& pubkey,
                   const std::vector<uint8_t>& msg32,
                   const std::vector<uint8_t>& sig64){
    // Accept 33-byte compressed or 64-byte uncompressed
    std::vector<uint8_t> un64;
    if (pubkey.size() == 33) {
        if(!Secp256k1::decompress_pub(pubkey, un64)) return false;
    } else if (pubkey.size() == 64) {
        un64 = pubkey;
    } else {
        return false;
    }
    return Secp256k1::verify(un64, msg32, sig64);
}

std::string ECDSA::backend(){
    return "libsecp256k1";
}

}} // namespace miq::crypto

// -------- optional C bridge (kept off by default) ---------
#if MIQ_SECP256K1_C_BRIDGE
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
    uint8_t c[33]; if(!miq_secp_compress(pub64,c)) return 0; uint8_t u[64]; if(!miq_secp_decompress(c,u)) return 0; return std::memcmp(u,pub64,64)==0;
}
}
#endif

#endif
