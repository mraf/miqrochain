extern "C" int miq_secp_make_key(unsigned char*, unsigned char*);

#include "ecdsa_uECC.h"
#include "../../vendor/microecc/uECC.h"
#include <vector>
#include <cstring>

namespace miq { namespace crypto {

static void compress64to33(const uint8_t* pub64, std::vector<uint8_t>& out33){
    out33.resize(33);
    uECC_compress(pub64, out33.data(), uECC_secp256k1());
}
static bool decompress33to64(const std::vector<uint8_t>& in33, std::vector<uint8_t>& out64){
    out64.resize(64);
    return uECC_decompress(in33.data(), out64.data(), uECC_secp256k1())==1;
}

bool ECDSA_uECC::generate_priv(std::vector<uint8_t>& out){
    out.resize(32);
    std::vector<uint8_t> pub(64);
    if(!uECC_make_key(pub.data(), out.data(), uECC_secp256k1())) return false;
    return true;
}
bool ECDSA_uECC::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){
    if(priv.size()!=32) return false;
    std::vector<uint8_t> pub64(64);
    // regenerate using sign trick: make_key not available; derive via scalar*G would be inside vendor; here we re-call bridge helper
    
    std::vector<uint8_t> p=priv;
    if(!miq_secp_make_key(pub64.data(), p.data())) return false; // uses priv to compute pub
    compress64to33(pub64.data(), out33);
    return true;
}
bool ECDSA_uECC::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){
    if(priv.size()!=32 || msg32.size()!=32) return false;
    sig64.resize(64);
    return uECC_sign_deterministic(priv.data(), msg32.data(), 32, nullptr, sig64.data(), uECC_secp256k1())==1;
}
bool ECDSA_uECC::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){
    if(pub33.size()!=33 || msg32.size()!=32 || sig64.size()!=64) return false;
    std::vector<uint8_t> pub64; if(!decompress33to64(pub33, pub64)) return false;
    return uECC_verify(pub64.data(), msg32.data(), 32, sig64.data(), uECC_secp256k1())==1;
}

// Wire into iface
bool ECDSA::generate_priv(std::vector<uint8_t>& out){ return ECDSA_uECC::generate_priv(out); }
bool ECDSA::derive_pub(const std::vector<uint8_t>& priv, std::vector<uint8_t>& out33){ return ECDSA_uECC::derive_pub(priv, out33); }
bool ECDSA::sign(const std::vector<uint8_t>& priv, const std::vector<uint8_t>& msg32, std::vector<uint8_t>& sig64){ return ECDSA_uECC::sign(priv, msg32, sig64); }
bool ECDSA::verify(const std::vector<uint8_t>& pub33, const std::vector<uint8_t>& msg32, const std::vector<uint8_t>& sig64){ return ECDSA_uECC::verify(pub33, msg32, sig64); }
std::string ECDSA::backend(){ return ECDSA_uECC::backend(); }

}} // ns
