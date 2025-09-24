
#include "uECC.h"
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

// Bridge to C++ backend
int miq_secp_make_key(uint8_t *pub64, uint8_t *priv32);
int miq_secp_sign_det(const uint8_t *priv32, const uint8_t *msg32, uint8_t *sig64);
int miq_secp_verify(const uint8_t *pub64, const uint8_t *msg32, const uint8_t *sig64);
int miq_secp_compress(const uint8_t *pub64, uint8_t *out33);
int miq_secp_decompress(const uint8_t *in33, uint8_t *out64);
int miq_secp_valid_pub(const uint8_t *pub64);

static uECC_RNG_Function g_rng = 0;
void uECC_set_rng(uECC_RNG_Function rng_function){ g_rng = rng_function; (void)g_rng; }

static struct uECC_Curve_t { int ident; } g_curve_secp256k1 = { 1 };
uECC_Curve uECC_secp256k1(void){ return &g_curve_secp256k1; }

int uECC_valid_public_key(const uint8_t *public_key, uECC_Curve curve){ (void)curve; return miq_secp_valid_pub(public_key); }

int uECC_compress(const uint8_t * public_key, uint8_t * compressed, uECC_Curve curve){ (void)curve; return miq_secp_compress(public_key, compressed); }
int uECC_decompress(const uint8_t * compressed, uint8_t * public_key, uECC_Curve curve){ (void)curve; return miq_secp_decompress(compressed, public_key); }

int uECC_sign_deterministic(const uint8_t *private_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *k_hash, uint8_t *signature, uECC_Curve curve){
    (void)curve; (void)k_hash;
    if(hash_size!=32) return 0;
    return miq_secp_sign_det(private_key, message_hash, signature);
}
int uECC_verify(const uint8_t *public_key, const uint8_t *message_hash, unsigned hash_size, const uint8_t *signature, uECC_Curve curve){
    (void)curve; if(hash_size!=32) return 0;
    return miq_secp_verify(public_key, message_hash, signature);
}

int uECC_make_key(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve){
    (void)curve; return miq_secp_make_key(public_key, private_key);
}

#ifdef __cplusplus
}
#endif
