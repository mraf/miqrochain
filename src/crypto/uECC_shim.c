#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Forward decl; uECC.h will come from micro-ecc
struct uECC_Curve_t;
const struct uECC_Curve_t* uECC_secp256k1(void);
int uECC_make_key(uint8_t* public_key, uint8_t* private_key,
                  const struct uECC_Curve_t* curve);

// Our stable wrapper name used in your C++ code
int miq_secp_make_key(uint8_t* pubkey, uint8_t* privkey) {
    return uECC_make_key(pubkey, privkey, uECC_secp256k1());
}
#ifdef __cplusplus
}
#endif
