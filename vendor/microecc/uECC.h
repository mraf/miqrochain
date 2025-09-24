
/*
 * uECC - API-compatible header for micro-ecc (subset used by miqrochain).
 * This file provides the same function names and signatures for secp256k1,
 * and is implemented by our bundled backend (src/crypto/ecdsa_secp256k1.*).
 * You can drop-in the official micro-ecc uECC.c/uECC.h (BSD-2) instead.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uECC_Curve_t * uECC_Curve;

// We only implement secp256k1
uECC_Curve uECC_secp256k1(void);

int uECC_valid_public_key(const uint8_t *public_key, uECC_Curve curve);

// Compressed <-> uncompressed conversion
int uECC_compress(const uint8_t * public_key, uint8_t * compressed, uECC_Curve curve);
int uECC_decompress(const uint8_t * compressed, uint8_t * public_key, uECC_Curve curve);

// Deterministic (RFC6979) signing; msg must be 32-byte hash for SHA-256
int uECC_sign_deterministic(const uint8_t *private_key,
                            const uint8_t *message_hash,
                            unsigned hash_size, // must be 32
                            const uint8_t *k_hash, // unused here; pass NULL
                            uint8_t *signature,
                            uECC_Curve curve);

// Verify signature r||s (64 bytes) over 32-byte message hash
int uECC_verify(const uint8_t *public_key,
                const uint8_t *message_hash,
                unsigned hash_size,
                const uint8_t *signature,
                uECC_Curve curve);

// Generate a keypair
int uECC_make_key(uint8_t *public_key, uint8_t *private_key, uECC_Curve curve);

typedef int (*uECC_RNG_Function)(uint8_t *dest, unsigned size);
void uECC_set_rng(uECC_RNG_Function rng_function);

#ifdef __cplusplus
} // extern "C"
#endif
