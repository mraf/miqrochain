/* cmake/secp256k1_basic_config.h
   Minimal, portable config for building libsecp256k1 from source without Autotools/Meson.
   Conservative defaults + fast path on non-MSVC 64-bit compilers.
*/

/* No bignum lib; use internal integer backends */
#define USE_NUM_NONE 1

/* Field/scalar selection:
   - On MSVC, prefer 32-bit limbs for portability (MSVC lacks __int128).
   - Else on 64-bit GCC/Clang, use 4x64/5x52 fast paths.
   - Else fall back to 8x32/10x26.
*/
#if defined(_MSC_VER)
  #define USE_SCALAR_8X32 1
  #define USE_FIELD_10X26 1
#else
  #if defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
    #define USE_SCALAR_4X64 1
    #define USE_FIELD_5X52 1
  #else
    #define USE_SCALAR_8X32 1
    #define USE_FIELD_10X26 1
  #endif
#endif

/* Use built-in modular inverses */
#define USE_FIELD_INV_BUILTIN 1
#define USE_SCALAR_INV_BUILTIN 1

/* No optional modules by default (you can enable later if you add those APIs) */
#define ENABLE_MODULE_ECDH 0
#define ENABLE_MODULE_RECOVERY 0

/* Reasonable precomp windows (match upstream defaults) */
#define ECMULT_WINDOW_SIZE 15
#define ECMULT_GEN_PREC_BITS 4
