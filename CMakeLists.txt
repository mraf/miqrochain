cmake_minimum_required(VERSION 3.16)

# Silence FetchContent_Populate deprecation for now (keeps current behavior)
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

# Enable C (for uECC.c) and C++
project(miqrochain_core C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ------------------------------------------------------------------
# Options
# ------------------------------------------------------------------
option(MIQ_ENABLE_WALLET_ENC "Enable wallet at-rest encryption" OFF)
option(MIQ_ENABLE_UPNP       "Enable UPnP/NAT-PMP port mapping" OFF)
option(MIQ_BUILD_TESTS       "Build tests"                                 OFF)
option(MIQ_FETCH_MICROECC    "Fetch micro-ecc from GitHub if not vendored" ON)

set(MIQ_VENDOR_MICROECC_DIR  "${CMAKE_SOURCE_DIR}/third_party/micro-ecc"
    CACHE PATH "Path to vendored micro-ecc")

# ------------------------------------------------------------------
# Warnings / Optimization
# ------------------------------------------------------------------
if(MSVC)
  add_compile_options(/O2 /Ot /Oi /GL /GF /Gy /Zc:inline)
  add_link_options(/LTCG)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus)
  add_definitions(/D_CRT_SECURE_NO_WARNINGS)
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
endif()

# ------------------------------------------------------------------
# micro-ecc source setup
# ------------------------------------------------------------------
# Choose one:
find_package(LevelDB REQUIRED)
target_link_libraries(miqrod PRIVATE LevelDB::LevelDB) # or rocksdb
set(MICRO_ECC_DIR "")
if(EXISTS "${MIQ_VENDOR_MICROECC_DIR}/uECC.c")
  set(MICRO_ECC_DIR "${MIQ_VENDOR_MICROECC_DIR}")
elseif(MIQ_FETCH_MICROECC)
  include(FetchContent)
  FetchContent_Declare(
    microecc
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        master
  )
  # micro-ecc is a plain C repo; just fetch the sources to a folder
  FetchContent_Populate(microecc)
  set(MICRO_ECC_DIR "${microecc_SOURCE_DIR}")
else()
  message(FATAL_ERROR "micro-ecc not found. Set MIQ_VENDOR_MICROECC_DIR or enable MIQ_FETCH_MICROECC.")
endif()

# Give the 3rd-party C files gentle, localized warning silencing
set_source_files_properties(
  ${MICRO_ECC_DIR}/uECC.c
  PROPERTIES
    COMPILE_OPTIONS "$<$<C_COMPILER_ID:GNU,Clang>:-Wno-sign-compare;-Wno-type-limits;-Wno-unused-function;-Wno-unused-parameter>"
)
if(MSVC)
  set_source_files_properties(
    ${MICRO_ECC_DIR}/uECC.c
    PROPERTIES
      COMPILE_OPTIONS "/wd4244;/wd4267;/wd4334"
  )
endif()

# Also mark our shim as C and keep it quiet if needed
set_source_files_properties(
  src/crypto/uECC_shim.c
  PROPERTIES
    LANGUAGE C
    COMPILE_OPTIONS "$<$<C_COMPILER_ID:GNU,Clang>:-Wno-unused-parameter>"
)

# ------------------------------------------------------------------
# Main daemon
# ------------------------------------------------------------------
add_executable(miqrod
    src/address.h src/address.cpp
    src/wallet_store.h src/wallet_store.cpp
    src/main.cpp
    src/constants.h
    src/config.h src/config.cpp
    src/log.h src/log.cpp
    src/util.h src/util.cpp
    src/sha256.h src/sha256.cpp
    src/hex.h src/hex.cpp
    src/base58.h src/base58.cpp
    src/base58check.h src/base58check.cpp
    src/ripemd160.h src/ripemd160.cpp
    src/hash160.h src/hash160.cpp
    src/merkle.h src/merkle.cpp
    src/serialize.h src/serialize.cpp
    src/json.h src/json.cpp
    src/tx.h src/tx.cpp
    src/block.h src/block.cpp
    src/difficulty.h src/difficulty.cpp
    src/storage.h src/storage.cpp
    src/utxo.h src/utxo.cpp
    src/mempool.h src/mempool.cpp
    src/hasher.h src/hasher.cpp
    src/lut.h src/lut.cpp
    src/blockindex.h src/blockindex.cpp
    src/chain.h src/chain.cpp
    src/miner.h src/miner.cpp
    src/netmsg.h src/netmsg.cpp
    src/p2p.h src/p2p.cpp
    src/http.h src/http.cpp
    src/rpc.h src/rpc.cpp

    # Crypto interface and backends
    src/crypto/ecdsa_iface.h
    src/crypto/ecdsa_uECC.h src/crypto/ecdsa_uECC.cpp
    src/crypto/ecdsa_secp256k1.h
    $<$<NOT:$<BOOL:${WIN32}>>:src/crypto/ecdsa_secp256k1.cpp>

    # micro-ecc + shim (C sources)
    ${MICRO_ECC_DIR}/uECC.c
    src/crypto/uECC_shim.c
)

# Extra sources (kept separate)
target_sources(miqrod PRIVATE
    src/reorg_manager.cpp
    src/nat.cpp # UPnP helper (no-op unless MIQ_ENABLE_UPNP=1)
    src/seeds.cpp
    src/mtp.cpp
)

target_include_directories(miqrod PRIVATE
    src
    ${MICRO_ECC_DIR}
)

# micro-ecc config: enable compressed points (safe, no consensus change)
target_compile_definitions(miqrod PRIVATE uECC_SUPPORT_COMPRESSED_POINT=1)

# MSVC target-specific hardening (after target exists)
if(MSVC)
  target_compile_definitions(miqrod PRIVATE MIQ_RULE_ENFORCE_LOW_S=1)
  target_compile_options(miqrod PRIVATE /guard:cf /GS /sdl /Zi)
  target_link_options(miqrod PRIVATE /guard:cf /DYNAMICBASE /NXCOMPAT)
endif()

if(WIN32)
  target_link_libraries(miqrod PRIVATE Ws2_32)
endif()

# ------------------------------------------------------------------
# Optional Wallet Encryption (OpenSSL AES-256-GCM + PBKDF2)
# (Sources compile into real impl when enabled, or stubs when disabled)
# ------------------------------------------------------------------
if(MIQ_ENABLE_WALLET_ENC)
  find_package(OpenSSL REQUIRED)
  target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_WALLET_ENC=1)
  target_link_libraries(miqrod PRIVATE OpenSSL::Crypto)
  message(STATUS "Wallet encryption: ENABLED (OpenSSL)")
else()
  message(STATUS "Wallet encryption: DISABLED (default)")
endif()

# Add sources unconditionally; implementation switches via the define above.
target_sources(miqrod PRIVATE
    src/wallet_encryptor.cpp
    src/crypto/secure_random.cpp
)
target_include_directories(miqrod PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

# ------------------------------------------------------------------
# Optional UPnP/NAT-PMP (miniupnpc)
# ------------------------------------------------------------------
if(MIQ_ENABLE_UPNP)
  find_path(MINIUPNP_INCLUDE_DIR miniupnpc/miniupnpc.h)
  find_library(MINIUPNP_LIBRARY NAMES miniupnpc)
  if(MINIUPNP_INCLUDE_DIR AND MINIUPNP_LIBRARY)
    target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_UPNP=1)
    target_include_directories(miqrod PRIVATE ${MINIUPNP_INCLUDE_DIR})
    target_link_libraries(miqrod PRIVATE ${MINIUPNP_LIBRARY})
    message(STATUS "UPnP enabled (miniupnpc)")
  else()
    message(FATAL_ERROR "MIQ_ENABLE_UPNP=ON but miniupnpc not found (e.g., libminiupnpc-dev / brew install miniupnpc / vcpkg).")
  endif()
else()
  message(STATUS "UPnP disabled (default)")
endif()

# ------------------------------------------------------------------
# Tests (optional)
# ------------------------------------------------------------------
if(MIQ_BUILD_TESTS)
  enable_testing()

  add_executable(test_crypto tests/test_crypto.cpp
      src/sha256.h src/sha256.cpp
      src/ripemd160.h src/ripemd160.cpp
      src/hash160.h src/hash160.cpp
      src/base58check.h src/base58check.cpp
      src/hex.h src/hex.cpp
      ${MICRO_ECC_DIR}/uECC.c
      src/crypto/uECC_shim.c
  )
  target_include_directories(test_crypto PRIVATE src ${MICRO_ECC_DIR})
  target_compile_definitions(test_crypto PRIVATE uECC_SUPPORT_COMPRESSED_POINT=1)
  if(WIN32)
    target_link_libraries(test_crypto PRIVATE Ws2_32)
  endif()
  add_test(NAME test_crypto COMMAND test_crypto)

  add_executable(test_ser tests/test_ser.cpp
      src/serialize.h src/serialize.cpp
      src/tx.h src/tx.cpp
      src/block.h src/block.cpp
      src/sha256.h src/sha256.cpp
  )
  target_include_directories(test_ser PRIVATE src)
  add_test(NAME test_ser COMMAND test_ser)

  add_executable(fuzz_json tests/fuzz_json.cpp src/json.h src/json.cpp)
  target_include_directories(fuzz_json PRIVATE src)
  add_test(NAME fuzz_json COMMAND fuzz_json)
endif()

# ------------------------------------------------------------------
# Tools
# ------------------------------------------------------------------
add_executable(miq-keygen
    src/tools/miq_keygen.cpp
    src/sha256.h src/sha256.cpp
    src/ripemd160.h src/ripemd160.cpp
    src/hash160.h src/hash160.cpp
    src/base58.h src/base58.cpp
    src/hex.h src/hex.cpp
    ${MICRO_ECC_DIR}/uECC.c
    src/crypto/uECC_shim.c
)
target_include_directories(miq-keygen PRIVATE src ${MICRO_ECC_DIR})
target_compile_definitions(miq-keygen PRIVATE uECC_SUPPORT_COMPRESSED_POINT=1)
if(WIN32)
  # bcrypt is useful if you later switch RNGs for key generation; harmless to link.
  target_link_libraries(miq-keygen PRIVATE bcrypt)
endif()
