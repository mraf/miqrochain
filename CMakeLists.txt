cmake_minimum_required(VERSION 3.16)

# Silence FetchContent_Populate deprecation for now (keeps current behavior)
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

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

# DB backend options
option(MIQ_USE_ROCKSDB       "Use RocksDB instead of LevelDB"              OFF)
option(MIQ_FETCH_LEVELDB     "Automatically fetch/build LevelDB if missing" ON)
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
  # Ensure modern Winsock API (inet_ntop etc.) declarations are available
  add_compile_definitions(_WIN32_WINNT=0x0600)
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
endif()

include(FetchContent)

# ------------------------------------------------------------------
# micro-ecc source setup
# ------------------------------------------------------------------
set(MICRO_ECC_DIR "")
if(EXISTS "${MIQ_VENDOR_MICROECC_DIR}/uECC.c")
  set(MICRO_ECC_DIR "${MIQ_VENDOR_MICROECC_DIR}")
elseif(MIQ_FETCH_MICROECC)
  FetchContent_Declare(
    microecc
    GIT_REPOSITORY https://github.com/kmackay/micro-ecc.git
    GIT_TAG        master
  )
  FetchContent_MakeAvailable(microecc)
  set(MICRO_ECC_DIR "${microecc_SOURCE_DIR}")
else()
  message(FATAL_ERROR "micro-ecc not found. Set MIQ_VENDOR_MICROECC_DIR or enable MIQ_FETCH_MICROECC.")
endif()

# Give the 3rd-party C files gentle, localized warning silencing
set_source_files_properties(
  ${MICRO_ECC_DIR}/uECC.c
  PROPERTIES
    COMPILE_OPTIONS "$<$<C_COMPILER_ID:GNU,Clang>:-Wno-sign-compare;-Wno-type-limits;-Wno-unused-function;-Wno-unused-parameter;-Wno-maybe-uninitialized>"
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
# Key-Value DB backend (LevelDB default, or RocksDB if opted)
# Exposes targets:
#   LevelDB::LevelDB  (or) RocksDB::rocksdb
# ------------------------------------------------------------------
set(MIQ_DB_TARGET "")
if(MIQ_USE_ROCKSDB)
  find_package(rocksdb QUIET)
  if(NOT rocksdb_FOUND)
    message(FATAL_ERROR "MIQ_USE_ROCKSDB=ON but RocksDB package not found. Install it or turn MIQ_USE_ROCKSDB OFF to use LevelDB.")
  endif()
  set(MIQ_DB_TARGET RocksDB::rocksdb)
  add_compile_definitions(MIQ_USE_ROCKSDB=1)
else()
  # Try system LevelDB first
  find_package(LevelDB QUIET)
  if(LevelDB_FOUND)
    set(MIQ_DB_TARGET LevelDB::LevelDB)
  else()
    if(NOT MIQ_FETCH_LEVELDB)
      message(FATAL_ERROR "LevelDB not found. Install a LevelDB dev package, set LevelDB_DIR, or enable MIQ_FETCH_LEVELDB.")
    endif()
    # Fetch LevelDB from upstream
    FetchContent_Declare(
      leveldb_src
      GIT_REPOSITORY https://github.com/google/leveldb.git
      GIT_TAG        1.23
    )
    set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
    set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(leveldb_src)
    if(NOT TARGET LevelDB::LevelDB)
      add_library(LevelDB::LevelDB ALIAS leveldb)
    endif()
    set(MIQ_DB_TARGET LevelDB::LevelDB)
  endif()
endif()

# ------------------------------------------------------------------
# TLS / Threads (for RPC TLS proxy & background threads)
# ------------------------------------------------------------------
find_package(OpenSSL REQUIRED)         # TLS proxy
find_package(Threads REQUIRED)         # std::thread on POSIX

# ------------------------------------------------------------------
# Main daemon
# ------------------------------------------------------------------
add_executable(miqrod
    src/hd_wallet.cpp
    src/hd_wallet.h
    src/bip39_words_en.h
    src/addrman.h
    src/addrman.cpp
    src/address.h src/address.cpp
    src/wallet_store.h src/wallet_store.cpp
    src/reindex_utxo.h
    src/reindex_utxo.cpp
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

    # If you keep the old utxo backend, leave these; otherwise comment them out.
    src/utxo.h src/utxo.cpp

    # New durable KV-backed chainstate
    src/kvdb.h src/kvdb.cpp
    src/utxo_kv.h src/utxo_kv.cpp

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
    src/crypto/ecdsa_secp256k1.cpp   # <— build libsecp backend on all platforms

    # micro-ecc + shim (C sources)
    ${MICRO_ECC_DIR}/uECC.c
    src/crypto/uECC_shim.c

    # --- TLS proxy & IBD monitor ---
    src/tls_proxy.h src/tls_proxy.cpp
    src/ibd_monitor.h src/ibd_monitor.cpp
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

# --- Default to libsecp256k1 backend for ECDSA ---
target_compile_definitions(miqrod PRIVATE MIQ_USE_SECP256K1=1)

# Link DB backend
target_link_libraries(miqrod PRIVATE ${MIQ_DB_TARGET})

# Platform libs
if(WIN32)
  target_link_libraries(miqrod PRIVATE Ws2_32)
endif()

# Link TLS + Threads
target_link_libraries(miqrod PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# ------------------------------------------------------------------
# Optional Wallet Encryption (OpenSSL AES-256-GCM + PBKDF2)
# ------------------------------------------------------------------
if(MIQ_ENABLE_WALLET_ENC)
  target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_WALLET_ENC=1)
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
    src/crypto/ecdsa_secp256k1.cpp
    src/crypto/ecdsa_secp256k1.h
    src/crypto/ecdsa_iface.h
    src/crypto/secure_random.cpp
    src/crypto/secure_random.h
)
target_compile_definitions(miq-keygen PRIVATE MIQ_USE_SECP256K1=1)
if(WIN32)
  target_link_libraries(miq-keygen PRIVATE bcrypt)
endif()
