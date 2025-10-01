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

# DB backend options
option(MIQ_USE_ROCKSDB       "Use RocksDB instead of LevelDB"              OFF)
option(MIQ_FETCH_LEVELDB     "Automatically fetch/build LevelDB if missing" ON)

# libsecp256k1 options
option(MIQ_USE_LIBSECP       "Use bitcoin-core/libsecp256k1 backend"        ON)
set(MIQ_LIBSECP_TAG "master" CACHE STRING "bitcoin-core/secp256k1 git tag or commit to fetch")

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
# libsecp256k1: try system package first, otherwise auto-fetch & use its target
# Exposes: MIQ_LIBSECP_TARGET = <imported target to link>
# ------------------------------------------------------------------
set(MIQ_LIBSECP_TARGET "")
if(MIQ_USE_LIBSECP)
  # Prefer system-provided config packages (vcpkg/Conan/etc.)
  find_package(secp256k1 CONFIG QUIET)

  if(secp256k1_FOUND)
    # Package exports an imported target; common name is secp256k1::secp256k1
    if(TARGET secp256k1::secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1::secp256k1)
      message(STATUS "Using system-provided secp256k1 (secp256k1::secp256k1)")
    else()
      # Some packages expose a plain 'secp256k1' target
      if(TARGET secp256k1)
        set(MIQ_LIBSECP_TARGET secp256k1)
        message(STATUS "Using system-provided secp256k1 (secp256k1)")
      else()
        message(FATAL_ERROR "secp256k1 package found but no usable CMake target exported.")
      endif()
    endif()
  else()
    message(STATUS "secp256k1 not found in system; fetching bitcoin-core/secp256k1 @ ${MIQ_LIBSECP_TAG}")

    include(FetchContent)
    # Optionally slim the upstream build; if a var is unknown, CMake just ignores it.
    set(SECP256K1_BUILD_TESTS OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_BENCHMARK OFF CACHE BOOL "" FORCE)
    set(SECP256K1_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)

    FetchContent_Declare(
      secp256k1_src
      GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
      GIT_TAG        ${MIQ_LIBSECP_TAG}
      GIT_PROGRESS   TRUE
    )
    FetchContent_MakeAvailable(secp256k1_src)

    # The fetched project already defines a target named 'secp256k1'.
    if(TARGET secp256k1::secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1::secp256k1)
    elseif(TARGET secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1)
    else()
      message(FATAL_ERROR "Fetched secp256k1 but no target named 'secp256k1' was created.")
    endif()
  endif()

  add_compile_definitions(MIQ_USE_LIBSECP256K1=1)
endif()

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

    # Crypto interface + libsecp backend wrapper
    src/crypto/ecdsa_iface.h
    src/crypto/ecdsa_libsecp256k1.cpp

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
)

# Link DB backend
target_link_libraries(miqrod PRIVATE ${MIQ_DB_TARGET})

# Platform libs
if(WIN32)
  target_link_libraries(miqrod PRIVATE Ws2_32)
endif()

# Link TLS + Threads
target_link_libraries(miqrod PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# Link libsecp256k1
if(MIQ_USE_LIBSECP)
  target_link_libraries(miqrod PRIVATE ${MIQ_LIBSECP_TARGET})
endif()

# ------------------------------------------------------------------
# Optional Wallet Encryption (OpenSSL AES-256-GCM + PBKDF2)
# ------------------------------------------------------------------
if(MIQ_ENABLE_WALLET_ENC)
  target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_WALLET_ENC=1)
  message(STATUS "Wallet encryption: ENABLED (OpenSSL)")
else()
  message(STATUS "Wallet encryption: DISABLED (default)")
endif()

# Add sources unconditionally; RNG is used by ECDSA backend too.
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
# Tests (optional) — now use libsecp backend via iface
# ------------------------------------------------------------------
if(MIQ_BUILD_TESTS)
  enable_testing()

  add_executable(test_crypto tests/test_crypto.cpp
      src/sha256.h src/sha256.cpp
      src/ripemd160.h src/ripemd160.cpp
      src/hash160.h src/hash160.cpp
      src/base58check.h src/base58check.cpp
      src/hex.h src/hex.cpp
      src/crypto/secure_random.cpp
      src/crypto/ecdsa_iface.h
      src/crypto/ecdsa_libsecp256k1.cpp
  )
  target_include_directories(test_crypto PRIVATE src)
  if(MIQ_USE_LIBSECP)
    target_link_libraries(test_crypto PRIVATE ${MIQ_LIBSECP_TARGET})
  endif()
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
    src/crypto/secure_random.cpp
    src/crypto/ecdsa_iface.h
    src/crypto/ecdsa_libsecp256k1.cpp
)
target_include_directories(miq-keygen PRIVATE src)
if(MIQ_USE_LIBSECP)
  target_link_libraries(miq-keygen PRIVATE ${MIQ_LIBSECP_TARGET})
endif()
if(WIN32)
  target_link_libraries(miq-keygen PRIVATE bcrypt)
endif()
