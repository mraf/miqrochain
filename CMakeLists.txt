cmake_minimum_required(VERSION 3.16)

# Keep FetchContent behavior stable
if(POLICY CMP0169)
  cmake_policy(SET CMP0169 OLD)
endif()

project(miqrochain_core C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(FetchContent)
find_package(PkgConfig QUIET)

# ------------------------------------------------------------------
# Options
# ------------------------------------------------------------------
option(MIQ_ENABLE_WALLET_ENC "Enable wallet at-rest encryption" OFF)

# We *aim* to enable UPnP, but will fall back cleanly if miniupnpc isn't present.
option(MIQ_ENABLE_UPNP       "Enable UPnP/NAT-PMP port mapping (auto-detect; falls back to stub if not found)" ON)

# Do NOT fetch miniupnpc automatically (GitHub runners without outbound net should still compile).
option(MIQ_FETCH_MINIUPNPC   "Auto-fetch miniupnpc if not found (requires outbound network)" OFF)

option(MIQ_BUILD_TESTS       "Build tests" OFF)

# DB backend options
option(MIQ_USE_ROCKSDB       "Use RocksDB instead of LevelDB"              OFF)
option(MIQ_FETCH_LEVELDB     "Automatically fetch/build LevelDB if missing" ON)

# libsecp256k1 options
option(MIQ_USE_LIBSECP "Use bitcoin-core/libsecp256k1 backend" ON)
set(MIQ_LIBSECP_TAG "master" CACHE STRING "bitcoin-core/secp256k1 git tag or commit to fetch")

# ------------------------------------------------------------------
# Warnings / Optimization
# ------------------------------------------------------------------
if(MSVC)
  add_compile_options(/O2 /Ot /Oi /GL /GF /Gy /Zc:inline)
  add_link_options(/LTCG)
  add_compile_options(/W4 /permissive- /Zc:__cplusplus)
  add_definitions(/D_CRT_SECURE_NO_WARNINGS)
  add_compile_definitions(_WIN32_WINNT=0x0600)
else()
  add_compile_options(-Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers)
endif()

# ------------------------------------------------------------------
# TLS / Threads
# ------------------------------------------------------------------
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

# ------------------------------------------------------------------
# Key-Value DB backend
# ------------------------------------------------------------------
set(MIQ_DB_TARGET "")
set(MIQ_DB_DEFINE "")

if(MIQ_USE_ROCKSDB)
  find_package(rocksdb QUIET)
  if(NOT rocksdb_FOUND)
    message(FATAL_ERROR "MIQ_USE_ROCKSDB=ON but RocksDB package not found.")
  endif()
  set(MIQ_DB_TARGET RocksDB::rocksdb)
  set(MIQ_DB_DEFINE MIQ_USE_ROCKSDB=1)
else()
  find_package(LevelDB QUIET)
  if(LevelDB_FOUND)
    set(MIQ_DB_TARGET LevelDB::LevelDB)
  else()
    if(NOT MIQ_FETCH_LEVELDB)
      message(FATAL_ERROR "LevelDB not found. Install LevelDB (e.g. apt install libleveldb-dev / brew install leveldb) or enable MIQ_FETCH_LEVELDB.")
    endif()
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
  set(MIQ_DB_DEFINE MIQ_USE_LEVELDB=1)
endif()

# ------------------------------------------------------------------
# libsecp256k1
# ------------------------------------------------------------------
set(MIQ_LIBSECP_TARGET "")
if(MIQ_USE_LIBSECP)
  find_package(secp256k1 CONFIG QUIET)
  if(secp256k1_FOUND)
    if(TARGET secp256k1::secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1::secp256k1)
    elseif(TARGET secp256k1)
      set(MIQ_LIBSECP_TARGET secp256k1)
    else()
      message(FATAL_ERROR "secp256k1 package found but no usable CMake target exported.")
    endif()
  else()
    message(STATUS "secp256k1 not found; fetching bitcoin-core/secp256k1 @ ${MIQ_LIBSECP_TAG}")
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
# Shared core sources
# ------------------------------------------------------------------
set(MIQ_CORE_SOURCES
    src/hd_wallet.cpp
    src/hd_wallet.h
    src/bip39_words_en.h
    src/addrman.h
    src/addrman.cpp
    src/address.h src/address.cpp
    src/wallet_store.h src/wallet_store.cpp
    src/reindex_utxo.h
    src/reindex_utxo.cpp
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
    src/crypto/ecdsa_iface.h
    src/crypto/ecdsa_libsecp256k1.cpp
    src/reorg_manager.h
    src/reorg_manager.cpp
    src/nat.cpp              # TryOpenP2PPort (real or stub depending on define)
    src/seeds.cpp
    src/mtp.h
    src/mtp.cpp
    src/tls_proxy.h src/tls_proxy.cpp
    src/ibd_monitor.h src/ibd_monitor.cpp
    src/wallet_encryptor.cpp
    src/crypto/secure_random.cpp
)

# ------------------------------------------------------------------
# UPnP/NAT-PMP detection & wiring
# ------------------------------------------------------------------
set(MIQ_UPNP_COMPILE_DEF 0)  # we will force a 0/1 define so nat.cpp always knows which branch

if(MIQ_ENABLE_UPNP)
  set(_MINIUPNPC_INC "")
  set(_MINIUPNPC_LIBS "")

  # pkg-config (Linux/macOS)
  if(PKG_CONFIG_FOUND)
    pkg_check_modules(MINIUPNPC QUIET miniupnpc)
    if(MINIUPNPC_FOUND)
      set(_MINIUPNPC_INC  ${MINIUPNPC_INCLUDE_DIRS})
      set(_MINIUPNPC_LIBS ${MINIUPNPC_LINK_LIBRARIES})
    endif()
  endif()

  # Fallback to find_path/library
  if(NOT _MINIUPNPC_LIBS)
    find_path(MINIUPNPC_INCLUDE_DIR miniupnpc/miniupnpc.h)
    find_library(MINIUPNPC_LIBRARY NAMES miniupnpc)
    if(MINIUPNPC_INCLUDE_DIR AND MINIUPNPC_LIBRARY)
      set(_MINIUPNPC_INC  ${MINIUPNPC_INCLUDE_DIR})
      set(_MINIUPNPC_LIBS ${MINIUPNPC_LIBRARY})
    endif()
  endif()

  # Optional fetch (OFF by default to keep CI offline-friendly)
  if(NOT _MINIUPNPC_LIBS AND MIQ_FETCH_MINIUPNPC)
    message(STATUS "miniupnpc not found; fetching miniupnp/miniupnpc (network required)")
    FetchContent_Declare(
      miniupnpc_src
      GIT_REPOSITORY https://github.com/miniupnp/miniupnpc.git
      GIT_TAG        master
      GIT_PROGRESS   TRUE
    )
    FetchContent_MakeAvailable(miniupnpc_src)
    # common names across versions
    if(TARGET miniupnpc)
      set(_MINIUPNPC_LIBS miniupnpc)
    elseif(TARGET libminiupnpc-static)
      set(_MINIUPNPC_LIBS libminiupnpc-static)
    elseif(TARGET libminiupnpc)
      set(_MINIUPNPC_LIBS libminiupnpc)
    endif()
    if(TARGET miniupnpc OR TARGET libminiupnpc-static OR TARGET libminiupnpc)
      # include dir normally ${miniupnpc_src_SOURCE_DIR}/include
      set(_MINIUPNPC_INC "${miniupnpc_src_SOURCE_DIR}/include")
    endif()
  endif()

  if(_MINIUPNPC_LIBS)
    set(MIQ_UPNP_COMPILE_DEF 1)
    message(STATUS "UPnP enabled (miniupnpc detected)")
  else()
    message(WARNING "miniupnpc not found; building with UPnP stub (no port mapping).")
  endif()
else()
  message(STATUS "UPnP disabled by option; building with stub.")
endif()

# ------------------------------------------------------------------
# Daemon (miqrod)
# ------------------------------------------------------------------
add_executable(miqrod src/main.cpp ${MIQ_CORE_SOURCES})

target_include_directories(miqrod PRIVATE src ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(miqrod PRIVATE ${MIQ_DB_TARGET})
if(MIQ_DB_DEFINE)
  target_compile_definitions(miqrod PRIVATE ${MIQ_DB_DEFINE})
endif()

# Always tell nat.cpp which branch it should compile (0 or 1).
target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_UPNP=${MIQ_UPNP_COMPILE_DEF})

# Link miniupnpc when available
if(MIQ_UPNP_COMPILE_DEF)
  if(_MINIUPNPC_INC)
    target_include_directories(miqrod PRIVATE ${_MINIUPNPC_INC})
  endif()
  if(_MINIUPNPC_LIBS)
    target_link_libraries(miqrod PRIVATE ${_MINIUPNPC_LIBS})
  endif()
  if(WIN32)
    # MiniUPnPc uses WinAPI networking helpers
    target_link_libraries(miqrod PRIVATE iphlpapi ws2_32)
  endif()
endif()

# Platform libs
if(WIN32)
  target_link_libraries(miqrod PRIVATE Ws2_32)
endif()

# TLS + Threads
target_link_libraries(miqrod PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)

# libsecp256k1 for daemon
if(MIQ_USE_LIBSECP)
  target_link_libraries(miqrod PRIVATE ${MIQ_LIBSECP_TARGET})
endif()

# Optional wallet encryption flag (code already uses OpenSSL)
if(MIQ_ENABLE_WALLET_ENC)
  target_compile_definitions(miqrod PRIVATE MIQ_ENABLE_WALLET_ENC=1)
  message(STATUS "Wallet encryption: ENABLED (OpenSSL)")
else()
  message(STATUS "Wallet encryption: DISABLED (default)")
endif()

# ------------------------------------------------------------------
# CLI wallet (miqwallet)
# ------------------------------------------------------------------
add_executable(miqwallet src/cli/miqwallet.cpp)
target_include_directories(miqwallet PRIVATE src)

# Sockets
if(WIN32)
  target_link_libraries(miqwallet PRIVATE ws2_32)
endif()

# Must link OpenSSL::Crypto because hd_wallet uses PBKDF2/HMAC/BIGNUMs
target_link_libraries(miqwallet PRIVATE OpenSSL::Crypto)

# Also link libsecp for key ops used by wallet code
if(MIQ_USE_LIBSECP)
  target_link_libraries(miqwallet PRIVATE ${MIQ_LIBSECP_TARGET})
endif()

set_target_properties(miqwallet PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED YES)

# ------------------------------------------------------------------
# Simple key tool
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
endif()
