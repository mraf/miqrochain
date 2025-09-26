// miner.cpp — optimized hot path (no consensus/ABI changes, no warnings on MSVC/GCC/Clang)
//
// - Keeps public behavior identical (header layout, PoW hash, meets_target signature).
// - Optimizations:
//     * Per-thread cached difficulty target
//     * Disjoint nonce strides per thread (no collisions)
//     * Fewer atomics (batched counters)
//     * Direct hash-vs-target compare (no intermediate copy)
//     * Optional Windows thread affinity behind MIQ_SET_AFFINITY
//
// Build tips: Release x64, /O2 or -O3, consider LTO. Define MIQ_SET_AFFINITY on Windows if you want core pinning.

#include "miner.h"
#include "sha256.h"
#include "merkle.h"
#include "hasher.h"  // accelerated double-SHA256 (salt disabled unless defined)
#include "log.h"

#include <thread>
#include <atomic>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <string>

#if defined(_WIN32) && defined(MIQ_SET_AFFINITY)
  #define NOMINMAX
  #include <windows.h>
#endif

namespace {
    constexpr size_t HASH_LEN = 32;
}

namespace miq {

// --------- miner stats (public API as before) ---------
static std::atomic<uint64_t> g_hashes{0};
static std::atomic<uint64_t> g_hashes_total{0};

uint64_t miner_hashes_snapshot_and_reset(){
    return g_hashes.exchange(0, std::memory_order_relaxed);
}
uint64_t miner_hashes_total(){
    return g_hashes_total.load(std::memory_order_relaxed);
}

// --------- difficulty: compact -> 32-byte big-endian target ---------
static inline void target_from_compact(uint32_t bits, unsigned char out[HASH_LEN]){
    std::memset(out, 0, HASH_LEN);
    const uint32_t exp  = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;
    if(exp <= 3){
        const uint32_t v = mant >> (8u*(3u-exp));
        out[29] = static_cast<uint8_t>((v >> 16) & 0xffu);
        out[30] = static_cast<uint8_t>((v >>  8) & 0xffu);
        out[31] = static_cast<uint8_t>((v      ) & 0xffu);
    } else {
        int idx = 32 - static_cast<int>(exp);
        if(idx < 0) idx = 0;
        if(idx > 29) idx = 29;
        out[static_cast<size_t>(idx)+0] = static_cast<uint8_t>((mant >> 16) & 0xffu);
        out[static_cast<size_t>(idx)+1] = static_cast<uint8_t>((mant >>  8) & 0xffu);
        out[static_cast<size_t>(idx)+2] = static_cast<uint8_t>((mant      ) & 0xffu);
    }
}

// h <= target ?  (big-endian byte-wise compare)
static inline bool hash_leq_target(const uint8_t* h, const uint8_t* T){
    for(size_t i=0;i<HASH_LEN;i++){
        if(h[i] < T[i]) return true;
        if(h[i] > T[i]) return false;
    }
    return true; // equal
}

// Keep exported signature (unchanged ABI)
bool meets_target(const std::vector<uint8_t>& hv, uint32_t bits){
    if(hv.size() != static_cast<size_t>(HASH_LEN)) return false;
    unsigned char T[HASH_LEN];
    target_from_compact(bits, T);
    return hash_leq_target(hv.data(), T);
}

// --------- helpers for binary header (LE integer encoding) ---------
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>((x >> 0) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 8) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xffu));
}
static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    v.push_back(static_cast<uint8_t>((x >> 0)  & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 8)  & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 16) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 24) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 32) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 40) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 48) & 0xffu));
    v.push_back(static_cast<uint8_t>((x >> 56) & 0xffu));
}
// Overwrite an existing 8-byte slot with LE nonce (no reallocation)
static inline void store_u64_le(uint8_t* p, uint64_t x) {
    p[0] = static_cast<uint8_t>((x >> 0)  & 0xffu);
    p[1] = static_cast<uint8_t>((x >> 8)  & 0xffu);
    p[2] = static_cast<uint8_t>((x >> 16) & 0xffu);
    p[3] = static_cast<uint8_t>((x >> 24) & 0xffu);
    p[4] = static_cast<uint8_t>((x >> 32) & 0xffu);
    p[5] = static_cast<uint8_t>((x >> 40) & 0xffu);
    p[6] = static_cast<uint8_t>((x >> 48) & 0xffu);
    p[7] = static_cast<uint8_t>((x >> 56) & 0xffu);
}

// Build the fixed header prefix (everything except nonce) once per block:
//   uint32 ver | 32 prev_hash | 32 merkle_root | int64 time | uint32 bits
static inline std::vector<uint8_t> build_header_prefix(const BlockHeader& h) {
    std::vector<uint8_t> v;
    v.reserve(4 + 32 + 32 + 8 + 4);
    put_u32_le(v, h.version);
    v.insert(v.end(), h.prev_hash.begin(), h.prev_hash.end());
    v.insert(v.end(), h.merkle_root.begin(), h.merkle_root.end());
    put_u64_le(v, static_cast<uint64_t>(h.time));
    put_u32_le(v, h.bits);
    return v;
}

Block mine_block(const std::vector<uint8_t>& prev_hash,
                 uint32_t bits,
                 const Transaction& coinbase,
                 const std::vector<Transaction>& mempool_txs,
                 unsigned threads)
{
    Block b;
    b.header.prev_hash = prev_hash;
    b.header.bits      = bits;
    b.header.time      = static_cast<int64_t>(time(nullptr));

    b.txs.clear();
    b.txs.push_back(coinbase);
    for(const auto& tx : mempool_txs) b.txs.push_back(tx);

    // Merkle
    std::vector<std::vector<uint8_t>> txids;
    txids.reserve(b.txs.size());
    for(const auto& t : b.txs) txids.push_back(t.txid());
    b.header.merkle_root = merkle_root(txids);

    if(threads==0) threads = 1;

    // === Build binary header prefix once (everything except nonce)
    const std::vector<uint8_t> header_prefix = build_header_prefix(b.header);
    const size_t nonce_off = header_prefix.size(); // LE nonce goes right after

    std::atomic<bool> found{false};
    std::atomic<uint64_t> best_nonce{0};

    std::vector<std::thread> ths;
    ths.reserve(threads);

    // Precompute target once (shared read-only)
    unsigned char Tglob[HASH_LEN];
    target_from_compact(bits, Tglob);

    // Make a common, well-distributed base
    const uint64_t base_nonce =
        (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull;

    for(unsigned t=0; t<threads; ++t){
        ths.emplace_back([&, t](){
            #if defined(_WIN32) && defined(MIQ_SET_AFFINITY)
            // Optional: pin this worker to a core (toggle with MIQ_SET_AFFINITY)
            const int maskBits = static_cast<int>(sizeof(DWORD_PTR) * 8);
            const int cpu = static_cast<int>(t % static_cast<unsigned>(maskBits));
            const DWORD_PTR mask = (DWORD_PTR(1) << cpu);
            SetThreadAffinityMask(GetCurrentThread(), mask);
            #endif

            uint64_t local_hashes = 0;
            const uint64_t FLUSH_EVERY = (1ull<<18); // fewer atomics, better throughput

            // Per-thread header buffer reused every hash (no allocations)
            std::vector<uint8_t> hdr = header_prefix;
            hdr.resize(header_prefix.size() + 8); // reserve LE nonce slot
            uint8_t* nonce_ptr = hdr.data() + nonce_off;

            // Each thread walks a disjoint arithmetic progression of nonces
            const uint64_t stride = static_cast<uint64_t>(threads);
            uint64_t nonce = (base_nonce + static_cast<uint64_t>(t));

            while(!found.load(std::memory_order_relaxed)){
                // Overwrite the 8-byte nonce in place (LE)
                store_u64_le(nonce_ptr, nonce);

                // Double-SHA256(header) — accelerated path (falls back internally)
                // NOTE: 'salted_header_hash' keeps PoW semantics unless MIQ_POW_SALT is defined.
                const auto hv = salted_header_hash(hdr);

                // Compare directly without copying; Tglob is constant per block
                if(hv.size()==HASH_LEN && hash_leq_target(hv.data(), Tglob)){
                    best_nonce.store(nonce, std::memory_order_relaxed);
                    found.store(true, std::memory_order_relaxed);
                    // final flush (count this attempt)
                    g_hashes.fetch_add(++local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    return;
                }

                // account this attempt and flush occasionally
                if((++local_hashes & (FLUSH_EVERY-1)) == 0){
                    g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    local_hashes = 0;
                }

                // next candidate for this thread
                nonce += stride;
            }

            if(local_hashes){
                g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
            }
        });
    }

    for(auto& th : ths) th.join();

    b.header.nonce = best_nonce.load(std::memory_order_relaxed);
    return b;
}

} // namespace miq
