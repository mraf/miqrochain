// src/miner.cpp — canonical binary-header miner + exact compact-target check
// - Consensus preserved: PoW is dsha256(binary header ver|prev|merkle|time|bits|nonce)
// - Nonce appended as LE uint64; all ints LE, hashes big-endian compare
// - Keeps public API & stats; keeps includes

#include "miner.h"
#include "sha256.h"
#include "merkle.h"
#include "hasher.h"  // used for accelerated double-SHA256 (salt disabled unless defined)
#include "log.h"

#include <thread>
#include <atomic>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <string>

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
static inline void target_from_compact(uint32_t bits, unsigned char out[32]){
    std::memset(out, 0, 32);
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if(exp <= 3){
        uint32_t v = mant >> (8*(3-exp));
        out[29] = (uint8_t)((v >> 16) & 0xff);
        out[30] = (uint8_t)((v >>  8) & 0xff);
        out[31] = (uint8_t)((v      ) & 0xff);
    } else {
        int idx = 32 - (int)exp;
        if(idx < 0) idx = 0;
        if(idx > 29) idx = 29;
        out[idx+0] = (uint8_t)((mant >> 16) & 0xff);
        out[idx+1] = (uint8_t)((mant >>  8) & 0xff);
        out[idx+2] = (uint8_t)((mant      ) & 0xff);
    }
}

// h <= target ?
static inline bool hash_meets_bits(const uint8_t h[32], uint32_t bits){
    unsigned char T[32];
    target_from_compact(bits, T);
    for(int i=0;i<32;i++){
        if(h[i] < T[i]) return true;
        if(h[i] > T[i]) return false;
    }
    return true; // equal
}

// Keep exported signature
bool meets_target(const std::vector<uint8_t>& hv, uint32_t bits){
    if(hv.size()!=32) return false;
    return hash_meets_bits(hv.data(), bits);
}

// --------- helpers for binary header (LE integer encoding) ---------
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t((x >> 0) & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff));
    v.push_back(uint8_t((x >> 24) & 0xff));
}
static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    v.push_back(uint8_t((x >> 0) & 0xff));
    v.push_back(uint8_t((x >> 8) & 0xff));
    v.push_back(uint8_t((x >> 16) & 0xff));
    v.push_back(uint8_t((x >> 24) & 0xff));
    v.push_back(uint8_t((x >> 32) & 0xff));
    v.push_back(uint8_t((x >> 40) & 0xff));
    v.push_back(uint8_t((x >> 48) & 0xff));
    v.push_back(uint8_t((x >> 56) & 0xff));
}
// Overwrite an existing 8-byte slot with LE nonce (no reallocation)
static inline void store_u64_le(uint8_t* p, uint64_t x) {
    p[0] = (uint8_t)((x >> 0)  & 0xff);
    p[1] = (uint8_t)((x >> 8)  & 0xff);
    p[2] = (uint8_t)((x >> 16) & 0xff);
    p[3] = (uint8_t)((x >> 24) & 0xff);
    p[4] = (uint8_t)((x >> 32) & 0xff);
    p[5] = (uint8_t)((x >> 40) & 0xff);
    p[6] = (uint8_t)((x >> 48) & 0xff);
    p[7] = (uint8_t)((x >> 56) & 0xff);
}

// Build the fixed header prefix (everything except nonce) once per block:
//   uint32 ver | 32 prev_hash | 32 merkle_root | int64 time | uint32 bits
static inline std::vector<uint8_t> build_header_prefix(const BlockHeader& h) {
    std::vector<uint8_t> v;
    v.reserve(4 + 32 + 32 + 8 + 4);
    put_u32_le(v, h.version);
    v.insert(v.end(), h.prev_hash.begin(), h.prev_hash.end());
    v.insert(v.end(), h.merkle_root.begin(), h.merkle_root.end());
    put_u64_le(v, (uint64_t)h.time);
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

    for(unsigned t=0; t<threads; ++t){
        ths.emplace_back([&, t](){
            uint64_t local_hashes = 0;
            const uint64_t FLUSH_EVERY = 1ull<<15; // reduce atomic overhead

            // Per-thread header buffer reused every hash (no allocations)
            std::vector<uint8_t> hdr = header_prefix;
            hdr.resize(header_prefix.size() + 8); // reserve LE nonce slot
            uint8_t* nonce_ptr = hdr.data() + nonce_off;

            // start nonce per thread (unique-ish)
            uint64_t nonce = ((uint64_t)time(nullptr) << 32)
                           ^ (0x9e3779b97f4a7c15ull + (uint64_t)t*0x5851f42d4c957f2dull);

            uint8_t h[32];

            while(!found.load(std::memory_order_relaxed)){
                // Overwrite the 8-byte nonce in place (LE)
                store_u64_le(nonce_ptr, nonce);

                // Double-SHA256(header) — accelerated path (falls back internally)
                // NOTE: 'salted_header_hash' keeps PoW semantics unless MIQ_POW_SALT is defined.
                auto hv = salted_header_hash(hdr);
                std::memcpy(h, hv.data(), 32);
                local_hashes++;

                if(hash_meets_bits(h, bits)){
                    best_nonce.store(nonce, std::memory_order_relaxed);
                    found.store(true, std::memory_order_relaxed);
                    // final flush
                    g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    return;
                }

                if((local_hashes & (FLUSH_EVERY-1)) == 0){
                    g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    local_hashes = 0;
                }

                nonce++;
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

