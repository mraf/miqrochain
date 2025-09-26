#include "miner.h"
#include "sha256.h"
#include "merkle.h"
#include "hasher.h"      // fast midstate path + salted_header_hash (optional)
#include "difficulty.h"  // lwma_next_bits
#include "constants.h"
#include "chain.h"
#include "p2p.h"
#include "mempool.h"
#include "log.h"

#include <thread>
#include <atomic>
#include <vector>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <algorithm>

#if defined(_WIN32) && defined(MIQ_SET_AFFINITY)
  #define NOMINMAX
  #include <windows.h>
#endif

namespace {
    constexpr size_t HASH_LEN = 32;
}

namespace miq {

// ---------------- Miner stats (kept compatible) ----------------
static std::atomic<uint64_t> g_hashes{0};
static std::atomic<uint64_t> g_hashes_total{0};

uint64_t miner_hashes_snapshot_and_reset(){
    return g_hashes.exchange(0, std::memory_order_relaxed);
}
uint64_t miner_hashes_total(){
    return g_hashes_total.load(std::memory_order_relaxed);
}

MinerStats miner_stats_now() {
    using clock = std::chrono::steady_clock;
    static auto last_t = clock::now();
    static uint64_t last_total = miner_hashes_total();

    const auto  now   = clock::now();
    const double secs = std::chrono::duration<double>(now - last_t).count();
    const uint64_t tot = miner_hashes_total();
    const uint64_t dif = (tot >= last_total) ? (tot - last_total) : 0ULL;
    const double hps = (secs > 0.0) ? static_cast<double>(dif) / secs : 0.0;

    last_t = now;
    last_total = tot;
    return MinerStats{ hps, tot, secs };
}

// --------- compact bits -> big-endian 32B target ---------
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
// h <= target ? (big-endian)
static inline bool hash_leq_target(const uint8_t* h, const uint8_t* T){
    for(size_t i=0;i<HASH_LEN;i++){
        if(h[i] < T[i]) return true;
        if(h[i] > T[i]) return false;
    }
    return true;
}
bool meets_target(const std::vector<uint8_t>& hv, uint32_t bits){
    if(hv.size() != HASH_LEN) return false;
    unsigned char T[HASH_LEN];
    target_from_compact(bits, T);
    return hash_leq_target(hv.data(), T);
}

// --------- little-endian helpers ---------
static inline void put_u32_le(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(uint8_t((x>>0)&0xff));
    v.push_back(uint8_t((x>>8)&0xff));
    v.push_back(uint8_t((x>>16)&0xff));
    v.push_back(uint8_t((x>>24)&0xff));
}
static inline void put_u64_le(std::vector<uint8_t>& v, uint64_t x) {
    v.push_back(uint8_t((x>>0 )&0xff));
    v.push_back(uint8_t((x>>8 )&0xff));
    v.push_back(uint8_t((x>>16)&0xff));
    v.push_back(uint8_t((x>>24)&0xff));
    v.push_back(uint8_t((x>>32)&0xff));
    v.push_back(uint8_t((x>>40)&0xff));
    v.push_back(uint8_t((x>>48)&0xff));
    v.push_back(uint8_t((x>>56)&0xff));
}
static inline void store_u64_le(uint8_t* p, uint64_t x) {
    p[0]=uint8_t((x>>0 )&0xff); p[1]=uint8_t((x>>8 )&0xff);
    p[2]=uint8_t((x>>16)&0xff); p[3]=uint8_t((x>>24)&0xff);
    p[4]=uint8_t((x>>32)&0xff); p[5]=uint8_t((x>>40)&0xff);
    p[6]=uint8_t((x>>48)&0xff); p[7]=uint8_t((x>>56)&0xff);
}

// header prefix (all but nonce)
static inline std::vector<uint8_t> build_header_prefix(const BlockHeader& h) {
    std::vector<uint8_t> v;
    v.reserve(4 + 32 + 32 + 8 + 4);
    put_u32_le(v, h.version);
    v.insert(v.end(), h.prev_hash.begin(),   h.prev_hash.end());
    v.insert(v.end(), h.merkle_root.begin(), h.merkle_root.end());
    put_u64_le(v, static_cast<uint64_t>(h.time));
    put_u32_le(v, h.bits);
    return v;
}

// ================== Miner ==================

Miner::Miner(Chain& chain, P2P* p2p) : chain_(chain), p2p_(p2p) {}
Miner::~Miner(){ stop(); }

void Miner::set_reward_pkh(const std::vector<uint8_t>& pkh20){
    reward_pkh20_ = pkh20;
}
void Miner::set_threads(unsigned t){
    threads_ = t;
}
void Miner::set_max_txs(size_t n){
    max_txs_ = n;
}
void Miner::set_rebuild_interval_ms(int64_t ms){
    rebuild_ms_ = std::max<int64_t>(1000, ms);
}

void Miner::start(){
    if (running_) return;
    running_ = true;
    th_ = std::thread([this]{ run(); });
}
void Miner::stop(){
    if (!running_) return;
    running_ = false;
    if (th_.joinable()) th_.join();
}

// Build coinbase paying only subsidy (fees are optional and safe to omit)
static Transaction make_coinbase_for(Chain& chain,
                                     const std::vector<uint8_t>& pkh20)
{
    Transaction cb;
    cb.vin.resize(1);
    cb.vin[0].prev.txid.assign(32, 0);
    cb.vin[0].prev.vout = 0;
    TxOut out0;
    out0.value = chain.subsidy_for_height(chain.height() + 1);
    out0.pkh   = (pkh20.size()==20) ? pkh20 : std::vector<uint8_t>(20,0);
    cb.vout.push_back(std::move(out0));
    return cb;
}

static uint32_t calc_bits_now(Chain& chain) {
    auto last = chain.last_headers(90);
    if (last.size() < 2) return last.empty() ? GENESIS_BITS : last.back().second;
    return lwma_next_bits(last, BLOCK_TIME_SECS, GENESIS_BITS);
}

bool Miner::build_template(Block& b, uint32_t& bits){
    // snapshot the tip and difficulty
    Tip tip = chain_.tip();
    bits = calc_bits_now(chain_);

    b = Block{};
    b.header.prev_hash = tip.hash;
    b.header.bits      = bits;
    b.header.time      = static_cast<int64_t>(time(nullptr));

    // coinbase + txs
    b.txs.clear();
    b.txs.push_back(make_coinbase_for(chain_, reward_pkh20_));

    if (p2p_) {
        // Pull high-fee txs (already policy-checked by mempool)
        auto picked = (p2p_ && p2p_->mempool())
                ? p2p_->mempool()->collect(max_txs_)
                : std::vector<Transaction>{};
        b.txs.insert(b.txs.end(), picked.begin(), picked.end());
    }

    // merkle
    std::vector<std::vector<uint8_t>> txids;
    txids.reserve(b.txs.size());
    for (const auto& tx : b.txs) txids.push_back(tx.txid());
    b.header.merkle_root = merkle_root(txids);

    return true;
}

bool Miner::pow_loop(Block& b, uint32_t bits){
    // Fixed job window to refresh time/txs periodically
    const auto job_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(rebuild_ms_);

    // Snapshot tip to detect reorg/new block
    const std::vector<uint8_t> tip_hash_start = chain_.tip().hash;

    // Build header prefix and (if enabled) midstate
    std::vector<uint8_t> header_prefix = build_header_prefix(b.header);
    const size_t nonce_off = header_prefix.size();

    unsigned char Tglob[HASH_LEN];
    target_from_compact(bits, Tglob);

#if !defined(MIQ_POW_SALT)
    FastSha256Ctx base1;
    fastsha_init(base1);
    fastsha_update(base1, header_prefix.data(), header_prefix.size()); // 80 bytes
#endif

    const unsigned nthreads = (threads_ == 0) ? std::max(1u, std::thread::hardware_concurrency()) : threads_;

    std::atomic<bool> found{false};
    std::atomic<uint64_t> best_nonce{0};
    std::atomic<bool> abort{false};

    // randomish base per job
    const uint64_t base_nonce =
        (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull;

    std::vector<std::thread> ths;
    ths.reserve(nthreads);

    for (unsigned t = 0; t < nthreads; ++t) {
        ths.emplace_back([&, t](){
        #if defined(_WIN32) && defined(MIQ_SET_AFFINITY)
            const int maskBits = static_cast<int>(sizeof(DWORD_PTR) * 8);
            const int cpu = static_cast<int>(t % static_cast<unsigned>(maskBits));
            const DWORD_PTR mask = (DWORD_PTR(1) << cpu);
            SetThreadAffinityMask(GetCurrentThread(), mask);
        #endif
            uint64_t local_hashes = 0;
            const uint64_t FLUSH_EVERY = (1ull<<18);

            std::vector<uint8_t> hdr = header_prefix;
            hdr.resize(header_prefix.size() + 8);
            uint8_t* nonce_ptr = hdr.data() + nonce_off;

            const uint64_t stride = (uint64_t)nthreads;
            uint64_t nonce = base_nonce + (uint64_t)t;

            while (!found.load(std::memory_order_relaxed)) {
                // abort conditions: deadline or tip changed or external stop
                if (abort.load(std::memory_order_relaxed)) break;
                if (std::chrono::steady_clock::now() > job_deadline) break;
                if (!running_.load(std::memory_order_relaxed)) break;
                if (chain_.tip().hash != tip_hash_start) break;

                store_u64_le(nonce_ptr, nonce);

                uint8_t h[HASH_LEN];
            #if !defined(MIQ_POW_SALT)
                uint8_t nonce_le[8];
                store_u64_le(nonce_le, nonce);
                dsha256_from_base(base1, nonce_le, sizeof(nonce_le), h);
            #else
                const auto hv = salted_header_hash(hdr);
                std::memcpy(h, hv.data(), HASH_LEN);
            #endif
                if (hash_leq_target(h, Tglob)) {
                    best_nonce.store(nonce, std::memory_order_relaxed);
                    found.store(true, std::memory_order_relaxed);
                    g_hashes.fetch_add(++local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    return;
                }

                if ((++local_hashes & (FLUSH_EVERY-1)) == 0) {
                    g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    local_hashes = 0;
                }
                nonce += stride;
            }

            if (local_hashes) {
                g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : ths) th.join();

    if (!found.load(std::memory_order_relaxed)) return false;

    b.header.nonce = best_nonce.load(std::memory_order_relaxed);
    return true;
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
    for (const auto& tx : mempool_txs) b.txs.push_back(tx);

    // Merkle
    std::vector<std::vector<uint8_t>> txids;
    txids.reserve(b.txs.size());
    for (const auto& t : b.txs) txids.push_back(t.txid());
    b.header.merkle_root = merkle_root(txids);

    if (threads == 0) threads = 1;

    // Header prefix (80 bytes): ver|prev|merkle|time|bits
    const std::vector<uint8_t> header_prefix = [&]{
        std::vector<uint8_t> v;
        v.reserve(4 + 32 + 32 + 8 + 4);
        // reuse local helpers declared earlier in this file
        // put_u32_le, put_u64_le
        put_u32_le(v, b.header.version);
        v.insert(v.end(), b.header.prev_hash.begin(),   b.header.prev_hash.end());
        v.insert(v.end(), b.header.merkle_root.begin(), b.header.merkle_root.end());
        put_u64_le(v, static_cast<uint64_t>(b.header.time));
        put_u32_le(v, b.header.bits);
        return v;
    }();
    const size_t nonce_off = header_prefix.size();

    std::atomic<bool> found{false};
    std::atomic<uint64_t> best_nonce{0};

    // Precompute target
    unsigned char Tglob[32];
    target_from_compact(bits, Tglob);

#if !defined(MIQ_POW_SALT)
    // Fast midstate for first SHA256
    FastSha256Ctx base1;
    fastsha_init(base1);
    fastsha_update(base1, header_prefix.data(), header_prefix.size());
#endif

    // Disjoint nonce streams per thread
    const uint64_t base_nonce =
        (static_cast<uint64_t>(time(nullptr)) << 32) ^ 0x9e3779b97f4a7c15ull;

    std::vector<std::thread> ths;
    ths.reserve(threads);

    for (unsigned t = 0; t < threads; ++t) {
        ths.emplace_back([&, t](){
        #if defined(_WIN32) && defined(MIQ_SET_AFFINITY)
            const int maskBits = static_cast<int>(sizeof(DWORD_PTR) * 8);
            const int cpu = static_cast<int>(t % static_cast<unsigned>(maskBits));
            const DWORD_PTR mask = (DWORD_PTR(1) << cpu);
            SetThreadAffinityMask(GetCurrentThread(), mask);
        #endif
            uint64_t local_hashes = 0;
            const uint64_t FLUSH_EVERY = (1ull<<18);

            std::vector<uint8_t> hdr = header_prefix;
            hdr.resize(header_prefix.size() + 8);
            uint8_t* nonce_ptr = hdr.data() + nonce_off;

            const uint64_t stride = (uint64_t)threads;
            uint64_t nonce = base_nonce + (uint64_t)t;

            while (!found.load(std::memory_order_relaxed)) {
                store_u64_le(nonce_ptr, nonce);

                uint8_t h[32];
            #if !defined(MIQ_POW_SALT)
                uint8_t nonce_le[8];
                store_u64_le(nonce_le, nonce);
                dsha256_from_base(base1, nonce_le, sizeof(nonce_le), h);
            #else
                const auto hv = salted_header_hash(hdr);
                std::memcpy(h, hv.data(), 32);
            #endif
                if (hash_leq_target(h, Tglob)) {
                    best_nonce.store(nonce, std::memory_order_relaxed);
                    found.store(true, std::memory_order_relaxed);
                    g_hashes.fetch_add(++local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    return;
                }

                if ((++local_hashes & (FLUSH_EVERY-1)) == 0) {
                    g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                    g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
                    local_hashes = 0;
                }
                nonce += stride;
            }

            if (local_hashes) {
                g_hashes.fetch_add(local_hashes, std::memory_order_relaxed);
                g_hashes_total.fetch_add(local_hashes, std::memory_order_relaxed);
            }
        });
    }

    for (auto& th : ths) th.join();

    b.header.nonce = best_nonce.load(std::memory_order_relaxed);
    return b;
}

void Miner::run(){
    log_info("miner: started");
    while (running_) {
        Block b;
        uint32_t bits = 0;

        // Build a fresh template (prev/bits/time/txs)
        if (!build_template(b, bits)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        // Hash until success or template expiration/tip change
        const bool ok = pow_loop(b, bits);
        if (!ok) continue; // just rebuild and keep going

        // If tip moved while hashing, this might be stale—recheck:
        if (chain_.tip().hash != b.header.prev_hash) {
            // stale; discard and rebuild
            continue;
        }

        std::string err;
        if (!chain_.submit_block(b, err)) {
            log_warn(std::string("miner: mined block rejected: ") + err);
            // rebuild a new template on next loop
            continue;
        }

        // Broadcast to peers
        if (p2p_) p2p_->broadcast_inv_block(b.block_hash());
        log_info("miner: mined and accepted a block");
        // Then immediately start a new round on the extended tip
    }
    log_info("miner: stopped");
}

}
