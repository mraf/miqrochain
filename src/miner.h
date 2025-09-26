#pragma once
#include <vector>
#include <cstdint>
#include <atomic>
#include <thread>
#include "block.h"

namespace miq {

// === Public miner stats API (kept stable) ===
struct MinerStats { double hps; uint64_t total; double window_secs; };

uint64_t miner_hashes_snapshot_and_reset();
uint64_t miner_hashes_total();
MinerStats miner_stats_now();
bool meets_target(const std::vector<uint8_t>& hv, uint32_t bits);

class Chain;
class P2P;

// Integrated, network-aware background miner
class Miner {
public:
    explicit Miner(Chain& chain, P2P* p2p = nullptr);
    ~Miner();

    void set_reward_pkh(const std::vector<uint8_t>& pkh20);  // 20-byte PKH
    void set_threads(unsigned t);                             // 0 => auto (hw_concurrency)
    void set_max_txs(size_t n);                               // txs to include from mempool
    void set_rebuild_interval_ms(int64_t ms);                 // refresh template (time/txs)

    void start();
    void stop();
    bool running() const { return running_; }

private:
    Chain& chain_;
    P2P*   p2p_;
    std::thread th_;
    std::atomic<bool> running_{false};

    std::vector<uint8_t> reward_pkh20_;
    unsigned threads_{0};
    size_t   max_txs_{2000};
    int64_t  rebuild_ms_{5000}; // rebuild header/time/tx set every ~5s

    void run();
    bool build_template(Block& b, uint32_t& bits);
    bool pow_loop(Block& b, uint32_t bits); // returns true if found (fills nonce)
};

Block mine_block(const std::vector<uint8_t>& prev_hash,
                 uint32_t bits,
                 const Transaction& coinbase,
                 const std::vector<Transaction>& mempool_txs,
                 unsigned threads);

}
