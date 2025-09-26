#pragma once
#include <atomic>
#include <thread>
#include <vector>
#include <cstdint>
#include <string>

#include "block.h"
#include "chain.h"
#include "mempool.h"
#include "p2p.h"

namespace miq {

class Miner {
public:
    // p2p may be null; when present we’ll use its mempool and broadcast
    Miner(Chain& chain, P2P* p2p = nullptr);
    ~Miner();

    // Set the payout pubkey-hash for the coinbase output (20 bytes expected).
    void set_reward_pkh(const std::vector<uint8_t>& pkh);

    // Start/stop a single mining thread.
    bool start();
    void stop();
    bool running() const { return running_.load(); }

private:
    Chain& chain_;
    P2P*   p2p_{nullptr};

    std::thread th_;
    std::atomic<bool> running_{false};

    // where to pay the subsidy+fees
    std::vector<uint8_t> reward_pkh_;

    // Build a block template (coinbase + selected mempool txs), return expected bits.
    bool build_template(Block& out, uint32_t& bits_out);

    // Main mining loop.
    void mine_loop();

    // Helpers: difficulty target checks
    static void bits_to_target_be(uint32_t bits, uint8_t out[32]);
    static bool meets_target_be(const std::vector<uint8_t>& hash32, uint32_t bits);
};

} // namespace miq
