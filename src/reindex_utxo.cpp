#include "reindex_utxo.h"
#include "serialize.h"
#include "log.h"
#include <cstdint>

namespace miq {

static inline UTXOEntry coin_from_txout(const Transaction& tx, uint32_t vout, uint32_t height){
    UTXOEntry e;
    e.value    = tx.vout[vout].value;           // uint64_t
    e.pkh      = tx.vout[vout].script_pubkey;   // raw script; if you're storing PKH only, adjust extraction
    e.height   = height;
    e.coinbase = (tx.vin.size() == 1 && tx.vin[0].prev_hash == std::vector<uint8_t>(32, 0));
    return e;
}

bool ReindexUTXO(Chain& chain, UTXOKV& kv, bool compact_after, std::string& err){
    // Open chainstate KV (inside UTXOKV::open)
    if (!kv.open(chain.datadir(), &err)) {
        if (err.empty()) err = "reindex_utxo: failed to open chainstate";
        return false;
    }

    const size_t tip = chain.height();
    const size_t batch_size = 2000; // tune as you like

    size_t i = 0;
    while (i <= tip) {
        UTXOKV::Batch batch(kv);

        size_t end = std::min(tip, i + batch_size - 1);
        for (; i <= end; ++i) {
            Block b;
            if (!chain.get_block_by_index(i, b)) {
                err = "reindex_utxo: missing block at index " + std::to_string(i);
                return false;
            }

            // Spend inputs then add outputs
            for (const auto& tx : b.txs) {
                // Spend (skip coinbase null prev)
                for (const auto& in : tx.vin) {
                    if (in.prev_hash.size() != 32) continue;
                    if (in.prev_hash == std::vector<uint8_t>(32, 0)) continue;
                    batch.spend(in.prev_hash, in.prev_index);
                }
                // Add new coins
                for (uint32_t vout = 0; vout < (uint32_t)tx.vout.size(); ++vout) {
                    auto e = coin_from_txout(tx, vout, (uint32_t)b.height);
                    batch.add(tx.txid(), vout, e);
                }
            }
        }

        std::string cerr;
        if (!batch.commit(/*sync=*/true, &cerr)) {
            err = cerr.empty() ? "reindex_utxo: batch commit failed" : cerr;
            return false;
        }

        if ((i % 5000) == 0 || i > tip) {
            log_info("reindex_utxo: " + std::to_string(std::min(i, tip+1)) + "/" + std::to_string(tip+1) + " blocks");
        }
    }

    // Optional compaction (depends on KVDB implementation; safe to call even if noop)
    // If your KVDB has db_.compact(), expose it via UTXOKV (e.g., kv.compact()).
    // For now we skip: no public compact() in UTXOKV interface.

    (void)compact_after; // kept for future when you expose compact()

    return true;
}

}
