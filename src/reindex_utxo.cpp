#include "reindex_utxo.h"
#include "serialize.h"
#include "log.h"

namespace miq {

static inline UTXOEntry coin_from_txout(const Transaction& tx, uint32_t vout, uint32_t height){
    UTXOEntry e;
    e.value    = tx.vout[vout].value;     // uint64_t
    e.pkh      = tx.vout[vout].pkh;       // 20 bytes
    e.height   = height;
    e.coinbase = (tx.vin.size() == 1 && tx.vin[0].prev.txid == std::vector<uint8_t>(32, 0));
    return e;
}

bool ReindexUTXO(Chain& chain, UTXOKV& kv, bool compact_after, std::string& err){
    // Open chainstate KV at <datadir>/chainstate
    if (!kv.open(chain.datadir(), &err)) {
        if (err.empty()) err = "reindex_utxo: failed to open chainstate";
        return false;
    }

    const size_t tip = chain.height();
    const size_t batch_size = 2000; // tune as needed

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
                    if (in.prev.txid.size() != 32) continue;
                    if (in.prev.txid == std::vector<uint8_t>(32, 0)) continue;
                    batch.spend(in.prev.txid, in.prev.vout);
                }
                // Add new coins
                for (uint32_t vout = 0; vout < (uint32_t)tx.vout.size(); ++vout) {
                    auto e = coin_from_txout(tx, vout, (uint32_t)i);
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

    (void)compact_after; // reserved for future KVDB compaction hook
    return true;
}

}
