#include "reindex.h"
#include "kv_log.h"
#include "serialize.h"
#include "log.h"

namespace miq {

bool reindex_utxo_from_chain(Chain& chain, const std::string& kv_path, bool compact_after, std::string& err){
    LogKV kv;
    if (!kv.open(kv_path, err)) return false;
    UTXOViewKV view(&kv);

    // Replay all blocks from genesis to tip.
    size_t height = chain.height();
    for (size_t i = 0; i <= height; ++i) {
        Block b;
        if (!chain.get_block_by_index(i, b)) { err = "reindex: missing block at index " + std::to_string(i); return false; }

        // Spend coinbase inputs from previous txs? (coinbase has no prevs)
        for (const auto& tx : b.txs) {
            // Spend inputs (skip coinbase’s null prev)
            for (const auto& in : tx.vin) {
                if (in.prev_hash.size() != 32) continue;
                if (in.prev_hash == std::vector<uint8_t>(32,0)) continue; // coinbase
                std::string derr;
                if (!view.spend(in.prev_hash, in.prev_index, derr)) {
                    // It might already be spent in earlier block (forks), ignore.
                }
            }
            // Add outputs
            for (uint32_t vout = 0; vout < (uint32_t)tx.vout.size(); ++vout) {
                Coin c;
                c.amount = tx.vout[vout].value;
                c.height = (uint32_t)b.height; // if you track height in header; fallback to i
                c.script = tx.vout[vout].script_pubkey;
                std::string perr;
                (void)view.add(tx.txid(), vout, c, perr);
            }
        }

        if ((i % 1000) == 0) {
            auto st = kv.stats();
            log_info("reindex: at " + std::to_string(i) + " / " + std::to_string(height) +
                     " live=" + std::to_string(st.live_keys) +
                     " file=" + std::to_string(st.file_bytes/1024) + " KiB");
        }
    }

    if (compact_after) {
        if (!kv.compact(err)) return false;
    }
    kv.close();
    return true;
}

}
