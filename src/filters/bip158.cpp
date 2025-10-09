#include "filters/bip158.h"
#include "hex.h"

#include <algorithm>
#include <cstring>
#include <sstream>

namespace miq {
namespace bip158 {

static std::array<uint8_t,16> key_from_block_hash_le16(const Block& b){
    auto h = b.block_hash();            // vector<uint8_t> (big-endian internal? we'll use bytes as-is then reverse for LE16)
    // BIP158: "first 16 bytes of the hash (in standard little-endian representation)"
    // Our block_hash() returns bytes in the internal hash-order (most chains use big-endian hex).
    // Convert to little-endian by reversing then taking first 16 bytes.
    std::array<uint8_t,16> k{};
    if (h.size() >= 32) {
        // reverse full 32 then take first 16
        std::reverse(h.begin(), h.end());
        std::memcpy(k.data(), h.data(), 16);
    } else {
        // fallback: copy as much as we have
        size_t n = std::min<size_t>(16, h.size());
        std::memcpy(k.data(), h.data(), n);
    }
    return k;
}

bool BuildBasicFilter(const Block& blk, const UTXO& utxo, BasicFilter& out, std::string* err){
    try {
        // Collect items (raw bytes) that go into the set
        std::vector<std::vector<uint8_t>> items;
        items.reserve(blk.txs.size() * 3);

        // For each tx: add prevout PKH for non-coinbase inputs
        for (size_t ti = 0; ti < blk.txs.size(); ++ti){
            const Transaction& tx = blk.txs[ti];
            const bool coinbase = (ti == 0);
            for (size_t vi = 0; vi < tx.vin.size(); ++vi){
                if (coinbase) break;
                const auto& in = tx.vin[vi];
                UTXOEntry e;
                if (utxo.get(in.prev.txid, in.prev.vout, e)) {
                    if (e.pkh.size() == 20) {
                        items.emplace_back(e.pkh.begin(), e.pkh.end());
                    }
                } else {
                    // Not found: could be building filter after spends applied. It's OK to skip (spec allows nil exclusion).
                    // (Optionally log at debug level.)
                }
            }
            // Add output PKHs (we don't have OP_RETURN in MIQ; include all)
            for (const auto& o : tx.vout){
                if (o.pkh.size() == 20) {
                    items.emplace_back(o.pkh.begin(), o.pkh.end());
                }
            }
        }

        // Build key and filter
        const auto key = key_from_block_hash_le16(blk);
        auto g = miq::gcs::build(key, items, { miq::gcs::BIP158_P, miq::gcs::BIP158_M });

        out.key   = key;
        out.bytes = std::move(g.bytes);
        return true;
    } catch (const std::exception& ex) {
        if (err) { *err = std::string("BuildBasicFilter exception: ") + ex.what(); }
        return false;
    } catch (...) {
        if (err) { *err = "BuildBasicFilter unknown error"; }
        return false;
    }
}

bool MatchPKH(const BasicFilter& f, const std::vector<uint8_t>& pkh20){
    if (pkh20.size() != 20) return false;
    miq::gcs::Filter gf{f.bytes, f.key};
    return miq::gcs::match_one(gf, pkh20, { miq::gcs::BIP158_P, miq::gcs::BIP158_M });
}

bool MatchAnyPKH(const BasicFilter& f, const std::vector<std::vector<uint8_t>>& pkhs){
    if (pkhs.empty()) return false;
    miq::gcs::Filter gf{f.bytes, f.key};
    return miq::gcs::match_any(gf, pkhs, { miq::gcs::BIP158_P, miq::gcs::BIP158_M });
}

}
}
