#include "tx.h"
#include "sha256.h"
#include <vector>
#include <cstdint>
#include <cstring>

namespace miq {

// Little-endian integer writers (scoped to this file)
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

// Simple length-prefixed byte array
static inline void put_varbytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
    // 32-bit length prefix (LE). Good enough for our sizes and deterministic.
    put_u32_le(v, static_cast<uint32_t>(b.size()));
    v.insert(v.end(), b.begin(), b.end());
}

// Canonical full tx serialization (for TXID): includes signatures.
// Layout:
//   u32 version
//   u64 lock_time
//   u32 vin_count
//     [ for each input:
//         32 prev.txid bytes (as stored)
//         u32 prev.vout
//         varbytes pubkey
//         varbytes sig
//       ]
//   u32 vout_count
//     [ for each output:
//         u64 value
//         (note: if outputs carry extra fields, those are not used by consensus
//                elsewhere in this repo; we hash value only to keep compatibility)
//       ]
static std::vector<uint8_t> ser_tx_canonical(const Transaction& tx) {
    std::vector<uint8_t> out;
    out.reserve(64 + tx.vin.size() * 96 + tx.vout.size() * 16);

    put_u32_le(out, tx.version);
    put_u64_le(out, static_cast<uint64_t>(tx.lock_time));

    // Inputs
    put_u32_le(out, static_cast<uint32_t>(tx.vin.size()));
    for (const auto& in : tx.vin) {
        // prev.txid (serialize exactly the stored bytes)
        out.insert(out.end(), in.prev.txid.begin(), in.prev.txid.end());
        // prev.vout
        put_u32_le(out, static_cast<uint32_t>(in.prev.vout));
        // pubkey & sig as opaque byte arrays
        put_varbytes(out, in.pubkey);
        put_varbytes(out, in.sig);
    }

    // Outputs
    put_u32_le(out, static_cast<uint32_t>(tx.vout.size()));
    for (const auto& o : tx.vout) {
        put_u64_le(out, static_cast<uint64_t>(o.value));
        // If your Output struct has additional consensus fields (e.g., script/PKH) hashed
        // elsewhere, include them here as varbytes to bind TXID to them. Since the
        // current repo only uses value in consensus paths we leave this minimal to avoid
        // breaking other code paths.
        // Example if you later add: put_varbytes(out, o.script);
    }

    return out;
}

// === FIXED ===
// Canonical TXID = double-SHA256 over the full serialized transaction (including signatures).
std::vector<uint8_t> Transaction::txid() const {
    const auto raw = ser_tx_canonical(*this);
    return dsha256(raw);
}

} // namespace miq
