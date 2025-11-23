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

// Canonical full tx serialization (for TXID): MUST match wire format exactly.
// Layout (identical to serialize.cpp ser_tx):
//   u32 version
//   u32 vin_count
//     [ for each input:
//         varbytes prev.txid
//         u32 prev.vout
//         varbytes sig
//         varbytes pubkey
//       ]
//   u32 vout_count
//     [ for each output:
//         u64 value
//         varbytes pkh
//       ]
//   u32 lock_time
static std::vector<uint8_t> ser_tx_canonical(const Transaction& tx) {
    std::vector<uint8_t> out;
    out.reserve(64 + tx.vin.size() * 128 + tx.vout.size() * 32);

    put_u32_le(out, tx.version);

    // Inputs
    put_u32_le(out, static_cast<uint32_t>(tx.vin.size()));
    for (const auto& in : tx.vin) {
        // prev.txid as length-prefixed bytes (matches ser_tx)
        put_varbytes(out, in.prev.txid);
        // prev.vout
        put_u32_le(out, static_cast<uint32_t>(in.prev.vout));
        // sig then pubkey (matches ser_tx order)
        put_varbytes(out, in.sig);
        put_varbytes(out, in.pubkey);
    }

    // Outputs
    put_u32_le(out, static_cast<uint32_t>(tx.vout.size()));
    for (const auto& o : tx.vout) {
        put_u64_le(out, static_cast<uint64_t>(o.value));
        // CRITICAL: Include pkh to match wire format
        put_varbytes(out, o.pkh);
    }

    // lock_time at end (matches ser_tx)
    put_u32_le(out, tx.lock_time);

    return out;
}

// === FIXED ===
// Canonical TXID = double-SHA256 over the full serialized transaction (including signatures).
std::vector<uint8_t> Transaction::txid() const {
    const auto raw = ser_tx_canonical(*this);
    return dsha256(raw);
}

} // namespace miq
