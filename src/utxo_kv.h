#pragma once
#include "kvdb.h"
#include "tx.h"
#include <string>
#include <vector>
#include <cstdint>

namespace miq {

// UTXO key format: "u" || txid(32) || u32_le(vout)
// Undo key:        "U" || height(8_le) || blockhash(32)  -> opaque bytes (already handled by chain.cpp files on disk)
// Meta keys (examples):
//  "M:state" -> serialized tip state (optional, chain.cpp already persists state to block storage)
// You can add more meta as needed.

struct UTXOEntry {
    uint64_t value{0};
    std::vector<uint8_t> pkh; // 20 bytes
    uint32_t height{0};
    bool coinbase{false};
};

class UTXOKV {
public:
    bool open(const std::string& dir, std::string* err = nullptr);

    // lookups
    bool get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const;

    // add/spend single (immediate, fsynced)
    bool add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e, std::string* err = nullptr);
    bool spend(const std::vector<uint8_t>& txid, uint32_t vout, std::string* err = nullptr);

    // batched interface (atomic)
    class Batch {
    public:
        explicit Batch(UTXOKV& kv) : kv_(kv), b_(kv.db_) {}
        void add(const std::vector<uint8_t>& txid, uint32_t vout, const UTXOEntry& e);
        void spend(const std::vector<uint8_t>& txid, uint32_t vout);
        bool commit(bool sync=true, std::string* err = nullptr) { return b_.commit(sync, err); }
    private:
        UTXOKV& kv_;
        KVDB::Batch b_;
    };

private:
    friend class Batch;
    KVDB db_;

    static std::string k_utxo(const std::vector<uint8_t>& txid, uint32_t vout);
    static std::string ser_entry(const UTXOEntry& e);
    static bool deser_entry(const std::string& v, UTXOEntry& e);
};

}
