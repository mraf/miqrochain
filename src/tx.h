
#pragma once
#include <cstdint>
#include <vector>
#include <string>

namespace miq {

struct OutPoint { std::vector<uint8_t> txid; uint32_t vout; };

// For P2PKH: sig (64) + pubkey(33)
struct TxIn { OutPoint prev; std::vector<uint8_t> sig; std::vector<uint8_t> pubkey; };

// P2PKH lock: 20-byte pubkey hash (HASH160(pubkey))
struct TxOut { uint64_t value; std::vector<uint8_t> pkh; };

struct Transaction {
    uint32_t version{1};
    std::vector<TxIn> vin;
    std::vector<TxOut> vout;
    uint32_t lock_time{0};
    std::vector<uint8_t> txid() const;
};

}
