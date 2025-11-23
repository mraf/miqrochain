#pragma once
// src/segwit.h - Segregated Witness (BIP-141, BIP-143, BIP-144)
// Fixes transaction malleability and enables advanced scripts

#include <vector>
#include <cstdint>
#include <string>
#include <array>
#include <cstring>

#include "sha256.h"
#include "hash160.h"

namespace miq {

// =============================================================================
// SEGWIT CONSTANTS
// =============================================================================

// Witness version for native SegWit v0
constexpr uint8_t WITNESS_V0 = 0x00;

// Witness version for Taproot (v1)
constexpr uint8_t WITNESS_V1 = 0x01;

// Witness program sizes
constexpr size_t WITNESS_V0_KEYHASH_SIZE = 20;  // P2WPKH
constexpr size_t WITNESS_V0_SCRIPTHASH_SIZE = 32;  // P2WSH
constexpr size_t WITNESS_V1_TAPROOT_SIZE = 32;  // P2TR

// Transaction marker and flag for witness serialization
constexpr uint8_t WITNESS_MARKER = 0x00;
constexpr uint8_t WITNESS_FLAG = 0x01;

// Witness scale factor (for virtual size calculation)
constexpr int WITNESS_SCALE_FACTOR = 4;

// =============================================================================
// WITNESS DATA STRUCTURES
// =============================================================================

// Witness stack for a single input
struct TxWitness {
    std::vector<std::vector<uint8_t>> stack;

    bool is_empty() const { return stack.empty(); }

    size_t serialized_size() const {
        size_t sz = 1;  // stack item count (varint)
        for (const auto& item : stack) {
            sz += 1 + item.size();  // varint + data
        }
        return sz;
    }
};

// Extended transaction with witness data
struct WitnessTransaction {
    // Base transaction fields
    uint32_t version{1};
    std::vector<struct TxIn> vin;
    std::vector<struct TxOut> vout;
    uint32_t lock_time{0};

    // Witness data (one per input)
    std::vector<TxWitness> witness;

    // Computed hashes
    std::vector<uint8_t> txid() const;      // Without witness
    std::vector<uint8_t> wtxid() const;     // With witness
    std::vector<uint8_t> hash() const { return wtxid(); }

    // Size calculations
    size_t base_size() const;     // Without witness
    size_t total_size() const;    // With witness
    size_t weight() const { return base_size() * 3 + total_size(); }
    size_t vsize() const { return (weight() + 3) / 4; }

    // Check if transaction has witness data
    bool has_witness() const {
        for (const auto& w : witness) {
            if (!w.is_empty()) return true;
        }
        return false;
    }
};

// =============================================================================
// SEGWIT ADDRESSES
// =============================================================================

// Bech32 character set
constexpr char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Bech32 HRP (Human-Readable Part)
constexpr char BECH32_HRP_MAINNET[] = "miq";
constexpr char BECH32_HRP_TESTNET[] = "tmiq";

// Bech32 encoding/decoding
inline std::vector<uint8_t> bech32_expand_hrp(const std::string& hrp) {
    std::vector<uint8_t> ret;
    ret.reserve(hrp.size() * 2 + 1);
    for (char c : hrp) {
        ret.push_back(c >> 5);
    }
    ret.push_back(0);
    for (char c : hrp) {
        ret.push_back(c & 0x1f);
    }
    return ret;
}

inline uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    uint32_t c = 1;
    for (uint8_t v : values) {
        uint8_t c0 = c >> 25;
        c = ((c & 0x1ffffff) << 5) ^ v;
        if (c0 & 1)  c ^= 0x3b6a57b2;
        if (c0 & 2)  c ^= 0x26508e6d;
        if (c0 & 4)  c ^= 0x1ea119fa;
        if (c0 & 8)  c ^= 0x3d4233dd;
        if (c0 & 16) c ^= 0x2a1462b3;
    }
    return c;
}

inline std::vector<uint8_t> bech32_create_checksum(const std::string& hrp,
                                                    const std::vector<uint8_t>& data) {
    std::vector<uint8_t> values = bech32_expand_hrp(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6);
    uint32_t polymod = bech32_polymod(values) ^ 1;
    std::vector<uint8_t> ret(6);
    for (int i = 0; i < 6; ++i) {
        ret[i] = (polymod >> (5 * (5 - i))) & 0x1f;
    }
    return ret;
}

// Convert 8-bit groups to 5-bit groups
inline std::vector<uint8_t> convert_bits(const std::vector<uint8_t>& data,
                                          int from_bits, int to_bits, bool pad) {
    std::vector<uint8_t> ret;
    int acc = 0;
    int bits = 0;
    int max_v = (1 << to_bits) - 1;
    int max_acc = (1 << (from_bits + to_bits - 1)) - 1;

    for (uint8_t value : data) {
        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            ret.push_back((acc >> bits) & max_v);
        }
    }

    if (pad && bits) {
        ret.push_back((acc << (to_bits - bits)) & max_v);
    }

    return ret;
}

// Encode SegWit address (Bech32)
inline std::string encode_segwit_address(const std::string& hrp,
                                          uint8_t witness_version,
                                          const std::vector<uint8_t>& program) {
    std::vector<uint8_t> data;
    data.push_back(witness_version);

    auto converted = convert_bits(program, 8, 5, true);
    data.insert(data.end(), converted.begin(), converted.end());

    auto checksum = bech32_create_checksum(hrp, data);
    data.insert(data.end(), checksum.begin(), checksum.end());

    std::string ret = hrp + "1";
    for (uint8_t d : data) {
        ret += BECH32_CHARSET[d];
    }

    return ret;
}

// Decode SegWit address
inline bool decode_segwit_address(const std::string& addr,
                                   std::string& out_hrp,
                                   uint8_t& out_version,
                                   std::vector<uint8_t>& out_program) {
    // Find separator
    size_t pos = addr.rfind('1');
    if (pos == std::string::npos || pos < 1 || pos + 7 > addr.size()) {
        return false;
    }

    out_hrp = addr.substr(0, pos);

    // Decode data part
    std::vector<uint8_t> data;
    for (size_t i = pos + 1; i < addr.size(); ++i) {
        char c = addr[i];
        const char* p = std::strchr(BECH32_CHARSET, c);
        if (!p) {
            // Try lowercase
            if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
            p = std::strchr(BECH32_CHARSET, c);
            if (!p) return false;
        }
        data.push_back((uint8_t)(p - BECH32_CHARSET));
    }

    // Verify checksum
    auto values = bech32_expand_hrp(out_hrp);
    values.insert(values.end(), data.begin(), data.end());
    if (bech32_polymod(values) != 1) return false;

    // Remove checksum
    data.resize(data.size() - 6);
    if (data.empty()) return false;

    out_version = data[0];
    data.erase(data.begin());

    // Convert from 5-bit to 8-bit
    out_program = convert_bits(data, 5, 8, false);

    // Validate
    if (out_version == 0) {
        if (out_program.size() != 20 && out_program.size() != 32) {
            return false;
        }
    } else if (out_version > 16) {
        return false;
    }

    return true;
}

// =============================================================================
// BIP-143 SIGNATURE HASHING
// New sighash algorithm for SegWit transactions
// =============================================================================

struct BIP143Precomputed {
    std::vector<uint8_t> hash_prevouts;
    std::vector<uint8_t> hash_sequence;
    std::vector<uint8_t> hash_outputs;
};

// Precompute hashes for BIP-143 (can be reused for all inputs)
inline BIP143Precomputed bip143_precompute(const WitnessTransaction& tx) {
    BIP143Precomputed pre;

    // hashPrevouts = SHA256(SHA256(outpoint1 || outpoint2 || ...))
    std::vector<uint8_t> prevouts;
    for (const auto& in : tx.vin) {
        prevouts.insert(prevouts.end(), in.prev.txid.begin(), in.prev.txid.end());
        for (int i = 0; i < 4; ++i) {
            prevouts.push_back((in.prev.vout >> (i * 8)) & 0xff);
        }
    }
    pre.hash_prevouts = dsha256(prevouts);

    // hashSequence = SHA256(SHA256(nSequence1 || nSequence2 || ...))
    std::vector<uint8_t> sequences;
    for (const auto& in : tx.vin) {
        uint32_t seq = 0xffffffff;  // Default sequence
        for (int i = 0; i < 4; ++i) {
            sequences.push_back((seq >> (i * 8)) & 0xff);
        }
    }
    pre.hash_sequence = dsha256(sequences);

    // hashOutputs = SHA256(SHA256(output1 || output2 || ...))
    std::vector<uint8_t> outputs;
    for (const auto& out : tx.vout) {
        for (int i = 0; i < 8; ++i) {
            outputs.push_back((out.value >> (i * 8)) & 0xff);
        }
        // Script pubkey (P2PKH format for now)
        outputs.push_back(25);  // Script length
        outputs.push_back(0x76); outputs.push_back(0xa9);  // OP_DUP OP_HASH160
        outputs.push_back(20);  // Push 20 bytes
        outputs.insert(outputs.end(), out.pkh.begin(), out.pkh.end());
        outputs.push_back(0x88); outputs.push_back(0xac);  // OP_EQUALVERIFY OP_CHECKSIG
    }
    pre.hash_outputs = dsha256(outputs);

    return pre;
}

// Compute BIP-143 sighash for a specific input
inline std::vector<uint8_t> bip143_sighash(
    const WitnessTransaction& tx,
    size_t input_index,
    const std::vector<uint8_t>& script_code,
    uint64_t value,
    uint32_t sighash_type,
    const BIP143Precomputed& pre)
{
    std::vector<uint8_t> data;
    data.reserve(256);

    // 1. nVersion (4 bytes LE)
    for (int i = 0; i < 4; ++i) {
        data.push_back((tx.version >> (i * 8)) & 0xff);
    }

    // 2. hashPrevouts (32 bytes)
    data.insert(data.end(), pre.hash_prevouts.begin(), pre.hash_prevouts.end());

    // 3. hashSequence (32 bytes)
    data.insert(data.end(), pre.hash_sequence.begin(), pre.hash_sequence.end());

    // 4. outpoint (32 + 4 bytes)
    data.insert(data.end(), tx.vin[input_index].prev.txid.begin(),
                tx.vin[input_index].prev.txid.end());
    for (int i = 0; i < 4; ++i) {
        data.push_back((tx.vin[input_index].prev.vout >> (i * 8)) & 0xff);
    }

    // 5. scriptCode (varint + script)
    if (script_code.size() < 0xfd) {
        data.push_back((uint8_t)script_code.size());
    } else {
        data.push_back(0xfd);
        data.push_back(script_code.size() & 0xff);
        data.push_back((script_code.size() >> 8) & 0xff);
    }
    data.insert(data.end(), script_code.begin(), script_code.end());

    // 6. value (8 bytes LE)
    for (int i = 0; i < 8; ++i) {
        data.push_back((value >> (i * 8)) & 0xff);
    }

    // 7. nSequence (4 bytes LE)
    uint32_t seq = 0xffffffff;
    for (int i = 0; i < 4; ++i) {
        data.push_back((seq >> (i * 8)) & 0xff);
    }

    // 8. hashOutputs (32 bytes)
    data.insert(data.end(), pre.hash_outputs.begin(), pre.hash_outputs.end());

    // 9. nLocktime (4 bytes LE)
    for (int i = 0; i < 4; ++i) {
        data.push_back((tx.lock_time >> (i * 8)) & 0xff);
    }

    // 10. sighash type (4 bytes LE)
    for (int i = 0; i < 4; ++i) {
        data.push_back((sighash_type >> (i * 8)) & 0xff);
    }

    return dsha256(data);
}

// =============================================================================
// WITNESS COMMITMENT
// For including in coinbase (BIP-141)
// =============================================================================

// Witness reserved value (32 zero bytes)
inline std::vector<uint8_t> witness_reserved_value() {
    return std::vector<uint8_t>(32, 0);
}

// Compute witness commitment
inline std::vector<uint8_t> compute_witness_commitment(
    const std::vector<std::vector<uint8_t>>& wtxids)
{
    // Build merkle tree of wtxids
    if (wtxids.empty()) {
        return std::vector<uint8_t>(32, 0);
    }

    std::vector<std::vector<uint8_t>> level = wtxids;

    while (level.size() > 1) {
        std::vector<std::vector<uint8_t>> next_level;

        for (size_t i = 0; i < level.size(); i += 2) {
            std::vector<uint8_t> combined;
            combined.insert(combined.end(), level[i].begin(), level[i].end());

            if (i + 1 < level.size()) {
                combined.insert(combined.end(), level[i + 1].begin(), level[i + 1].end());
            } else {
                combined.insert(combined.end(), level[i].begin(), level[i].end());
            }

            next_level.push_back(dsha256(combined));
        }

        level = std::move(next_level);
    }

    // Combine with witness reserved value
    std::vector<uint8_t> data;
    data.insert(data.end(), level[0].begin(), level[0].end());
    auto reserved = witness_reserved_value();
    data.insert(data.end(), reserved.begin(), reserved.end());

    return dsha256(data);
}

// Build witness commitment output script
inline std::vector<uint8_t> build_witness_commitment_script(
    const std::vector<uint8_t>& commitment)
{
    std::vector<uint8_t> script;
    script.push_back(0x6a);  // OP_RETURN
    script.push_back(0x24);  // Push 36 bytes
    script.push_back(0xaa);  // Witness commitment header
    script.push_back(0x21);
    script.push_back(0xa9);
    script.push_back(0xed);
    script.insert(script.end(), commitment.begin(), commitment.end());
    return script;
}

// =============================================================================
// SEGWIT SCRIPT TYPES
// =============================================================================

enum class SegWitType {
    NONE,
    P2WPKH,   // Pay to Witness Public Key Hash
    P2WSH,    // Pay to Witness Script Hash
    P2TR      // Pay to Taproot (v1)
};

// Determine SegWit type from script
inline SegWitType get_segwit_type(const std::vector<uint8_t>& script) {
    if (script.size() < 2) return SegWitType::NONE;

    uint8_t version = script[0];
    if (version > 16 && version != 0x00 && version != 0x51) {
        return SegWitType::NONE;
    }

    if (version == 0x00) {
        // Witness v0
        if (script.size() == 22 && script[1] == 20) {
            return SegWitType::P2WPKH;
        } else if (script.size() == 34 && script[1] == 32) {
            return SegWitType::P2WSH;
        }
    } else if (version == 0x51 && script.size() == 34 && script[1] == 32) {
        // Witness v1 (Taproot)
        return SegWitType::P2TR;
    }

    return SegWitType::NONE;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// Create P2WPKH output script from pubkey hash
inline std::vector<uint8_t> create_p2wpkh_script(const std::vector<uint8_t>& pubkey_hash) {
    std::vector<uint8_t> script;
    script.push_back(0x00);  // Witness version 0
    script.push_back(0x14);  // Push 20 bytes
    script.insert(script.end(), pubkey_hash.begin(), pubkey_hash.end());
    return script;
}

// Create P2WSH output script from script hash
inline std::vector<uint8_t> create_p2wsh_script(const std::vector<uint8_t>& script_hash) {
    std::vector<uint8_t> script;
    script.push_back(0x00);  // Witness version 0
    script.push_back(0x20);  // Push 32 bytes
    script.insert(script.end(), script_hash.begin(), script_hash.end());
    return script;
}

// Get pubkey hash from P2WPKH address
inline bool get_p2wpkh_pubkey_hash(const std::string& address, std::vector<uint8_t>& out_hash) {
    std::string hrp;
    uint8_t version;
    std::vector<uint8_t> program;

    if (!decode_segwit_address(address, hrp, version, program)) {
        return false;
    }

    if (version != 0 || program.size() != 20) {
        return false;
    }

    out_hash = program;
    return true;
}

} // namespace miq
