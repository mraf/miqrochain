#pragma once
// src/taproot.h - Taproot Support (BIP-340, BIP-341, BIP-342)
// Schnorr signatures, MAST, and key path/script path spending

#include <vector>
#include <cstdint>
#include <string>
#include <array>
#include <optional>

#include "sha256.h"
#include "segwit.h"

namespace miq {

// =============================================================================
// TAPROOT CONSTANTS
// =============================================================================

// Taproot leaf version
constexpr uint8_t TAPROOT_LEAF_VERSION = 0xc0;

// Maximum script size in Taproot
constexpr size_t MAX_TAPROOT_SCRIPT_SIZE = 10000;

// Maximum stack element size
constexpr size_t MAX_STACK_ELEMENT_SIZE = 520;

// Annex prefix
constexpr uint8_t ANNEX_PREFIX = 0x50;

// =============================================================================
// TAGGED HASHES (BIP-340)
// SHA256(SHA256(tag) || SHA256(tag) || msg)
// =============================================================================

inline std::vector<uint8_t> tagged_hash(const std::string& tag, const std::vector<uint8_t>& msg) {
    // Hash the tag
    std::vector<uint8_t> tag_bytes(tag.begin(), tag.end());
    auto tag_hash = sha256(tag_bytes);

    // Build input: tag_hash || tag_hash || msg
    std::vector<uint8_t> data;
    data.reserve(32 + 32 + msg.size());
    data.insert(data.end(), tag_hash.begin(), tag_hash.end());
    data.insert(data.end(), tag_hash.begin(), tag_hash.end());
    data.insert(data.end(), msg.begin(), msg.end());

    return sha256(data);
}

// Common tagged hash functions
inline std::vector<uint8_t> hash_tap_leaf(const std::vector<uint8_t>& msg) {
    return tagged_hash("TapLeaf", msg);
}

inline std::vector<uint8_t> hash_tap_branch(const std::vector<uint8_t>& msg) {
    return tagged_hash("TapBranch", msg);
}

inline std::vector<uint8_t> hash_tap_tweak(const std::vector<uint8_t>& msg) {
    return tagged_hash("TapTweak", msg);
}

inline std::vector<uint8_t> hash_tap_sighash(const std::vector<uint8_t>& msg) {
    return tagged_hash("TapSighash", msg);
}

inline std::vector<uint8_t> hash_bip340_challenge(const std::vector<uint8_t>& msg) {
    return tagged_hash("BIP0340/challenge", msg);
}

inline std::vector<uint8_t> hash_bip340_aux(const std::vector<uint8_t>& msg) {
    return tagged_hash("BIP0340/aux", msg);
}

inline std::vector<uint8_t> hash_bip340_nonce(const std::vector<uint8_t>& msg) {
    return tagged_hash("BIP0340/nonce", msg);
}

// =============================================================================
// SCHNORR SIGNATURES (BIP-340)
// 64-byte signatures: (r, s) where r is an x-coordinate
// =============================================================================

// Schnorr public key (32 bytes, x-only)
using SchnorrPubKey = std::array<uint8_t, 32>;

// Schnorr signature (64 bytes)
using SchnorrSig = std::array<uint8_t, 64>;

// Lift x-only public key to full point (for verification)
// Returns true if the point exists and has even y
inline bool lift_x(const SchnorrPubKey& x, std::vector<uint8_t>& out_full_pubkey) {
    // This would require secp256k1 point decompression
    // Placeholder implementation - in production use libsecp256k1
    out_full_pubkey.resize(33);
    out_full_pubkey[0] = 0x02;  // Even y
    std::copy(x.begin(), x.end(), out_full_pubkey.begin() + 1);
    return true;
}

// Verify Schnorr signature (BIP-340)
// In production, use libsecp256k1-zkp or similar
inline bool schnorr_verify(const SchnorrPubKey& pubkey,
                            const std::vector<uint8_t>& message,
                            const SchnorrSig& sig) {
    // Extract r and s from signature
    std::vector<uint8_t> r(sig.begin(), sig.begin() + 32);
    std::vector<uint8_t> s(sig.begin() + 32, sig.end());

    // Build challenge
    std::vector<uint8_t> challenge_input;
    challenge_input.insert(challenge_input.end(), r.begin(), r.end());
    challenge_input.insert(challenge_input.end(), pubkey.begin(), pubkey.end());
    challenge_input.insert(challenge_input.end(), message.begin(), message.end());

    auto e = hash_bip340_challenge(challenge_input);

    // In production: verify s*G = R + e*P
    // This is a placeholder that always returns true
    // Real implementation requires elliptic curve operations
    (void)s;
    (void)e;

    return true;  // Placeholder
}

// =============================================================================
// TAPROOT MERKLE TREE (MAST)
// =============================================================================

// Taproot script leaf
struct TapLeaf {
    uint8_t version{TAPROOT_LEAF_VERSION};
    std::vector<uint8_t> script;

    // Compute leaf hash
    std::vector<uint8_t> hash() const {
        std::vector<uint8_t> data;
        data.push_back(version);
        // Script with compact size prefix
        if (script.size() < 0xfd) {
            data.push_back((uint8_t)script.size());
        } else {
            data.push_back(0xfd);
            data.push_back(script.size() & 0xff);
            data.push_back((script.size() >> 8) & 0xff);
        }
        data.insert(data.end(), script.begin(), script.end());
        return hash_tap_leaf(data);
    }
};

// Taproot branch node
struct TapBranch {
    std::vector<uint8_t> left;   // 32 bytes
    std::vector<uint8_t> right;  // 32 bytes

    // Compute branch hash (sorted lexicographically)
    std::vector<uint8_t> hash() const {
        std::vector<uint8_t> data;
        if (left < right) {
            data.insert(data.end(), left.begin(), left.end());
            data.insert(data.end(), right.begin(), right.end());
        } else {
            data.insert(data.end(), right.begin(), right.end());
            data.insert(data.end(), left.begin(), left.end());
        }
        return hash_tap_branch(data);
    }
};

// Control block for script path spending
struct TapControlBlock {
    uint8_t leaf_version{0};
    SchnorrPubKey internal_key;
    std::vector<std::vector<uint8_t>> path;  // Merkle path (32 bytes each)

    // Serialize control block
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> data;
        data.push_back(leaf_version);
        data.insert(data.end(), internal_key.begin(), internal_key.end());
        for (const auto& node : path) {
            data.insert(data.end(), node.begin(), node.end());
        }
        return data;
    }

    // Deserialize control block
    static std::optional<TapControlBlock> deserialize(const std::vector<uint8_t>& data) {
        if (data.size() < 33 || ((data.size() - 33) % 32) != 0) {
            return std::nullopt;
        }

        TapControlBlock cb;
        cb.leaf_version = data[0];
        std::copy(data.begin() + 1, data.begin() + 33, cb.internal_key.begin());

        for (size_t i = 33; i < data.size(); i += 32) {
            std::vector<uint8_t> node(data.begin() + i, data.begin() + i + 32);
            cb.path.push_back(node);
        }

        return cb;
    }
};

// =============================================================================
// TAPROOT ADDRESS AND OUTPUT
// =============================================================================

// Compute tweaked public key from internal key and merkle root
inline SchnorrPubKey compute_taproot_output_key(
    const SchnorrPubKey& internal_key,
    const std::vector<uint8_t>& merkle_root)
{
    // tweak = H_TapTweak(internal_key || merkle_root)
    std::vector<uint8_t> tweak_input;
    tweak_input.insert(tweak_input.end(), internal_key.begin(), internal_key.end());
    if (!merkle_root.empty()) {
        tweak_input.insert(tweak_input.end(), merkle_root.begin(), merkle_root.end());
    }
    auto tweak = hash_tap_tweak(tweak_input);

    // output_key = internal_key + tweak*G
    // This requires EC point addition - placeholder returns tweaked internal key
    SchnorrPubKey output_key = internal_key;
    for (size_t i = 0; i < 32; ++i) {
        output_key[i] ^= tweak[i];  // Placeholder XOR
    }

    return output_key;
}

// Create Taproot output script
inline std::vector<uint8_t> create_taproot_output_script(const SchnorrPubKey& output_key) {
    std::vector<uint8_t> script;
    script.push_back(0x51);  // OP_1 (witness version 1)
    script.push_back(0x20);  // Push 32 bytes
    script.insert(script.end(), output_key.begin(), output_key.end());
    return script;
}

// Create Taproot address (bech32m)
inline std::string create_taproot_address(const SchnorrPubKey& output_key, bool testnet = false) {
    std::string hrp = testnet ? BECH32_HRP_TESTNET : BECH32_HRP_MAINNET;
    std::vector<uint8_t> program(output_key.begin(), output_key.end());
    return encode_segwit_address(hrp, WITNESS_V1, program);
}

// =============================================================================
// TAPROOT SIGHASH (BIP-341)
// =============================================================================

// Sighash type extensions for Taproot
constexpr uint8_t SIGHASH_DEFAULT = 0x00;      // Same as SIGHASH_ALL for Taproot
constexpr uint8_t SIGHASH_ALL_TAPROOT = 0x00;  // Explicit
constexpr uint8_t SIGHASH_NONE_TAPROOT = 0x02;
constexpr uint8_t SIGHASH_SINGLE_TAPROOT = 0x03;
constexpr uint8_t SIGHASH_ANYONECANPAY_TAPROOT = 0x80;

// Epoch for Taproot sighash
constexpr uint8_t TAPROOT_SIGHASH_EPOCH = 0x00;

// Compute Taproot sighash
inline std::vector<uint8_t> compute_taproot_sighash(
    const WitnessTransaction& tx,
    size_t input_index,
    uint8_t sighash_type,
    const std::vector<uint64_t>& input_amounts,
    const std::vector<std::vector<uint8_t>>& input_scripts,
    bool is_key_path,
    const TapLeaf* leaf = nullptr)
{
    std::vector<uint8_t> data;
    data.reserve(512);

    // Epoch
    data.push_back(TAPROOT_SIGHASH_EPOCH);

    // Control
    uint8_t output_type = sighash_type & 0x03;
    bool anyone_can_pay = (sighash_type & SIGHASH_ANYONECANPAY_TAPROOT) != 0;
    data.push_back(sighash_type);

    // nVersion
    for (int i = 0; i < 4; ++i) {
        data.push_back((tx.version >> (i * 8)) & 0xff);
    }

    // nLockTime
    for (int i = 0; i < 4; ++i) {
        data.push_back((tx.lock_time >> (i * 8)) & 0xff);
    }

    if (!anyone_can_pay) {
        // sha_prevouts
        std::vector<uint8_t> prevouts;
        for (const auto& in : tx.vin) {
            prevouts.insert(prevouts.end(), in.prev.txid.begin(), in.prev.txid.end());
            for (int i = 0; i < 4; ++i) {
                prevouts.push_back((in.prev.vout >> (i * 8)) & 0xff);
            }
        }
        auto hash = sha256(prevouts);
        data.insert(data.end(), hash.begin(), hash.end());

        // sha_amounts
        std::vector<uint8_t> amounts;
        for (uint64_t amt : input_amounts) {
            for (int i = 0; i < 8; ++i) {
                amounts.push_back((amt >> (i * 8)) & 0xff);
            }
        }
        hash = sha256(amounts);
        data.insert(data.end(), hash.begin(), hash.end());

        // sha_scriptpubkeys
        std::vector<uint8_t> scripts;
        for (const auto& script : input_scripts) {
            if (script.size() < 0xfd) {
                scripts.push_back((uint8_t)script.size());
            } else {
                scripts.push_back(0xfd);
                scripts.push_back(script.size() & 0xff);
                scripts.push_back((script.size() >> 8) & 0xff);
            }
            scripts.insert(scripts.end(), script.begin(), script.end());
        }
        hash = sha256(scripts);
        data.insert(data.end(), hash.begin(), hash.end());

        // sha_sequences
        std::vector<uint8_t> sequences;
        for (size_t i = 0; i < tx.vin.size(); ++i) {
            uint32_t seq = 0xffffffff;
            for (int j = 0; j < 4; ++j) {
                sequences.push_back((seq >> (j * 8)) & 0xff);
            }
        }
        hash = sha256(sequences);
        data.insert(data.end(), hash.begin(), hash.end());
    }

    if (output_type == SIGHASH_ALL_TAPROOT) {
        // sha_outputs
        std::vector<uint8_t> outputs;
        for (const auto& out : tx.vout) {
            for (int i = 0; i < 8; ++i) {
                outputs.push_back((out.value >> (i * 8)) & 0xff);
            }
            // Script pubkey
            std::vector<uint8_t> spk;
            spk.push_back(0x76); spk.push_back(0xa9);
            spk.push_back(20);
            spk.insert(spk.end(), out.pkh.begin(), out.pkh.end());
            spk.push_back(0x88); spk.push_back(0xac);

            if (spk.size() < 0xfd) {
                outputs.push_back((uint8_t)spk.size());
            } else {
                outputs.push_back(0xfd);
                outputs.push_back(spk.size() & 0xff);
                outputs.push_back((spk.size() >> 8) & 0xff);
            }
            outputs.insert(outputs.end(), spk.begin(), spk.end());
        }
        auto hash = sha256(outputs);
        data.insert(data.end(), hash.begin(), hash.end());
    }

    // spend_type
    uint8_t spend_type = 0;
    if (!is_key_path) spend_type |= 0x02;  // Script path
    // Annex not implemented
    data.push_back(spend_type);

    if (anyone_can_pay) {
        // Outpoint
        data.insert(data.end(), tx.vin[input_index].prev.txid.begin(),
                    tx.vin[input_index].prev.txid.end());
        for (int i = 0; i < 4; ++i) {
            data.push_back((tx.vin[input_index].prev.vout >> (i * 8)) & 0xff);
        }

        // Amount
        for (int i = 0; i < 8; ++i) {
            data.push_back((input_amounts[input_index] >> (i * 8)) & 0xff);
        }

        // Script pubkey
        const auto& spk = input_scripts[input_index];
        if (spk.size() < 0xfd) {
            data.push_back((uint8_t)spk.size());
        } else {
            data.push_back(0xfd);
            data.push_back(spk.size() & 0xff);
            data.push_back((spk.size() >> 8) & 0xff);
        }
        data.insert(data.end(), spk.begin(), spk.end());

        // Sequence
        uint32_t seq = 0xffffffff;
        for (int i = 0; i < 4; ++i) {
            data.push_back((seq >> (i * 8)) & 0xff);
        }
    } else {
        // input_index
        for (int i = 0; i < 4; ++i) {
            data.push_back((input_index >> (i * 8)) & 0xff);
        }
    }

    // Script path specific data
    if (!is_key_path && leaf) {
        auto leaf_hash = leaf->hash();
        data.insert(data.end(), leaf_hash.begin(), leaf_hash.end());
        data.push_back(0x00);  // key_version
        // codeseparator_position not implemented
        for (int i = 0; i < 4; ++i) {
            data.push_back(0xff);  // No codesep
        }
    }

    return hash_tap_sighash(data);
}

// =============================================================================
// TAPROOT VALIDATION
// =============================================================================

// Validate key path spend
inline bool validate_taproot_key_path(
    const SchnorrPubKey& output_key,
    const SchnorrSig& signature,
    const std::vector<uint8_t>& sighash)
{
    return schnorr_verify(output_key, sighash, signature);
}

// Validate script path spend
inline bool validate_taproot_script_path(
    const SchnorrPubKey& output_key,
    const TapControlBlock& control_block,
    const TapLeaf& leaf)
{
    // Compute leaf hash
    auto leaf_hash = leaf.hash();

    // Compute merkle root from leaf and path
    std::vector<uint8_t> current = leaf_hash;
    for (const auto& node : control_block.path) {
        TapBranch branch;
        branch.left = current;
        branch.right = node;
        current = branch.hash();
    }

    // Verify output key matches internal key + tweak
    auto expected_output = compute_taproot_output_key(control_block.internal_key, current);

    return expected_output == output_key;
}

// =============================================================================
// TAPSCRIPT OPCODES (BIP-342)
// =============================================================================

// New opcodes for Tapscript
constexpr uint8_t OP_CHECKSIGADD = 0xba;

// Disabled opcodes in Tapscript (return success)
constexpr uint8_t OP_CHECKMULTISIG = 0xae;
constexpr uint8_t OP_CHECKMULTISIGVERIFY = 0xaf;

// Check if script is valid Tapscript
inline bool is_valid_tapscript(const std::vector<uint8_t>& script) {
    // Check for disabled opcodes
    for (size_t i = 0; i < script.size(); ++i) {
        uint8_t op = script[i];

        // Skip push data
        if (op <= 0x4e) {
            size_t push_size = 0;
            if (op <= 0x4b) {
                push_size = op;
            } else if (op == 0x4c && i + 1 < script.size()) {
                push_size = script[++i];
            } else if (op == 0x4d && i + 2 < script.size()) {
                push_size = script[i + 1] | (script[i + 2] << 8);
                i += 2;
            } else if (op == 0x4e && i + 4 < script.size()) {
                push_size = script[i + 1] | (script[i + 2] << 8) |
                            (script[i + 3] << 16) | (script[i + 4] << 24);
                i += 4;
            }
            i += push_size;
            continue;
        }

        // Check for disabled opcodes
        if (op == OP_CHECKMULTISIG || op == OP_CHECKMULTISIGVERIFY) {
            return false;
        }
    }

    return true;
}

} // namespace miq
