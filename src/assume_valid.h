#pragma once
// src/assume_valid.h - Assume-valid optimization for faster initial sync
// Skip signature validation for blocks before a known-good checkpoint

#include <vector>
#include <cstdint>
#include <string>
#include <cstring>

namespace miq {

// =============================================================================
// ASSUME-VALID OPTIMIZATION
// Dramatically speeds up initial block download by skipping signature
// verification for blocks that are known to be valid (below a checkpoint).
// This is safe because:
// 1. The checkpoint hash is hardcoded and verified
// 2. Block headers are still fully validated (PoW, difficulty, timestamps)
// 3. UTXO set is still computed correctly
// 4. Only signature verification is skipped
// =============================================================================

struct AssumeValidConfig {
    // Block hash to assume valid (blocks at or before this are not sig-checked)
    std::vector<uint8_t> hash;  // 32 bytes, little-endian

    // Height of the assume-valid block (for signature skip optimization)
    // Set to 0 to disable signature skipping (verify all signatures)
    uint64_t height{0};

    // Whether assume-valid is enabled (for signature optimization)
    bool enabled{false};  // Disabled by default - verify all signatures

    // Whether we've passed the assume-valid point
    bool passed{false};
};

// Global assume-valid configuration
inline AssumeValidConfig& assume_valid_config() {
    static AssumeValidConfig cfg;
    return cfg;
}

// Initialize assume-valid with a known-good block
// Call this at startup with the most recent known-good block
inline void init_assume_valid(const std::vector<uint8_t>& hash, uint64_t height) {
    auto& cfg = assume_valid_config();
    cfg.hash = hash;
    cfg.height = height;
    cfg.enabled = true;
    cfg.passed = false;
}

// Initialize from hex string
inline bool init_assume_valid_hex(const std::string& hash_hex, uint64_t height) {
    if (hash_hex.size() != 64) return false;

    std::vector<uint8_t> hash(32);
    for (size_t i = 0; i < 32; ++i) {
        char buf[3] = {hash_hex[i*2], hash_hex[i*2+1], 0};
        char* end = nullptr;
        hash[i] = (uint8_t)std::strtoul(buf, &end, 16);
        if (end != buf + 2) return false;
    }

    init_assume_valid(hash, height);
    return true;
}

// Disable assume-valid (for paranoid mode / reindex)
inline void disable_assume_valid() {
    assume_valid_config().enabled = false;
}

// Check if we should skip signature validation for a block
// Returns true if signatures should be validated (not skipped)
inline bool should_validate_signatures(const std::vector<uint8_t>& block_hash, uint64_t height) {
    auto& cfg = assume_valid_config();

    // If disabled or already passed, always validate
    if (!cfg.enabled || cfg.passed) {
        return true;
    }

    // If we've reached or passed the assume-valid block, mark as passed
    if (height >= cfg.height) {
        if (block_hash == cfg.hash) {
            // This is the assume-valid block - validate it fully
            cfg.passed = true;
            return true;
        } else if (height > cfg.height) {
            // Past the assume-valid height - validate all future blocks
            cfg.passed = true;
            return true;
        }
    }

    // Before assume-valid height - skip signature validation
    return false;
}

// Check if assume-valid is active (for logging/display)
inline bool is_assume_valid_active() {
    auto& cfg = assume_valid_config();
    return cfg.enabled && !cfg.passed;
}

// CRITICAL FIX: Check if merkle verification should be skipped for this block
// ONLY the genesis block (height 0) needs to skip merkle verification because
// it was created with different tooling. All other blocks mined by stratum
// have correct merkle roots computed using tx.txid().
inline bool should_skip_merkle_verification(uint64_t height) {
    // Skip merkle verification ONLY for genesis block (height 0)
    // The genesis block was created with unknown tooling that computed
    // the merkle root differently than tx.txid(). This is a known issue
    // that cannot be fixed without changing the genesis block hash.
    // All blocks at height > 0 are mined by stratum and have correct merkles.
    return height == 0;
}

// Overload for when height is unknown (e.g., orphan blocks during reorg)
// During IBD before assume-valid checkpoint, we may encounter orphan blocks
// For safety, only skip merkle for blocks that we can confirm are genesis
inline bool should_skip_merkle_verification_during_ibd() {
    // Don't skip merkle verification for orphan blocks during IBD
    // They should all have correct merkles (mined by stratum)
    return false;
}

// Get progress toward assume-valid point (for display)
inline double assume_valid_progress(uint64_t current_height) {
    auto& cfg = assume_valid_config();
    if (!cfg.enabled || cfg.height == 0) return 1.0;
    if (current_height >= cfg.height) return 1.0;
    return (double)current_height / (double)cfg.height;
}

// =============================================================================
// SCRIPT VALIDATION FLAGS
// Control which validation checks to perform
// =============================================================================

enum ScriptValidationFlags : uint32_t {
    SCRIPT_VERIFY_NONE          = 0,
    SCRIPT_VERIFY_SIGNATURE     = (1U << 0),  // Verify ECDSA signatures
    SCRIPT_VERIFY_LOW_S         = (1U << 1),  // Enforce low-S signatures
    SCRIPT_VERIFY_STRICT_ENC    = (1U << 2),  // Strict DER encoding
    SCRIPT_VERIFY_NULLDUMMY     = (1U << 3),  // OP_CHECKMULTISIG dummy must be empty
    SCRIPT_VERIFY_CLEANSTACK    = (1U << 4),  // Only one element on stack after eval
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 5),  // BIP-65
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 6),  // BIP-112
    SCRIPT_VERIFY_WITNESS       = (1U << 7),  // BIP-141 (SegWit)
    SCRIPT_VERIFY_TAPROOT       = (1U << 8),  // BIP-341 (Taproot)

    // Standard validation for new blocks
    SCRIPT_VERIFY_STANDARD = SCRIPT_VERIFY_SIGNATURE | SCRIPT_VERIFY_LOW_S |
                             SCRIPT_VERIFY_STRICT_ENC | SCRIPT_VERIFY_NULLDUMMY,

    // Assume-valid mode (skip signatures)
    SCRIPT_VERIFY_ASSUME_VALID = SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICT_ENC
};

// Get validation flags for a block at given height
inline uint32_t get_script_flags(uint64_t height, const std::vector<uint8_t>& block_hash) {
    if (should_validate_signatures(block_hash, height)) {
        return SCRIPT_VERIFY_STANDARD;
    } else {
        return SCRIPT_VERIFY_ASSUME_VALID;
    }
}

} // namespace miq
