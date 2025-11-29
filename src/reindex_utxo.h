#pragma once
#include "chain.h"
#include "utxo_kv.h"
#include <string>
#include <functional>
#include <cstdint>

namespace miq {

// =============================================================================
// PRODUCTION CHAINSTATE REPAIR TOOLS v2.0
// =============================================================================
// Comprehensive tools for rebuilding and verifying UTXO/chainstate
// =============================================================================

// Progress callback for long operations
// Arguments: current_block, total_blocks, phase_name
using ReindexProgressCallback = std::function<void(uint64_t, uint64_t, const char*)>;

// =============================================================================
// UTXO REINDEX
// =============================================================================

// Rebuilds the UTXO set into <datadir>/chainstate using UTXOKV.
// - Reads blocks from the active chain (index 0..tip).
// - Best-effort spend: ignores missing coins from old forks.
// - Batched writes for throughput; fsync at commit.
// - `compact_after` is kept for future use (no-op unless you expose KV compaction).
//
// Returns true on success; false and sets `err` on failure.
bool ReindexUTXO(Chain& chain, UTXOKV& kv, bool compact_after, std::string& err);

// Enhanced reindex with progress reporting
bool ReindexUTXOWithProgress(Chain& chain,
                              UTXOKV& kv,
                              bool compact_after,
                              ReindexProgressCallback progress,
                              std::string& err);

// =============================================================================
// CHAINSTATE VERIFICATION
// =============================================================================

// Verification result structure
struct ChainstateVerifyResult {
    bool valid{false};
    uint64_t blocks_checked{0};
    uint64_t utxos_verified{0};
    uint64_t missing_utxos{0};
    uint64_t extra_utxos{0};
    uint64_t invalid_utxos{0};
    uint64_t total_value{0};
    std::string error;

    bool has_errors() const {
        return missing_utxos > 0 || extra_utxos > 0 || invalid_utxos > 0;
    }
};

// Verify UTXO set consistency against blockchain
// Checks that every unspent output in the set corresponds to a real transaction
bool VerifyChainstate(Chain& chain,
                      UTXOKV& kv,
                      ChainstateVerifyResult& result,
                      ReindexProgressCallback progress = nullptr);

// Quick consistency check (headers only, faster)
bool QuickVerifyChainstate(Chain& chain, UTXOKV& kv, std::string& err);

// =============================================================================
// CHAINSTATE REPAIR
// =============================================================================

// Repair modes
enum class RepairMode {
    QUICK,      // Fix obvious issues only
    FULL,       // Full rebuild from blockchain
    VERIFY_ONLY // Don't fix, just report issues
};

// Repair result structure
struct ChainstateRepairResult {
    bool success{false};
    RepairMode mode_used{RepairMode::VERIFY_ONLY};
    uint64_t utxos_added{0};
    uint64_t utxos_removed{0};
    uint64_t utxos_fixed{0};
    bool required_full_rebuild{false};
    std::string error;
};

// Attempt to repair chainstate
// Will try quick repair first, then full rebuild if needed
bool RepairChainstate(Chain& chain,
                      UTXOKV& kv,
                      RepairMode mode,
                      ChainstateRepairResult& result,
                      ReindexProgressCallback progress = nullptr);

// =============================================================================
// STARTUP CONSISTENCY CHECK
// =============================================================================

// Check if chainstate is consistent with blockchain tip
// Should be called on startup to detect corruption
bool CheckChainstateConsistency(Chain& chain,
                                 UTXOKV& kv,
                                 std::string& err);

// Detect if reindex is needed (e.g., after crash)
bool NeedsReindex(Chain& chain, UTXOKV& kv);

// Get stored chainstate tip hash (for comparison with blockchain tip)
bool GetChainstateTipHash(UTXOKV& kv, std::vector<uint8_t>& tip_hash);

// Store chainstate tip hash
bool SetChainstateTipHash(UTXOKV& kv, const std::vector<uint8_t>& tip_hash);

// =============================================================================
// UNDO DATA
// =============================================================================

// Structure for undo data (spent outputs to restore on reorg)
struct UndoEntry {
    std::vector<uint8_t> txid;    // 32 bytes
    uint32_t vout;
    uint64_t value;
    std::vector<uint8_t> pkh;     // 20 bytes
    uint32_t height;
    bool coinbase;
};

struct BlockUndo {
    uint64_t block_height{0};
    std::vector<uint8_t> block_hash;  // 32 bytes
    std::vector<UndoEntry> spent_outputs;
};

// Save undo data for a block
bool SaveBlockUndo(const std::string& datadir,
                   uint64_t height,
                   const BlockUndo& undo,
                   std::string& err);

// Load undo data for a block
bool LoadBlockUndo(const std::string& datadir,
                   uint64_t height,
                   BlockUndo& undo,
                   std::string& err);

// Delete undo data (after sufficient confirmations)
bool PruneBlockUndo(const std::string& datadir,
                    uint64_t below_height,
                    std::string& err);

// =============================================================================
// STATISTICS
// =============================================================================

struct ChainstateStats {
    uint64_t utxo_count{0};
    uint64_t total_value{0};
    uint64_t db_size_bytes{0};
    uint64_t tip_height{0};
    std::vector<uint8_t> tip_hash;
    int64_t last_flush_time{0};
    uint64_t cache_hits{0};
    uint64_t cache_misses{0};
};

// Get chainstate statistics
bool GetChainstateStats(UTXOKV& kv, ChainstateStats& stats);

}
