#pragma once
#include <cstdint>
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <functional>
#include <optional>
#include <deque>
#include "block.h"
#include "tx.h"
#include "utxo.h"
#include "merkle.h"
#include "difficulty.h"
#include "constants.h"

namespace miq {

// Validation result codes
enum class ValidationResult {
    OK = 0,
    
    // Block structure errors
    INVALID_BLOCK_HASH,
    INVALID_MERKLE_ROOT,
    INVALID_TIMESTAMP,
    INVALID_BLOCK_SIZE,
    INVALID_BLOCK_WEIGHT,
    INVALID_COINBASE,
    DUPLICATE_BLOCK,
    
    // PoW errors
    INVALID_PROOF_OF_WORK,
    DIFFICULTY_MISMATCH,
    INVALID_BITS_FIELD,
    
    // Chain connectivity errors  
    ORPHAN_BLOCK,
    INVALID_PREVIOUS_BLOCK,
    BLOCK_HEIGHT_MISMATCH,
    
    // Transaction errors
    INVALID_TRANSACTION,
    DUPLICATE_TRANSACTION,
    MISSING_INPUTS,
    DOUBLE_SPEND,
    INVALID_SCRIPT,
    INSUFFICIENT_FEE,
    INVALID_OUTPUT_VALUE,
    COINBASE_MATURITY,
    
    // Checkpoint errors
    CHECKPOINT_MISMATCH,
    CHECKPOINT_TOO_OLD,
    
    // Fork/reorg errors
    FORK_TOO_DEEP,
    INVALID_FORK,
    
    // Database errors
    DB_ERROR,
    DB_CORRUPTION,
    
    // Resource limits
    MEMORY_LIMIT_EXCEEDED,
    VALIDATION_TIMEOUT,
    
    // Network/consensus rules
    INVALID_CHAIN_ID,
    CONSENSUS_RULE_VIOLATION,
    SOFT_FORK_VIOLATION,
    UNKNOWN_RULE_ACTIVATION
};

// Checkpoint data
struct Checkpoint {
    uint64_t height;
    Hash256 block_hash;
    uint64_t timestamp;
    uint64_t total_work;
    
    Checkpoint(uint64_t h, const Hash256& hash, uint64_t ts, uint64_t work)
        : height(h), block_hash(hash), timestamp(ts), total_work(work) {}
};

// Validation context for a single block
struct BlockValidationContext {
    bool is_coinbase_only = false;
    uint64_t block_reward = 0;
    uint64_t total_fees = 0;
    uint64_t block_weight = 0;
    uint64_t sig_op_count = 0;
    uint32_t block_version = 0;
    std::chrono::milliseconds validation_time{0};
    std::vector<ValidationResult> warnings;
    
    // Cache for expensive validations
    std::unordered_map<Hash256, bool> script_cache;
    std::unordered_map<Hash256, bool> signature_cache;
};

// Block validation statistics
struct ValidationStats {
    std::atomic<uint64_t> blocks_validated{0};
    std::atomic<uint64_t> blocks_rejected{0};
    std::atomic<uint64_t> orphan_blocks{0};
    std::atomic<uint64_t> reorgs_performed{0};
    std::atomic<uint64_t> total_validation_time_ms{0};
    std::atomic<uint64_t> script_validations{0};
    std::atomic<uint64_t> signature_verifications{0};
    
    std::string GetStats() const;
};

// Configuration for validation rules
struct ValidationConfig {
    // Size limits
    static constexpr size_t MAX_BLOCK_SIZE = 4'000'000;  // 4MB
    static constexpr size_t MAX_BLOCK_WEIGHT = 16'000'000;  // 16M weight units
    static constexpr size_t MAX_STANDARD_TX_SIZE = 100'000;
    static constexpr size_t MAX_SCRIPT_SIZE = 10'000;
    static constexpr size_t MAX_SCRIPT_OPS = 201;
    
    // Time constraints
    static constexpr int64_t MAX_FUTURE_BLOCK_TIME = 2 * 60 * 60;  // 2 hours
    static constexpr int64_t TIMESTAMP_WINDOW = 11;  // Median of 11 blocks
    
    // Coinbase maturity
    static constexpr uint64_t COINBASE_MATURITY = 100;
    
    // Fork limits
    static constexpr uint64_t MAX_REORG_DEPTH = 100;
    static constexpr uint64_t ASSUME_VALID_DEPTH = 6;
    
    // Checkpoint configuration
    bool enforce_checkpoints = true;
    bool accept_non_standard = false;
    bool skip_script_validation = false;  // Dangerous - only for testing
    
    // Performance tuning
    size_t script_cache_size = 10'000;
    size_t signature_cache_size = 100'000;
    size_t max_orphan_blocks = 100;
    std::chrono::seconds orphan_expiry{3600};  // 1 hour
    
    // Network specific
    uint32_t chain_id = 1;  // Main network
    std::vector<Checkpoint> checkpoints;
    
    static ValidationConfig MainNet();
    static ValidationConfig TestNet();
    static ValidationConfig RegTest();
};

// Interface for UTXO access during validation
class IUTXOView {
public:
    virtual ~IUTXOView() = default;
    virtual bool GetUTXO(const Hash256& txid, uint32_t vout, UTXO& utxo) const = 0;
    virtual bool HaveUTXO(const Hash256& txid, uint32_t vout) const = 0;
    virtual bool SpendUTXO(const Hash256& txid, uint32_t vout) = 0;
    virtual bool AddUTXO(const Hash256& txid, uint32_t vout, const UTXO& utxo) = 0;
    virtual uint64_t GetBestHeight() const = 0;
    virtual Hash256 GetBestBlockHash() const = 0;
};

// Cached UTXO view for validation
class CachedUTXOView : public IUTXOView {
private:
    const IUTXOView& base_view_;
    mutable std::unordered_map<std::string, std::optional<UTXO>> cache_;
    std::unordered_set<std::string> spent_;
    
    std::string MakeKey(const Hash256& txid, uint32_t vout) const;
    
public:
    explicit CachedUTXOView(const IUTXOView& base);
    
    bool GetUTXO(const Hash256& txid, uint32_t vout, UTXO& utxo) const override;
    bool HaveUTXO(const Hash256& txid, uint32_t vout) const override;
    bool SpendUTXO(const Hash256& txid, uint32_t vout) override;
    bool AddUTXO(const Hash256& txid, uint32_t vout, const UTXO& utxo) override;
    uint64_t GetBestHeight() const override { return base_view_.GetBestHeight(); }
    Hash256 GetBestBlockHash() const override { return base_view_.GetBestBlockHash(); }
    
    void Flush();  // Commit changes to base view
    void Clear();  // Discard changes
};

// Main block validator class
class BlockValidator {
private:
    ValidationConfig config_;
    ValidationStats stats_;
    std::unique_ptr<IUTXOView> utxo_view_;
    
    // Caches for performance
    mutable std::unordered_map<Hash256, bool> script_cache_;
    mutable std::unordered_map<Hash256, bool> signature_cache_;
    mutable std::shared_mutex cache_mutex_;
    
    // Orphan block management
    struct OrphanBlock {
        Block block;
        std::chrono::steady_clock::time_point received_time;
    };
    std::unordered_map<Hash256, OrphanBlock> orphan_blocks_;
    std::unordered_multimap<Hash256, Hash256> orphan_index_;  // parent -> orphan
    mutable std::mutex orphan_mutex_;
    
    // Checkpoint validation
    std::optional<Checkpoint> GetCheckpointAt(uint64_t height) const;
    ValidationResult ValidateAgainstCheckpoint(const Block& block, uint64_t height) const;
    
    // Block structure validation
    ValidationResult ValidateBlockHeader(const BlockHeader& header, uint64_t height) const;
    ValidationResult ValidateBlockSize(const Block& block) const;
    ValidationResult ValidateBlockWeight(const Block& block, uint64_t& weight) const;
    ValidationResult ValidateMerkleRoot(const Block& block) const;
    ValidationResult ValidateTimestamp(const BlockHeader& header, uint64_t height) const;
    ValidationResult ValidateProofOfWork(const BlockHeader& header, uint32_t expected_bits) const;
    
    // Transaction validation
    ValidationResult ValidateTransaction(const Transaction& tx, 
                                        const CachedUTXOView& view,
                                        uint64_t height,
                                        BlockValidationContext& ctx) const;
    ValidationResult ValidateCoinbase(const Transaction& tx, 
                                     uint64_t height, 
                                     uint64_t expected_reward) const;
    ValidationResult ValidateTransactionInputs(const Transaction& tx,
                                              const CachedUTXOView& view,
                                              uint64_t height,
                                              uint64_t& total_input_value) const;
    ValidationResult ValidateTransactionOutputs(const Transaction& tx,
                                               uint64_t& total_output_value) const;
    ValidationResult ValidateTransactionScripts(const Transaction& tx,
                                               const std::vector<UTXO>& spent_utxos,
                                               BlockValidationContext& ctx) const;
    
    // Helper functions
    bool IsFinalTransaction(const Transaction& tx, uint64_t height, uint64_t timestamp) const;
    uint64_t CalculateBlockReward(uint64_t height) const;
    uint32_t CalculateNextWorkRequired(uint64_t height) const;
    uint64_t GetMedianTimePast(uint64_t height) const;
    
    void CleanOrphanBlocks();
    
public:
    explicit BlockValidator(ValidationConfig config);
    ~BlockValidator();
    
    // Main validation interface
    ValidationResult ValidateBlock(const Block& block, 
                                  uint64_t height,
                                  BlockValidationContext& ctx);
    
    ValidationResult ValidateBlockHeader(const BlockHeader& header,
                                        uint64_t height);
    
    ValidationResult ConnectBlock(const Block& block, 
                                 uint64_t height,
                                 CachedUTXOView& view,
                                 BlockValidationContext& ctx);
    
    ValidationResult DisconnectBlock(const Block& block,
                                    uint64_t height,
                                    CachedUTXOView& view);
    
    // Orphan block management
    bool AddOrphanBlock(const Block& block);
    bool HaveOrphanBlock(const Hash256& hash) const;
    std::vector<Block> GetOrphanDescendants(const Hash256& parent_hash);
    void RemoveOrphanBlock(const Hash256& hash);
    size_t GetOrphanCount() const;
    
    // Cache management
    void ClearCaches();
    void ResizeCaches(size_t script_cache_size, size_t sig_cache_size);
    
    // Statistics
    ValidationStats GetStats() const { return stats_; }
    void ResetStats() { stats_ = ValidationStats(); }
    
    // Configuration
    void SetConfig(const ValidationConfig& config) { config_ = config; }
    ValidationConfig GetConfig() const { return config_; }
    
    void SetUTXOView(std::unique_ptr<IUTXOView> view) { 
        utxo_view_ = std::move(view); 
    }
};

// Parallel block validator for faster validation
class ParallelBlockValidator {
private:
    BlockValidator& validator_;
    size_t num_threads_;
    
    struct ValidationTask {
        Transaction tx;
        uint64_t height;
        std::promise<ValidationResult> promise;
    };
    
    std::vector<std::thread> worker_threads_;
    std::queue<ValidationTask> task_queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stop_{false};
    
    void WorkerThread();
    
public:
    ParallelBlockValidator(BlockValidator& validator, size_t num_threads = 0);
    ~ParallelBlockValidator();
    
    ValidationResult ValidateBlock(const Block& block, uint64_t height);
    void Stop();
};

// Chain reorganization handler
class ChainReorgHandler {
private:
    struct ForkPoint {
        uint64_t height;
        Hash256 common_ancestor;
        std::vector<Block> disconnected_blocks;
        std::vector<Block> connected_blocks;
    };
    
    ForkPoint FindForkPoint(const Hash256& old_tip, const Hash256& new_tip);
    
public:
    ValidationResult HandleReorg(const Hash256& old_tip, 
                                const Hash256& new_tip,
                                BlockValidator& validator,
                                IUTXOView& utxo_view);
    
    bool IsReorgNeeded(uint64_t old_height, uint64_t old_work,
                       uint64_t new_height, uint64_t new_work) const;
};

// Helper function to convert validation result to string
const char* ValidationResultToString(ValidationResult result);

// Validation exception class
class ValidationException : public std::exception {
private:
    ValidationResult result_;
    std::string message_;
    
public:
    ValidationException(ValidationResult result, const std::string& msg = "")
        : result_(result) {
        message_ = std::string(ValidationResultToString(result));
        if (!msg.empty()) {
            message_ += ": " + msg;
        }
    }
    
    const char* what() const noexcept override { return message_.c_str(); }
    ValidationResult GetResult() const { return result_; }
};

}
