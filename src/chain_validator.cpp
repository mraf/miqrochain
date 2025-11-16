#include "chain_validator.h"
#include "sha256.h"
#include "merkle.h"
#include "serialize.h"
#include <sstream>
#include <algorithm>
#include <thread>

namespace miq {

// Validation result string conversion
const char* ValidationResultToString(ValidationResult result) {
    switch (result) {
        case ValidationResult::OK: return "OK";
        case ValidationResult::INVALID_BLOCK_HASH: return "Invalid block hash";
        case ValidationResult::INVALID_MERKLE_ROOT: return "Invalid merkle root";
        case ValidationResult::INVALID_TIMESTAMP: return "Invalid timestamp";
        case ValidationResult::INVALID_BLOCK_SIZE: return "Invalid block size";
        case ValidationResult::INVALID_BLOCK_WEIGHT: return "Invalid block weight";
        case ValidationResult::INVALID_COINBASE: return "Invalid coinbase";
        case ValidationResult::DUPLICATE_BLOCK: return "Duplicate block";
        case ValidationResult::INVALID_PROOF_OF_WORK: return "Invalid proof of work";
        case ValidationResult::DIFFICULTY_MISMATCH: return "Difficulty mismatch";
        case ValidationResult::INVALID_BITS_FIELD: return "Invalid bits field";
        case ValidationResult::ORPHAN_BLOCK: return "Orphan block";
        case ValidationResult::INVALID_PREVIOUS_BLOCK: return "Invalid previous block";
        case ValidationResult::BLOCK_HEIGHT_MISMATCH: return "Block height mismatch";
        case ValidationResult::INVALID_TRANSACTION: return "Invalid transaction";
        case ValidationResult::DUPLICATE_TRANSACTION: return "Duplicate transaction";
        case ValidationResult::MISSING_INPUTS: return "Missing inputs";
        case ValidationResult::DOUBLE_SPEND: return "Double spend";
        case ValidationResult::INVALID_SCRIPT: return "Invalid script";
        case ValidationResult::INSUFFICIENT_FEE: return "Insufficient fee";
        case ValidationResult::INVALID_OUTPUT_VALUE: return "Invalid output value";
        case ValidationResult::COINBASE_MATURITY: return "Coinbase maturity violation";
        case ValidationResult::CHECKPOINT_MISMATCH: return "Checkpoint mismatch";
        case ValidationResult::CHECKPOINT_TOO_OLD: return "Checkpoint too old";
        case ValidationResult::FORK_TOO_DEEP: return "Fork too deep";
        case ValidationResult::INVALID_FORK: return "Invalid fork";
        case ValidationResult::DB_ERROR: return "Database error";
        case ValidationResult::DB_CORRUPTION: return "Database corruption";
        case ValidationResult::MEMORY_LIMIT_EXCEEDED: return "Memory limit exceeded";
        case ValidationResult::VALIDATION_TIMEOUT: return "Validation timeout";
        case ValidationResult::INVALID_CHAIN_ID: return "Invalid chain ID";
        case ValidationResult::CONSENSUS_RULE_VIOLATION: return "Consensus rule violation";
        case ValidationResult::SOFT_FORK_VIOLATION: return "Soft fork violation";
        case ValidationResult::UNKNOWN_RULE_ACTIVATION: return "Unknown rule activation";
        default: return "Unknown error";
    }
}

// ValidationStats implementation
std::string ValidationStats::GetStats() const {
    std::stringstream ss;
    ss << "Validation Statistics:\n"
       << "  Blocks validated: " << blocks_validated.load() << "\n"
       << "  Blocks rejected: " << blocks_rejected.load() << "\n"
       << "  Orphan blocks: " << orphan_blocks.load() << "\n"
       << "  Reorganizations: " << reorgs_performed.load() << "\n"
       << "  Total validation time: " << total_validation_time_ms.load() << " ms\n"
       << "  Script validations: " << script_validations.load() << "\n"
       << "  Signature verifications: " << signature_verifications.load();
    return ss.str();
}

// ValidationConfig implementations
ValidationConfig ValidationConfig::MainNet() {
    ValidationConfig config;
    config.chain_id = 1;
    config.enforce_checkpoints = true;
    config.accept_non_standard = false;
    
    // Add mainnet checkpoints (example values - replace with actual)
    config.checkpoints = {
        {0,      Hash256("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"), 1231006505, 1},
        {10000,  Hash256("0000000000000000000000000000000000000000000000000000000000000000"), 1234567890, 10000000},
        {50000,  Hash256("0000000000000000000000000000000000000000000000000000000000000001"), 1345678901, 50000000},
        {100000, Hash256("0000000000000000000000000000000000000000000000000000000000000002"), 1456789012, 100000000},
    };
    
    return config;
}

ValidationConfig ValidationConfig::TestNet() {
    ValidationConfig config;
    config.chain_id = 2;
    config.enforce_checkpoints = false;
    config.accept_non_standard = true;
    return config;
}

ValidationConfig ValidationConfig::RegTest() {
    ValidationConfig config;
    config.chain_id = 3;
    config.enforce_checkpoints = false;
    config.accept_non_standard = true;
    config.skip_script_validation = false;
    return config;
}

// CachedUTXOView implementation
CachedUTXOView::CachedUTXOView(const IUTXOView& base) : base_view_(base) {}

std::string CachedUTXOView::MakeKey(const Hash256& txid, uint32_t vout) const {
    return txid.ToString() + ":" + std::to_string(vout);
}

bool CachedUTXOView::GetUTXO(const Hash256& txid, uint32_t vout, UTXO& utxo) const {
    std::string key = MakeKey(txid, vout);
    
    // Check if spent in this view
    if (spent_.count(key) > 0) {
        return false;
    }
    
    // Check cache
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        if (it->second.has_value()) {
            utxo = it->second.value();
            return true;
        }
        return false;
    }
    
    // Check base view
    if (base_view_.GetUTXO(txid, vout, utxo)) {
        cache_[key] = utxo;
        return true;
    }
    
    cache_[key] = std::nullopt;
    return false;
}

bool CachedUTXOView::HaveUTXO(const Hash256& txid, uint32_t vout) const {
    UTXO utxo;
    return GetUTXO(txid, vout, utxo);
}

bool CachedUTXOView::SpendUTXO(const Hash256& txid, uint32_t vout) {
    std::string key = MakeKey(txid, vout);
    
    // Verify it exists
    UTXO utxo;
    if (!GetUTXO(txid, vout, utxo)) {
        return false;
    }
    
    spent_.insert(key);
    cache_.erase(key);
    return true;
}

bool CachedUTXOView::AddUTXO(const Hash256& txid, uint32_t vout, const UTXO& utxo) {
    std::string key = MakeKey(txid, vout);
    
    // Remove from spent set if present
    spent_.erase(key);
    
    // Add to cache
    cache_[key] = utxo;
    return true;
}

void CachedUTXOView::Flush() {
    // In a real implementation, this would commit changes to the base view
    // For now, just clear the cache
    Clear();
}

void CachedUTXOView::Clear() {
    cache_.clear();
    spent_.clear();
}

// BlockValidator implementation
BlockValidator::BlockValidator(ValidationConfig config) 
    : config_(std::move(config)) {
    script_cache_.reserve(config_.script_cache_size);
    signature_cache_.reserve(config_.signature_cache_size);
}

BlockValidator::~BlockValidator() = default;

ValidationResult BlockValidator::ValidateBlock(const Block& block, 
                                              uint64_t height,
                                              BlockValidationContext& ctx) {
    auto start_time = std::chrono::steady_clock::now();
    
    // Validate header
    ValidationResult result = ValidateBlockHeader(block.header, height);
    if (result != ValidationResult::OK) {
        stats_.blocks_rejected++;
        return result;
    }
    
    // Validate size
    result = ValidateBlockSize(block);
    if (result != ValidationResult::OK) {
        stats_.blocks_rejected++;
        return result;
    }
    
    // Validate weight
    result = ValidateBlockWeight(block, ctx.block_weight);
    if (result != ValidationResult::OK) {
        stats_.blocks_rejected++;
        return result;
    }
    
    // Validate merkle root
    result = ValidateMerkleRoot(block);
    if (result != ValidationResult::OK) {
        stats_.blocks_rejected++;
        return result;
    }
    
    // Validate against checkpoints if enabled
    if (config_.enforce_checkpoints) {
        result = ValidateAgainstCheckpoint(block, height);
        if (result != ValidationResult::OK) {
            stats_.blocks_rejected++;
            return result;
        }
    }
    
    // Validate timestamp
    result = ValidateTimestamp(block.header, height);
    if (result != ValidationResult::OK) {
        stats_.blocks_rejected++;
        return result;
    }
    
    // Validate proof of work
    uint32_t expected_bits = CalculateNextWorkRequired(height);
    result = ValidateProofOfWork(block.header, expected_bits);
    if (result != ValidationResult::OK) {
        stats_.blocks_rejected++;
        return result;
    }
    
    // Check for duplicate transactions
    std::unordered_set<Hash256> tx_hashes;
    for (const auto& tx : block.transactions) {
        Hash256 txid = tx.GetHash();
        if (!tx_hashes.insert(txid).second) {
            stats_.blocks_rejected++;
            return ValidationResult::DUPLICATE_TRANSACTION;
        }
    }
    
    // Validate coinbase
    if (!block.transactions.empty()) {
        ctx.block_reward = CalculateBlockReward(height);
        result = ValidateCoinbase(block.transactions[0], height, ctx.block_reward);
        if (result != ValidationResult::OK) {
            stats_.blocks_rejected++;
            return result;
        }
        ctx.is_coinbase_only = (block.transactions.size() == 1);
    }
    
    // Create cached UTXO view for transaction validation
    if (utxo_view_) {
        CachedUTXOView cached_view(*utxo_view_);
        
        // Validate all transactions (skip coinbase)
        for (size_t i = 1; i < block.transactions.size(); ++i) {
            result = ValidateTransaction(block.transactions[i], cached_view, height, ctx);
            if (result != ValidationResult::OK) {
                stats_.blocks_rejected++;
                return result;
            }
        }
    }
    
    auto end_time = std::chrono::steady_clock::now();
    ctx.validation_time = std::chrono::duration_cast<std::chrono::milliseconds>(
        end_time - start_time);
    
    stats_.blocks_validated++;
    stats_.total_validation_time_ms += ctx.validation_time.count();
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateBlockHeader(const BlockHeader& header,
                                                    uint64_t height) const {
    // Check block hash meets difficulty target
    Hash256 hash = header.GetHash();
    uint256_t hash_value = Hash256ToUint256(hash);
    uint256_t target = BitsToTarget(header.bits);
    
    if (hash_value > target) {
        return ValidationResult::INVALID_PROOF_OF_WORK;
    }
    
    // Validate version
    if (header.version < 1) {
        return ValidationResult::CONSENSUS_RULE_VIOLATION;
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateBlockSize(const Block& block) const {
    size_t block_size = block.GetSerializedSize();
    if (block_size > ValidationConfig::MAX_BLOCK_SIZE) {
        return ValidationResult::INVALID_BLOCK_SIZE;
    }
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateBlockWeight(const Block& block, 
                                                    uint64_t& weight) const {
    weight = 0;
    
    for (const auto& tx : block.transactions) {
        // Weight = (base_size * 3) + total_size
        size_t base_size = tx.GetBaseSize();
        size_t total_size = tx.GetSerializedSize();
        weight += (base_size * 3) + total_size;
    }
    
    if (weight > ValidationConfig::MAX_BLOCK_WEIGHT) {
        return ValidationResult::INVALID_BLOCK_WEIGHT;
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateMerkleRoot(const Block& block) const {
    if (block.transactions.empty()) {
        return ValidationResult::INVALID_MERKLE_ROOT;
    }
    
    std::vector<Hash256> tx_hashes;
    tx_hashes.reserve(block.transactions.size());
    
    for (const auto& tx : block.transactions) {
        tx_hashes.push_back(tx.GetHash());
    }
    
    Hash256 computed_root = ComputeMerkleRoot(tx_hashes);
    if (computed_root != block.header.merkle_root) {
        return ValidationResult::INVALID_MERKLE_ROOT;
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateTimestamp(const BlockHeader& header,
                                                  uint64_t height) const {
    // Check not too far in future
    uint64_t current_time = std::chrono::system_clock::now().time_since_epoch().count() / 1000000000;
    if (header.timestamp > current_time + ValidationConfig::MAX_FUTURE_BLOCK_TIME) {
        return ValidationResult::INVALID_TIMESTAMP;
    }
    
    // Check against median time past
    if (height > 0) {
        uint64_t median_time = GetMedianTimePast(height - 1);
        if (header.timestamp <= median_time) {
            return ValidationResult::INVALID_TIMESTAMP;
        }
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateProofOfWork(const BlockHeader& header,
                                                    uint32_t expected_bits) const {
    // Validate bits field matches expected difficulty
    if (header.bits != expected_bits) {
        return ValidationResult::DIFFICULTY_MISMATCH;
    }
    
    // Validate proof of work
    Hash256 hash = header.GetHash();
    uint256_t hash_value = Hash256ToUint256(hash);
    uint256_t target = BitsToTarget(header.bits);
    
    if (hash_value > target) {
        return ValidationResult::INVALID_PROOF_OF_WORK;
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateCoinbase(const Transaction& tx,
                                                 uint64_t height,
                                                 uint64_t expected_reward) const {
    // Check coinbase flag
    if (!tx.IsCoinbase()) {
        return ValidationResult::INVALID_COINBASE;
    }
    
    // Check single input
    if (tx.inputs.size() != 1) {
        return ValidationResult::INVALID_COINBASE;
    }
    
    // Check coinbase script size (must be between 2 and 100 bytes)
    if (tx.inputs[0].script_sig.size() < 2 || tx.inputs[0].script_sig.size() > 100) {
        return ValidationResult::INVALID_COINBASE;
    }
    
    // Calculate total output value
    uint64_t total_output = 0;
    for (const auto& output : tx.outputs) {
        if (output.value > MAX_MONEY) {
            return ValidationResult::INVALID_OUTPUT_VALUE;
        }
        total_output += output.value;
        if (total_output > MAX_MONEY) {
            return ValidationResult::INVALID_OUTPUT_VALUE;
        }
    }
    
    // Check reward doesn't exceed block reward + fees
    // Note: We can't check fees here as we need to validate other transactions first
    if (total_output > expected_reward) {
        return ValidationResult::INVALID_COINBASE;
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateTransaction(const Transaction& tx,
                                                    const CachedUTXOView& view,
                                                    uint64_t height,
                                                    BlockValidationContext& ctx) const {
    // Basic checks
    if (tx.inputs.empty() || tx.outputs.empty()) {
        return ValidationResult::INVALID_TRANSACTION;
    }
    
    // Check for duplicate inputs
    std::unordered_set<std::string> input_set;
    for (const auto& input : tx.inputs) {
        std::string key = input.prevout.hash.ToString() + ":" + 
                         std::to_string(input.prevout.index);
        if (!input_set.insert(key).second) {
            return ValidationResult::DOUBLE_SPEND;
        }
    }
    
    // Validate inputs
    uint64_t total_input_value = 0;
    ValidationResult result = ValidateTransactionInputs(tx, view, height, total_input_value);
    if (result != ValidationResult::OK) {
        return result;
    }
    
    // Validate outputs
    uint64_t total_output_value = 0;
    result = ValidateTransactionOutputs(tx, total_output_value);
    if (result != ValidationResult::OK) {
        return result;
    }
    
    // Check fee
    if (total_input_value < total_output_value) {
        return ValidationResult::INSUFFICIENT_FEE;
    }
    uint64_t fee = total_input_value - total_output_value;
    ctx.total_fees += fee;
    
    // Validate scripts if not skipping
    if (!config_.skip_script_validation) {
        std::vector<UTXO> spent_utxos;
        spent_utxos.reserve(tx.inputs.size());
        
        for (const auto& input : tx.inputs) {
            UTXO utxo;
            if (!view.GetUTXO(input.prevout.hash, input.prevout.index, utxo)) {
                return ValidationResult::MISSING_INPUTS;
            }
            spent_utxos.push_back(utxo);
        }
        
        result = ValidateTransactionScripts(tx, spent_utxos, ctx);
        if (result != ValidationResult::OK) {
            return result;
        }
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateTransactionInputs(const Transaction& tx,
                                                          const CachedUTXOView& view,
                                                          uint64_t height,
                                                          uint64_t& total_input_value) const {
    total_input_value = 0;
    
    for (const auto& input : tx.inputs) {
        UTXO utxo;
        if (!view.GetUTXO(input.prevout.hash, input.prevout.index, utxo)) {
            return ValidationResult::MISSING_INPUTS;
        }
        
        // Check coinbase maturity
        if (utxo.is_coinbase) {
            if (height < utxo.height + ValidationConfig::COINBASE_MATURITY) {
                return ValidationResult::COINBASE_MATURITY;
            }
        }
        
        // Add to total
        total_input_value += utxo.output.value;
        if (total_input_value < utxo.output.value) {  // Overflow check
            return ValidationResult::INVALID_OUTPUT_VALUE;
        }
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateTransactionOutputs(const Transaction& tx,
                                                           uint64_t& total_output_value) const {
    total_output_value = 0;
    
    for (const auto& output : tx.outputs) {
        // Check individual output value
        if (output.value > MAX_MONEY) {
            return ValidationResult::INVALID_OUTPUT_VALUE;
        }
        
        // Check script size
        if (output.script_pubkey.size() > ValidationConfig::MAX_SCRIPT_SIZE) {
            return ValidationResult::INVALID_SCRIPT;
        }
        
        // Add to total
        total_output_value += output.value;
        if (total_output_value < output.value) {  // Overflow check
            return ValidationResult::INVALID_OUTPUT_VALUE;
        }
    }
    
    // Check total doesn't exceed max money
    if (total_output_value > MAX_MONEY) {
        return ValidationResult::INVALID_OUTPUT_VALUE;
    }
    
    return ValidationResult::OK;
}

ValidationResult BlockValidator::ValidateTransactionScripts(const Transaction& tx,
                                                           const std::vector<UTXO>& spent_utxos,
                                                           BlockValidationContext& ctx) const {
    // Check cache first
    Hash256 tx_hash = tx.GetHash();
    
    {
        std::shared_lock lock(cache_mutex_);
        auto it = script_cache_.find(tx_hash);
        if (it != script_cache_.end()) {
            stats_.script_validations++;
            return it->second ? ValidationResult::OK : ValidationResult::INVALID_SCRIPT;
        }
    }
    
    // Validate each input script
    for (size_t i = 0; i < tx.inputs.size(); ++i) {
        const auto& input = tx.inputs[i];
        const auto& utxo = spent_utxos[i];
        
        // Here you would implement actual script validation
        // For now, we'll do a simplified check
        bool valid = true;  // Placeholder
        
        if (!valid) {
            std::unique_lock lock(cache_mutex_);
            script_cache_[tx_hash] = false;
            return ValidationResult::INVALID_SCRIPT;
        }
        
        stats_.signature_verifications++;
    }
    
    // Cache successful validation
    {
        std::unique_lock lock(cache_mutex_);
        script_cache_[tx_hash] = true;
    }
    
    stats_.script_validations++;
    return ValidationResult::OK;
}

std::optional<Checkpoint> BlockValidator::GetCheckpointAt(uint64_t height) const {
    for (const auto& cp : config_.checkpoints) {
        if (cp.height == height) {
            return cp;
        }
    }
    return std::nullopt;
}

ValidationResult BlockValidator::ValidateAgainstCheckpoint(const Block& block,
                                                          uint64_t height) const {
    auto checkpoint = GetCheckpointAt(height);
    if (!checkpoint) {
        return ValidationResult::OK;
    }
    
    Hash256 block_hash = block.GetHash();
    if (block_hash != checkpoint->block_hash) {
        return ValidationResult::CHECKPOINT_MISMATCH;
    }
    
    if (block.header.timestamp != checkpoint->timestamp) {
        return ValidationResult::CHECKPOINT_MISMATCH;
    }
    
    return ValidationResult::OK;
}

uint64_t BlockValidator::CalculateBlockReward(uint64_t height) const {
    // Bitcoin-like halving every 210,000 blocks
    uint64_t halvings = height / 210000;
    if (halvings >= 64) {
        return 0;
    }
    
    uint64_t reward = 50 * COIN;
    reward >>= halvings;
    return reward;
}

uint32_t BlockValidator::CalculateNextWorkRequired(uint64_t height) const {
    // Simplified difficulty adjustment
    // In production, this would look at previous blocks and adjust every 2016 blocks
    return 0x1d00ffff;  // Placeholder
}

uint64_t BlockValidator::GetMedianTimePast(uint64_t height) const {
    // Get median timestamp of last 11 blocks
    // This is simplified - would need actual chain access
    return 0;  // Placeholder
}

bool BlockValidator::AddOrphanBlock(const Block& block) {
    std::lock_guard<std::mutex> lock(orphan_mutex_);
    
    if (orphan_blocks_.size() >= config_.max_orphan_blocks) {
        CleanOrphanBlocks();
        if (orphan_blocks_.size() >= config_.max_orphan_blocks) {
            return false;  // Still too many
        }
    }
    
    Hash256 hash = block.GetHash();
    orphan_blocks_[hash] = {block, std::chrono::steady_clock::now()};
    orphan_index_.emplace(block.header.previous_block, hash);
    stats_.orphan_blocks++;
    
    return true;
}

void BlockValidator::CleanOrphanBlocks() {
    auto now = std::chrono::steady_clock::now();
    auto expiry = config_.orphan_expiry;
    
    auto it = orphan_blocks_.begin();
    while (it != orphan_blocks_.end()) {
        if (now - it->second.received_time > expiry) {
            // Remove from index
            auto range = orphan_index_.equal_range(it->second.block.header.previous_block);
            for (auto idx_it = range.first; idx_it != range.second; ) {
                if (idx_it->second == it->first) {
                    idx_it = orphan_index_.erase(idx_it);
                } else {
                    ++idx_it;
                }
            }
            
            it = orphan_blocks_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<Block> BlockValidator::GetOrphanDescendants(const Hash256& parent_hash) {
    std::lock_guard<std::mutex> lock(orphan_mutex_);
    std::vector<Block> descendants;
    
    auto range = orphan_index_.equal_range(parent_hash);
    for (auto it = range.first; it != range.second; ++it) {
        auto block_it = orphan_blocks_.find(it->second);
        if (block_it != orphan_blocks_.end()) {
            descendants.push_back(block_it->second.block);
        }
    }
    
    return descendants;
}

void BlockValidator::ClearCaches() {
    std::unique_lock lock(cache_mutex_);
    script_cache_.clear();
    signature_cache_.clear();
}

// Helper functions for uint256 operations
uint256_t Hash256ToUint256(const Hash256& hash) {
    uint256_t result = 0;
    for (size_t i = 0; i < 32; ++i) {
        result = (result << 8) | hash.data[31 - i];
    }
    return result;
}

uint256_t BitsToTarget(uint32_t bits) {
    uint32_t exponent = bits >> 24;
    uint32_t mantissa = bits & 0x00ffffff;
    uint256_t target = mantissa;
    if (exponent > 3) {
        target <<= (8 * (exponent - 3));
    } else {
        target >>= (8 * (3 - exponent));
    }
    return target;
}

}
