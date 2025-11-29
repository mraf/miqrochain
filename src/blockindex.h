#pragma once
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include "block.h"

namespace miq {

// =============================================================================
// PRODUCTION BLOCK INDEX v2.0
// =============================================================================
// Thread-safe header index with MTP validation and crash-safe state
// =============================================================================

// Header record stored in-memory for headers-first sync and chain selection.
struct HeaderRec {
    std::vector<uint8_t> hash;     // 32-byte block header hash
    std::vector<uint8_t> prev;     // 32-byte prev hash
    int64_t  time{0};              // header timestamp
    uint32_t bits{0};              // nBits compact target
    uint64_t height{0};            // header height (0 = genesis)
    long double chainwork{0};      // cumulative work (monotonic on best header chain)
    std::shared_ptr<HeaderRec> parent;

    // True once the full block body has been received/validated/connected.
    bool have_body{false};

    // MTP (Median Time Past) cached for this header's parent chain
    int64_t cached_mtp{0};
    bool mtp_valid{false};

    // Validation status
    enum class ValidationStatus : uint8_t {
        UNKNOWN = 0,
        HEADER_VALID = 1,
        BLOCK_VALID = 2,
        FAILED = 3
    };
    ValidationStatus status{ValidationStatus::UNKNOWN};

    // Track if this header is on the main chain
    bool on_main_chain{false};

    // Merkle root (cached for faster validation)
    std::vector<uint8_t> merkle_root;
};

// Validation result for header checks
struct HeaderValidationResult {
    bool valid{false};
    std::string error;
    int64_t computed_mtp{0};
    bool mtp_check_passed{false};
    bool pow_check_passed{false};
    bool time_check_passed{false};
};

// In-memory index for block headers (and which headers already have bodies).
class BlockIndex {
public:
    BlockIndex() = default;
    ~BlockIndex() = default;

    // Thread-safe operations
    void reset(const std::vector<uint8_t>& genesis_hash, int64_t time, uint32_t bits);

    // Add a new header that links to a known parent.
    // Returns the created HeaderRec, or nullptr if parent is unknown.
    std::shared_ptr<HeaderRec> add_header(const BlockHeader& h,
                                          const std::vector<uint8_t>& real_hash);

    // Add header with MTP validation
    std::shared_ptr<HeaderRec> add_header_validated(const BlockHeader& h,
                                                    const std::vector<uint8_t>& real_hash,
                                                    HeaderValidationResult& result);

    // Mark that we have validated/connected the full block body for hash 'h'.
    void set_have_body(const std::vector<uint8_t>& h);

    // Mark header as failed validation
    void set_failed(const std::vector<uint8_t>& h, const std::string& reason);

    // Best header by cumulative work (tip of the headers chain).
    std::shared_ptr<HeaderRec> tip() const;

    // Best connected block body (tip of the fully-connected chain).
    std::shared_ptr<HeaderRec> best_connected_body() const;

    // Build a classic "locator" (back by powers of two) from best header tip.
    std::vector<std::vector<uint8_t>> locator() const;

    // Given a peer's locator, find our first known HeaderRec on that path.
    std::shared_ptr<HeaderRec> find_fork(const std::vector<std::vector<uint8_t>>& locator) const;

    // Find the next header **towards the best header chain** from 'cur'.
    std::shared_ptr<HeaderRec> next_on_best_header_chain(const std::shared_ptr<HeaderRec>& cur) const;

    // =============================================================================
    // MTP-RELATED METHODS
    // =============================================================================

    // Compute MTP for a header (uses cached value if available)
    int64_t compute_mtp_for_header(const std::shared_ptr<HeaderRec>& header) const;

    // Get the last N timestamps for MTP calculation
    std::vector<int64_t> get_last_n_times(const std::shared_ptr<HeaderRec>& from, int n) const;

    // Validate header time against MTP
    bool validate_header_time(const BlockHeader& h,
                             const std::shared_ptr<HeaderRec>& parent,
                             std::string& err) const;

    // =============================================================================
    // LOOKUP & QUERY
    // =============================================================================

    // Find header by hash (thread-safe)
    std::shared_ptr<HeaderRec> find_by_hash(const std::vector<uint8_t>& hash) const;

    // Find header by height on main chain
    std::shared_ptr<HeaderRec> find_by_height(uint64_t height) const;

    // Check if we have a header
    bool contains(const std::vector<uint8_t>& hash) const;

    // Get current header count
    size_t size() const;

    // Get best header height
    uint64_t best_height() const;

    // Get best body height
    uint64_t best_body_height() const;

    // =============================================================================
    // CRASH-SAFE PERSISTENCE
    // =============================================================================

    // Save header index to disk (atomic)
    bool save_to_disk(const std::string& path, std::string& err) const;

    // Load header index from disk
    bool load_from_disk(const std::string& path, std::string& err);

    // Verify index integrity
    bool verify_integrity(std::string& err) const;

    // =============================================================================
    // CHAIN REORGANIZATION
    // =============================================================================

    // Get common ancestor of two headers
    std::shared_ptr<HeaderRec> find_common_ancestor(
        const std::shared_ptr<HeaderRec>& a,
        const std::shared_ptr<HeaderRec>& b) const;

    // Mark headers on main chain (from genesis to tip)
    void update_main_chain_flags();

    // Get headers between two points (for reorg)
    std::vector<std::shared_ptr<HeaderRec>> get_chain_between(
        const std::shared_ptr<HeaderRec>& from,
        const std::shared_ptr<HeaderRec>& to) const;

private:
    mutable std::recursive_mutex mtx_;  // Protects all members

    // hash(hex) -> HeaderRec
    std::unordered_map<std::string, std::shared_ptr<HeaderRec>> map_;

    // Parent->children adjacency for forward walking.
    std::unordered_map<std::string, std::vector<std::shared_ptr<HeaderRec>>> children_;

    // Best header by chainwork.
    std::shared_ptr<HeaderRec> tip_;

    // Best fully-connected block (body) tip.
    std::shared_ptr<HeaderRec> best_body_;

    // Height-indexed main chain (for fast height lookups)
    std::unordered_map<uint64_t, std::shared_ptr<HeaderRec>> height_index_;

    // Statistics
    std::atomic<size_t> total_headers_{0};
    std::atomic<size_t> validated_headers_{0};
    std::atomic<size_t> failed_headers_{0};

    // Helper: convert hash to map key
    static std::string K(const std::vector<uint8_t>& h);

    // Helper: compute work from compact bits
    static long double work_from_bits(uint32_t bits);

    // Internal helper: add header without lock (caller must hold lock)
    std::shared_ptr<HeaderRec> add_header_internal(const BlockHeader& h,
                                                   const std::vector<uint8_t>& real_hash);
};

}
