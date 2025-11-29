#include "blockindex.h"
#include "util.h"      // hex(), to_hex helpers consistent with your codebase
#include "mtp.h"       // MTP computation
#include "log.h"
#include <cmath>
#include <algorithm>
#include <cstring>
#include <fstream>
#include <ctime>

namespace miq {

// =============================================================================
// PRODUCTION BLOCK INDEX IMPLEMENTATION v2.0
// =============================================================================

// Convert 32-byte hash vector to hex key for maps.
std::string BlockIndex::K(const std::vector<uint8_t>& h){
    return hex(h);
}

// Convert compact 'bits' to an approximate "work" measure.
// work ≈ 2^256 / (target + 1)
long double BlockIndex::work_from_bits(uint32_t bits){
    const uint32_t exp  = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;

    if (mant == 0) return 0.0L;

    // target ≈ mant * 2^(8*(exp-3))
    long double target = static_cast<long double>(mant);
    int shift = 8 * (static_cast<int>(exp) - 3);
    target = std::ldexp(target, shift);

    long double two256 = std::ldexp(1.0L, 256);
    long double w = two256 / (target + 1.0L);
    return w;
}

// =============================================================================
// CORE OPERATIONS
// =============================================================================

void BlockIndex::reset(const std::vector<uint8_t>& genesis_hash, int64_t time, uint32_t bits){
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    map_.clear();
    children_.clear();
    height_index_.clear();
    tip_.reset();
    best_body_.reset();
    total_headers_.store(0, std::memory_order_relaxed);
    validated_headers_.store(0, std::memory_order_relaxed);
    failed_headers_.store(0, std::memory_order_relaxed);

    auto g = std::make_shared<HeaderRec>();
    g->hash  = genesis_hash;
    g->prev  = std::vector<uint8_t>(32, 0);
    g->time  = time;
    g->bits  = bits;
    g->height = 0;
    g->chainwork = work_from_bits(bits);
    g->parent.reset();
    g->have_body = false;
    g->cached_mtp = 0;
    g->mtp_valid = true;  // Genesis has no MTP requirement
    g->status = HeaderRec::ValidationStatus::HEADER_VALID;
    g->on_main_chain = true;

    map_[K(g->hash)] = g;
    height_index_[0] = g;
    tip_ = g;
    total_headers_.fetch_add(1, std::memory_order_relaxed);
    validated_headers_.fetch_add(1, std::memory_order_relaxed);
}

std::shared_ptr<HeaderRec> BlockIndex::add_header_internal(const BlockHeader& h,
                                                           const std::vector<uint8_t>& real_hash){
    // Check if already exists
    auto existing = map_.find(K(real_hash));
    if (existing != map_.end()) {
        return existing->second;
    }

    // Parent must be known
    auto pit = map_.find(K(h.prev_hash));
    if(pit == map_.end()){
        return nullptr;
    }

    auto rec = std::make_shared<HeaderRec>();
    rec->hash   = real_hash;
    rec->prev   = h.prev_hash;
    rec->time   = h.time;
    rec->bits   = h.bits;
    rec->parent = pit->second;
    rec->height = rec->parent->height + 1;
    rec->chainwork = rec->parent->chainwork + work_from_bits(h.bits);
    rec->have_body = false;
    rec->status = HeaderRec::ValidationStatus::UNKNOWN;

    // Cache MTP
    rec->cached_mtp = compute_mtp_for_header(rec->parent);
    rec->mtp_valid = true;

    // Insert into maps
    map_[K(rec->hash)] = rec;
    children_[K(rec->parent->hash)].push_back(rec);
    total_headers_.fetch_add(1, std::memory_order_relaxed);

    // Update best header tip by cumulative work
    if(!tip_ || rec->chainwork > tip_->chainwork){
        tip_ = rec;
    }

    return rec;
}

std::shared_ptr<HeaderRec> BlockIndex::add_header(const BlockHeader& h,
                                                  const std::vector<uint8_t>& real_hash){
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return add_header_internal(h, real_hash);
}

std::shared_ptr<HeaderRec> BlockIndex::add_header_validated(const BlockHeader& h,
                                                            const std::vector<uint8_t>& real_hash,
                                                            HeaderValidationResult& result){
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    result = {};

    // Find parent
    auto pit = map_.find(K(h.prev_hash));
    if(pit == map_.end()){
        result.error = "unknown parent";
        return nullptr;
    }

    auto parent = pit->second;

    // Compute MTP
    result.computed_mtp = compute_mtp_for_header(parent);

    // Check MTP rule: block time must be > MTP
    if (h.time <= result.computed_mtp) {
        result.error = "block time " + std::to_string(h.time) +
                       " not greater than MTP " + std::to_string(result.computed_mtp);
        result.mtp_check_passed = false;
        return nullptr;
    }
    result.mtp_check_passed = true;

    // Check future time rule
    int64_t now = get_adjusted_time();
    int64_t max_future = now + MIQ_MAX_FUTURE_DRIFT_SECS;
    if (h.time > max_future) {
        result.error = "block time " + std::to_string(h.time) +
                       " too far in future (max " + std::to_string(max_future) + ")";
        result.time_check_passed = false;
        return nullptr;
    }
    result.time_check_passed = true;

    // Add the header
    auto rec = add_header_internal(h, real_hash);
    if (!rec) {
        result.error = "failed to add header";
        return nullptr;
    }

    rec->status = HeaderRec::ValidationStatus::HEADER_VALID;
    validated_headers_.fetch_add(1, std::memory_order_relaxed);

    result.valid = true;
    result.pow_check_passed = true;  // POW is checked elsewhere
    return rec;
}

void BlockIndex::set_have_body(const std::vector<uint8_t>& h){
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    auto it = map_.find(K(h));
    if(it == map_.end()) return;

    auto& rec = it->second;
    rec->have_body = true;
    rec->status = HeaderRec::ValidationStatus::BLOCK_VALID;

    // Track best connected body tip by height
    if(!best_body_ || rec->height > best_body_->height){
        best_body_ = rec;
    }

    // Update height index for main chain
    if (rec->on_main_chain) {
        height_index_[rec->height] = rec;
    }
}

void BlockIndex::set_failed(const std::vector<uint8_t>& h, const std::string& reason){
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    auto it = map_.find(K(h));
    if(it == map_.end()) return;

    it->second->status = HeaderRec::ValidationStatus::FAILED;
    failed_headers_.fetch_add(1, std::memory_order_relaxed);

    log_warn("Header marked as failed: " + K(h).substr(0, 16) + "... reason: " + reason);
}

std::shared_ptr<HeaderRec> BlockIndex::tip() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return tip_;
}

std::shared_ptr<HeaderRec> BlockIndex::best_connected_body() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return best_body_;
}

// =============================================================================
// MTP METHODS
// =============================================================================

int64_t BlockIndex::compute_mtp_for_header(const std::shared_ptr<HeaderRec>& header) const {
    if (!header) return 0;

    // Check cached value
    if (header->mtp_valid && header->cached_mtp > 0) {
        return header->cached_mtp;
    }

    // Compute MTP from timestamps
    auto times = get_last_n_times(header, MIQ_MTP_WINDOW);
    return compute_mtp_from_times(times);
}

std::vector<int64_t> BlockIndex::get_last_n_times(const std::shared_ptr<HeaderRec>& from, int n) const {
    std::vector<int64_t> times;
    times.reserve(n);

    auto cur = from;
    for (int i = 0; i < n && cur; ++i) {
        times.push_back(cur->time);
        cur = cur->parent;
    }

    return times;
}

bool BlockIndex::validate_header_time(const BlockHeader& h,
                                     const std::shared_ptr<HeaderRec>& parent,
                                     std::string& err) const {
    int64_t mtp = compute_mtp_for_header(parent);

    if (h.time <= mtp) {
        err = "block time <= MTP";
        return false;
    }

    int64_t now = get_adjusted_time();
    if (h.time > now + MIQ_MAX_FUTURE_DRIFT_SECS) {
        err = "block time too far in future";
        return false;
    }

    return true;
}

// =============================================================================
// LOOKUP METHODS
// =============================================================================

std::shared_ptr<HeaderRec> BlockIndex::find_by_hash(const std::vector<uint8_t>& hash) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    auto it = map_.find(K(hash));
    return (it != map_.end()) ? it->second : nullptr;
}

std::shared_ptr<HeaderRec> BlockIndex::find_by_height(uint64_t height) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    auto it = height_index_.find(height);
    return (it != height_index_.end()) ? it->second : nullptr;
}

bool BlockIndex::contains(const std::vector<uint8_t>& hash) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return map_.find(K(hash)) != map_.end();
}

size_t BlockIndex::size() const {
    return total_headers_.load(std::memory_order_relaxed);
}

uint64_t BlockIndex::best_height() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return tip_ ? tip_->height : 0;
}

uint64_t BlockIndex::best_body_height() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return best_body_ ? best_body_->height : 0;
}

// =============================================================================
// LOCATOR & FORK FINDING
// =============================================================================

std::vector<std::vector<uint8_t>> BlockIndex::locator() const{
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    std::vector<std::vector<uint8_t>> v;
    auto cur = tip_;
    int step = 1;
    int count = 0;

    while(cur && count < 32){
        v.push_back(cur->hash);

        for(int i=0; i<step && cur->parent; ++i){
            cur = cur->parent;
        }
        if(count >= 10) step <<= 1;
        ++count;
    }

    // Include genesis (root)
    if(tip_){
        auto root = tip_;
        while(root->parent) root = root->parent;
        if(v.empty() || K(v.back()) != K(root->hash)){
            v.push_back(root->hash);
        }
    }

    return v;
}

std::shared_ptr<HeaderRec> BlockIndex::find_fork(const std::vector<std::vector<uint8_t>>& locator) const{
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    for(const auto& h : locator){
        auto it = map_.find(K(h));
        if(it != map_.end()){
            return it->second;
        }
    }

    // Fallback: return root
    if(!tip_) return nullptr;
    auto cur = tip_;
    while(cur->parent) cur = cur->parent;
    return cur;
}

std::shared_ptr<HeaderRec> BlockIndex::next_on_best_header_chain(const std::shared_ptr<HeaderRec>& cur) const{
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if(!cur) return nullptr;
    auto it = children_.find(K(cur->hash));
    if(it == children_.end() || it->second.empty()) return nullptr;

    const auto& kids = it->second;
    auto best = kids.front();
    for(const auto& c : kids){
        if(c->chainwork > best->chainwork){
            best = c;
        }
    }
    return best;
}

// =============================================================================
// CRASH-SAFE PERSISTENCE
// =============================================================================

bool BlockIndex::save_to_disk(const std::string& path, std::string& err) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    std::string tmp_path = path + ".tmp";

    try {
        std::ofstream f(tmp_path, std::ios::binary | std::ios::trunc);
        if (!f.good()) {
            err = "cannot create temp file";
            return false;
        }

        // Write header: magic + version + count
        const char magic[4] = {'M','I','X','H'};
        f.write(magic, 4);

        uint32_t version = 2;
        f.write(reinterpret_cast<const char*>(&version), 4);

        uint64_t count = map_.size();
        f.write(reinterpret_cast<const char*>(&count), 8);

        // Write each header record
        for (const auto& kv : map_) {
            const auto& rec = kv.second;

            // Hash (32 bytes)
            f.write(reinterpret_cast<const char*>(rec->hash.data()), 32);

            // Prev hash (32 bytes)
            f.write(reinterpret_cast<const char*>(rec->prev.data()), 32);

            // Time (8 bytes)
            f.write(reinterpret_cast<const char*>(&rec->time), 8);

            // Bits (4 bytes)
            f.write(reinterpret_cast<const char*>(&rec->bits), 4);

            // Height (8 bytes)
            f.write(reinterpret_cast<const char*>(&rec->height), 8);

            // Have body (1 byte)
            uint8_t have = rec->have_body ? 1 : 0;
            f.write(reinterpret_cast<const char*>(&have), 1);

            // Status (1 byte)
            uint8_t status = static_cast<uint8_t>(rec->status);
            f.write(reinterpret_cast<const char*>(&status), 1);
        }

        // Write best header hash
        if (tip_) {
            f.write(reinterpret_cast<const char*>(tip_->hash.data()), 32);
        } else {
            std::vector<uint8_t> zero(32, 0);
            f.write(reinterpret_cast<const char*>(zero.data()), 32);
        }

        // Write best body hash
        if (best_body_) {
            f.write(reinterpret_cast<const char*>(best_body_->hash.data()), 32);
        } else {
            std::vector<uint8_t> zero(32, 0);
            f.write(reinterpret_cast<const char*>(zero.data()), 32);
        }

        f.flush();
        f.close();

        // Atomic rename
        std::remove(path.c_str());
        if (std::rename(tmp_path.c_str(), path.c_str()) != 0) {
            err = "rename failed";
            std::remove(tmp_path.c_str());
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        err = std::string("exception: ") + e.what();
        std::remove(tmp_path.c_str());
        return false;
    }
}

bool BlockIndex::load_from_disk(const std::string& path, std::string& err) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    try {
        std::ifstream f(path, std::ios::binary);
        if (!f.good()) {
            err = "cannot open file";
            return false;
        }

        // Read header
        char magic[4];
        f.read(magic, 4);
        if (std::memcmp(magic, "MIXH", 4) != 0) {
            err = "bad magic";
            return false;
        }

        uint32_t version;
        f.read(reinterpret_cast<char*>(&version), 4);
        if (version != 2) {
            err = "unsupported version";
            return false;
        }

        uint64_t count;
        f.read(reinterpret_cast<char*>(&count), 8);

        // Clear existing data
        map_.clear();
        children_.clear();
        height_index_.clear();

        // First pass: create all records
        std::vector<std::shared_ptr<HeaderRec>> records;
        records.reserve(count);

        for (uint64_t i = 0; i < count; ++i) {
            auto rec = std::make_shared<HeaderRec>();

            rec->hash.resize(32);
            f.read(reinterpret_cast<char*>(rec->hash.data()), 32);

            rec->prev.resize(32);
            f.read(reinterpret_cast<char*>(rec->prev.data()), 32);

            f.read(reinterpret_cast<char*>(&rec->time), 8);
            f.read(reinterpret_cast<char*>(&rec->bits), 4);
            f.read(reinterpret_cast<char*>(&rec->height), 8);

            uint8_t have;
            f.read(reinterpret_cast<char*>(&have), 1);
            rec->have_body = (have != 0);

            uint8_t status;
            f.read(reinterpret_cast<char*>(&status), 1);
            rec->status = static_cast<HeaderRec::ValidationStatus>(status);

            records.push_back(rec);
            map_[K(rec->hash)] = rec;
        }

        // Second pass: link parents and compute chainwork
        for (auto& rec : records) {
            if (rec->prev != std::vector<uint8_t>(32, 0)) {
                auto pit = map_.find(K(rec->prev));
                if (pit != map_.end()) {
                    rec->parent = pit->second;
                    rec->chainwork = rec->parent->chainwork + work_from_bits(rec->bits);
                    children_[K(rec->prev)].push_back(rec);
                }
            } else {
                rec->chainwork = work_from_bits(rec->bits);
            }

            total_headers_.fetch_add(1, std::memory_order_relaxed);
            if (rec->status == HeaderRec::ValidationStatus::HEADER_VALID ||
                rec->status == HeaderRec::ValidationStatus::BLOCK_VALID) {
                validated_headers_.fetch_add(1, std::memory_order_relaxed);
            }
        }

        // Read best header hash
        std::vector<uint8_t> best_hash(32);
        f.read(reinterpret_cast<char*>(best_hash.data()), 32);
        if (best_hash != std::vector<uint8_t>(32, 0)) {
            auto it = map_.find(K(best_hash));
            if (it != map_.end()) tip_ = it->second;
        }

        // Read best body hash
        std::vector<uint8_t> best_body_hash(32);
        f.read(reinterpret_cast<char*>(best_body_hash.data()), 32);
        if (best_body_hash != std::vector<uint8_t>(32, 0)) {
            auto it = map_.find(K(best_body_hash));
            if (it != map_.end()) best_body_ = it->second;
        }

        // Update main chain flags and height index
        update_main_chain_flags();

        log_info("Loaded " + std::to_string(count) + " headers from disk");
        return true;
    } catch (const std::exception& e) {
        err = std::string("exception: ") + e.what();
        return false;
    }
}

bool BlockIndex::verify_integrity(std::string& err) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    // Check that all parents exist
    for (const auto& kv : map_) {
        const auto& rec = kv.second;

        // Skip genesis (no parent)
        if (rec->prev == std::vector<uint8_t>(32, 0)) {
            continue;
        }

        auto pit = map_.find(K(rec->prev));
        if (pit == map_.end()) {
            err = "orphan header found: " + K(rec->hash).substr(0, 16);
            return false;
        }

        // Verify height is parent + 1
        if (rec->height != pit->second->height + 1) {
            err = "height mismatch at " + K(rec->hash).substr(0, 16);
            return false;
        }
    }

    // Verify tip is reachable from genesis
    if (tip_) {
        auto cur = tip_;
        while (cur->parent) {
            cur = cur->parent;
        }
        // cur should now be genesis (height 0)
        if (cur->height != 0) {
            err = "tip not connected to genesis";
            return false;
        }
    }

    return true;
}

// =============================================================================
// CHAIN REORGANIZATION HELPERS
// =============================================================================

std::shared_ptr<HeaderRec> BlockIndex::find_common_ancestor(
    const std::shared_ptr<HeaderRec>& a,
    const std::shared_ptr<HeaderRec>& b) const
{
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!a || !b) return nullptr;

    auto x = a;
    auto y = b;

    // Move higher one down to same height
    while (x->height > y->height && x->parent) {
        x = x->parent;
    }
    while (y->height > x->height && y->parent) {
        y = y->parent;
    }

    // Now walk both up until they meet
    while (x != y && x && y) {
        x = x->parent;
        y = y->parent;
    }

    return x;  // Common ancestor (or nullptr if none)
}

void BlockIndex::update_main_chain_flags() {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    // Clear all flags
    for (auto& kv : map_) {
        kv.second->on_main_chain = false;
    }
    height_index_.clear();

    // Walk from tip to genesis marking main chain
    auto cur = tip_;
    while (cur) {
        cur->on_main_chain = true;
        height_index_[cur->height] = cur;
        cur = cur->parent;
    }
}

std::vector<std::shared_ptr<HeaderRec>> BlockIndex::get_chain_between(
    const std::shared_ptr<HeaderRec>& from,
    const std::shared_ptr<HeaderRec>& to) const
{
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    std::vector<std::shared_ptr<HeaderRec>> result;
    if (!from || !to) return result;

    // Walk from 'to' back to 'from'
    auto cur = to;
    while (cur && cur != from) {
        result.push_back(cur);
        cur = cur->parent;
    }

    // Reverse to get from->to order
    std::reverse(result.begin(), result.end());
    return result;
}

}
