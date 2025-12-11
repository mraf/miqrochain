// =============================================================================
// ADDRESS INDEX - Implementation
// =============================================================================

#include "addressindex.h"
#include "block.h"
#include "tx.h"
#include "hex.h"
#include "log.h"
#include "hash160.h"
#include "assume_valid.h"  // For is_ibd_mode()

#include <cstring>
#include <filesystem>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <chrono>

namespace fs = std::filesystem;

namespace miq {

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

static int64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// =============================================================================
// AddrKey Implementation
// =============================================================================

bool AddressIndex::AddrKey::operator<(const AddrKey& o) const {
    // Sort by height descending (most recent first)
    if (height != o.height) return height > o.height;
    if (tx_pos != o.tx_pos) return tx_pos > o.tx_pos;
    if (type != o.type) return type < o.type;  // outputs before inputs
    return io_idx < o.io_idx;
}

bool AddressIndex::AddrKey::operator==(const AddrKey& o) const {
    return pkh == o.pkh && height == o.height && tx_pos == o.tx_pos &&
           type == o.type && io_idx == o.io_idx;
}

std::string AddressIndex::AddrKey::to_string() const {
    std::string result;
    result.reserve(20 + 8 + 4 + 1 + 4);
    result.append(reinterpret_cast<const char*>(pkh.data()), 20);
    result.append(reinterpret_cast<const char*>(&height), 8);
    result.append(reinterpret_cast<const char*>(&tx_pos), 4);
    result.append(reinterpret_cast<const char*>(&type), 1);
    result.append(reinterpret_cast<const char*>(&io_idx), 4);
    return result;
}

AddressIndex::AddrKey AddressIndex::AddrKey::from_string(const std::string& s) {
    AddrKey k{};
    if (s.size() < 37) return k;
    std::memcpy(k.pkh.data(), s.data(), 20);
    std::memcpy(&k.height, s.data() + 20, 8);
    std::memcpy(&k.tx_pos, s.data() + 28, 4);
    std::memcpy(&k.type, s.data() + 32, 1);
    std::memcpy(&k.io_idx, s.data() + 33, 4);
    return k;
}

size_t AddressIndex::AddrKeyHash::operator()(const AddrKey& k) const noexcept {
    size_t h = k.height * 2654435761u;
    h ^= k.tx_pos * 2246822519u;
    h ^= k.type * 3266489917u;
    h ^= k.io_idx * 668265263u;
    if (k.pkh[0]) h ^= k.pkh[0] * 374761393u;
    if (k.pkh[19]) h ^= k.pkh[19] * 2869860233u;
    return h;
}

// =============================================================================
// AddrValue Implementation
// =============================================================================

std::string AddressIndex::AddrValue::serialize() const {
    std::string result;
    result.reserve(32 + 8 + 8 + 32 + 4);
    result.append(reinterpret_cast<const char*>(txid.data()), 32);
    result.append(reinterpret_cast<const char*>(&value), 8);
    result.append(reinterpret_cast<const char*>(&timestamp), 8);
    result.append(reinterpret_cast<const char*>(spent_txid.data()), 32);
    result.append(reinterpret_cast<const char*>(&spent_vout), 4);
    return result;
}

AddressIndex::AddrValue AddressIndex::AddrValue::deserialize(const std::string& s) {
    AddrValue v{};
    if (s.size() < 84) return v;
    std::memcpy(v.txid.data(), s.data(), 32);
    std::memcpy(&v.value, s.data() + 32, 8);
    std::memcpy(&v.timestamp, s.data() + 40, 8);
    std::memcpy(v.spent_txid.data(), s.data() + 48, 32);
    std::memcpy(&v.spent_vout, s.data() + 80, 4);
    return v;
}

// =============================================================================
// AddressIndex Implementation
// =============================================================================

AddressIndex::~AddressIndex() {
    close();
}

std::string AddressIndex::pkh_key(const std::vector<uint8_t>& pkh) {
    return to_hex(pkh);
}

std::string AddressIndex::hash_key(const std::vector<uint8_t>& hash) {
    return std::string(reinterpret_cast<const char*>(hash.data()), hash.size());
}

bool AddressIndex::open(const std::string& datadir) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    datadir_ = datadir;
    std::string indexdir = datadir + "/addressindex";

    try {
        fs::create_directories(indexdir);
    } catch (const std::exception& e) {
        log_error("AddressIndex: Failed to create directory: " + std::string(e.what()));
        return false;
    }

    addr_log_path_ = indexdir + "/addr.log";
    hash_log_path_ = indexdir + "/hash.log";
    state_path_ = indexdir + "/state.dat";

    // Load existing index
    if (!load_from_disk()) {
        log_warn("AddressIndex: Failed to load existing index, starting fresh");
        addr_index_.clear();
        hash_index_.clear();
        tx_to_addrs_.clear();
        best_height_ = 0;
        total_entries_ = 0;
    }

    enabled_ = true;
    log_info("AddressIndex: Opened with " + std::to_string(addr_index_.size()) +
             " addresses, " + std::to_string(total_entries_) + " entries, " +
             std::to_string(hash_index_.size()) + " block hashes");

    return true;
}

void AddressIndex::close() {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (enabled_ && dirty_) {
        flush();
    }

    addr_index_.clear();
    hash_index_.clear();
    tx_to_addrs_.clear();
    enabled_ = false;
}

bool AddressIndex::index_block(const Block& block, uint64_t height) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_) return false;

    // CRITICAL PERFORMANCE: Skip address indexing during IBD
    // Address index does file I/O for every transaction which is very slow
    // Explorer features are not needed during sync - reindex after IBD if needed
    if (miq::is_ibd_mode()) return true;

    int64_t timestamp = block.header.time;
    uint32_t tx_pos = 0;

    for (const auto& tx : block.txs) {
        if (!index_transaction(tx, height, tx_pos, timestamp)) {
            log_error("AddressIndex: Failed to index tx at height " + std::to_string(height));
            return false;
        }
        tx_pos++;
    }

    // Update block hash index
    auto block_hash = block.block_hash();
    add_block_hash(block_hash, height);

    if (height > best_height_) {
        best_height_ = height;
    }

    dirty_ = true;

    // Periodic flush
    if (height % FLUSH_INTERVAL == 0) {
        flush();
    }

    return true;
}

bool AddressIndex::unindex_block(const Block& block, uint64_t height) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_) return false;

    // Remove all transactions in reverse order
    for (auto it = block.txs.rbegin(); it != block.txs.rend(); ++it) {
        unindex_transaction(it->txid());
    }

    // Remove block hash
    remove_block_hash(block.block_hash());

    // Update best height
    if (height == best_height_ && best_height_ > 0) {
        best_height_--;
    }

    dirty_ = true;
    return true;
}

bool AddressIndex::index_transaction(const Transaction& tx, uint64_t height,
                                      uint32_t tx_pos, int64_t timestamp) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_) return false;

    auto txid = tx.txid();
    std::string txid_key = to_hex(txid);
    std::vector<std::string> affected_addrs;

    // Index outputs (received)
    for (size_t vout = 0; vout < tx.vout.size(); ++vout) {
        const auto& out = tx.vout[vout];
        if (out.pkh.size() != 20) continue;

        std::string pkh_str = pkh_key(out.pkh);
        affected_addrs.push_back(pkh_str);

        AddressTxEntry entry;
        entry.txid = txid;
        entry.block_height = height;
        entry.tx_position = tx_pos;
        entry.timestamp = timestamp;
        entry.is_input = false;
        entry.value = out.value;
        entry.io_index = static_cast<uint32_t>(vout);

        // Add to index
        auto& addr_entries = addr_index_[pkh_str];
        addr_entries.push_back(entry);
        total_entries_++;

        // Log entry
        AddrKey key{};
        std::copy(out.pkh.begin(), out.pkh.end(), key.pkh.begin());
        key.height = height;
        key.tx_pos = tx_pos;
        key.type = 0;  // output
        key.io_idx = static_cast<uint32_t>(vout);

        AddrValue val{};
        std::copy(txid.begin(), txid.end(), val.txid.begin());
        val.value = out.value;
        val.timestamp = timestamp;

        append_log('A', key, &val);
    }

    // Index inputs (spent) - skip coinbase
    bool is_coinbase = tx.vin.size() > 0 &&
                       (tx.vin[0].prev.txid.empty() ||
                        std::all_of(tx.vin[0].prev.txid.begin(), tx.vin[0].prev.txid.end(),
                                    [](uint8_t b) { return b == 0; }));

    if (!is_coinbase) {
        for (size_t vin = 0; vin < tx.vin.size(); ++vin) {
            const auto& in = tx.vin[vin];
            if (in.prev.txid.empty() || in.pubkey.size() < 33) continue;

            // Compute PKH from pubkey: RIPEMD160(SHA256(pubkey))
            std::vector<uint8_t> pkh = hash160(in.pubkey);

            if (pkh.size() != 20) continue;

            std::string pkh_str = pkh_key(pkh);
            affected_addrs.push_back(pkh_str);

            AddressTxEntry entry;
            entry.txid = txid;
            entry.block_height = height;
            entry.tx_position = tx_pos;
            entry.timestamp = timestamp;
            entry.is_input = true;
            entry.io_index = static_cast<uint32_t>(vin);
            entry.spent_txid = in.prev.txid;
            entry.spent_vout = in.prev.vout;

            // We need to look up the value from the spent output
            // This requires access to UTXO or previous tx - for now, set to 0
            // The caller should provide this info if needed
            entry.value = 0;

            // Add to index
            auto& addr_entries = addr_index_[pkh_str];
            addr_entries.push_back(entry);
            total_entries_++;

            // Log entry
            AddrKey key{};
            std::copy(pkh.begin(), pkh.end(), key.pkh.begin());
            key.height = height;
            key.tx_pos = tx_pos;
            key.type = 1;  // input
            key.io_idx = static_cast<uint32_t>(vin);

            AddrValue val{};
            std::copy(txid.begin(), txid.end(), val.txid.begin());
            val.value = 0;
            val.timestamp = timestamp;
            if (in.prev.txid.size() == 32) {
                std::copy(in.prev.txid.begin(), in.prev.txid.end(), val.spent_txid.begin());
            }
            val.spent_vout = in.prev.vout;

            append_log('A', key, &val);
        }
    }

    // Track tx -> addresses mapping for unindexing
    if (!affected_addrs.empty()) {
        // Remove duplicates
        std::sort(affected_addrs.begin(), affected_addrs.end());
        affected_addrs.erase(std::unique(affected_addrs.begin(), affected_addrs.end()),
                            affected_addrs.end());
        tx_to_addrs_[txid_key] = affected_addrs;
    }

    return true;
}

bool AddressIndex::unindex_transaction(const std::vector<uint8_t>& txid) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_) return false;

    std::string txid_key = to_hex(txid);

    // Find affected addresses
    auto it = tx_to_addrs_.find(txid_key);
    if (it == tx_to_addrs_.end()) {
        return true;  // Transaction not indexed
    }

    // Remove entries from each affected address
    for (const auto& pkh_str : it->second) {
        auto addr_it = addr_index_.find(pkh_str);
        if (addr_it == addr_index_.end()) continue;

        auto& entries = addr_it->second;
        size_t old_size = entries.size();

        entries.erase(
            std::remove_if(entries.begin(), entries.end(),
                          [&txid](const AddressTxEntry& e) {
                              return e.txid == txid;
                          }),
            entries.end()
        );

        size_t removed = old_size - entries.size();
        total_entries_ -= removed;

        // Remove address if empty
        if (entries.empty()) {
            addr_index_.erase(addr_it);
        }
    }

    tx_to_addrs_.erase(it);
    dirty_ = true;

    return true;
}

std::vector<std::vector<uint8_t>> AddressIndex::get_address_txids(
    const std::vector<uint8_t>& pkh,
    uint64_t start_height,
    uint64_t end_height,
    size_t skip,
    size_t limit
) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    std::vector<std::vector<uint8_t>> result;
    if (!enabled_ || pkh.size() != 20) return result;

    std::string pkh_str = pkh_key(pkh);
    auto it = addr_index_.find(pkh_str);
    if (it == addr_index_.end()) return result;

    // Get sorted entries
    std::vector<AddressTxEntry> filtered;
    for (const auto& e : it->second) {
        if (e.block_height >= start_height && e.block_height <= end_height) {
            filtered.push_back(e);
        }
    }

    // Sort by height descending
    std::sort(filtered.begin(), filtered.end());

    // Deduplicate txids (same tx might have multiple entries)
    std::unordered_set<std::string> seen;
    std::vector<std::vector<uint8_t>> unique_txids;

    for (const auto& e : filtered) {
        std::string txid_str = to_hex(e.txid);
        if (seen.insert(txid_str).second) {
            unique_txids.push_back(e.txid);
        }
    }

    // Apply pagination
    size_t start = std::min(skip, unique_txids.size());
    size_t end = std::min(start + limit, unique_txids.size());

    result.reserve(end - start);
    for (size_t i = start; i < end; ++i) {
        result.push_back(unique_txids[i]);
    }

    return result;
}

std::vector<AddressTxEntry> AddressIndex::get_address_history(
    const std::vector<uint8_t>& pkh,
    uint64_t start_height,
    uint64_t end_height,
    size_t skip,
    size_t limit
) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    std::vector<AddressTxEntry> result;
    if (!enabled_ || pkh.size() != 20) return result;

    std::string pkh_str = pkh_key(pkh);
    auto it = addr_index_.find(pkh_str);
    if (it == addr_index_.end()) return result;

    // Filter by height range
    std::vector<AddressTxEntry> filtered;
    for (const auto& e : it->second) {
        if (e.block_height >= start_height && e.block_height <= end_height) {
            filtered.push_back(e);
        }
    }

    // Sort by height descending
    std::sort(filtered.begin(), filtered.end());

    // Apply pagination
    size_t start = std::min(skip, filtered.size());
    size_t end = std::min(start + limit, filtered.size());

    result.reserve(end - start);
    for (size_t i = start; i < end; ++i) {
        result.push_back(filtered[i]);
    }

    return result;
}

AddressBalance AddressIndex::get_address_balance(
    const std::vector<uint8_t>& pkh,
    uint64_t current_height,
    uint64_t coinbase_maturity
) const {
    (void)current_height;     // Reserved for coinbase maturity filtering
    (void)coinbase_maturity;  // Reserved for coinbase maturity filtering
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    AddressBalance bal;
    if (!enabled_ || pkh.size() != 20) return bal;

    std::string pkh_str = pkh_key(pkh);
    auto it = addr_index_.find(pkh_str);
    if (it == addr_index_.end()) return bal;

    // Track which outputs have been spent
    std::unordered_set<std::string> spent_outputs;

    // First pass: find all spent outputs
    for (const auto& e : it->second) {
        if (e.is_input && !e.spent_txid.empty()) {
            std::string key = to_hex(e.spent_txid) + ":" + std::to_string(e.spent_vout);
            spent_outputs.insert(key);
        }
    }

    // Track unique txids for tx_count
    std::unordered_set<std::string> unique_txids;

    // Second pass: calculate balances
    for (const auto& e : it->second) {
        unique_txids.insert(to_hex(e.txid));

        if (!e.is_input) {
            // This is an output (received)
            std::string outpoint = to_hex(e.txid) + ":" + std::to_string(e.io_index);
            bal.total_received += e.value;

            if (spent_outputs.find(outpoint) == spent_outputs.end()) {
                // Unspent output
                bal.utxo_count++;

                if (e.block_height == 0) {
                    // Unconfirmed
                    bal.unconfirmed += e.value;
                } else {
                    // Check coinbase maturity (simplified - would need coinbase flag)
                    // For now, treat all as confirmed
                    bal.confirmed += e.value;
                }
            }
        } else {
            // This is an input (spent)
            bal.total_sent += e.value;
        }
    }

    bal.tx_count = static_cast<uint32_t>(unique_txids.size());

    return bal;
}

size_t AddressIndex::get_address_tx_count(const std::vector<uint8_t>& pkh) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || pkh.size() != 20) return 0;

    std::string pkh_str = pkh_key(pkh);
    auto it = addr_index_.find(pkh_str);
    if (it == addr_index_.end()) return 0;

    // Count unique txids
    std::unordered_set<std::string> unique_txids;
    for (const auto& e : it->second) {
        unique_txids.insert(to_hex(e.txid));
    }

    return unique_txids.size();
}

bool AddressIndex::has_transactions(const std::vector<uint8_t>& pkh) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || pkh.size() != 20) return false;

    std::string pkh_str = pkh_key(pkh);
    auto it = addr_index_.find(pkh_str);
    return it != addr_index_.end() && !it->second.empty();
}

// =============================================================================
// Block Hash Index
// =============================================================================

void AddressIndex::add_block_hash(const std::vector<uint8_t>& hash, uint64_t height) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || hash.size() != 32) return;

    std::string key = hash_key(hash);
    hash_index_[key] = height;
    append_hash_log('A', hash, height);
    dirty_ = true;
}

void AddressIndex::remove_block_hash(const std::vector<uint8_t>& hash) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || hash.size() != 32) return;

    std::string key = hash_key(hash);
    hash_index_.erase(key);
    append_hash_log('R', hash, 0);
    dirty_ = true;
}

int64_t AddressIndex::get_height_for_hash(const std::vector<uint8_t>& hash) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || hash.size() != 32) return -1;

    std::string key = hash_key(hash);
    auto it = hash_index_.find(key);
    if (it == hash_index_.end()) return -1;

    return static_cast<int64_t>(it->second);
}

bool AddressIndex::has_block_hash(const std::vector<uint8_t>& hash) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || hash.size() != 32) return false;

    std::string key = hash_key(hash);
    return hash_index_.find(key) != hash_index_.end();
}

// =============================================================================
// Persistence
// =============================================================================

bool AddressIndex::flush() {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_ || !dirty_) return true;

    // Save state
    if (!save_to_disk()) {
        log_error("AddressIndex: Failed to save state");
        return false;
    }

    dirty_ = false;
    return true;
}

bool AddressIndex::load_from_disk() {
    // Load state file
    std::ifstream state_f(state_path_, std::ios::binary);
    if (state_f) {
        uint32_t magic = 0, version = 0;
        state_f.read(reinterpret_cast<char*>(&magic), sizeof(magic));
        state_f.read(reinterpret_cast<char*>(&version), sizeof(version));

        if (magic != ADDR_INDEX_MAGIC || version != ADDR_INDEX_VERSION) {
            log_warn("AddressIndex: Invalid state file, reindexing required");
            return false;
        }

        state_f.read(reinterpret_cast<char*>(&best_height_), sizeof(best_height_));
        state_f.read(reinterpret_cast<char*>(&total_entries_), sizeof(total_entries_));
    }

    // Load address log
    std::ifstream addr_f(addr_log_path_, std::ios::binary);
    if (addr_f) {
        while (addr_f) {
            char op;
            addr_f.read(&op, 1);
            if (!addr_f) break;

            // Read key (37 bytes)
            char key_buf[37];
            addr_f.read(key_buf, 37);
            if (!addr_f) break;

            AddrKey key = AddrKey::from_string(std::string(key_buf, 37));

            if (op == 'A') {
                // Read value (84 bytes)
                char val_buf[84];
                addr_f.read(val_buf, 84);
                if (!addr_f) break;

                AddrValue val = AddrValue::deserialize(std::string(val_buf, 84));

                // Reconstruct entry
                AddressTxEntry entry;
                entry.txid = std::vector<uint8_t>(val.txid.begin(), val.txid.end());
                entry.block_height = key.height;
                entry.tx_position = key.tx_pos;
                entry.timestamp = val.timestamp;
                entry.is_input = (key.type == 1);
                entry.value = val.value;
                entry.io_index = key.io_idx;
                entry.spent_txid = std::vector<uint8_t>(val.spent_txid.begin(), val.spent_txid.end());
                entry.spent_vout = val.spent_vout;

                std::string pkh_str = to_hex(std::vector<uint8_t>(key.pkh.begin(), key.pkh.end()));
                addr_index_[pkh_str].push_back(entry);
            }
        }
    }

    // Load hash log
    std::ifstream hash_f(hash_log_path_, std::ios::binary);
    if (hash_f) {
        while (hash_f) {
            char op;
            hash_f.read(&op, 1);
            if (!hash_f) break;

            char hash_buf[32];
            hash_f.read(hash_buf, 32);
            if (!hash_f) break;

            uint64_t height = 0;
            hash_f.read(reinterpret_cast<char*>(&height), sizeof(height));
            if (!hash_f) break;

            std::string key(hash_buf, 32);
            if (op == 'A') {
                hash_index_[key] = height;
            } else if (op == 'R') {
                hash_index_.erase(key);
            }
        }
    }

    return true;
}

bool AddressIndex::save_to_disk() const {
    // Save state
    std::string temp_path = state_path_ + ".tmp";
    std::ofstream f(temp_path, std::ios::binary | std::ios::trunc);
    if (!f) return false;

    f.write(reinterpret_cast<const char*>(&ADDR_INDEX_MAGIC), sizeof(ADDR_INDEX_MAGIC));
    f.write(reinterpret_cast<const char*>(&ADDR_INDEX_VERSION), sizeof(ADDR_INDEX_VERSION));
    f.write(reinterpret_cast<const char*>(&best_height_), sizeof(best_height_));
    f.write(reinterpret_cast<const char*>(&total_entries_), sizeof(total_entries_));

    f.flush();
    f.close();

    try {
        fs::rename(temp_path, state_path_);
    } catch (...) {
        return false;
    }

    return true;
}

bool AddressIndex::append_log(char op, const AddrKey& key, const AddrValue* val) {
    std::ofstream f(addr_log_path_, std::ios::app | std::ios::binary);
    if (!f) return false;

    f.write(&op, 1);

    std::string key_str = key.to_string();
    f.write(key_str.data(), key_str.size());

    if (op == 'A' && val) {
        std::string val_str = val->serialize();
        f.write(val_str.data(), val_str.size());
    }

    f.flush();
    return f.good();
}

bool AddressIndex::append_hash_log(char op, const std::vector<uint8_t>& hash, uint64_t height) {
    std::ofstream f(hash_log_path_, std::ios::app | std::ios::binary);
    if (!f) return false;

    f.write(&op, 1);
    f.write(reinterpret_cast<const char*>(hash.data()), 32);
    f.write(reinterpret_cast<const char*>(&height), sizeof(height));

    f.flush();
    return f.good();
}

bool AddressIndex::reindex(const std::function<bool(uint64_t, Block&)>& get_block_fn,
                           uint64_t chain_height,
                           ProgressCallback progress) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!enabled_) return false;

    log_info("AddressIndex: Starting reindex from genesis to height " + std::to_string(chain_height));

    // Clear existing data
    addr_index_.clear();
    hash_index_.clear();
    tx_to_addrs_.clear();
    total_entries_ = 0;
    best_height_ = 0;

    // Truncate log files
    std::ofstream(addr_log_path_, std::ios::trunc).close();
    std::ofstream(hash_log_path_, std::ios::trunc).close();

    int64_t start_time = now_ms();
    int64_t last_log = start_time;

    for (uint64_t h = 0; h <= chain_height; ++h) {
        Block block;
        if (!get_block_fn(h, block)) {
            log_error("AddressIndex: Failed to get block at height " + std::to_string(h));
            return false;
        }

        if (!index_block(block, h)) {
            log_error("AddressIndex: Failed to index block at height " + std::to_string(h));
            return false;
        }

        // Progress callback
        if (progress && !progress(h, chain_height)) {
            log_info("AddressIndex: Reindex aborted by user");
            return false;
        }

        // Log progress every 10 seconds
        int64_t now = now_ms();
        if (now - last_log >= 10000) {
            double pct = (chain_height > 0) ? (100.0 * h / chain_height) : 100.0;
            double elapsed_s = (now - start_time) / 1000.0;
            double blocks_per_sec = (elapsed_s > 0) ? (h / elapsed_s) : 0;

            log_info("AddressIndex: Reindex progress " + std::to_string(static_cast<int>(pct)) +
                     "% (" + std::to_string(h) + "/" + std::to_string(chain_height) +
                     ") " + std::to_string(static_cast<int>(blocks_per_sec)) + " blocks/sec");

            last_log = now;
        }
    }

    // Final flush
    flush();

    double elapsed_s = (now_ms() - start_time) / 1000.0;
    log_info("AddressIndex: Reindex complete in " + std::to_string(static_cast<int>(elapsed_s)) +
             "s, indexed " + std::to_string(addr_index_.size()) + " addresses, " +
             std::to_string(total_entries_) + " entries");

    return true;
}

// =============================================================================
// Statistics
// =============================================================================

size_t AddressIndex::address_count() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return addr_index_.size();
}

size_t AddressIndex::transaction_count() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return tx_to_addrs_.size();
}

size_t AddressIndex::block_hash_count() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    return hash_index_.size();
}

size_t AddressIndex::disk_usage() const {
    size_t total = 0;
    try {
        if (fs::exists(addr_log_path_)) {
            total += fs::file_size(addr_log_path_);
        }
        if (fs::exists(hash_log_path_)) {
            total += fs::file_size(hash_log_path_);
        }
        if (fs::exists(state_path_)) {
            total += fs::file_size(state_path_);
        }
    } catch (...) {}
    return total;
}

// =============================================================================
// BlockHashIndex Implementation (Standalone)
// =============================================================================

std::string BlockHashIndex::key(const std::vector<uint8_t>& hash) {
    return std::string(reinterpret_cast<const char*>(hash.data()), hash.size());
}

void BlockHashIndex::add(const std::vector<uint8_t>& hash, uint64_t height) {
    std::lock_guard<std::mutex> lk(mtx_);
    index_[key(hash)] = height;
}

void BlockHashIndex::remove(const std::vector<uint8_t>& hash) {
    std::lock_guard<std::mutex> lk(mtx_);
    index_.erase(key(hash));
}

int64_t BlockHashIndex::get(const std::vector<uint8_t>& hash) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = index_.find(key(hash));
    return (it != index_.end()) ? static_cast<int64_t>(it->second) : -1;
}

bool BlockHashIndex::has(const std::vector<uint8_t>& hash) const {
    std::lock_guard<std::mutex> lk(mtx_);
    return index_.find(key(hash)) != index_.end();
}

size_t BlockHashIndex::size() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return index_.size();
}

void BlockHashIndex::clear() {
    std::lock_guard<std::mutex> lk(mtx_);
    index_.clear();
}

bool BlockHashIndex::save(const std::string& path) const {
    std::lock_guard<std::mutex> lk(mtx_);

    std::string temp_path = path + ".tmp";
    std::ofstream f(temp_path, std::ios::binary | std::ios::trunc);
    if (!f) return false;

    uint64_t count = index_.size();
    f.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for (const auto& kv : index_) {
        if (kv.first.size() != 32) continue;
        f.write(kv.first.data(), 32);
        f.write(reinterpret_cast<const char*>(&kv.second), sizeof(kv.second));
    }

    f.flush();
    f.close();

    try {
        fs::rename(temp_path, path);
    } catch (...) {
        return false;
    }

    return true;
}

bool BlockHashIndex::load(const std::string& path) {
    std::lock_guard<std::mutex> lk(mtx_);

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    index_.clear();

    uint64_t count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    if (!f) return false;

    for (uint64_t i = 0; i < count; ++i) {
        char hash_buf[32];
        f.read(hash_buf, 32);
        if (!f) break;

        uint64_t height = 0;
        f.read(reinterpret_cast<char*>(&height), sizeof(height));
        if (!f) break;

        index_[std::string(hash_buf, 32)] = height;
    }

    return true;
}

}  // namespace miq
