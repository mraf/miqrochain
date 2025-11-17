// === NEW FILE: src/compact_blocks.cpp ===
// compact_blocks.cpp - BIP152 Compact Block implementation
#include "compact_blocks.h"
#include "sha256.h"
#include "serialize.h"
#include <algorithm>
#include <random>

namespace miq {

// SipHash for short transaction IDs
uint64_t SipHashUint256(uint64_t k0, uint64_t k1, const uint256& val) {
    // Simplified SipHash implementation
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0;
    uint64_t v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0;
    uint64_t v3 = 0x7465646279746573ULL ^ k1;
    
    // Mix in the data
    const uint64_t* pdata = reinterpret_cast<const uint64_t*>(val.data());
    for (int i = 0; i < 4; ++i) {
        v3 ^= pdata[i];
        // SIPROUND
        v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0;
        v0 = (v0 << 32) | (v0 >> 32);
        v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2;
        v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0;
        v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2;
        v2 = (v2 << 32) | (v2 >> 32);
        v0 ^= pdata[i];
    }
    
    // Finalization
    v2 ^= 0xff;
    for (int i = 0; i < 4; ++i) {
        v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0;
        v0 = (v0 << 32) | (v0 >> 32);
        v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2;
        v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0;
        v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2;
        v2 = (v2 << 32) | (v2 >> 32);
    }
    
    return v0 ^ v1 ^ v2 ^ v3;
}

CompactBlock CompactBlock::FromBlock(const Block& block, bool use_wtxid) {
    CompactBlock cmpct;
    cmpct.header = block.header;
    
    // Generate random nonce for SipHash
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    cmpct.nonce = dis(gen);
    
    // Calculate k0 and k1 for SipHash
    std::vector<uint8_t> stream;
    stream.insert(stream.end(), block.header.hash().begin(), block.header.hash().end());
    stream.insert(stream.end(), reinterpret_cast<uint8_t*>(&cmpct.nonce), 
                  reinterpret_cast<uint8_t*>(&cmpct.nonce) + 8);
    
    uint256 hash = SHA256(SHA256(stream));
    uint64_t k0 = *reinterpret_cast<uint64_t*>(hash.data());
    uint64_t k1 = *reinterpret_cast<uint64_t*>(hash.data() + 8);
    
    // Create short IDs for all transactions except coinbase
    for (size_t i = 1; i < block.txs.size(); ++i) {
        uint256 txhash = use_wtxid ? block.txs[i].wtxid() : block.txs[i].txid();
        uint64_t short_id = SipHashUint256(k0, k1, txhash) & 0xffffffffffffL;
        cmpct.short_ids.push_back(short_id);
    }
    
    // Always include coinbase as prefilled
    cmpct.prefilled_txs.push_back(block.txs[0]);
    
    return cmpct;
}

Block CompactBlock::ReconstructBlock(const std::vector<Tx>& mempool_txs) const {
    Block block;
    block.header = header;
    
    // Map of transaction hash to transaction
    std::unordered_map<uint64_t, Tx> tx_map;
    
    // Calculate k0 and k1 for SipHash
    std::vector<uint8_t> stream;
    stream.insert(stream.end(), header.hash().begin(), header.hash().end());
    stream.insert(stream.end(), reinterpret_cast<const uint8_t*>(&nonce), 
                  reinterpret_cast<const uint8_t*>(&nonce) + 8);
    
    uint256 hash = SHA256(SHA256(stream));
    uint64_t k0 = *reinterpret_cast<uint64_t*>(hash.data());
    uint64_t k1 = *reinterpret_cast<uint64_t*>(hash.data() + 8);
    
    // Build short ID map from mempool
    for (const auto& tx : mempool_txs) {
        uint256 txhash = tx.txid();
        uint64_t short_id = SipHashUint256(k0, k1, txhash) & 0xffffffffffffL;
        tx_map[short_id] = tx;
    }
    
    // Add prefilled transactions (usually coinbase)
    for (const auto& tx : prefilled_txs) {
        block.txs.push_back(tx);
    }
    
    // Fill in transactions from short IDs
    for (uint64_t short_id : short_ids) {
        auto it = tx_map.find(short_id);
        if (it != tx_map.end()) {
            block.txs.push_back(it->second);
        } else {
            // Missing transaction - request it
            return Block(); // Return empty block to signal failure
        }
    }
    
    return block;
}

} // namespace miq

// === NEW FILE: src/fee_estimation.cpp ===
// fee_estimation.cpp - Smart fee estimation
#include "fee_estimation.h"
#include <algorithm>
#include <cmath>

namespace miq {

class FeeEstimator::Impl {
public:
    struct TxStatsInfo {
        double fee_rate;
        int blocks_to_confirm;
        bool successful;
    };
    
private:
    mutable std::mutex mutex_;
    std::vector<TxStatsInfo> history_;
    static constexpr size_t MAX_HISTORY = 10000;
    static constexpr double DEFAULT_FEE_RATE = 0.00001; // BTC per KB
    
public:
    void AddTransaction(const Tx& tx, double fee_rate) {
        std::lock_guard lock(mutex_);
        
        if (history_.size() >= MAX_HISTORY) {
            history_.erase(history_.begin());
        }
        
        history_.push_back({fee_rate, 0, false});
    }
    
    void UpdateTransaction(const uint256& txid, int blocks_to_confirm) {
        std::lock_guard lock(mutex_);
        
        // Find and update transaction
        // In production, would use a map for O(1) lookup
        for (auto& info : history_) {
            // Match by some criteria
            info.blocks_to_confirm = blocks_to_confirm;
            info.successful = true;
        }
    }
    
    double EstimateFee(int target_blocks) const {
        std::lock_guard lock(mutex_);
        
        if (history_.size() < 100) {
            return DEFAULT_FEE_RATE;
        }
        
        // Filter transactions that confirmed within target
        std::vector<double> confirmed_fees;
        for (const auto& info : history_) {
            if (info.successful && info.blocks_to_confirm <= target_blocks) {
                confirmed_fees.push_back(info.fee_rate);
            }
        }
        
        if (confirmed_fees.empty()) {
            return DEFAULT_FEE_RATE;
        }
        
        // Return median fee rate
        std::sort(confirmed_fees.begin(), confirmed_fees.end());
        return confirmed_fees[confirmed_fees.size() / 2];
    }
    
    double EstimateSmartFee(int target_blocks, int& found_target) const {
        // Try progressively longer targets until we have enough data
        for (int target = target_blocks; target <= 1008; target *= 2) {
            double fee = EstimateFee(target);
            if (fee > DEFAULT_FEE_RATE) {
                found_target = target;
                return fee;
            }
        }
        
        found_target = -1;
        return DEFAULT_FEE_RATE;
    }
};

FeeEstimator::FeeEstimator() : pImpl(std::make_unique<Impl>()) {}
FeeEstimator::~FeeEstimator() = default;

void FeeEstimator::AddTransaction(const Tx& tx, double fee_rate) {
    pImpl->AddTransaction(tx, fee_rate);
}

void FeeEstimator::UpdateTransaction(const uint256& txid, int blocks_to_confirm) {
    pImpl->UpdateTransaction(txid, blocks_to_confirm);
}

double FeeEstimator::EstimateFee(int target_blocks) const {
    return pImpl->EstimateFee(target_blocks);
}

double FeeEstimator::EstimateSmartFee(int target_blocks, int& found_target) const {
    return pImpl->EstimateSmartFee(target_blocks, found_target);
}

} // namespace miq

// === NEW FILE: src/orphan_manager.cpp ===
// orphan_manager.cpp - Orphan transaction management
#include "orphan_manager.h"
#include <algorithm>

namespace miq {

class OrphanManager::Impl {
private:
    mutable std::mutex mutex_;
    
    struct OrphanTx {
        CTransactionRef tx;
        NodeId from_peer;
        int64_t time_expire;
    };
    
    std::map<uint256, OrphanTx> mapOrphanTransactions;
    std::map<COutPoint, std::set<uint256>> mapOrphanTransactionsByPrev;
    
    static constexpr size_t MAX_ORPHAN_TRANSACTIONS = 100;
    static constexpr int64_t ORPHAN_TX_EXPIRE_TIME = 20 * 60; // 20 minutes
    
    void LimitOrphans() {
        int64_t now = GetTime();
        
        // Remove expired orphans
        auto it = mapOrphanTransactions.begin();
        while (it != mapOrphanTransactions.end()) {
            if (it->second.time_expire < now) {
                RemoveOrphanTx(it++);
            } else {
                ++it;
            }
        }
        
        // Limit size
        while (mapOrphanTransactions.size() > MAX_ORPHAN_TRANSACTIONS) {
            // Evict a random orphan
            auto it = mapOrphanTransactions.begin();
            std::advance(it, rand() % mapOrphanTransactions.size());
            RemoveOrphanTx(it);
        }
    }
    
    void RemoveOrphanTx(std::map<uint256, OrphanTx>::iterator it) {
        // Remove from prevout index
        for (const auto& input : it->second.tx->inputs) {
            auto itPrev = mapOrphanTransactionsByPrev.find(input.GetOutPoint());
            if (itPrev != mapOrphanTransactionsByPrev.end()) {
                itPrev->second.erase(it->first);
                if (itPrev->second.empty()) {
                    mapOrphanTransactionsByPrev.erase(itPrev);
                }
            }
        }
        
        mapOrphanTransactions.erase(it);
    }
    
public:
    bool AddOrphanTx(const CTransactionRef& tx, NodeId peer) {
        std::lock_guard lock(mutex_);
        
        uint256 hash = tx->GetHash();
        if (mapOrphanTransactions.count(hash)) {
            return false;
        }
        
        // Add to orphan pool
        int64_t expire_time = GetTime() + ORPHAN_TX_EXPIRE_TIME;
        mapOrphanTransactions[hash] = {tx, peer, expire_time};
        
        // Add to index by prevout
        for (const auto& input : tx->inputs) {
            mapOrphanTransactionsByPrev[input.GetOutPoint()].insert(hash);
        }
        
        LimitOrphans();
        return true;
    }
    
    void EraseOrphansFor(NodeId peer) {
        std::lock_guard lock(mutex_);
        
        auto it = mapOrphanTransactions.begin();
        while (it != mapOrphanTransactions.end()) {
            if (it->second.from_peer == peer) {
                RemoveOrphanTx(it++);
            } else {
                ++it;
            }
        }
    }
    
    std::vector<CTransactionRef> GetOrphanChildren(const COutPoint& outpoint) {
        std::lock_guard lock(mutex_);
        std::vector<CTransactionRef> children;
        
        auto it = mapOrphanTransactionsByPrev.find(outpoint);
        if (it != mapOrphanTransactionsByPrev.end()) {
            for (const uint256& hash : it->second) {
                auto itOrphan = mapOrphanTransactions.find(hash);
                if (itOrphan != mapOrphanTransactions.end()) {
                    children.push_back(itOrphan->second.tx);
                }
            }
        }
        
        return children;
    }
    
    size_t Size() const {
        std::lock_guard lock(mutex_);
        return mapOrphanTransactions.size();
    }
};

OrphanManager::OrphanManager() : pImpl(std::make_unique<Impl>()) {}
OrphanManager::~OrphanManager() = default;

bool OrphanManager::AddOrphanTx(const CTransactionRef& tx, NodeId peer) {
    return pImpl->AddOrphanTx(tx, peer);
}

void OrphanManager::EraseOrphansFor(NodeId peer) {
    pImpl->EraseOrphansFor(peer);
}

std::vector<CTransactionRef> OrphanManager::GetOrphanChildren(const COutPoint& outpoint) {
    return pImpl->GetOrphanChildren(outpoint);
}

size_t OrphanManager::Size() const {
    return pImpl->Size();
}

} // namespace miq

// === NEW FILE: src/ban_manager.cpp ===
// ban_manager.cpp - Peer banning and DoS prevention
#include "ban_manager.h"
#include <algorithm>

namespace miq {

class BanManager::Impl {
private:
    mutable std::shared_mutex mutex_;
    
    struct BanEntry {
        int64_t ban_time;
        int64_t create_time;
        std::string reason;
    };
    
    std::map<CSubNet, BanEntry> setBanned;
    bool is_dirty_{false};
    
    static constexpr int64_t DEFAULT_BAN_TIME = 24 * 60 * 60; // 24 hours
    
public:
    void Ban(const CNetAddr& addr, int64_t ban_time_offset, const std::string& reason) {
        std::unique_lock lock(mutex_);
        
        CSubNet subnet(addr);
        int64_t ban_time = GetTime() + (ban_time_offset ? ban_time_offset : DEFAULT_BAN_TIME);
        
        setBanned[subnet] = {ban_time, GetTime(), reason};
        is_dirty_ = true;
    }
    
    void Ban(const CSubNet& subnet, int64_t ban_time_offset, const std::string& reason) {
        std::unique_lock lock(mutex_);
        
        int64_t ban_time = GetTime() + (ban_time_offset ? ban_time_offset : DEFAULT_BAN_TIME);
        setBanned[subnet] = {ban_time, GetTime(), reason};
        is_dirty_ = true;
    }
    
    bool Unban(const CNetAddr& addr) {
        std::unique_lock lock(mutex_);
        
        CSubNet subnet(addr);
        if (setBanned.erase(subnet)) {
            is_dirty_ = true;
            return true;
        }
        return false;
    }
    
    bool Unban(const CSubNet& subnet) {
        std::unique_lock lock(mutex_);
        
        if (setBanned.erase(subnet)) {
            is_dirty_ = true;
            return true;
        }
        return false;
    }
    
    void ClearBanned() {
        std::unique_lock lock(mutex_);
        setBanned.clear();
        is_dirty_ = true;
    }
    
    bool IsBanned(const CNetAddr& addr) {
        std::shared_lock lock(mutex_);
        
        int64_t now = GetTime();
        
        // Check if in any banned subnet
        for (auto it = setBanned.begin(); it != setBanned.end();) {
            const CSubNet& subnet = it->first;
            const BanEntry& ban_entry = it->second;
            
            if (ban_entry.ban_time < now) {
                // Expired ban
                it = setBanned.erase(it);
                is_dirty_ = true;
            } else if (subnet.Match(addr)) {
                return true;
            } else {
                ++it;
            }
        }
        
        return false;
    }
    
    bool IsBanned(const CSubNet& subnet) {
        std::shared_lock lock(mutex_);
        
        int64_t now = GetTime();
        auto it = setBanned.find(subnet);
        
        if (it != setBanned.end()) {
            if (it->second.ban_time < now) {
                // Expired
                setBanned.erase(it);
                is_dirty_ = true;
                return false;
            }
            return true;
        }
        
        return false;
    }
    
    void GetBanned(std::map<CSubNet, int64_t>& banned) {
        std::shared_lock lock(mutex_);
        
        banned.clear();
        int64_t now = GetTime();
        
        for (auto it = setBanned.begin(); it != setBanned.end();) {
            if (it->second.ban_time < now) {
                it = setBanned.erase(it);
                is_dirty_ = true;
            } else {
                banned[it->first] = it->second.ban_time;
                ++it;
            }
        }
    }
    
    bool DumpBanlist(const std::string& path) {
        std::shared_lock lock(mutex_);
        
        try {
            std::ofstream file(path, std::ios::binary);
            if (!file) return false;
            
            // Write ban entries
            uint32_t count = setBanned.size();
            file.write(reinterpret_cast<char*>(&count), sizeof(count));
            
            for (const auto& [subnet, entry] : setBanned) {
                // Serialize subnet and ban entry
                // Implementation depends on serialization format
            }
            
            return true;
        } catch (...) {
            return false;
        }
    }
    
    bool LoadBanlist(const std::string& path) {
        std::unique_lock lock(mutex_);
        
        try {
            std::ifstream file(path, std::ios::binary);
            if (!file) return false;
            
            setBanned.clear();
            
            uint32_t count;
            file.read(reinterpret_cast<char*>(&count), sizeof(count));
            
            for (uint32_t i = 0; i < count; ++i) {
                // Deserialize subnet and ban entry
                // Implementation depends on serialization format
            }
            
            return true;
        } catch (...) {
            return false;
        }
    }
};

BanManager::BanManager() : pImpl(std::make_unique<Impl>()) {}
BanManager::~BanManager() = default;

void BanManager::Ban(const CNetAddr& addr, int64_t ban_time_offset, const std::string& reason) {
    pImpl->Ban(addr, ban_time_offset, reason);
}

bool BanManager::Unban(const CNetAddr& addr) {
    return pImpl->Unban(addr);
}

void BanManager::ClearBanned() {
    pImpl->ClearBanned();
}

bool BanManager::IsBanned(const CNetAddr& addr) {
    return pImpl->IsBanned(addr);
}

}
