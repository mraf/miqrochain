#include "mempool.h"
#include "serialize.h"
#include "constants.h"
#include "block.h"   // Block type for connect/disconnect
#include "utxo.h"    // UTXOSet + UTXOEntry definition
#include "sha256.h"  // dsha256 for sighash
#include "hash160.h" // hash160(pubkey) to compare with PKH
#include "crypto/ecdsa_iface.h" // crypto::ECDSA::verify

#include <algorithm>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <deque>

namespace miq {

static inline std::string key_from_vec(const std::vector<uint8_t>& v){
    return std::string(reinterpret_cast<const char*>(v.data()), v.size());
}

Mempool::Mempool() {}

Mempool::Key Mempool::k(const std::vector<uint8_t>& txid){
    return key_from_vec(txid);
}

bool Mempool::exists(const std::vector<uint8_t>& txid) const {
    return map_.find(k(txid)) != map_.end();
}

size_t Mempool::est_tx_size(const Transaction& tx){
    // Use actual serialized size for stability
    return ser_tx(tx).size();
}

uint64_t Mempool::sum_outputs(const Transaction& tx){
    uint64_t out=0;
    for (const auto& o: tx.vout){
        uint64_t tmp = out + o.value;
        if (tmp < out) return (uint64_t)-1; // overflow guard
        out = tmp;
    }
    return out;
}

int64_t Mempool::now_ms(){
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// Helper: compute a minimal relay fee based on transaction size.
// Uses MIQ_MEMPOOL_MIN_FEE_RATE from constants.h (sat/byte)
// CRITICAL FIX: Always enforce minimum fee - this was previously broken due to macro mismatch
static inline uint64_t min_fee_for_size_bytes(size_t sz){
    // Default minimum: 1 sat/byte (1000 sat/kB)
    // This ensures transactions have at least some fee to prevent spam
#ifdef MIQ_MEMPOOL_MIN_FEE_RATE
    // MIQ_MEMPOOL_MIN_FEE_RATE is in sat/byte, convert to sat/kB for calculation
    constexpr uint64_t fee_rate_per_kb = (uint64_t)MIQ_MEMPOOL_MIN_FEE_RATE * 1000ULL;
#else
    constexpr uint64_t fee_rate_per_kb = 1000ULL;  // Default: 1 sat/byte = 1000 sat/kB
#endif
    uint64_t kb = (uint64_t)((sz + 999) / 1000);
    if (kb == 0) kb = 1;
    return kb * fee_rate_per_kb;
}

bool Mempool::validate_inputs_and_calc_fee(const Transaction& tx, const UTXOView& utxo, uint64_t& fee, std::string& err) const {
    // coinbase cannot be in mempool (loose check)
    if (tx.vin.size()==1 &&
        tx.vin[0].prev.vout==0 &&
        tx.vin[0].prev.txid.size()==32 &&
        std::all_of(tx.vin[0].prev.txid.begin(), tx.vin[0].prev.txid.end(), [](uint8_t v){return v==0;})) {
        err = "coinbase in mempool";
        return false;
    }

    // CRITICAL FIX: Check for duplicate inputs within the same transaction
    std::unordered_set<std::string> seen_inputs;
    for (const auto& in : tx.vin) {
        std::string input_key = key_from_vec(in.prev.txid) + ":" + std::to_string(in.prev.vout);
        if (!seen_inputs.insert(input_key).second) {
            err = "duplicate input";
            return false;
        }

        // CRITICAL FIX: Check for double-spend against mempool
        if (spent_outputs_.count(input_key) > 0) {
            err = "double-spend";
            return false;
        }
    }

    // Prepare sighash: blank sig/pubkey for all inputs, serialize, double-SHA256
    Transaction sighash_tx = tx;
    for (auto& i : sighash_tx.vin) { i.sig.clear(); i.pubkey.clear(); }
    const std::vector<uint8_t> sighash = dsha256(ser_tx(sighash_tx));

    // Sum inputs using UTXO or mempool-provided outputs, while verifying each input's signature & PKH
    uint64_t in_sum = 0;
    for (const auto& in : tx.vin) {
        // Determine previous output (value + PKH), first try mempool parent
        std::vector<uint8_t> expect_pkh;
        uint64_t prev_value = 0;

        auto pit = map_.find(k(in.prev.txid));
        if (pit != map_.end()) {
            const auto& ptx = pit->second.tx;
            if (in.prev.vout >= ptx.vout.size()) { err="bad prev vout"; return false; }
            const auto& prev_out = ptx.vout[in.prev.vout];
            prev_value = prev_out.value;
            expect_pkh = prev_out.pkh;
        } else {
            // Then UTXO set via interface
            UTXOEntry e;
            if (!utxo.get(in.prev.txid, in.prev.vout, e)) {
                // Not found in UTXO or mempool -> orphan candidate
                err.clear();
                return false; // caller treats empty err as orphan
            }
            prev_value = e.value;
            expect_pkh = e.pkh;
        }

        // Basic input fields
        if (in.sig.size() != 64) { err = "bad sig size"; return false; }
        if (in.pubkey.size() != 33 && in.pubkey.size() != 65) { err = "bad pubkey size"; return false; }

        // PKH must match referenced output's PKH
        if (hash160(in.pubkey) != expect_pkh) { err = "pkh mismatch"; return false; }

        // Verify ECDSA over the tx-wide sighash
        if (!crypto::ECDSA::verify(in.pubkey, sighash, in.sig)) {
            err = "bad signature"; return false;
        }

        // input sum + overflow guard
        uint64_t tmp = in_sum + prev_value;
        if (tmp < in_sum) { err="input overflow"; return false; }
        in_sum = tmp;
    }

    uint64_t out_sum = sum_outputs(tx);
    if (out_sum == (uint64_t)-1) { err="output overflow"; return false; }
    if (out_sum > in_sum) { err="fees negative"; return false; }
    fee = in_sum - out_sum;
    return true;
}

bool Mempool::compute_ancestor_stats(const Key& root, size_t& cnt, size_t& bytes) const {
    cnt = 0; bytes = 0;
    std::unordered_set<Key> seen;
    std::deque<Key> q;
    auto it = map_.find(root);
    if (it == map_.end()) return false;
    for (const auto& p : it->second.parents) q.push_back(p);

    while (!q.empty()){
        Key u = q.front(); q.pop_front();
        if (!seen.insert(u).second) continue;
        auto i2 = map_.find(u);
        if (i2 == map_.end()) continue; // parent might have left; ignore
        cnt++;
        bytes += i2->second.size_bytes;
        for (const auto& pp : i2->second.parents) q.push_back(pp);
        if (cnt > 4096) break; // sanity cap
    }
    return true;
}
bool Mempool::compute_descendant_stats(const Key& root, size_t& cnt, size_t& bytes) const {
    cnt = 0; bytes = 0;
    std::unordered_set<Key> seen;
    std::deque<Key> q;
    q.push_back(root);
    while (!q.empty()){
        Key u = q.front(); q.pop_front();
        auto it = map_.find(u);
        if (it == map_.end()) continue;
        for (const auto& ch : it->second.children) {
            if (!seen.insert(ch).second) continue;
            auto c2 = map_.find(ch);
            if (c2 == map_.end()) continue;
            cnt++;
            bytes += c2->second.size_bytes;
            q.push_back(ch);
            if (cnt > 4096) break;
        }
        if (cnt > 4096) break;
    }
    return true;
}

void Mempool::link_child_to_parents(const Key& child, const std::vector<TxIn>& vin){
    auto cit = map_.find(child);
    if (cit == map_.end()) return;
    for (const auto& in : vin) {
        Key pk = k(in.prev.txid);
        auto pit = map_.find(pk);
        if (pit != map_.end()) {
            cit->second.parents.insert(pk);
            pit->second.children.insert(child);
        }
    }
    // Recompute ancestor/descendant aggregates
    size_t ac=0, ab=0, dc=0, db=0;
    compute_ancestor_stats(child, ac, ab);
    compute_descendant_stats(child, dc, db);
    cit->second.ancestor_count = ac;
    cit->second.ancestor_size  = ab;
    cit->second.descendant_count = dc;
    cit->second.descendant_size  = db;
}

void Mempool::unlink_entry(const Key& kk){
    auto it = map_.find(kk);
    if (it == map_.end()) return;

    // CRITICAL FIX: Remove spent outputs when transaction is removed
    for (const auto& in : it->second.tx.vin) {
        std::string input_key = key_from_vec(in.prev.txid) + ":" + std::to_string(in.prev.vout);
        spent_outputs_.erase(input_key);
    }

    // Remove child link from all parents
    for (const auto& pk : it->second.parents) {
        auto pit = map_.find(pk);
        if (pit != map_.end()) pit->second.children.erase(kk);
    }
    // Remove parent link from all children
    for (const auto& ck : it->second.children) {
        auto cit = map_.find(ck);
        if (cit != map_.end()) cit->second.parents.erase(kk);
    }
}

bool Mempool::enforce_limits_and_insert(const Transaction& tx, uint64_t fee, std::string& err){
    Key kk = k(tx.txid());
    if (map_.find(kk) != map_.end()) return true; // already in

    size_t sz = est_tx_size(tx);
    // Build entry
    MempoolEntry e;
    e.tx = tx;
    e.size_bytes = sz;
    e.fee = fee;
    e.fee_rate = sz ? (double)fee / (double)sz : 0.0;
    e.added_ms = now_ms();

    // CRITICAL FIX: Track spent outputs for double-spend detection
    std::vector<std::string> spent_keys;
    for (const auto& in : tx.vin) {
        std::string input_key = key_from_vec(in.prev.txid) + ":" + std::to_string(in.prev.vout);
        spent_keys.push_back(input_key);
        spent_outputs_.insert(input_key);
    }

    // Temporarily stage it to compute ancestry limits
    map_.emplace(kk, std::move(e));
    total_bytes_ += sz;

    link_child_to_parents(kk, tx.vin);

    // Enforce ancestor/descendant limits
    size_t ac=0, ab=0, dc=0, db=0;
    compute_ancestor_stats(kk, ac, ab);
    compute_descendant_stats(kk, dc, db);
    if (ac > MIQ_MEMPOOL_MAX_ANCESTORS) {
        err = "too many ancestors";
        unlink_entry(kk);
        map_.erase(kk);
        total_bytes_ -= sz;
        // CRITICAL FIX: Rollback spent outputs on failure
        for (const auto& sk : spent_keys) spent_outputs_.erase(sk);
        return false;
    }
    if (dc > MIQ_MEMPOOL_MAX_DESCENDANTS) {
        err = "too many descendants";
        unlink_entry(kk);
        map_.erase(kk);
        total_bytes_ -= sz;
        // CRITICAL FIX: Rollback spent outputs on failure
        for (const auto& sk : spent_keys) spent_outputs_.erase(sk);
        return false;
    }

    // Trim pool if needed based on fee rate
    if (total_bytes_ > MIQ_MEMPOOL_MAX_BYTES) {
        evict_lowest_feerate_until(MIQ_MEMPOOL_MAX_BYTES);
        if (total_bytes_ > MIQ_MEMPOOL_MAX_BYTES) {
            // Couldn't make space (fee too low)
            err = "mempool full (low feerate)";
            unlink_entry(kk);
            map_.erase(kk);
            total_bytes_ -= sz;
            // CRITICAL FIX: Rollback spent outputs on failure
            for (const auto& sk : spent_keys) spent_outputs_.erase(sk);
            return false;
        }
    }

    return true;
}

// CRITICAL FIX: Maximum transaction size limit
static constexpr size_t MIQ_MAX_TX_SIZE = 4 * 1024 * 1024; // 4 MiB

// Generic accept
bool Mempool::accept(const Transaction& tx, const UTXOView& utxo, uint32_t height, std::string& err){
    std::lock_guard<std::recursive_mutex> lk(mtx_);  // CRITICAL FIX: Thread safety
    (void)height; // reserved for future height-based rules

    // Quick dup check
    if (exists(tx.txid())) return true;

    // CRITICAL FIX: Validate transaction size before expensive operations
    const size_t sz = est_tx_size(tx);
    if (sz > MIQ_MAX_TX_SIZE) {
        err = "transaction too large";
        return false;
    }

    // Calculate fee; if missing inputs, store as orphan
    uint64_t fee = 0;
    std::string terr;
    if (!validate_inputs_and_calc_fee(tx, utxo, fee, terr)) {
        if (terr.empty()) {
            // Orphan path: cache and index by missing parents
            add_orphan(tx);
            return true; // not a hard reject
        }
        err = terr;
        return false;
    }

    // Fee sanity
    if (fee > (uint64_t)MAX_MONEY) { err="fee>MAX_MONEY"; return false; }

    // Min relay fee policy (no behavior change if MIN_RELAY_FEE_RATE isn't defined)
    const uint64_t minfee = min_fee_for_size_bytes(sz);
    if (fee < minfee) { err = "insufficient fee"; return false; }

    if (!enforce_limits_and_insert(tx, fee, err)) return false;

    // Accepting a tx may unblock orphans
    try_promote_orphans_depending_on(k(tx.txid()), utxo, height);
    return true;
}

// Overload for UTXOSet to keep existing call sites compiling
struct UTXOAdapter : public UTXOView {
    const UTXOSet& u;
    explicit UTXOAdapter(const UTXOSet& uu) : u(uu) {}
    bool get(const std::vector<uint8_t>& txid, uint32_t vout, UTXOEntry& out) const override {
        return u.get(txid, vout, out);
    }
};
bool Mempool::accept(const Transaction& tx, const UTXOSet& utxo, uint32_t height, std::string& err){
    UTXOAdapter a(utxo);
    return accept(tx, static_cast<const UTXOView&>(a), height, err);
}

void Mempool::add_orphan(const Transaction& tx){
    Key ck = k(tx.txid());
    if (orphans_.find(ck) != orphans_.end()) return;

    // CRITICAL FIX: Enforce orphan pool limits to prevent DoS
    size_t tx_size = est_tx_size(tx);

    // Check count limit
    if (orphans_.size() >= MAX_ORPHANS) {
        // Evict oldest orphan (FIFO-ish: just remove the first one)
        if (!orphans_.empty()) {
            auto oldest = orphans_.begin();
            size_t old_size = est_tx_size(oldest->second);
            // Clean up waiting_on_ entries for the evicted orphan
            for (const auto& in : oldest->second.vin) {
                Key pk = k(in.prev.txid);
                auto wit = waiting_on_.find(pk);
                if (wit != waiting_on_.end()) {
                    wit->second.erase(oldest->first);
                    if (wit->second.empty()) waiting_on_.erase(wit);
                }
            }
            orphan_bytes_ -= old_size;
            orphans_.erase(oldest);
        }
    }

    // Check byte limit
    while (orphan_bytes_ + tx_size > MAX_ORPHAN_BYTES && !orphans_.empty()) {
        auto oldest = orphans_.begin();
        size_t old_size = est_tx_size(oldest->second);
        // Clean up waiting_on_ entries
        for (const auto& in : oldest->second.vin) {
            Key pk = k(in.prev.txid);
            auto wit = waiting_on_.find(pk);
            if (wit != waiting_on_.end()) {
                wit->second.erase(oldest->first);
                if (wit->second.empty()) waiting_on_.erase(wit);
            }
        }
        orphan_bytes_ -= old_size;
        orphans_.erase(oldest);
    }

    // If still over limit after evictions, reject this orphan
    if (orphan_bytes_ + tx_size > MAX_ORPHAN_BYTES) {
        return; // Silently drop - this is acceptable for orphans
    }

    orphans_.emplace(ck, tx);
    orphan_bytes_ += tx_size;

    for (const auto& in : tx.vin){
        Key pk = k(in.prev.txid);
        waiting_on_[pk].insert(ck);
    }
}

void Mempool::remove_orphan(const Key& ck){
    auto it = orphans_.find(ck);
    if (it == orphans_.end()) return;

    // CRITICAL FIX: Track orphan bytes when removing
    size_t tx_size = est_tx_size(it->second);
    if (orphan_bytes_ >= tx_size) {
        orphan_bytes_ -= tx_size;
    } else {
        orphan_bytes_ = 0; // Safety: prevent underflow
    }

    for (const auto& in : it->second.vin){
        Key pk = k(in.prev.txid);
        auto wit = waiting_on_.find(pk);
        if (wit != waiting_on_.end()){
            wit->second.erase(ck);
            if (wit->second.empty()) waiting_on_.erase(wit);
        }
    }
    orphans_.erase(it);
}

void Mempool::try_promote_orphans_depending_on(const Key& parent, const UTXOView& utxo, uint32_t height){
    auto wit = waiting_on_.find(parent);
    if (wit == waiting_on_.end()) return;

    // Copy to avoid iterator invalidation if we mutate maps
    std::vector<Key> cands(wit->second.begin(), wit->second.end());
    // Clear the waiting list for this parent (children may re-register if still missing other inputs)
    waiting_on_.erase(wit);

    for (const auto& ck : cands){
        auto oit = orphans_.find(ck);
        if (oit == orphans_.end()) continue;

        // CRITICAL FIX: Copy the transaction before removing from orphan pool
        // This prevents the orphan from being skipped in add_orphan() due to
        // the exists-in-orphans check, allowing it to be re-added with updated
        // waiting_on_ entries if it still has missing inputs.
        Transaction orphan_tx = oit->second;

        // Remove from orphan pool BEFORE attempting to accept
        // This is essential because accept() -> add_orphan() checks if already exists
        remove_orphan(ck);

        std::string err;
        if (accept(orphan_tx, utxo, height, err)) {
            // Successfully promoted to main mempool (or re-added as orphan with new waiting_on_ entries)
            // Nothing more to do
        } else if (!err.empty()) {
            // Hard rejected with specific error - transaction is invalid, already removed
            // Log for debugging if needed
        }
        // If err.empty(), accept() already added it back to orphans with updated waiting_on_
    }
}

void Mempool::evict_lowest_feerate_until(size_t target_bytes){
    if (total_bytes_ <= target_bytes) return;

    // Build a min-heap by fee rate
    struct Item { double fr; Key k; size_t sz; };
    auto cmp = [](const Item& a, const Item& b){ return a.fr > b.fr; };
    std::priority_queue<Item, std::vector<Item>, decltype(cmp)> pq(cmp);

    for (const auto& kv : map_) {
        pq.push(Item{kv.second.fee_rate, kv.first, kv.second.size_bytes});
    }

    // Evict until under target
    while (total_bytes_ > target_bytes && !pq.empty()){
        auto it = map_.find(pq.top().k);
        pq.pop();
        if (it == map_.end()) continue; // already evicted by linkage cascade

        // Prefer evicting leaf descendants first to reduce churn
        if (!it->second.children.empty()) {
            // Requeue with slight penalty to try others first
            pq.push(Item{it->second.fee_rate * 1.01, it->first, it->second.size_bytes});
            continue;
        }

        // Unlink and erase
        unlink_entry(it->first);
        total_bytes_ -= it->second.size_bytes;
        map_.erase(it);
    }
}

void Mempool::trim_to_size(size_t max_bytes){
    std::lock_guard<std::recursive_mutex> lk(mtx_);  // CRITICAL FIX: Thread safety
    if (total_bytes_ <= max_bytes) return;
    evict_lowest_feerate_until(max_bytes);
}

void Mempool::maintenance(){
    std::lock_guard<std::recursive_mutex> lk(mtx_);  // CRITICAL FIX: Thread safety
    // Expire very old entries
    int64_t cutoff = now_ms() - (int64_t)MIQ_MEMPOOL_TX_EXPIRY_SECS * 1000;
    std::vector<Key> expired;
    for (const auto& kv : map_) {
        if (kv.second.added_ms < cutoff) expired.push_back(kv.first);
    }
    for (const auto& kx : expired) {
        unlink_entry(kx);
        total_bytes_ -= map_[kx].size_bytes;
        map_.erase(kx);
    }
    // Trim to size (in case)
    evict_lowest_feerate_until(MIQ_MEMPOOL_MAX_BYTES);
}

void Mempool::on_block_connect(const Block& b){
    std::lock_guard<std::recursive_mutex> lk(mtx_);  // CRITICAL FIX: Thread safety
    // Remove all txs that were confirmed and any in-mempool conflicts
    // (coinbase is never in mempool)
    for (size_t i=1; i<b.txs.size(); ++i){
        const auto& tx = b.txs[i];
        Key kk = k(tx.txid());
        // Remove this tx if present
        auto it = map_.find(kk);
        if (it != map_.end()) {
            unlink_entry(kk);
            total_bytes_ -= it->second.size_bytes;
            map_.erase(it);
        }
        // Remove any mempool txs that spend the same inputs (now conflicting with the block)
        for (const auto& in : tx.vin){
            // conservative scan for conflicts
            std::vector<Key> victims;
            for (const auto& kv : map_){
                for (const auto& cin : kv.second.tx.vin){
                    if (cin.prev.txid == in.prev.txid && cin.prev.vout == in.prev.vout) {
                        victims.push_back(kv.first);
                        break;
                    }
                }
            }
            for (const auto& r : victims){
                unlink_entry(r);
                total_bytes_ -= map_[r].size_bytes;
                map_.erase(r);
            }
        }
    }
}

void Mempool::on_block_disconnect(const Block& b, const UTXOView& utxo, uint32_t height){
    std::lock_guard<std::recursive_mutex> lk(mtx_);  // CRITICAL FIX: Thread safety
    // Try to re-accept all non-coinbase txs in block order
    for (size_t i=1; i<b.txs.size(); ++i){
        const auto& tx = b.txs[i];
        std::string err;
        (void)accept(tx, utxo, height, err); // if orphan/hard-reject, accept() handles it
    }
}
void Mempool::on_block_disconnect(const Block& b, const UTXOSet& utxo, uint32_t height){
    UTXOAdapter a(utxo);
    on_block_disconnect(b, static_cast<const UTXOView&>(a), height);
}

std::vector<Transaction> Mempool::collect(size_t max) const{
    std::lock_guard<std::recursive_mutex> lk(mtx_);  // CRITICAL FIX: Thread safety
    // Parents-first, highest feerate preference.
    // Strategy: greedy passes—each pass select the best-fee tx whose parents
    // are either not in mempool or already selected.
    struct NodeRef {
        const MempoolEntry* e;
    };
    std::vector<NodeRef> nodes;
    nodes.reserve(map_.size());
    for (const auto& kv : map_) nodes.push_back(NodeRef{&kv.second});

    // Sort by fee rate (desc)
    std::sort(nodes.begin(), nodes.end(), [](const NodeRef& a, const NodeRef& b){
        if (a.e->fee_rate == b.e->fee_rate) return a.e->size_bytes < b.e->size_bytes;
        return a.e->fee_rate > b.e->fee_rate;
    });

    std::unordered_set<std::string> selected_keys;
    std::vector<Transaction> out; out.reserve(std::min(max, nodes.size()));
    bool progress = true;

    while (out.size() < max && progress) {
        progress = false;
        for (const auto& n : nodes) {
            if (out.size() >= max) break;
            const auto& e = *n.e;
            const std::string myk = key_from_vec(e.tx.txid());
            if (selected_keys.count(myk)) continue;

            bool parents_ok = true;
            for (const auto& pk : e.parents) {
                // allow if parent not in mempool (spends confirmed UTXO) or already selected
                if (map_.find(pk) != map_.end() && !selected_keys.count(pk)) {
                    parents_ok = false; break;
                }
            }
            if (!parents_ok) continue;

            // select
            out.push_back(e.tx);
            selected_keys.insert(myk);
            progress = true;
        }
    }
    return out;
}

// === SFINAE targets ==========================================================
// 1) snapshot(out): return parents-first, feerate-desc full list (no size cap)
void Mempool::snapshot(std::vector<Transaction>& out) const {
    out.clear();
    // Reuse collect(max) to preserve ordering guarantees; pass full size.
    const size_t n = map_.size();
    std::vector<Transaction> v = collect(n == 0 ? 0 : n);
    out.swap(v);
}

// 2) collect_for_block(out, max_bytes): parents-first, feerate-desc with size cap
void Mempool::collect_for_block(std::vector<Transaction>& out, size_t max_bytes) const {
    out.clear();

    // Build sorted node view by feerate desc (tie-break: smaller size first)
    struct NodeRef { const MempoolEntry* e; };
    std::vector<NodeRef> nodes;
    nodes.reserve(map_.size());
    for (const auto& kv : map_) nodes.push_back(NodeRef{ &kv.second });

    std::sort(nodes.begin(), nodes.end(), [](const NodeRef& a, const NodeRef& b){
        if (a.e->fee_rate == b.e->fee_rate) return a.e->size_bytes < b.e->size_bytes;
        return a.e->fee_rate > b.e->fee_rate;
    });

    std::unordered_set<std::string> selected_keys;
    size_t used = 0;
    bool progress = true;

    while (progress) {
        progress = false;
        for (const auto& n : nodes) {
            const auto& e = *n.e;
            const std::string myk = key_from_vec(e.tx.txid());
            if (selected_keys.count(myk)) continue;

            // parents must be either not in mempool or already selected
            bool parents_ok = true;
            for (const auto& pk : e.parents) {
                if (map_.find(pk) != map_.end() && !selected_keys.count(pk)) {
                    parents_ok = false; break;
                }
            }
            if (!parents_ok) continue;

            const size_t sz = e.size_bytes;
            if (sz > max_bytes) continue; // single tx larger than cap remainder; skip
            if (used > max_bytes - sz) continue; // avoid overflow and respect cap

            out.push_back(e.tx);
            selected_keys.insert(myk);
            used += sz;
            progress = true;

            if (used >= max_bytes) return; // filled
        }
        // If no progress and still have space, we're done.
    }
}

// ============================================================================

std::vector<std::vector<uint8_t>> Mempool::txids() const{
    std::vector<std::vector<uint8_t>> v;
    v.reserve(map_.size());
    for (const auto& kv : map_){
        v.push_back(kv.second.tx.txid());
    }
    return v;
}

// =============================================================================
// PRODUCTION-GRADE IMPLEMENTATIONS
// =============================================================================

double Mempool::estimate_fee(int target_blocks) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (map_.empty()) {
        // Fallback to minimum when mempool is empty
        return static_cast<double>(MIQ_MEMPOOL_MIN_RELAY_FEE);
    }

    // Collect all fee rates
    std::vector<double> rates;
    rates.reserve(map_.size());
    for (const auto& kv : map_) {
        rates.push_back(kv.second.fee_rate);
    }
    std::sort(rates.begin(), rates.end());

    // Estimate based on target blocks
    // Higher urgency = higher percentile
    double percentile;
    if (target_blocks <= 1) {
        percentile = 0.95;  // Top 5% for next block
    } else if (target_blocks <= 3) {
        percentile = 0.80;  // Top 20% for 2-3 blocks
    } else if (target_blocks <= 6) {
        percentile = 0.60;  // Top 40% for 4-6 blocks
    } else {
        percentile = 0.40;  // Top 60% for 6+ blocks
    }

    size_t idx = static_cast<size_t>(rates.size() * percentile);
    if (idx >= rates.size()) idx = rates.size() - 1;

    // Apply minimum floor
    double estimate = rates[idx];
    return std::max(estimate, static_cast<double>(MIQ_MEMPOOL_MIN_RELAY_FEE));
}

FeeEstimateBucket Mempool::get_fee_estimates() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    FeeEstimateBucket bucket;
    bucket.high_priority = estimate_fee(1);
    bucket.medium_priority = estimate_fee(3);
    bucket.low_priority = estimate_fee(6);
    bucket.last_updated_ms = now_ms();
    return bucket;
}

void Mempool::update_fee_estimates(uint32_t height) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);
    (void)height;  // Could be used for historical tracking
    fee_estimates_ = get_fee_estimates();
}

bool Mempool::is_rbf_candidate(const Transaction& tx) const {
    // Check if any input signals RBF (sequence < 0xFFFFFFFE)
    for (const auto& in : tx.vin) {
        (void)in;  // Reserved for future RBF signaling check
        // Check sequence number for RBF signaling
        // In our simple format, we use a convention where replaceable is signaled
        // For now, all transactions are considered replaceable if RBF is enabled
    }
    return MIQ_MEMPOOL_RBF_ENABLED != 0;
}

bool Mempool::validate_rbf_rules(const Transaction& new_tx, const MempoolEntry& old_entry,
                                  uint64_t new_fee, std::string& err) const {
    // Rule 1: Must pay higher absolute fee
    if (new_fee <= old_entry.fee) {
        err = "RBF: insufficient fee increase";
        return false;
    }

    // Rule 2: Must pay higher fee rate
    size_t new_size = est_tx_size(new_tx);
    double new_rate = new_size ? static_cast<double>(new_fee) / static_cast<double>(new_size) : 0.0;

    // Must increase by at least incremental relay fee
    double min_new_rate = old_entry.fee_rate + MIQ_MEMPOOL_INCREMENTAL_FEE;
    if (new_rate < min_new_rate) {
        err = "RBF: insufficient fee rate increase";
        return false;
    }

    // Rule 3: Additional fee must pay for its own relay
    uint64_t fee_increase = new_fee - old_entry.fee;
    uint64_t min_additional_fee = new_size * MIQ_MEMPOOL_MIN_RELAY_FEE;
    if (fee_increase < min_additional_fee) {
        err = "RBF: additional fee too low for relay";
        return false;
    }

    // Rule 4: Cannot replace more than 100 transactions
    if (old_entry.descendant_count > 100) {
        err = "RBF: too many descendants to replace";
        return false;
    }

    return true;
}

bool Mempool::accept_replacement(const Transaction& tx, const UTXOView& utxo,
                                  uint32_t height, std::string& err) {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    if (!MIQ_MEMPOOL_RBF_ENABLED) {
        err = "RBF disabled";
        return false;
    }

    // Find conflicting transactions
    std::vector<Key> conflicts;
    for (const auto& in : tx.vin) {
        std::string input_key = key_from_vec(in.prev.txid) + ":" + std::to_string(in.prev.vout);
        if (spent_outputs_.count(input_key)) {
            // Find which transaction spends this
            for (const auto& kv : map_) {
                for (const auto& existing_in : kv.second.tx.vin) {
                    if (existing_in.prev.txid == in.prev.txid &&
                        existing_in.prev.vout == in.prev.vout) {
                        conflicts.push_back(kv.first);
                        break;
                    }
                }
            }
        }
    }

    if (conflicts.empty()) {
        // No conflicts, use normal accept path
        return accept(tx, utxo, height, err);
    }

    // Calculate new transaction fee
    uint64_t new_fee = 0;
    std::string fee_err;
    if (!validate_inputs_and_calc_fee(tx, utxo, new_fee, fee_err)) {
        err = fee_err.empty() ? "cannot calculate fee" : fee_err;
        return false;
    }

    // Validate RBF rules against all conflicts
    for (const auto& conflict_key : conflicts) {
        auto it = map_.find(conflict_key);
        if (it == map_.end()) continue;

        if (!validate_rbf_rules(tx, it->second, new_fee, err)) {
            return false;
        }
    }

    // Remove conflicted transactions and their descendants
    for (const auto& conflict_key : conflicts) {
        auto it = map_.find(conflict_key);
        if (it == map_.end()) continue;

        // Collect descendants to remove
        std::vector<Key> to_remove;
        to_remove.push_back(conflict_key);

        std::deque<Key> q;
        for (const auto& child : it->second.children) q.push_back(child);

        std::unordered_set<std::string> seen;
        while (!q.empty()) {
            Key ck = q.front();
            q.pop_front();
            if (!seen.insert(ck).second) continue;

            auto cit = map_.find(ck);
            if (cit == map_.end()) continue;

            to_remove.push_back(ck);
            for (const auto& child : cit->second.children) {
                q.push_back(child);
            }
        }

        // Remove all
        for (const auto& rk : to_remove) {
            auto rit = map_.find(rk);
            if (rit == map_.end()) continue;
            unlink_entry(rk);
            total_bytes_ -= rit->second.size_bytes;
            map_.erase(rit);
        }
    }

    // Insert the replacement
    return enforce_limits_and_insert(tx, new_fee, err);
}

void Mempool::update_cpfp_scores() {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    // Update modified fee rates considering CPFP
    for (auto& kv : map_) {
        uint64_t total_fee = kv.second.fee;
        size_t total_size = kv.second.size_bytes;

        // Add ancestor fees and sizes
        std::unordered_set<Key> visited;
        std::deque<Key> q;
        for (const auto& pk : kv.second.parents) q.push_back(pk);

        while (!q.empty()) {
            Key pk = q.front();
            q.pop_front();
            if (!visited.insert(pk).second) continue;

            auto pit = map_.find(pk);
            if (pit == map_.end()) continue;

            total_fee += pit->second.fee;
            total_size += pit->second.size_bytes;

            for (const auto& ppk : pit->second.parents) {
                q.push_back(ppk);
            }
        }

        kv.second.ancestor_fee = total_fee - kv.second.fee;
        kv.second.modified_fee_rate = total_size ?
            static_cast<double>(total_fee) / static_cast<double>(total_size) : 0.0;
    }
}

double Mempool::get_package_fee_rate(const std::vector<uint8_t>& txid) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    auto it = map_.find(k(txid));
    if (it == map_.end()) return 0.0;

    return it->second.modified_fee_rate;
}

Mempool::MempoolStats Mempool::get_stats() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    MempoolStats stats;
    stats.tx_count = map_.size();
    stats.bytes_used = total_bytes_;
    stats.orphan_count = orphans_.size();
    stats.orphan_bytes = orphan_bytes_;

    if (map_.empty()) return stats;

    std::vector<double> rates;
    rates.reserve(map_.size());
    uint64_t total_fees = 0;
    int64_t total_age = 0;
    int64_t now = now_ms();

    double min_rate = std::numeric_limits<double>::max();
    double max_rate = 0.0;

    for (const auto& kv : map_) {
        rates.push_back(kv.second.fee_rate);
        total_fees += kv.second.fee;
        total_age += (now - kv.second.added_ms);

        if (kv.second.fee_rate < min_rate) min_rate = kv.second.fee_rate;
        if (kv.second.fee_rate > max_rate) max_rate = kv.second.fee_rate;
    }

    stats.min_fee_rate = min_rate;
    stats.max_fee_rate = max_rate;
    stats.total_fees = total_fees;

    // Average
    double sum = 0.0;
    for (double r : rates) sum += r;
    stats.avg_fee_rate = sum / rates.size();

    // Median
    std::sort(rates.begin(), rates.end());
    stats.median_fee_rate = rates[rates.size() / 2];

    stats.avg_age_ms = total_age / static_cast<int64_t>(map_.size());

    return stats;
}

bool Mempool::get_transaction(const std::vector<uint8_t>& txid, Transaction& out) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    auto it = map_.find(k(txid));
    if (it == map_.end()) return false;

    out = it->second.tx;
    return true;
}

bool Mempool::has_spent_input(const std::vector<uint8_t>& txid, uint32_t vout) const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    std::string input_key = key_from_vec(txid) + ":" + std::to_string(vout);
    return spent_outputs_.count(input_key) > 0;
}

size_t Mempool::dynamic_memory_usage() const {
    std::lock_guard<std::recursive_mutex> lk(mtx_);

    size_t usage = 0;

    // Map entries
    for (const auto& kv : map_) {
        usage += sizeof(kv);
        usage += kv.first.capacity();
        usage += kv.second.size_bytes;  // Approximate tx size
        usage += kv.second.parents.size() * 32;
        usage += kv.second.children.size() * 32;
    }

    // Spent outputs tracking
    usage += spent_outputs_.size() * 48;  // Approximate

    // Orphans
    usage += orphan_bytes_;

    // Waiting_on index
    for (const auto& kv : waiting_on_) {
        usage += kv.first.capacity();
        usage += kv.second.size() * 32;
    }

    return usage;
}

}  // namespace miq
