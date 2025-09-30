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

// Helper: compute a minimal relay fee if a global policy macro is defined.
// If MIN_RELAY_FEE_RATE is not defined globally, this returns 0 (no floor change).
static inline uint64_t min_fee_for_size_bytes(size_t sz){
#ifdef MIN_RELAY_FEE_RATE
    uint64_t kb = (uint64_t)((sz + 999) / 1000);
    if (kb == 0) kb = 1;
    return kb * (uint64_t)MIN_RELAY_FEE_RATE;
#else
    (void)sz;
    return 0;
#endif
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
        return false;
    }
    if (dc > MIQ_MEMPOOL_MAX_DESCENDANTS) {
        err = "too many descendants";
        unlink_entry(kk);
        map_.erase(kk);
        total_bytes_ -= sz;
        return false;
    }

    // Trim pool if needed based on fee rate
    if (total_bytes_ > MIQ_MEMPOOL_MAX_BYTES) {
        evict_lowest_feerate_until(MIQ_MEMPOOL_MAX_BYTES);
        if (total_bytes_ > MIQ_MEMPOOL_MAX_BYTES) {
            // Couldn’t make space (fee too low)
            err = "mempool full (low feerate)";
            unlink_entry(kk);
            map_.erase(kk);
            total_bytes_ -= sz;
            return false;
        }
    }

    return true;
}

// Generic accept
bool Mempool::accept(const Transaction& tx, const UTXOView& utxo, uint32_t height, std::string& err){
    (void)height; // reserved for future height-based rules

    // Quick dup check
    if (exists(tx.txid())) return true;

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
    const size_t sz = est_tx_size(tx);
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
    orphans_.emplace(ck, tx);
    for (const auto& in : tx.vin){
        Key pk = k(in.prev.txid);
        waiting_on_[pk].insert(ck);
    }
}

void Mempool::remove_orphan(const Key& ck){
    auto it = orphans_.find(ck);
    if (it == orphans_.end()) return;
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
        std::string err;
        if (accept(oit->second, utxo, height, err)) {
            remove_orphan(ck);
        } else {
            // Hard rejected, drop it
            remove_orphan(ck);
        }
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
    if (total_bytes_ <= max_bytes) return;
    evict_lowest_feerate_until(max_bytes);
}

void Mempool::maintenance(){
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
    trim_to_size(MIQ_MEMPOOL_MAX_BYTES);
}

void Mempool::on_block_connect(const Block& b){
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

std::vector<std::vector<uint8_t>> Mempool::txids() const{
    std::vector<std::vector<uint8_t>> v;
    v.reserve(map_.size());
    for (const auto& kv : map_){
        v.push_back(kv.second.tx.txid());
    }
    return v;
}

}
