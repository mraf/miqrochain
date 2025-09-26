#include "chain.h"
#include "sha256.h"
#include "merkle.h"
#include "hasher.h"
#include "log.h"
#include "hash160.h"
#include "crypto/ecdsa_iface.h"
#include "constants.h"     // BLOCK_TIME_SECS, GENESIS_BITS, etc.
#include "difficulty.h"    // lwma_next_bits
#include <sstream>
#include <unordered_set>

// === Added includes for security checks ===
#include <algorithm>       // std::any_of
#include <chrono>          // future-time bound
#include <cstring>         // std::memcmp

// after your existing includes in chain.cpp
#ifndef MAX_TX_SIZE
#define MIQ_FALLBACK_MAX_TX_SIZE (100u * 1024u) // 100 KiB default
#else
#define MIQ_FALLBACK_MAX_TX_SIZE (MAX_TX_SIZE)
#endif


namespace miq {

// === Added: local constants (non-breaking) ===
static constexpr size_t MAX_BLOCK_SIZE_LOCAL = 1 * 1024 * 1024; // 1 MiB

// === Added: compact bits -> 32-byte big-endian target, and hash <= target check ===
static inline void bits_to_target_be(uint32_t bits, uint8_t out[32]) {
    std::memset(out, 0, 32);
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) { return; } // invalid -> zero target (will fail compare)

    if (exp <= 3) {
        // Right shift mantissa
        uint32_t mant2 = mant >> (8 * (3 - exp));
        out[29] = uint8_t((mant2 >> 16) & 0xff);
        out[30] = uint8_t((mant2 >> 8)  & 0xff);
        out[31] = uint8_t((mant2 >> 0)  & 0xff);
    } else {
        // Place mantissa at position (32 - exp)
        int pos = int(32) - int(exp);
        if (pos < 0) {
            // Extremely large exponent -> target overflows 256 bits -> treat as max target
            out[0] = 0xff; out[1] = 0xff; out[2] = 0xff; // effectively "always true"
            return;
        }
        if (pos > 29) pos = 29; // defensive clamp
        out[pos + 0] = uint8_t((mant >> 16) & 0xff);
        out[pos + 1] = uint8_t((mant >> 8)  & 0xff);
        out[pos + 2] = uint8_t((mant >> 0)  & 0xff);
    }
}

static inline bool meets_target_be(const std::vector<uint8_t>& hash32, uint32_t bits) {
    if (hash32.size() != 32) return false;
    uint8_t target[32];
    bits_to_target_be(bits, target);
    // Interpret both as big-endian 256-bit integers: hash <= target
    return std::memcmp(hash32.data(), target, 32) <= 0;
}

// =====================================================================

bool Chain::open(const std::string& dir){
    bool ok = storage_.open(dir) && utxo_.open(dir);
    if(!ok) return false;
    (void)load_state();
    return true;
}

bool Chain::save_state(){
    std::vector<uint8_t> b;
    auto P64=[&](uint64_t x){ for(int i=0;i<8;i++) b.push_back((x>>(i*8))&0xff); };
    auto P32=[&](uint32_t x){ for(int i=0;i<4;i++) b.push_back((x>>(i*8))&0xff); };

    b.insert(b.end(), tip_.hash.begin(), tip_.hash.end());
    P64(tip_.height);
    P64((uint64_t)tip_.time);
    P32(tip_.bits);
    P64(tip_.issued);

    return storage_.write_state(b);
}

bool Chain::load_state(){
    std::vector<uint8_t> b;

    if(!storage_.read_state(b)){
        tip_.hash = std::vector<uint8_t>(32, 0);
        tip_.height = 0;
        tip_.time = 0;
        tip_.bits = 0;
        tip_.issued = 0;
        return true;
    }

    if(b.size() < 32 + 8 + 8 + 4 + 8){
        tip_.hash = std::vector<uint8_t>(32, 0);
        tip_.height = 0;
        tip_.time = 0;
        tip_.bits = 0;
        tip_.issued = 0;
        return true;
    }

    size_t i = 0;
    tip_.hash.assign(b.begin() + i, b.begin() + i + 32); i += 32;

    tip_.height = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.height |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    tip_.time = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.time |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    tip_.bits = b[i] | (b[i+1] << 8) | (b[i+2] << 16) | (b[i+3] << 24);
    i += 4;

    tip_.issued = 0;
    for (int k = 0; k < 8; ++k) {
        tip_.issued |= (uint64_t)b[i + k] << (k * 8);
    }
    i += 8;

    return true;
}

uint64_t Chain::subsidy_for_height(uint64_t h) const {
    uint64_t halv = h / HALVING_INTERVAL;
    if(halv >= 64) return 0;
    return INITIAL_SUBSIDY >> halv;
}

bool Chain::init_genesis(const Block& g){
    if(tip_.hash != std::vector<uint8_t>(32,0)) return true;

    std::vector<std::vector<uint8_t>> txids;
    for(const auto& tx : g.txs) txids.push_back(tx.txid());
    auto mr = merkle_root(txids);
    if(mr != g.header.merkle_root) return false;

    storage_.append_block(ser_block(g), g.block_hash());

    // Add coinbase UTXOs and compute total issued at height 0
    const auto& cb = g.txs[0];
    uint64_t cb_sum = 0;
    for(size_t i=0;i<cb.vout.size();++i){
        UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, 0, true};
        utxo_.add(cb.txid(), (uint32_t)i, e);
        cb_sum += cb.vout[i].value;
    }

    tip_ = Tip{0, g.block_hash(), g.header.bits, g.header.time, cb_sum};
    index_.reset(tip_.hash, tip_.time, tip_.bits);
    save_state();
    return true;
}

bool Chain::verify_block(const Block& b, std::string& err) const{
    // Prev-hash must point to current tip (linear chain for now)
    if(b.header.prev_hash != tip_.hash){ err="bad prev hash"; return false; }

    // ---- Median-Time-Past (median of last up to 11 blocks) ----
    auto hdrs = last_headers(11);
    int64_t mtp = tip_.time;
    if (!hdrs.empty()) {
        std::vector<int64_t> ts; ts.reserve(hdrs.size());
        for (auto& p : hdrs) ts.push_back(p.first);
        std::sort(ts.begin(), ts.end());
        mtp = ts[ts.size()/2];
    }
    if (b.header.time <= mtp) { err = "time <= MTP"; return false; }

    // Future bound
    {
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (b.header.time > now + (int64_t)MAX_TIME_SKEW) { err="time too far in future"; return false; }
    }

    // Merkle must match actual txids
    if (b.txs.empty()){ err="no coinbase"; return false; }
    {
        // also reject duplicate txids (merkle-mutation guard)
        std::unordered_set<std::string> seen;
        std::vector<std::vector<uint8_t>> txids;
        txids.reserve(b.txs.size());
        for (const auto& tx : b.txs) {
            auto id = tx.txid();
            std::string key(reinterpret_cast<const char*>(id.data()), id.size());
            if (!seen.insert(key).second) { err="duplicate txid"; return false; }
            txids.push_back(std::move(id));
        }
        auto mr = merkle_root(txids);
        if(mr != b.header.merkle_root){ err="bad merkle"; return false; }
    }

    // Coinbase shape
    const auto& cb = b.txs[0];
    if (cb.vin.size()!=1 || !cb.vin[0].sig.empty() || !cb.vin[0].pubkey.empty()) { err="bad coinbase"; return false; }
    if (cb.vin[0].prev.txid.size()!=32) { err="bad coinbase prev size"; return false; }
    if (std::any_of(cb.vin[0].prev.txid.begin(), cb.vin[0].prev.txid.end(), [](uint8_t v){ return v!=0; })) { err="bad coinbase prev"; return false; }
    if (cb.vin[0].prev.vout != 0) { err="bad coinbase vout"; return false; }

    // Forbid coinbase-like txs elsewhere; require vin/vout
    for (size_t ti=1; ti<b.txs.size(); ++ti) {
        const auto& tx = b.txs[ti];
        if (tx.vin.empty() || tx.vout.empty()) { err="empty tx"; return false; }
        if (tx.vin.size()==1 && tx.vin[0].prev.vout==0 &&
            tx.vin[0].prev.txid.size()==32 &&
            std::all_of(tx.vin[0].prev.txid.begin(), tx.vin[0].prev.txid.end(), [](uint8_t v){return v==0;})) {
            err="multiple coinbase"; return false;
        }
        // per-tx size cap (DoS)
        auto raw = ser_tx(tx);
        if (raw.size() > MIQ_FALLBACK_MAX_TX_SIZE) { err="tx too large"; return false; }
    }

    // Difficulty bits must match
    {
        auto last = last_headers(90);
        uint32_t expected;
        if (last.size() < 2) expected = last.empty() ? GENESIS_BITS : last.back().second;
        else expected = lwma_next_bits(last, BLOCK_TIME_SECS, GENESIS_BITS);
        if (b.header.bits != expected) { err = "bad bits"; return false; }
    }

    // POW: H(header) <= target(bits)
    if (!meets_target_be(b.block_hash(), b.header.bits)) { err = "bad pow"; return false; }

    // Block raw size cap
    if (ser_block(b).size() > MAX_BLOCK_SIZE_LOCAL) { err = "oversize block"; return false; }

    // ---- Safe math helpers ----
    auto add_u64_safe = [](uint64_t a, uint64_t b, uint64_t& out)->bool { out = a + b; return out >= a; };
    auto leq_max_money = [](uint64_t v)->bool { return v <= (uint64_t)MAX_MONEY; };

    // Track outpoints spent inside this block to prevent intra-block double-spends
    struct Key { std::vector<uint8_t> txid; uint32_t vout; };
    struct KH { size_t operator()(Key const& k) const noexcept {
        size_t h = k.vout * 1315423911u;
        if(!k.txid.empty()){ h ^= (size_t)k.txid.front() * 2654435761u; h ^= (size_t)k.txid.back() * 2246822519u; }
        return h;
    }};
    struct KE { bool operator()(Key const& a, Key const& b) const noexcept { return a.vout==b.vout && a.txid==b.txid; } };
    std::unordered_set<Key, KH, KE> spent_in_block;

    // Sig checks & fees
    auto sigh=[&](const Transaction& t){ Transaction tmp=t; for(auto& i: tmp.vin) i.sig.clear(); return dsha256(ser_tx(tmp)); };

    uint64_t fees = 0;
    for(size_t ti=1; ti<b.txs.size(); ++ti){
        const auto& tx=b.txs[ti];
        uint64_t in=0, out=0, tmp=0;

        for (const auto& o : tx.vout) {
            if (!leq_max_money(o.value)) { err="txout>MAX_MONEY"; return false; }
            if (!add_u64_safe(out, o.value, tmp)) { err="tx out overflow"; return false; }
            out = tmp;
        }
        if (!leq_max_money(out)) { err="sum(out)>MAX_MONEY"; return false; }

        auto hash = sigh(tx);

        for(const auto& inx: tx.vin){
            Key k{inx.prev.txid, inx.prev.vout};
            if (spent_in_block.find(k) != spent_in_block.end()){ err="in-block double-spend"; return false; }
            spent_in_block.insert(k);

            UTXOEntry e;
            if(!utxo_.get(inx.prev.txid, inx.prev.vout, e)){ err="missing utxo"; return false; }
            if(e.coinbase && tip_.height+1 < e.height + COINBASE_MATURITY){ err="immature coinbase"; return false; }
            if(hash160(inx.pubkey)!=e.pkh){ err="pkh mismatch"; return false; }
            if(!crypto::ECDSA::verify(inx.pubkey, hash, inx.sig)){ err="bad signature"; return false; }

            if (!leq_max_money(e.value)) { err="utxo>MAX_MONEY"; return false; }
            if (!add_u64_safe(in, e.value, tmp)) { err="tx in overflow"; return false; }
            in = tmp;
        }
        if (!leq_max_money(in)) { err="sum(in)>MAX_MONEY"; return false; }

        if(out > in){ err="outputs>inputs"; return false; }
        uint64_t fee = in - out;
        if (!leq_max_money(fee)) { err="fee>MAX_MONEY"; return false; }
        if (!add_u64_safe(fees, fee, tmp)) { err="fees overflow"; return false; }
        fees = tmp;
    }

    // Coinbase payout checks
    uint64_t sub = subsidy_for_height(tip_.height+1);
    uint64_t cb_sum = 0, tmp2 = 0;
    for(const auto& o:cb.vout){
        if (!leq_max_money(o.value)) { err="coinbase out>MAX_MONEY"; return false; }
        if (!add_u64_safe(cb_sum, o.value, tmp2)) { err="coinbase overflow"; return false; }
        cb_sum = tmp2;
    }
    if(cb_sum > sub + fees){ err="coinbase too high"; return false; }
    if(!leq_max_money(cb_sum)){ err="coinbase>MAX_MONEY"; return false; }
    if(tip_.issued > (uint64_t)MAX_MONEY - cb_sum){ err="exceeds cap"; return false; }

    return true;
}

bool Chain::submit_block(const Block& b, std::string& err){
    if(!verify_block(b, err)) return false;

    storage_.append_block(ser_block(b), b.block_hash());

    for(size_t ti=1; ti<b.txs.size(); ++ti){
        const auto& tx=b.txs[ti];
        for(const auto& in: tx.vin) utxo_.spend(in.prev.txid, in.prev.vout);
        for(size_t i=0;i<tx.vout.size();++i){
            UTXOEntry e{tx.vout[i].value, tx.vout[i].pkh, tip_.height+1, false};
            utxo_.add(tx.txid(), (uint32_t)i, e);
        }
    }

    const auto& cb=b.txs[0];
    uint64_t cb_sum=0;
    for(size_t i=0;i<cb.vout.size();++i){
        UTXOEntry e{cb.vout[i].value, cb.vout[i].pkh, tip_.height+1, true};
        utxo_.add(cb.txid(), (uint32_t)i, e);
        cb_sum += cb.vout[i].value;
    }

    tip_.height += 1;
    tip_.hash = b.block_hash();
    tip_.bits = b.header.bits;
    tip_.time = b.header.time;
    tip_.issued += cb_sum;

    save_state();
    return true;
}

// Return the last n headers (time,bits) along the canonical chain via storage.
std::vector<std::pair<int64_t,uint32_t>> Chain::last_headers(size_t n) const{
    std::vector<std::pair<int64_t,uint32_t>> v;
    if (tip_.time == 0) return v;

    size_t start = 0;
    if (tip_.height + 1 > n) start = (size_t)(tip_.height + 1 - n);

    for (size_t idx = start; idx <= (size_t)tip_.height; ++idx) {
        Block b;
        if (!get_block_by_index(idx, b)) break;
        v.emplace_back(b.header.time, b.header.bits);
    }
    return v;
}

bool Chain::get_block_by_index(size_t idx, Block& out) const{
    std::vector<uint8_t> raw;
    if(!storage_.read_block_by_index(idx, raw)) return false;
    return deser_block(raw, out);
}

bool Chain::get_block_by_hash(const std::vector<uint8_t>& h, Block& out) const{
    std::vector<uint8_t> raw;
    if(!storage_.read_block_by_hash(h, raw)) return false;
    return deser_block(raw, out);
}

bool Chain::have_block(const std::vector<uint8_t>& h) const{
    std::vector<uint8_t> raw;
    return storage_.read_block_by_hash(h, raw);
}

} // namespace miq
