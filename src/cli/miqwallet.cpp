// MIQ wallet CLI (P2P-only): local HD + SPV UTXO discovery + P2P tx broadcast.
// Default P2P seed: 62.38.73.147:9833
//
// Build deps: hd_wallet, wallet_store, sha256, ripemd160, hash160,
// base58*, hex, serialize, tx, secp256k1, and wallet/p2p_light.*

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <tuple>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <fstream>
#include <random>
#include <cmath>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>

#include "constants.h"
#include "hd_wallet.h"
#include "wallet_store.h"
#include "sha256.h"
#include "hash160.h"
#include "base58check.h"
#include "hex.h"
#include "serialize.h"
#include "tx.h"
#include "block.h"
#include "crypto/ecdsa_iface.h"
#include "wallet/p2p_light.h"

using miq::CHAIN_NAME;
using miq::COIN;

// ----------------- tiny helpers -----------------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}

static uint64_t parse_amount_miqron(const std::string& s){
    if(s.find('.')!=std::string::npos){
        long double v = std::stold(s);
        long double sat = v * (long double)COIN;
        if(sat < 0) throw std::runtime_error("negative");
        return (uint64_t) std::llround(sat);
    } else {
        unsigned long long x = std::stoull(s);
        return (uint64_t)x;
    }
}

static size_t est_size_bytes(size_t nin, size_t nout){ return nin*148 + nout*34 + 10; }
static uint64_t fee_for(size_t nin, size_t nout, uint64_t feerate){
    size_t sz = est_size_bytes(nin, nout);
    uint64_t kb = (uint64_t)((sz + 999) / 1000);
    if(kb==0) kb=1;
    return kb * feerate;
}

// -----------------------------------------------------------------------------
// P2P helpers (broadcast + simple SPV UTXO discovery)
// -----------------------------------------------------------------------------
static bool p2p_broadcast_tx(const std::string& seed_host, const std::string& seed_port,
                             const std::vector<uint8_t>& raw_tx,
                             std::string& err)
{
    miq::P2POpts o;
    o.host = seed_host;
    o.port = seed_port;
    o.user_agent = "/miqwallet-p2p:0.1/";
    miq::P2PLight p2p;
    if(!p2p.connect_and_handshake(o, err)) return false;
    bool ok = p2p.send_tx(raw_tx, err);
    p2p.close();
    return ok;
}

struct UtxoLite {
    std::vector<uint8_t> txid;   // 32
    uint32_t vout;               // index
    uint64_t value;              // in miqron
    std::vector<uint8_t> pkh;    // 20
    uint32_t height;             // block height (0 for mempool)
    bool coinbase{false};
};

// SPV: collect UTXOs for a set of PKHs using only P2P.
// Requires P2PLight: get_best_header, has_compact_filters (stubbed false),
// scan_blocks_with_filters (stubbed false), match_recent_blocks, get_block_by_hash.
static bool spv_collect_utxos(
    const std::string& host, const std::string& port,
    const std::vector<std::vector<uint8_t>>& pkhs,
    uint32_t recent_block_window,
    std::vector<UtxoLite>& out,
    std::string& err)
{
    out.clear();

    // 1) connect + get tip
    miq::P2POpts o; o.host=host; o.port=port; o.user_agent="/miqwallet-spv:0.1/";
    miq::P2PLight p2p;
    if(!p2p.connect_and_handshake(o, err)) return false;

    uint32_t tip_height=0; std::vector<uint8_t> tip_hash;
    if(!p2p.get_best_header(tip_height, tip_hash, err)){ p2p.close(); return false; }

    // 2) find blocks that might contain our PKHs
    std::vector<std::pair<std::vector<uint8_t>, uint32_t>> matched; // (blockhash,height)
    if(p2p.has_compact_filters()){
        if(!p2p.scan_blocks_with_filters(pkhs, tip_height, matched, err)){ p2p.close(); return false; }
    } else {
        uint32_t from_h = (tip_height > recent_block_window) ? (tip_height - recent_block_window) : 0;
        if(!p2p.match_recent_blocks(pkhs, from_h, tip_height, matched, err)){ p2p.close(); return false; }
    }

    // 3) walk matched blocks: add our outputs / remove spent ones
    auto key_of = [](const std::vector<uint8_t>& txid, uint32_t vout){
        std::string k; k.reserve(36);
        k.assign((const char*)txid.data(), txid.size());
        k.push_back(char((vout>>0)&0xFF)); k.push_back(char((vout>>8)&0xFF));
        k.push_back(char((vout>>16)&0xFF)); k.push_back(char((vout>>24)&0xFF));
        return k;
    };
    std::vector<UtxoLite> view;
    std::unordered_map<std::string,size_t> idx;

    struct VecHash {
        size_t operator()(const std::vector<uint8_t>& v) const noexcept {
            size_t h = 1469598103934665603ull; // FNV-1a
            for(uint8_t b: v){ h ^= b; h *= 1099511628211ull; }
            return h;
        }
    };
    std::unordered_set<std::vector<uint8_t>, VecHash> pkhset(pkhs.begin(), pkhs.end());

    for(const auto& [bh, h] : matched){
        std::vector<uint8_t> raw;
        if(!p2p.get_block_by_hash(bh, raw, err)){ p2p.close(); return false; }
        miq::Block b; if(!miq::Block::deserialize(raw, b)) continue;

        // remove spends
        for(const auto& tx : b.vtx){
            for(const auto& in : tx.vin){
                auto k = key_of(in.prev.txid, in.prev.vout);
                auto it = idx.find(k);
                if(it!=idx.end()){
                    size_t pos = it->second;
                    size_t last = view.size()-1;
                    if(pos!=last){
                        idx[key_of(view[last].txid, view[last].vout)] = pos;
                        std::swap(view[pos], view[last]);
                    }
                    view.pop_back();
                    idx.erase(it);
                }
            }
        }
        // add our outputs (respect coinbase maturity)
        for(const auto& tx : b.vtx){
            bool is_cb = tx.is_coinbase();
            for(uint32_t i=0;i<(uint32_t)tx.vout.size();++i){
                const auto& o = tx.vout[i];
                if(pkhset.find(o.pkh)!=pkhset.end()){
                    if(is_cb){
                        uint32_t conf = (tip_height >= h) ? (tip_height - h + 1) : 0;
                        if(conf < miq::COINBASE_MATURITY) continue; // skip immature coinbase
                    }
                    UtxoLite u; u.txid = tx.txid(); u.vout=i; u.value=o.value; u.pkh=o.pkh; u.height=h; u.coinbase=is_cb;
                    idx[key_of(u.txid, u.vout)] = (uint32_t)view.size();
                    view.push_back(std::move(u));
                }
            }
        }
    }

    p2p.close();
    out = std::move(view);
    return true;
}

static uint64_t utxo_sum(const std::vector<UtxoLite>& v){
    uint64_t s=0; for(const auto& u: v) s+=u.value; return s;
}

// -----------------------------------------------------------------------------
// Wallet ops
// -----------------------------------------------------------------------------
static bool make_or_restore_wallet(bool restore){
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::string mnemonic, mpass, wpass;
    if(restore){
        std::cout << "Paste 12/24-word mnemonic:\n> ";
        std::getline(std::cin, mnemonic);
        std::cout << "Mnemonic passphrase (ENTER for none): ";
        std::getline(std::cin, mpass);
        std::cout << "Wallet encryption passphrase (ENTER for none): ";
        std::getline(std::cin, wpass);
        mnemonic = trim(mnemonic);
    } else {
        std::cout << "Wallet encryption passphrase (ENTER for none): ";
        std::getline(std::cin, wpass);
        std::string outmn;
        if(!miq::HdWallet::GenerateMnemonic(128, outmn)) { std::cout << "mnemonic generation failed\n"; return false; }
        mnemonic = outmn;
        std::cout << "\nYour mnemonic:\n  " << mnemonic << "\n\n";
    }

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) { std::cout << "mnemonic->seed failed\n"; return false; }
    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)) { std::cout << "save failed: " << e << "\n"; return false; }

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)) { std::cout << "derive address failed\n"; return false; }
    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)) { std::cout << "save meta failed: " << e << "\n"; }
    std::cout << "First receive address: " << addr << "\n";
    return true;
}

static bool flow_send_p2p_only(const std::string& p2p_host, const std::string& p2p_port){
    // load wallet
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass; // prompt
    std::cout << "Wallet passphrase (ENTER if none): ";
    std::getline(std::cin, pass);
    if(!miq::LoadHdWallet(wdir, seed, meta, pass, e)){ std::cout << "Load wallet failed: " << e << "\n"; return false; }
    miq::HdWallet w(seed, meta);

    // recipient & amount
    std::cout << "Recipient address: "; std::string to; std::getline(std::cin, to); to=trim(to);
    std::cout << "Amount (MIQ, e.g. 1.23456789): "; std::string amt; std::getline(std::cin, amt); amt=trim(amt);
    uint64_t amount=0; try{ amount = parse_amount_miqron(amt);}catch(...){ std::cout<<"Bad amount\n"; return false;}

    // decode dest
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!miq::base58check_decode(to, ver, payload) || ver!=miq::VERSION_P2PKH || payload.size()!=20){
        std::cout << "Bad address.\n"; return false;
    }

    // Derive a horizon of keys (simple gap limit)
    struct Key { std::vector<uint8_t> priv, pub, pkh; uint32_t chain, index; };
    std::vector<Key> keys;
    auto add_range = [&](uint32_t chain, uint32_t upto){
        for(uint32_t i=0;i<=upto + 20; ++i){
            Key k; k.chain=chain; k.index=i;
            if(!w.DerivePrivPub(meta.account, chain, i, k.priv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            keys.push_back(std::move(k));
        }
    };
    add_range(0, meta.next_recv);
    add_range(1, meta.next_change);

    // SPV UTXO discovery over P2P
    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    std::vector<UtxoLite> utxos; std::string perr;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!spv_collect_utxos(p2p_host, p2p_port, pkhs, /*recent_block_window=*/8000, utxos, perr)){
        std::cout << "SPV collection failed: " << perr << "\n";
        return false;
    }
    if(utxos.empty()){
        std::cout << "No spendable UTXOs found for this seed yet.\n";
        return false;
    }

    // Build transaction: prefer coinbase (common for mined payouts, but only mature ones were kept)
    miq::Transaction tx;
    uint64_t in_sum=0;
    std::stable_sort(utxos.begin(), utxos.end(), [](const UtxoLite& a, const UtxoLite& b){
        if(a.coinbase != b.coinbase) return a.coinbase && !b.coinbase;
        return a.value > b.value;
    });

    for(const auto& u : utxos){
        miq::TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
        tx.vin.push_back(in);
        in_sum += u.value;
        uint64_t fee_guess = fee_for(tx.vin.size(), 2, 1000);
        if(in_sum >= amount + fee_guess) break;
    }
    if(tx.vin.empty()){ std::cout << "Insufficient funds.\n"; return false; }

    // outputs + fee
    uint64_t fee_final = 0, change = 0;
    {
        auto fee2 = fee_for(tx.vin.size(), 2, 1000);
        if(in_sum < amount + fee2){
            auto fee1 = fee_for(tx.vin.size(), 1, 1000);
            if(in_sum < amount + fee1){ std::cout << "Insufficient (need fee).\n"; return false; }
            fee_final = fee1; change = 0;
        }else{
            fee_final = fee2; change = in_sum - amount - fee_final;
            if(change < 1000){ change = 0; fee_final = fee_for(tx.vin.size(), 1, 1000); }
        }
    }
    miq::TxOut o; o.pkh = payload; o.value = amount; tx.vout.push_back(o);

    bool used_change=false; std::vector<uint8_t> cpub, cpriv, cpkh;
    if(change>0){
        if(!w.DerivePrivPub(meta.account, 1, meta.next_change, cpriv, cpub)){ std::cout << "derive change failed\n"; return false; }
        cpkh = miq::hash160(cpub);
        miq::TxOut ch; ch.value = change; ch.pkh = cpkh; tx.vout.push_back(ch); used_change=true;
    }

    // sign each input
    auto sighash = [&](){
        miq::Transaction t=tx;
        for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); }
        return miq::dsha256(miq::ser_tx(t));
    }();
    auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const Key*{
        for(const auto& k: keys) if(k.pkh==pkh) return &k;
        return nullptr;
    };
    for(auto& in : tx.vin){
        const UtxoLite* u=nullptr;
        for(const auto& x: utxos) if(x.txid==in.prev.txid && x.vout==in.prev.vout){ u=&x; break; }
        if(!u){ std::cout << "internal: utxo lookup failed\n"; return false; }
        auto* K = find_key_for_pkh(u->pkh);
        if(!K){ std::cout << "internal: key lookup failed\n"; return false; }
        std::vector<uint8_t> sig64;
        if(!miq::crypto::ECDSA::sign(K->priv, sighash, sig64)){ std::cout << "sign failed\n"; return false; }
        in.sig = sig64; in.pubkey = K->pub;
    }

    // serialize + broadcast
    auto raw = miq::ser_tx(tx);
    std::string txid_hex = miq::to_hex(tx.txid());
    std::cout << "Broadcasting via P2P to " << p2p_host << ":" << p2p_port << " ...\n";
    if(!p2p_broadcast_tx(p2p_host, p2p_port, raw, perr)){
        std::cout << "P2P broadcast failed: " << perr << "\n";
        return false;
    }
    std::cout << "Broadcasted (P2P). Txid: " << txid_hex << "\n";

    // bump change index if used
    if(used_change){
        auto m = w.meta(); m.next_change = meta.next_change + 1;
        if(!miq::SaveHdWallet(wdir, seed, m, pass, e)){
            std::cout << "WARN: SaveHdWallet(next_change) failed: " << e << "\n";
        }
    }
    return true;
}

static bool show_balance_spv(const std::string& p2p_host, const std::string& p2p_port){
    // load wallet meta/seed to derive PKHs
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass;
    std::cout << "Wallet passphrase (ENTER if none): ";
    std::getline(std::cin, pass);
    if(!miq::LoadHdWallet(wdir, seed, meta, pass, e)){ std::cout << "Load wallet failed: " << e << "\n"; return false; }
    miq::HdWallet w(seed, meta);

    struct Key { std::vector<uint8_t> priv, pub, pkh; };
    std::vector<Key> keys;
    auto add_range = [&](uint32_t chain, uint32_t upto){
        for(uint32_t i=0;i<=upto + 20; ++i){
            Key k;
            if(!w.DerivePrivPub(meta.account, chain, i, k.priv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            keys.push_back(std::move(k));
        }
    };
    add_range(0, meta.next_recv);
    add_range(1, meta.next_change);

    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    std::vector<UtxoLite> utxos; std::string err;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!spv_collect_utxos(p2p_host, p2p_port, pkhs, 8000, utxos, err)){
        std::cout << "SPV collection failed: " << err << "\n";
        return false;
    }
    auto v = utxo_sum(utxos);
    std::ostringstream s; s << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
    std::cout << "Balance (SPV): " << s.str() << " MIQ (" << v << " miqron)\n";
    return true;
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    // P2P seed (default to your node)
    std::string p2p_host = "62.38.73.147";
    std::string p2p_port = "9833";

    // parse flags
    for(int i=1;i<argc;i++){
        std::string a = argv[i];
        auto eat = [&](const char* k, std::string& dst)->bool{
            size_t L = std::strlen(k);
            if(a.rfind(k, 0)==0){
                if(a.size()>L && a[L]=='='){ dst = a.substr(L+1); return true; }
                if(i+1<argc){ dst = argv[++i]; return true; }
            }
            return false;
        };
        if(eat("--p2pseed", p2p_host)) { auto c=p2p_host.find(':'); if(c!=std::string::npos){ p2p_port=p2p_host.substr(c+1); p2p_host=p2p_host.substr(0,c);} continue; }
        if(eat("--p2pport", p2p_port)) continue;
    }

    std::cout << "Chain: " << CHAIN_NAME << "\n";
    std::cout << "P2P seed: " << p2p_host << ":" << p2p_port << "\n";

    for(;;){
        std::cout << "\n==== MIQ Wallet (P2P) ====\n";
        std::cout << "1) Create wallet\n";
        std::cout << "2) Recover wallet\n";
        std::cout << "3) Send MIQ (P2P broadcast)\n";
        std::cout << "4) Show balance (SPV)\n";
        std::cout << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="1"){ (void)make_or_restore_wallet(false); }
        else if(c=="2"){ (void)make_or_restore_wallet(true); }
        else if(c=="3"){ (void)flow_send_p2p_only(p2p_host, p2p_port); }
        else if(c=="4"){ (void)show_balance_spv(p2p_host, p2p_port); }
        else if(c=="q"||c=="Q"||c=="exit") break;
    }
    return 0;
}
