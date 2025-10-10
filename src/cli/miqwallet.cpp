// src/cli/miqwallet.cpp
// MIQ wallet CLI (P2P-only): local HD + SPV UTXO discovery + P2P tx broadcast.
//
// Build deps: hd_wallet, wallet_store, sha256, ripemd160, hash160,
// base58*, hex, serialize, tx, secp256k1,
// wallet/p2p_light.*, wallet/spv_simple.*

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
#include "crypto/ecdsa_iface.h"

#include "wallet/p2p_light.h"
#include "wallet/spv_simple.h"   // SpvOptions, UtxoLite, spv_collect_utxos

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
// P2P helpers
// -----------------------------------------------------------------------------
static bool p2p_broadcast_tx_one(const std::string& seed_host, const std::string& seed_port,
                                 const std::vector<uint8_t>& raw_tx,
                                 std::string& err)
{
    miq::P2POpts o;
    o.host = seed_host;
    o.port = seed_port;
    o.user_agent = "/miqwallet-p2p:0.1/";
    o.io_timeout_ms = 5000;             // valid for P2PLight::P2POpts (NOT SpvOptions)
    miq::P2PLight p2p;
    if(!p2p.connect_and_handshake(o, err)) return false;
    bool ok = p2p.send_tx(raw_tx, err);
    p2p.close();
    return ok;
}

static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v) return false;
    std::string s = v;
    for(char& c: s) c = (char)std::tolower((unsigned char)c);
    return (s=="1" || s=="true" || s=="yes" || s=="on");
}

static std::vector<std::pair<std::string,std::string>>
build_seed_candidates(const std::string& cli_host, const std::string& cli_port)
{
    std::vector<std::pair<std::string,std::string>> seeds;

    // 0) explicit CLI
    if(!cli_host.empty()) seeds.emplace_back(cli_host, cli_port);

    // 1) env override (MIQ_P2P_SEED="host[:port]")
    if(const char* e = std::getenv("MIQ_P2P_SEED"); e && *e){
        std::string v = e;
        auto c = v.find(':');
        if(c != std::string::npos) seeds.emplace_back(v.substr(0,c), v.substr(c+1));
        else                       seeds.emplace_back(v, std::to_string(miq::P2P_PORT));
    }

    // 2) global static seeds from constants.h (worldwide reach)
    seeds.emplace_back(miq::DNS_SEED, std::to_string(miq::P2P_PORT));
    for(size_t i=0;i<miq::DNS_SEEDS_COUNT;i++){
        seeds.emplace_back(miq::DNS_SEEDS[i], std::to_string(miq::P2P_PORT));
    }

    // 3) localhost LAST — only if explicitly allowed (avoids accidental self-dials)
    if (env_truthy("MIQ_ALLOW_LOCALHOST")) {
        seeds.emplace_back("127.0.0.1", std::to_string(miq::P2P_PORT));
    }

    // de-dup while preserving order
    std::vector<std::pair<std::string,std::string>> uniq;
    std::unordered_set<std::string> seen;
    for(auto& hp: seeds){
        std::string key = hp.first + ":" + hp.second;
        if(seen.insert(key).second) uniq.push_back(hp);
    }
    return uniq;
}

static bool try_broadcast_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
                                   const std::vector<uint8_t>& raw,
                                   std::string& used_host,
                                   std::string& last_err)
{
    used_host.clear(); last_err.clear();
    for(const auto& [h,p] : seeds){
        std::string e;
        if(p2p_broadcast_tx_one(h, p, raw, e)){
            used_host = h + ":" + p;
            return true;
        }
        last_err = e.empty() ? "connect failed" : e;
    }
    return false;
}

static bool try_spv_collect_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
                                     const std::vector<std::vector<uint8_t>>& pkhs,
                                     uint32_t recent_window,
                                     std::vector<miq::UtxoLite>& out,
                                     std::string& used_host,
                                     uint32_t& used_tip_height,
                                     std::string& last_err)
{
    used_host.clear(); used_tip_height = 0; last_err.clear();
    out.clear();

    miq::SpvOptions opts{};                 // use what exists in your tree
    opts.recent_block_window = recent_window;
    // NOTE: Do NOT set opts.io_timeout_ms here — it doesn't exist in your repo.

    for(const auto& [h,p] : seeds){
        std::vector<miq::UtxoLite> v; std::string e;
        if(miq::spv_collect_utxos(h, p, pkhs, opts, v, e)){
            out.swap(v);
            used_host = h + ":" + p;
            used_tip_height = 0;            // SpvOptions in your tree has no tip_height field
            return true;
        }
        last_err = e.empty() ? "tip query failed" : e;
    }
    return false;
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

static bool flow_send_p2p_only(const std::string& cli_host, const std::string& cli_port){
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

    // SPV UTXO discovery over P2P (any seed)
    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    auto seeds = build_seed_candidates(cli_host, cli_port);

    std::vector<miq::UtxoLite> utxos; std::string used_seed, perr;
    uint32_t tip_h=0;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!try_spv_collect_any_seed(seeds, pkhs, /*recent_window=*/8000, utxos, used_seed, tip_h, perr)){
        std::cout << "SPV collection failed: " << perr << "\n";
        return false;
    }
    if(utxos.empty()){
        std::cout << "No spendable UTXOs found for this seed yet.\n";
        return false;
    }

    // Build transaction: prefer coinbase first, then larger outputs
    miq::Transaction tx;
    uint64_t in_sum=0;
    std::stable_sort(utxos.begin(), utxos.end(), [](const miq::UtxoLite& a, const miq::UtxoLite& b){
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
    (void)fee_final; // fee implied by inputs-outputs

    miq::TxOut o; o.pkh = payload; o.value = amount; tx.vout.push_back(o);

    bool used_change=false; std::vector<uint8_t> cpub, cpriv, cpkh;
    if(change>0){
        if(!w.DerivePrivPub(meta.account, 1, meta.next_change, cpriv, cpub)){ std::cout << "derive change failed\n"; return false; }
        cpkh = miq::hash160(cpub);
        miq::TxOut ch; ch.value = change; ch.pkh = cpkh; tx.vout.push_back(ch); used_change=true;
    }

    // sign each input
    auto sighash = [&](){ miq::Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); } return miq::dsha256(miq::ser_tx(t)); }();
    auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const Key*{
        for(const auto& k: keys) if(k.pkh==pkh) return &k;
        return nullptr;
    };
    for(auto& in : tx.vin){
        const miq::UtxoLite* u=nullptr;
        for(const auto& x: utxos) if(x.txid==in.prev.txid && x.vout==in.prev.vout){ u=&x; break; }
        if(!u){ std::cout << "internal: utxo lookup failed\n"; return false; }
        auto* K = find_key_for_pkh(u->pkh);
        if(!K){ std::cout << "internal: key lookup failed\n"; return false; }
        std::vector<uint8_t> sig64;
        if(!miq::crypto::ECDSA::sign(K->priv, sighash, sig64)){ std::cout << "sign failed\n"; return false; }
        in.sig = sig64; in.pubkey = K->pub;
    }

    // serialize + broadcast (any seed)
    auto raw = miq::ser_tx(tx);
    std::string txid_hex = miq::to_hex(tx.txid());
    std::string used_bcast_seed, berr;
    std::cout << "Broadcasting via P2P (multi-seed)…\n";
    if(!try_broadcast_any_seed(seeds, raw, used_bcast_seed, berr)){
        std::cout << "P2P broadcast failed: " << berr << "\n";
        return false;
    }
    std::cout << "Broadcasted via " << used_bcast_seed << ". Txid: " << txid_hex << "\n";

    // bump change index if used
    if(used_change){
        auto m = w.meta(); m.next_change = meta.next_change + 1;
        if(!miq::SaveHdWallet(wdir, seed, m, pass, e)){
            std::cout << "WARN: SaveHdWallet(next_change) failed: " << e << "\n";
        }
    }
    return true;
}

static bool show_balance_spv(const std::string& cli_host, const std::string& cli_port){
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

    auto seeds = build_seed_candidates(cli_host, cli_port);

    std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
    uint32_t tip_h=0;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!try_spv_collect_any_seed(seeds, pkhs, 8000, utxos, used_seed, tip_h, err)){
        std::cout << "SPV collection failed: " << err << "\n";
        return false;
    }
    uint64_t v=0; for(const auto& u: utxos) v += u.value;
    std::ostringstream s; s << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
    std::cout << "Balance (SPV via " << used_seed << "): " << s.str() << " MIQ (" << v << " miqron)\n";
    return true;
}

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    // CLI seed (optional). If empty, we auto-build candidate list.
    std::string cli_host;
    std::string cli_port = std::to_string(miq::P2P_PORT);

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
        if(eat("--p2pseed", cli_host)) { auto c=cli_host.find(':'); if(c!=std::string::npos){ cli_port=cli_host.substr(c+1); cli_host=cli_host.substr(0,c);} continue; }
        if(eat("--p2pport", cli_port)) continue;
    }

    std::cout << "Chain: " << CHAIN_NAME << "\n";
    {
        auto seeds = build_seed_candidates(cli_host, cli_port);
        std::cout << "Seed order:";
        for(size_t i=0;i<seeds.size();++i){
            if(i==0) std::cout << " ";
            else     std::cout << ", ";
            std::cout << seeds[i].first << ":" << seeds[i].second;
        }
        std::cout << "\n";
    }

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
        else if(c=="3"){ (void)flow_send_p2p_only(cli_host, cli_port); }
        else if(c=="4"){ (void)show_balance_spv(cli_host, cli_port); }
        else if(c=="q"||c=="Q"||c=="exit") break;
    }
    return 0;
}
