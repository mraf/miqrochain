// src/cli/miqwallet.cpp
// MIQ Wallet CLI — Remote-only, interactive login (create/load), balance & send.
//
// What you get:
// - Start menu: Create wallet OR Load from seed. Then auto-login to show balance.
// - If encrypted, it asks for wallet password; if not, it logs in directly.
// - Balance via P2P/SPV from remote seeds (default = 62.38.73.147:9833).
// - Send MIQ to P2PKH address; coinbase maturity respected; robust P2P broadcast.
// - Pending-spent cache so unconfirmed sends aren’t double-counted.
// - DNS seeds are OFF by default (enable with MIQ_USE_DNS_SEEDS=1).
// - Override seeds with --p2pseed=host:port or MIQ_P2P_SEED (comma-separated).
//
// Build deps already in repo: hd_wallet, wallet_store, sha256, hash160,
// base58check, hex, serialize, tx, crypto/ecdsa_iface,
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
#include <set>

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

// ------------------------------ small utils ---------------------------------
static std::string trim(const std::string& s){
    size_t a=0,b=s.size();
    while(a<b && std::isspace((unsigned char)s[a])) ++a;
    while(b>a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}
static uint64_t get_env_u64(const char* name, uint64_t defv){
    if(const char* v = std::getenv(name)){
        if(*v){
            char* end=nullptr;
            unsigned long long t = std::strtoull(v,&end,10);
            if(end && *end=='\0') return (uint64_t)t;
        }
    }
    return defv;
}
static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v) return false;
    std::string s=v; for(char& c: s) c=(char)std::tolower((unsigned char)c);
    return (s=="1"||s=="true"||s=="yes"||s=="on");
}
static std::string join_path(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a+sep+b;
}
static std::string wallet_dir_from_default(){
    std::string p = miq::default_wallet_file();
    if(!p.empty()){
        size_t pos = p.find_last_of("/\\");
        if(pos!=std::string::npos) p = p.substr(0,pos);
        return p;
    }
    return "wallets/default";
}
static std::string fmt_amount(uint64_t v){
    std::ostringstream s; s<<(v/COIN)<<"."<<std::setw(8)<<std::setfill('0')<<(v%COIN);
    return s.str();
}

// --------------------------- pending-spent cache -----------------------------
struct OutpointKey {
    std::string txid_hex;
    uint32_t vout{0};
    bool operator<(const OutpointKey& o) const {
        if(txid_hex!=o.txid_hex) return txid_hex<o.txid_hex;
        return vout<o.vout;
    }
};
static std::string pending_file_path_for_wdir(const std::string& wdir){
    return join_path(wdir, "pending_spent.dat");
}
static void load_pending(const std::string& wdir, std::set<OutpointKey>& out){
    out.clear();
    std::ifstream f(pending_file_path_for_wdir(wdir));
    if(!f.good()) return;
    std::string line;
    while(std::getline(f,line)){
        if(line.empty()) continue;
        size_t c = line.find(':'); if(c==std::string::npos) continue;
        OutpointKey k; k.txid_hex = line.substr(0,c);
        k.vout = (uint32_t)std::strtoul(line.c_str()+c+1,nullptr,10);
        out.insert(k);
    }
}
static void save_pending(const std::string& wdir, const std::set<OutpointKey>& st){
    std::ofstream f(pending_file_path_for_wdir(wdir), std::ios::out|std::ios::trunc);
    if(!f.good()) return;
    for(const auto& k: st) f<<k.txid_hex<<":"<<k.vout<<"\n";
}

// ------------------------------- seeds --------------------------------------
static const char* kDefaultSeedHost = "62.38.73.147"; // your working node

static std::vector<std::pair<std::string,std::string>>
build_seed_candidates(const std::string& cli_host,
                      const std::string& cli_port,
                      bool allow_localhost)
{
    std::vector<std::pair<std::string,std::string>> seeds;

    // 0) CLI seed has top priority
    if(!cli_host.empty()) seeds.emplace_back(cli_host, cli_port);

    // 1) MIQ_P2P_SEED env (comma-separated host[:port])
    if(const char* e = std::getenv("MIQ_P2P_SEED"); e && *e){
        std::string v=e; size_t start=0;
        while(start<v.size()){
            size_t comma = v.find(',',start);
            std::string tok = (comma==std::string::npos)? v.substr(start) : v.substr(start,comma-start);
            auto c = tok.find(':');
            if(c!=std::string::npos) seeds.emplace_back(tok.substr(0,c), tok.substr(c+1));
            else seeds.emplace_back(tok, std::to_string(miq::P2P_PORT));
            if(comma==std::string::npos) break;
            start=comma+1;
        }
    }

    // 2) hard default: your public seed
    seeds.emplace_back(std::string(kDefaultSeedHost), std::to_string(miq::P2P_PORT));

    // 3) DNS seeds opt-in
    if(env_truthy("MIQ_USE_DNS_SEEDS")){
        seeds.emplace_back(miq::DNS_SEED, std::to_string(miq::P2P_PORT));
        for(size_t i=0;i<miq::DNS_SEEDS_COUNT;i++){
            seeds.emplace_back(miq::DNS_SEEDS[i], std::to_string(miq::P2P_PORT));
        }
    }

    // 4) localhost (only if allowed)
    if(allow_localhost){
        seeds.emplace_back("127.0.0.1", std::to_string(miq::P2P_PORT));
        seeds.emplace_back("::1",       std::to_string(miq::P2P_PORT));
        seeds.emplace_back("localhost", std::to_string(miq::P2P_PORT));
    }

    // de-dup preserving order
    std::vector<std::pair<std::string,std::string>> uniq;
    std::unordered_set<std::string> seen;
    for(auto& hp: seeds){
        std::string key = hp.first + ":" + hp.second;
        if(seen.insert(key).second) uniq.push_back(hp);
    }
    return uniq;
}

// ------------------------------- SPV/UTXO -----------------------------------
static bool try_spv_collect_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
                                     const std::vector<std::vector<uint8_t>>& pkhs,
                                     uint32_t recent_window,
                                     std::vector<miq::UtxoLite>& out,
                                     std::string& used_host,
                                     std::string& last_err)
{
    used_host.clear(); out.clear(); last_err.clear();

    miq::SpvOptions opts{};               // your repo: only .recent_block_window is present
    opts.recent_block_window = recent_window;

    std::ostringstream diag;
    bool any=false;
    for(const auto& [h,p]: seeds){
        any=true;
        std::vector<miq::UtxoLite> v; std::string e;
        if(miq::spv_collect_utxos(h,p,pkhs,opts,v,e)){
            out.swap(v);
            used_host = h + ":" + p;
            return true;
        }
        diag<<"  - "<<h<<":"<<p<<" -> "<<(e.empty()?"connect failed":e)<<"\n";
        last_err = e.empty()? "connect failed" : e;
    }
    if(!any) last_err = "no seeds available";
    else last_err = std::string("all seeds failed:\n") + diag.str();
    return false;
}

struct WalletBalance {
    uint64_t total{0};
    uint64_t spendable{0};
    uint64_t immature{0};
    uint64_t pending_hold{0};
    uint64_t approx_tip_h{0};
};

static WalletBalance compute_balance(const std::vector<miq::UtxoLite>& utxos,
                                     const std::set<OutpointKey>& pending)
{
    WalletBalance wb{};
    for(const auto& u : utxos) wb.approx_tip_h = std::max<uint64_t>(wb.approx_tip_h, u.height);
    for(const auto& u : utxos){
        wb.total += u.value;
        bool is_immature = false;
        if(u.coinbase){
            uint64_t mature_h = (uint64_t)u.height + (uint64_t)miq::COINBASE_MATURITY;
            if(wb.approx_tip_h + 1 < mature_h) is_immature = true;
        }
        OutpointKey k{ miq::to_hex(u.txid), u.vout };
        bool held = (pending.find(k) != pending.end());
        if(is_immature) wb.immature += u.value;
        else if(held)   wb.pending_hold += u.value;
        else            wb.spendable += u.value;
    }
    return wb;
}

// ----------------------------- broadcasting ---------------------------------
static bool p2p_broadcast_tx_one(const std::string& seed_host,
                                 const std::string& seed_port,
                                 const std::vector<uint8_t>& raw_tx,
                                 std::string& err)
{
    miq::P2POpts o;
    o.host = seed_host;
    o.port = seed_port;
    o.user_agent = "/miqwallet-p2p:1.0/";
    o.io_timeout_ms = 6000; // exists on P2PLight opts
    miq::P2PLight p2p;
    if(!p2p.connect_and_handshake(o, err)) return false;
    bool ok = p2p.send_tx(raw_tx, err);
    p2p.close();
    return ok;
}
static bool try_broadcast_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
                                   const std::vector<uint8_t>& raw,
                                   std::string& used_host,
                                   std::string& last_err)
{
    used_host.clear(); last_err.clear();
    std::ostringstream diag; bool any=false;
    for(const auto& [h,p] : seeds){
        any=true;
        std::string e;
        if(p2p_broadcast_tx_one(h,p,raw,e)){ used_host=h+":"+p; return true; }
        diag<<"  - "<<h<<":"<<p<<" -> "<<(e.empty()?"connect failed":e)<<"\n";
        last_err = e.empty()? "connect failed" : e;
    }
    last_err = any? std::string("all seeds failed:\n")+diag.str() : "no seeds available";
    return false;
}

// ------------------------------ fees / sizing --------------------------------
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

// ------------------------------- wallet ops ---------------------------------
static bool create_wallet(){
    std::string wdir = wallet_dir_from_default();

    std::string wpass;
    std::cout << "Wallet encryption passphrase (ENTER for none): ";
    std::getline(std::cin, wpass);

    std::string mnemonic;
    if(!miq::HdWallet::GenerateMnemonic(128, mnemonic)){
        std::cout << "mnemonic generation failed\n"; return false;
    }
    std::cout << "\nYour mnemonic (WRITE IT DOWN):\n  " << mnemonic << "\n\n";

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, /*mnemonic passphrase*/"", seed)){
        std::cout<<"mnemonic->seed failed\n"; return false;
    }

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)){
        std::cout << "save failed: " << e << "\n"; return false;
    }

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)){ std::cout<<"derive address failed\n"; return false; }
    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)){ std::cout<<"save meta failed: "<<e<<"\n"; }
    std::cout << "First receive address: " << addr << "\n";
    return true;
}

static bool load_from_seed(){
    std::string wdir = wallet_dir_from_default();

    std::string mnemonic, mpass, wpass;
    std::cout << "Paste 12/24-word mnemonic:\n> ";
    std::getline(std::cin, mnemonic); mnemonic = trim(mnemonic);
    std::cout << "Mnemonic passphrase (ENTER for none): ";
    std::getline(std::cin, mpass);
    std::cout << "Wallet encryption passphrase to store (ENTER for none): ";
    std::getline(std::cin, wpass);

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)){
        std::cout<<"mnemonic->seed failed\n"; return false;
    }
    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)){
        std::cout<<"save failed: "<<e<<"\n"; return false;
    }

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)){ std::cout<<"derive address failed\n"; return false; }
    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)){ std::cout<<"save meta failed: "<<e<<"\n"; }
    std::cout << "First receive address: " << addr << "\n";
    return true;
}

// derive key horizon (gap limit = 20)
struct KeyLite { std::vector<uint8_t> priv, pub, pkh; uint32_t chain{0}, index{0}; };
static void derive_horizon(miq::HdWallet& w, const miq::HdAccountMeta& meta, std::vector<KeyLite>& out){
    out.clear();
    auto add = [&](uint32_t chain, uint32_t upto){
        for(uint32_t i=0;i<=upto+20;++i){
            KeyLite k; k.chain=chain; k.index=i;
            if(!w.DerivePrivPub(meta.account, chain, i, k.priv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            out.push_back(std::move(k));
        }
    };
    add(0, meta.next_recv);
    add(1, meta.next_change);
}

// login flow: load wallet (prompt pass if encrypted), then run dashboard
static bool login_and_dashboard(const std::string& cli_host,
                                const std::string& cli_port,
                                bool allow_localhost)
{
    std::string wdir = wallet_dir_from_default();

    // Load with prompt
    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass;
    std::cout << "Wallet passphrase (ENTER if none): ";
    std::getline(std::cin, pass);
    if(!miq::LoadHdWallet(wdir, seed, meta, pass, e)){
        std::cout << "Load wallet failed: " << e << "\n";
        return false;
    }
    miq::HdWallet w(seed, meta);

    // seed list
    const bool allow_local = allow_localhost || env_truthy("MIQ_ALLOW_LOCALHOST");
    auto seeds = build_seed_candidates(cli_host, cli_port, allow_local);

    // main loop
    for(;;){
        // derive keys (lookahead)
        std::vector<KeyLite> keys; derive_horizon(w, meta, keys);
        std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
        for(auto& k: keys) pkhs.push_back(k.pkh);

        // SPV window
        const uint32_t spv_win = (uint32_t)get_env_u64("MIQ_SPV_WINDOW", 200000);

        // collect utxos
        std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
        std::cout << "\nSyncing (P2P/SPV)…\n";
        if(!try_spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err)){
            std::cout << "SPV failed:\n" << err << "\n";
            std::cout << "Hint: --p2pseed=host:port or MIQ_P2P_SEED=host1:port,host2:port\n";
        }

        // pending file maintenance
        std::set<OutpointKey> pending;
        load_pending(wdir, pending);
        {
            std::set<OutpointKey> cur;
            for(const auto& u: utxos) cur.insert(OutpointKey{ miq::to_hex(u.txid), u.vout });
            for(auto it = pending.begin(); it!=pending.end(); ){
                if(cur.find(*it) == cur.end()) it = pending.erase(it);
                else ++it;
            }
            save_pending(wdir, pending);
        }

        WalletBalance wb = compute_balance(utxos, pending);

        std::cout << "=== Wallet (" << CHAIN_NAME << ") via " << (used_seed.empty()?"<no-conn>":used_seed) << " ===\n";
        std::cout << "Total:        " << fmt_amount(wb.total)        << " MIQ  (" << wb.total        << ")\n";
        std::cout << "Spendable:    " << fmt_amount(wb.spendable)    << " MIQ  (" << wb.spendable    << ")\n";
        std::cout << "Immature:     " << fmt_amount(wb.immature)     << " MIQ  (" << wb.immature     << ")\n";
        std::cout << "Pending-hold: " << fmt_amount(wb.pending_hold) << " MIQ  (" << wb.pending_hold << ")\n";

        std::cout << "\nOptions:\n";
        std::cout << "  1) Receive address\n";
        std::cout << "  2) Send MIQ\n";
        std::cout << "  r) Refresh balance\n";
        std::cout << "  q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);

        if(c=="q"||c=="Q") break;

        if(c=="1"){
            std::string addr;
            if(!w.GetNewAddress(addr)){ std::cout<<"derive address failed\n"; continue; }
            // persist bumped next_recv
            std::string e2;
            if(!miq::SaveHdWallet(wdir, seed, w.meta(), pass, e2))
                std::cout<<"WARN: SaveHdWallet failed: "<<e2<<"\n";
            std::cout<<"New receive address: "<<addr<<"\n";
            continue;
        }

        if(c=="2"){
            if(wb.spendable==0){ std::cout<<"No spendable balance.\n"; continue; }

            // Ask for recipient & amount
            std::string to; std::cout<<"Recipient address (P2PKH): "; std::getline(std::cin,to); to=trim(to);
            uint8_t ver=0; std::vector<uint8_t> payload;
            if(!miq::base58check_decode(to, ver, payload) || ver!=miq::VERSION_P2PKH || payload.size()!=20){
                std::cout<<"Bad address (expect Base58 P2PKH).\n"; continue;
            }
            std::string sAmt; std::cout<<"Amount (e.g. 1.2345 or miqron): ";
            std::getline(std::cin,sAmt); sAmt=trim(sAmt);
            uint64_t amount=0; try{ amount=parse_amount_miqron(sAmt);}catch(...){ std::cout<<"Bad amount.\n"; continue; }
            if(amount==0){ std::cout<<"Amount must be > 0\n"; continue; }

            // build spendable UTXO list (exclude immature & pending)
            std::vector<miq::UtxoLite> spendable_utxos;
            for(const auto& u: utxos){
                bool is_imm=false;
                if(u.coinbase){
                    uint64_t mature_h = (uint64_t)u.height + (uint64_t)miq::COINBASE_MATURITY;
                    if(wb.approx_tip_h + 1 < mature_h) is_imm = true;
                }
                OutpointKey k{ miq::to_hex(u.txid), u.vout };
                bool held = (pending.find(k) != pending.end());
                if(!is_imm && !held) spendable_utxos.push_back(u);
            }
            if(spendable_utxos.empty()){ std::cout<<"No spendable UTXOs.\n"; continue; }

            // coin selection: prefer coinbase last, otherwise larger-first
            std::stable_sort(spendable_utxos.begin(), spendable_utxos.end(),
                [](const miq::UtxoLite& a, const miq::UtxoLite& b){
                    if(a.coinbase!=b.coinbase) return !a.coinbase && b.coinbase; // non-coinbase first
                    return a.value > b.value; // larger first
                });

            miq::Transaction tx; uint64_t in_sum=0;
            for(const auto& u: spendable_utxos){
                miq::TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
                tx.vin.push_back(in);
                in_sum += u.value;
                uint64_t fee_guess = fee_for(tx.vin.size(), 2, 1000);
                if(in_sum >= amount + fee_guess) break;
            }
            if(tx.vin.empty()){ std::cout<<"Insufficient funds.\n"; continue; }

            // outputs & final fee
            uint64_t fee_final=0, change=0;
            {
                auto fee2 = fee_for(tx.vin.size(), 2, 1000);
                if(in_sum < amount + fee2){
                    auto fee1 = fee_for(tx.vin.size(), 1, 1000);
                    if(in_sum < amount + fee1){ std::cout<<"Insufficient (need fee).\n"; continue; }
                    fee_final = fee1; change=0;
                }else{
                    fee_final = fee2; change = in_sum - amount - fee_final;
                    if(change < 1000){ change=0; fee_final = fee_for(tx.vin.size(), 1, 1000); }
                }
            }
            miq::TxOut out; out.value = amount; out.pkh = payload; tx.vout.push_back(out);

            bool used_change=false; std::vector<uint8_t> cpriv, cpub, cpkh;
            if(change>0){
                if(!w.DerivePrivPub(meta.account, 1, meta.next_change, cpriv, cpub)){ std::cout<<"derive change failed\n"; continue; }
                cpkh = miq::hash160(cpub);
                miq::TxOut ch; ch.value = change; ch.pkh = cpkh; tx.vout.push_back(ch); used_change=true;
            }

            // sign inputs
            auto sighash = [&](){ miq::Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); } return miq::dsha256(miq::ser_tx(t)); }();
            auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const KeyLite*{
                for(const auto& k: keys) if(k.pkh==pkh) return &k;
                return nullptr;
            };
            for(auto& in : tx.vin){
                const miq::UtxoLite* u=nullptr;
                for(const auto& x: spendable_utxos) if(x.txid==in.prev.txid && x.vout==in.prev.vout){ u=&x; break; }
                if(!u){ std::cout<<"internal: utxo lookup failed\n"; goto SEND_ABORT; }
                auto* K = find_key_for_pkh(u->pkh);
                if(!K){ std::cout<<"internal: key lookup failed\n"; goto SEND_ABORT; }
                std::vector<uint8_t> sig64;
                if(!miq::crypto::ECDSA::sign(K->priv, sighash, sig64)){ std::cout<<"sign failed\n"; goto SEND_ABORT; }
                in.sig = sig64; in.pubkey = K->pub;
            }

            {
                auto raw = miq::ser_tx(tx);
                std::string txid_hex = miq::to_hex(tx.txid());

                std::string used_bcast_seed, berr;
                std::cout<<"Broadcasting via P2P…\n";
                if(!try_broadcast_any_seed(seeds, raw, used_bcast_seed, berr)){
                    std::cout<<"Broadcast failed:\n"<<berr;
                    std::cout<<"\n"; goto SEND_ABORT;
                }
                std::cout<<"Broadcasted via "<<used_bcast_seed<<"\nTxid: "<<txid_hex<<"\n";

                // mark inputs as pending-held
                for(const auto& in: tx.vin){
                    pending.insert(OutpointKey{ miq::to_hex(in.prev.txid), in.prev.vout });
                }
                save_pending(wdir, pending);

                // bump change index if used
                if(used_change){
                    auto m = w.meta(); m.next_change = meta.next_change + 1;
                    std::string e3;
                    if(!miq::SaveHdWallet(wdir, seed, m, pass, e3))
                        std::cout<<"WARN: SaveHdWallet(next_change) failed: "<<e3<<"\n";
                    meta = m; // keep in-memory in sync
                }
            }

            std::cout<<"NOTE: Balance will reflect this as 'Pending-hold' until mined.\n";
            continue;

        SEND_ABORT:
            std::cout<<"Send aborted.\n";
            continue;
        }

        // refresh on any other input too
    }

    return true;
}

// ---------------------------------- main ------------------------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    // Remote-only by default; localhost allowed only if explicitly asked.
    bool allow_localhost = false;
    std::string cli_host;
    std::string cli_port = std::to_string(miq::P2P_PORT);

    // Parse flags
    for(int i=1;i<argc;i++){
        std::string a = argv[i];
        auto eat_str = [&](const char* k, std::string& dst)->bool{
            size_t L = std::strlen(k);
            if(a.rfind(k,0)==0){
                if(a.size()>L && a[L]=='='){ dst = a.substr(L+1); return true; }
                if(i+1<argc){ dst = argv[++i]; return true; }
            }
            return false;
        };
        if(a=="--allow-localhost"){ allow_localhost = true; continue; }
        if(eat_str("--p2pseed", cli_host)) { auto c=cli_host.find(':'); if(c!=std::string::npos){ cli_port=cli_host.substr(c+1); cli_host=cli_host.substr(0,c);} continue; }
        if(eat_str("--p2pport", cli_port)) continue;
    }

    std::cout << "Chain: " << CHAIN_NAME << "\n";
    std::cout << "Remote seeds (first is default): ";
    auto seeds_preview = build_seed_candidates(cli_host, cli_port, allow_localhost);
    for(size_t i=0;i<seeds_preview.size();++i){
        if(i) std::cout<<", ";
        std::cout<<seeds_preview[i].first<<":"<<seeds_preview[i].second;
    }
    std::cout<<"\n";

    for(;;){
        std::cout << "\n=== MIQ Wallet ===\n";
        std::cout << "1) Create wallet\n";
        std::cout << "2) Load wallet from seed\n";
        std::cout << "3) Login (show balance & send)\n";
        std::cout << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="1"){ (void)create_wallet(); }
        else if(c=="2"){ (void)load_from_seed(); }
        else if(c=="3"){ (void)login_and_dashboard(cli_host, cli_port, allow_localhost); }
        else if(c=="q"||c=="Q"||c=="exit") break;
    }
    return 0;
}
