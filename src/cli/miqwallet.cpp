// src/cli/miqwallet.cpp
// MIQ wallet CLI (Remote-only, auto-balance by default).
//
// - Launching the EXE shows wallet balance immediately (no prompts).
// - Remote-only P2P/SPV (won't dial localhost unless --allow-localhost).
// - Robust multi-seed failover: --p2pseed, MIQ_P2P_SEED (comma list), DNS seeds.
// - Mature coinbase filtering, pending-spent cache, clear totals.
// - Encrypted wallets: read MIQ_WALLET_PASSPHRASE env so double-click works.
// - Interactive mode available with --interactive.
//
// Build deps: hd_wallet, wallet_store, sha256, hash160, base58check, hex,
// serialize, tx, crypto/ecdsa_iface, wallet/p2p_light.*, wallet/spv_simple.*

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

// -------------------------------------------------------------
// Small utils
// -------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}

static uint64_t get_env_u64(const char* name, uint64_t defv){
    if(const char* v = std::getenv(name)){
        if(*v){
            char* end=nullptr;
            unsigned long long t = std::strtoull(v, &end, 10);
            if(end && *end=='\0') return (uint64_t)t;
        }
    }
    return defv;
}

static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v) return false;
    std::string s = v;
    for(char& c: s) c = (char)std::tolower((unsigned char)c);
    return (s=="1" || s=="true" || s=="yes" || s=="on");
}

static std::string join_path(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}

// -------------------------------------------------------------
// Pending-spent cache (avoid double-spend while unconfirmed)
// -------------------------------------------------------------
struct OutpointKey {
    std::string txid_hex;
    uint32_t vout{0};
    bool operator<(const OutpointKey& o) const {
        if (txid_hex != o.txid_hex) return txid_hex < o.txid_hex;
        return vout < o.vout;
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
        k.vout = (uint32_t)std::strtoul(line.c_str()+c+1, nullptr, 10);
        out.insert(k);
    }
}
static void save_pending(const std::string& wdir, const std::set<OutpointKey>& st){
    std::ofstream f(pending_file_path_for_wdir(wdir), std::ios::out | std::ios::trunc);
    if(!f.good()) return;
    for(const auto& k : st){
        f << k.txid_hex << ":" << k.vout << "\n";
    }
}

// -------------------------------------------------------------
// Remote-only seeds
// -------------------------------------------------------------
static std::vector<std::pair<std::string,std::string>>
build_seed_candidates(const std::string& cli_host, const std::string& cli_port, bool allow_localhost)
{
    std::vector<std::pair<std::string,std::string>> seeds;

    // 0) CLI seed
    if(!cli_host.empty()){
        seeds.emplace_back(cli_host, cli_port);
    }

    // 1) MIQ_P2P_SEED env (comma-separated list of host[:port])
    if(const char* e = std::getenv("MIQ_P2P_SEED"); e && *e){
        std::string v = e;
        size_t start = 0;
        while(start < v.size()){
            size_t comma = v.find(',', start);
            std::string tok = (comma==std::string::npos)? v.substr(start) : v.substr(start, comma-start);
            auto c = tok.find(':');
            if(c != std::string::npos) seeds.emplace_back(tok.substr(0,c), tok.substr(c+1));
            else                       seeds.emplace_back(tok, std::to_string(miq::P2P_PORT));
            if(comma==std::string::npos) break;
            start = comma + 1;
        }
    }

    // 2) DNS seeds (global)
    seeds.emplace_back(miq::DNS_SEED, std::to_string(miq::P2P_PORT));
    for(size_t i=0;i<miq::DNS_SEEDS_COUNT;i++){
        seeds.emplace_back(miq::DNS_SEEDS[i], std::to_string(miq::P2P_PORT));
    }

    // 3) Optional localhost (only if explicitly allowed)
    if(allow_localhost){
        seeds.emplace_back("127.0.0.1", std::to_string(miq::P2P_PORT));
        seeds.emplace_back("::1",       std::to_string(miq::P2P_PORT));
        seeds.emplace_back("localhost", std::to_string(miq::P2P_PORT));
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

// -------------------------------------------------------------
// SPV collection with diagnostics
// -------------------------------------------------------------
static bool try_spv_collect_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
                                     const std::vector<std::vector<uint8_t>>& pkhs,
                                     uint32_t recent_window,
                                     std::vector<miq::UtxoLite>& out,
                                     std::string& used_host,
                                     std::string& last_err)
{
    used_host.clear(); last_err.clear();
    out.clear();

    miq::SpvOptions opts{};
    opts.recent_block_window = recent_window;

    std::ostringstream diag;
    bool any_attempt=false;

    for(const auto& [h,p] : seeds){
        any_attempt=true;
        std::vector<miq::UtxoLite> v; std::string e;
        if(miq::spv_collect_utxos(h, p, pkhs, opts, v, e)){
            out.swap(v);
            used_host = h + ":" + p;
            return true;
        }
        diag << "  - " << h << ":" << p << " -> " << (e.empty() ? "connect failed" : e) << "\n";
        last_err = e.empty() ? "connect failed" : e;
    }
    if(!any_attempt) last_err = "no seeds available";
    else last_err = std::string("all seeds failed:\n") + diag.str();
    return false;
}

// -------------------------------------------------------------
// Balance computation (Total/Spendable/Immature/Pending-hold)
// -------------------------------------------------------------
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

    for(const auto& u: utxos){
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

static std::string fmt_amount(uint64_t v){
    std::ostringstream s; s << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
    return s.str();
}

// -------------------------------------------------------------
// Auto-balance flow (non-interactive)
// -------------------------------------------------------------
static int run_auto_balance(const std::string& cli_host,
                            const std::string& cli_port,
                            bool allow_localhost)
{
    std::cout << "Chain: " << CHAIN_NAME << "  (auto-balance)\n";

    // Wallet dir
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    // Load wallet (empty pass first, then MIQ_WALLET_PASSPHRASE)
    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass;
    if(!miq::LoadHdWallet(wdir, seed, meta, pass, e)){
        const char* pe = std::getenv("MIQ_WALLET_PASSPHRASE");
        if(pe) pass = pe;
        if(!miq::LoadHdWallet(wdir, seed, meta, pass, e)){
            std::cout << "Load wallet failed: " << e << "\n";
            std::cout << "Tip: set MIQ_WALLET_PASSPHRASE env if your wallet is encrypted.\n";
            return 2;
        }
    }
    miq::HdWallet w(seed, meta);

    // Derive PKHs with +20 lookahead
    struct Key { std::vector<uint8_t> pub, pkh; };
    std::vector<Key> keys;
    auto add_range = [&](uint32_t chain, uint32_t upto){
        for(uint32_t i=0;i<=upto + 20; ++i){
            Key k; std::vector<uint8_t> prv;
            if(!w.DerivePrivPub(meta.account, chain, i, prv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            keys.push_back(std::move(k));
        }
    };
    add_range(0, meta.next_recv);
    add_range(1, meta.next_change);
    if(keys.empty()){
        std::cout << "No keys derived (wallet metadata empty?).\n";
        return 3;
    }

    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    // Seeds (remote-only unless allowed)
    const bool allow_local = allow_localhost || env_truthy("MIQ_ALLOW_LOCALHOST");
    auto seeds = build_seed_candidates(cli_host, cli_port, allow_local);
    std::cout << "Seed order: ";
    for(size_t i=0;i<seeds.size();++i){
        if(i) std::cout << ", ";
        std::cout << seeds[i].first << ":" << seeds[i].second;
    }
    std::cout << "\n";

    // SPV window
    const uint32_t spv_win = (uint32_t)get_env_u64("MIQ_SPV_WINDOW", 200000);
    std::cout << "SPV recent window: " << spv_win << " blocks\n";

    // Collect UTXOs
    std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!try_spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err)){
        std::cout << "SPV failed:\n" << err << "\n";
        std::cout << "Hint: pass --p2pseed=host:port or set MIQ_P2P_SEED=host1:port,host2:port\n";
        return 4;
    }

    // Pending-spent cache (prune entries that no longer exist)
    std::set<OutpointKey> pending;
    load_pending(wdir, pending);
    {
        std::set<OutpointKey> cur;
        for(const auto& u : utxos){
            cur.insert(OutpointKey{ miq::to_hex(u.txid), u.vout });
        }
        for(auto it = pending.begin(); it != pending.end(); ){
            if(cur.find(*it) == cur.end()) it = pending.erase(it);
            else ++it;
        }
        save_pending(wdir, pending);
    }

    // Compute totals
    WalletBalance wb = compute_balance(utxos, pending);

    std::cout << "Balance via " << used_seed << ":\n";
    std::cout << "  Total:       " << fmt_amount(wb.total)        << " MIQ  (" << wb.total        << " miqron)\n";
    std::cout << "  Spendable:   " << fmt_amount(wb.spendable)    << " MIQ  (" << wb.spendable    << " miqron)\n";
    std::cout << "  Immature:    " << fmt_amount(wb.immature)     << " MIQ  (" << wb.immature     << " miqron)\n";
    std::cout << "  Pending-hold:" << fmt_amount(wb.pending_hold) << " MIQ  (" << wb.pending_hold << " miqron)\n";

    return 0;
}

// -------------------------------------------------------------
// Interactive menu (optional)
// -------------------------------------------------------------
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

static bool p2p_broadcast_tx_one(const std::string& seed_host, const std::string& seed_port,
                                 const std::vector<uint8_t>& raw_tx,
                                 std::string& err)
{
    miq::P2POpts o;
    o.host = seed_host;
    o.port = seed_port;
    o.user_agent = "/miqwallet-p2p:0.2/";
    o.io_timeout_ms = 5000; // P2PLight knob
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
    std::ostringstream diag;
    bool any_attempt=false;
    for(const auto& [h,p] : seeds){
        any_attempt=true;
        std::string e;
        if(p2p_broadcast_tx_one(h, p, raw, e)){
            used_host = h + ":" + p;
            return true;
        }
        diag << "  - " << h << ":" << p << " -> " << (e.empty() ? "connect failed" : e) << "\n";
        last_err = e.empty() ? "connect failed" : e;
    }
    if(!any_attempt) last_err = "no seeds available";
    else last_err = std::string("all seeds failed:\n") + diag.str();
    return false;
}

// Minimal interactive bits kept (send, balance, create/recover)
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

static bool show_balance_interactive(const std::string& cli_host,
                                     const std::string& cli_port,
                                     bool allow_localhost)
{
    // Wallet dir
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    // Load (ask pass)
    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass;
    std::cout << "Wallet passphrase (ENTER if none): ";
    std::getline(std::cin, pass);
    if(!miq::LoadHdWallet(wdir, seed, meta, pass, e)){ std::cout << "Load wallet failed: " << e << "\n"; return false; }
    miq::HdWallet w(seed, meta);

    // Keys with lookahead
    struct Key { std::vector<uint8_t> pub, pkh; };
    std::vector<Key> keys;
    auto add_range = [&](uint32_t chain, uint32_t upto){
        for(uint32_t i=0;i<=upto + 20; ++i){
            Key k; std::vector<uint8_t> prv;
            if(!w.DerivePrivPub(meta.account, chain, i, prv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            keys.push_back(std::move(k));
        }
    };
    add_range(0, meta.next_recv);
    add_range(1, meta.next_change);

    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    const bool allow_local = allow_localhost || env_truthy("MIQ_ALLOW_LOCALHOST");
    auto seeds = build_seed_candidates(cli_host, cli_port, allow_local);

    const uint32_t spv_win = (uint32_t)get_env_u64("MIQ_SPV_WINDOW", 200000);

    std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!try_spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err)){
        std::cout << "SPV failed:\n" << err << "\n";
        return false;
    }

    std::set<OutpointKey> pending;
    load_pending(wdir, pending);
    {
        std::set<OutpointKey> cur;
        for(const auto& u : utxos){
            cur.insert(OutpointKey{ miq::to_hex(u.txid), u.vout });
        }
        for(auto it = pending.begin(); it != pending.end(); ){
            if(cur.find(*it) == cur.end()) it = pending.erase(it);
            else ++it;
        }
        save_pending(wdir, pending);
    }

    WalletBalance wb = compute_balance(utxos, pending);

    std::cout << "Balance via " << used_seed << ":\n";
    std::cout << "  Total:       " << fmt_amount(wb.total)        << " MIQ  (" << wb.total        << " miqron)\n";
    std::cout << "  Spendable:   " << fmt_amount(wb.spendable)    << " MIQ  (" << wb.spendable    << " miqron)\n";
    std::cout << "  Immature:    " << fmt_amount(wb.immature)     << " MIQ  (" << wb.immature     << " miqron)\n";
    std::cout << "  Pending-hold:" << fmt_amount(wb.pending_hold) << " MIQ  (" << wb.pending_hold << " miqron)\n";
    return true;
}

// -------------------------------------------------------------
// main
// -------------------------------------------------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    // Defaults: auto-balance; remote-only; no localhost.
    bool interactive = false;
    bool allow_localhost = false;

    std::string cli_host;
    std::string cli_port = std::to_string(miq::P2P_PORT);

    // Parse flags
    for(int i=1;i<argc;i++){
        std::string a = argv[i];
        auto eat_str = [&](const char* k, std::string& dst)->bool{
            size_t L = std::strlen(k);
            if(a.rfind(k, 0)==0){
                if(a.size()>L && a[L]=='='){ dst = a.substr(L+1); return true; }
                if(i+1<argc){ dst = argv[++i]; return true; }
            }
            return false;
        };
        if(a=="--interactive"){ interactive = true; continue; }
        if(a=="--allow-localhost"){ allow_localhost = true; continue; }
        if(eat_str("--p2pseed", cli_host)) { auto c=cli_host.find(':'); if(c!=std::string::npos){ cli_port=cli_host.substr(c+1); cli_host=cli_host.substr(0,c);} continue; }
        if(eat_str("--p2pport", cli_port)) continue;
    }

    if(!interactive){
        int rc = run_auto_balance(cli_host, cli_port, allow_localhost);
#ifdef _WIN32
        // Keep console open when double-clicked
        std::cout << "\nPress Enter to exit…";
        std::string dummy; std::getline(std::cin, dummy);
#endif
        return rc;
    }

    // Interactive menu
    std::cout << "Chain: " << CHAIN_NAME << "  (interactive)\n";
    {
        auto seeds = build_seed_candidates(cli_host, cli_port, allow_localhost);
        std::cout << "Seed order:";
        for(size_t i=0;i<seeds.size();++i){
            if(i==0) std::cout << " ";
            else     std::cout << ", ";
            std::cout << seeds[i].first << ":" << seeds[i].second;
        }
        std::cout << "\n";
    }

    for(;;){
        std::cout << "\n==== MIQ Wallet (Interactive) ====\n";
        std::cout << "1) Create wallet\n";
        std::cout << "2) Recover wallet\n";
        std::cout << "3) Show balance (SPV)\n";
        std::cout << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="1"){ (void)make_or_restore_wallet(false); }
        else if(c=="2"){ (void)make_or_restore_wallet(true); }
        else if(c=="3"){ (void)show_balance_interactive(cli_host, cli_port, allow_localhost); }
        else if(c=="q"||c=="Q"||c=="exit") break;
    }
    return 0;
}
