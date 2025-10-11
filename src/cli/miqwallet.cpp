// src/cli/miqwallet.cpp
// MIQ wallet CLI (Remote P2P/SPV; create or load from seed; show balance; send).
//
// - First screen: 1) Create wallet  2) Load wallet from seed
// - Remote-only by default (no localhost unless --allow-localhost).
// - Seeds: --p2pseed → MIQ_P2P_SEED (comma list) → 62.38.73.147 → DNS seeds → localhost (opt).
// - Correct SaveHdWallet signature (5 args) and NO use of HdWallet::seed().
// - Coinbase maturity respected; pending-spent cache to avoid double-spend before confirmation.
// - Uses MIQ_WALLET_PASSPHRASE env if present to re-save metadata without re-prompt.
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
#include <unordered_map>
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

static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}
static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v) return false;
    std::string s = v;
    for(char& c: s) c = (char)std::tolower((unsigned char)c);
    return (s=="1" || s=="true" || s=="yes" || s=="on");
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

// -------- Pending-spent cache --------
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

// -------- Seeds (remote-first; your IP prioritized) --------
static std::vector<std::pair<std::string,std::string>>
build_seed_candidates(const std::string& cli_host, const std::string& cli_port, bool allow_localhost)
{
    std::vector<std::pair<std::string,std::string>> seeds;

    // 0) CLI explicit
    if(!cli_host.empty()){
        seeds.emplace_back(cli_host, cli_port);
    }

    // 1) MIQ_P2P_SEED env (comma list)
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

    // 2) User’s working public node (prioritized)
    seeds.emplace_back("62.38.73.147", std::to_string(miq::P2P_PORT));

    // 3) DNS seeds
    seeds.emplace_back(miq::DNS_SEED, std::to_string(miq::P2P_PORT));
    for(size_t i=0;i<miq::DNS_SEEDS_COUNT;i++){
        seeds.emplace_back(miq::DNS_SEEDS[i], std::to_string(miq::P2P_PORT));
    }

    // 4) Optional localhost
    if(allow_localhost){
        seeds.emplace_back("127.0.0.1", std::to_string(miq::P2P_PORT));
        seeds.emplace_back("::1",       std::to_string(miq::P2P_PORT));
        seeds.emplace_back("localhost", std::to_string(miq::P2P_PORT));
    }

    // de-dup
    std::vector<std::pair<std::string,std::string>> uniq;
    std::unordered_set<std::string> seen;
    for(auto& hp: seeds){
        std::string key = hp.first + ":" + hp.second;
        if(seen.insert(key).second) uniq.push_back(hp);
    }
    return uniq;
}

// -------- SPV collect with diagnostics --------
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

// -------- Helpers: amounts, fees, tx broadcast --------
static std::string fmt_amount(uint64_t v){
    std::ostringstream s; s << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
    return s.str();
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

static bool p2p_broadcast_tx_one(const std::string& seed_host, const std::string& seed_port,
                                 const std::vector<uint8_t>& raw_tx,
                                 std::string& err)
{
    miq::P2POpts o;
    o.host = seed_host;
    o.port = seed_port;
    o.user_agent = "/miqwallet:1.0/";
    o.io_timeout_ms = 6000; // knob in P2PLight
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

// -------- Wallet balance computation --------
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

// -------- Derivation & addresses --------
struct KeyRec { std::vector<uint8_t> priv, pub, pkh; uint32_t chain{0}, index{0}; };
static void derive_key_horizon(miq::HdWallet& w, const miq::HdAccountMeta& meta,
                               std::vector<KeyRec>& out)
{
    auto push_range = [&](uint32_t chain, uint32_t upto){
        for(uint32_t i=0;i<=upto + 20; ++i){
            KeyRec k; k.chain=chain; k.index=i;
            if(!w.DerivePrivPub(meta.account, chain, i, k.priv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            out.push_back(std::move(k));
        }
    };
    out.clear();
    push_range(0, meta.next_recv);
    push_range(1, meta.next_change);
}
static void list_receive_addresses(miq::HdWallet& w, const miq::HdAccountMeta& meta){
    std::cout << "Receive addresses (m/44'/coin'/0'/0/i):\n";
    for(uint32_t i=0;i<=meta.next_recv + 20; ++i){
        std::vector<uint8_t> prv, pub;
        if(!w.DerivePrivPub(meta.account, 0, i, prv, pub)) continue;
        auto pkh = miq::hash160(pub);
        std::string addr = miq::base58check_encode(miq::VERSION_P2PKH, pkh);
        std::cout << "  [" << i << "] " << addr << "\n";
    }
}

// -------- Send flow --------
static bool send_flow(miq::HdWallet& w,
                      miq::HdAccountMeta& meta,
                      const std::string& wdir,
                      const std::string& pass_for_store,
                      const std::vector<uint8_t>& seed,
                      const std::vector<std::pair<std::string,std::string>>& seeds)
{
    // Prompt dest & amount
    std::string to, amt;
    std::cout << "Recipient address: "; std::getline(std::cin, to); to=trim(to);
    std::cout << "Amount (MIQ, e.g. 1.23456789): "; std::getline(std::cin, amt); amt=trim(amt);
    uint64_t amount=0; try{ amount = parse_amount_miqron(amt);}catch(...){ std::cout<<"Bad amount\n"; return false;}

    // Decode dest
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!miq::base58check_decode(to, ver, payload) || ver!=miq::VERSION_P2PKH || payload.size()!=20){
        std::cout << "Bad address.\n"; return false;
    }

    // Keys + PKHs
    std::vector<KeyRec> keys; derive_key_horizon(w, meta, keys);
    if(keys.empty()){ std::cout << "No keys available.\n"; return false; }
    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    // SPV snapshot
    const uint32_t spv_win = (uint32_t)get_env_u64("MIQ_SPV_WINDOW", 200000);
    std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
    std::cout << "Syncing (P2P/SPV)…\n";
    if(!try_spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err)){
        std::cout << "SPV failed:\n" << err << "\n";
        return false;
    }

    // Pending-hold cache (FIRST declaration)
    std::set<OutpointKey> pending;
    load_pending(wdir, pending);

    // Filter spendables (exclude immature coinbase & pending holds)
    uint64_t approx_tip_h = 0; for(const auto& u: utxos) approx_tip_h = std::max<uint64_t>(approx_tip_h, u.height);
    auto is_spendable = [&](const miq::UtxoLite& u)->bool{
        if(u.coinbase){
            uint64_t m = (uint64_t)u.height + (uint64_t)miq::COINBASE_MATURITY;
            if(approx_tip_h + 1 < m) return false;
        }
        OutpointKey k{ miq::to_hex(u.txid), u.vout };
        if(pending.find(k) != pending.end()) return false;
        return true;
    };

    std::vector<miq::UtxoLite> sp;
    for(const auto& u: utxos) if(is_spendable(u)) sp.push_back(u);
    if(sp.empty()){ std::cout<<"No spendable UTXOs.\n"; return false; }

    // Coin selection: prefer non-coinbase, then larger
    std::stable_sort(sp.begin(), sp.end(), [](const miq::UtxoLite& a, const miq::UtxoLite& b){
        if(a.coinbase != b.coinbase) return !a.coinbase && b.coinbase; // non-coinbase first
        return a.value > b.value; // larger first
    });

    miq::Transaction tx; uint64_t in_sum=0;
    for(const auto& u : sp){
        miq::TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
        tx.vin.push_back(in);
        in_sum += u.value;
        uint64_t fee_guess = fee_for(tx.vin.size(), 2, 1000);
        if(in_sum >= amount + fee_guess) break;
    }
    if(tx.vin.empty()){ std::cout<<"Insufficient funds.\n"; return false; }

    // Outputs + fee/change
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

    // Sign
    auto sighash = [&](){ miq::Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); } return miq::dsha256(miq::ser_tx(t)); }();
    auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const KeyRec*{
        for(const auto& k: keys) if(k.pkh==pkh) return &k;
        return nullptr;
    };
    for(auto& in : tx.vin){
        const miq::UtxoLite* u=nullptr;
        for(const auto& x: sp) if(x.txid==in.prev.txid && x.vout==in.prev.vout){ u=&x; break; }
        if(!u){ std::cout << "internal: utxo lookup failed\n"; return false; }
        auto* K = find_key_for_pkh(u->pkh);
        if(!K){ std::cout << "internal: key lookup failed\n"; return false; }
        std::vector<uint8_t> sig64;
        if(!miq::crypto::ECDSA::sign(K->priv, sighash, sig64)){ std::cout << "sign failed\n"; return false; }
        in.sig = sig64; in.pubkey = K->pub;
    }

    // Broadcast
    auto raw = miq::ser_tx(tx);
    std::string txid_hex = miq::to_hex(tx.txid());
    std::string used_bcast_seed, berr;
    std::cout << "Broadcasting (P2P)…\n";
    if(!try_broadcast_any_seed(seeds, raw, used_bcast_seed, berr)){
        std::cout << "Broadcast failed:\n" << berr << "\n";
        return false;
    }
    std::cout << "Broadcasted via " << used_bcast_seed << "  txid=" << txid_hex << "\n";

    // Reuse SAME 'pending' (no redefinition). Reload, mark, save.
    load_pending(wdir, pending); // refresh from disk
    for(const auto& in : tx.vin){
        pending.insert(OutpointKey{ miq::to_hex(in.prev.txid), in.prev.vout });
    }
    save_pending(wdir, pending);

    if(used_change){
        miq::HdAccountMeta m2 = meta; m2.next_change = meta.next_change + 1;
        std::string e;
        if(!miq::SaveHdWallet(wdir, seed, m2, pass_for_store, e)){
            std::cout << "WARN: SaveHdWallet(next_change) failed: " << e << "\n";
        } else {
            meta = m2;
        }
    }
    return true;
}

// -------- Dashboard after wallet is loaded --------
static void run_dashboard(miq::HdWallet& w,
                          miq::HdAccountMeta& meta,
                          const std::string& wdir,
                          const std::string& pass_for_store,
                          const std::vector<uint8_t>& seed,
                          const std::vector<std::pair<std::string,std::string>>& seeds)
{
    for(;;){
        // derive keys to pkhs
        std::vector<KeyRec> keys; derive_key_horizon(w, meta, keys);
        std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
        for(auto& k: keys) pkhs.push_back(k.pkh);

        const uint32_t spv_win = (uint32_t)get_env_u64("MIQ_SPV_WINDOW", 200000);

        // collect utxos
        std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
        std::cout << "\nSyncing (P2P/SPV)…\n";
        bool have_utxos = try_spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err);
        if(!have_utxos){
            std::cout << "SPV failed:\n" << err << "\n";
            used_seed = "<no-conn>";
        }

        // pending cache (prune missing)
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

        std::cout << "=== Wallet (" << CHAIN_NAME << ") via " << used_seed << " ===\n";
        std::cout << "Total:        " << fmt_amount(wb.total)        << " MIQ  (" << wb.total        << ")\n";
        std::cout << "Spendable:    " << fmt_amount(wb.spendable)    << " MIQ  (" << wb.spendable    << ")\n";
        std::cout << "Immature:     " << fmt_amount(wb.immature)     << " MIQ  (" << wb.immature     << ")\n";
        std::cout << "Pending-hold: " << fmt_amount(wb.pending_hold) << " MIQ  (" << wb.pending_hold << ")\n";

        std::cout << "\nOptions:\n";
        std::cout << "  1) List receive addresses\n";
        std::cout << "  2) Send MIQ\n";
        std::cout << "  r) Refresh balance\n";
        std::cout << "  q) Quit\n> ";

        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="1"){ list_receive_addresses(w, meta); continue; }
        if(c=="2"){
            (void)send_flow(w, meta, wdir, pass_for_store, seed, seeds);
            continue;
        }
        if(c=="r"||c=="R"){ continue; }
        if(c=="q"||c=="Q"||c=="exit") break;
    }
}

// -------- Create wallet --------
static bool flow_create_wallet(miq::HdWallet& outW,
                               miq::HdAccountMeta& outMeta,
                               std::string& outWdir,
                               std::string& outPass,
                               std::vector<uint8_t>& outSeed)
{
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    std::string wpass;
    std::cout << "Wallet encryption passphrase to store (ENTER for none): ";
    std::getline(std::cin, wpass);

    std::string outmn;
    if(!miq::HdWallet::GenerateMnemonic(128, outmn)) { std::cout << "mnemonic generation failed\n"; return false; }
    std::cout << "\nYour mnemonic (WRITE IT DOWN safely):\n  " << outmn << "\n\n";

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(outmn, /*mpass*/"", seed)) { std::cout << "mnemonic->seed failed\n"; return false; }

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)) { std::cout << "save failed: " << e << "\n"; return false; }

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)) { std::cout << "derive address failed\n"; return false; }
    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)) { std::cout << "save meta failed: " << e << "\n"; }
    std::cout << "First receive address: " << addr << "\n";

    outW = w; outMeta = w.meta(); outWdir = wdir; outPass = wpass; outSeed = seed;
    return true;
}

// -------- Load wallet from seed --------
static bool flow_load_from_seed(miq::HdWallet& outW,
                                miq::HdAccountMeta& outMeta,
                                std::string& outWdir,
                                std::string& outPass,
                                std::vector<uint8_t>& outSeed)
{
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    std::cout << "Paste 12/24-word mnemonic:\n> ";
    std::string mnemonic; std::getline(std::cin, mnemonic); mnemonic = trim(mnemonic);

    std::cout << "Mnemonic passphrase (ENTER for none): ";
    std::string mpass; std::getline(std::cin, mpass);

    std::cout << "Wallet encryption passphrase to store (ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) { std::cout << "mnemonic->seed failed\n"; return false; }

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)) {
        std::cout << "save failed: " << e << "\n";
    } else {
        // derive first receive so next_recv increments
        miq::HdWallet tmp(seed, meta);
        std::string addr; tmp.GetNewAddress(addr);
        if(!miq::SaveHdWallet(wdir, seed, tmp.meta(), wpass, e)){
            std::cout << "save meta failed: " << e << "\n";
        } else {
            meta = tmp.meta();
            std::cout << "First receive address: " << addr << "\n";
        }
    }

    miq::HdWallet w(seed, meta);
    outW = w; outMeta = meta; outWdir = wdir; outPass = wpass; outSeed = seed;
    return true;
}

// -------- main --------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

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
        if(a=="--allow-localhost"){ allow_localhost = true; continue; }
        if(eat_str("--p2pseed", cli_host)) { auto c=cli_host.find(':'); if(c!=std::string::npos){ cli_port=cli_host.substr(c+1); cli_host=cli_host.substr(0,c);} continue; }
        if(eat_str("--p2pport", cli_port)) continue;
    }

    // Seeds preview
    {
        auto seeds = build_seed_candidates(cli_host, cli_port, allow_localhost);
        std::cout << "Chain: " << CHAIN_NAME << "\n";
        std::cout << "Seed order:";
        for(size_t i=0;i<seeds.size();++i){
            if(i==0) std::cout << " ";
            else     std::cout << ", ";
            std::cout << seeds[i].first << ":" << seeds[i].second;
        }
        std::cout << "\n";
    }

    // Two-option menu (as requested)
    for(;;){
        std::cout << "\n=== MIQ Wallet ===\n";
        std::cout << "1) Create wallet\n";
        std::cout << "2) Load wallet from seed\n";
        std::cout << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="q"||c=="Q"||c=="exit"){ return 0; }

        miq::HdWallet w({}, {}); // will be replaced by flows
        miq::HdAccountMeta meta{};
        std::string wdir, wpass;
        std::vector<uint8_t> seed;

        bool ok=false;
        if(c=="1"){ ok = flow_create_wallet(w, meta, wdir, wpass, seed); }
        else if(c=="2"){ ok = flow_load_from_seed(w, meta, wdir, wpass, seed); }
        else { continue; }

        if(!ok) continue;

        // Build seeds for dashboard
        const bool allow_local = allow_localhost || env_truthy("MIQ_ALLOW_LOCALHOST");
        auto seeds = build_seed_candidates(cli_host, cli_port, allow_local);

        run_dashboard(w, meta, wdir, wpass, seed, seeds);
        // loop back to main menu after exit
    }
}
