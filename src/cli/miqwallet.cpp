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

// -------------------------------------------------------------
// Small utils
// -------------------------------------------------------------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}
static uint64_t env_u64(const char* name, uint64_t defv){
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
static std::string default_wallet_dir(){
    std::string wfile = miq::default_wallet_file();
    if(!wfile.empty()){
        size_t pos = wfile.find_last_of("/\\"); if(pos!=std::string::npos) wfile = wfile.substr(0,pos);
        return wfile;
    }
    return "wallets/default";
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
// Seeds (remote-first, plus smart localhost fallback)
// -------------------------------------------------------------
static void push_unique(std::vector<std::pair<std::string,std::string>>& v,
                        const std::string& h, const std::string& p,
                        std::unordered_set<std::string>& seen)
{
    std::string key = h + ":" + p;
    if(seen.insert(key).second) v.emplace_back(h,p);
}

// if env MIQ_DISABLE_LOCAL=1 -> no localhost fallback
static std::vector<std::pair<std::string,std::string>>
build_seed_candidates(const std::string& cli_host, const std::string& cli_port)
{
    std::vector<std::pair<std::string,std::string>> seeds;
    std::unordered_set<std::string> seen;

    // 0) CLI seed (if provided)
    if(!cli_host.empty()){
        push_unique(seeds, cli_host, cli_port, seen);
    }

    // 1) MIQ_P2P_SEED (comma list)
    if(const char* e = std::getenv("MIQ_P2P_SEED"); e && *e){
        std::string v = e;
        size_t start = 0;
        while(start < v.size()){
            size_t comma = v.find(',', start);
            std::string tok = (comma==std::string::npos)? v.substr(start) : v.substr(start, comma-start);
            auto c = tok.find(':');
            if(c != std::string::npos) push_unique(seeds, tok.substr(0,c), tok.substr(c+1), seen);
            else                       push_unique(seeds, tok, std::to_string(miq::P2P_PORT), seen);
            if(comma==std::string::npos) break;
            start = comma + 1;
        }
    }

    // 2) Your public node first by default (works "everywhere")
    push_unique(seeds, "62.38.73.147", std::to_string(miq::P2P_PORT), seen);

    // 3) DNS seeds
    push_unique(seeds, miq::DNS_SEED, std::to_string(miq::P2P_PORT), seen);
    for(size_t i=0;i<miq::DNS_SEEDS_COUNT;i++){
        push_unique(seeds, miq::DNS_SEEDS[i], std::to_string(miq::P2P_PORT), seen);
    }

    // 4) Smart localhost fallback unless disabled
    if(!env_truthy("MIQ_DISABLE_LOCAL")){
        push_unique(seeds, "127.0.0.1", std::to_string(miq::P2P_PORT), seen);
        push_unique(seeds, "::1",       std::to_string(miq::P2P_PORT), seen);
        push_unique(seeds, "localhost", std::to_string(miq::P2P_PORT), seen);
    }

    return seeds;
}

// -------------------------------------------------------------
// SPV collection and broadcast helpers
// -------------------------------------------------------------
static bool spv_collect_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
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
    bool any=false;

    for(const auto& [h,p] : seeds){
        any=true;
        std::vector<miq::UtxoLite> v; std::string e;
        if(miq::spv_collect_utxos(h, p, pkhs, opts, v, e)){
            out.swap(v);
            used_host = h + ":" + p;
            return true;
        }
        diag << "  - " << h << ":" << p << " -> " << (e.empty() ? "connect failed" : e) << "\n";
        last_err = e.empty() ? "connect failed" : e;
    }
    if(!any) last_err = "no seeds available";
    else last_err = std::string("all seeds failed:\n") + diag.str();
    return false;
}

static bool p2p_broadcast_tx_one(const std::string& seed_host, const std::string& seed_port,
                                 const std::vector<uint8_t>& raw_tx,
                                 std::string& err)
{
    miq::P2POpts o;
    o.host = seed_host;
    o.port = seed_port;
    o.user_agent = "/miqwallet:1.0/";
    o.io_timeout_ms = 8000; // keep conservative but robust
    miq::P2PLight p2p;
    if(!p2p.connect_and_handshake(o, err)) return false;
    bool ok = p2p.send_tx(raw_tx, err);
    p2p.close();
    return ok;
}

static bool broadcast_any_seed(const std::vector<std::pair<std::string,std::string>>& seeds,
                               const std::vector<uint8_t>& raw,
                               std::string& used_host,
                               std::string& last_err)
{
    used_host.clear(); last_err.clear();
    std::ostringstream diag;
    bool any=false;
    for(const auto& [h,p] : seeds){
        any=true;
        std::string e;
        if(p2p_broadcast_tx_one(h,p,raw,e)){
            used_host = h + ":" + p;
            return true;
        }
        diag << "  - " << h << ":" << p << " -> " << (e.empty() ? "connect failed" : e) << "\n";
        last_err = e.empty() ? "connect failed" : e;
    }
    if(!any) last_err = "no seeds available";
    else last_err = std::string("all seeds failed:\n") + diag.str();
    return false;
}

// -------------------------------------------------------------
// Amount + fee helpers
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
static std::string fmt_amount(uint64_t v){
    std::ostringstream s; s << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
    return s.str();
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

// -------------------------------------------------------------
// Wallet session (show balance + send)
// -------------------------------------------------------------
static bool wallet_session(const std::string& cli_host,
                           const std::string& cli_port,
                           std::vector<uint8_t> seed,
                           miq::HdAccountMeta meta,
                           const std::string& pass)
{
    miq::HdWallet w(seed, meta);
    const std::string wdir = default_wallet_dir();

    // derive a key horizon (+20 lookahead)
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
    const uint32_t GAP = (uint32_t)env_u64("MIQ_GAP_LIMIT", 100);
    uint32_t end_recv = meta.next_recv + GAP;
    add_range(0, end_recv);
    uint32_t end_change = meta.next_change + GAP;
    add_range(1, end_change);

    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);
    std::unordered_map<std::string, std::pair<uint32_t,uint32_t>> pkh2ci;
    for (auto& k: keys) { pkh2ci[miq::to_hex(k.pkh)] = {k.chain, k.index}; }

    auto seeds = build_seed_candidates(cli_host, cli_port);
    std::cout << "Chain: " << CHAIN_NAME << "\n";
    std::cout << "Seed order: ";
    for(size_t i=0;i<seeds.size();++i){
        if(i) std::cout << ", ";
        std::cout << seeds[i].first << ":" << seeds[i].second;
    }
    std::cout << "\n";

    const uint32_t spv_win = (uint32_t)env_u64("MIQ_SPV_WINDOW", 200000);

    // Load pending-spent cache
    std::set<OutpointKey> pending;
    load_pending(wdir, pending);

    auto refresh_and_print = [&]()->std::vector<miq::UtxoLite>{
        std::cout << "\nSyncing (P2P/SPV)…\n";
        std::vector<miq::UtxoLite> utxos; std::string used_seed, err;
        if(!spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err)){
            std::cout << "SPV failed:\n" << err << "\n";
            used_seed = "<no-conn>";
        }

        // prune pending entries that no longer exist
        {
            std::set<OutpointKey> cur;
            for(const auto& u : utxos) cur.insert(OutpointKey{ miq::to_hex(u.txid), u.vout });
            for(auto it = pending.begin(); it != pending.end(); ){
                if(cur.find(*it) == cur.end()) it = pending.erase(it);
                else ++it;
            }
            save_pending(wdir, pending);
        }

                // bump meta next indices based on highest seen PKH indexes in UTXOs
        {
            uint32_t max_recv = meta.next_recv;
            uint32_t max_change = meta.next_change;
            for (const auto& u: utxos) {
                auto it = pkh2ci.find(miq::to_hex(u.pkh));
                if (it != pkh2ci.end()) {
                    if (it->second.first == 0) max_recv = std::max<uint32_t>(max_recv, it->second.second + 1);
                    else if (it->second.first == 1) max_change = std::max<uint32_t>(max_change, it->second.second + 1);
                }
            }
            if (max_recv != meta.next_recv || max_change != meta.next_change) {
                auto m = meta; m.next_recv = max_recv; m.next_change = max_change;
                std::string e2; (void)e2;
                if(!miq::SaveHdWallet(wdir, seed, m, wpass, e2)) {
                    std::cout << "WARN: SaveHdWallet(next_*) failed: " << e2 << "\n";
                } else {
                    meta = m;
                }
            }
        }
WalletBalance wb = compute_balance(utxos, pending);
        std::cout << "=== Wallet (" << CHAIN_NAME << ") via " << used_seed << " ===\n";
        std::cout << "Total:        " << fmt_amount(wb.total)        << " MIQ  (" << wb.total        << ")\n";
        std::cout << "Spendable:    " << fmt_amount(wb.spendable)    << " MIQ  (" << wb.spendable    << ")\n";
        std::cout << "Immature:     " << fmt_amount(wb.immature)     << " MIQ  (" << wb.immature     << ")\n";
        std::cout << "Pending-hold: " << fmt_amount(wb.pending_hold) << " MIQ  (" << wb.pending_hold << ")\n";
        return utxos;
    };

    auto utxos = refresh_and_print();

    for(;;){
        std::cout << "\nOptions:\n"
                     "  1) List receive addresses\n"
                     "  2) Send MIQ\n"
                     "  r) Refresh balance\n"
                     "  q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);

        if(c=="1"){
            // list first N receive addresses (derived up to next_recv)
            int N = (int)meta.next_recv;
            if(N<=0) N = 1;
            std::cout << "Receive addresses:\n";
            for(int i=0;i<N;i++){
                std::string addr;
                miq::HdWallet tmp(seed, meta);
                if(tmp.GetAddressAt((uint32_t)i, addr)){
                    std::cout << "  ["<<i<<"] " << addr << "\n";
                }
            }
        } else if(c=="2"){
            // send funds
            std::cout << "Recipient address: "; std::string to; std::getline(std::cin, to); to=trim(to);
            std::cout << "Amount (MIQ, e.g. 1.23456789): "; std::string amt; std::getline(std::cin, amt); amt=trim(amt);
            uint64_t amount=0; try{ amount = parse_amount_miqron(amt);}catch(...){ std::cout<<"Bad amount\n"; continue;}

            // decode dest
            uint8_t ver=0; std::vector<uint8_t> payload;
            if(!miq::base58check_decode(to, ver, payload) || ver!=miq::VERSION_P2PKH || payload.size()!=20){
                std::cout << "Bad address.\n"; continue;
            }

            // recompute utxos fresh
            utxos = refresh_and_print();

            // filter for spendable (mature coinbase + not pending-held)
            // approximate tip height:
            uint64_t tip_h=0; for(const auto& u: utxos) tip_h = std::max<uint64_t>(tip_h, u.height);

            std::vector<miq::UtxoLite> spendables;
            for(const auto& u: utxos){
                bool immature=false;
                if(u.coinbase){
                    uint64_t mh = (uint64_t)u.height + (uint64_t)miq::COINBASE_MATURITY;
                    if(tip_h + 1 < mh) immature=true;
                }
                OutpointKey k{ miq::to_hex(u.txid), u.vout };
                if(!immature && pending.find(k)==pending.end())
                    spendables.push_back(u);
            }

            if(spendables.empty()){ std::cout<<"No spendable UTXOs (all immature or pending-held).\n"; continue; }

            // oldest-first, then larger
            std::stable_sort(spendables.begin(), spendables.end(), [](const miq::UtxoLite& a, const miq::UtxoLite& b){
                if(a.height != b.height) return a.height < b.height;
                return a.value > b.value;
            });

            miq::Transaction tx;
            uint64_t in_sum=0;
            for(const auto& u : spendables){
                miq::TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
                tx.vin.push_back(in);
                in_sum += u.value;
                uint64_t fee_guess = fee_for(tx.vin.size(), 2, 1000);
                if(in_sum >= amount + fee_guess) break;
            }
            if(tx.vin.empty()){ std::cout << "Insufficient funds.\n"; continue; }

            // outputs + fee
            uint64_t fee_final = 0, change = 0;
            {
                auto fee2 = fee_for(tx.vin.size(), 2, 1000);
                if(in_sum < amount + fee2){
                    auto fee1 = fee_for(tx.vin.size(), 1, 1000);
                    if(in_sum < amount + fee1){ std::cout << "Insufficient (need fee).\n"; continue; }
                    fee_final = fee1; change = 0;
                }else{
                    fee_final = fee2; change = in_sum - amount - fee_final;
                    if(change < 1000){ change = 0; fee_final = fee_for(tx.vin.size(), 1, 1000); }
                }
            }
            (void)fee_final; // implied by inputs-outputs

            miq::TxOut o; o.pkh = payload; o.value = amount; tx.vout.push_back(o);

            // change -> new change address
            bool used_change=false; std::vector<uint8_t> cpub, cpriv, cpkh;
            if(change>0){
                if(!w.DerivePrivPub(meta.account, 1, meta.next_change, cpriv, cpub)){ std::cout << "derive change failed\n"; continue; }
                cpkh = miq::hash160(cpub);
                miq::TxOut ch; ch.value = change; ch.pkh = cpkh; tx.vout.push_back(ch); used_change=true;
            }

            // sign inputs
            auto sighash = [&](){ miq::Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); } return miq::dsha256(miq::ser_tx(t)); }();
            auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const Key*{
                for(const auto& k: keys) if(k.pkh==pkh) return &k;
                return nullptr;
            };
            for(auto& in : tx.vin){
                const miq::UtxoLite* u=nullptr;
                for(const auto& x: utxos) if(x.txid==in.prev.txid && x.vout==in.prev.vout){ u=&x; break; }
                if(!u){ std::cout << "internal: utxo lookup failed\n"; goto send_done; }
                auto* K = find_key_for_pkh(u->pkh);
                if(!K){ std::cout << "internal: key lookup failed\n"; goto send_done; }
                std::vector<uint8_t> sig64;
                if(!miq::crypto::ECDSA::sign(K->priv, sighash, sig64)){ std::cout << "sign failed\n"; goto send_done; }
                in.sig = sig64; in.pubkey = K->pub;
            }

            {
                auto raw = miq::ser_tx(tx);
                std::string txid_hex = miq::to_hex(tx.txid());
                std::string used_bcast_seed, berr;
                auto seeds_b = build_seed_candidates(cli_host, cli_port);
                std::cout << "Broadcasting via P2P…\n";
                if(!broadcast_any_seed(seeds_b, raw, used_bcast_seed, berr)){
                    std::cout << "P2P broadcast failed:\n" << berr << "\n";
                    goto send_done;
                }
                std::cout << "Broadcasted via " << used_bcast_seed << ". Txid: " << txid_hex << "\n";

                // hold inputs in pending cache
                for(const auto& in : tx.vin){
                    pending.insert(OutpointKey{ miq::to_hex(in.prev.txid), in.prev.vout });
                }
                save_pending(wdir, pending);

                // bump change index if used
                if(used_change){
                    auto m = w.meta(); m.next_change = meta.next_change + 1;
                    std::string e;
                    if(!miq::SaveHdWallet(wdir, seed, m, pass, e)){
                        std::cout << "WARN: SaveHdWallet(next_change) failed: " << e << "\n";
                    } else {
                        meta = m; // keep in-session meta updated
                    }
                }
            }

        send_done:
            // refresh view
            utxos = refresh_and_print();
        } else if(c=="r" || c=="R"){
            utxos = refresh_and_print();
        } else if(c=="q" || c=="Q" || c=="exit"){
            break;
        }
    }

    return true;
}

// -------------------------------------------------------------
// Create wallet or Load-from-seed flows
// -------------------------------------------------------------
static bool flow_create_wallet(const std::string& cli_host, const std::string& cli_port){
    std::string wdir = default_wallet_dir();

    std::string wpass;
    std::cout << "Wallet encryption passphrase to store (ENTER for none): ";
    std::getline(std::cin, wpass);

    std::string mnemonic;
    if(!miq::HdWallet::GenerateMnemonic(128, mnemonic)) { std::cout << "mnemonic generation failed\n"; return false; }
    std::cout << "\nYour mnemonic:\n  " << mnemonic << "\n\n";

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, /*mpass*/"", seed)) { std::cout << "mnemonic->seed failed\n"; return false; }

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)){ std::cout << "save failed: " << e << "\n"; return false; }

    // produce first address
    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)) { std::cout << "derive address failed\n"; return false; }

    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)) { std::cout << "save meta failed: " << e << "\n"; }

    std::cout << "First receive address: " << addr << "\n";

    // straight into session
    return wallet_session(cli_host, cli_port, seed, w.meta(), wpass);
}

static bool flow_load_from_seed(const std::string& cli_host, const std::string& cli_port){
    std::string wdir = default_wallet_dir();

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
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)){ std::cout << "save failed: " << e << "\n"; return false; }

    // make first address now so wallet has next_recv advanced
    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)) { std::cout << "derive address failed\n"; return false; }
    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)) { std::cout << "save meta failed: " << e << "\n"; }
    std::cout << "First receive address: " << addr << "\n";

    return wallet_session(cli_host, cli_port, seed, w.meta(), wpass);
}

// -------------------------------------------------------------
// main
// -------------------------------------------------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

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
        if(eat_str("--p2pseed", cli_host)) { auto c=cli_host.find(':'); if(c!=std::string::npos){ cli_port=cli_host.substr(c+1); cli_host=cli_host.substr(0,c);} continue; }
        if(eat_str("--p2pport", cli_port)) continue;
    }

    std::cout << "Chain: " << CHAIN_NAME << "\n";
    std::cout << "Seed order: ";
    {
        auto seeds = build_seed_candidates(cli_host, cli_port);
        for(size_t i=0;i<seeds.size();++i){
            if(i) std::cout << ", ";
            std::cout << seeds[i].first << ":" << seeds[i].second;
        }
        std::cout << "\n";
    }

    for(;;){
        std::cout << "\n=== MIQ Wallet ===\n";
        std::cout << "1) Create wallet\n";
        std::cout << "2) Load wallet from seed\n";
        std::cout << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="1"){ (void)flow_create_wallet(cli_host, cli_port); }
        else if(c=="2"){ (void)flow_load_from_seed(cli_host, cli_port); }
        else if(c=="q"||c=="Q"||c=="exit") break;
    }
    return 0;
}
