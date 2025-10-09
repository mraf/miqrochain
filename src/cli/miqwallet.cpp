// MIQ wallet CLI (client-side signing, remote-node broadcast).
//
// - Auto-discovers RPC gateways (62.38.73.147:9834 + nodes.txt + MIQ_NODE_URLS).
// - Token auth (X-Auth-Token or Authorization: Bearer) handled by NodeClient.
// - Wallet is local: create/restore/load, derive addresses, construct + sign tx,
//   then broadcast via sendrawtransaction.
// - Simple menu: 1) Create  2) Recover  3) Send  4) Show balance  q) Quit

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <thread>
#include <cstdlib>

#ifdef _WIN32
  #include <windows.h>
  #pragma comment(lib, "ws2_32.lib")
#endif

// Project headers
#include "constants.h"          // CHAIN_NAME, RPC_PORT, COIN, VERSION_P2PKH, COINBASE_MATURITY
#include "wallet/paths.h"       // wallet_data_dir(), ensure_dir()
#include "wallet/node_client.h" // NodeClient, NodeEndpoint discovery
#include "hd_wallet.h"          // HdWallet
#include "wallet_store.h"       // SaveHdWallet / LoadHdWallet / default dirs
#include "serialize.h"          // JNode, json helpers
#include "tx.h"                 // Transaction, TxIn, TxOut, ser_tx
#include "sha256.h"             // dsha256
#include "hash160.h"            // hash160
#include "base58check.h"        // base58check_encode
#include "crypto/ecdsa_iface.h" // crypto::ECDSA::sign
#include "hex.h"                // to_hex/from_hex

using miq::CHAIN_NAME;
using miq::RPC_PORT;
using miq::COIN;
using miq::COINBASE_MATURITY;

#ifndef MIN_RELAY_FEE_RATE
// miqron per kB (1e-8 MIQ = 1 miqron)
static constexpr uint64_t MIN_RELAY_FEE_RATE = 1000;
#endif

#ifndef DUST_THRESHOLD
static constexpr uint64_t DUST_THRESHOLD = 1000; // 0.00001000 MIQ
#endif

// ---------- small helpers ----------
static inline std::string trim(std::string s){
    size_t a=0,b=s.size();
    while(a<b && std::isspace((unsigned char)s[a])) ++a;
    while(b>a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}

static std::string joinp(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}

static std::string fmt_miq(uint64_t miqron){
    std::ostringstream s;
    s << (miqron / COIN) << "." << std::setw(8) << std::setfill('0') << (miqron % COIN);
    return s.str();
}

static size_t estimate_size_bytes(size_t nin, size_t nout){
    // (rough conservative legacy P2PKH)
    return nin*148 + nout*34 + 10;
}
static uint64_t fee_for(size_t nin, size_t nout, uint64_t feerate){
    size_t sz = estimate_size_bytes(nin, nout);
    uint64_t kb = (uint64_t)((sz + 999) / 1000);
    if (kb==0) kb=1;
    return kb * feerate;
}

// ---- RPC thin wrapper on NodeClient ----
struct Rpc {
    miq::NodeClient* nc{nullptr};

    bool call(const std::string& method,
              const std::vector<miq::JNode>& params,
              miq::JNode& out,
              std::string& err) const
    {
        return nc && nc->call(method, params, out, err);
    }
};

static bool j_is_num(const miq::JNode& n){ return std::holds_alternative<double>(n.v); }
static bool j_is_str(const miq::JNode& n){ return std::holds_alternative<std::string>(n.v); }
static bool j_is_obj(const miq::JNode& n){ return std::holds_alternative<std::map<std::string,miq::JNode>>(n.v); }
static bool j_is_arr(const miq::JNode& n){ return std::holds_alternative<std::vector<miq::JNode>>(n.v); }
static double j_as_num(const miq::JNode& n){ return std::get<double>(n.v); }
static std::string j_as_str(const miq::JNode& n){ return std::get<std::string>(n.v); }
static const std::map<std::string,miq::JNode>& j_as_obj(const miq::JNode& n){ return std::get<std::map<std::string,miq::JNode>>(n.v); }
static const std::vector<miq::JNode>& j_as_arr(const miq::JNode& n){ return std::get<std::vector<miq::JNode>>(n.v); }

// ---------- Local wallet paths ----------
static std::string wallet_root(){
    auto d = miq::wallet_data_dir();                // e.g. ~/.miqwallet
    auto w = joinp(d, "wallets");
    miq::ensure_dir(w);
    return w;
}
static std::string default_wallet_dir(){
    auto w = joinp(wallet_root(), "default");
    miq::ensure_dir(w);
    return w;
}

// ---------- Core wallet ops (local) ----------
static bool create_wallet_local(std::string& out_mnemonic, const std::string& wpass){
    std::string mnemonic;
    if(!miq::HdWallet::GenerateMnemonic(128, mnemonic)) return false;

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, /*mpass*/"", seed)) return false;

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!SaveHdWallet(default_wallet_dir(), seed, meta, wpass, e)){
        std::cerr << "SaveHdWallet failed: " << e << "\n";
        return false;
    }
    out_mnemonic = mnemonic;
    return true;
}

static bool restore_wallet_local(const std::string& mnemonic, const std::string& mpass, const std::string& wpass){
    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) {
        std::cerr << "mnemonic->seed failed\n";
        return false;
    }
    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!SaveHdWallet(default_wallet_dir(), seed, meta, wpass, e)){
        std::cerr << "SaveHdWallet failed: " << e << "\n";
        return false;
    }
    return true;
}

static bool load_wallet(const std::string& wpass, std::vector<uint8_t>& seed, miq::HdAccountMeta& meta, std::string& e){
    return LoadHdWallet(default_wallet_dir(), seed, meta, wpass, e);
}

static std::string addr_from_pub(const std::vector<uint8_t>& pub){
    auto pkh = hash160(pub);
    std::string addr;
    base58check_encode(VERSION_P2PKH, pkh, addr);
    return addr;
}

// ---- Gather UTXOs for our derived addresses (gap-limit scan) ----
struct OwnedUtxo {
    std::vector<uint8_t> txid;
    uint32_t vout{0};
    uint64_t value{0};
    bool coinbase{false};
    uint64_t height{0};
    // key material to spend
    uint32_t chain{0};   // 0=recv, 1=change
    uint32_t index{0};
    std::vector<uint8_t> priv, pub, pkh;
};

static bool rpc_getaddressutxos(const Rpc& rpc, const std::string& addr,
                                std::vector<OwnedUtxo>& out)
{
    miq::JNode resp; std::string err;
    if(!rpc.call("getaddressutxos", { miq::JNode{addr} }, resp, err)) {
        std::cerr << "getaddressutxos rpc error: " << err << "\n";
        return false;
    }
    if(!j_is_arr(resp)) { return true; } // empty is fine
    for(const auto& n : j_as_arr(resp)){
        if(!j_is_obj(n)) continue;
        const auto& o = j_as_obj(n);
        OwnedUtxo u;
        auto it = o.find("txid");    if(it!=o.end() && j_is_str(it->second)) u.txid = from_hex(j_as_str(it->second));
        it = o.find("vout");         if(it!=o.end() && j_is_num(it->second)) u.vout = (uint32_t)j_as_num(it->second);
        it = o.find("value");        if(it!=o.end() && j_is_num(it->second)) u.value = (uint64_t)j_as_num(it->second);
        it = o.find("coinbase");     if(it!=o.end() && (std::holds_alternative<bool>(it->second.v))) u.coinbase = std::get<bool>(it->second.v);
        it = o.find("height");       if(it!=o.end() && j_is_num(it->second)) u.height = (uint64_t)j_as_num(it->second);
        out.push_back(std::move(u));
    }
    return true;
}

static bool wallet_collect_utxos(const Rpc& rpc,
                                 miq::HdWallet& w, const miq::HdAccountMeta& meta,
                                 std::vector<OwnedUtxo>& spendables,
                                 uint64_t& total, uint64_t& spendable, uint64_t& locked, uint64_t& curH)
{
    total = spendable = locked = 0;

    // Best height
    {
        miq::JNode h; std::string e;
        if(!rpc.call("getblockcount", {}, h, e)) { std::cerr << "getblockcount failed: " << e << "\n"; return false; }
        curH = (uint64_t)(j_is_num(h) ? j_as_num(h) : 0.0);
    }

    // BIP44-like gap limit scan (simple): scan next_recv + lookahead (20) for recv and change
    const uint32_t GAP = 20;
    auto scan_chain = [&](uint32_t chain, uint32_t start, uint32_t count){
        for(uint32_t i = start; i < start+count; ++i){
            std::vector<uint8_t> priv, pub;
            if(!w.DerivePrivPub(meta.account, chain, i, priv, pub)) continue;
            auto pkh = hash160(pub);
            std::string addr; base58check_encode(VERSION_P2PKH, pkh, addr);

            std::vector<OwnedUtxo> tmp;
            if(!rpc_getaddressutxos(rpc, addr, tmp)) return false;

            for(auto& u : tmp){
                OwnedUtxo o = u;
                o.chain = chain; o.index = i;
                o.priv = priv; o.pub = pub; o.pkh = pkh;
                total += o.value;

                bool spend_ok = true;
                if (o.coinbase) {
                    uint64_t mature_h = o.height + COINBASE_MATURITY;
                    if (curH + 1 < mature_h) { spend_ok = false; locked += o.value; }
                }
                if (spend_ok) { spendables.push_back(std::move(o)); spendable += u.value; }
            }
        }
        return true;
    };

    if(!scan_chain(0, 0, std::max<uint32_t>(meta.next_recv, GAP)))  return false;
    if(!scan_chain(1, 0, std::max<uint32_t>(meta.next_change, GAP)))return false;

    // Sort oldest-first (height asc, txid lex, vout asc)
    auto lex_less = [](const std::vector<uint8_t>& A, const std::vector<uint8_t>& B){
        return std::lexicographical_compare(A.begin(), A.end(), B.begin(), B.end());
    };
    std::sort(spendables.begin(), spendables.end(),
              [&](const OwnedUtxo& A, const OwnedUtxo& B){
                  if (A.height != B.height) return A.height < B.height;
                  if (A.txid != B.txid)     return lex_less(A.txid, B.txid);
                  return A.vout < B.vout;
              });
    return true;
}

// ---------- UI flows ----------
static bool flow_create(const Rpc& /*rpc*/){
    std::cout << "\n-- Create new HD wallet (LOCAL) --\n";
    std::cout << "Optional wallet passphrase (ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string mnemonic;
    if(!create_wallet_local(mnemonic, wpass)){
        std::cout << "Create failed.\n"; return false;
    }
    std::cout << "\nYour 12-word mnemonic (WRITE IT DOWN, keep offline!):\n\n  "
              << mnemonic << "\n\n";
    return true;
}

static bool flow_restore(const Rpc& /*rpc*/){
    std::cout << "\n-- Recover HD wallet (LOCAL) --\n";
    std::cout << "Paste 12 or 24-word mnemonic:\n> ";
    std::string mnemonic; std::getline(std::cin, mnemonic); mnemonic = trim(mnemonic);

    std::cout << "BIP39 mnemonic passphrase (ENTER if none): ";
    std::string mpass; std::getline(std::cin, mpass);

    std::cout << "Wallet encryption passphrase (new; ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    if(!restore_wallet_local(mnemonic, mpass, wpass)){
        std::cout << "Restore failed.\n"; return false;
    }
    std::cout << "Restored locally.\n";
    return true;
}

static bool flow_balance(const Rpc& rpc){
    std::cout << "\n-- Show balance --\n";
    std::cout << "Wallet passphrase (ENTER if not encrypted): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    if(!load_wallet(wpass, seed, meta, e)){ std::cout << "Load failed: " << e << "\n"; return false; }
    miq::HdWallet w(seed, meta);

    std::vector<OwnedUtxo> spendables;
    uint64_t total=0, spendable=0, locked=0, curH=0;
    if(!wallet_collect_utxos(rpc, w, meta, spendables, total, spendable, locked, curH)) return false;

    std::cout << "Total:     " << fmt_miq(total)     << " MIQ (" << total    << " miqron)\n";
    std::cout << "Spendable: " << fmt_miq(spendable) << " MIQ (" << spendable<< " miqron)\n";
    if(locked) std::cout << "Locked:    " << fmt_miq(locked)    << " MIQ (" << locked  << " miqron)\n";
    return true;
}

static bool in_mempool(const Rpc& rpc, const std::string& txid_hex){
    miq::JNode r; std::string e;
    if(!rpc.call("getrawmempool", {}, r, e)) return false;
    if(!j_is_arr(r)) return false;
    for(const auto& n : j_as_arr(r)){
        if(j_is_str(n) && j_as_str(n) == txid_hex) return true;
    }
    return false;
}

static int confs_for_tx_by_recipient(const Rpc& rpc, const std::string& txid_hex, const std::string& recipient_addr){
    if(in_mempool(rpc, txid_hex)) return 0;
    // crude: if it's mined, it should appear in UTXOs (if not spent); otherwise 0
    miq::JNode utx; std::string e;
    if(!rpc.call("getaddressutxos", { miq::JNode{recipient_addr} }, utx, e)) return 0;
    if(!j_is_arr(utx)) return 0;
    int mined_h = -1;
    for(const auto& n : j_as_arr(utx)){
        if(!j_is_obj(n)) continue;
        const auto& o = j_as_obj(n);
        auto it_txid = o.find("txid");
        if(it_txid==o.end() || !j_is_str(it_txid->second)) continue;
        if(j_as_str(it_txid->second) != txid_hex) continue;
        auto it_h = o.find("height");
        if(it_h!=o.end() && j_is_num(it_h->second)) { mined_h = (int)j_as_num(it_h->second); break; }
    }
    if(mined_h < 0) return 0;
    miq::JNode h; if(!rpc.call("getblockcount", {}, h, e)) return 0;
    int curH = (int)(j_is_num(h) ? j_as_num(h) : 0.0);
    int c = (curH - mined_h + 1); if(c<0) c=0;
    return c;
}

static bool flow_send(const Rpc& rpc){
    std::cout << "\n-- Send MIQ --\n";
    std::cout << "Wallet passphrase (ENTER if not encrypted): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    if(!load_wallet(wpass, seed, meta, e)){ std::cout << "Load failed: " << e << "\n"; return false; }
    miq::HdWallet w(seed, meta);

    std::cout << "Recipient address: ";
    std::string to; std::getline(std::cin, to); to = trim(to);

    std::cout << "Amount (MIQ, e.g. 1.23456789): ";
    std::string amt; std::getline(std::cin, amt); amt = trim(amt);

    // Parse amount to miqron
    uint64_t amount = 0;
    try {
        if(amt.find('.')!=std::string::npos){
            long double v = std::stold(amt);
            long double sat = v * (long double)COIN;
            if(sat < 0) throw std::runtime_error("neg");
            amount = (uint64_t)std::llround(sat);
        } else amount = (uint64_t)std::stoull(amt);
    } catch(...) { std::cout << "Bad amount.\n"; return false; }
    if(amount == 0){ std::cout << "Amount must be >0\n"; return false; }

    // Validate address
    uint8_t ver=0; std::vector<uint8_t> payload;
    if(!base58check_decode(to, ver, payload) || ver!=VERSION_P2PKH || payload.size()!=20){
        std::cout << "Bad recipient address.\n"; return false;
    }

    // Collect spendables
    std::vector<OwnedUtxo> spendables;
    uint64_t total=0, spendable=0, locked=0, curH=0;
    if(!wallet_collect_utxos(rpc, w, meta, spendables, total, spendable, locked, curH)) return false;
    if(spendables.empty()){ std::cout << "No spendable funds.\n"; return false; }

    // Select inputs
    Transaction tx;
    uint64_t in_sum = 0;
    uint64_t feerate = MIN_RELAY_FEE_RATE;

    for(size_t k=0; k<spendables.size(); ++k){
        const auto& u = spendables[k];
        TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
        tx.vin.push_back(in);
        in_sum += u.value;
        uint64_t fee_guess = fee_for(tx.vin.size(), /*nout*/2, feerate);
        if(in_sum >= amount + fee_guess) break;
    }
    if(tx.vin.empty()){ std::cout << "Insufficient funds.\n"; return false; }

    // Outputs: recipient + optional change
    TxOut out; out.pkh = payload; out.value = amount; tx.vout.push_back(out);

    uint64_t fee_final = fee_for(tx.vin.size(), /*nout 2 (with change tentative)*/2, feerate);
    uint64_t change = 0;
    if (in_sum < amount + fee_final) {
        fee_final = fee_for(tx.vin.size(), /*nout=1*/1, feerate);
        if (in_sum < amount + fee_final) { std::cout << "Insufficient after fee.\n"; return false; }
    } else {
        change = in_sum - amount - fee_final;
        if (change < DUST_THRESHOLD) {
            change = 0;
            fee_final = fee_for(tx.vin.size(), /*nout=1*/1, feerate);
            if (in_sum < amount + fee_final) { std::cout << "Insufficient after dust fold.\n"; return false; }
        }
    }

    // Change (new change address)
    std::vector<uint8_t> cpriv, cpub;
    std::vector<uint8_t> cpkh;
    bool used_change = false;
    if(change > 0){
        if(!w.DerivePrivPub(meta.account, /*chain=*/1, meta.next_change, cpriv, cpub)){
            std::cout << "Derive change failed.\n"; return false;
        }
        cpkh = hash160(cpub);
        TxOut ch; ch.value = change; ch.pkh = cpkh;
        tx.vout.push_back(ch);
        used_change = true;
    }

    // Sign
    auto sighash = [&](){ Transaction t=tx; for(auto& i : t.vin){ i.sig.clear(); i.pubkey.clear(); } return dsha256(ser_tx(t)); }();
    for(auto& in : tx.vin){
        const OwnedUtxo* key=nullptr;
        for(const auto& u : spendables){
            if(u.txid==in.prev.txid && u.vout==in.prev.vout){ key=&u; break; }
        }
        if(!key){ std::cout << "Internal key lookup failed.\n"; return false; }
        std::vector<uint8_t> sig;
        if(!crypto::ECDSA::sign(key->priv, sighash, sig)){ std::cout << "Sign failed.\n"; return false; }
        in.sig = sig; in.pubkey = key->pub;
    }

    // Broadcast
    std::string txhex = to_hex(ser_tx(tx));
    miq::JNode r; std::string err;
    if(!rpc.call("sendrawtransaction", { miq::JNode{txhex} }, r, err)){
        std::cout << "Broadcast RPC failed: " << err << "\n"; return false;
    }
    if(!j_is_str(r)){ std::cout << "Broadcast error: " << miq::json_dump(r) << "\n"; return false; }
    std::string txid_hex = j_as_str(r);
    std::cout << "Broadcasted. Txid: " << txid_hex << "\n";

    // Save wallet meta if we used a change index
    if(used_change){
        miq::HdAccountMeta newm = w.meta();
        newm.next_change = meta.next_change + 1;
        std::string se;
        if(!SaveHdWallet(default_wallet_dir(), seed, newm, wpass, se)){
            std::cerr << "Warning: failed to persist change index: " << se << "\n";
        }
    }

    // Watch for confirmations (target: 3)
    std::cout << "Waiting for confirmations (target: 3). Press Ctrl+C to stop.\n";
    int last=-1;
    std::string recipient_addr = to;
    for(;;){
        int c = confs_for_tx_by_recipient(rpc, txid_hex, recipient_addr);
        if(c!=last){
            if(c==0) std::cout << "  0-conf (in mempool or not yet visible)\n";
            else     std::cout << "  confirmations: " << c << "\n";
            last = c;
        }
        if(c>=3) break;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    std::cout << "Reached 3 confirmations.\n";
    return true;
}

// ---------- main ----------
int main(){
    std::ios::sync_with_stdio(false);

    // Auto-discover remote RPC endpoints (includes 62.38.73.147:9834 and local).
    auto datadir = miq::wallet_data_dir();
    auto eps = miq::discover_nodes(datadir, /*probe_timeout_ms=*/2000);
    miq::NodeClient nc(eps, /*timeout_ms=*/3000);
    Rpc rpc{ &nc };

    auto cur = nc.current();
    std::cout << "Target: " << CHAIN_NAME << " RPC at " << cur.host << ":" << cur.port << "\n";

    for(;;){
        std::cout << "\n==== MIQ Wallet ====\n"
                  << "1) Create wallet (mnemonic + address)\n"
                  << "2) Recover wallet (from 12/24 words)\n"
                  << "3) Send MIQ (auto-fee) + live 3-conf\n"
                  << "4) Show balance\n"
                  << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c = trim(c);
        if(c=="1"){ (void)flow_create(rpc); }
        else if(c=="2"){ (void)flow_restore(rpc); }
        else if(c=="3"){ (void)flow_send(rpc); }
        else if(c=="4"){ (void)flow_balance(rpc); }
        else if(c=="q" || c=="Q" || c=="exit") break;
    }
    return 0;
}
