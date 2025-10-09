// MIQ wallet CLI (hybrid): local HD + (RPC optional) + P2P tx broadcast.
// Default P2P seed: 62.38.73.147:9833
//
// Build dependencies: hd_wallet, wallet_store, sha256, ripemd160, hash160,
// base58*, hex, serialize, tx, secp256k1, and wallet/p2p_light.*

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <fstream>
#include <random>

#ifdef _WIN32
  #include <windows.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#endif

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

using miq::RPC_PORT;
using miq::CHAIN_NAME;
using miq::COIN;

// ----------------- tiny helpers -----------------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}

static bool read_first_line(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f.good()) return false;
    std::getline(f, out);
    // trim
    while(!out.empty() && (out.back()=='\r'||out.back()=='\n'||out.back()==' '||out.back()=='\t')) out.pop_back();
    return !out.empty();
}

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (char c: s) {
        switch(c){
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c; }
                else o << c;
        }
    }
    o << '"';
    return o.str();
}
static std::string jstrp(const std::string& s){ return json_escape(s); }

// --------------- Base64 for HTTP Basic ---------------
static std::string b64_encode(const std::string& in){
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((in.size()+2)/3)*4);
    size_t i=0;
    while(i+3 <= in.size()){
        unsigned v = (unsigned((unsigned char)in[i])<<16) | (unsigned((unsigned char)in[i+1])<<8) | unsigned((unsigned char)in[i+2]);
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]); out.push_back(T[(v>>6)&63]); out.push_back(T[v&63]);
        i += 3;
    }
    if(i+1 == in.size()){
        unsigned v = (unsigned((unsigned char)in[i])<<16);
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]); out.push_back('='); out.push_back('=');
    } else if(i+2 == in.size()){
        unsigned v = (unsigned((unsigned char)in[i])<<16) | (unsigned((unsigned char)in[i+1])<<8);
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]); out.push_back(T[(v>>6)&63]); out.push_back('=');
    }
    return out;
}
static std::string make_basic_auth(const std::string& userpass){
    return "Basic " + b64_encode(userpass);
}

// --------------- HTTP POST (for optional RPC) ---------------
static bool http_post(const std::string& host, const std::string& port,
                      const std::string& path, const std::string& auth_header,
                      const std::string& body, std::string& out_body)
{
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res=nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    int fd = -1; addrinfo* rp=res;
    for (; rp; rp=rp->ai_next) {
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << ":" << port << "\r\n"
        << "Connection: close\r\n"
        << "Content-Type: application/json\r\n";
    if (!auth_header.empty()) req << "Authorization: " << auth_header << "\r\n";
    req << "Content-Length: " << body.size() << "\r\n\r\n"
        << body;

    std::string data = req.str();
    size_t sent = 0;
    while (sent < data.size()) {
#ifdef _WIN32
        int n = send(fd, data.data() + sent, (int)(data.size() - sent), 0);
#else
        ssize_t n = send(fd, data.data() + sent, data.size() - sent, 0);
#endif
        if (n <= 0) break;
        sent += (size_t)n;
    }

    std::string resp;
    char buf[4096];
    for (;;) {
#ifdef _WIN32
        int n = recv(fd, buf, sizeof(buf), 0);
#else
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
#endif
        if (n <= 0) break;
        resp.append(buf, buf+n);
    }
#ifdef _WIN32
    closesocket(fd); WSACleanup();
#else
    close(fd);
#endif

    auto p = resp.find("\r\n\r\n");
    if (p == std::string::npos) return false;
    out_body = trim(resp.substr(p+4));
    return true;
}

// ---------------- cookie discovery ----------------
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

static bool find_cookie_auto(std::string& out_userpass, std::string& source_hint,
                             const std::string& cmd_cookiefile,
                             const std::string& cmd_datadir)
{
    const char* env_cookie_line = std::getenv("MIQ_RPC_COOKIE");
    if(env_cookie_line && *env_cookie_line){
        out_userpass = env_cookie_line;
        source_hint  = "env:MIQ_RPC_COOKIE";
        return true;
    }

    std::string cf;
    if(!cmd_cookiefile.empty()) cf = cmd_cookiefile;
    else {
        const char* e = std::getenv("MIQ_RPC_COOKIEFILE");
        if(e && *e) cf = e;
    }
    if(!cf.empty()){
        if(read_first_line(cf, out_userpass)) { source_hint = cf; return true; }
    }

    if(!cmd_datadir.empty()){
        std::string p = join_path(cmd_datadir, ".cookie");
        if(read_first_line(p, out_userpass)) { source_hint = p; return true; }
    }

#ifndef _WIN32
    {
        std::vector<std::string> cands;
        const char* home = std::getenv("HOME");
        if(home && *home){
            cands.push_back(std::string(home) + "/.miqrochain/.cookie");
            cands.push_back(std::string(home) + "/.config/miqrochain/.cookie");
            cands.push_back(std::string(home) + "/.local/share/miqrochain/.cookie");
        }
        for(const auto& p : cands){
            if(read_first_line(p, out_userpass)) { source_hint = p; return true; }
        }
    }
#else
    // keep it simple on Windows (pass cookiefile/env)
#endif
    return false;
}

// ---------------- RPC wrapper (optional) ----------------
struct Rpc {
    std::string host = "127.0.0.1";
    std::string port = std::to_string(RPC_PORT);
    std::string auth_header; // "Basic ..."

    bool available() const { return !auth_header.empty(); }

    std::string call_raw(const std::string& method, const std::vector<std::string>& params_json) const {
        std::ostringstream b;
        b << "{\"method\":" << jstrp(method);
        if (!params_json.empty()) {
            b << ",\"params\":[";
            for (size_t i=0;i<params_json.size();++i) { if (i) b << ','; b << params_json[i]; }
            b << "]";
        }
        b << "}";
        std::string resp;
        if (!http_post(host, port, "/", auth_header, b.str(), resp)) return "";
        return resp;
    }
};

// -----------------------------------------------------------------------------
// P2P helpers
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

// -----------------------------------------------------------------------------
// Wallet ops
// -----------------------------------------------------------------------------
static bool make_or_restore_wallet(bool restore){
    std::string wdir = default_wallet_file();
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
    if(!SaveHdWallet(wdir, seed, meta, wpass, e)) { std::cout << "save failed: " << e << "\n"; return false; }

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)) { std::cout << "derive address failed\n"; return false; }
    if(!SaveHdWallet(wdir, seed, w.meta(), wpass, e)) { std::cout << "save meta failed: " << e << "\n"; }
    std::cout << "First receive address: " << addr << "\n";
    return true;
}

struct OwnedUtxo {
    std::vector<uint8_t> txid; uint32_t vout; uint64_t value;
    std::vector<uint8_t> priv, pub, pkh;
};

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

// very small RPC shape helpers (stringly)
static bool rpc_getbalance(const Rpc& rpc, uint64_t& miqron){
    if(!rpc.available()) return false;
    std::string r = rpc.call_raw("getbalance", {});
    auto p = r.find("\"miqron\"");
    if(p==std::string::npos) return false;
    p = r.find(':', p); if(p==std::string::npos) return false; ++p;
    while(p<r.size() && std::isspace((unsigned char)r[p])) ++p;
    uint64_t v=0; bool any=false;
    while(p<r.size() && std::isdigit((unsigned char)r[p])){ any=true; v = v*10 + (r[p]-'0'); ++p; }
    if(!any) return false; miqron=v; return true;
}

static bool rpc_listutxos(const Rpc& rpc, std::vector<std::tuple<std::vector<uint8_t>,uint32_t,uint64_t,std::vector<uint8_t>>>& out){
    if(!rpc.available()) return false;
    std::string r = rpc.call_raw("listutxos", {});
    if(r.empty() || r=="null") return false;
    // crude scan
    size_t pos=0;
    while(true){
        auto ptx = r.find("\"txid\"", pos); if(ptx==std::string::npos) break;
        auto pquo = r.find('"', r.find(':', ptx)+1); if(pquo==std::string::npos) break;
        auto pquo2= r.find('"', pquo+1); if(pquo2==std::string::npos) break;
        std::string txid_hex = r.substr(pquo+1, pquo2-pquo-1);
        pos = pquo2+1;

        auto pvout = r.find("\"vout\"", pos); if(pvout==std::string::npos) break;
        uint32_t vout=0; { auto c=r.find(':', pvout); ++c; while(std::isspace((unsigned char)r[c])) ++c; while(std::isdigit((unsigned char)r[c])){ vout = vout*10 + (r[c]-'0'); ++c; } }

        auto pval = r.find("\"value\"", pos); if(pval==std::string::npos) break;
        uint64_t val=0; { auto c=r.find(':', pval); ++c; while(std::isspace((unsigned char)r[c])) ++c; while(std::isdigit((unsigned char)r[c])){ val = val*10 + (r[c]-'0'); ++c; } }

        auto ppkh = r.find("\"pkh\"", pos); if(ppkh==std::string::npos) break;
        auto q1 = r.find('"', r.find(':', ppkh)+1), q2 = r.find('"', q1+1);
        std::string pkh_hex = r.substr(q1+1, q2-q1-1);

        out.emplace_back(miq::from_hex(txid_hex), vout, val, miq::from_hex(pkh_hex));
        pos = q2+1;
    }
    return !out.empty();
}

static bool flow_send(const Rpc& rpc, const std::string& p2p_host, const std::string& p2p_port){
    // load wallet
    std::string wdir = miq::default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else wdir = "wallets/default";

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass; // we use env/cached in future; for now prompt
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

    // source UTXOs via RPC (temporary until SPV)
    std::vector<std::tuple<std::vector<uint8_t>,uint32_t,uint64_t,std::vector<uint8_t>>> utx;
    if(!rpc_listutxos(rpc, utx)){
        std::cout << "No RPC UTXO view. P2P-only balance/UTXO discovery is coming with SPV.\n";
        return false;
    }

    // Gather keys for pkh
    struct Key { std::vector<uint8_t> priv, pub, pkh; };
    std::vector<Key> keys;
    auto add_range = [&](uint32_t chain, uint32_t n){
        for(uint32_t i=0;i<=n;i++){
            Key k;
            if(!w.DerivePrivPub(meta.account, chain, i, k.priv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            keys.push_back(k);
        }
    };
    add_range(0, meta.next_recv);
    add_range(1, meta.next_change);

    auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const Key*{
        for(auto& k: keys) if(k.pkh==pkh) return &k; return nullptr;
    };

    // coin selection (oldest-first is fine if RPC returns in order; otherwise simple accumulate)
    miq::Transaction tx;
    uint64_t in_sum=0;
    for(auto& t: utx){
        auto& txid = std::get<0>(t); uint32_t vout = std::get<1>(t);
        uint64_t val = std::get<2>(t); auto& pkh = std::get<3>(t);
        const Key* K = find_key_for_pkh(pkh);
        if(!K) continue;
        miq::TxIn in; in.prev.txid = txid; in.prev.vout = vout;
        tx.vin.push_back(in);
        in_sum += val;

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

    // sign
    auto sighash = [&](){ miq::Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); } return miq::dsha256(miq::ser_tx(t)); }();
    for(auto& in: tx.vin){
        // find key by prev pkh from our UTXO table
        const Key* key=nullptr;
        for(auto& t: utx){
            if(std::get<0>(t)==in.prev.txid && std::get<1>(t)==in.prev.vout){
                key = find_key_for_pkh(std::get<3>(t)); break;
            }
        }
        if(!key){ std::cout << "internal: key lookup failed\n"; return false; }
        std::vector<uint8_t> sig64;
        if(!miq::crypto::ECDSA::sign(key->priv, sighash, sig64)){ std::cout << "sign failed\n"; return false; }
        in.sig = sig64; in.pubkey = key->pub;
    }

    // serialize tx
    auto raw = miq::ser_tx(tx);
    std::string txid_hex = miq::to_hex(tx.txid());
    std::cout << "Broadcasting via P2P to " << p2p_host << ":" << p2p_port << " ...\n";

    std::string perr;
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

// -----------------------------------------------------------------------------
// main
// -----------------------------------------------------------------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    // RPC target (optional)
    std::string rpc_host = "127.0.0.1";
    std::string rpc_port = std::to_string(RPC_PORT);
    std::string cookiefile, datadir, rpc_user, rpc_pass;

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
        if(eat("--rpcconnect", rpc_host)) continue;
        if(eat("--rpcport",    rpc_port)) continue;
        if(eat("--cookiefile", cookiefile)) continue;
        if(eat("--datadir",    datadir)) continue;
        if(eat("--rpcuser",    rpc_user)) continue;
        if(eat("--rpcpassword",rpc_pass)) continue;
        if(eat("--p2pseed",    p2p_host)) { auto c=p2p_host.find(':'); if(c!=std::string::npos){ p2p_port=p2p_host.substr(c+1); p2p_host=p2p_host.substr(0,c);} continue; }
        if(eat("--p2pport",    p2p_port)) continue;
    }

    // Build RPC auth if available
    Rpc rpc;
    rpc.host = rpc_host; rpc.port = rpc_port;
    std::string userpass, source_hint;
    if(!rpc_user.empty() || !rpc_pass.empty()){
        userpass = rpc_user + ":" + rpc_pass; source_hint="rpcuser/rpcpassword";
    } else {
        (void)find_cookie_auto(userpass, source_hint, cookiefile, datadir);
    }
    if(!userpass.empty()) rpc.auth_header = make_basic_auth(userpass);

    std::cout << "Chain: " << CHAIN_NAME << "\n";
    std::cout << "P2P seed: " << p2p_host << ":" << p2p_port << "\n";
    if(rpc.available()){
        std::cout << "RPC at " << rpc.host << ":" << rpc.port << " (auth: " << source_hint << ")\n";
    } else {
        std::cout << "RPC not configured (balance via SPV not yet implemented).\n";
    }

    for(;;){
        std::cout << "\n==== MIQ Wallet (Hybrid) ====\n";
        std::cout << "1) Create wallet\n";
        std::cout << "2) Recover wallet\n";
        std::cout << "3) Send MIQ (P2P broadcast)\n";
        std::cout << "4) Show balance (RPC if available)\n";
        std::cout << "q) Quit\n> ";
        std::string c; std::getline(std::cin, c); c=trim(c);
        if(c=="1"){ (void)make_or_restore_wallet(false); }
        else if(c=="2"){ (void)make_or_restore_wallet(true); }
        else if(c=="3"){ (void)flow_send(rpc, p2p_host, p2p_port); }
        else if(c=="4"){
            if(!rpc.available()){ std::cout << "RPC unavailable. SPV balance coming next.\n"; continue; }
            uint64_t v=0;
            if(rpc_getbalance(rpc, v)){
                std::ostringstream s; s << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
                std::cout << "Balance: " << s.str() << " MIQ (" << v << " miqron)\n";
            } else std::cout << "getbalance RPC failed.\n";
        }
        else if(c=="q"||c=="Q"||c=="exit") break;
    }
    return 0;
}
