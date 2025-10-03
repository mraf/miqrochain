// src/rpc.cpp  — full file (adds sendfromhd + walletunlock/lock + getwalletinfo + listaddresses + listutxos)
#include "hd_wallet.h"
#include "wallet_store.h"
#include "rpc.h"
#include "sha256.h"
#include "ibd_monitor.h"
#include "constants.h"
#include "util.h"
#include "hex.h"
#include "serialize.h"
#include "tx.h"
#include "log.h"
#include "crypto/ecdsa_iface.h"
#include "miner.h"
#include "base58check.h"
#include "hash160.h"
#include "utxo.h"          // UTXOEntry & list_for_pkh

#include <sstream>
#include <array>
#include <map>
#include <exception>
#include <chrono>
#include <algorithm>
#include <tuple>
#include <cmath>
#include <cctype>   // std::isxdigit
#include <string>
#include <vector>
#include <cstring>  // std::memset
#include <cstdlib>  // std::getenv

#include <fstream>
#include <random>
#include <cerrno>

#ifndef _WIN32
  #include <sys/stat.h>
  #include <unistd.h>
#endif

#ifndef MIN_RELAY_FEE_RATE
// sat/KB (miqron per kilobyte)
static constexpr uint64_t MIN_RELAY_FEE_RATE = 1000;
#endif
#ifndef DUST_THRESHOLD
static constexpr uint64_t DUST_THRESHOLD = 1000; // 0.00001000 MIQ
#endif

// --- RPC request limits ---
static constexpr size_t RPC_MAX_BODY_BYTES = 512 * 1024; // 512 KiB

namespace miq {

// ======== Cookie auth (token file) — used by HTTP layer via env header token ========

static std::string& rpc_cookie_token() {
    static std::string tok;
    return tok;
}
static std::string& rpc_cookie_path() {
    static std::string p;
    return p;
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

static std::string hex32_random() {
    std::array<uint8_t,32> buf{};
    std::random_device rd;
    for (auto &b : buf) b = static_cast<uint8_t>(rd());
    return to_hex(std::vector<uint8_t>(buf.begin(), buf.end()));
}

static bool file_exists(const std::string& p) {
    std::ifstream f(p, std::ios::in | std::ios::binary);
    return f.good();
}

static bool read_first_line_trim(const std::string& p, std::string& out) {
    std::ifstream f(p, std::ios::in | std::ios::binary);
    if(!f.good()) return false;
    std::string s;
    std::getline(f, s);
    // trim spaces and newlines
    while(!s.empty() && (s.back()=='\r' || s.back()=='\n' || s.back()==' ' || s.back()=='\t')) s.pop_back();
    out = s;
    return true;
}

// Constant-time compare to avoid token timing leaks (kept for future use)
static bool timing_safe_eq(const std::string& a, const std::string& b){
    if (a.size() != b.size()) return false;
    unsigned char acc = 0;
    for (size_t i=0;i<a.size();++i) acc |= (unsigned char)(a[i] ^ b[i]);
    return acc == 0;
}

static bool write_cookie_file_secure(const std::string& p, const std::string& tok) {
#ifndef _WIN32
    // best-effort: 0600
    umask(0077);
#endif
    std::ofstream f(p, std::ios::out | std::ios::trunc | std::ios::binary);
    if(!f.good()) return false;
    f << tok << "\n";
    f.flush();
#ifndef _WIN32
    ::chmod(p.c_str(), 0600);
#endif
    return f.good();
}

// Helper: export token to the HTTP layer so it can validate headers.
// http.cpp checks MIQ_RPC_TOKEN against Authorization/X-Auth-Token.
static void export_token_to_env(const std::string& tok){
#ifdef _WIN32
    _putenv_s("MIQ_RPC_TOKEN", tok.c_str());
#else
    setenv("MIQ_RPC_TOKEN", tok.c_str(), 1);
#endif
}

void rpc_enable_auth_cookie(const std::string& datadir) {
    std::string path = join_path(datadir, ".cookie");
    rpc_cookie_path() = path;

    std::string tok;
    if (file_exists(path)) {
        if (read_first_line_trim(path, tok) && !tok.empty()) {
            rpc_cookie_token() = tok;
            export_token_to_env(tok);  // hand to HTTP layer (header-based auth)
            log_info("RPC auth cookie loaded from " + path);
            return;
        } else {
            log_warn("RPC cookie file exists but unreadable/empty; recreating: " + path);
        }
    }

    tok = hex32_random();
    if (!write_cookie_file_secure(path, tok)) {
        log_error("Failed to write RPC cookie file at " + path + " (errno=" + std::to_string(errno) + ")");
        // Fallback: still enable with in-memory token (not persisted).
        rpc_cookie_token() = tok;
        export_token_to_env(tok);
        return;
    }
    rpc_cookie_token() = tok;
    export_token_to_env(tok);
    log_info("RPC auth cookie created at " + path + " (600 perms).");
}

// ==============================================================================

static std::string err(const std::string& m){
    miq::JNode n;
    std::map<std::string,miq::JNode> o;
    miq::JNode e; e.v = std::string(m);
    o["error"] = e;
    n.v = o;
    return json_dump(n);
}

// Local difficulty helper (same formula as Chain::work_from_bits, but public here)
static double difficulty_from_bits(uint32_t bits){
    uint32_t exp  = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    if (mant == 0) return 0.0;

    uint32_t bexp  = GENESIS_BITS >> 24;
    uint32_t bmant = GENESIS_BITS & 0x007fffff;

    long double target      = (long double)mant  * std::pow(256.0L, (long double)((int)exp - 3));
    long double base_target = (long double)bmant * std::pow(256.0L, (long double)((int)bexp - 3));
    if (target <= 0.0L) return 0.0;

    long double difficulty = base_target / target;
    if (difficulty < 0.0L) difficulty = 0.0L;
    return (double)difficulty; // cast to double for JNode
}

static bool is_hex(const std::string& s){
    if(s.empty()) return false;
    return std::all_of(s.begin(), s.end(), [](unsigned char c){ return std::isxdigit(c)!=0; });
}

static uint64_t parse_amount_str(const std::string& s){
    // Accept "1.23" (MIQ) or "123456" (miqron)
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

static size_t estimate_size_bytes(size_t nin, size_t nout){
    // Conservative: ~148/vin + ~34/vout + 10
    return nin*148 + nout*34 + 10;
}

static uint64_t min_fee_for_size(size_t sz_bytes){
    const uint64_t rate = MIN_RELAY_FEE_RATE; // sat/kB
    uint64_t kb = (uint64_t)((sz_bytes + 999) / 1000);
    if(kb==0) kb=1;
    return kb * rate;
}

// ---- Wallet passphrase cache (RAM only) ------------------------------------
namespace {
    static std::string g_cached_pass;
    static int64_t     g_pass_expires_ms = 0;

    static inline int64_t now_ms_rpc() {
        using namespace std::chrono;
        return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
    }
    static inline bool wallet_is_unlocked() {
        return !g_cached_pass.empty() && now_ms_rpc() < g_pass_expires_ms;
    }
    static inline void wallet_lock_cached() {
        g_cached_pass.clear();
        g_pass_expires_ms = 0;
    }
    static inline void wallet_unlock_cache_for(const std::string& pass, uint64_t seconds) {
        g_cached_pass = pass;
        g_pass_expires_ms = now_ms_rpc() + (int64_t)seconds * 1000;
    }
    static inline std::string get_wallet_pass_or_cached() {
        const char* envp = std::getenv("MIQ_WALLET_PASSPHRASE");
        if (envp && *envp) return std::string(envp);
        if (wallet_is_unlocked()) return g_cached_pass;
        return std::string();
    }
}

void RpcService::start(uint16_t port){
    // http.cpp authenticates via Authorization / X-Auth-Token (MIQ_RPC_TOKEN).
    // Use the headers-aware start() so we can access headers later if needed.
    http_.start(
        port,
        [this](const std::string& b,
               const std::vector<std::pair<std::string,std::string>>& /*headers*/) {
            try {
                return this->handle(b); // current handler ignores headers (by design)
            } catch (const std::exception& ex) {
                log_error(std::string("rpc exception: ") + ex.what());
                return err("internal error");
            } catch (...) {
                log_error("rpc exception: unknown");
                return err("internal error");
            }
        }
    );
}
void RpcService::stop(){ http_.stop(); }

// simple uptime base
static std::chrono::steady_clock::time_point& rpc_start_time(){
    static auto t0 = std::chrono::steady_clock::now();
    return t0;
}

static JNode jbool(bool v){ JNode n; n.v = v; return n; }
static JNode jnum(double v){ JNode n; n.v = v; return n; }
static JNode jstr(const std::string& s){ JNode n; n.v = s; return n; }

std::string RpcService::handle(const std::string& body){
    // Request-size guard (defense-in-depth)
    if (body.size() > RPC_MAX_BODY_BYTES) {
        return err("request too large");
    }

    try {
        JNode req;
        if(!json_parse(body, req)) return err("bad json");
        if(!std::holds_alternative<std::map<std::string,JNode>>(req.v)) return err("bad json obj");
        auto& obj = std::get<std::map<std::string,JNode>>(req.v);

        // ---- Header-based auth happens in http.cpp. No JSON "auth" required anymore. ----

        auto it = obj.find("method");
        if(it==obj.end() || !std::holds_alternative<std::string>(it->second.v)) return err("missing method");
        std::string method = std::get<std::string>(it->second.v);

        std::vector<JNode> params;
        auto ip = obj.find("params");
        if(ip!=obj.end() && std::holds_alternative<std::vector<JNode>>(ip->second.v))
            params = std::get<std::vector<JNode>>(ip->second.v);

        // ---------------- basic/info ----------------

auto err = [&](const char* m) -> std::string {
    miq::JNode root;
    std::map<std::string, miq::JNode> o;
    miq::JNode e; e.v = std::string(m);
    o["error"] = e;
    root.v = o;
    return json_dump(root);
};

auto ok = [&](const miq::JNode& res) -> std::string {
    miq::JNode root;
    std::map<std::string, miq::JNode> o;
    miq::JNode rn; rn.v = res.v;
    miq::JNode en; en.v = miq::JNull{};
    o["result"] = rn;
    o["error"]  = en;
    root.v = o;
    return json_dump(root);
};

auto get_str = [](const miq::JNode& n, std::string& out) -> bool {
    if (!std::holds_alternative<std::string>(n.v)) return false;
    out = std::get<std::string>(n.v);
    return true;
};

// --- the actual handler ---
if (method == "getaddressutxos")
{
    // Expect: params = ["<base58 address>"]
    auto itParams = obj.find("params");
    if (itParams == obj.end())
        return err("usage: getaddressutxos <address>");
    if (!std::holds_alternative<std::vector<miq::JNode>>(itParams->second.v))
        return err("usage: getaddressutxos <address>");

    auto& params = std::get<std::vector<miq::JNode>>(itParams->second.v);
    if (params.size() != 1)
        return err("usage: getaddressutxos <address>");

    std::string addr;
    if (!get_str(params[0], addr))
        return err("address must be string");

    // Decode Base58Check and validate P2PKH
    uint8_t ver = 0;
    std::vector<uint8_t> payload;
    if (!miq::base58check_decode(addr, ver, payload))
        return err("bad address");
    if (ver != miq::VERSION_P2PKH || payload.size() != 20)
        return err("bad address");

    const std::vector<uint8_t> pkh = payload;

    // Lookup UTXOs
    auto entries = chain_.utxo().list_for_pkh(pkh);

    // Build JSON array result
    std::vector<miq::JNode> out;
    out.reserve(entries.size());
    for (const auto& t : entries) {
        const std::vector<uint8_t>& txid = std::get<0>(t);
        uint32_t vout = std::get<1>(t);
        const miq::UTXOEntry& e = std::get<2>(t);

        std::map<std::string, miq::JNode> o;
        miq::JNode jtxid; jtxid.v = miq::to_hex(txid);
        miq::JNode jvout; jvout.v = static_cast<double>(vout);       // numbers are doubles in JSON
        miq::JNode jval;  jval.v  = static_cast<double>(e.value);
        miq::JNode jpkh;  jpkh.v  = miq::to_hex(e.pkh);

        o["txid"]  = jtxid;
        o["vout"]  = jvout;
        o["value"] = jval;
        o["pkh"]   = jpkh;

        miq::JNode on; on.v = o;
        out.emplace_back(std::move(on));
    }

    miq::JNode arr; arr.v = out;
    return ok(arr);
}

        if(method=="help"){
            static const char* k[] = {
                "help","version","ping","uptime",
                "getnetworkinfo","getblockchaininfo","getblockcount","getbestblockhash",
                "getblock","getblockhash","getcoinbaserecipient",
                "getrawmempool","gettxout",
                "validateaddress","decodeaddress","decoderawtx",
                "getminerstats","sendrawtransaction","sendtoaddress",
                "estimatemediantime","getdifficulty","getchaintips",
                "getpeerinfo","getconnectioncount",
                "createhdwallet","restorehdwallet","walletinfo","getnewaddress","deriveaddressat",
                "walletunlock","walletlock","getwalletinfo","listaddresses","listutxos",
                "sendfromhd"
                // (getibdinfo exists but not listed here to keep help stable)
            };
            std::vector<JNode> v;
            for(const char* s: k){ v.push_back(jstr(s)); }
            JNode out; out.v = v; return json_dump(out);
        }

        if(method=="version"){
            JNode n; n.v = std::string("miqrochain-rpc/1");
            return json_dump(n);
        }

        if(method=="ping"){
            return "\"pong\"";
        }

        if(method=="uptime"){
            using clock = std::chrono::steady_clock;
            auto secs = std::chrono::duration<double>(clock::now() - rpc_start_time()).count();
            return json_dump(jnum(secs));
        }

        if(method=="getnetworkinfo"){
            std::map<std::string,JNode> o;
            JNode n;  n.v = std::string(CHAIN_NAME);                 o["chain"] = n;
            JNode b;  b.v = (double)RPC_PORT;                        o["rpcport"] = b;
            JNode be; be.v = std::string(crypto::ECDSA::backend());  o["crypto_backend"] = be;
            JNode r;  r.v = o; return json_dump(r);
        }

        if(method=="getblockchaininfo"){
            JNode n; std::map<std::string,JNode> o;
            JNode a; a.v = std::string(CHAIN_NAME);              o["chain"] = a;
            JNode h; h.v = (double)chain_.tip().height;          o["height"] = h;
            JNode d; d.v = (double)Chain::work_from_bits_public(chain_.tip().bits); o["difficulty"] = d;
            JNode r; r.v = o; return json_dump(r);
        }

        // --- IBD snapshot ---
        if(method=="getibdinfo"){
            auto s = miq::get_ibd_info_snapshot();
            std::map<std::string,JNode> o;
            o["ibd_active"]                = jbool(s.ibd_active);
            o["best_block_height"]         = jnum((double)s.best_block_height);
            o["est_best_header_height"]    = jnum((double)s.est_best_header_height);
            o["headers_ahead"]             = jnum((double)s.headers_ahead);
            o["peers"]                     = jnum((double)s.peers);
            o["phase"]                     = jstr(s.phase);
            o["started_ms"]                = jnum((double)s.started_ms);
            o["last_update_ms"]            = jnum((double)s.last_update_ms);
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="getblockcount"){
            JNode n; n.v = (double)chain_.tip().height;
            return json_dump(n);
        }

        if(method=="getbestblockhash"){
            JNode n; n.v = std::string(to_hex(chain_.tip().hash));
            return json_dump(n);
        }

        if(method=="getblockhash"){
            if(params.size()<1 || !std::holds_alternative<double>(params[0].v))
                return err("need height");
            size_t idx = (size_t)std::get<double>(params[0].v);
            Block b; if(!chain_.get_block_by_index(idx, b)) return err("not found");
            JNode n; n.v = std::string(to_hex(b.block_hash()));
            return json_dump(n);
        }

        // getblock(height or hex_hash) -> {hash,time,txs,hex}
        if(method=="getblock"){
            if(params.size()<1) return err("need index_or_hash");

            Block b;
            bool ok = false;

            if(std::holds_alternative<double>(params[0].v)){
                size_t idx = (size_t)std::get<double>(params[0].v);
                ok = chain_.get_block_by_index(idx, b);
            } else if(std::holds_alternative<std::string>(params[0].v)){
                const std::string hstr = std::get<std::string>(params[0].v);
                if(!is_hex(hstr)) return err("bad hash hex");
                std::vector<uint8_t> want;
                try { want = from_hex(hstr); } catch(...) { return err("bad hash hex"); }

                auto tip = chain_.tip();
                for(size_t i=0;i<= (size_t)tip.height;i++){
                    Block tb;
                    if(chain_.get_block_by_index(i, tb)){
                        if(tb.block_hash() == want){ b = tb; ok = true; break; }
                    }
                }
            } else {
                return err("bad arg");
            }

            if(!ok) return err("not found");

            std::map<std::string,JNode> o;
            JNode h;   h.v  = std::string(to_hex(b.block_hash())); o["hash"] = h;
            JNode t;   t.v  = (double)b.header.time;               o["time"] = t;
            JNode nt;  nt.v = (double)b.txs.size();                o["txs"]  = nt;
            JNode raw; raw.v = std::string(to_hex(ser_block(b)));  o["hex"]  = raw;

            JNode out; out.v = o; return json_dump(out);
        }

        // who gets the coinbase vout0?
        if(method=="getcoinbaserecipient"){
            if(params.size()<1) return err("need index_or_hash");

            Block b;
            bool ok = false;

            if(std::holds_alternative<double>(params[0].v)){
                size_t idx = (size_t)std::get<double>(params[0].v);
                ok = chain_.get_block_by_index(idx, b);
            } else if(std::holds_alternative<std::string>(params[0].v)){
                const std::string hstr = std::get<std::string>(params[0].v);
                if(!is_hex(hstr)) return err("bad hash hex");
                std::vector<uint8_t> want;
                try { want = from_hex(hstr); } catch(...) { return err("bad hash hex"); }

                auto tip = chain_.tip();
                for(size_t i=0;i<= (size_t)tip.height;i++){
                    Block tb;
                    if(chain_.get_block_by_index(i, tb)){
                        if(tb.block_hash() == want){ b = tb; ok = true; break; }
                    }
                }
            } else {
                return err("bad arg");
            }

            if(!ok) return err("not found");
            if(b.txs.empty()) return err("no transactions in block");
            const auto& cb = b.txs[0];
            if(cb.vout.empty()) return err("coinbase has no outputs");
            const auto& o0 = cb.vout[0];

            std::map<std::string,JNode> o;
            JNode val; val.v = (double)o0.value;            o["value"] = val;   // in miqron
            JNode pk ; pk.v  = std::string(to_hex(o0.pkh)); o["pkh"]   = pk;

            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="gettipinfo"){
            auto tip = chain_.tip();
            std::map<std::string,JNode> o;
            JNode h;  h.v  = (double)tip.height;               o["height"] = h;
            JNode b;  b.v  = (double)tip.bits;                 o["bits"]   = b;
            JNode t;  t.v  = (double)tip.time;                 o["time"]   = t;
            JNode hh; hh.v = std::string(to_hex(tip.hash));    o["hash"]   = hh;
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="decodeaddress"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need address");
            uint8_t ver=0; std::vector<uint8_t> payload;
            if(!base58check_decode(std::get<std::string>(params[0].v), ver, payload))
                return err("bad address");
            std::map<std::string,JNode> o;
            JNode v; v.v = (double)ver;               o["version"]     = v;
            JNode p; p.v = (double)payload.size();    o["payload_size"]= p;
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="validateaddress"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need address");
            uint8_t ver=0; std::vector<uint8_t> payload;
            bool ok = base58check_decode(std::get<std::string>(params[0].v), ver, payload);
            std::map<std::string,JNode> o;
            o["isvalid"] = jbool(ok && ver==VERSION_P2PKH && payload.size()==20);
            o["version"] = jnum((double)ver);
            if(ok && payload.size()==20){ o["pkh"] = jstr(to_hex(payload)); }
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="decoderawtx"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txhex");
            std::vector<uint8_t> raw;
            try { raw = from_hex(std::get<std::string>(params[0].v)); }
            catch(...) { return err("bad txhex"); }
            Transaction tx;
            if(!deser_tx(raw, tx)) return err("bad tx");
            std::map<std::string,JNode> o;
            o["txid"] = jstr(to_hex(tx.txid()));
            o["size"] = jnum((double)raw.size());
            // vin
            {
                std::vector<JNode> arr;
                for(const auto& in: tx.vin){
                    std::map<std::string,JNode> i;
                    i["prev_txid"] = jstr(to_hex(in.prev.txid));
                    i["vout"]      = jnum((double)in.prev.vout);
                    i["pubkey"]    = jstr(to_hex(in.pubkey));
                    i["siglen"]    = jnum((double)in.sig.size());
                    JNode n; n.v = i; arr.push_back(n);
                }
                JNode n; n.v = arr; o["vin"] = n;
            }
            // vout
            {
                std::vector<JNode> arr;
                for(const auto& out: tx.vout){
                    std::map<std::string,JNode> v;
                    v["value"] = jnum((double)out.value);
                    v["pkh"]   = jstr(to_hex(out.pkh));
                    JNode n; n.v = v; arr.push_back(n);
                }
                JNode n; n.v = arr; o["vout"] = n;
            }
            JNode out; out.v = o; return json_dump(out);
        }

        if(method=="getrawmempool"){
            auto ids = mempool_.txids();
            JNode arr; std::vector<JNode> v;
            for(auto& id: ids){ JNode s; s.v = std::string(to_hex(id)); v.push_back(s); }
            arr.v = v; return json_dump(arr);
        }

        if(method=="gettxout"){
            if(params.size()<2) return err("need txid & vout");
            if(!std::holds_alternative<std::string>(params[0].v)) return err("need txid");
            if(!std::holds_alternative<double>(params[1].v))      return err("need vout");

            const std::string txidhex = std::get<std::string>(params[0].v);
            uint32_t vout = (uint32_t)std::get<double>(params[1].v);

            std::vector<uint8_t> txid;
            try { txid = from_hex(txidhex); }
            catch(...) { return err("bad txid"); }

            UTXOEntry e;
            if(chain_.utxo().get(txid, vout, e)){
                std::map<std::string,JNode> o;
                JNode val; val.v = (double)e.value;  o["value"]    = val;
                JNode cb;  cb.v  = e.coinbase;       o["coinbase"] = cb;
                JNode n;   n.v   = o; return json_dump(n);
            } else {
                return "null";
            }
        }

        if(method=="sendrawtransaction"){
            if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v))
                return err("need txhex");
            const std::string h = std::get<std::string>(params[0].v);

            std::vector<uint8_t> raw;
            try { raw = from_hex(h); }
            catch(...) { return err("bad txhex"); }

            Transaction tx;
            if(!deser_tx(raw, tx)) return err("bad tx");

            auto tip = chain_.tip(); std::string e;
            if(mempool_.accept(tx, chain_.utxo(), (size_t)tip.height, e)){
                JNode r; r.v = std::string(to_hex(tx.txid())); return json_dump(r);
            } else {
                return err(e);
            }
        }

        // Miner stats
        if(method=="getminerstats"){
            using clock = std::chrono::steady_clock;
            static clock::time_point prev = clock::now();

            const uint64_t hashes = miner_hashes_snapshot_and_reset();
            const auto now = clock::now();
            double secs = std::chrono::duration<double>(now - prev).count();
            if (secs <= 0) secs = 1e-9;
            prev = now;

            const double hps = double(hashes) / secs;
            const uint64_t total = miner_hashes_total();

            std::map<std::string,JNode> o;
            JNode jh; jh.v = (double)hashes;         o["hashes"]  = jh;
            JNode js; js.v = secs;                   o["seconds"] = js;
            JNode jj; jj.v = hps;                    o["hps"]     = jj;
            JNode jt; jt.v = (double)total;          o["total"]   = jt;

            JNode out; out.v = o; return json_dump(out);
        }

        // --- HD wallet RPCs ---

// --- createhdwallet ---
if (method == "createhdwallet") {
    auto get_opt = [&](size_t i)->std::string{
        return (params.size()>i && std::holds_alternative<std::string>(params[i].v))
               ? std::get<std::string>(params[i].v) : std::string();
    };
    std::string mnemonic = get_opt(0);
    std::string mpass    = get_opt(1);
    std::string wpass    = get_opt(2);

    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed(64);
    if(mnemonic.empty()){
        std::string outmn;
        if(!miq::HdWallet::GenerateMnemonic(128, outmn)) return err("mnemonic generation failed");
        mnemonic = outmn;
    }
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) return err("mnemonic->seed failed");

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!SaveHdWallet(wdir, seed, meta, wpass, e)) return err(e);

    std::map<std::string,JNode> o;
    o["mnemonic"]  = jstr(mnemonic);
    o["wallet_dir"]= jstr(wdir);
    JNode out; out.v = o; return json_dump(out);
}

// --- restorehdwallet ---
if (method == "restorehdwallet") {
    if(params.size()<1 || !std::holds_alternative<std::string>(params[0].v)) return err("mnemonic required");
    auto get_opt = [&](size_t i)->std::string{
        return (params.size()>i && std::holds_alternative<std::string>(params[i].v))
               ? std::get<std::string>(params[i].v) : std::string();
    };
    std::string mnemonic = std::get<std::string>(params[0].v);
    std::string mpass    = get_opt(1);
    std::string wpass    = get_opt(2);

    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)) return err("mnemonic->seed failed");

    miq::HdAccountMeta meta; meta.account=0; meta.next_recv=0; meta.next_change=0;
    std::string e;
    if(!SaveHdWallet(wdir, seed, meta, wpass, e)) return err(e);

    return "\"ok\"";
}

// --- walletinfo ---
if (method == "walletinfo") {
    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass = get_wallet_pass_or_cached();
    if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

    std::map<std::string,JNode> o;
    o["account"]     = jnum((double)meta.account);
    o["next_recv"]   = jnum((double)meta.next_recv);
    o["next_change"] = jnum((double)meta.next_change);
    JNode out; out.v = o; return json_dump(out);
}

// --- getnewaddress ---
if (method == "getnewaddress") {
    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass = get_wallet_pass_or_cached();
    if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)) return err("derive failed");

    if(!SaveHdWallet(wdir, seed, w.meta(), pass, e)) return err(e);
    return json_dump(jstr(addr));
}

// --- deriveaddressat ---
if (method == "deriveaddressat") {
    if(params.size()<1) return err("index required");
    uint32_t idx = 0;
    if (std::holds_alternative<double>(params[0].v)) {
        idx = (uint32_t)std::get<double>(params[0].v);
    } else if (std::holds_alternative<std::string>(params[0].v)) {
        try { idx = (uint32_t)std::stoul(std::get<std::string>(params[0].v)); }
        catch(...) { return err("bad index"); }
    } else {
        return err("bad index");
    }

    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass = get_wallet_pass_or_cached();
    if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetAddressAt(idx, addr)) return err("derive failed");
    return json_dump(jstr(addr));
}

// --- walletunlock (cache passphrase with timeout) ---
if (method == "walletunlock") {
    if (params.size() < 1 || !std::holds_alternative<std::string>(params[0].v)) {
        return err("usage: walletunlock pass [timeout_sec]");
    }
    std::string pass = std::get<std::string>(params[0].v);
    if (pass.empty()) return err("empty passphrase refused");

    uint64_t timeout_s = 300;
    if (params.size() >= 2) {
        if (std::holds_alternative<double>(params[1].v)) {
            timeout_s = (uint64_t)std::get<double>(params[1].v);
        } else if (std::holds_alternative<std::string>(params[1].v)) {
            try { timeout_s = (uint64_t)std::stoull(std::get<std::string>(params[1].v)); }
            catch(...) { return err("bad timeout"); }
        }
        if (timeout_s == 0) return err("timeout must be >0");
    }

    // Validate passphrase by attempting to load
    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }
    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    if (!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

    wallet_unlock_cache_for(pass, timeout_s);

    std::map<std::string,JNode> o;
    o["ok"]                = jbool(true);
    o["unlocked_until_ms"] = jnum((double)g_pass_expires_ms);
    JNode out; out.v = o; return json_dump(out);
}

// --- walletlock ---
if (method == "walletlock") {
    wallet_lock_cached();
    return "\"ok\"";
}

// --- getwalletinfo (unlocked status + meta if readable) ---
if (method == "getwalletinfo") {
    std::map<std::string,JNode> o;
    o["unlocked"]          = jbool(wallet_is_unlocked());
    o["unlocked_until_ms"] = jnum((double)g_pass_expires_ms);

    // Try to surface meta from disk using helper (env or cached pass)
    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }
    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass = get_wallet_pass_or_cached();
    if (LoadHdWallet(wdir, seed, meta, pass, e)) {
        o["next_recv"]   = jnum((double)meta.next_recv);
        o["next_change"] = jnum((double)meta.next_change);
    }
    JNode out; out.v = o; return json_dump(out);
}

// --- listaddresses [count?] ---
if (method == "listaddresses") {
    int want = -1;
    if (params.size()>0) {
        if (std::holds_alternative<double>(params[0].v)) want = (int)std::get<double>(params[0].v);
        else if (std::holds_alternative<std::string>(params[0].v)) {
            try { want = (int)std::stoul(std::get<std::string>(params[0].v)); } catch(...) { return err("bad count"); }
        }
    }

    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass = get_wallet_pass_or_cached();
    if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

    miq::HdWallet w(seed, meta);
    int n = (want>0) ? std::min<int>(want, (int)meta.next_recv) : (int)meta.next_recv;

    std::vector<JNode> arr;
    for (int i=0;i<n;i++){
        std::string addr;
        if (w.GetAddressAt((uint32_t)i, addr)) arr.push_back(jstr(addr));
    }
    JNode out; out.v = arr; return json_dump(out);
}

// --- listutxos ---
if (method == "listutxos") {
    std::string wdir = default_wallet_file();
    if(!wdir.empty()){
        size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
    } else {
        wdir = "wallets/default";
    }

    std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string e;
    std::string pass = get_wallet_pass_or_cached();
    if(!LoadHdWallet(wdir, seed, meta, pass, e)) return err(e);

    miq::HdWallet w(seed, meta);

    // Build PKHs for known receive & change ranges
    auto collect_pkh_for_range = [&](bool change, uint32_t n, std::vector<std::array<uint8_t,20>>& out){
        for (uint32_t i=0;i<n;i++){
            std::vector<uint8_t> priv, pub;
            if (!w.DerivePrivPub(meta.account, change?1u:0u, i, priv, pub)) continue;
            auto h = hash160(pub);
            if (h.size()!=20) continue;
            std::array<uint8_t,20> p{}; std::copy(h.begin(), h.end(), p.begin());
            out.push_back(p);
        }
    };
    std::vector<std::array<uint8_t,20>> pkhs;
    collect_pkh_for_range(false, meta.next_recv, pkhs);
    collect_pkh_for_range(true,  meta.next_change, pkhs);

    std::vector<JNode> outarr;
    for (const auto& pkh : pkhs){
        auto lst = chain_.utxo().list_for_pkh(std::vector<uint8_t>(pkh.begin(), pkh.end()));
        for (const auto& t : lst){
            const auto& txid = std::get<0>(t);
            uint32_t vout    = std::get<1>(t);
            const auto& e2   = std::get<2>(t);

            std::map<std::string,JNode> o;
            o["txid"]  = jstr(to_hex(txid));
            o["vout"]  = jnum((double)vout);
            o["value"] = jnum((double)e2.value);
            JNode n; n.v = o; outarr.push_back(n);
        }
    }
    JNode out; out.v = outarr; return json_dump(out);
}

        // -------- NEW: spend from HD wallet (account 0) --------
        if (method == "sendfromhd") {
            // params: [to_address, amount, feerate(optional miqron per kB)]
            if (params.size() < 2
                || !std::holds_alternative<std::string>(params[0].v)
                || !std::holds_alternative<std::string>(params[1].v)) {
                return err("need to_address, amount");
            }
            const std::string toaddr = std::get<std::string>(params[0].v);
            const std::string amtstr = std::get<std::string>(params[1].v);

            uint64_t feerate = MIN_RELAY_FEE_RATE;
            if (params.size() >= 3) {
                if (std::holds_alternative<double>(params[2].v)) {
                    feerate = (uint64_t)std::get<double>(params[2].v);
                } else if (std::holds_alternative<std::string>(params[2].v)) {
                    try { feerate = (uint64_t)std::stoull(std::get<std::string>(params[2].v)); }
                    catch(...) { return err("bad feerate"); }
                }
                if (feerate == 0) feerate = MIN_RELAY_FEE_RATE;
            }

            // decode destination
            uint8_t ver=0; std::vector<uint8_t> to_payload;
            if(!base58check_decode(toaddr, ver, to_payload) || to_payload.size()!=20 || ver!=VERSION_P2PKH)
                return err("bad to_address");

            // amount
            uint64_t amount = 0;
            try { amount = parse_amount_str(amtstr); }
            catch(...) { return err("bad amount"); }
            if (amount == 0) return err("amount must be >0");

            // Load wallet data
            std::string wdir = default_wallet_file();
            if(!wdir.empty()){
                size_t pos = wdir.find_last_of("/\\"); if(pos!=std::string::npos) wdir = wdir.substr(0,pos);
            } else {
                wdir = "wallets/default";
            }
            std::vector<uint8_t> seed; miq::HdAccountMeta meta{}; std::string werr;
            std::string pass = get_wallet_pass_or_cached();
            if(!LoadHdWallet(wdir, seed, meta, pass, werr)) return err(werr);

            miq::HdWallet w(seed, meta);

            struct OwnedUtxo {
                std::vector<uint8_t> txid; uint32_t vout; UTXOEntry e;
                std::vector<uint8_t> priv; std::vector<uint8_t> pub; std::vector<uint8_t> pkh;
            };
            std::vector<OwnedUtxo> owned;

            auto gather_chain = [&](uint32_t chain, uint32_t limit){
                for (uint32_t i = 0; i < limit + 1; ++i) { // include current "next" (fresh)
                    std::vector<uint8_t> priv, pub;
                    if (!w.DerivePrivPub(meta.account, chain, i, priv, pub)) continue;
                    auto pkh = hash160(pub);
                    auto lst = chain_.utxo().list_for_pkh(pkh);
                    for (auto& t : lst){
                        OwnedUtxo ou;
                        ou.txid = std::get<0>(t);
                        ou.vout = std::get<1>(t);
                        ou.e    = std::get<2>(t);
                        ou.priv = priv;
                        ou.pub  = pub;
                        ou.pkh  = pkh;
                        owned.push_back(std::move(ou));
                    }
                }
            };
            gather_chain(0, meta.next_recv);
            gather_chain(1, meta.next_change);

            if (owned.empty()) return err("no funds");

            std::sort(owned.begin(), owned.end(), [](const OwnedUtxo& A, const OwnedUtxo& B){
                return A.e.value < B.e.value;
            });

            Transaction tx;
            uint64_t in_sum = 0;

            auto fee_for = [&](size_t nin, size_t nout)->uint64_t{
                size_t sz = estimate_size_bytes(nin, nout);
                uint64_t kb = (uint64_t)((sz + 999) / 1000);
                if (kb==0) kb=1;
                return kb * feerate;
            };

            for (size_t k = 0; k < owned.size(); ++k){
                const auto& u = owned[k];
                TxIn in; in.prev.txid = u.txid; in.prev.vout = u.vout;
                tx.vin.push_back(in);
                in_sum += u.e.value;

                uint64_t fee_guess = fee_for(tx.vin.size(), 2);
                if (in_sum >= amount + fee_guess) break;
            }
            if (tx.vin.empty()) return err("insufficient funds");

            // Outputs & fee
            TxOut out; out.pkh = to_payload;

            uint64_t fee_final = 0, change = 0;
            {
                size_t est_size = estimate_size_bytes(tx.vin.size(), 2);
                (void)est_size;
                fee_final = fee_for(tx.vin.size(), 2);
                if(in_sum < amount + fee_final){
                    size_t est_size1 = estimate_size_bytes(tx.vin.size(), 1);
                    (void)est_size1;
                    fee_final = fee_for(tx.vin.size(), 1);
                    if(in_sum < amount + fee_final) return err("insufficient funds (need amount+fee)");
                    change = 0;
                } else {
                    change = in_sum - amount - fee_final;
                    if(change < DUST_THRESHOLD){
                        change = 0;
                        size_t est_size2 = estimate_size_bytes(tx.vin.size(), 1);
                        (void)est_size2;
                        fee_final = fee_for(tx.vin.size(), 1);
                        if(in_sum < amount + fee_final) return err("insufficient after dust fold");
                    }
                }
            }

            out.value = amount;
            tx.vout.push_back(out);

            // Change -> new change address (m/44'/coin'/account'/1/index)
            std::vector<uint8_t> change_priv, change_pub; std::vector<uint8_t> change_pkh;
            bool used_change = false;
            if (change > 0) {
                if (!w.DerivePrivPub(meta.account, 1, meta.next_change, change_priv, change_pub))
                    return err("derive change failed");
                change_pkh = hash160(change_pub);
                TxOut ch; ch.value = change; ch.pkh = change_pkh;
                tx.vout.push_back(ch);
                used_change = true;
            }

            // Sighash and sign each input with its matching key
            auto sighash = [&](){
                Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); }
                return dsha256(ser_tx(t));
            }();
            for (auto& in : tx.vin){
                const OwnedUtxo* key = nullptr;
                for (const auto& u : owned){
                    if (u.txid == in.prev.txid && u.vout == in.prev.vout) { key = &u; break; }
                }
                if (!key) return err("internal: key lookup failed");
                std::vector<uint8_t> sig64;
                if(!crypto::ECDSA::sign(key->priv, sighash, sig64)) return err("sign failed");
                in.sig = sig64;
                in.pubkey = key->pub;
            }

            auto tip = chain_.tip(); std::string e;
            if(mempool_.accept(tx, chain_.utxo(), (size_t)tip.height, e)){
                if (used_change) {
                    HdAccountMeta newm = w.meta();
                    newm.next_change = meta.next_change + 1;
                    if(!SaveHdWallet(wdir, seed, newm, pass, e)) {
                        log_warn(std::string("sendfromhd: SaveHdWallet failed: ") + e);
                    }
                }
                JNode r; r.v = std::string(to_hex(tx.txid())); return json_dump(r);
            } else {
                return err(e);
            }
        }

        // ---------------- chain-related helpers ----------------

        if(method=="estimatemediantime"){
            auto hdrs = chain_.last_headers(11);
            if(hdrs.empty()){
                return json_dump(jnum(0.0));
            }
            std::vector<int64_t> ts;
            ts.reserve(hdrs.size());
            for(auto& p : hdrs) ts.push_back(p.first);
            std::sort(ts.begin(), ts.end());
            double mtp = (double)ts[ts.size()/2];
            return json_dump(jnum(mtp));
        }

        if(method=="getdifficulty"){
            double d = (double)Chain::work_from_bits_public(chain_.tip().bits);
            return json_dump(jnum(d));
        }

        if(method=="getchaintips"){
            // Minimal: only the active tip (we don't expose side branches here)
            auto tip = chain_.tip();
            std::map<std::string,JNode> t;
            t["height"]    = jnum((double)tip.height);
            t["hash"]      = jstr(to_hex(tip.hash));
            t["branchlen"] = jnum(0.0);
            t["status"]    = jstr("active");
            JNode obj; obj.v = t;
            std::vector<JNode> arr; arr.push_back(obj);
            JNode out; out.v = arr; return json_dump(out);
        }

        // ---------------- p2p stubs (no P2P reference here) ----------------

        if(method=="getpeerinfo"){
            // Return empty list if P2P service isn't injected here
            std::vector<JNode> v; JNode out; out.v = v; return json_dump(out);
        }

        if(method=="getconnectioncount"){
            // Return 0 if not wired to P2P
            return json_dump(jnum(0.0));
        }

        return err("unknown method");
    } catch(const std::exception& ex){
        log_error(std::string("rpc handle exception: ")+ex.what());
        return err("internal error");
    } catch(...){
        log_error("rpc handle exception: unknown");
        return err("internal error");
    }
}

}
