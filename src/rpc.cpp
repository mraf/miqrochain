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

        if(method=="help"){
            static const char* k[] = {
                "help","version","ping","uptime",
                "getnetworkinfo","getblockchaininfo","getblockcount","getbestblockhash",
                "getblock","getblockhash","getcoinbaserecipient",
                "getrawmempool","gettxout",
                "validateaddress","decodeaddress","decoderawtx",
                "getminerstats","sendrawtransaction","sendtoaddress",
                "estimatemediantime","getdifficulty","getchaintips",
                "getpeerinfo","getconnectioncount"
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

        // sendtoaddress(priv_hex, to_address, amount) with auto-fee + change
        if(method=="sendtoaddress"){
            if(params.size()<3
               || !std::holds_alternative<std::string>(params[0].v)
               || !std::holds_alternative<std::string>(params[1].v)
               || !std::holds_alternative<std::string>(params[2].v)) {
                return err("need priv_hex, to_address, amount");
            }

            const std::string privh  = std::get<std::string>(params[0].v);
            const std::string toaddr = std::get<std::string>(params[1].v);
            const std::string amtstr = std::get<std::string>(params[2].v);

            std::vector<uint8_t> priv;
            try { priv = from_hex(privh); } catch(...) { return err("bad priv_hex"); }
            std::vector<uint8_t> pub33;
            if(!crypto::ECDSA::derive_pub(priv, pub33) || pub33.size()!=33) return err("derive_pub failed");
            const auto my_pkh = hash160(pub33);

            uint8_t ver=0; std::vector<uint8_t> to_payload;
            if(!base58check_decode(toaddr, ver, to_payload) || to_payload.size()!=20 || ver!=VERSION_P2PKH)
                return err("bad to_address");

            uint64_t amount = 0;
            try { amount = parse_amount_str(amtstr); }
            catch(...) { return err("bad amount"); }

            // Gather UTXOs
            auto utxos = chain_.utxo().list_for_pkh(my_pkh);
            if(utxos.empty()) return err("no funds");

            // Smallest-first to reduce change
            std::sort(utxos.begin(), utxos.end(),
                      [](const auto& A, const auto& B){
                          return std::get<2>(A).value < std::get<2>(B).value;
                      });

            Transaction tx;
            uint64_t in_sum = 0;

            for(const auto& itU : utxos){
                const auto& txid = std::get<0>(itU);
                uint32_t vout = std::get<1>(itU);
                const auto& e  = std::get<2>(itU);

                TxIn in; in.prev.txid = txid; in.prev.vout = vout;
                tx.vin.push_back(in);
                in_sum += e.value;

                uint64_t change_if_two = (in_sum > amount) ? (in_sum - amount) : 0;
                size_t nout_guess = (change_if_two > 0) ? 2 : 1;
                size_t est_size = estimate_size_bytes(tx.vin.size(), nout_guess);
                uint64_t fee = min_fee_for_size(est_size);

                if(in_sum >= amount + fee){
                    break;
                }
            }

            if(tx.vin.empty()) return err("insufficient funds");

            // Build outputs + fee
            TxOut out; out.pkh = to_payload;

            uint64_t fee_final = 0, change = 0;
            {
                size_t est_size = estimate_size_bytes(tx.vin.size(), 2);
                fee_final = min_fee_for_size(est_size);
                if(in_sum < amount + fee_final){
                    est_size = estimate_size_bytes(tx.vin.size(), 1);
                    fee_final = min_fee_for_size(est_size);
                    if(in_sum < amount + fee_final) return err("insufficient funds (need amount+fee)");
                    change = 0;
                } else {
                    change = in_sum - amount - fee_final;
                    if(change < DUST_THRESHOLD){
                        change = 0;
                        size_t est2 = estimate_size_bytes(tx.vin.size(), 1);
                        fee_final = min_fee_for_size(est2);
                        if(in_sum < amount + fee_final) return err("insufficient after dust fold");
                    }
                }
            }

            out.value = amount;
            tx.vout.push_back(out);

            if(change > 0){
                TxOut ch; ch.value = change; ch.pkh = my_pkh;
                tx.vout.push_back(ch);
            }

            // Sign all inputs (single-key case)
            auto sighash = [&](){
                Transaction t=tx; for(auto& i: t.vin){ i.sig.clear(); i.pubkey.clear(); }
                return dsha256(ser_tx(t));
            }();
            for(auto& in : tx.vin){
                std::vector<uint8_t> sig64;
                if(!crypto::ECDSA::sign(priv, sighash, sig64)) return err("sign failed");
                in.sig = sig64;
                in.pubkey = pub33;
            }

            // Mempool accept
            auto tip = chain_.tip(); std::string e;
            if(mempool_.accept(tx, chain_.utxo(), (size_t)tip.height, e)){
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
