// src/main.cpp  — MIQ core entrypoint (node-only by default; miner is optional/extern)

// Prevent Windows headers from defining min/max macros that break std::min/std::max
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#endif

#include "constants.h"
#include "config.h"
#include "log.h"
#include "chain.h"
#include "mempool.h"
#include "rpc.h"
#include "p2p.h"
#include "tx.h"
#include "serialize.h"
#include "base58check.h"
#include "hash160.h"
#include "crypto/ecdsa_iface.h"
#include "difficulty.h"
#include "miner.h"      // <- for miq::mine_block
#include "sha256.h"     // <- for dsha256
#include "hex.h"        // <- for to_hex / from_hex

#include "tls_proxy.h"    // TLS terminator for RPC (if used)
#include "ibd_monitor.h"  // IBD sampling for getibdinfo

// === UTXO KV + Reindex =======================================================
#include "utxo_kv.h"
#include "reindex_utxo.h"
// ============================================================================

#include <thread>
#include <cctype>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>   // memcpy
#include <cstdlib>   // getenv, setenv, _putenv_s, _dupenv_s
#include <csignal>   // signal handling
#include <atomic>
#include <memory>    // std::unique_ptr
#include <algorithm> // std::max
#include <ctime>     // time()
#include <random>    // extraNonce for unique coinbase txid
#include <type_traits>
#include <utility>
#include <cstdint>   // uint64_t

#if defined(_WIN32)
  #include <io.h>
  #define MIQ_ISATTY() (_isatty(_fileno(stdin)) != 0)
#else
  #include <unistd.h>
  #define MIQ_ISATTY() (::isatty(fileno(stdin)) != 0)
#endif

// Belt-and-suspenders: if min/max slipped in, kill them.
#ifdef _WIN32
#  ifdef min
#    undef min
#  endif
#  ifdef max
#    undef max
#  endif
#endif

using namespace miq;

static std::atomic<bool> g_shutdown_requested{false};

// ---------- default per-user datadir (stable across launch locations) --------
static std::string default_datadir() {
#ifdef _WIN32
    // %APPDATA%\miqrochain  (Roaming, works on all supported Windows)
    size_t len = 0; char* v = nullptr;
    if (_dupenv_s(&v, &len, "APPDATA") == 0 && v && len) {
        std::string base(v); free(v);
        return base + "\\miqrochain";
    }
    return "C:\\miqrochain-data";
#elif defined(__APPLE__)
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/Library/Application Support/miqrochain";
    return "./miqdata";
#else
    if (const char* xdg = std::getenv("XDG_DATA_HOME")) {
        if (*xdg) return std::string(xdg) + "/miqrochain";
    }
    const char* home = std::getenv("HOME");
    if (home && *home) return std::string(home) + "/.miqrochain";
    return "./miqdata";
#endif
}

static inline void trim_inplace(std::string& s) {
    auto notspace = [](int ch){ return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
}

// ---------- small helpers (file + optional genesis key loader) --------------
static bool read_file_all(const std::string& path, std::vector<uint8_t>& out){
    std::ifstream f(path, std::ios::binary);
    if(!f) return false;
    f.seekg(0, std::ios::end);
    std::streamsize n = f.tellg();
    if(n < 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize((size_t)n);
    if(n > 0 && !f.read(reinterpret_cast<char*>(out.data()), n)) return false;
    return true;
}

// POSIX-style simple signal handler (safe operations only).
static void handle_signal(int /*sig*/){
    g_shutdown_requested.store(true);
}

// ======== Simple mempool packer (MSVC-safe; no SFINAE needed) ===============
static std::vector<Transaction> collect_mempool_for_block(Mempool& mp,
                                                          const Transaction& coinbase,
                                                          size_t max_bytes) {
    const size_t coinbase_sz = ser_tx(coinbase).size();
    const size_t budget = (max_bytes > coinbase_sz) ? (max_bytes - coinbase_sz) : 0;

    auto cands = mp.collect(100000);
    std::vector<Transaction> kept;
    kept.reserve(cands.size());

    size_t used = 0;
    for (auto& tx : cands) {
        size_t sz = ser_tx(tx).size();
        if (used + sz > budget) continue;
        kept.push_back(std::move(tx));
        used += sz;
        if (used >= budget) break;
    }
    return kept;
}
// ============================================================================

// Fatal terminate hook extracted to a named function (avoids [] in set_terminate)
static void fatal_terminate() noexcept {
    // DO NOT abort; keep the node alive if a worker thread dies.
    std::fputs("[FATAL] std::terminate() called from a background thread (suppressed to keep node alive)\n", stderr);
    // best-effort sleep to avoid tight loop; the offending thread will end.
#ifdef _WIN32
    Sleep(10);
#else
    usleep(10 * 1000);
#endif
}

// Miner worker extracted to a named function (no lambda captures)
// NOTE: internal miner is disabled by default; this worker runs only when --mine is used.
static void miner_worker(Chain* chain,
                         Mempool* mempool,
                         P2P* p2p,
                         const std::vector<uint8_t> mine_pkh,
                         unsigned threads) {
    // thread-local RNG for extraNonce
    std::random_device rd;
    std::mt19937_64 gen(
        (uint64_t(std::chrono::high_resolution_clock::now().time_since_epoch().count())
        ^ (uint64_t)rd() ^ (uint64_t)(uintptr_t)&gen));

    const size_t kBlockMaxBytes = 900 * 1024;

    while (!g_shutdown_requested.load()) {
        try {
            auto t = chain->tip();

            // Build coinbase (vin)
            Transaction cbt;
            TxIn cin;
            cin.prev.txid = std::vector<uint8_t>(32, 0);
            cin.prev.vout = 0;
            cbt.vin.push_back(cin);

            // Build coinbase (vout)
            TxOut cbout;
            cbout.value = chain->subsidy_for_height(t.height + 1);

            if (mine_pkh.size() != 20) {
                log_error(std::string("miner C2(assign pkh) fatal: pkh size != 20 (got ")
                          + std::to_string(mine_pkh.size()) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            cbout.pkh.resize(20);
            std::memcpy(cbout.pkh.data(), mine_pkh.data(), 20);
            cbt.vout.push_back(cbout);

            // Ensure coinbase txid uniqueness
            cbt.lock_time = static_cast<uint32_t>(t.height + 1);
            const uint32_t ch   = static_cast<uint32_t>(t.height + 1);
            const uint32_t now  = static_cast<uint32_t>(time(nullptr));
            const uint64_t extraNonce = gen();

            std::vector<uint8_t> tag;
            tag.reserve(1 + 4 + 4 + 8);
            tag.push_back(0x01);
            tag.push_back(uint8_t(ch      & 0xff));
            tag.push_back(uint8_t((ch>>8) & 0xff));
            tag.push_back(uint8_t((ch>>16)& 0xff));
            tag.push_back(uint8_t((ch>>24)& 0xff));
            tag.push_back(uint8_t(now      & 0xff));
            tag.push_back(uint8_t((now>>8) & 0xff));
            tag.push_back(uint8_t((now>>16)& 0xff));
            tag.push_back(uint8_t((now>>24)& 0xff));
            for (int i=0;i<8;i++) tag.push_back(uint8_t((extraNonce >> (8*i)) & 0xff));
            cbt.vin[0].sig = std::move(tag);

            // Gather mempool txs (size-capped)
            std::vector<Transaction> txs;
            try {
                txs = collect_mempool_for_block(*mempool, cbt, kBlockMaxBytes);
            } catch(...) {
                txs.clear();
            }

            // Mine with epoch retarget
            Block b;
            try {
                auto last = chain->last_headers(MIQ_RETARGET_INTERVAL);
                uint32_t nb = miq::epoch_next_bits(
                    last,
                    BLOCK_TIME_SECS,
                    GENESIS_BITS,
                    /*next_height=*/ t.height + 1,
                    /*interval=*/ MIQ_RETARGET_INTERVAL
                );
                b = miq::mine_block(t.hash, nb, cbt, txs, threads);
            } catch (...) {
                log_error("miner D(mine_block) fatal");
                continue;
            }

            // Submit
            try {
                std::string err;
                if (chain->submit_block(b, err)) {
                    std::string miner_addr = "(unknown)";
                    std::string cb_txid_hex = "(n/a)";
                    if (!b.txs.empty()) {
                        cb_txid_hex = to_hex(b.txs[0].txid());
                        if (!b.txs[0].vout.empty() && b.txs[0].vout[0].pkh.size()==20) {
                            miner_addr = base58check_encode(VERSION_P2PKH, b.txs[0].vout[0].pkh);
                        }
                    }
                    int noncb = (int)b.txs.size() - 1;
                    log_info("mined block accepted, height=" + std::to_string(t.height + 1)
                             + ", miner=" + miner_addr
                             + ", coinbase_txid=" + cb_txid_hex
                             + ", txs=" + std::to_string(std::max(0, noncb)));

                    if (!g_shutdown_requested.load() && p2p) {
                        p2p->announce_block_async(b.block_hash());
                    }
                } else {
                    log_warn(std::string("mined block rejected: ") + err);
                }
            } catch (...) {
                log_error("miner F(submit_block) fatal");
            }

        } catch (...) {
            log_error("miner outer fatal");
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

static void print_usage(){
    std::cout
      << "miqrod (node) options:\n"
      << "  --conf=<path>                                config file (key=value)\n"
      << "  --datadir=<path>                             data directory (overrides config)\n"
      << "  --genaddress                                 generate ECDSA-P2PKH address (priv/pk/address)\n"
      << "  --buildtx <priv_hex> <prev_txid_hex> <vout> <value> <to_address>  (prints txhex)\n"
      << "  --reindex_utxo                               rebuild chainstate/UTXO from current chain\n"
      << "  --utxo_kv                                    (reserved) enable KV-backed UTXO at runtime if supported\n"
      << "  --mine                                       (optional) run built-in miner [NOT default]\n"
      << "\n"
      << "Recommended: run the separate miner executable (miqminer / miqp2pminer).\n"
      << "The node forms the distributed timestamp server by validating & serving blocks\n"
      << "over P2P; miners (external or --mine) timestamp by finding valid blocks.\n"
      << "Env:\n"
      << "  MIQ_MINER_THREADS   If set, overrides miner thread count\n"
      << "  MIQ_RPC_TOKEN       If set, HTTP gate token (synced to .cookie on start)\n";
}

static bool is_recognized_arg(const std::string& s){
    if(s.rfind("--conf=",0)==0) return true;
    if(s.rfind("--datadir=",0)==0) return true;
    if(s=="--genaddress") return true;
    if(s=="--buildtx") return true;
    if(s=="--reindex_utxo") return true;
    if(s=="--utxo_kv") return true;
    if(s=="--mine") return true;
    if(s=="--help") return true;
    return false;
}

int main(int argc, char** argv){
    try {
        // Make stdio unbuffered so single-shot commands print immediately.
        std::ios::sync_with_stdio(false);
        std::setvbuf(stdout, nullptr, _IONBF, 0);
        std::setvbuf(stderr, nullptr, _IONBF, 0);

        // Fatal terminate hook (helps catch background thread aborts)
        std::set_terminate(&fatal_terminate);

        // Register SIGINT/SIGTERM for graceful shutdown
        std::signal(SIGINT,  handle_signal);
        std::signal(SIGTERM, handle_signal);
#ifndef _WIN32
        std::signal(SIGPIPE, SIG_IGN);
#endif

        // ----- Parse CLI FIRST (no heavy work yet) -----------------------
        Config cfg;
        std::string conf;
        bool genaddr=false, buildtx=false, mine_flag=false;

        // NEW flags
        bool flag_reindex_utxo = false;
        bool flag_utxo_kv      = false;

        std::string privh, prevtxid_hex, toaddr;
        uint32_t vout=0;
        uint64_t value=0;

        // Guard unsupported flags
        for(int i=1;i<argc;i++){
            std::string a(argv[i]);
            if(a.rfind("--",0)==0 && !is_recognized_arg(a)){
                std::fprintf(stderr, "Unknown option: %s\nUse --help to see supported options.\n", argv[i]);
                return 2;
            }
        }

        // Parse supported args
        for(int i=1;i<argc;i++){
            std::string a(argv[i]);
            if(a.rfind("--conf=",0)==0){
                conf = a.substr(7);
            } else if(a.rfind("--datadir=",0)==0){
                cfg.datadir = a.substr(10);
            } else if(a=="--genaddress"){
                genaddr = true;
            } else if(a=="--buildtx" && i+5<argc){
                buildtx     = true;
                privh       = argv[++i];
                prevtxid_hex= argv[++i];
                vout        = (uint32_t)std::stoul(argv[++i]);
                value       = (uint64_t)std::stoull(argv[++i]);
                toaddr      = argv[++i];
            } else if(a=="--reindex_utxo"){
                flag_reindex_utxo = true;
            } else if(a=="--utxo_kv"){
                flag_utxo_kv = true; // reserved
            } else if(a=="--mine"){
                mine_flag = true;     // opt-in internal miner
            } else if(a=="--help"){
                print_usage();
                return 0;
            }
        }

        // ===== FAST PATHS: return before heavy init ======================
        if(genaddr){
            std::vector<uint8_t> priv;
            if(!crypto::ECDSA::generate_priv(priv)){
                std::fprintf(stderr, "keygen failed\n");
                return 1;
            }
            std::vector<uint8_t> pub33;
            if(!crypto::ECDSA::derive_pub(priv, pub33)){
                std::fprintf(stderr, "derive_pub failed\n");
                return 1;
            }
            auto pkh  = hash160(pub33);
            auto addr = base58check_encode(VERSION_P2PKH, pkh);
            std::cout
              << "priv_hex=" << to_hex(priv)   << "\n"
              << "pub_hex="  << to_hex(pub33)  << "\n"
              << "address="  << addr           << "\n";
            return 0;
        }

        if(buildtx){
            std::vector<uint8_t> priv = miq::from_hex(privh);
            std::vector<uint8_t> pub33;
            if(!crypto::ECDSA::derive_pub(priv, pub33)){
                std::fprintf(stderr, "derive_pub failed\n");
                return 1;
            }

            uint8_t ver=0; std::vector<uint8_t> to_payload;
            if(!base58check_decode(toaddr, ver, to_payload) || to_payload.size()!=20){
                std::fprintf(stderr, "bad to_address\n");
                return 1;
            }

            Transaction tx;
            TxIn in;
            in.prev.txid = miq::from_hex(prevtxid_hex);
            in.prev.vout = vout;
            tx.vin.push_back(in);

            TxOut out;
            out.value = value;
            out.pkh   = to_payload;
            tx.vout.push_back(out);

            auto h = dsha256(ser_tx(tx));
            std::vector<uint8_t> sig64;
            if(!crypto::ECDSA::sign(priv, h, sig64)){
                std::fprintf(stderr, "sign failed\n");
                return 1;
            }
            tx.vin[0].sig    = sig64;
            tx.vin[0].pubkey = pub33;

            auto raw = ser_tx(tx);
            std::cout << "txhex=" << to_hex(raw) << "\n";
            return 0;
        }
        // =================================================================

        std::fprintf(stderr, "[BOOT] enter main()\n");

        if(!conf.empty()){
            load_config(conf, cfg);
        }

        // Use stable per-user default datadir if not provided
        if(cfg.datadir.empty()) cfg.datadir = default_datadir();

        std::error_code ec;
        std::filesystem::create_directories(cfg.datadir, ec); // best-effort

        std::fprintf(stderr, "[BOOT] datadir=%s no_rpc=%d no_p2p=%d no_mine=%d\n",
                     cfg.datadir.c_str(), cfg.no_rpc?1:0, cfg.no_p2p?1:0, cfg.no_mine?1:0);

        // Consume the --utxo_kv flag (no-op, but prevents unused-var warning)
        if (flag_utxo_kv) {
            log_info("Flag --utxo_kv set (runtime no-op; UTXO KV backend is compiled-in).");
        }

        Chain chain;
        if(!chain.open(cfg.datadir)){
            log_error("failed to open chain data");
            return 1;
        }
        std::fprintf(stderr, "[BOOT] chain.open OK\n");

        // --- Genesis from pinned raw block --------------------------------
        std::fprintf(stderr, "[BOOT] load genesis from constants raw hex\n");
        {
            std::vector<uint8_t> raw;
            try {
                raw = miq::from_hex(GENESIS_RAW_BLOCK_HEX);
            } catch (...) {
                log_error("GENESIS_RAW_BLOCK_HEX is not valid hex");
                return 1;
            }
            if (raw.empty()) {
                log_error("GENESIS_RAW_BLOCK_HEX is empty");
                return 1;
            }

            Block g;
            if (!deser_block(raw, g)) {
                log_error("Failed to deserialize GENESIS_RAW_BLOCK_HEX");
                return 1;
            }

            const std::string got_hash   = to_hex(g.block_hash());
            const std::string want_hash  = std::string(GENESIS_HASH_HEX);
            if (got_hash != want_hash) {
                log_error(std::string("Genesis hash mismatch. got=") + got_hash + " want=" + want_hash);
                return 1;
            }

            const std::string got_merkle = to_hex(g.header.merkle_root);
            const std::string want_merkle= std::string(GENESIS_MERKLE_HEX);
            if (got_merkle != want_merkle) {
                log_error(std::string("Genesis merkle mismatch. got=") + got_merkle + " want=" + want_merkle);
                return 1;
            }

            std::fprintf(stderr, "[BOOT] init_genesis begin\n");
            if (!chain.init_genesis(g)) {
                log_error("genesis init failed");
                return 1;
            }
            std::fprintf(stderr, "[BOOT] init_genesis OK\n");
        }
        // ------------------------------------------------------------------

        // === Optional UTXO reindex BEFORE starting services ================
        if (flag_reindex_utxo) {
            log_info("ReindexUTXO: rebuilding chainstate from active chain...");
            UTXOKV utxo_kv;
            std::string err;
            if (!ReindexUTXO(chain, utxo_kv, /*compact_after=*/true, err)) {
                log_error(std::string("ReindexUTXO failed: ") + (err.empty() ? "unknown error" : err));
                return 1;
            }
            log_info("ReindexUTXO: done");
        }
        // ===================================================================

        // --- Services ---
        Mempool mempool;
        RpcService rpc(chain, mempool);

        P2P p2p(chain);
        p2p.set_datadir(cfg.datadir);   // persist peers/bans in datadir
        p2p.set_mempool(&mempool);      // enable tx relay from mempool
        rpc.set_p2p(&p2p);              // RPC can report peer info/conn count

        // Start P2P first so RPC has a valid P2P pointer immediately
        if(!cfg.no_p2p){
            if(p2p.start(P2P_PORT)){
                log_info("P2P listening on " + std::to_string(P2P_PORT));
                p2p.connect_seed(DNS_SEED, P2P_PORT);
            } else {
                log_warn("P2P failed to start on port " + std::to_string(P2P_PORT));
            }
        }

        // start IBD monitor (crash-safe in its own try/catch loop)
        start_ibd_monitor(&chain, &p2p);

        if(!cfg.no_rpc){
            // Enable RPC cookie auth (.cookie in datadir) and export token to HTTP layer
            miq::rpc_enable_auth_cookie(cfg.datadir);

            // **Security hardening**: require token on ALL RPC requests, even loopback.
#ifdef _WIN32
            _putenv_s("MIQ_RPC_REQUIRE_TOKEN", "1");
#else
            setenv("MIQ_RPC_REQUIRE_TOKEN", "1", 1);
#endif

            // Sync HTTP gate token to the RPC cookie so clients can use Authorization: Bearer <cookie>
            try {
                std::string cookie_path =
#ifdef _WIN32
                    cfg.datadir + "\\.cookie";
#else
                    cfg.datadir + "/.cookie";
#endif
                std::vector<uint8_t> buf;
                if (!read_file_all(cookie_path, buf)) {
                    throw std::runtime_error("failed to read cookie");
                }
                std::string tok(buf.begin(), buf.end());
                while(!tok.empty() && (tok.back()=='\r'||tok.back()=='\n'||tok.back()==' '||tok.back()=='\t')) tok.pop_back();
#ifdef _WIN32
                _putenv_s("MIQ_RPC_TOKEN", tok.c_str());
#else
                setenv("MIQ_RPC_TOKEN", tok.c_str(), 1);
#endif
                log_info("HTTP gate token synchronized with RPC cookie");
            } catch (...) {
                log_warn("Could not sync MIQ_RPC_TOKEN to cookie; clients may need X-Auth-Token");
            }

            rpc.start(RPC_PORT);
            log_info("RPC listening on " + std::to_string(RPC_PORT));
        }

        // --- Built-in miner (OFF by default). Opt-in with --mine -----------
        unsigned threads = 0;
        if (mine_flag) {
            // choose threads
            if (cfg.miner_threads) threads = cfg.miner_threads;
            if (threads == 0) {
                if (const char* s = std::getenv("MIQ_MINER_THREADS")) {
                    char* end = nullptr;
                    long v = std::strtol(s, &end, 10);
                    if (end != s && v > 0 && v <= 256) {
                        threads = static_cast<unsigned>(v);
                    }
                }
            }
            if (threads == 0) threads = std::max(1u, std::thread::hardware_concurrency());

            // ask for mining address interactively ONLY when --mine was specified and a TTY exists
            std::vector<uint8_t> mine_pkh;
            if (MIQ_ISATTY()) {
                std::string addr;
                std::cout << "Enter P2PKH Base58 address to mine to (leave empty to cancel): ";
                std::getline(std::cin, addr);
                trim_inplace(addr);
                if (!addr.empty()) {
                    uint8_t ver=0; std::vector<uint8_t> payload;
                    if (base58check_decode(addr, ver, payload) && ver==VERSION_P2PKH && payload.size()==20) {
                        mine_pkh = payload;
                    } else {
                        log_error("Invalid mining address; built-in miner disabled.");
                    }
                } else {
                    log_info("No address entered; built-in miner disabled.");
                }
            } else {
                log_info("No TTY available; built-in miner disabled.");
            }

            if (!mine_pkh.empty()) {
                P2P* p2p_ptr = cfg.no_p2p ? nullptr : &p2p;
                std::thread th(miner_worker, &chain, &mempool, p2p_ptr, mine_pkh, threads);
                th.detach();
                log_info("Built-in miner started with " + std::to_string(threads) + " thread(s).");
            }
        } else {
            log_info("Miner not started (run external miner or use --mine to opt in).");
        }

        log_info(std::string(CHAIN_NAME) + " node running. RPC " + std::to_string(RPC_PORT) +
                 ", P2P " + std::to_string(P2P_PORT));

        // Wait loop, responsive to shutdown signals
        while(!g_shutdown_requested.load()){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Begin shutdown
        log_info("Shutdown requested — stopping services...");
        try { rpc.stop(); } catch(...) {}
        try { p2p.stop(); } catch(...) {}
        log_info("Shutdown complete.");
        return 0;

    } catch(const std::exception& ex){
        std::fprintf(stderr, "[FATAL] %s\n", ex.what());
        return 1;
    } catch(...){
        std::fprintf(stderr, "[FATAL] unknown exception\n");
        return 1;
    }
}
