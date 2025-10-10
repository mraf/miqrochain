// src/main.cpp  — MIQ core entrypoint (MSVC-safe; no lambda-capture pitfalls)

// Prevent Windows headers from defining min/max macros that break std::min/std::max
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#endif

#include "constants.h"
#include "address.h"
#include "wallet_store.h"
#include <exception>
#include "config.h"
#include "log.h"
#include "chain.h"
#include "mempool.h"
#include "miner.h"
#include "rpc.h"
#include "p2p.h"
#include "tx.h"
#include "serialize.h"
#include "sha256.h"
#include "base58check.h"
#include "hash160.h"
#include "merkle.h"
#include "crypto/ecdsa_iface.h"
#include "hex.h"
#include "difficulty.h"   // epoch_next_bits

#include "tls_proxy.h"    // TLS terminator for RPC (if used)
#include "ibd_monitor.h"  // IBD sampling for getibdinfo

// === UTXO KV + Reindex =======================================================
#include "utxo_kv.h"
#include "reindex_utxo.h"
// ============================================================================

#include <thread>
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

// Load the *existing* genesis private key.
// Accepts: env MIQ_GENESIS_PRIV_HEX (64 hex) or <datadir>/genesis.key (32 raw bytes or 64 hex).
static bool load_existing_genesis_priv(const std::string& datadir, std::vector<uint8_t>& out32){
    // 1) Environment override
    if (const char* h = std::getenv("MIQ_GENESIS_PRIV_HEX")) {
        auto v = miq::from_hex(std::string(h));
        if (v.size() == 32) { out32 = std::move(v); return true; }
        return false;
    }
    // 2) datadir/genesis.key
    std::vector<uint8_t> buf;
    if (read_file_all(datadir + "/genesis.key", buf)) {
        if (buf.size() == 32) { out32 = std::move(buf); return true; }
        // allow text hex file
        std::string s(reinterpret_cast<const char*>(buf.data()), buf.size());
        auto v = miq::from_hex(s);
        if (v.size() == 32) { out32 = std::move(v); return true; }
        return false;
    }
    return false; // not found
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

    // Grab a generous number in feerate order, then trim by bytes.
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
    std::fputs("[FATAL] std::terminate() called (likely from a background thread)\n", stderr);
    std::abort();
}

// Miner worker extracted to a named function (no lambda captures)
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

    // Soft cap (bytes) to keep blocks < 1 MiB
    const size_t kBlockMaxBytes = 900 * 1024;

    while (!g_shutdown_requested.load()) {
        try {
            // ---- A) get tip
            auto t = chain->tip();

            // ---- B) build coinbase (vin)
            Transaction cbt;
            TxIn cin;
            cin.prev.txid = std::vector<uint8_t>(32, 0);
            cin.prev.vout = 0;
            cbt.vin.push_back(cin);

            // ---- C) build coinbase (vout)
            TxOut cbout;

            // C1: set value
            cbout.value = chain->subsidy_for_height(t.height + 1);

            // C2: assign pkh (strict 20 bytes)
            if (mine_pkh.size() != 20) {
                log_error(std::string("miner C2(assign pkh) fatal: pkh size != 20 (got ")
                          + std::to_string(mine_pkh.size()) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            cbout.pkh.resize(20);
            std::memcpy(cbout.pkh.data(), mine_pkh.data(), 20);

            // C3: push_back into vout
            cbt.vout.push_back(cbout);

            // C4: ensure coinbase txid is UNIQUE per block
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

            // ---- D) collect mempool txs (size-capped)
            std::vector<Transaction> txs;
            try {
                txs = collect_mempool_for_block(*mempool, cbt, kBlockMaxBytes);
            } catch(...) {
                txs.clear();
            }

            // ---- E) mine_block using EPOCH retarget (matches consensus)
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

            // ---- F) submit_block
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

// Resolve mining address. Interactive prompt if mining_enabled=true; otherwise try env/default wallet.
static bool resolve_mining_address(std::vector<uint8_t>& out_pkh, bool mining_enabled, const std::string& /*conf_hint*/){
    out_pkh.clear();

    // 0) Interactive prompt (every run)
    if(mining_enabled){
        while(true){
            std::cout << "Enter mining address (P2PKH Base58Check), or leave blank to skip mining: " << std::flush;
            std::string addr;
            if(!std::getline(std::cin, addr)){
                log_warn("stdin closed; mining disabled for this run.");
                return false;
            }
            if(addr.empty()){
                log_info("No address provided; mining disabled for this run.");
                return false;
            }
            uint8_t ver=0; std::vector<uint8_t> payload;
            if(base58check_decode(addr, ver, payload) && ver==VERSION_P2PKH && payload.size()==20){
                out_pkh = payload;
                log_info("Using mining address from interactive prompt");
                return true;
            }
            std::fprintf(stderr, "[ERROR] Invalid address. Expected P2PKH Base58Check (version 0x%02x). Try again.\n",
                         (unsigned)VERSION_P2PKH);
        }
    }

    // 1) Env override (used only if mining_enabled==false)
    if(const char* e = std::getenv("MIQ_MINING_ADDR")){
        uint8_t ver=0; std::vector<uint8_t> payload;
        if(base58check_decode(e, ver, payload) && ver==VERSION_P2PKH && payload.size()==20){
            out_pkh = payload;
            log_info("Using mining address from MIQ_MINING_ADDR");
            return true;
        } else {
            log_warn("MIQ_MINING_ADDR invalid (expects Base58Check P2PKH)");
        }
    }

    // 2) Default wallet store (used only if mining_enabled==false)
    {
        std::string a;
        if(miq::load_default_wallet_address(a)){
            uint8_t ver=0; std::vector<uint8_t> payload;
            if(base58check_decode(a, ver, payload) && ver==VERSION_P2PKH && payload.size()==20){
                out_pkh = payload;
                log_info("Using mining address from default wallet store");
                return true;
            }
        }
    }

    return false; // Not mining or no address available
}

static void print_usage(){
    std::cout
      << "miqrod options:\n"
      << "  --conf=<path>                                config file (key=value)\n"
      << "  --datadir=<path>                             data directory (overrides config)\n"
      << "  --genaddress                                generate ECDSA-P2PKH address (priv/pk/address)\n"
      << "  --buildtx <priv_hex> <prev_txid_hex> <vout> <value> <to_address>  (prints txhex)\n"
      << "  --reindex_utxo                              rebuild chainstate/UTXO from current chain\n"
      << "  --utxo_kv                                   (reserved) enable KV-backed UTXO at runtime if supported\n"
      << "Env:\n"
      << "  MIQ_MINING_ADDR     If set, node will mine to this address (Base58 P2PKH)\n"
      << "  MIQ_MINER_THREADS   If set, overrides miner thread count\n";
}

static bool is_recognized_arg(const std::string& s){
    if(s.rfind("--conf=",0)==0) return true;
    if(s.rfind("--datadir=",0)==0) return true;
    if(s=="--genaddress") return true;
    if(s=="--buildtx") return true;
    if(s=="--reindex_utxo") return true;
    if(s=="--utxo_kv") return true;
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
        // Prevent process death on write to a closed socket (Linux/Unix/BSD/macOS)
        std::signal(SIGPIPE, SIG_IGN);
#endif

        // ----- Parse CLI FIRST (no heavy work yet) -----------------------
        Config cfg;
        std::string conf;
        bool genaddr=false, buildtx=false;
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
            // Parse raw block bytes from constants
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

            // Deserialize and verify against pinned hash/merkle
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

        // Resolve mining address (prompt if needed — ALWAYS prompts first)
        std::vector<uint8_t> g_mine_pkh;
        bool have_addr = resolve_mining_address(g_mine_pkh, !cfg.no_mine, conf);
        if(!have_addr){
            cfg.no_mine = true; // disable mining for this run
        }

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

        // start IBD monitor
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

            // NEW: synchronize HTTP gate token to the RPC cookie so clients only need Authorization: Bearer <cookie>
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
                // trim trailing whitespace
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

        // --- Miner (off if no_mine or no address). Keep coinbase prev.vout=0.
        // Thread selection:
        // 1) If config provided miner_threads, use it.
        // 2) Else env MIQ_MINER_THREADS.
        // 3) Else DEFAULT 6 (double-click UX).
        unsigned threads = cfg.miner_threads;
        if (threads == 0) {
            if (const char* s = std::getenv("MIQ_MINER_THREADS")) {
                char* end = nullptr;
                long v = std::strtol(s, &end, 10);
                if (end != s && v > 0 && v <= 256) {
                    threads = static_cast<unsigned>(v);
                }
            }
        }
        if (threads == 0) threads = 6;
        log_info("miner: using " + std::to_string(threads) + " thread(s)");

        if(!cfg.no_mine){
            // Pass pointers and values explicitly (no lambda captures)
            P2P* p2p_ptr = cfg.no_p2p ? nullptr : &p2p;
            std::thread th(miner_worker, &chain, &mempool, p2p_ptr, g_mine_pkh, threads);
            th.detach();
        }

        log_info(std::string(CHAIN_NAME) + " core running. RPC " + std::to_string(RPC_PORT) +
                 ", P2P " + std::to_string(P2P_PORT));

        // Wait loop, responsive to shutdown signals
        while(!g_shutdown_requested.load()){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }

        // Begin shutdown
        log_info("Shutdown requested — stopping services...");
        try { rpc.stop(); } catch(...) {}
        try { p2p.stop(); } catch(...) {}
        // stop TLS proxy by destroying it (if applicable)
        try { /* if running */ } catch(...) {}
        { /* explicit reset via RAII on scope exit */ }

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
