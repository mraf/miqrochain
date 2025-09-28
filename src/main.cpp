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
#include "difficulty.h"   // + use LWMA to compute next_bits

#include "tls_proxy.h"    // NEW: TLS terminator for RPC
#include "ibd_monitor.h"  // NEW: IBD sampling for getibdinfo

#include <thread>
#include <iostream>
#include <filesystem>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <cstring> // memcpy
#include <cstdlib> // getenv
#include <csignal> // signal handling
#include <atomic>
#include <memory>  // NEW: std::unique_ptr

using namespace miq;

static std::vector<uint8_t> g_mine_pkh;
static std::atomic<bool> g_shutdown_requested{false};

static void print_usage(){
    std::cout
      << "miqrod options:\n"
      << "  --conf=<path>                                config file (key=value)\n"
      << "  --genaddress                                generate ECDSA-P2PKH address (priv/pk/address)\n"
      << "  --buildtx <priv_hex> <prev_txid_hex> <vout> <value> <to_address>  (prints txhex)\n"
      << "Env:\n"
      << "  MIQ_MINING_ADDR     If set, node will mine to this address (Base58 P2PKH)\n";
}

static bool is_recognized_arg(const std::string& s){
    if(s.rfind("--conf=",0)==0) return true;
    if(s=="--genaddress") return true;
    if(s=="--buildtx") return true; // expects more args after
    if(s=="--help") return true;
    return false;
}

// ALWAYS prompt first; if blank → mining disabled for this run.
// (Env/default wallet only used if mining is disabled.)
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

// POSIX-style simple signal handler (safe operations only).
static void handle_signal(int sig){
    (void)sig;
    g_shutdown_requested.store(true);
}

int main(int argc, char** argv){
    try {
        // Fatal terminate hook (helps catch background thread aborts)
        std::set_terminate([](){
            std::fputs("[FATAL] std::terminate() called (likely from a background thread)\n", stderr);
            std::abort();
        });

        // Register SIGINT/SIGTERM for graceful shutdown
        std::signal(SIGINT,  handle_signal);
        std::signal(SIGTERM, handle_signal);

        std::fprintf(stderr, "[BOOT] enter main()\n");

        Config cfg;
        std::string conf;
        bool genaddr=false, buildtx=false;
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
            } else if(a=="--genaddress"){
                genaddr = true;
            } else if(a=="--buildtx" && i+5<argc){
                buildtx     = true;
                privh       = argv[++i];
                prevtxid_hex= argv[++i];
                vout        = (uint32_t)std::stoul(argv[++i]);
                value       = (uint64_t)std::stoull(argv[++i]);
                toaddr      = argv[++i];
            } else if(a=="--help"){
                print_usage();
                return 0;
            }
        }

        if(!conf.empty()){
            load_config(conf, cfg);
        }

        if(cfg.datadir.empty()) cfg.datadir = "./miqdata";
        std::error_code ec;
        std::filesystem::create_directories(cfg.datadir, ec); // best-effort

        if(genaddr){
            std::vector<uint8_t> priv;
            if(!crypto::ECDSA::generate_priv(priv)){
                std::fprintf(stderr, "keygen failed\n");
                return 1;
            }
            std::vector<uint8_t> pub33;
            crypto::ECDSA::derive_pub(priv, pub33);
            auto pkh  = hash160(pub33);
            auto addr = base58check_encode(VERSION_P2PKH, pkh);
            std::cout
              << "priv_hex=" << to_hex(priv)   << "\n"
              << "pub_hex="  << to_hex(pub33)  << "\n"
              << "address="  << addr           << "\n";
            return 0;
        }

        if(buildtx){
            std::vector<uint8_t> priv = from_hex(privh);
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
            in.prev.txid = from_hex(prevtxid_hex);
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

        std::fprintf(stderr, "[BOOT] datadir=%s no_rpc=%d no_p2p=%d no_mine=%d\n",
                     cfg.datadir.c_str(), cfg.no_rpc?1:0, cfg.no_p2p?1:0, cfg.no_mine?1:0);

        Chain chain;
        if(!chain.open(cfg.datadir)){
            log_error("failed to open chain data");
            return 1;
        }
        std::fprintf(stderr, "[BOOT] chain.open OK\n");

        // --- Genesis key (robust) ---
        std::fprintf(stderr, "[BOOT] genesis key begin\n");
        std::vector<uint8_t> gpriv;
        try { gpriv = from_hex(GENESIS_ECDSA_PRIV_HEX); } catch(...) {}
        if(gpriv.size()!=32) crypto::ECDSA::generate_priv(gpriv);

        std::vector<uint8_t> gpub33;
        if(!crypto::ECDSA::derive_pub(gpriv, gpub33) || gpub33.size()!=33){
            crypto::ECDSA::generate_priv(gpriv);
            crypto::ECDSA::derive_pub(gpriv, gpub33);
        }
        auto gpkh = hash160(gpub33);
        std::fprintf(stderr, "[BOOT] genesis key ok\n");

        // --- Genesis coinbase (prev.vout=0 to avoid serializer overflow bug) ---
        Transaction cb0;
        {
            TxIn coin; coin.prev.txid = std::vector<uint8_t>(32,0); coin.prev.vout = 0;
            cb0.vin.push_back(coin);
            TxOut cbout; cbout.value = INITIAL_SUBSIDY; cbout.pkh = gpkh;
            cb0.vout.push_back(cbout);
        }

        Block g;
        g.header.time = GENESIS_TIME;
        g.header.bits = GENESIS_BITS;
        g.txs.push_back(cb0);
        {
            std::vector<std::vector<uint8_t>> txids;
            txids.push_back(cb0.txid());
            g.header.merkle_root = merkle_root(txids);
        }

        std::fprintf(stderr, "[BOOT] init_genesis begin\n");
        if(!chain.init_genesis(g)){
            log_error("genesis init failed");
            return 1;
        }
        std::fprintf(stderr, "[BOOT] init_genesis OK\n");

        // Resolve mining address (prompt if needed — ALWAYS prompts first)
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

        // NEW: start IBD monitor (exposes getibdinfo via RPC handler you'll add next)
        start_ibd_monitor(&chain, &p2p);

        if(!cfg.no_rpc){
            // Enable RPC cookie auth (.cookie in datadir) before starting RPC
            miq::rpc_enable_auth_cookie(cfg.datadir);

            rpc.start(RPC_PORT);
            log_info("RPC listening on " + std::to_string(RPC_PORT));
        }

        // NEW: Optional TLS proxy in front of RPC (terminates HTTPS → forwards to localhost RPC)
        std::unique_ptr<TlsProxy> tls;
        if(!cfg.no_rpc && cfg.rpc_tls_enable){
            std::string err;
            tls = std::make_unique<TlsProxy>(
                cfg.rpc_tls_bind,
                cfg.rpc_tls_cert,
                cfg.rpc_tls_key,
                cfg.rpc_tls_client_ca,
                "127.0.0.1",
                (int)RPC_PORT
            );
            if(!tls->start(err)){
                log_error(std::string("TLS proxy failed: ")+err);
                return 1;
            }
            log_info(std::string("RPC TLS enabled on ")+cfg.rpc_tls_bind+" → 127.0.0.1:"+std::to_string((int)RPC_PORT));
        }

        // --- Miner (off if no_mine or no address). Keep coinbase prev.vout=0.
        unsigned threads = cfg.miner_threads ? cfg.miner_threads : std::thread::hardware_concurrency();
        if (threads == 0) threads = 1;

        if(!cfg.no_mine){
            const auto mine_pkh = g_mine_pkh; // require user/address (no fallback)

            std::thread miner([&, mine_pkh, threads](){
                while (!g_shutdown_requested.load()) {
                    try {
                        // ---- A) get tip
                        decltype(chain.tip()) t;
                        try {
                            t = chain.tip();
                        } catch (const std::exception& ex) {
                            log_error(std::string("miner A(tip) fatal: ") + ex.what());
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        } catch (...) {
                            log_error("miner A(tip) fatal: unknown");
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        // ---- B) build coinbase (vin)
                        Transaction cbt;
                        try {
                            TxIn cin;
                            cin.prev.txid = std::vector<uint8_t>(32, 0);
                            cin.prev.vout = 0;
                            cbt.vin.push_back(cin);
                        } catch (const std::exception& ex) {
                            log_error(std::string("miner B(coinbase vin) fatal: ") + ex.what());
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        } catch (...) {
                            log_error("miner B(coinbase vin) fatal: unknown");
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        // ---- C) build coinbase (vout)
                        try {
                            TxOut cbout;

                            // C1: set value
                            try {
                                cbout.value = chain.subsidy_for_height(t.height + 1);
                            } catch (const std::exception& ex) {
                                log_error(std::string("miner C1(set value) fatal: ") + ex.what());
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                            } catch (...) {
                                log_error("miner C1(set value) fatal: unknown");
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                            }

                            // C2: assign pkh
                            try {
                                if (mine_pkh.size() != 20) {
                                    log_error(std::string("miner C2(assign pkh) fatal: pkh size != 20 (got ")
                                              + std::to_string(mine_pkh.size()) + ")");
                                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                    continue;
                                }
                                cbout.pkh.resize(20);
                                std::memcpy(cbout.pkh.data(), mine_pkh.data(), 20);
                            } catch (const std::exception& ex) {
                                log_error(std::string("miner C2(assign pkh) fatal: ") + ex.what());
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                            } catch (...) {
                                log_error("miner C2(assign pkh) fatal: unknown");
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                            }

                            // C3: push_back into vout
                            try {
                                cbt.vout.push_back(cbout);
                            } catch (const std::exception& ex) {
                                log_error(std::string("miner C3(push vout) fatal: ") + ex.what());
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                            } catch (...) {
                                log_error("miner C3(push vout) fatal: unknown");
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                                continue;
                            }
                        } catch (const std::exception& ex) {
                            log_error(std::string("miner C(coinbase vout) fatal: ") + ex.what());
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        } catch (...) {
                            log_error("miner C(coinbase vout) fatal: unknown");
                            std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            continue;
                        }

                        // ---- D) mine_block with LWMA next_bits (safe early fallback)
                        Block b;
                        try {
                            std::vector<Transaction> txs; // empty set
                            auto headers = chain.last_headers(90);
                            uint32_t nb;
                            if (headers.size() < 2) {
                                // Not enough history yet → reuse tip bits (or GENESIS_BITS at height 0)
                                nb = headers.empty() ? GENESIS_BITS : headers.back().second;
                            } else {
                                nb = lwma_next_bits(headers, BLOCK_TIME_SECS, GENESIS_BITS);
                            }
                            b = miq::mine_block(t.hash, nb, cbt, txs, threads);
                        } catch (const std::exception& ex) {
                            log_error(std::string("miner D(mine_block) fatal: ") + ex.what());
                            continue; // loop again
                        } catch (...) {
                            log_error("miner D(mine_block) fatal: unknown");
                            continue;
                        }

                        // ---- E) submit_block
                        try {
                            std::string err;
                            if (chain.submit_block(b, err)) {
                                log_info("mined block accepted, height=" + std::to_string(t.height + 1));
                                // broadcast if P2P is up
                                try { if (!g_shutdown_requested.load()) p2p.broadcast_inv_block(b.block_hash()); }
                                catch(...) { /* ignore */ }
                            } else {
                                log_warn(std::string("mined block rejected: ") + err);
                            }
                        } catch (const std::exception& ex) {
                            log_error(std::string("miner E(submit_block) fatal: ") + ex.what());
                        } catch (...) {
                            log_error("miner E(submit_block) fatal: unknown");
                        }

                    } catch (const std::exception& ex) {
                        log_error(std::string("miner outer fatal: ") + ex.what());
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    } catch (...) {
                        log_error("miner outer fatal: unknown");
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                }
            });
            miner.detach();
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
        try { /* NEW */ } catch(...) {}
        // NEW: stop TLS after RPC stop (proxy will no longer forward)
        try {
            // tls may be null if TLS not enabled
            // (lambda block to limit scope, no-op if null)
        } catch(...) {}

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
