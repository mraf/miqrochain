// src/miqwallet.cpp - Professional MIQ Wallet CLI
// Production-grade SPV wallet with enterprise reliability and beautiful UI
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
#include <cstdint>
#include <atomic>
#include <mutex>
#include <memory>
#include <functional>
#include <regex>

// =============================================================================
// PRODUCTION CONSTANTS
// =============================================================================
namespace wallet_config {
    // Network resilience
    static constexpr int MAX_CONNECTION_RETRIES = 5;
    static constexpr int BASE_RETRY_DELAY_MS = 1000;
    static constexpr int MAX_RETRY_DELAY_MS = 30000;
    static constexpr int CONNECTION_TIMEOUT_MS = 15000;
    static constexpr int BROADCAST_TIMEOUT_MS = 10000;

    // Security limits
    static constexpr size_t MAX_UTXO_COUNT = 100000;
    static constexpr size_t MAX_TX_INPUTS = 1000;
    static constexpr size_t MAX_TX_OUTPUTS = 100;
    static constexpr uint64_t MAX_SINGLE_TX_VALUE = 1000000ULL * 100000000ULL;
    static constexpr uint64_t DUST_THRESHOLD = 546;

    // Memory management
    static constexpr size_t MAX_PENDING_CACHE = 10000;
    static constexpr size_t KEY_DERIVATION_BATCH = 100;

    // User experience
    static constexpr int SYNC_PROGRESS_INTERVAL_MS = 500;
    static constexpr int BALANCE_REFRESH_COOLDOWN_MS = 3000;
}

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
#include "wallet/spv_simple.h"

using miq::CHAIN_NAME;
using miq::COIN;

// =============================================================================
// UI STYLING - Professional Terminal Interface
// =============================================================================
namespace ui {
    static bool g_use_colors = true;

    // ANSI color codes
    inline std::string reset()   { return g_use_colors ? "\033[0m" : ""; }
    inline std::string bold()    { return g_use_colors ? "\033[1m" : ""; }
    inline std::string dim()     { return g_use_colors ? "\033[2m" : ""; }
    inline std::string cyan()    { return g_use_colors ? "\033[36m" : ""; }
    inline std::string green()   { return g_use_colors ? "\033[32m" : ""; }
    inline std::string yellow()  { return g_use_colors ? "\033[33m" : ""; }
    inline std::string red()     { return g_use_colors ? "\033[31m" : ""; }
    inline std::string blue()    { return g_use_colors ? "\033[34m" : ""; }
    inline std::string magenta() { return g_use_colors ? "\033[35m" : ""; }
    inline std::string white()   { return g_use_colors ? "\033[37m" : ""; }

    // Box drawing characters
    const char* const BOX_TL = "+";
    const char* const BOX_TR = "+";
    const char* const BOX_BL = "+";
    const char* const BOX_BR = "+";
    const char* const BOX_H  = "-";
    const char* const BOX_V  = "|";
    const char* const BOX_ML = "+";
    const char* const BOX_MR = "+";

    void print_header(const std::string& title, int width = 60) {
        std::cout << cyan() << bold();
        std::cout << BOX_TL;
        for(int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_TR << "\n";

        int padding = (width - 2 - (int)title.size()) / 2;
        std::cout << BOX_V;
        for(int i = 0; i < padding; i++) std::cout << " ";
        std::cout << title;
        for(int i = 0; i < width - 2 - padding - (int)title.size(); i++) std::cout << " ";
        std::cout << BOX_V << "\n";

        std::cout << BOX_BL;
        for(int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_BR << reset() << "\n";
    }

    void print_separator(int width = 60) {
        std::cout << dim();
        for(int i = 0; i < width; i++) std::cout << "-";
        std::cout << reset() << "\n";
    }

    void print_banner() {
        std::cout << cyan() << bold();
        std::cout << R"(
    __  __ ___ ___   __        __    _ _      _
   |  \/  |_ _/ _ \  \ \      / /_ _| | | ___| |_
   | |\/| || | | | |  \ \ /\ / / _` | | |/ _ \ __|
   | |  | || | |_| |   \ V  V / (_| | | |  __/ |_
   |_|  |_|___\__\_\    \_/\_/ \__,_|_|_|\___|\__|

)" << reset();
        std::cout << dim() << "        Professional Cryptocurrency Wallet v1.0" << reset() << "\n\n";
    }

    void print_success(const std::string& msg) {
        std::cout << green() << bold() << "[OK] " << reset() << msg << "\n";
    }

    void print_error(const std::string& msg) {
        std::cout << red() << bold() << "[ERROR] " << reset() << msg << "\n";
    }

    void print_warning(const std::string& msg) {
        std::cout << yellow() << bold() << "[WARNING] " << reset() << msg << "\n";
    }

    void print_info(const std::string& msg) {
        std::cout << blue() << "[INFO] " << reset() << msg << "\n";
    }

    void print_progress(const std::string& msg) {
        std::cout << "\r" << cyan() << "[...] " << reset() << msg << std::flush;
    }

    void clear_line() {
        std::cout << "\r" << std::string(80, ' ') << "\r" << std::flush;
    }

    std::string prompt(const std::string& msg) {
        std::cout << yellow() << "> " << reset() << msg;
        std::string input;
        std::getline(std::cin, input);
        return input;
    }

    std::string secure_prompt(const std::string& msg) {
        std::cout << yellow() << "> " << reset() << msg;
        // Note: For true secure input, we'd disable echo. For now, standard input.
        std::string input;
        std::getline(std::cin, input);
        return input;
    }

    bool confirm(const std::string& msg) {
        std::cout << yellow() << "? " << reset() << msg << " [y/N]: ";
        std::string input;
        std::getline(std::cin, input);
        return !input.empty() && (input[0] == 'y' || input[0] == 'Y');
    }
}

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================
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

[[maybe_unused]] static bool env_truthy(const char* name){
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
        size_t pos = wfile.find_last_of("/\\");
        if(pos!=std::string::npos) wfile = wfile.substr(0,pos);
        return wfile;
    }
    return "wallets/default";
}

static void clear_spv_cache(const std::string& wdir){
    std::string state_file = join_path(wdir, "spv_state.dat");
    std::string utxo_file = join_path(wdir, "utxo_cache.dat");
    std::remove(state_file.c_str());
    std::remove(utxo_file.c_str());
}

// =============================================================================
// PENDING-SPENT CACHE
// =============================================================================
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

// =============================================================================
// NETWORK HELPERS
// =============================================================================
#ifdef _WIN32
  #ifndef WIN32_LEAN_AND_MEAN
  #define WIN32_LEAN_AND_MEAN
  #endif
  #ifndef NOMINMAX
  #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "Ws2_32.lib")
  static void winsock_ensure(){
      static bool inited=false;
      if(!inited){
          WSADATA wsa;
          if (WSAStartup(MAKEWORD(2,2), &wsa)==0) inited=true;
      }
  }
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  static void winsock_ensure(){}
#endif

static bool is_public_ipv4_literal(const std::string& host){
    sockaddr_in a{};
#ifdef _WIN32
    if (InetPtonA(AF_INET, host.c_str(), &a.sin_addr) != 1) return false;
#else
    if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) != 1) return false;
#endif
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&a.sin_addr);
    const uint8_t A = b[0], B = b[1];
    if (A==127) return false;
    if (A==10) return false;
    if (A==172 && B>=16 && B<=31) return false;
    if (A==192 && B==168) return false;
    return true;
}

static bool resolves_to_public_ip(const std::string& host){
    winsock_ensure();

    bool is_numeric_ip = true;
    for(char c : host){
        if(c!='.' && !std::isdigit((unsigned char)c)){
            is_numeric_ip = false; break;
        }
    }

    if(is_numeric_ip){
        if(host == "127.0.0.1") return true;
        return is_public_ipv4_literal(host);
    }

    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if(getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0) return false;

    bool found_public = false;
    for(addrinfo* p = res; p; p = p->ai_next){
        if(p->ai_family == AF_INET){
            sockaddr_in* sin = (sockaddr_in*)p->ai_addr;
            const uint8_t* b = reinterpret_cast<const uint8_t*>(&sin->sin_addr);
            const uint8_t A = b[0], B = b[1];
            bool is_pub = true;
            if(A==127||A==10) is_pub=false;
            if(A==172 && B>=16 && B<=31) is_pub=false;
            if(A==192 && B==168) is_pub=false;
            if(is_pub){ found_public = true; break; }
        }
    }
    freeaddrinfo(res);
    return found_public;
}

// =============================================================================
// SEED NODE MANAGEMENT
// =============================================================================
static std::vector<std::pair<std::string,std::string>> build_seed_candidates(
    const std::string& cli_host, const std::string& cli_port)
{
    std::vector<std::pair<std::string,std::string>> out;
    const std::string default_port = std::to_string(miq::P2P_PORT);

    auto add_host_port = [&](const std::string& h, const std::string& p){
        for(const auto& x : out) if(x.first==h && x.second==p) return;
        out.push_back({h, p});
    };

    // 1) CLI argument (highest priority)
    if(!cli_host.empty()){
        add_host_port(cli_host, cli_port);
    }

    // 2) Environment variable
    if(const char* env = std::getenv("MIQ_P2P_SEED")){
        std::string s = env;
        size_t pos = 0;
        while(pos < s.size()){
            size_t comma = s.find(',', pos);
            if(comma == std::string::npos) comma = s.size();
            std::string tok = s.substr(pos, comma - pos);
            pos = comma + 1;
            tok = trim(tok);
            if(tok.empty()) continue;
            std::string h = tok, p = default_port;
            size_t col = tok.find(':');
            if(col != std::string::npos){ h = tok.substr(0,col); p = tok.substr(col+1); }
            add_host_port(h, p);
        }
    }

    // 3) Localhost (critical for local mining)
    if(!env_truthy("MIQ_NO_LOCAL_PRIORITY")){
        add_host_port("127.0.0.1", default_port);
    }

    // 4) Hardcoded public nodes
    add_host_port("62.38.73.147", default_port);

    // 5) DNS seeds
    add_host_port("seed.miqrochain.org", default_port);
    for(const auto& s : miq::DNS_SEEDS){
        add_host_port(s, default_port);
    }

    // Filter out private IPs (except localhost)
    std::vector<std::pair<std::string,std::string>> filtered;
    for(const auto& s : out){
        if(s.first == "127.0.0.1" || resolves_to_public_ip(s.first)){
            filtered.push_back(s);
        }
    }

    // Fallback to localhost if nothing else available
    if(filtered.empty() && !env_truthy("MIQ_NO_LOCAL_FALLBACK")){
        filtered.push_back({"127.0.0.1", default_port});
    }

    return filtered;
}

// =============================================================================
// SPV COLLECTION WITH PROGRESS
// =============================================================================
static bool spv_collect_any_seed(
    const std::vector<std::pair<std::string,std::string>>& seeds,
    const std::vector<std::vector<uint8_t>>& pkhs,
    uint32_t window,
    std::vector<miq::UtxoLite>& out,
    std::string& used_seed,
    std::string& err_out)
{
    for(const auto& [host, port] : seeds){
        std::string seed_str = host + ":" + port;
        ui::print_progress("Connecting to " + seed_str + "...");

        miq::SpvOptions opts;
        opts.recent_block_window = window;

        int max_attempts = (host == "127.0.0.1") ? 1 : wallet_config::MAX_CONNECTION_RETRIES;

        for(int attempt = 0; attempt < max_attempts; ++attempt){
            if(attempt > 0){
                int delay = std::min(
                    wallet_config::BASE_RETRY_DELAY_MS * (1 << std::min(attempt, 5)),
                    wallet_config::MAX_RETRY_DELAY_MS
                );
                ui::print_progress("Retry " + std::to_string(attempt+1) + "/" +
                                   std::to_string(max_attempts) + " in " +
                                   std::to_string(delay/1000) + "s...");
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }

            std::string local_err;

            if(miq::spv_collect_utxos(host, port, pkhs, opts, out, local_err)){
                ui::clear_line();
                used_seed = seed_str;
                return true;
            }

            err_out = seed_str + ": " + local_err;
        }
    }

    ui::clear_line();
    if(err_out.empty()) err_out = "No seed nodes available";
    return false;
}

// =============================================================================
// TRANSACTION BROADCASTING WITH PROGRESS
// =============================================================================
static bool broadcast_any_seed(
    const std::vector<std::pair<std::string,std::string>>& seeds,
    const std::vector<uint8_t>& raw_tx,
    std::string& used_seed,
    std::string& err_out)
{
    for(const auto& [host, port] : seeds){
        std::string seed_str = host + ":" + port;
        ui::print_progress("Broadcasting to " + seed_str + "...");

        for(int attempt = 0; attempt < wallet_config::MAX_CONNECTION_RETRIES; ++attempt){
            if(attempt > 0){
                int delay = std::min(
                    wallet_config::BASE_RETRY_DELAY_MS * (1 << std::min(attempt, 5)),
                    wallet_config::MAX_RETRY_DELAY_MS
                );
                // Add jitter
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<int> jitter(-delay/4, delay/4);
                delay += jitter(gen);

                ui::print_progress("Retry " + std::to_string(attempt+1) + "...");
                std::this_thread::sleep_for(std::chrono::milliseconds(delay));
            }

            std::string local_err;

            // Use P2PLight to broadcast transaction
            miq::P2PLight p2p;
            miq::P2POpts opts;
            opts.host = host;
            opts.port = port;
            opts.user_agent = "/miqwallet:1.0/";
            opts.io_timeout_ms = wallet_config::BROADCAST_TIMEOUT_MS;

            if(p2p.connect_and_handshake(opts, local_err)){
                if(p2p.send_tx(raw_tx, local_err)){
                    p2p.close();
                    ui::clear_line();
                    used_seed = seed_str;
                    return true;
                }
                p2p.close();
            }

            err_out = seed_str + ": " + local_err;
        }
    }

    ui::clear_line();
    if(err_out.empty()) err_out = "All broadcast attempts failed";
    return false;
}

// =============================================================================
// AMOUNT FORMATTING
// =============================================================================
static uint64_t parse_amount_miqron(const std::string& s){
    // Supports "1.5" or "150000000"
    double d = std::stod(s);
    if(d < 0) throw std::runtime_error("negative amount");
    if(d > (double)wallet_config::MAX_SINGLE_TX_VALUE / (double)COIN){
        throw std::runtime_error("amount too large");
    }
    return (uint64_t)std::round(d * (double)COIN);
}

static size_t est_size_bytes(size_t nin, size_t nout){
    return nin * 148 + nout * 34 + 10;
}

static uint64_t fee_for(size_t nin, size_t nout, uint64_t feerate_per_kb){
    size_t sz = est_size_bytes(nin, nout);
    return ((sz + 999) / 1000) * feerate_per_kb;
}

static std::string fmt_amount(uint64_t miqron){
    std::ostringstream os;
    os << std::fixed << std::setprecision(8) << ((double)miqron / (double)COIN);
    return os.str();
}

static std::string fmt_amount_short(uint64_t miqron){
    std::ostringstream os;
    os << std::fixed << std::setprecision(4) << ((double)miqron / (double)COIN);
    return os.str();
}

// =============================================================================
// BALANCE COMPUTATION
// =============================================================================
struct WalletBalance {
    uint64_t total{0};
    uint64_t spendable{0};
    uint64_t immature{0};
    uint64_t pending_hold{0};
    uint64_t approx_tip_h{0};
};

static inline bool safe_add(uint64_t& sum, uint64_t val) {
    if (val > UINT64_MAX - sum) return false;
    sum += val;
    return true;
}

static WalletBalance compute_balance(const std::vector<miq::UtxoLite>& utxos,
                                     const std::set<OutpointKey>& pending)
{
    WalletBalance wb{};
    for(const auto& u : utxos) wb.approx_tip_h = std::max<uint64_t>(wb.approx_tip_h, u.height);

    for(const auto& u: utxos){
        if (!safe_add(wb.total, u.value)) {
            wb.total = UINT64_MAX;
        }
        bool is_immature = false;
        if(u.coinbase){
            uint64_t mature_h = (uint64_t)u.height + (uint64_t)miq::COINBASE_MATURITY;
            if(wb.approx_tip_h + 1 < mature_h) is_immature = true;
        }
        OutpointKey k{ miq::to_hex(u.txid), u.vout };
        bool held = (pending.find(k) != pending.end());
        if(is_immature) {
            if (!safe_add(wb.immature, u.value)) wb.immature = UINT64_MAX;
        }
        else if(held) {
            if (!safe_add(wb.pending_hold, u.value)) wb.pending_hold = UINT64_MAX;
        }
        else {
            if (!safe_add(wb.spendable, u.value)) wb.spendable = UINT64_MAX;
        }
    }
    return wb;
}

// =============================================================================
// WALLET SESSION - Main Wallet Interface
// =============================================================================
static bool wallet_session(const std::string& cli_host,
                           const std::string& cli_port,
                           std::vector<uint8_t> seed,
                           miq::HdAccountMeta meta,
                           const std::string& pass)
{
    miq::HdWallet w(seed, meta);
    const std::string wdir = default_wallet_dir();

    // Derive key horizon with GAP lookahead
    struct Key { std::vector<uint8_t> priv, pub, pkh; uint32_t chain, index; };
    std::vector<Key> keys;
    auto add_range = [&](uint32_t chain, uint32_t upto){
        const uint32_t GAP = (uint32_t)env_u64("MIQ_GAP_LIMIT", 1000);
        for(uint32_t i=0;i<=upto + GAP; ++i){
            Key k; k.chain=chain; k.index=i;
            if(!w.DerivePrivPub(meta.account, chain, i, k.priv, k.pub)) continue;
            k.pkh = miq::hash160(k.pub);
            keys.push_back(std::move(k));
        }
    };
    add_range(0, meta.next_recv);
    add_range(1, meta.next_change);

    std::vector<std::vector<uint8_t>> pkhs; pkhs.reserve(keys.size());
    for(auto& k: keys) pkhs.push_back(k.pkh);

    std::unordered_map<std::string, std::pair<uint32_t,uint32_t>> pkh2ci;
    pkh2ci.reserve(keys.size());
    for (const auto& k : keys) {
        pkh2ci[miq::to_hex(k.pkh)] = {k.chain, k.index};
    }

    auto seeds = build_seed_candidates(cli_host, cli_port);
    const uint32_t spv_win = (uint32_t)env_u64("MIQ_SPV_WINDOW", 0);

    std::set<OutpointKey> pending;
    load_pending(wdir, pending);

    // Cache for derived addresses
    std::unordered_map<uint32_t, std::string> addr_cache;
    for(uint32_t i = 0; i <= meta.next_recv + 10; ++i){
        std::string addr;
        if(w.GetAddressAt(i, addr)){
            addr_cache[i] = addr;
        }
    }

    // Refresh balance function
    auto refresh_and_print = [&]()->std::vector<miq::UtxoLite>{
        ui::print_info("Syncing wallet with network...");

        std::vector<miq::UtxoLite> utxos;
        std::string used_seed, err;

        if(!spv_collect_any_seed(seeds, pkhs, spv_win, utxos, used_seed, err)){
            std::cout << "\n";
            ui::print_error("Failed to sync with network");
            std::cout << ui::dim() << err << ui::reset() << "\n\n";

            ui::print_header("TROUBLESHOOTING", 50);
            std::cout << "  1. Ensure miqrochain node is running\n";
            std::cout << "  2. Check port " << miq::P2P_PORT << " is accessible\n";
            std::cout << "  3. Try: miqwallet --p2pseed=127.0.0.1:" << miq::P2P_PORT << "\n";
            std::cout << "\n";
            used_seed = "<offline>";
        }

        // Prune pending entries
        {
            std::set<OutpointKey> cur;
            for(const auto& u : utxos) cur.insert(OutpointKey{ miq::to_hex(u.txid), u.vout });
            for(auto it = pending.begin(); it != pending.end(); ){
                if(cur.find(*it) == cur.end()) it = pending.erase(it);
                else ++it;
            }
            save_pending(wdir, pending);
        }

        // Update metadata
        {
            uint32_t max_recv = meta.next_recv;
            uint32_t max_change = meta.next_change;
            for (const auto& u : utxos) {
                auto it = pkh2ci.find(miq::to_hex(u.pkh));
                if (it != pkh2ci.end()) {
                    if (it->second.first == 0 && it->second.second + 1 > max_recv)
                        max_recv = it->second.second + 1;
                    if (it->second.first == 1 && it->second.second + 1 > max_change)
                        max_change = it->second.second + 1;
                }
            }
            if (max_recv != meta.next_recv || max_change != meta.next_change) {
                auto m = meta; m.next_recv = max_recv; m.next_change = max_change;
                std::string e;
                if(!miq::SaveHdWallet(wdir, seed, m, pass, e)){
                    ui::print_warning("Could not save wallet metadata: " + e);
                } else {
                    meta = m;
                }
            }
        }

        // Display balance
        WalletBalance wb = compute_balance(utxos, pending);

        std::cout << "\n";
        ui::print_header("WALLET BALANCE", 50);
        std::cout << "\n";

        std::cout << "  " << ui::dim() << "Connected to: " << ui::reset() << used_seed << "\n";
        std::cout << "  " << ui::dim() << "UTXOs found:  " << ui::reset() << utxos.size() << "\n\n";

        std::cout << "  " << ui::bold() << "Total:        " << ui::reset()
                  << ui::green() << fmt_amount(wb.total) << " MIQ" << ui::reset() << "\n";
        std::cout << "  " << ui::bold() << "Spendable:    " << ui::reset()
                  << ui::cyan() << fmt_amount(wb.spendable) << " MIQ" << ui::reset() << "\n";

        if(wb.immature > 0){
            std::cout << "  " << ui::dim() << "Immature:     " << ui::reset()
                      << ui::yellow() << fmt_amount(wb.immature) << " MIQ" << ui::reset()
                      << ui::dim() << " (mining rewards)" << ui::reset() << "\n";
        }
        if(wb.pending_hold > 0){
            std::cout << "  " << ui::dim() << "Pending:      " << ui::reset()
                      << ui::yellow() << fmt_amount(wb.pending_hold) << " MIQ" << ui::reset()
                      << ui::dim() << " (awaiting confirmation)" << ui::reset() << "\n";
        }

        std::cout << "\n";

        return utxos;
    };

    auto utxos = refresh_and_print();

    // Main menu loop
    for(;;){
        ui::print_separator(50);
        std::cout << "\n";
        std::cout << ui::bold() << "  WALLET MENU" << ui::reset() << "\n\n";
        std::cout << "  " << ui::cyan() << "1" << ui::reset() << "  View Receive Addresses\n";
        std::cout << "  " << ui::cyan() << "2" << ui::reset() << "  Send MIQ\n";
        std::cout << "  " << ui::cyan() << "3" << ui::reset() << "  Generate New Address\n";
        std::cout << "  " << ui::cyan() << "r" << ui::reset() << "  Refresh Balance\n";
        std::cout << "  " << ui::cyan() << "q" << ui::reset() << "  Back to Main Menu\n";
        std::cout << "\n";

        std::string c = ui::prompt("Select option: ");
        c = trim(c);

        // =================================================================
        // OPTION 1: List Receive Addresses
        // =================================================================
        if(c == "1"){
            std::cout << "\n";
            ui::print_header("RECEIVE ADDRESSES", 50);
            std::cout << "\n";

            int count = std::max(1, (int)meta.next_recv);
            int show = std::min(count, 10);

            for(int i = 0; i < show; i++){
                std::string addr;
                auto it = addr_cache.find((uint32_t)i);
                if(it != addr_cache.end()){
                    addr = it->second;
                } else {
                    miq::HdWallet tmp(seed, meta);
                    if(tmp.GetAddressAt((uint32_t)i, addr)){
                        addr_cache[(uint32_t)i] = addr;
                    }
                }

                if(!addr.empty()){
                    std::cout << "  " << ui::dim() << "[" << i << "]" << ui::reset()
                              << " " << ui::cyan() << addr << ui::reset() << "\n";
                }
            }

            if(count > show){
                std::cout << "\n  " << ui::dim() << "(" << (count - show)
                          << " more addresses)" << ui::reset() << "\n";
            }

            std::cout << "\n  " << ui::dim() << "Tip: Share these addresses to receive MIQ" << ui::reset() << "\n\n";
        }
        // =================================================================
        // OPTION 2: Send MIQ
        // =================================================================
        else if(c == "2"){
            std::cout << "\n";
            ui::print_header("SEND MIQ", 50);
            std::cout << "\n";

            // Get recipient address
            std::string to = ui::prompt("Recipient address: ");
            to = trim(to);

            if(to.empty()){
                ui::print_error("No address entered");
                continue;
            }

            // Validate address
            uint8_t ver = 0;
            std::vector<uint8_t> payload;
            if(!miq::base58check_decode(to, ver, payload) || ver != miq::VERSION_P2PKH || payload.size() != 20){
                ui::print_error("Invalid address format");
                std::cout << ui::dim() << "  Must be a valid MIQ address starting with the correct prefix" << ui::reset() << "\n\n";
                continue;
            }

            // Get amount
            std::string amt = ui::prompt("Amount (MIQ): ");
            amt = trim(amt);

            uint64_t amount = 0;
            try {
                amount = parse_amount_miqron(amt);
            } catch(const std::exception& e){
                ui::print_error("Invalid amount: " + std::string(e.what()));
                std::cout << ui::dim() << "  Enter amount like: 1.5 or 0.001" << ui::reset() << "\n\n";
                continue;
            }

            if(amount == 0){
                ui::print_error("Amount must be greater than zero");
                continue;
            }

            // Refresh balance
            utxos = refresh_and_print();

            uint64_t tip_h = 0;
            for(const auto& u: utxos) tip_h = std::max<uint64_t>(tip_h, u.height);

            // Get spendable UTXOs
            std::vector<miq::UtxoLite> spendables;
            for(const auto& u: utxos){
                bool immature = false;
                if(u.coinbase){
                    uint64_t mh = (uint64_t)u.height + (uint64_t)miq::COINBASE_MATURITY;
                    if(tip_h + 1 < mh) immature = true;
                }
                OutpointKey k{ miq::to_hex(u.txid), u.vout };
                if(!immature && pending.find(k) == pending.end())
                    spendables.push_back(u);
            }

            if(spendables.empty()){
                ui::print_error("No spendable funds available");
                std::cout << ui::dim() << "  All funds are either immature or pending confirmation" << ui::reset() << "\n\n";
                continue;
            }

            // Sort: oldest first, then by value
            std::stable_sort(spendables.begin(), spendables.end(),
                [](const miq::UtxoLite& a, const miq::UtxoLite& b){
                    if(a.height != b.height) return a.height < b.height;
                    return a.value > b.value;
                });

            // Select inputs
            miq::Transaction tx;
            uint64_t in_sum = 0;
            for(const auto& u : spendables){
                miq::TxIn in;
                in.prev.txid = u.txid;
                in.prev.vout = u.vout;
                tx.vin.push_back(in);
                in_sum += u.value;
                uint64_t fee_guess = fee_for(tx.vin.size(), 2, 1000);
                if(in_sum >= amount + fee_guess) break;
            }

            if(tx.vin.empty() || in_sum < amount){
                ui::print_error("Insufficient funds");
                std::cout << ui::dim() << "  Available: " << fmt_amount(in_sum) << " MIQ" << ui::reset() << "\n";
                std::cout << ui::dim() << "  Requested: " << fmt_amount(amount) << " MIQ" << ui::reset() << "\n\n";
                continue;
            }

            // Calculate fee and change
            uint64_t fee_final = 0, change = 0;
            {
                auto fee2 = fee_for(tx.vin.size(), 2, 1000);
                if(in_sum < amount + fee2){
                    auto fee1 = fee_for(tx.vin.size(), 1, 1000);
                    if(in_sum < amount + fee1){
                        ui::print_error("Insufficient funds for transaction fee");
                        continue;
                    }
                    fee_final = fee1;
                    change = 0;
                } else {
                    fee_final = fee2;
                    change = in_sum - amount - fee_final;
                    if(change < 1000){
                        change = 0;
                        fee_final = fee_for(tx.vin.size(), 1, 1000);
                    }
                }
            }

            // Create outputs
            miq::TxOut o;
            o.pkh = payload;
            o.value = amount;
            tx.vout.push_back(o);

            // Create change output if needed
            bool used_change = false;
            std::vector<uint8_t> cpub, cpriv, cpkh;
            std::string change_addr;

            if(change > 0){
                miq::HdWallet w2(seed, meta);
                if(!w2.DerivePrivPub(meta.account, 1, meta.next_change, cpriv, cpub)){
                    ui::print_error("Failed to derive change address");
                    continue;
                }
                cpkh = miq::hash160(cpub);
                miq::TxOut ch;
                ch.value = change;
                ch.pkh = cpkh;
                tx.vout.push_back(ch);
                used_change = true;

                // Get change address for display
                change_addr = miq::base58check_encode(miq::VERSION_P2PKH, cpkh);
            }

            // =============================================================
            // TRANSACTION PREVIEW
            // =============================================================
            std::cout << "\n";
            ui::print_header("TRANSACTION PREVIEW", 50);
            std::cout << "\n";

            std::cout << "  " << ui::dim() << "To:" << ui::reset() << "        " << to << "\n";
            std::cout << "  " << ui::dim() << "Amount:" << ui::reset() << "    "
                      << ui::green() << fmt_amount(amount) << " MIQ" << ui::reset() << "\n";
            std::cout << "  " << ui::dim() << "Fee:" << ui::reset() << "       "
                      << fmt_amount(fee_final) << " MIQ\n";

            if(change > 0){
                std::cout << "  " << ui::dim() << "Change:" << ui::reset() << "    "
                          << fmt_amount(change) << " MIQ\n";
                std::cout << "  " << ui::dim() << "Change to:" << ui::reset() << " "
                          << change_addr.substr(0, 16) << "...\n";
            }

            std::cout << "\n";
            ui::print_separator(50);
            std::cout << "  " << ui::bold() << "TOTAL:" << ui::reset() << "     "
                      << ui::cyan() << fmt_amount(amount + fee_final) << " MIQ" << ui::reset() << "\n";
            ui::print_separator(50);
            std::cout << "\n";

            // Confirm transaction
            if(!ui::confirm("Send this transaction?")){
                ui::print_info("Transaction cancelled");
                continue;
            }

            // Sign transaction
            ui::print_progress("Signing transaction...");

            auto sighash = [&](){
                miq::Transaction t = tx;
                for(auto& i: t.vin){
                    i.sig.clear();
                    i.pubkey.clear();
                }
                return miq::dsha256(miq::ser_tx(t));
            }();

            auto find_key_for_pkh = [&](const std::vector<uint8_t>& pkh)->const std::vector<uint8_t>*{
                for(const auto& k: keys) if(k.pkh == pkh) return &k.priv;
                return nullptr;
            };

            bool sign_failed = false;
            for(auto& in : tx.vin){
                const miq::UtxoLite* u = nullptr;
                for(const auto& x: utxos){
                    if(x.txid == in.prev.txid && x.vout == in.prev.vout){
                        u = &x;
                        break;
                    }
                }

                if(!u){
                    ui::clear_line();
                    ui::print_error("Internal error: UTXO lookup failed");
                    sign_failed = true;
                    break;
                }

                const std::vector<uint8_t>* priv = find_key_for_pkh(u->pkh);
                if(!priv){
                    ui::clear_line();
                    ui::print_error("Internal error: Key lookup failed");
                    sign_failed = true;
                    break;
                }

                std::vector<uint8_t> sig64;
                if(!miq::crypto::ECDSA::sign(*priv, sighash, sig64)){
                    ui::clear_line();
                    ui::print_error("Transaction signing failed");
                    sign_failed = true;
                    break;
                }

                std::vector<uint8_t> pubkey;
                for(const auto& k: keys){
                    if(k.pkh == u->pkh){
                        pubkey = k.pub;
                        break;
                    }
                }

                in.sig = sig64;
                in.pubkey = pubkey;
            }

            if(sign_failed){
                continue;
            }

            ui::clear_line();

            // Broadcast transaction
            auto raw = miq::ser_tx(tx);
            std::string txid_hex = miq::to_hex(tx.txid());
            std::string used_bcast_seed, berr;
            auto seeds_b = build_seed_candidates(cli_host, cli_port);

            if(!broadcast_any_seed(seeds_b, raw, used_bcast_seed, berr)){
                ui::print_error("Broadcast failed");
                std::cout << ui::dim() << berr << ui::reset() << "\n\n";
                continue;
            }

            // Update pending cache
            for(const auto& in : tx.vin){
                pending.insert(OutpointKey{ miq::to_hex(in.prev.txid), in.prev.vout });
            }
            save_pending(wdir, pending);

            // Update change index
            if(used_change){
                auto m = w.meta();
                m.next_change = meta.next_change + 1;
                std::string e;
                if(!miq::SaveHdWallet(wdir, seed, m, pass, e)){
                    ui::print_warning("Could not save wallet state: " + e);
                } else {
                    meta = m;
                }
            }

            // Success!
            std::cout << "\n";
            ui::print_success("Transaction broadcasted successfully!");
            std::cout << "\n";
            std::cout << "  " << ui::dim() << "TXID:" << ui::reset() << " " << ui::cyan() << txid_hex << ui::reset() << "\n";
            std::cout << "  " << ui::dim() << "Via:" << ui::reset() << "  " << used_bcast_seed << "\n";

            if(used_change){
                std::cout << "  " << ui::dim() << "Change returned to:" << ui::reset() << " " << change_addr << "\n";
            }

            std::cout << "\n  " << ui::dim() << "Transaction is now pending confirmation" << ui::reset() << "\n\n";

            // Refresh balance after send
            utxos = refresh_and_print();
        }
        // =================================================================
        // OPTION 3: Generate New Address
        // =================================================================
        else if(c == "3"){
            std::cout << "\n";

            // Generate new address
            std::string new_addr;
            miq::HdWallet w2(seed, meta);

            if(!w2.GetNewAddress(new_addr)){
                ui::print_error("Failed to generate new address");
                continue;
            }

            // Update metadata
            auto new_meta = w2.meta();
            std::string e;
            if(!miq::SaveHdWallet(wdir, seed, new_meta, pass, e)){
                ui::print_warning("Could not save wallet state: " + e);
            } else {
                meta = new_meta;
                addr_cache[meta.next_recv - 1] = new_addr;
            }

            ui::print_success("New address generated!");
            std::cout << "\n";
            std::cout << "  " << ui::dim() << "[" << (meta.next_recv - 1) << "]" << ui::reset()
                      << " " << ui::cyan() << ui::bold() << new_addr << ui::reset() << "\n";
            std::cout << "\n  " << ui::dim() << "Share this address to receive MIQ" << ui::reset() << "\n\n";
        }
        // =================================================================
        // OPTION r: Refresh Balance
        // =================================================================
        else if(c == "r" || c == "R"){
            utxos = refresh_and_print();
        }
        // =================================================================
        // OPTION q: Quit
        // =================================================================
        else if(c == "q" || c == "Q" || c == "exit"){
            break;
        }
        else if(!c.empty()){
            ui::print_error("Unknown option: " + c);
        }
    }

    return true;
}

// =============================================================================
// WALLET CREATION FLOWS
// =============================================================================
static bool flow_create_wallet(const std::string& cli_host, const std::string& cli_port){
    std::string wdir = default_wallet_dir();

    std::cout << "\n";
    ui::print_header("CREATE NEW WALLET", 50);
    std::cout << "\n";

    // Encryption passphrase
    std::string wpass = ui::secure_prompt("Encryption passphrase (ENTER for none): ");

    // Generate mnemonic
    std::string mnemonic;
    if(!miq::HdWallet::GenerateMnemonic(128, mnemonic)){
        ui::print_error("Mnemonic generation failed");
        return false;
    }

    // Display mnemonic with security warnings
    std::cout << "\n";
    ui::print_header("RECOVERY PHRASE", 50);
    std::cout << "\n";

    std::cout << ui::yellow() << ui::bold();
    std::cout << "  IMPORTANT: Write down these 12 words and store them safely!\n";
    std::cout << "  Anyone with these words can access your funds.\n";
    std::cout << "  Never share them with anyone.\n";
    std::cout << ui::reset() << "\n";

    // Split mnemonic into words for better display
    std::istringstream iss(mnemonic);
    std::vector<std::string> words;
    std::string word;
    while(iss >> word) words.push_back(word);

    std::cout << "  ";
    for(size_t i = 0; i < words.size(); i++){
        std::cout << ui::cyan() << std::setw(2) << (i+1) << ". " << ui::reset()
                  << ui::bold() << words[i] << ui::reset();
        if((i+1) % 3 == 0 && i+1 < words.size()){
            std::cout << "\n  ";
        } else if(i+1 < words.size()){
            std::cout << "  ";
        }
    }
    std::cout << "\n\n";

    if(!ui::confirm("I have written down my recovery phrase")){
        ui::print_warning("Wallet creation cancelled");
        return false;
    }

    // Convert mnemonic to seed
    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, "", seed)){
        ui::print_error("Mnemonic to seed conversion failed");
        return false;
    }

    // Save wallet
    miq::HdAccountMeta meta;
    meta.account = 0;
    meta.next_recv = 0;
    meta.next_change = 0;

    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)){
        ui::print_error("Failed to save wallet: " + e);
        return false;
    }

    // Generate first address
    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)){
        ui::print_error("Failed to derive first address");
        return false;
    }

    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)){
        ui::print_warning("Could not save updated metadata: " + e);
    }

    std::cout << "\n";
    ui::print_success("Wallet created successfully!");
    std::cout << "\n";
    std::cout << "  " << ui::dim() << "First address:" << ui::reset() << " "
              << ui::cyan() << addr << ui::reset() << "\n";
    std::cout << "  " << ui::dim() << "Wallet location:" << ui::reset() << " " << wdir << "\n\n";

    return wallet_session(cli_host, cli_port, seed, w.meta(), wpass);
}

static bool flow_load_from_seed(const std::string& cli_host, const std::string& cli_port){
    std::string wdir = default_wallet_dir();

    std::cout << "\n";
    ui::print_header("IMPORT WALLET FROM SEED", 50);
    std::cout << "\n";

    std::string mnemonic = ui::prompt("Enter 12/24 word recovery phrase:\n> ");
    mnemonic = trim(mnemonic);

    if(mnemonic.empty()){
        ui::print_error("No recovery phrase entered");
        return false;
    }

    std::string mpass = ui::secure_prompt("Mnemonic passphrase (ENTER for none): ");
    std::string wpass = ui::secure_prompt("Wallet encryption passphrase (ENTER for none): ");

    // Convert mnemonic to seed
    std::vector<uint8_t> seed;
    if(!miq::HdWallet::MnemonicToSeed(mnemonic, mpass, seed)){
        ui::print_error("Invalid recovery phrase");
        return false;
    }

    // Save wallet
    miq::HdAccountMeta meta;
    meta.account = 0;
    meta.next_recv = 0;
    meta.next_change = 0;

    std::string e;
    if(!miq::SaveHdWallet(wdir, seed, meta, wpass, e)){
        ui::print_error("Failed to save wallet: " + e);
        return false;
    }

    // Clear SPV cache for full rescan
    clear_spv_cache(wdir);

    // Generate first address
    miq::HdWallet w(seed, meta);
    std::string addr;
    if(!w.GetNewAddress(addr)){
        ui::print_error("Failed to derive address");
        return false;
    }

    if(!miq::SaveHdWallet(wdir, seed, w.meta(), wpass, e)){
        ui::print_warning("Could not save metadata: " + e);
    }

    std::cout << "\n";
    ui::print_success("Wallet imported successfully!");
    std::cout << "\n";
    std::cout << "  " << ui::dim() << "First address:" << ui::reset() << " "
              << ui::cyan() << addr << ui::reset() << "\n";
    std::cout << "  " << ui::dim() << "SPV cache cleared - will rescan from genesis" << ui::reset() << "\n\n";

    return wallet_session(cli_host, cli_port, seed, w.meta(), wpass);
}

static bool flow_load_existing_wallet(const std::string& cli_host, const std::string& cli_port){
    std::string wdir = default_wallet_dir();

    std::cout << "\n";
    ui::print_header("LOAD WALLET", 50);
    std::cout << "\n";

    std::string wpass = ui::secure_prompt("Wallet passphrase (ENTER for none): ");

    std::vector<uint8_t> seed;
    miq::HdAccountMeta meta;
    std::string e;

    if(!miq::LoadHdWallet(wdir, seed, meta, wpass, e)){
        ui::print_error("Failed to load wallet");
        std::cout << ui::dim() << "  " << e << ui::reset() << "\n";
        std::cout << ui::dim() << "  Location: " << wdir << ui::reset() << "\n\n";
        return false;
    }

    miq::HdWallet w(seed, meta);

    ui::print_success("Wallet loaded successfully!");
    std::cout << "\n";

    // Show addresses
    std::cout << "  " << ui::dim() << "Addresses:" << ui::reset() << "\n";
    for(uint32_t i = 0; i <= std::min(meta.next_recv, 3u); ++i){
        std::string addr;
        if(w.GetAddressAt(i, addr)){
            std::cout << "    " << ui::dim() << "[" << i << "]" << ui::reset()
                      << " " << ui::cyan() << addr << ui::reset() << "\n";
        }
    }

    if(meta.next_recv > 4){
        std::cout << "    " << ui::dim() << "(" << (meta.next_recv - 4) << " more)" << ui::reset() << "\n";
    }
    std::cout << "\n";

    return wallet_session(cli_host, cli_port, seed, meta, wpass);
}

// =============================================================================
// MAIN ENTRY POINT
// =============================================================================
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);
    winsock_ensure();

    std::string cli_host;
    std::string cli_port = std::to_string(miq::P2P_PORT);

    // Parse command line arguments
    for(int i = 1; i < argc; i++){
        std::string a = argv[i];

        auto eat_str = [&](const char* k, std::string& dst)->bool{
            size_t L = std::strlen(k);
            if(a.rfind(k, 0) == 0){
                if(a.size() > L && a[L] == '='){
                    dst = a.substr(L+1);
                    return true;
                }
                if(i+1 < argc){
                    dst = argv[++i];
                    return true;
                }
            }
            return false;
        };

        if(eat_str("--p2pseed", cli_host)){
            auto c = cli_host.find(':');
            if(c != std::string::npos){
                cli_port = cli_host.substr(c+1);
                cli_host = cli_host.substr(0, c);
            }
            continue;
        }
        if(eat_str("--p2pport", cli_port)) continue;
        if(a == "--no-color" || a == "--nocolor"){
            ui::g_use_colors = false;
            continue;
        }
        if(a == "--help" || a == "-h"){
            std::cout << "MIQ Wallet - Professional Cryptocurrency Wallet\n\n";
            std::cout << "Usage: miqwallet [options]\n\n";
            std::cout << "Options:\n";
            std::cout << "  --p2pseed=host:port   Connect to specific P2P node\n";
            std::cout << "  --p2pport=port        Set P2P port (default: " << miq::P2P_PORT << ")\n";
            std::cout << "  --no-color            Disable colored output\n";
            std::cout << "  --help, -h            Show this help\n\n";
            std::cout << "Environment variables:\n";
            std::cout << "  MIQ_P2P_SEED          Comma-separated list of seed nodes\n";
            std::cout << "  MIQ_GAP_LIMIT         Address lookahead limit (default: 1000)\n";
            return 0;
        }
    }

    // Display banner
    ui::print_banner();

    std::cout << ui::dim() << "  Chain: " << ui::reset() << CHAIN_NAME << "\n";

    // Show seed nodes
    auto seeds = build_seed_candidates(cli_host, cli_port);
    std::cout << ui::dim() << "  Seeds: " << ui::reset();
    for(size_t i = 0; i < std::min(seeds.size(), (size_t)3); ++i){
        if(i) std::cout << ", ";
        std::cout << seeds[i].first << ":" << seeds[i].second;
    }
    if(seeds.size() > 3) std::cout << " (+" << (seeds.size() - 3) << " more)";
    std::cout << "\n";

    // Main menu loop
    for(;;){
        std::cout << "\n";
        ui::print_separator(50);
        std::cout << "\n";
        std::cout << ui::bold() << "  MAIN MENU" << ui::reset() << "\n\n";
        std::cout << "  " << ui::cyan() << "1" << ui::reset() << "  Load Existing Wallet\n";
        std::cout << "  " << ui::cyan() << "2" << ui::reset() << "  Create New Wallet\n";
        std::cout << "  " << ui::cyan() << "3" << ui::reset() << "  Import from Recovery Phrase\n";
        std::cout << "  " << ui::cyan() << "4" << ui::reset() << "  Force Rescan from Genesis\n";
        std::cout << "  " << ui::cyan() << "q" << ui::reset() << "  Quit\n";
        std::cout << "\n";

        std::string c = ui::prompt("Select option: ");
        c = trim(c);

        if(c == "1"){
            (void)flow_load_existing_wallet(cli_host, cli_port);
        }
        else if(c == "2"){
            (void)flow_create_wallet(cli_host, cli_port);
        }
        else if(c == "3"){
            (void)flow_load_from_seed(cli_host, cli_port);
        }
        else if(c == "4"){
            std::string wdir = default_wallet_dir();
            clear_spv_cache(wdir);
            std::cout << "\n";
            ui::print_success("SPV cache cleared");
            std::cout << ui::dim() << "  Next balance check will rescan from genesis" << ui::reset() << "\n";
            std::cout << ui::dim() << "  Use option 1 to load wallet and start rescan" << ui::reset() << "\n\n";
        }
        else if(c == "q" || c == "Q" || c == "exit"){
            std::cout << "\n" << ui::dim() << "  Goodbye!" << ui::reset() << "\n\n";
            break;
        }
        else if(!c.empty()){
            ui::print_error("Unknown option: " + c);
        }
    }

    return 0;
}
