// src/miqwallet.cpp - Professional MIQ Wallet CLI v1.0 Stable
// Production-grade SPV wallet with enterprise reliability, offline transactions,
// persistent queue system, and professional PowerShell 5+ compatible UI
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

// Platform-specific includes for terminal detection
#ifdef _WIN32
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <windows.h>
  #include <io.h>
  #define isatty _isatty
  #define STDOUT_FILENO _fileno(stdout)
#else
  #include <unistd.h>
#endif

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

    // Transaction queue system
    static constexpr int MAX_QUEUE_SIZE = 1000;
    static constexpr int AUTO_BROADCAST_INTERVAL_MS = 30000;
    static constexpr int TX_EXPIRY_HOURS = 72;
    static constexpr int MAX_BROADCAST_ATTEMPTS = 10;

    // Animation timings (PowerShell 5+ compatible)
    static constexpr int ANIMATION_FRAME_MS = 100;
    static constexpr int SPINNER_FRAME_MS = 80;
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

    // Detect if terminal supports ANSI escape codes
    inline bool detect_terminal_colors() {
#if defined(_WIN32)
        // On Windows, try to enable VT processing
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return false;

        DWORD mode = 0;
        if (!GetConsoleMode(hOut, &mode)) return false;

        // Try to enable VT processing
        if (SetConsoleMode(hOut, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
            return true;
        }

        // Check for known ANSI-capable terminals
        const char* term = std::getenv("TERM");
        const char* wt = std::getenv("WT_SESSION");
        const char* conemu = std::getenv("ConEmuANSI");
        if (wt || (conemu && std::strcmp(conemu, "ON") == 0)) return true;
        if (term && (std::strstr(term, "xterm") || std::strstr(term, "color"))) return true;

        return false;
#else
        // On Unix/Linux, check if stdout is a TTY and TERM is set
        if (!isatty(STDOUT_FILENO)) return false;

        const char* term = std::getenv("TERM");
        if (!term || !*term) return false;

        // Check for dumb terminal
        if (std::strcmp(term, "dumb") == 0) return false;

        // Check NO_COLOR environment variable (https://no-color.org/)
        const char* no_color = std::getenv("NO_COLOR");
        if (no_color && *no_color) return false;

        // Most modern terminals support ANSI
        return true;
#endif
    }

    // Initialize colors based on terminal detection
    inline void init_colors() {
        g_use_colors = detect_terminal_colors();
    }

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

    // Box drawing characters (ASCII fallback - works everywhere)
    const char* const BOX_TL = "+";
    const char* const BOX_TR = "+";
    const char* const BOX_BL = "+";
    const char* const BOX_BR = "+";
    const char* const BOX_H  = "-";
    const char* const BOX_V  = "|";
    const char* const BOX_ML = "+";
    const char* const BOX_MR = "+";
    const char* const BOX_MC = "+";  // Middle cross

    // Enhanced UI components for professional display
    std::string progress_bar(double percent, int width = 30) {
        int filled = (int)(percent * width / 100.0);
        std::string bar = "[";
        for (int i = 0; i < width; i++) {
            if (i < filled) bar += "=";
            else if (i == filled) bar += ">";
            else bar += " ";
        }
        bar += "]";
        return bar;
    }

    std::string format_time(int64_t timestamp) {
        time_t t = (time_t)timestamp;
        struct tm* tm_info = localtime(&t);
        char buf[64];
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);
        return std::string(buf);
    }

    std::string format_time_short(int64_t timestamp) {
        time_t t = (time_t)timestamp;
        struct tm* tm_info = localtime(&t);
        char buf[32];
        strftime(buf, sizeof(buf), "%m/%d %H:%M", tm_info);
        return std::string(buf);
    }

    std::string format_time_ago(int64_t timestamp) {
        int64_t now = (int64_t)time(nullptr);
        int64_t diff = now - timestamp;
        if (diff < 60) return std::to_string(diff) + "s ago";
        if (diff < 3600) return std::to_string(diff / 60) + "m ago";
        if (diff < 86400) return std::to_string(diff / 3600) + "h ago";
        return std::to_string(diff / 86400) + "d ago";
    }

    void print_double_header(const std::string& title, int width = 60) {
        std::cout << cyan() << bold();
        std::cout << BOX_TL;
        for(int i = 0; i < width - 2; i++) std::cout << "=";
        std::cout << BOX_TR << "\n";

        int padding = (width - 2 - (int)title.size()) / 2;
        std::cout << BOX_V;
        for(int i = 0; i < padding; i++) std::cout << " ";
        std::cout << title;
        for(int i = 0; i < width - 2 - padding - (int)title.size(); i++) std::cout << " ";
        std::cout << BOX_V << "\n";

        std::cout << BOX_BL;
        for(int i = 0; i < width - 2; i++) std::cout << "=";
        std::cout << BOX_BR << reset() << "\n";
    }

    void print_table_row(const std::vector<std::pair<std::string, int>>& cols, int total_width = 60) {
        (void)total_width;  // Unused, kept for API consistency
        std::cout << BOX_V;
        for (const auto& col : cols) {
            std::string text = col.first;
            int width = col.second;
            if ((int)text.size() > width - 2) {
                text = text.substr(0, width - 5) + "...";
            }
            std::cout << " " << std::left << std::setw(width - 2) << text << " ";
        }
        std::cout << BOX_V << "\n";
    }

    void print_table_separator(const std::vector<int>& widths) {
        std::cout << BOX_ML;
        for (size_t i = 0; i < widths.size(); i++) {
            for (int j = 0; j < widths[i]; j++) std::cout << BOX_H;
            if (i < widths.size() - 1) std::cout << BOX_MC;
        }
        std::cout << BOX_MR << "\n";
    }

    void print_status_line(const std::string& left, const std::string& right, int width = 60) {
        int space = width - (int)left.size() - (int)right.size() - 4;
        std::cout << dim() << "[ " << reset() << left;
        for (int i = 0; i < space; i++) std::cout << " ";
        std::cout << right << dim() << " ]" << reset() << "\n";
    }

    // ASCII QR-like code for addresses (simple checkered pattern with address embedded)
    void print_address_display(const std::string& address, int width = 50) {
        std::cout << cyan() << bold();
        std::cout << BOX_TL;
        for(int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_TR << "\n";

        // Address label
        std::cout << BOX_V << "  " << dim() << "Receive Address:" << reset() << cyan() << bold();
        for(int i = 0; i < width - 20; i++) std::cout << " ";
        std::cout << BOX_V << "\n";

        // Address value (centered)
        int addr_pad = (width - 2 - (int)address.size()) / 2;
        std::cout << BOX_V;
        for(int i = 0; i < addr_pad; i++) std::cout << " ";
        std::cout << green() << bold() << address << reset() << cyan() << bold();
        for(int i = 0; i < width - 2 - addr_pad - (int)address.size(); i++) std::cout << " ";
        std::cout << BOX_V << "\n";

        // Simple visual pattern for easy recognition
        std::cout << BOX_V << "  ";
        for(int i = 0; i < width - 6; i++) {
            unsigned char c = (i < (int)address.size()) ? (unsigned char)address[i] : (unsigned char)i;
            std::cout << ((c % 2) ? "#" : " ");
        }
        std::cout << "  " << BOX_V << "\n";

        std::cout << BOX_BL;
        for(int i = 0; i < width - 2; i++) std::cout << BOX_H;
        std::cout << BOX_BR << reset() << "\n";
    }

    void print_amount_highlight(const std::string& label, const std::string& amount, const std::string& color_fn) {
        std::cout << "  " << bold() << std::setw(14) << std::left << label << reset();
        if (color_fn == "green") std::cout << green();
        else if (color_fn == "cyan") std::cout << cyan();
        else if (color_fn == "yellow") std::cout << yellow();
        else if (color_fn == "red") std::cout << red();
        std::cout << amount << reset() << "\n";
    }

    void print_menu_item(const std::string& key, const std::string& desc, bool highlight = false) {
        std::cout << "  ";
        if (highlight) std::cout << green() << bold();
        else std::cout << cyan();
        std::cout << std::setw(3) << key << reset() << "  " << desc << "\n";
    }

    void clear_screen() {
        std::cout << "\033[2J\033[H";
    }

    void print_loading_animation(const std::string& msg, int frame) {
        const char* spinner[] = {"|", "/", "-", "\\"};
        std::cout << "\r" << cyan() << "[" << spinner[frame % 4] << "] " << reset() << msg << std::flush;
    }

    // Enhanced spinner for PowerShell 5+ (Braille pattern animation)
    void print_spinner(const std::string& msg, int frame) {
        // Works well in PowerShell 5+ and modern terminals
        const char* frames[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        const char* fallback[] = {"[*   ]", "[ *  ]", "[  * ]", "[   *]", "[  * ]", "[ *  ]"};

        // Use ASCII fallback for better compatibility
        std::cout << "\r" << cyan() << fallback[frame % 6] << " " << reset() << msg
                  << std::string(20, ' ') << std::flush;
    }

    // Animated progress bar
    void print_animated_progress(const std::string& msg, double percent, int frame) {
        int width = 25;
        int filled = (int)(percent * width / 100.0);

        std::cout << "\r  " << msg << " ";
        std::cout << cyan() << "[";

        for (int i = 0; i < width; i++) {
            if (i < filled) {
                std::cout << green() << "=" << reset() << cyan();
            } else if (i == filled) {
                // Animated cursor
                const char* cursors[] = {">", "*", "+", "*"};
                std::cout << yellow() << cursors[frame % 4] << reset() << cyan();
            } else {
                std::cout << dim() << "-" << reset() << cyan();
            }
        }

        std::cout << "]" << reset() << " " << std::fixed << std::setprecision(1) << percent << "%"
                  << std::string(10, ' ') << std::flush;
    }

    // Network status indicator
    void print_network_status(bool connected, const std::string& node = "") {
        if (connected) {
            std::cout << green() << "[ONLINE]" << reset();
            if (!node.empty()) {
                std::cout << dim() << " " << node << reset();
            }
        } else {
            std::cout << red() << "[OFFLINE]" << reset();
        }
        std::cout << "\n";
    }

    // Transaction status badge
    std::string tx_status_badge(const std::string& status) {
        if (status == "confirmed") return green() + "[CONFIRMED]" + reset();
        if (status == "pending") return yellow() + "[PENDING]" + reset();
        if (status == "queued") return cyan() + "[QUEUED]" + reset();
        if (status == "failed") return red() + "[FAILED]" + reset();
        if (status == "expired") return dim() + "[EXPIRED]" + reset();
        return dim() + "[" + status + "]" + reset();
    }

    // Pulsing text effect for important messages
    void print_pulse(const std::string& msg, int frame) {
        if ((frame / 5) % 2 == 0) {
            std::cout << bold() << msg << reset();
        } else {
            std::cout << msg;
        }
    }

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
        std::cout << dim() << "        Professional Cryptocurrency Wallet v1.0 Stable" << reset() << "\n";
        std::cout << dim() << "           Offline Transactions | Persistent Queue" << reset() << "\n\n";
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
// TRANSACTION HISTORY - Professional tracking
// =============================================================================
struct TxHistoryEntry {
    std::string txid_hex;
    int64_t timestamp{0};
    int64_t amount{0};       // positive = received, negative = sent
    uint64_t fee{0};
    uint32_t confirmations{0};
    std::string direction;   // "sent", "received", "self"
    std::string to_address;
    std::string from_address;
    std::string memo;
};

static std::string tx_history_path(const std::string& wdir){
    return join_path(wdir, "tx_history.dat");
}

static void load_tx_history(const std::string& wdir, std::vector<TxHistoryEntry>& out){
    out.clear();
    std::ifstream f(tx_history_path(wdir));
    if(!f.good()) return;
    std::string line;
    while(std::getline(f, line)){
        if(line.empty() || line[0] == '#') continue;
        // Format: txid|timestamp|amount|fee|confirmations|direction|to|from|memo
        std::vector<std::string> parts;
        size_t start = 0, end = 0;
        while((end = line.find('|', start)) != std::string::npos){
            parts.push_back(line.substr(start, end - start));
            start = end + 1;
        }
        parts.push_back(line.substr(start));

        if(parts.size() >= 6){
            TxHistoryEntry e;
            e.txid_hex = parts[0];
            e.timestamp = std::strtoll(parts[1].c_str(), nullptr, 10);
            e.amount = std::strtoll(parts[2].c_str(), nullptr, 10);
            e.fee = std::strtoull(parts[3].c_str(), nullptr, 10);
            e.confirmations = (uint32_t)std::strtoul(parts[4].c_str(), nullptr, 10);
            e.direction = parts[5];
            if(parts.size() > 6) e.to_address = parts[6];
            if(parts.size() > 7) e.from_address = parts[7];
            if(parts.size() > 8) e.memo = parts[8];
            out.push_back(e);
        }
    }
    // Sort by timestamp descending (newest first)
    std::sort(out.begin(), out.end(), [](const TxHistoryEntry& a, const TxHistoryEntry& b){
        return a.timestamp > b.timestamp;
    });
}

static void save_tx_history(const std::string& wdir, const std::vector<TxHistoryEntry>& hist){
    std::ofstream f(tx_history_path(wdir), std::ios::out | std::ios::trunc);
    if(!f.good()) return;
    f << "# MIQ Wallet Transaction History\n";
    for(const auto& e : hist){
        f << e.txid_hex << "|" << e.timestamp << "|" << e.amount << "|"
          << e.fee << "|" << e.confirmations << "|" << e.direction << "|"
          << e.to_address << "|" << e.from_address << "|" << e.memo << "\n";
    }
}

static void add_tx_history(const std::string& wdir, const TxHistoryEntry& entry){
    std::vector<TxHistoryEntry> hist;
    load_tx_history(wdir, hist);

    // Check for duplicate
    for(const auto& e : hist){
        if(e.txid_hex == entry.txid_hex) return; // Already exists
    }

    hist.push_back(entry);

    // Keep only last 1000 transactions
    if(hist.size() > 1000){
        hist.erase(hist.begin(), hist.begin() + (hist.size() - 1000));
    }

    save_tx_history(wdir, hist);
}

// =============================================================================
// QUEUED TRANSACTION - Offline transaction support with persistence
// =============================================================================
struct QueuedTransaction {
    std::string txid_hex;
    std::vector<uint8_t> raw_tx;
    int64_t created_at{0};
    int64_t last_attempt{0};
    int broadcast_attempts{0};
    std::string status;  // "queued", "broadcasting", "confirmed", "failed", "expired"
    std::string to_address;
    uint64_t amount{0};
    uint64_t fee{0};
    std::string memo;
    std::string error_msg;
};

static std::string tx_queue_path(const std::string& wdir){
    return join_path(wdir, "tx_queue.dat");
}

static void load_tx_queue(const std::string& wdir, std::vector<QueuedTransaction>& out){
    out.clear();
    std::ifstream f(tx_queue_path(wdir), std::ios::binary);
    if(!f.good()) return;

    // Read number of transactions
    uint32_t count = 0;
    f.read(reinterpret_cast<char*>(&count), sizeof(count));
    if(count > wallet_config::MAX_QUEUE_SIZE) count = wallet_config::MAX_QUEUE_SIZE;

    for(uint32_t i = 0; i < count && f.good(); i++){
        QueuedTransaction tx;

        // Read txid
        uint32_t txid_len = 0;
        f.read(reinterpret_cast<char*>(&txid_len), sizeof(txid_len));
        if(txid_len > 0 && txid_len < 1000){
            tx.txid_hex.resize(txid_len);
            f.read(&tx.txid_hex[0], txid_len);
        }

        // Read raw tx
        uint32_t raw_len = 0;
        f.read(reinterpret_cast<char*>(&raw_len), sizeof(raw_len));
        if(raw_len > 0 && raw_len < 1000000){
            tx.raw_tx.resize(raw_len);
            f.read(reinterpret_cast<char*>(tx.raw_tx.data()), raw_len);
        }

        // Read metadata
        f.read(reinterpret_cast<char*>(&tx.created_at), sizeof(tx.created_at));
        f.read(reinterpret_cast<char*>(&tx.last_attempt), sizeof(tx.last_attempt));
        f.read(reinterpret_cast<char*>(&tx.broadcast_attempts), sizeof(tx.broadcast_attempts));

        // Read status
        uint32_t status_len = 0;
        f.read(reinterpret_cast<char*>(&status_len), sizeof(status_len));
        if(status_len > 0 && status_len < 100){
            tx.status.resize(status_len);
            f.read(&tx.status[0], status_len);
        }

        // Read to_address
        uint32_t addr_len = 0;
        f.read(reinterpret_cast<char*>(&addr_len), sizeof(addr_len));
        if(addr_len > 0 && addr_len < 200){
            tx.to_address.resize(addr_len);
            f.read(&tx.to_address[0], addr_len);
        }

        // Read amount and fee
        f.read(reinterpret_cast<char*>(&tx.amount), sizeof(tx.amount));
        f.read(reinterpret_cast<char*>(&tx.fee), sizeof(tx.fee));

        // Read memo
        uint32_t memo_len = 0;
        f.read(reinterpret_cast<char*>(&memo_len), sizeof(memo_len));
        if(memo_len > 0 && memo_len < 1000){
            tx.memo.resize(memo_len);
            f.read(&tx.memo[0], memo_len);
        }

        // Read error message
        uint32_t err_len = 0;
        f.read(reinterpret_cast<char*>(&err_len), sizeof(err_len));
        if(err_len > 0 && err_len < 1000){
            tx.error_msg.resize(err_len);
            f.read(&tx.error_msg[0], err_len);
        }

        if(f.good()){
            out.push_back(std::move(tx));
        }
    }
}

static void save_tx_queue(const std::string& wdir, const std::vector<QueuedTransaction>& queue){
    std::ofstream f(tx_queue_path(wdir), std::ios::binary | std::ios::trunc);
    if(!f.good()) return;

    uint32_t count = (uint32_t)queue.size();
    f.write(reinterpret_cast<const char*>(&count), sizeof(count));

    for(const auto& tx : queue){
        // Write txid
        uint32_t txid_len = (uint32_t)tx.txid_hex.size();
        f.write(reinterpret_cast<const char*>(&txid_len), sizeof(txid_len));
        f.write(tx.txid_hex.data(), txid_len);

        // Write raw tx
        uint32_t raw_len = (uint32_t)tx.raw_tx.size();
        f.write(reinterpret_cast<const char*>(&raw_len), sizeof(raw_len));
        f.write(reinterpret_cast<const char*>(tx.raw_tx.data()), raw_len);

        // Write metadata
        f.write(reinterpret_cast<const char*>(&tx.created_at), sizeof(tx.created_at));
        f.write(reinterpret_cast<const char*>(&tx.last_attempt), sizeof(tx.last_attempt));
        f.write(reinterpret_cast<const char*>(&tx.broadcast_attempts), sizeof(tx.broadcast_attempts));

        // Write status
        uint32_t status_len = (uint32_t)tx.status.size();
        f.write(reinterpret_cast<const char*>(&status_len), sizeof(status_len));
        f.write(tx.status.data(), status_len);

        // Write to_address
        uint32_t addr_len = (uint32_t)tx.to_address.size();
        f.write(reinterpret_cast<const char*>(&addr_len), sizeof(addr_len));
        f.write(tx.to_address.data(), addr_len);

        // Write amount and fee
        f.write(reinterpret_cast<const char*>(&tx.amount), sizeof(tx.amount));
        f.write(reinterpret_cast<const char*>(&tx.fee), sizeof(tx.fee));

        // Write memo
        uint32_t memo_len = (uint32_t)tx.memo.size();
        f.write(reinterpret_cast<const char*>(&memo_len), sizeof(memo_len));
        f.write(tx.memo.data(), memo_len);

        // Write error message
        uint32_t err_len = (uint32_t)tx.error_msg.size();
        f.write(reinterpret_cast<const char*>(&err_len), sizeof(err_len));
        f.write(tx.error_msg.data(), err_len);
    }
}

static void add_to_tx_queue(const std::string& wdir, const QueuedTransaction& tx){
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    // Check for duplicate
    for(const auto& q : queue){
        if(q.txid_hex == tx.txid_hex) return;
    }

    queue.push_back(tx);

    // Keep only recent transactions (remove expired)
    int64_t now = (int64_t)time(nullptr);
    int64_t expiry_seconds = wallet_config::TX_EXPIRY_HOURS * 3600;

    std::vector<QueuedTransaction> filtered;
    for(const auto& q : queue){
        if(now - q.created_at < expiry_seconds || q.status == "confirmed"){
            filtered.push_back(q);
        }
    }

    // Limit queue size
    if(filtered.size() > wallet_config::MAX_QUEUE_SIZE){
        filtered.erase(filtered.begin(), filtered.begin() + (filtered.size() - wallet_config::MAX_QUEUE_SIZE));
    }

    save_tx_queue(wdir, filtered);
}

static void update_tx_queue_status(const std::string& wdir, const std::string& txid_hex,
                                    const std::string& status, const std::string& error = ""){
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    for(auto& tx : queue){
        if(tx.txid_hex == txid_hex){
            tx.status = status;
            tx.last_attempt = (int64_t)time(nullptr);
            if(!error.empty()) tx.error_msg = error;
            if(status == "broadcasting" || status == "failed"){
                tx.broadcast_attempts++;
            }
            break;
        }
    }

    save_tx_queue(wdir, queue);
}

static int count_pending_in_queue(const std::string& wdir){
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    int count = 0;
    for(const auto& tx : queue){
        if(tx.status == "queued" || tx.status == "broadcasting"){
            count++;
        }
    }
    return count;
}

// =============================================================================
// ADDRESS BOOK - Professional contacts management
// =============================================================================
struct AddressBookEntry {
    std::string address;
    std::string label;
    std::string notes;
    int64_t created_at{0};
    int64_t last_used{0};
};

static std::string address_book_path(const std::string& wdir){
    return join_path(wdir, "address_book.dat");
}

static void load_address_book(const std::string& wdir, std::vector<AddressBookEntry>& out){
    out.clear();
    std::ifstream f(address_book_path(wdir));
    if(!f.good()) return;
    std::string line;
    while(std::getline(f, line)){
        if(line.empty() || line[0] == '#') continue;
        // Format: address|label|notes|created|last_used
        std::vector<std::string> parts;
        size_t start = 0, end = 0;
        while((end = line.find('|', start)) != std::string::npos){
            parts.push_back(line.substr(start, end - start));
            start = end + 1;
        }
        parts.push_back(line.substr(start));

        if(parts.size() >= 2){
            AddressBookEntry e;
            e.address = parts[0];
            e.label = parts[1];
            if(parts.size() > 2) e.notes = parts[2];
            if(parts.size() > 3) e.created_at = std::strtoll(parts[3].c_str(), nullptr, 10);
            if(parts.size() > 4) e.last_used = std::strtoll(parts[4].c_str(), nullptr, 10);
            out.push_back(e);
        }
    }
    // Sort by label
    std::sort(out.begin(), out.end(), [](const AddressBookEntry& a, const AddressBookEntry& b){
        return a.label < b.label;
    });
}

static void save_address_book(const std::string& wdir, const std::vector<AddressBookEntry>& book){
    std::ofstream f(address_book_path(wdir), std::ios::out | std::ios::trunc);
    if(!f.good()) return;
    f << "# MIQ Wallet Address Book\n";
    for(const auto& e : book){
        f << e.address << "|" << e.label << "|" << e.notes << "|"
          << e.created_at << "|" << e.last_used << "\n";
    }
}

static void add_to_address_book(const std::string& wdir, const std::string& address,
                                const std::string& label, const std::string& notes = ""){
    std::vector<AddressBookEntry> book;
    load_address_book(wdir, book);

    // Check for duplicate address
    for(auto& e : book){
        if(e.address == address){
            e.label = label;
            if(!notes.empty()) e.notes = notes;
            e.last_used = (int64_t)time(nullptr);
            save_address_book(wdir, book);
            return;
        }
    }

    AddressBookEntry e;
    e.address = address;
    e.label = label;
    e.notes = notes;
    e.created_at = (int64_t)time(nullptr);
    e.last_used = e.created_at;
    book.push_back(e);

    save_address_book(wdir, book);
}

// =============================================================================
// FEE ESTIMATION - Professional fee calculation
// =============================================================================
static uint64_t estimate_tx_fee(size_t num_inputs, size_t num_outputs, uint64_t fee_per_byte = 1){
    // Estimate transaction size:
    // Base: ~10 bytes (version, locktime, etc.)
    // Per input: ~148 bytes (outpoint + scriptSig + sequence)
    // Per output: ~34 bytes (value + scriptPubKey)
    size_t estimated_size = 10 + (num_inputs * 148) + (num_outputs * 34);
    return estimated_size * fee_per_byte;
}

static std::string fee_priority_label(int priority){
    switch(priority){
        case 0: return "Economy (1 sat/byte)";
        case 1: return "Normal (2 sat/byte)";
        case 2: return "Priority (5 sat/byte)";
        case 3: return "Urgent (10 sat/byte)";
        default: return "Custom";
    }
}

static uint64_t fee_priority_rate(int priority){
    switch(priority){
        case 0: return 1;
        case 1: return 2;
        case 2: return 5;
        case 3: return 10;
        default: return 1;
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
// TRANSACTION QUEUE PROCESSING - Auto-broadcast pending transactions
// =============================================================================
static int process_tx_queue(
    const std::string& wdir,
    const std::vector<std::pair<std::string,std::string>>& seeds,
    bool verbose = true)
{
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    if(queue.empty()) return 0;

    int broadcasted = 0;
    int64_t now = (int64_t)time(nullptr);

    for(auto& tx : queue){
        // Skip if not queued or already too many attempts
        if(tx.status != "queued" && tx.status != "broadcasting") continue;
        if(tx.broadcast_attempts >= wallet_config::MAX_BROADCAST_ATTEMPTS){
            tx.status = "failed";
            tx.error_msg = "Max broadcast attempts exceeded";
            continue;
        }

        // Check expiry
        int64_t age_hours = (now - tx.created_at) / 3600;
        if(age_hours >= wallet_config::TX_EXPIRY_HOURS){
            tx.status = "expired";
            tx.error_msg = "Transaction expired after " + std::to_string(wallet_config::TX_EXPIRY_HOURS) + " hours";
            continue;
        }

        if(verbose){
            ui::print_spinner("Broadcasting " + tx.txid_hex.substr(0, 8) + "...", tx.broadcast_attempts);
        }

        tx.status = "broadcasting";
        tx.last_attempt = now;
        tx.broadcast_attempts++;

        std::string used_seed, err;
        if(broadcast_any_seed(seeds, tx.raw_tx, used_seed, err)){
            tx.status = "confirmed";
            tx.error_msg = "";
            broadcasted++;

            if(verbose){
                ui::clear_line();
                ui::print_success("Broadcasted: " + tx.txid_hex.substr(0, 16) + "...");
            }

            // Add to transaction history
            TxHistoryEntry hist;
            hist.txid_hex = tx.txid_hex;
            hist.timestamp = tx.created_at;
            hist.amount = -(int64_t)tx.amount;
            hist.fee = tx.fee;
            hist.confirmations = 0;
            hist.direction = "sent";
            hist.to_address = tx.to_address;
            hist.memo = tx.memo;
            add_tx_history(wdir, hist);
        } else {
            tx.error_msg = err;
            if(verbose){
                ui::clear_line();
                ui::print_warning("Failed: " + tx.txid_hex.substr(0, 16) + "... - " + err);
            }
        }
    }

    save_tx_queue(wdir, queue);
    return broadcasted;
}

// Check network connectivity by attempting to connect to any seed
static bool check_network_status(
    const std::vector<std::pair<std::string,std::string>>& seeds,
    std::string& connected_node)
{
    for(const auto& [host, port] : seeds){
        miq::P2PLight p2p;
        miq::P2POpts opts;
        opts.host = host;
        opts.port = port;
        opts.user_agent = "/miqwallet:1.0/";
        opts.io_timeout_ms = 5000;  // Quick check

        std::string err;
        if(p2p.connect_and_handshake(opts, err)){
            p2p.close();
            connected_node = host + ":" + port;
            return true;
        }
    }
    connected_node = "";
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

    // Track last connected node for display
    std::string last_connected_node = "<not connected>";

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

        // Update shared variable for other UI sections
        last_connected_node = used_seed;

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

    // Process any pending transactions on startup
    {
        int pending_count = count_pending_in_queue(wdir);
        if(pending_count > 0){
            std::cout << "\n";
            ui::print_info("Found " + std::to_string(pending_count) + " pending transaction(s) in queue");
            std::cout << "  " << ui::dim() << "Attempting to broadcast..." << ui::reset() << "\n";

            int broadcasted = process_tx_queue(wdir, seeds, true);
            if(broadcasted > 0){
                std::cout << "\n";
                ui::print_success("Successfully broadcasted " + std::to_string(broadcasted) + " transaction(s)");
            }
            std::cout << "\n";
        }
    }

    // Track network status
    bool is_online = (last_connected_node != "<offline>" && last_connected_node != "<not connected>");

    // Main menu loop
    for(;;){
        ui::print_separator(50);
        std::cout << "\n";

        // Network status indicator
        std::cout << "  " << ui::bold() << "Status: " << ui::reset();
        if(is_online){
            std::cout << ui::green() << "[ONLINE]" << ui::reset();
            std::cout << ui::dim() << " " << last_connected_node << ui::reset();
        } else {
            std::cout << ui::red() << "[OFFLINE]" << ui::reset();
        }

        // Show pending queue count
        int queue_count = count_pending_in_queue(wdir);
        if(queue_count > 0){
            std::cout << "  " << ui::yellow() << "[" << queue_count << " queued]" << ui::reset();
        }
        std::cout << "\n\n";

        std::cout << ui::bold() << "  WALLET MENU" << ui::reset() << "\n\n";

        // Primary actions
        std::cout << ui::dim() << "  Actions:" << ui::reset() << "\n";
        ui::print_menu_item("1", "View Receive Addresses");
        ui::print_menu_item("2", "Send MIQ");
        ui::print_menu_item("3", "Generate New Address");

        // Information
        std::cout << "\n" << ui::dim() << "  Information:" << ui::reset() << "\n";
        ui::print_menu_item("4", "Transaction History");
        ui::print_menu_item("5", "Address Book");
        ui::print_menu_item("6", "Wallet Info");
        ui::print_menu_item("7", "Transaction Queue");

        // System
        std::cout << "\n" << ui::dim() << "  System:" << ui::reset() << "\n";
        ui::print_menu_item("r", "Refresh Balance");
        ui::print_menu_item("b", "Broadcast Queue");
        ui::print_menu_item("h", "Help");
        ui::print_menu_item("q", "Back to Main Menu");
        std::cout << "\n";

        std::string c = ui::prompt("Select option: ");
        c = trim(c);

        // =================================================================
        // OPTION 4: Transaction History
        // =================================================================
        if(c == "4"){
            std::cout << "\n";
            ui::print_double_header("TRANSACTION HISTORY", 60);
            std::cout << "\n";

            std::vector<TxHistoryEntry> history;
            load_tx_history(wdir, history);

            if(history.empty()){
                std::cout << "  " << ui::dim() << "No transactions yet." << ui::reset() << "\n";
                std::cout << "  " << ui::dim() << "Send or receive MIQ to see transaction history." << ui::reset() << "\n\n";
            } else {
                // Show last 20 transactions
                int show_count = std::min((int)history.size(), 20);

                std::cout << ui::dim() << "  Recent transactions (showing " << show_count << " of "
                          << history.size() << "):" << ui::reset() << "\n\n";

                for(int i = 0; i < show_count; i++){
                    const auto& tx = history[i];

                    // Direction indicator
                    std::string dir_symbol, dir_color;
                    if(tx.direction == "sent"){
                        dir_symbol = "[-]";
                        dir_color = "red";
                    } else if(tx.direction == "received"){
                        dir_symbol = "[+]";
                        dir_color = "green";
                    } else {
                        dir_symbol = "[=]";
                        dir_color = "yellow";
                    }

                    // Format amount
                    std::string amt_str;
                    if(tx.amount >= 0){
                        amt_str = "+" + fmt_amount_short((uint64_t)tx.amount) + " MIQ";
                    } else {
                        amt_str = fmt_amount_short((uint64_t)(-tx.amount)) + " MIQ";
                    }

                    // Print transaction
                    std::cout << "  ";
                    if(dir_color == "red") std::cout << ui::red();
                    else if(dir_color == "green") std::cout << ui::green();
                    else std::cout << ui::yellow();
                    std::cout << dir_symbol << ui::reset();

                    std::cout << " " << ui::dim() << ui::format_time_short(tx.timestamp) << ui::reset();
                    std::cout << "  " << std::setw(18) << std::right << amt_str;

                    if(tx.confirmations == 0){
                        std::cout << "  " << ui::yellow() << "(unconfirmed)" << ui::reset();
                    } else if(tx.confirmations < 6){
                        std::cout << "  " << ui::dim() << "(" << tx.confirmations << " conf)" << ui::reset();
                    }

                    std::cout << "\n";

                    // Show address on second line
                    if(!tx.to_address.empty() && tx.direction == "sent"){
                        std::cout << "      " << ui::dim() << "To: " << tx.to_address.substr(0, 30)
                                  << (tx.to_address.size() > 30 ? "..." : "") << ui::reset() << "\n";
                    }
                }

                std::cout << "\n  " << ui::dim() << "Press ENTER to return..." << ui::reset();
                std::string dummy;
                std::getline(std::cin, dummy);
            }
            continue;
        }

        // =================================================================
        // OPTION 5: Address Book
        // =================================================================
        if(c == "5"){
            std::cout << "\n";
            ui::print_double_header("ADDRESS BOOK", 60);
            std::cout << "\n";

            std::vector<AddressBookEntry> book;
            load_address_book(wdir, book);

            if(book.empty()){
                std::cout << "  " << ui::dim() << "Address book is empty." << ui::reset() << "\n\n";
            } else {
                for(size_t i = 0; i < book.size(); i++){
                    const auto& entry = book[i];
                    std::cout << "  " << ui::cyan() << "[" << (i+1) << "]" << ui::reset()
                              << " " << ui::bold() << entry.label << ui::reset() << "\n";
                    std::cout << "      " << ui::dim() << entry.address << ui::reset() << "\n";
                    if(!entry.notes.empty()){
                        std::cout << "      " << ui::dim() << "Note: " << entry.notes << ui::reset() << "\n";
                    }
                }
                std::cout << "\n";
            }

            // Address book submenu
            std::cout << "  " << ui::cyan() << "a" << ui::reset() << "  Add new contact\n";
            std::cout << "  " << ui::cyan() << "d" << ui::reset() << "  Delete contact\n";
            std::cout << "  " << ui::cyan() << "q" << ui::reset() << "  Back\n\n";

            std::string ab_cmd = ui::prompt("Address book action: ");
            ab_cmd = trim(ab_cmd);

            if(ab_cmd == "a"){
                std::cout << "\n";
                std::string new_label = ui::prompt("Contact name: ");
                new_label = trim(new_label);
                if(new_label.empty()){
                    ui::print_error("Name cannot be empty");
                    continue;
                }

                std::string new_addr = ui::prompt("Address: ");
                new_addr = trim(new_addr);

                // Validate address
                uint8_t ver = 0;
                std::vector<uint8_t> payload;
                if(!miq::base58check_decode(new_addr, ver, payload) || ver != miq::VERSION_P2PKH || payload.size() != 20){
                    ui::print_error("Invalid address format");
                    continue;
                }

                std::string notes = ui::prompt("Notes (optional): ");
                notes = trim(notes);

                add_to_address_book(wdir, new_addr, new_label, notes);
                ui::print_success("Contact added successfully!");
            }
            else if(ab_cmd == "d" && !book.empty()){
                std::string idx_str = ui::prompt("Contact number to delete: ");
                int idx = std::atoi(trim(idx_str).c_str()) - 1;
                if(idx >= 0 && idx < (int)book.size()){
                    if(ui::confirm("Delete '" + book[idx].label + "'?")){
                        book.erase(book.begin() + idx);
                        save_address_book(wdir, book);
                        ui::print_success("Contact deleted");
                    }
                } else {
                    ui::print_error("Invalid contact number");
                }
            }
            continue;
        }

        // =================================================================
        // OPTION 6: Wallet Info
        // =================================================================
        if(c == "6"){
            std::cout << "\n";
            ui::print_double_header("WALLET INFORMATION", 60);
            std::cout << "\n";

            std::cout << "  " << ui::bold() << "Wallet Directory:" << ui::reset() << "\n";
            std::cout << "    " << ui::cyan() << wdir << ui::reset() << "\n\n";

            std::cout << "  " << ui::bold() << "Address Statistics:" << ui::reset() << "\n";
            std::cout << "    Receive addresses used: " << meta.next_recv << "\n";
            std::cout << "    Change addresses used:  " << meta.next_change << "\n\n";

            std::cout << "  " << ui::bold() << "UTXO Statistics:" << ui::reset() << "\n";
            std::cout << "    Total UTXOs: " << utxos.size() << "\n";

            uint64_t min_utxo = UINT64_MAX, max_utxo = 0;
            for(const auto& u : utxos){
                min_utxo = std::min(min_utxo, u.value);
                max_utxo = std::max(max_utxo, u.value);
            }
            if(!utxos.empty()){
                std::cout << "    Smallest UTXO: " << fmt_amount(min_utxo) << " MIQ\n";
                std::cout << "    Largest UTXO:  " << fmt_amount(max_utxo) << " MIQ\n";
            }

            std::cout << "\n  " << ui::bold() << "Connected Node:" << ui::reset() << "\n";
            std::cout << "    " << last_connected_node << "\n\n";

            std::cout << "  " << ui::dim() << "Press ENTER to return..." << ui::reset();
            std::string dummy;
            std::getline(std::cin, dummy);
            continue;
        }

        // =================================================================
        // OPTION h: Help
        // =================================================================
        if(c == "h" || c == "H"){
            std::cout << "\n";
            ui::print_double_header("WALLET HELP", 60);
            std::cout << "\n";

            std::cout << ui::bold() << "  Quick Start:" << ui::reset() << "\n";
            std::cout << "  1. Generate a new address (option 3) to receive MIQ\n";
            std::cout << "  2. Share this address with others to receive payments\n";
            std::cout << "  3. Use Send (option 2) to send MIQ to others\n\n";

            std::cout << ui::bold() << "  Security Tips:" << ui::reset() << "\n";
            std::cout << "  - Always verify the recipient address before sending\n";
            std::cout << "  - Keep your mnemonic phrase secure and private\n";
            std::cout << "  - Use strong encryption passphrase for your wallet\n";
            std::cout << "  - Backup your wallet files regularly\n\n";

            std::cout << ui::bold() << "  Transaction Status:" << ui::reset() << "\n";
            std::cout << "  - Unconfirmed: Transaction not yet in a block\n";
            std::cout << "  - 1-5 conf: Recent transaction, not fully confirmed\n";
            std::cout << "  - 6+ conf: Transaction is considered confirmed\n";
            std::cout << "  - Immature: Mining rewards, need 100 confirmations\n\n";

            std::cout << ui::bold() << "  Fee Priorities:" << ui::reset() << "\n";
            std::cout << "  - Economy (1 sat/byte): Cheap, may take longer\n";
            std::cout << "  - Normal (2 sat/byte): Standard speed\n";
            std::cout << "  - Priority (5 sat/byte): Faster confirmation\n";
            std::cout << "  - Urgent (10 sat/byte): Fastest confirmation\n\n";

            std::cout << "  " << ui::dim() << "Press ENTER to return..." << ui::reset();
            std::string dummy;
            std::getline(std::cin, dummy);
            continue;
        }

        // =================================================================
        // OPTION 1: List Receive Addresses
        // =================================================================
        if(c == "1"){
            std::cout << "\n";
            ui::print_double_header("RECEIVE ADDRESSES", 50);
            std::cout << "\n";

            // Get primary receive address (current)
            std::string primary_addr;
            uint32_t primary_idx = meta.next_recv > 0 ? meta.next_recv - 1 : 0;
            {
                auto it = addr_cache.find(primary_idx);
                if(it != addr_cache.end()){
                    primary_addr = it->second;
                } else {
                    miq::HdWallet tmp(seed, meta);
                    if(tmp.GetAddressAt(primary_idx, primary_addr)){
                        addr_cache[primary_idx] = primary_addr;
                    }
                }
            }

            // Show primary address prominently
            if(!primary_addr.empty()){
                std::cout << "  " << ui::bold() << "Primary Address:" << ui::reset() << "\n";
                ui::print_address_display(primary_addr, 48);
                std::cout << "\n";
            }

            // Show address history
            int count = std::max(1, (int)meta.next_recv);
            int show = std::min(count, 10);

            std::cout << "  " << ui::bold() << "Address History:" << ui::reset() << "\n\n";

            for(int i = show - 1; i >= 0; i--){
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
                    bool is_current = (i == (int)primary_idx);
                    std::cout << "  ";
                    if(is_current){
                        std::cout << ui::green() << ">" << ui::reset();
                    } else {
                        std::cout << " ";
                    }
                    std::cout << ui::dim() << "[" << std::setw(2) << i << "]" << ui::reset();

                    if(is_current){
                        std::cout << " " << ui::cyan() << ui::bold() << addr << ui::reset();
                        std::cout << " " << ui::green() << "(current)" << ui::reset();
                    } else {
                        std::cout << " " << ui::dim() << addr << ui::reset();
                    }
                    std::cout << "\n";
                }
            }

            if(count > show){
                std::cout << "\n  " << ui::dim() << "(" << (count - show)
                          << " more addresses available)" << ui::reset() << "\n";
            }

            std::cout << "\n  " << ui::cyan() << "n" << ui::reset() << "  Generate new address\n";
            std::cout << "  " << ui::cyan() << "c" << ui::reset() << "  Copy primary address to clipboard\n";
            std::cout << "  " << ui::cyan() << "q" << ui::reset() << "  Back\n\n";

            std::string recv_cmd = ui::prompt("Action: ");
            recv_cmd = trim(recv_cmd);

            if(recv_cmd == "n"){
                // Generate new address
                miq::HdWallet hw(seed, meta);
                std::string newaddr;
                if(hw.GetNewAddress(newaddr)){
                    auto m2 = meta; m2.next_recv++;
                    std::string e;
                    if(miq::SaveHdWallet(wdir, seed, m2, pass, e)){
                        meta = m2;
                        addr_cache[m2.next_recv - 1] = newaddr;
                        std::cout << "\n";
                        ui::print_success("New address generated!");
                        ui::print_address_display(newaddr, 48);
                    } else {
                        ui::print_error("Failed to save: " + e);
                    }
                }
            }
            else if(recv_cmd == "c" && !primary_addr.empty()){
                // Note: actual clipboard access would need platform-specific code
                std::cout << "\n  " << ui::dim() << "Address: " << primary_addr << ui::reset() << "\n";
                std::cout << "  " << ui::dim() << "(Copy the address above manually)" << ui::reset() << "\n\n";
            }
        }
        // =================================================================
        // OPTION 2: Send MIQ
        // =================================================================
        else if(c == "2"){
            std::cout << "\n";
            ui::print_double_header("SEND MIQ", 50);
            std::cout << "\n";

            // Check address book for quick selection
            std::vector<AddressBookEntry> book;
            load_address_book(wdir, book);

            std::string to;

            if(!book.empty()){
                std::cout << "  " << ui::dim() << "Quick select from address book:" << ui::reset() << "\n";
                for(size_t i = 0; i < std::min(book.size(), (size_t)5); i++){
                    std::cout << "    " << ui::cyan() << "[" << (i+1) << "]" << ui::reset()
                              << " " << book[i].label << "\n";
                }
                std::cout << "    " << ui::cyan() << "[0]" << ui::reset() << " Enter address manually\n\n";

                std::string sel = ui::prompt("Select (0 for manual): ");
                sel = trim(sel);
                int idx = std::atoi(sel.c_str());
                if(idx > 0 && idx <= (int)book.size()){
                    to = book[idx-1].address;
                    std::cout << "  " << ui::dim() << "Sending to: " << book[idx-1].label << ui::reset() << "\n\n";
                }
            }

            // Manual address entry
            if(to.empty()){
                to = ui::prompt("Recipient address: ");
                to = trim(to);
            }

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

            // Fee priority selection
            std::cout << "\n  " << ui::bold() << "Fee Priority:" << ui::reset() << "\n";
            std::cout << "    " << ui::cyan() << "[0]" << ui::reset() << " Economy - 1 sat/byte (slower)\n";
            std::cout << "    " << ui::cyan() << "[1]" << ui::reset() << " Normal - 2 sat/byte (recommended)\n";
            std::cout << "    " << ui::cyan() << "[2]" << ui::reset() << " Priority - 5 sat/byte (faster)\n";
            std::cout << "    " << ui::cyan() << "[3]" << ui::reset() << " Urgent - 10 sat/byte (fastest)\n\n";

            std::string fee_sel = ui::prompt("Fee priority [1]: ");
            fee_sel = trim(fee_sel);
            int fee_priority = fee_sel.empty() ? 1 : std::atoi(fee_sel.c_str());
            if(fee_priority < 0 || fee_priority > 3) fee_priority = 1;

            uint64_t fee_rate = fee_priority_rate(fee_priority);

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

            // Select inputs (use selected fee rate)
            uint64_t fee_rate_kb = fee_rate * 1000;  // Convert sat/byte to sat/kB
            miq::Transaction tx;
            uint64_t in_sum = 0;
            for(const auto& u : spendables){
                miq::TxIn in;
                in.prev.txid = u.txid;
                in.prev.vout = u.vout;
                tx.vin.push_back(in);
                in_sum += u.value;
                uint64_t fee_guess = fee_for(tx.vin.size(), 2, fee_rate_kb);
                if(in_sum >= amount + fee_guess) break;
            }

            if(tx.vin.empty() || in_sum < amount){
                ui::print_error("Insufficient funds");
                std::cout << ui::dim() << "  Available: " << fmt_amount(in_sum) << " MIQ" << ui::reset() << "\n";
                std::cout << ui::dim() << "  Requested: " << fmt_amount(amount) << " MIQ" << ui::reset() << "\n\n";
                continue;
            }

            // Calculate fee and change using selected fee rate
            uint64_t fee_final = 0, change = 0;
            {
                auto fee2 = fee_for(tx.vin.size(), 2, fee_rate_kb);
                if(in_sum < amount + fee2){
                    auto fee1 = fee_for(tx.vin.size(), 1, fee_rate_kb);
                    if(in_sum < amount + fee1){
                        ui::print_error("Insufficient funds for transaction fee");
                        continue;
                    }
                    fee_final = fee1;
                    change = 0;
                } else {
                    fee_final = fee2;
                    change = in_sum - amount - fee_final;
                    if(change < wallet_config::DUST_THRESHOLD){
                        change = 0;
                        fee_final = fee_for(tx.vin.size(), 1, fee_rate_kb);
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

            bool broadcast_success = broadcast_any_seed(seeds_b, raw, used_bcast_seed, berr);

            // Update pending cache regardless of broadcast success
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

            if(!broadcast_success){
                // Save transaction to queue for later broadcast
                QueuedTransaction qtx;
                qtx.txid_hex = txid_hex;
                qtx.raw_tx = raw;
                qtx.created_at = (int64_t)time(nullptr);
                qtx.last_attempt = qtx.created_at;
                qtx.broadcast_attempts = 1;
                qtx.status = "queued";
                qtx.to_address = to;
                qtx.amount = amount;
                qtx.fee = fee_final;
                qtx.error_msg = berr;

                add_to_tx_queue(wdir, qtx);

                std::cout << "\n";
                ui::print_warning("Broadcast failed - transaction saved to queue");
                std::cout << "\n";
                std::cout << "  " << ui::dim() << "Error:" << ui::reset() << " " << berr << "\n";
                std::cout << "  " << ui::dim() << "TXID:" << ui::reset() << " " << ui::cyan() << txid_hex << ui::reset() << "\n";
                std::cout << "\n";
                std::cout << "  " << ui::green() << "Transaction saved!" << ui::reset() << "\n";
                std::cout << "  " << ui::dim() << "The transaction has been saved and will be" << ui::reset() << "\n";
                std::cout << "  " << ui::dim() << "automatically broadcasted when network is available." << ui::reset() << "\n";
                std::cout << "\n";
                std::cout << "  " << ui::dim() << "Use 'b' to manually broadcast, or '7' to view queue." << ui::reset() << "\n\n";

                is_online = false;
                continue;
            }

            // Add to transaction history
            TxHistoryEntry hist;
            hist.txid_hex = txid_hex;
            hist.timestamp = (int64_t)time(nullptr);
            hist.amount = -(int64_t)amount;
            hist.fee = fee_final;
            hist.confirmations = 0;
            hist.direction = "sent";
            hist.to_address = to;
            add_tx_history(wdir, hist);

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

            is_online = true;

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
        // OPTION 7: Transaction Queue
        // =================================================================
        else if(c == "7"){
            std::cout << "\n";
            ui::print_double_header("TRANSACTION QUEUE", 60);
            std::cout << "\n";

            std::vector<QueuedTransaction> queue;
            load_tx_queue(wdir, queue);

            if(queue.empty()){
                std::cout << "  " << ui::dim() << "No transactions in queue." << ui::reset() << "\n";
                std::cout << "  " << ui::dim() << "Transactions created while offline will appear here." << ui::reset() << "\n\n";
            } else {
                std::cout << "  " << ui::dim() << "Transactions in queue: " << queue.size() << ui::reset() << "\n\n";

                // Count by status
                int queued = 0, confirmed = 0, failed = 0, expired = 0;
                for(const auto& tx : queue){
                    if(tx.status == "queued" || tx.status == "broadcasting") queued++;
                    else if(tx.status == "confirmed") confirmed++;
                    else if(tx.status == "failed") failed++;
                    else if(tx.status == "expired") expired++;
                }

                if(queued > 0)
                    std::cout << "  " << ui::yellow() << "Pending: " << queued << ui::reset() << "\n";
                if(confirmed > 0)
                    std::cout << "  " << ui::green() << "Confirmed: " << confirmed << ui::reset() << "\n";
                if(failed > 0)
                    std::cout << "  " << ui::red() << "Failed: " << failed << ui::reset() << "\n";
                if(expired > 0)
                    std::cout << "  " << ui::dim() << "Expired: " << expired << ui::reset() << "\n";

                std::cout << "\n";

                // Show recent transactions
                int show_count = std::min((int)queue.size(), 10);
                for(int i = 0; i < show_count; i++){
                    const auto& tx = queue[i];

                    std::cout << "  " << ui::tx_status_badge(tx.status);
                    std::cout << " " << ui::dim() << tx.txid_hex.substr(0, 16) << "..." << ui::reset();
                    std::cout << " " << ui::cyan() << fmt_amount_short(tx.amount) << " MIQ" << ui::reset();

                    if(!tx.to_address.empty()){
                        std::cout << " -> " << ui::dim() << tx.to_address.substr(0, 12) << "..." << ui::reset();
                    }

                    std::cout << "\n";

                    // Show error if any
                    if(!tx.error_msg.empty() && tx.status != "confirmed"){
                        std::cout << "    " << ui::red() << ui::dim() << tx.error_msg << ui::reset() << "\n";
                    }
                }

                if((int)queue.size() > show_count){
                    std::cout << "\n  " << ui::dim() << "(" << (queue.size() - show_count)
                              << " more transactions)" << ui::reset() << "\n";
                }
            }

            std::cout << "\n  " << ui::dim() << "Press ENTER to return..." << ui::reset();
            std::string dummy;
            std::getline(std::cin, dummy);
        }
        // =================================================================
        // OPTION b: Broadcast Queue
        // =================================================================
        else if(c == "b" || c == "B"){
            std::cout << "\n";
            int pending_count = count_pending_in_queue(wdir);

            if(pending_count == 0){
                ui::print_info("No pending transactions to broadcast");
                std::cout << "\n";
            } else {
                ui::print_info("Broadcasting " + std::to_string(pending_count) + " pending transaction(s)...");
                std::cout << "\n";

                int broadcasted = process_tx_queue(wdir, seeds, true);

                std::cout << "\n";
                if(broadcasted > 0){
                    ui::print_success("Successfully broadcasted " + std::to_string(broadcasted) + " transaction(s)");
                    is_online = true;
                } else if(broadcasted == 0 && pending_count > 0){
                    ui::print_warning("No transactions could be broadcasted");
                    std::cout << "  " << ui::dim() << "Check network connectivity and try again" << ui::reset() << "\n";
                }
                std::cout << "\n";
            }
        }
        // =================================================================
        // OPTION r: Refresh Balance
        // =================================================================
        else if(c == "r" || c == "R"){
            utxos = refresh_and_print();
            is_online = (last_connected_node != "<offline>" && last_connected_node != "<not connected>");

            // Try to broadcast any pending transactions
            int pending_count = count_pending_in_queue(wdir);
            if(pending_count > 0 && is_online){
                std::cout << "  " << ui::dim() << "Broadcasting " << pending_count << " queued transaction(s)..." << ui::reset() << "\n";
                int broadcasted = process_tx_queue(wdir, seeds, false);
                if(broadcasted > 0){
                    std::cout << "  " << ui::green() << "Broadcasted " << broadcasted << " transaction(s)" << ui::reset() << "\n\n";
                }
            }
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

    // Initialize colors based on terminal capability detection
    ui::init_colors();

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
