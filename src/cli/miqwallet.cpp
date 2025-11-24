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
// WALLET FINGERPRINT - Prevents cache contamination between wallets
// =============================================================================

// Generate a fingerprint from wallet's first few addresses
static std::string generate_wallet_fingerprint(const std::vector<std::vector<uint8_t>>& pkhs){
    if(pkhs.empty()) return "";

    // Use first 5 PKHs to create fingerprint
    std::vector<uint8_t> data;
    size_t count = std::min(pkhs.size(), (size_t)5);
    for(size_t i = 0; i < count; ++i){
        data.insert(data.end(), pkhs[i].begin(), pkhs[i].end());
    }

    auto hash = miq::dsha256(data);
    return miq::to_hex(hash).substr(0, 16);  // First 16 chars
}

static std::string fingerprint_file_path(const std::string& wdir){
    return join_path(wdir, "wallet_fingerprint.dat");
}

static std::string load_cached_fingerprint(const std::string& wdir){
    std::ifstream f(fingerprint_file_path(wdir));
    if(!f.good()) return "";
    std::string fp;
    std::getline(f, fp);
    return fp;
}

static void save_wallet_fingerprint(const std::string& wdir, const std::string& fp){
    std::ofstream f(fingerprint_file_path(wdir), std::ios::out | std::ios::trunc);
    if(f.good()) f << fp << "\n";
}

// Check if cache belongs to current wallet, clear if not
static void verify_cache_ownership(const std::string& wdir,
                                    const std::vector<std::vector<uint8_t>>& pkhs){
    std::string current_fp = generate_wallet_fingerprint(pkhs);
    std::string cached_fp = load_cached_fingerprint(wdir);

    if(cached_fp.empty()){
        // No fingerprint - new cache or old format, save current
        save_wallet_fingerprint(wdir, current_fp);
        return;
    }

    if(cached_fp != current_fp){
        // Different wallet! Clear ALL cached data
        clear_spv_cache(wdir);

        // Also clear pending spent since it's wallet-specific
        std::remove(join_path(wdir, "pending_spent.dat").c_str());

        // Save new fingerprint
        save_wallet_fingerprint(wdir, current_fp);

        // Note: Cache was invalidated due to wallet fingerprint mismatch
        // This happens when switching between different wallets
    }
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

// =============================================================================
// PROFESSIONAL WALLET FEATURES - v2.0 Stable
// =============================================================================

// Transaction validation result
struct TxValidationResult {
    bool valid{false};
    std::string error;
    uint64_t total_input{0};
    uint64_t total_output{0};
    uint64_t fee{0};
    size_t size_bytes{0};
    double fee_rate{0.0};  // sat/byte
};

// UTXO selection strategies
enum class CoinSelectionStrategy {
    OLDEST_FIRST,      // Spend oldest UTXOs first (default)
    LARGEST_FIRST,     // Spend largest UTXOs first
    SMALLEST_FIRST,    // Spend smallest UTXOs first (consolidation)
    MINIMIZE_INPUTS,   // Use fewest inputs possible
    PRIVACY_OPTIMIZED  // Avoid address reuse patterns
};

// Network health status
struct NetworkHealth {
    bool connected{false};
    int peer_count{0};
    uint32_t tip_height{0};
    int64_t last_block_time{0};
    double estimated_hashrate{0.0};
    int mempool_size{0};
    std::string node_version;
};

// Wallet statistics
struct WalletStats {
    uint64_t total_received{0};
    uint64_t total_sent{0};
    uint64_t total_fees_paid{0};
    uint32_t tx_count{0};
    uint32_t utxo_count{0};
    uint32_t address_count{0};
    int64_t first_activity{0};
    int64_t last_activity{0};
    double avg_tx_size{0.0};
    double avg_fee_rate{0.0};
};

// Transaction confirmation info
struct TxConfirmation {
    std::string txid_hex;
    uint32_t confirmations{0};
    uint32_t block_height{0};
    int64_t block_time{0};
    bool in_mempool{false};
    bool double_spent{false};
};

// Address info for tracking
struct AddressInfo {
    std::string address;
    std::string label;
    uint32_t chain{0};      // 0=receive, 1=change
    uint32_t index{0};
    uint64_t total_received{0};
    uint64_t total_sent{0};
    uint32_t tx_count{0};
    int64_t first_seen{0};
    int64_t last_seen{0};
    bool used{false};
};

// =============================================================================
// COIN SELECTION ALGORITHMS
// =============================================================================

// Branch and Bound coin selection for optimal input selection
static bool coin_select_branch_and_bound(
    const std::vector<miq::UtxoLite>& available,
    uint64_t target_value,
    uint64_t fee_rate,
    std::vector<size_t>& selected_indices,
    uint64_t& total_selected,
    int max_iterations = 100000)
{
    if(available.empty()) return false;

    // Sort by value descending for efficiency
    std::vector<std::pair<uint64_t, size_t>> sorted;
    sorted.reserve(available.size());
    for(size_t i = 0; i < available.size(); ++i){
        sorted.push_back({available[i].value, i});
    }
    std::sort(sorted.begin(), sorted.end(),
        [](const auto& a, const auto& b){ return a.first > b.first; });

    // Estimate fee for single input
    uint64_t input_fee = fee_rate * 148;  // ~148 bytes per P2PKH input
    uint64_t output_fee = fee_rate * 34;  // ~34 bytes per output
    uint64_t base_fee = fee_rate * 10;    // ~10 bytes overhead

    uint64_t target_with_fee = target_value + base_fee + output_fee * 2;

    // Try exact match first
    std::vector<bool> current(sorted.size(), false);
    std::vector<bool> best(sorted.size(), false);
    uint64_t best_waste = UINT64_MAX;
    uint64_t current_value = 0;
    int iterations = 0;

    std::function<void(size_t, uint64_t)> search = [&](size_t depth, uint64_t remaining) {
        if(iterations++ > max_iterations) return;

        uint64_t fees = base_fee + output_fee * 2;
        for(size_t i = 0; i < depth; ++i){
            if(current[i]) fees += input_fee;
        }

        if(current_value >= target_value + fees){
            uint64_t waste = current_value - target_value - fees;
            if(waste < best_waste){
                best_waste = waste;
                best = current;
            }
            return;
        }

        if(depth >= sorted.size()) return;

        // Calculate remaining available value
        uint64_t remaining_value = 0;
        for(size_t i = depth; i < sorted.size(); ++i){
            remaining_value += sorted[i].first;
        }

        if(current_value + remaining_value < target_with_fee) return;

        // Include current
        current[depth] = true;
        current_value += sorted[depth].first;
        search(depth + 1, remaining - sorted[depth].first);
        current[depth] = false;
        current_value -= sorted[depth].first;

        // Exclude current
        search(depth + 1, remaining);
    };

    uint64_t total_available = 0;
    for(const auto& u : available) total_available += u.value;
    search(0, total_available);

    if(best_waste == UINT64_MAX){
        // Branch and bound failed, use greedy
        return false;
    }

    selected_indices.clear();
    total_selected = 0;
    for(size_t i = 0; i < best.size(); ++i){
        if(best[i]){
            selected_indices.push_back(sorted[i].second);
            total_selected += sorted[i].first;
        }
    }

    return !selected_indices.empty();
}

// Greedy coin selection with strategy
static bool coin_select_greedy(
    const std::vector<miq::UtxoLite>& available,
    uint64_t target_value,
    uint64_t fee_rate,
    CoinSelectionStrategy strategy,
    std::vector<size_t>& selected_indices,
    uint64_t& total_selected)
{
    if(available.empty()) return false;

    // Create sorted indices based on strategy
    std::vector<size_t> order;
    order.reserve(available.size());
    for(size_t i = 0; i < available.size(); ++i) order.push_back(i);

    switch(strategy){
        case CoinSelectionStrategy::OLDEST_FIRST:
            std::sort(order.begin(), order.end(), [&](size_t a, size_t b){
                if(available[a].height != available[b].height)
                    return available[a].height < available[b].height;
                return available[a].value > available[b].value;
            });
            break;
        case CoinSelectionStrategy::LARGEST_FIRST:
            std::sort(order.begin(), order.end(), [&](size_t a, size_t b){
                return available[a].value > available[b].value;
            });
            break;
        case CoinSelectionStrategy::SMALLEST_FIRST:
            std::sort(order.begin(), order.end(), [&](size_t a, size_t b){
                return available[a].value < available[b].value;
            });
            break;
        case CoinSelectionStrategy::MINIMIZE_INPUTS:
            std::sort(order.begin(), order.end(), [&](size_t a, size_t b){
                return available[a].value > available[b].value;
            });
            break;
        case CoinSelectionStrategy::PRIVACY_OPTIMIZED:
            // Shuffle for privacy
            {
                std::random_device rd;
                std::mt19937 g(rd());
                std::shuffle(order.begin(), order.end(), g);
            }
            break;
    }

    selected_indices.clear();
    total_selected = 0;
    uint64_t base_fee = fee_rate * 10;
    uint64_t output_fee = fee_rate * 34;
    uint64_t input_fee = fee_rate * 148;

    for(size_t idx : order){
        selected_indices.push_back(idx);
        total_selected += available[idx].value;

        uint64_t total_fee = base_fee + output_fee * 2 + input_fee * selected_indices.size();
        if(total_selected >= target_value + total_fee){
            return true;
        }
    }

    // Not enough funds
    selected_indices.clear();
    total_selected = 0;
    return false;
}

// Smart coin selection: tries branch and bound, falls back to greedy
[[maybe_unused]] static bool smart_coin_select(
    const std::vector<miq::UtxoLite>& available,
    uint64_t target_value,
    uint64_t fee_rate,
    CoinSelectionStrategy fallback_strategy,
    std::vector<size_t>& selected_indices,
    uint64_t& total_selected)
{
    // Try branch and bound first for optimal selection
    if(coin_select_branch_and_bound(available, target_value, fee_rate,
                                     selected_indices, total_selected)){
        return true;
    }

    // Fall back to greedy
    return coin_select_greedy(available, target_value, fee_rate,
                              fallback_strategy, selected_indices, total_selected);
}

// =============================================================================
// TRANSACTION VALIDATION
// =============================================================================

static TxValidationResult validate_transaction(
    const miq::Transaction& tx,
    const std::vector<miq::UtxoLite>& utxos,
    uint64_t max_fee = 10000000)  // 0.1 MIQ max fee by default
{
    TxValidationResult result;

    // Check basic structure
    if(tx.vin.empty()){
        result.error = "Transaction has no inputs";
        return result;
    }
    if(tx.vout.empty()){
        result.error = "Transaction has no outputs";
        return result;
    }
    if(tx.vin.size() > wallet_config::MAX_TX_INPUTS){
        result.error = "Too many inputs (" + std::to_string(tx.vin.size()) + ")";
        return result;
    }
    if(tx.vout.size() > wallet_config::MAX_TX_OUTPUTS){
        result.error = "Too many outputs (" + std::to_string(tx.vout.size()) + ")";
        return result;
    }

    // Build UTXO lookup
    std::unordered_map<std::string, const miq::UtxoLite*> utxo_map;
    for(const auto& u : utxos){
        std::string key = miq::to_hex(u.txid) + ":" + std::to_string(u.vout);
        utxo_map[key] = &u;
    }

    // Calculate input sum
    result.total_input = 0;
    for(const auto& in : tx.vin){
        std::string key = miq::to_hex(in.prev.txid) + ":" + std::to_string(in.prev.vout);
        auto it = utxo_map.find(key);
        if(it == utxo_map.end()){
            result.error = "Input UTXO not found: " + key.substr(0, 16) + "...";
            return result;
        }
        result.total_input += it->second->value;
    }

    // Calculate output sum
    result.total_output = 0;
    for(const auto& out : tx.vout){
        if(out.value == 0){
            result.error = "Output with zero value";
            return result;
        }
        if(out.value < wallet_config::DUST_THRESHOLD){
            result.error = "Output below dust threshold (" +
                          std::to_string(out.value) + " < " +
                          std::to_string(wallet_config::DUST_THRESHOLD) + ")";
            return result;
        }
        result.total_output += out.value;
    }

    // Check fee
    if(result.total_input < result.total_output){
        result.error = "Outputs exceed inputs (negative fee)";
        return result;
    }
    result.fee = result.total_input - result.total_output;

    if(result.fee == 0){
        result.error = "Zero fee transaction";
        return result;
    }
    if(result.fee > max_fee){
        result.error = "Fee too high (" + std::to_string(result.fee) + " > " +
                      std::to_string(max_fee) + ")";
        return result;
    }

    // Estimate size and fee rate
    result.size_bytes = 10 + tx.vin.size() * 148 + tx.vout.size() * 34;
    result.fee_rate = (double)result.fee / result.size_bytes;

    result.valid = true;
    return result;
}

// =============================================================================
// ADDRESS VALIDATION
// =============================================================================

static bool validate_address(const std::string& addr, std::string& error){
    if(addr.empty()){
        error = "Address is empty";
        return false;
    }

    // Check length
    if(addr.length() < 25 || addr.length() > 35){
        error = "Invalid address length";
        return false;
    }

    // Check base58 characters
    const char* b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for(char c : addr){
        if(strchr(b58chars, c) == nullptr){
            error = "Invalid character in address: " + std::string(1, c);
            return false;
        }
    }

    // Decode and verify checksum
    uint8_t ver = 0;
    std::vector<uint8_t> payload;
    if(!miq::base58check_decode(addr, ver, payload)){
        error = "Invalid address checksum";
        return false;
    }

    // Check version byte
    if(ver != miq::VERSION_P2PKH){
        error = "Invalid address version (expected P2PKH)";
        return false;
    }

    // Check payload length (should be 20 bytes for hash160)
    if(payload.size() != 20){
        error = "Invalid address payload length";
        return false;
    }

    return true;
}

// =============================================================================
// WALLET STATISTICS
// =============================================================================

static std::string stats_file_path(const std::string& wdir){
    return join_path(wdir, "wallet_stats.dat");
}

static void load_wallet_stats(const std::string& wdir, WalletStats& stats){
    std::ifstream f(stats_file_path(wdir));
    if(!f.good()) return;

    std::string line;
    while(std::getline(f, line)){
        if(line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if(eq == std::string::npos) continue;
        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if(key == "total_received") stats.total_received = std::strtoull(val.c_str(), nullptr, 10);
        else if(key == "total_sent") stats.total_sent = std::strtoull(val.c_str(), nullptr, 10);
        else if(key == "total_fees") stats.total_fees_paid = std::strtoull(val.c_str(), nullptr, 10);
        else if(key == "tx_count") stats.tx_count = (uint32_t)std::strtoul(val.c_str(), nullptr, 10);
        else if(key == "first_activity") stats.first_activity = std::strtoll(val.c_str(), nullptr, 10);
        else if(key == "last_activity") stats.last_activity = std::strtoll(val.c_str(), nullptr, 10);
    }
}

static void save_wallet_stats(const std::string& wdir, const WalletStats& stats){
    std::ofstream f(stats_file_path(wdir), std::ios::out | std::ios::trunc);
    if(!f.good()) return;

    f << "# MIQ Wallet Statistics\n";
    f << "total_received=" << stats.total_received << "\n";
    f << "total_sent=" << stats.total_sent << "\n";
    f << "total_fees=" << stats.total_fees_paid << "\n";
    f << "tx_count=" << stats.tx_count << "\n";
    f << "first_activity=" << stats.first_activity << "\n";
    f << "last_activity=" << stats.last_activity << "\n";
}

static void update_stats_for_send(const std::string& wdir, uint64_t amount, uint64_t fee){
    WalletStats stats{};
    load_wallet_stats(wdir, stats);

    stats.total_sent += amount;
    stats.total_fees_paid += fee;
    stats.tx_count++;
    stats.last_activity = (int64_t)time(nullptr);
    if(stats.first_activity == 0) stats.first_activity = stats.last_activity;

    save_wallet_stats(wdir, stats);
}

// =============================================================================
// FEE ESTIMATION
// =============================================================================

struct FeeEstimate {
    uint64_t low_priority;      // sat/byte - next 6 blocks
    uint64_t medium_priority;   // sat/byte - next 3 blocks
    uint64_t high_priority;     // sat/byte - next block
    int64_t estimated_time;     // seconds for medium priority
};

[[maybe_unused]] static FeeEstimate get_fee_estimates(){
    // Default fee estimates (can be updated from network)
    FeeEstimate est;
    est.low_priority = 1;
    est.medium_priority = 2;
    est.high_priority = 5;
    est.estimated_time = 600;  // ~10 minutes
    return est;
}

[[maybe_unused]] static uint64_t estimate_tx_fee(size_t num_inputs, size_t num_outputs, uint64_t fee_rate){
    // P2PKH transaction size estimation
    // Header: 4 (version) + 4 (locktime) + 1-2 (input count varint) + 1-2 (output count varint) = ~10 bytes
    // Input: 32 (txid) + 4 (vout) + 1 (script len) + ~107 (sig + pubkey) + 4 (sequence) = ~148 bytes
    // Output: 8 (value) + 1 (script len) + 25 (P2PKH script) = ~34 bytes

    size_t estimated_size = 10 + num_inputs * 148 + num_outputs * 34;
    return estimated_size * fee_rate;
}

// =============================================================================
// UTXO CONSOLIDATION
// =============================================================================

[[maybe_unused]] static bool should_consolidate_utxos(const std::vector<miq::UtxoLite>& utxos,
                                     uint64_t threshold_count = 100,
                                     uint64_t dust_threshold = 10000){
    if(utxos.size() < threshold_count) return false;

    // Count dust UTXOs
    size_t dust_count = 0;
    for(const auto& u : utxos){
        if(u.value < dust_threshold) dust_count++;
    }

    // Recommend consolidation if >20% are dust
    return dust_count > utxos.size() / 5;
}

[[maybe_unused]] static std::vector<miq::UtxoLite> get_consolidation_candidates(
    const std::vector<miq::UtxoLite>& utxos,
    size_t max_inputs = 50,
    uint64_t min_value = 1000)
{
    std::vector<miq::UtxoLite> candidates;
    candidates.reserve(std::min(utxos.size(), max_inputs));

    // Sort by value ascending (consolidate smallest first)
    std::vector<std::pair<uint64_t, size_t>> sorted;
    for(size_t i = 0; i < utxos.size(); ++i){
        if(utxos[i].value >= min_value){
            sorted.push_back({utxos[i].value, i});
        }
    }
    std::sort(sorted.begin(), sorted.end());

    for(size_t i = 0; i < std::min(sorted.size(), max_inputs); ++i){
        candidates.push_back(utxos[sorted[i].second]);
    }

    return candidates;
}

// =============================================================================
// TRANSACTION TRACKING
// =============================================================================

struct TrackedTransaction {
    std::string txid_hex;
    int64_t created_at{0};
    int64_t confirmed_at{0};
    uint32_t block_height{0};
    uint32_t confirmations{0};
    uint64_t amount{0};
    uint64_t fee{0};
    std::string direction;  // "sent", "received"
    std::string to_address;
    std::string memo;
    bool confirmed{false};
    bool failed{false};
    std::string failure_reason;
};

static std::string tracked_tx_path(const std::string& wdir){
    return join_path(wdir, "tracked_transactions.dat");
}

static void save_tracked_transaction(const std::string& wdir, const TrackedTransaction& tx){
    std::ofstream f(tracked_tx_path(wdir), std::ios::app);
    if(!f.good()) return;

    f << tx.txid_hex << "|"
      << tx.created_at << "|"
      << tx.confirmed_at << "|"
      << tx.block_height << "|"
      << tx.amount << "|"
      << tx.fee << "|"
      << tx.direction << "|"
      << tx.to_address << "|"
      << tx.memo << "|"
      << (tx.confirmed ? "1" : "0") << "|"
      << (tx.failed ? "1" : "0") << "|"
      << tx.failure_reason << "\n";
}

[[maybe_unused]] static void load_tracked_transactions(const std::string& wdir,
                                       std::vector<TrackedTransaction>& out){
    out.clear();
    std::ifstream f(tracked_tx_path(wdir));
    if(!f.good()) return;

    std::string line;
    while(std::getline(f, line)){
        if(line.empty()) continue;

        TrackedTransaction tx;
        std::vector<std::string> parts;
        std::istringstream ss(line);
        std::string part;
        while(std::getline(ss, part, '|')){
            parts.push_back(part);
        }

        if(parts.size() >= 12){
            tx.txid_hex = parts[0];
            tx.created_at = std::strtoll(parts[1].c_str(), nullptr, 10);
            tx.confirmed_at = std::strtoll(parts[2].c_str(), nullptr, 10);
            tx.block_height = (uint32_t)std::strtoul(parts[3].c_str(), nullptr, 10);
            tx.amount = std::strtoull(parts[4].c_str(), nullptr, 10);
            tx.fee = std::strtoull(parts[5].c_str(), nullptr, 10);
            tx.direction = parts[6];
            tx.to_address = parts[7];
            tx.memo = parts[8];
            tx.confirmed = (parts[9] == "1");
            tx.failed = (parts[10] == "1");
            tx.failure_reason = parts[11];
            out.push_back(tx);
        }
    }
}

// =============================================================================
// SECURITY FEATURES
// =============================================================================

// Check for address reuse (privacy concern)
[[maybe_unused]] static bool check_address_reuse(
    const std::vector<miq::UtxoLite>& utxos,
    const std::vector<uint8_t>& pkh,
    int& reuse_count)
{
    reuse_count = 0;
    for(const auto& u : utxos){
        if(u.pkh == pkh) reuse_count++;
    }
    return reuse_count > 1;
}

// Verify transaction signatures
[[maybe_unused]] static bool verify_tx_signatures(const miq::Transaction& tx){
    for(const auto& in : tx.vin){
        if(in.sig.empty() || in.pubkey.empty()){
            return false;
        }
        // Basic signature length checks
        if(in.sig.size() != 64){  // ECDSA signature is 64 bytes
            return false;
        }
        if(in.pubkey.size() != 33 && in.pubkey.size() != 65){  // Compressed or uncompressed
            return false;
        }
    }
    return true;
}

// Check for potential double-spend attempts
[[maybe_unused]] static bool check_double_spend_risk(
    const miq::Transaction& tx,
    const std::set<OutpointKey>& pending)
{
    for(const auto& in : tx.vin){
        OutpointKey k{ miq::to_hex(in.prev.txid), in.prev.vout };
        if(pending.find(k) != pending.end()){
            return true;  // Input already used in pending tx
        }
    }
    return false;
}

// =============================================================================
// MEMORY MANAGEMENT
// =============================================================================

// Compact UTXO set to reduce memory usage
[[maybe_unused]] static void compact_utxo_set(std::vector<miq::UtxoLite>& utxos){
    // Remove any invalid entries
    utxos.erase(
        std::remove_if(utxos.begin(), utxos.end(), [](const miq::UtxoLite& u){
            return u.txid.size() != 32 || u.pkh.size() != 20 || u.value == 0;
        }),
        utxos.end()
    );

    // Shrink to fit
    utxos.shrink_to_fit();
}

// Estimate memory usage of UTXO set
[[maybe_unused]] static size_t estimate_utxo_memory(const std::vector<miq::UtxoLite>& utxos){
    // Each UtxoLite: 32 (txid) + 4 (vout) + 8 (value) + 20 (pkh) + 4 (height) + 1 (coinbase)
    // Plus vector overhead
    return utxos.size() * (32 + 4 + 8 + 20 + 4 + 1 + 24);  // ~93 bytes per UTXO
}

// =============================================================================
// BACKUP AND RESTORE
// =============================================================================

static std::string backup_file_path(const std::string& wdir, int64_t timestamp){
    std::ostringstream oss;
    oss << "wallet_backup_" << timestamp << ".dat";
    return join_path(wdir, oss.str());
}

static bool create_wallet_backup(const std::string& wdir, std::string& backup_path, std::string& error){
    int64_t now = (int64_t)time(nullptr);
    backup_path = backup_file_path(wdir, now);

    // Read wallet file
    std::string wallet_file = join_path(wdir, "wallet.dat");
    std::ifstream in(wallet_file, std::ios::binary);
    if(!in.good()){
        error = "Cannot read wallet file";
        return false;
    }

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(in)), {});
    in.close();

    // Write backup
    std::ofstream out(backup_path, std::ios::binary);
    if(!out.good()){
        error = "Cannot create backup file";
        return false;
    }

    out.write((const char*)data.data(), data.size());
    out.close();

    return true;
}

// =============================================================================
// RATE LIMITING
// =============================================================================

static std::atomic<int64_t> g_last_sync_time{0};
static std::atomic<int> g_sync_count{0};

[[maybe_unused]] static bool check_rate_limit(int max_per_minute = 10){
    int64_t now = (int64_t)time(nullptr);
    int64_t last = g_last_sync_time.load();

    if(now - last >= 60){
        g_last_sync_time.store(now);
        g_sync_count.store(1);
        return true;
    }

    int count = g_sync_count.fetch_add(1);
    return count < max_per_minute;
}

// =============================================================================
// LOGGING
// =============================================================================

static std::string wallet_log_path(const std::string& wdir){
    return join_path(wdir, "wallet.log");
}

static void log_wallet_event(const std::string& wdir, const std::string& event){
    std::ofstream f(wallet_log_path(wdir), std::ios::app);
    if(!f.good()) return;

    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);

    f << "[" << buf << "] " << event << "\n";
}

// =============================================================================
// PROFESSIONAL WALLET UPGRADE v1.0 - Enterprise Grade Features
// =============================================================================

// =============================================================================
// ADVANCED UI SYSTEM - Professional Terminal Interface
// =============================================================================

namespace ui_pro {
    // Animation state
    static std::atomic<bool> g_animation_running{false};
    static std::atomic<int> g_animation_frame{0};

    // Professional spinner frames (ASCII compatible)
    static const char* SPINNER_FRAMES[] = {"|", "/", "-", "\\"};
    static const int SPINNER_FRAME_COUNT = 4;

    // Progress bar styles
    enum class ProgressStyle {
        CLASSIC,      // [=====>    ]
        BLOCKS,       // [▓▓▓▓░░░░░░]
        DOTS,         // [●●●●○○○○○○]
        ARROW         // [>>>>>>    ]
    };

    // Draw a professional progress bar
    static std::string draw_progress_bar(double percent, int width, ProgressStyle style = ProgressStyle::CLASSIC){
        int filled = (int)(percent * width / 100.0);
        std::string bar = "[";

        for(int i = 0; i < width; ++i){
            if(i < filled){
                switch(style){
                    case ProgressStyle::CLASSIC: bar += "="; break;
                    case ProgressStyle::BLOCKS: bar += "#"; break;
                    case ProgressStyle::DOTS: bar += "*"; break;
                    case ProgressStyle::ARROW: bar += ">"; break;
                }
            } else if(i == filled && style == ProgressStyle::CLASSIC){
                bar += ">";
            } else {
                switch(style){
                    case ProgressStyle::CLASSIC: bar += " "; break;
                    case ProgressStyle::BLOCKS: bar += "-"; break;
                    case ProgressStyle::DOTS: bar += "."; break;
                    case ProgressStyle::ARROW: bar += " "; break;
                }
            }
        }
        bar += "]";
        return bar;
    }

    // Format large numbers with commas
    static std::string format_number(uint64_t n){
        std::string s = std::to_string(n);
        int insertPosition = (int)s.length() - 3;
        while(insertPosition > 0){
            s.insert(insertPosition, ",");
            insertPosition -= 3;
        }
        return s;
    }

    // Format amount with proper decimal places and thousands separators
    static std::string format_miq_professional(uint64_t miqron){
        uint64_t whole = miqron / 100000000ULL;
        uint64_t frac = miqron % 100000000ULL;

        std::string whole_str = format_number(whole);

        if(frac == 0){
            return whole_str + ".00";
        }

        char frac_str[16];
        snprintf(frac_str, sizeof(frac_str), "%08llu", (unsigned long long)frac);

        // Trim trailing zeros but keep at least 2 decimal places
        std::string f = frac_str;
        while(f.length() > 2 && f.back() == '0') f.pop_back();

        return whole_str + "." + f;
    }

    // Print a status line with icon
    static void print_status(const std::string& icon, const std::string& message,
                             const std::string& color = ""){
        if(!color.empty()) std::cout << color;
        std::cout << "  " << icon << " " << message;
        if(!color.empty()) std::cout << ui::reset();
        std::cout << "\n";
    }

    // Print a key-value pair aligned
    static void print_kv(const std::string& key, const std::string& value,
                         int key_width = 20, const std::string& value_color = ""){
        std::cout << "  " << ui::dim() << std::left << std::setw(key_width)
                  << key << ui::reset();
        if(!value_color.empty()) std::cout << value_color;
        std::cout << value;
        if(!value_color.empty()) std::cout << ui::reset();
        std::cout << "\n";
    }

    // Print a boxed message
    static void print_box(const std::string& title, const std::vector<std::string>& lines,
                          int width = 60){
        // Top border
        std::cout << ui::cyan() << "+";
        for(int i = 0; i < width - 2; ++i) std::cout << "-";
        std::cout << "+" << ui::reset() << "\n";

        // Title
        int padding = (width - 2 - (int)title.length()) / 2;
        std::cout << ui::cyan() << "|" << ui::reset();
        for(int i = 0; i < padding; ++i) std::cout << " ";
        std::cout << ui::bold() << title << ui::reset();
        for(int i = 0; i < width - 2 - padding - (int)title.length(); ++i) std::cout << " ";
        std::cout << ui::cyan() << "|" << ui::reset() << "\n";

        // Separator
        std::cout << ui::cyan() << "+";
        for(int i = 0; i < width - 2; ++i) std::cout << "-";
        std::cout << "+" << ui::reset() << "\n";

        // Content
        for(const auto& line : lines){
            std::cout << ui::cyan() << "|" << ui::reset() << " ";
            std::cout << std::left << std::setw(width - 4) << line;
            std::cout << " " << ui::cyan() << "|" << ui::reset() << "\n";
        }

        // Bottom border
        std::cout << ui::cyan() << "+";
        for(int i = 0; i < width - 2; ++i) std::cout << "-";
        std::cout << "+" << ui::reset() << "\n";
    }

    // Print transaction details in a nice format
    static void print_tx_details(const std::string& txid, uint64_t amount, uint64_t fee,
                                  const std::string& to_addr, const std::string& status){
        std::vector<std::string> lines;
        lines.push_back("TXID: " + txid.substr(0, 32) + "...");
        lines.push_back("Amount: " + format_miq_professional(amount) + " MIQ");
        lines.push_back("Fee: " + format_miq_professional(fee) + " MIQ");
        lines.push_back("To: " + to_addr.substr(0, 34));
        lines.push_back("Status: " + status);
        print_box("TRANSACTION DETAILS", lines, 50);
    }

    // Animated waiting indicator
    static void show_spinner_once(){
        int frame = g_animation_frame.fetch_add(1) % SPINNER_FRAME_COUNT;
        std::cout << "\r  " << SPINNER_FRAMES[frame] << " " << std::flush;
    }
}

// =============================================================================
// SESSION MANAGEMENT - Timeout and Security
// =============================================================================

struct SessionState {
    int64_t last_activity{0};
    int64_t session_start{0};
    bool locked{false};
    int failed_attempts{0};
    std::string session_id;

    void update_activity(){
        last_activity = (int64_t)time(nullptr);
    }

    bool is_timed_out(int timeout_seconds = 900) const {  // 15 min default
        if(timeout_seconds <= 0) return false;
        return (time(nullptr) - last_activity) > timeout_seconds;
    }

    void reset(){
        session_start = time(nullptr);
        last_activity = session_start;
        locked = false;
        failed_attempts = 0;

        // Generate session ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        const char* hex = "0123456789abcdef";
        session_id.clear();
        for(int i = 0; i < 16; ++i){
            session_id += hex[dis(gen)];
        }
    }
};

// =============================================================================
// PASSWORD STRENGTH CHECKER
// =============================================================================

struct PasswordStrength {
    int score{0};          // 0-100
    std::string rating;    // "Weak", "Fair", "Good", "Strong", "Very Strong"
    std::vector<std::string> suggestions;
};

[[maybe_unused]] static PasswordStrength check_password_strength(const std::string& password){
    PasswordStrength result;
    result.score = 0;

    if(password.empty()){
        result.rating = "None";
        result.suggestions.push_back("Enter a password for security");
        return result;
    }

    // Length scoring
    if(password.length() >= 8) result.score += 20;
    if(password.length() >= 12) result.score += 10;
    if(password.length() >= 16) result.score += 10;

    // Character variety
    bool has_lower = false, has_upper = false, has_digit = false, has_special = false;
    for(char c : password){
        if(std::islower(c)) has_lower = true;
        else if(std::isupper(c)) has_upper = true;
        else if(std::isdigit(c)) has_digit = true;
        else has_special = true;
    }

    if(has_lower) result.score += 15;
    if(has_upper) result.score += 15;
    if(has_digit) result.score += 15;
    if(has_special) result.score += 15;

    // Suggestions
    if(password.length() < 8){
        result.suggestions.push_back("Use at least 8 characters");
    }
    if(!has_upper){
        result.suggestions.push_back("Add uppercase letters");
    }
    if(!has_digit){
        result.suggestions.push_back("Add numbers");
    }
    if(!has_special){
        result.suggestions.push_back("Add special characters (!@#$%^&*)");
    }

    // Rating
    if(result.score < 30) result.rating = "Weak";
    else if(result.score < 50) result.rating = "Fair";
    else if(result.score < 70) result.rating = "Good";
    else if(result.score < 90) result.rating = "Strong";
    else result.rating = "Very Strong";

    return result;
}

// =============================================================================
// SECURE MEMORY OPERATIONS
// =============================================================================

// Securely wipe memory
static void secure_wipe(void* ptr, size_t len){
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while(len--){
        *p++ = 0;
    }
}

// Secure string that wipes on destruction
class SecureString {
public:
    SecureString() = default;
    SecureString(const std::string& s) : data_(s) {}
    ~SecureString() { wipe(); }

    void wipe(){
        if(!data_.empty()){
            secure_wipe(&data_[0], data_.size());
            data_.clear();
        }
    }

    const std::string& str() const { return data_; }
    std::string& str() { return data_; }
    bool empty() const { return data_.empty(); }
    size_t length() const { return data_.length(); }

private:
    std::string data_;
};

// =============================================================================
// NETWORK DIAGNOSTICS
// =============================================================================

struct NetworkDiagnostics {
    bool node_reachable{false};
    int latency_ms{-1};
    uint32_t node_height{0};
    uint32_t our_height{0};
    int peer_count{0};
    std::string node_version;
    std::string network_name;
    int64_t last_block_time{0};
    double sync_progress{0.0};
    std::vector<std::string> errors;

    // Extended diagnostics for multi-node testing
    int64_t timestamp{0};
    int successful_connections{0};
    int failed_connections{0};
    std::vector<int> latency_samples;
    int avg_latency_ms{0};
};

static std::string diagnostics_file_path(const std::string& wdir){
    return join_path(wdir, "network_diagnostics.log");
}

static void save_diagnostics(const std::string& wdir, const NetworkDiagnostics& diag){
    std::ofstream f(diagnostics_file_path(wdir), std::ios::app);
    if(!f.good()) return;

    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", tm_info);

    f << "[" << buf << "] "
      << "reachable=" << (diag.node_reachable ? "yes" : "no")
      << " latency=" << diag.latency_ms << "ms"
      << " height=" << diag.node_height
      << " peers=" << diag.peer_count
      << "\n";
}

// =============================================================================
// ADDRESS LABELS AND MANAGEMENT
// =============================================================================

struct LabeledAddress {
    std::string address;
    std::string label;
    std::string category;     // "personal", "business", "exchange", "other"
    int64_t created_at{0};
    int64_t last_used{0};
    uint64_t total_received{0};
    uint64_t total_sent{0};
    int tx_count{0};
    bool is_change{false};
    bool is_watch_only{false};
    std::string notes;
};

static std::string labeled_addresses_path(const std::string& wdir){
    return join_path(wdir, "labeled_addresses.dat");
}

[[maybe_unused]] static void save_labeled_addresses(const std::string& wdir,
                                    const std::vector<LabeledAddress>& addrs){
    std::ofstream f(labeled_addresses_path(wdir), std::ios::out | std::ios::trunc);
    if(!f.good()) return;

    f << "# MIQ Wallet Labeled Addresses\n";
    f << "# Format: address|label|category|created|last_used|received|sent|tx_count|is_change|watch_only|notes\n";

    for(const auto& a : addrs){
        f << a.address << "|"
          << a.label << "|"
          << a.category << "|"
          << a.created_at << "|"
          << a.last_used << "|"
          << a.total_received << "|"
          << a.total_sent << "|"
          << a.tx_count << "|"
          << (a.is_change ? "1" : "0") << "|"
          << (a.is_watch_only ? "1" : "0") << "|"
          << a.notes << "\n";
    }
}

[[maybe_unused]] static void load_labeled_addresses(const std::string& wdir,
                                    std::vector<LabeledAddress>& out){
    out.clear();
    std::ifstream f(labeled_addresses_path(wdir));
    if(!f.good()) return;

    std::string line;
    while(std::getline(f, line)){
        if(line.empty() || line[0] == '#') continue;

        std::vector<std::string> parts;
        std::istringstream ss(line);
        std::string part;
        while(std::getline(ss, part, '|')){
            parts.push_back(part);
        }

        if(parts.size() >= 11){
            LabeledAddress a;
            a.address = parts[0];
            a.label = parts[1];
            a.category = parts[2];
            a.created_at = std::strtoll(parts[3].c_str(), nullptr, 10);
            a.last_used = std::strtoll(parts[4].c_str(), nullptr, 10);
            a.total_received = std::strtoull(parts[5].c_str(), nullptr, 10);
            a.total_sent = std::strtoull(parts[6].c_str(), nullptr, 10);
            a.tx_count = std::atoi(parts[7].c_str());
            a.is_change = (parts[8] == "1");
            a.is_watch_only = (parts[9] == "1");
            a.notes = parts[10];
            out.push_back(a);
        }
    }
}

// =============================================================================
// TRANSACTION MEMO/NOTES SYSTEM
// =============================================================================

struct TransactionMemo {
    std::string txid_hex;
    std::string memo;
    std::string category;    // "payment", "salary", "gift", "purchase", "other"
    std::vector<std::string> tags;
    int64_t created_at{0};
};

static std::string memos_file_path(const std::string& wdir){
    return join_path(wdir, "transaction_memos.dat");
}

[[maybe_unused]] static void save_transaction_memo(const std::string& wdir, const TransactionMemo& memo){
    std::ofstream f(memos_file_path(wdir), std::ios::app);
    if(!f.good()) return;

    std::string tags_str;
    for(size_t i = 0; i < memo.tags.size(); ++i){
        if(i > 0) tags_str += ",";
        tags_str += memo.tags[i];
    }

    f << memo.txid_hex << "|"
      << memo.memo << "|"
      << memo.category << "|"
      << tags_str << "|"
      << memo.created_at << "\n";
}

[[maybe_unused]] static void load_transaction_memos(const std::string& wdir,
                                    std::unordered_map<std::string, TransactionMemo>& out){
    out.clear();
    std::ifstream f(memos_file_path(wdir));
    if(!f.good()) return;

    std::string line;
    while(std::getline(f, line)){
        if(line.empty()) continue;

        std::vector<std::string> parts;
        std::istringstream ss(line);
        std::string part;
        while(std::getline(ss, part, '|')){
            parts.push_back(part);
        }

        if(parts.size() >= 5){
            TransactionMemo m;
            m.txid_hex = parts[0];
            m.memo = parts[1];
            m.category = parts[2];

            // Parse tags
            std::istringstream tag_ss(parts[3]);
            std::string tag;
            while(std::getline(tag_ss, tag, ',')){
                if(!tag.empty()) m.tags.push_back(tag);
            }

            m.created_at = std::strtoll(parts[4].c_str(), nullptr, 10);
            out[m.txid_hex] = m;
        }
    }
}

// =============================================================================
// EXPORT/IMPORT FUNCTIONALITY
// =============================================================================

// Export format types
enum class ExportFormat {
    CSV,
    JSON,
    TXT
};

// Note: export_transactions_csv and export_transactions_json are defined after TxHistoryEntry struct

static bool export_to_file(const std::string& filepath, const std::string& content,
                           std::string& error){
    std::ofstream f(filepath, std::ios::out | std::ios::trunc);
    if(!f.good()){
        error = "Cannot create file: " + filepath;
        return false;
    }
    f << content;
    f.close();
    return true;
}

// =============================================================================
// QR CODE DISPLAY (ASCII Art)
// =============================================================================

// Simple QR code representation using ASCII
// Note: This is a visual representation, not actual QR encoding
[[maybe_unused]] static void display_address_visual(const std::string& address){
    std::cout << "\n";
    std::cout << "  " << ui::dim() << "Address:" << ui::reset() << "\n";
    std::cout << "  " << ui::cyan() << ui::bold() << address << ui::reset() << "\n\n";

    // Create a visual box around the address for easy copying
    int len = (int)address.length();
    std::cout << "  +" << std::string(len + 2, '-') << "+\n";
    std::cout << "  | " << address << " |\n";
    std::cout << "  +" << std::string(len + 2, '-') << "+\n\n";

    std::cout << "  " << ui::dim() << "Scan or copy the address above" << ui::reset() << "\n";
}

// =============================================================================
// CHANGE OPTIMIZATION
// =============================================================================

struct ChangeOptimizationResult {
    uint64_t change_amount{0};
    bool should_create_change{false};
    bool is_exact_match{false};
    uint64_t dust_absorbed{0};  // Small amounts absorbed into fee
    std::string recommendation;
};

static ChangeOptimizationResult optimize_change(uint64_t total_input, uint64_t amount,
                                                  uint64_t fee, uint64_t dust_threshold = 546){
    ChangeOptimizationResult result;

    if(total_input < amount + fee){
        result.recommendation = "Insufficient funds";
        return result;
    }

    uint64_t excess = total_input - amount - fee;

    if(excess == 0){
        result.is_exact_match = true;
        result.recommendation = "Exact match - no change needed";
    } else if(excess < dust_threshold){
        result.dust_absorbed = excess;
        result.recommendation = "Small excess (" + std::to_string(excess) +
                               " sat) added to fee to avoid dust";
    } else {
        result.should_create_change = true;
        result.change_amount = excess;
        result.recommendation = "Change of " + ui_pro::format_miq_professional(excess) +
                               " MIQ will be returned";
    }

    return result;
}

// =============================================================================
// FEE OPTIMIZATION AND ESTIMATION
// =============================================================================

struct FeeRecommendation {
    uint64_t economy_rate{1};       // sat/byte
    uint64_t normal_rate{2};
    uint64_t priority_rate{5};
    uint64_t urgent_rate{10};
    int64_t estimated_time_economy{3600};    // seconds
    int64_t estimated_time_normal{1200};
    int64_t estimated_time_priority{600};
    int64_t estimated_time_urgent{180};
    std::string network_status;
};

[[maybe_unused]] static FeeRecommendation get_fee_recommendation(){
    // In a full implementation, this would query mempool status
    FeeRecommendation rec;
    rec.network_status = "Normal";
    return rec;
}

[[maybe_unused]] static std::string format_time_estimate(int64_t seconds){
    if(seconds < 60) return std::to_string(seconds) + " seconds";
    if(seconds < 3600) return std::to_string(seconds / 60) + " minutes";
    return std::to_string(seconds / 3600) + " hours";
}

// =============================================================================
// TRANSACTION BUILDER - Professional Transaction Construction
// =============================================================================

struct TransactionPlan {
    std::vector<size_t> input_indices;
    uint64_t total_input{0};
    uint64_t amount{0};
    uint64_t fee{0};
    uint64_t change{0};
    bool has_change{false};
    std::string change_address;
    std::string to_address;
    std::string memo;
    int priority{1};
    std::string error;
    bool valid{false};
};

[[maybe_unused]] static TransactionPlan plan_transaction(
    const std::vector<miq::UtxoLite>& utxos,
    const std::set<OutpointKey>& pending,
    uint64_t amount,
    uint64_t fee_rate,
    const std::string& to_address,
    const std::string& change_address,
    uint32_t tip_height)
{
    TransactionPlan plan;
    plan.amount = amount;
    plan.to_address = to_address;
    plan.change_address = change_address;

    // Filter spendable UTXOs
    std::vector<std::pair<size_t, uint64_t>> spendable;
    for(size_t i = 0; i < utxos.size(); ++i){
        const auto& u = utxos[i];

        // Skip immature coinbase
        if(u.coinbase){
            uint64_t mature_h = (uint64_t)u.height + 100ULL;
            if(tip_height + 1 < mature_h) continue;
        }

        // Skip pending
        OutpointKey k{ miq::to_hex(u.txid), u.vout };
        if(pending.find(k) != pending.end()) continue;

        spendable.push_back({i, u.value});
    }

    if(spendable.empty()){
        plan.error = "No spendable UTXOs available";
        return plan;
    }

    // Sort by value descending for greedy selection
    std::sort(spendable.begin(), spendable.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    // Greedy selection
    plan.total_input = 0;
    for(const auto& [idx, value] : spendable){
        plan.input_indices.push_back(idx);
        plan.total_input += value;

        // Estimate fee with current inputs
        size_t est_size = 10 + plan.input_indices.size() * 148 + 2 * 34;
        plan.fee = est_size * fee_rate;

        if(plan.total_input >= amount + plan.fee){
            break;
        }
    }

    if(plan.total_input < amount + plan.fee){
        plan.error = "Insufficient funds. Need " +
                     ui_pro::format_miq_professional(amount + plan.fee) +
                     " MIQ but only have " +
                     ui_pro::format_miq_professional(plan.total_input) + " MIQ";
        return plan;
    }

    // Calculate change
    uint64_t excess = plan.total_input - amount - plan.fee;
    if(excess >= 546){  // Dust threshold
        plan.has_change = true;
        plan.change = excess;
    } else {
        // Add to fee
        plan.fee += excess;
    }

    plan.valid = true;
    return plan;
}

// =============================================================================
// BATCH TRANSACTION SUPPORT
// =============================================================================

struct BatchOutput {
    std::string address;
    uint64_t amount{0};
    std::string label;
};

struct BatchTransactionPlan {
    std::vector<size_t> input_indices;
    std::vector<BatchOutput> outputs;
    uint64_t total_input{0};
    uint64_t total_output{0};
    uint64_t fee{0};
    uint64_t change{0};
    bool has_change{false};
    std::string change_address;
    std::string error;
    bool valid{false};
};

[[maybe_unused]] static BatchTransactionPlan plan_batch_transaction(
    const std::vector<miq::UtxoLite>& utxos,
    const std::set<OutpointKey>& pending,
    const std::vector<BatchOutput>& outputs,
    uint64_t fee_rate,
    const std::string& change_address,
    uint32_t tip_height)
{
    BatchTransactionPlan plan;
    plan.outputs = outputs;
    plan.change_address = change_address;

    // Calculate total output
    for(const auto& out : outputs){
        plan.total_output += out.amount;
    }

    // Filter spendable UTXOs
    std::vector<std::pair<size_t, uint64_t>> spendable;
    for(size_t i = 0; i < utxos.size(); ++i){
        const auto& u = utxos[i];
        if(u.coinbase && tip_height + 1 < u.height + 100) continue;
        OutpointKey k{ miq::to_hex(u.txid), u.vout };
        if(pending.find(k) != pending.end()) continue;
        spendable.push_back({i, u.value});
    }

    std::sort(spendable.begin(), spendable.end(),
              [](const auto& a, const auto& b){ return a.second > b.second; });

    // Select inputs
    for(const auto& [idx, value] : spendable){
        plan.input_indices.push_back(idx);
        plan.total_input += value;

        size_t num_outputs = outputs.size() + 1;  // +1 for potential change
        size_t est_size = 10 + plan.input_indices.size() * 148 + num_outputs * 34;
        plan.fee = est_size * fee_rate;

        if(plan.total_input >= plan.total_output + plan.fee){
            break;
        }
    }

    if(plan.total_input < plan.total_output + plan.fee){
        plan.error = "Insufficient funds for batch transaction";
        return plan;
    }

    uint64_t excess = plan.total_input - plan.total_output - plan.fee;
    if(excess >= 546){
        plan.has_change = true;
        plan.change = excess;
    } else {
        plan.fee += excess;
    }

    plan.valid = true;
    return plan;
}

// =============================================================================
// WALLET HEALTH CHECK
// =============================================================================

struct WalletHealth {
    bool is_healthy{true};
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    int utxo_count{0};
    int dust_utxo_count{0};
    uint64_t total_balance{0};
    uint64_t dust_amount{0};
    bool needs_consolidation{false};
    bool has_pending_txs{false};
    int pending_tx_count{0};
    double fragmentation_score{0.0};  // 0-100, higher = more fragmented

    // Extended health metrics
    int health_score{100};           // Overall health score 0-100
    uint64_t largest_utxo{0};
    uint64_t smallest_utxo{UINT64_MAX};
    int dust_count{0};
    int pending_count{0};
    std::vector<std::string> issues;
    std::vector<std::string> recommendations;
};

static WalletHealth check_wallet_health(
    const std::vector<miq::UtxoLite>& utxos,
    const std::set<OutpointKey>& pending,
    uint64_t dust_threshold = 10000)
{
    WalletHealth health;
    health.utxo_count = (int)utxos.size();
    health.pending_tx_count = (int)pending.size();
    health.pending_count = (int)pending.size();
    health.has_pending_txs = !pending.empty();

    for(const auto& u : utxos){
        health.total_balance += u.value;

        // Track largest/smallest
        if(u.value > health.largest_utxo) health.largest_utxo = u.value;
        if(u.value < health.smallest_utxo) health.smallest_utxo = u.value;

        if(u.value < dust_threshold){
            health.dust_utxo_count++;
            health.dust_count++;
            health.dust_amount += u.value;
        }
    }

    // Reset smallest if no UTXOs
    if(utxos.empty()) health.smallest_utxo = 0;

    // Check for issues and build recommendations
    if(health.utxo_count > 100){
        health.warnings.push_back("High UTXO count (" + std::to_string(health.utxo_count) +
                                   ") - consider consolidation");
        health.issues.push_back("High UTXO fragmentation");
        health.recommendations.push_back("Consolidate UTXOs to reduce transaction fees");
        health.needs_consolidation = true;
        health.health_score -= 15;
    }

    if(health.dust_utxo_count > 10){
        health.warnings.push_back("Many dust UTXOs (" + std::to_string(health.dust_utxo_count) +
                                   ") - wasting fees");
        health.issues.push_back("Excessive dust UTXOs");
        health.recommendations.push_back("Consider sweeping dust to a single UTXO");
        health.health_score -= 10;
    }

    if(health.pending_tx_count > 5){
        health.warnings.push_back("Multiple pending transactions (" +
                                   std::to_string(health.pending_tx_count) + ")");
        health.issues.push_back("Many unconfirmed transactions");
        health.recommendations.push_back("Wait for confirmations before sending more");
        health.health_score -= 10;
    }

    // Calculate fragmentation score
    if(health.utxo_count > 0 && health.total_balance > 0){
        health.fragmentation_score = std::min(100.0,
            (double)health.utxo_count / 10.0 * 10.0 +
            (double)health.dust_utxo_count / (double)health.utxo_count * 50.0);

        // Adjust health score based on fragmentation
        if(health.fragmentation_score > 50) health.health_score -= 5;
        if(health.fragmentation_score > 75) health.health_score -= 5;
    }

    // Ensure score stays in valid range
    health.health_score = std::max(0, std::min(100, health.health_score));

    health.is_healthy = health.errors.empty() && health.warnings.size() <= 1;
    return health;
}

// =============================================================================
// CONFIRMATION TRACKER
// =============================================================================

struct ConfirmationStatus {
    std::string txid_hex;
    uint32_t confirmations{0};
    uint32_t target_confirmations{6};
    bool confirmed{false};
    int64_t first_seen{0};
    int64_t confirmed_at{0};
    std::string status_message;
};

static std::string confirmations_file_path(const std::string& wdir){
    return join_path(wdir, "confirmation_tracker.dat");
}

[[maybe_unused]] static void save_confirmation_status(const std::string& wdir,
                                      const ConfirmationStatus& status){
    std::ofstream f(confirmations_file_path(wdir), std::ios::app);
    if(!f.good()) return;

    f << status.txid_hex << "|"
      << status.confirmations << "|"
      << status.target_confirmations << "|"
      << (status.confirmed ? "1" : "0") << "|"
      << status.first_seen << "|"
      << status.confirmed_at << "\n";
}

// =============================================================================
// INPUT VALIDATION UTILITIES
// =============================================================================

[[maybe_unused]] static bool is_valid_amount_string(const std::string& s){
    if(s.empty()) return false;

    bool has_dot = false;
    int decimal_places = 0;
    bool after_dot = false;

    for(size_t i = 0; i < s.length(); ++i){
        char c = s[i];
        if(c == '.'){
            if(has_dot) return false;  // Multiple dots
            has_dot = true;
            after_dot = true;
        } else if(std::isdigit(c)){
            if(after_dot) decimal_places++;
        } else {
            return false;  // Invalid character
        }
    }

    if(decimal_places > 8) return false;  // Too many decimal places
    return true;
}

[[maybe_unused]] static bool is_valid_fee_rate(uint64_t rate){
    return rate >= 1 && rate <= 1000;  // 1-1000 sat/byte
}

// =============================================================================
// DISPLAY UTILITIES
// =============================================================================

// Note: display_balance_breakdown is defined after WalletBalance struct

[[maybe_unused]] static void display_utxo_summary(const std::vector<miq::UtxoLite>& utxos){
    if(utxos.empty()){
        std::cout << "  " << ui::dim() << "No UTXOs found" << ui::reset() << "\n";
        return;
    }

    uint64_t total = 0;
    uint64_t min_val = UINT64_MAX;
    uint64_t max_val = 0;
    int dust_count = 0;

    for(const auto& u : utxos){
        total += u.value;
        min_val = std::min(min_val, u.value);
        max_val = std::max(max_val, u.value);
        if(u.value < 10000) dust_count++;
    }

    double avg_val = (double)total / utxos.size();

    std::cout << "\n";
    ui_pro::print_kv("UTXO Count:", std::to_string(utxos.size()));
    ui_pro::print_kv("Total Value:", ui_pro::format_miq_professional(total) + " MIQ");
    ui_pro::print_kv("Average:", ui_pro::format_miq_professional((uint64_t)avg_val) + " MIQ");
    ui_pro::print_kv("Smallest:", ui_pro::format_miq_professional(min_val) + " MIQ");
    ui_pro::print_kv("Largest:", ui_pro::format_miq_professional(max_val) + " MIQ");
    if(dust_count > 0){
        ui_pro::print_kv("Dust UTXOs:", std::to_string(dust_count), 20, ui::yellow());
    }
    std::cout << "\n";
}

[[maybe_unused]] static void display_transaction_confirmation(const std::string& txid, uint64_t amount,
                                              uint64_t fee, const std::string& to_addr){
    std::cout << "\n";
    ui::print_header("CONFIRM TRANSACTION", 55);
    std::cout << "\n";

    ui_pro::print_kv("To:", to_addr.substr(0, 34));
    ui_pro::print_kv("Amount:", ui_pro::format_miq_professional(amount) + " MIQ", 20, ui::cyan());
    ui_pro::print_kv("Fee:", ui_pro::format_miq_professional(fee) + " MIQ", 20, ui::yellow());
    ui_pro::print_kv("Total:", ui_pro::format_miq_professional(amount + fee) + " MIQ", 20, ui::bold());

    std::cout << "\n  " << ui::dim() << "TXID: " << txid.substr(0, 32) << "..." << ui::reset() << "\n";
    std::cout << "\n";
}

// =============================================================================
// ERROR RECOVERY
// =============================================================================

[[maybe_unused]] static void handle_network_error(const std::string& error, int attempt, int max_attempts){
    std::cout << "\n";
    ui::print_error("Network error: " + error);

    if(attempt < max_attempts){
        int delay = std::min(1000 * (1 << attempt), 30000);
        std::cout << "  " << ui::dim() << "Retrying in " << (delay / 1000)
                  << " seconds... (attempt " << (attempt + 1) << "/" << max_attempts << ")"
                  << ui::reset() << "\n";
        std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    } else {
        std::cout << "  " << ui::dim() << "Max retries reached. Please check:" << ui::reset() << "\n";
        std::cout << "    - Node is running and synced\n";
        std::cout << "    - Network connection is stable\n";
        std::cout << "    - Firewall allows P2P port\n";
        std::cout << "\n";
    }
}

// =============================================================================
// CONFIGURATION MANAGEMENT
// =============================================================================

struct WalletConfig {
    // Display settings
    bool show_fiat_equivalent{false};
    std::string fiat_currency{"USD"};
    int decimal_places{8};
    bool use_thousands_separator{true};

    // Security settings
    int session_timeout_minutes{15};
    bool require_password_for_send{true};
    int max_failed_attempts{5};
    bool auto_lock{true};

    // Network settings
    int connection_timeout_ms{15000};
    int max_retries{5};
    std::string preferred_node;

    // Transaction settings
    int default_fee_priority{1};
    bool enable_rbf{false};
    uint64_t dust_threshold{546};
    int min_confirmations{1};

    // UI settings
    bool show_animations{true};
    bool verbose_mode{false};
    std::string language{"en"};
};

static std::string config_file_path(const std::string& wdir){
    return join_path(wdir, "wallet_config.dat");
}

[[maybe_unused]] static void save_wallet_config(const std::string& wdir, const WalletConfig& cfg){
    std::ofstream f(config_file_path(wdir), std::ios::out | std::ios::trunc);
    if(!f.good()) return;

    f << "# MIQ Wallet Configuration\n";
    f << "session_timeout=" << cfg.session_timeout_minutes << "\n";
    f << "require_password=" << (cfg.require_password_for_send ? "1" : "0") << "\n";
    f << "max_failed_attempts=" << cfg.max_failed_attempts << "\n";
    f << "connection_timeout=" << cfg.connection_timeout_ms << "\n";
    f << "max_retries=" << cfg.max_retries << "\n";
    f << "default_fee_priority=" << cfg.default_fee_priority << "\n";
    f << "dust_threshold=" << cfg.dust_threshold << "\n";
    f << "min_confirmations=" << cfg.min_confirmations << "\n";
    f << "show_animations=" << (cfg.show_animations ? "1" : "0") << "\n";
    f << "verbose_mode=" << (cfg.verbose_mode ? "1" : "0") << "\n";
}

[[maybe_unused]] static void load_wallet_config(const std::string& wdir, WalletConfig& cfg){
    std::ifstream f(config_file_path(wdir));
    if(!f.good()) return;

    std::string line;
    while(std::getline(f, line)){
        if(line.empty() || line[0] == '#') continue;
        size_t eq = line.find('=');
        if(eq == std::string::npos) continue;

        std::string key = line.substr(0, eq);
        std::string val = line.substr(eq + 1);

        if(key == "session_timeout") cfg.session_timeout_minutes = std::atoi(val.c_str());
        else if(key == "require_password") cfg.require_password_for_send = (val == "1");
        else if(key == "max_failed_attempts") cfg.max_failed_attempts = std::atoi(val.c_str());
        else if(key == "connection_timeout") cfg.connection_timeout_ms = std::atoi(val.c_str());
        else if(key == "max_retries") cfg.max_retries = std::atoi(val.c_str());
        else if(key == "default_fee_priority") cfg.default_fee_priority = std::atoi(val.c_str());
        else if(key == "dust_threshold") cfg.dust_threshold = std::strtoull(val.c_str(), nullptr, 10);
        else if(key == "min_confirmations") cfg.min_confirmations = std::atoi(val.c_str());
        else if(key == "show_animations") cfg.show_animations = (val == "1");
        else if(key == "verbose_mode") cfg.verbose_mode = (val == "1");
    }
}

// =============================================================================
// AUDIT LOG - Complete Transaction Audit Trail
// =============================================================================

struct AuditEntry {
    int64_t timestamp{0};
    std::string action;      // "send", "receive", "generate_address", "backup", etc.
    std::string details;
    std::string txid_hex;
    uint64_t amount{0};
    std::string result;      // "success", "failed", "cancelled"
    std::string ip_address;  // Node connected to
};

static std::string audit_log_path(const std::string& wdir){
    return join_path(wdir, "audit_log.dat");
}

[[maybe_unused]] static void append_audit_log(const std::string& wdir, const AuditEntry& entry){
    std::ofstream f(audit_log_path(wdir), std::ios::app);
    if(!f.good()) return;

    f << entry.timestamp << "|"
      << entry.action << "|"
      << entry.details << "|"
      << entry.txid_hex << "|"
      << entry.amount << "|"
      << entry.result << "|"
      << entry.ip_address << "\n";
}

// =============================================================================
// PERFORMANCE METRICS
// =============================================================================

struct PerformanceMetrics {
    int64_t sync_start_time{0};
    int64_t sync_end_time{0};
    int blocks_scanned{0};
    int utxos_found{0};
    size_t bytes_downloaded{0};
    double sync_speed{0.0};  // blocks per second
};

static std::string metrics_file_path(const std::string& wdir){
    return join_path(wdir, "performance_metrics.log");
}

[[maybe_unused]] static void log_performance_metrics(const std::string& wdir, const PerformanceMetrics& metrics){
    std::ofstream f(metrics_file_path(wdir), std::ios::app);
    if(!f.good()) return;

    int64_t duration = metrics.sync_end_time - metrics.sync_start_time;
    double speed = duration > 0 ? (double)metrics.blocks_scanned / duration : 0;

    time_t now = time(nullptr);
    f << now << "|"
      << metrics.blocks_scanned << "|"
      << metrics.utxos_found << "|"
      << metrics.bytes_downloaded << "|"
      << duration << "|"
      << speed << "\n";
}

// =============================================================================
// END OF PROFESSIONAL WALLET UPGRADE v1.0
// =============================================================================

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

// Forward declaration for pending management functions (defined after QueuedTransaction)
static bool remove_inputs_from_pending(const std::string& wdir,
                                        const std::vector<uint8_t>& raw_tx,
                                        std::set<OutpointKey>& pending);

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

// Export functions that use TxHistoryEntry
static std::string export_transactions_csv(const std::vector<TxHistoryEntry>& history){
    std::ostringstream oss;
    oss << "TXID,Timestamp,Direction,Amount,Fee,To Address,Confirmations\n";

    for(const auto& tx : history){
        oss << tx.txid_hex << ","
            << tx.timestamp << ","
            << tx.direction << ","
            << tx.amount << ","
            << tx.fee << ","
            << tx.to_address << ","
            << tx.confirmations << "\n";
    }

    return oss.str();
}

static std::string export_transactions_json(const std::vector<TxHistoryEntry>& history){
    std::ostringstream oss;
    oss << "{\n  \"transactions\": [\n";

    for(size_t i = 0; i < history.size(); ++i){
        const auto& tx = history[i];
        oss << "    {\n"
            << "      \"txid\": \"" << tx.txid_hex << "\",\n"
            << "      \"timestamp\": " << tx.timestamp << ",\n"
            << "      \"direction\": \"" << tx.direction << "\",\n"
            << "      \"amount\": " << tx.amount << ",\n"
            << "      \"fee\": " << tx.fee << ",\n"
            << "      \"to_address\": \"" << tx.to_address << "\",\n"
            << "      \"confirmations\": " << tx.confirmations << "\n"
            << "    }";
        if(i < history.size() - 1) oss << ",";
        oss << "\n";
    }

    oss << "  ]\n}\n";
    return oss.str();
}

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
        if(now - q.created_at < expiry_seconds || q.status == "confirmed" || q.status == "broadcast"){
            filtered.push_back(q);
        }
    }

    // Limit queue size
    if(filtered.size() > wallet_config::MAX_QUEUE_SIZE){
        filtered.erase(filtered.begin(), filtered.begin() + (filtered.size() - wallet_config::MAX_QUEUE_SIZE));
    }

    save_tx_queue(wdir, filtered);
}

[[maybe_unused]] static void update_tx_queue_status(const std::string& wdir, const std::string& txid_hex,
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
// CRITICAL BUG FIX: Remove inputs from pending when transactions fail/expire
// =============================================================================

// Remove pending entries for all inputs in a raw transaction
static bool remove_inputs_from_pending(const std::string& wdir,
                                        const std::vector<uint8_t>& raw_tx,
                                        std::set<OutpointKey>& pending) {
    // Deserialize transaction to get inputs
    miq::Transaction tx;
    if (!miq::deser_tx(raw_tx, tx)) {
        return false;  // Could not deserialize
    }

    bool removed_any = false;
    for (const auto& in : tx.vin) {
        OutpointKey k{ miq::to_hex(in.prev.txid), in.prev.vout };
        auto it = pending.find(k);
        if (it != pending.end()) {
            pending.erase(it);
            removed_any = true;
        }
    }

    if (removed_any) {
        save_pending(wdir, pending);
    }

    return removed_any;
}

// Remove pending entries for a transaction by TXID (looks up in queue)
[[maybe_unused]] static bool remove_tx_inputs_from_pending_by_txid(const std::string& wdir,
                                                   const std::string& txid_hex,
                                                   std::set<OutpointKey>& pending) {
    // Load queue to find the transaction
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    for (const auto& qtx : queue) {
        if (qtx.txid_hex == txid_hex && !qtx.raw_tx.empty()) {
            return remove_inputs_from_pending(wdir, qtx.raw_tx, pending);
        }
    }
    return false;
}

// Clean up all failed/expired transactions from pending set
[[maybe_unused]] static int cleanup_failed_tx_pending(const std::string& wdir,
                                      std::set<OutpointKey>& pending) {
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    int cleaned = 0;
    for (const auto& tx : queue) {
        if ((tx.status == "failed" || tx.status == "expired") && !tx.raw_tx.empty()) {
            if (remove_inputs_from_pending(wdir, tx.raw_tx, pending)) {
                cleaned++;
            }
        }
    }
    return cleaned;
}

// Cancel a pending transaction and release its inputs
[[maybe_unused]] static bool cancel_pending_transaction(const std::string& wdir,
                                        const std::string& txid_hex,
                                        std::set<OutpointKey>& pending,
                                        std::string& error) {
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    // Find and remove the transaction
    bool found = false;
    std::vector<uint8_t> raw_tx;
    std::vector<QueuedTransaction> new_queue;

    for (auto& tx : queue) {
        if (tx.txid_hex == txid_hex) {
            found = true;
            raw_tx = tx.raw_tx;

            // Can only cancel if not already confirmed/broadcast
            if (tx.status == "confirmed" || tx.status == "broadcast") {
                error = "Cannot cancel transaction that was already broadcast to network";
                return false;
            }
            // Don't add to new queue - effectively removes it
        } else {
            new_queue.push_back(tx);
        }
    }

    if (!found) {
        error = "Transaction not found in queue";
        return false;
    }

    // Remove inputs from pending
    if (!raw_tx.empty()) {
        remove_inputs_from_pending(wdir, raw_tx, pending);
    }

    // Save updated queue
    save_tx_queue(wdir, new_queue);

    return true;
}

// Force release all pending UTXOs (emergency recovery)
[[maybe_unused]] static int force_release_all_pending(const std::string& wdir,
                                      std::set<OutpointKey>& pending) {
    int count = (int)pending.size();
    pending.clear();
    save_pending(wdir, pending);
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
// PROFESSIONAL TRANSACTION HISTORY v1.0 - Live History & Details
// =============================================================================

// Enhanced transaction entry with complete details
struct TxDetailedEntry {
    std::string txid_hex;
    int64_t timestamp{0};
    int64_t amount{0};
    uint64_t fee{0};
    uint32_t confirmations{0};
    std::string direction;
    std::string to_address;
    std::string from_address;
    std::string memo;
    std::string category;
    uint32_t block_height{0};
    size_t tx_size{0};
    double fee_rate{0.0};
    std::string status;
};

// Transaction history filter options
struct TxHistoryFilter {
    std::string direction;
    std::string status;
    int64_t date_from{0};
    int64_t date_to{0};
    uint64_t amount_min{0};
    uint64_t amount_max{UINT64_MAX};
    std::string search;
};

// Transaction history sort options
enum class TxSortOrder {
    DATE_DESC,
    DATE_ASC,
    AMOUNT_DESC,
    AMOUNT_ASC,
    CONFIRMATIONS
};

// History viewer state
struct TxHistoryViewState {
    int page{0};
    int per_page{12};
    int total_pages{0};
    int total_count{0};
    int selected{-1};
    TxSortOrder sort_order{TxSortOrder::DATE_DESC};
    TxHistoryFilter filter;
};

// Convert basic TxHistoryEntry to detailed entry
static TxDetailedEntry convert_to_detailed(const TxHistoryEntry& basic) {
    TxDetailedEntry detailed;
    detailed.txid_hex = basic.txid_hex;
    detailed.timestamp = basic.timestamp;
    detailed.amount = basic.amount;
    detailed.fee = basic.fee;
    detailed.confirmations = basic.confirmations;
    detailed.direction = basic.direction;
    detailed.to_address = basic.to_address;
    detailed.from_address = basic.from_address;
    detailed.memo = basic.memo;
    detailed.status = basic.confirmations > 0 ? "confirmed" : "pending";
    detailed.tx_size = 225;
    if (detailed.fee > 0) {
        detailed.fee_rate = (double)detailed.fee / detailed.tx_size;
    }
    return detailed;
}

// Filter transactions
static std::vector<TxDetailedEntry> filter_transactions(
    const std::vector<TxDetailedEntry>& all,
    const TxHistoryFilter& filter)
{
    std::vector<TxDetailedEntry> result;
    for (const auto& tx : all) {
        if (!filter.direction.empty() && tx.direction != filter.direction) continue;
        if (!filter.status.empty()) {
            if (filter.status == "confirmed" && tx.confirmations == 0) continue;
            if (filter.status == "pending" && tx.confirmations > 0) continue;
        }
        if (filter.date_from > 0 && tx.timestamp < filter.date_from) continue;
        if (filter.date_to > 0 && tx.timestamp > filter.date_to) continue;
        uint64_t abs_amount = tx.amount >= 0 ? (uint64_t)tx.amount : (uint64_t)(-tx.amount);
        if (abs_amount < filter.amount_min || abs_amount > filter.amount_max) continue;
        if (!filter.search.empty()) {
            std::string lower_search = filter.search;
            for (auto& c : lower_search) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            std::string lower_txid = tx.txid_hex;
            for (auto& c : lower_txid) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            bool found = (lower_txid.find(lower_search) != std::string::npos ||
                         tx.to_address.find(filter.search) != std::string::npos ||
                         tx.memo.find(filter.search) != std::string::npos);
            if (!found) continue;
        }
        result.push_back(tx);
    }
    return result;
}

// Sort transactions
static void sort_transactions(std::vector<TxDetailedEntry>& txs, TxSortOrder order) {
    switch (order) {
        case TxSortOrder::DATE_DESC:
            std::sort(txs.begin(), txs.end(), [](const auto& a, const auto& b) {
                return a.timestamp > b.timestamp;
            });
            break;
        case TxSortOrder::DATE_ASC:
            std::sort(txs.begin(), txs.end(), [](const auto& a, const auto& b) {
                return a.timestamp < b.timestamp;
            });
            break;
        case TxSortOrder::AMOUNT_DESC:
            std::sort(txs.begin(), txs.end(), [](const auto& a, const auto& b) {
                uint64_t aa = a.amount >= 0 ? (uint64_t)a.amount : (uint64_t)(-a.amount);
                uint64_t ba = b.amount >= 0 ? (uint64_t)b.amount : (uint64_t)(-b.amount);
                return aa > ba;
            });
            break;
        case TxSortOrder::AMOUNT_ASC:
            std::sort(txs.begin(), txs.end(), [](const auto& a, const auto& b) {
                uint64_t aa = a.amount >= 0 ? (uint64_t)a.amount : (uint64_t)(-a.amount);
                uint64_t ba = b.amount >= 0 ? (uint64_t)b.amount : (uint64_t)(-b.amount);
                return aa < ba;
            });
            break;
        case TxSortOrder::CONFIRMATIONS:
            std::sort(txs.begin(), txs.end(), [](const auto& a, const auto& b) {
                return a.confirmations < b.confirmations;
            });
            break;
    }
}

// Confirmation progress bar
static std::string confirmation_bar(uint32_t confirmations, int width = 6) {
    std::string bar;
    if (confirmations == 0) {
        bar = ui::yellow() + "[";
        for (int i = 0; i < width; i++) bar += ".";
        bar += "]" + ui::reset();
    } else if (confirmations >= 6) {
        bar = ui::green() + "[";
        for (int i = 0; i < width; i++) bar += "#";
        bar += "]" + ui::reset();
    } else {
        int filled = (int)(confirmations * width / 6);
        bar = ui::cyan() + "[";
        for (int i = 0; i < width; i++) {
            if (i < filled) bar += "#";
            else bar += ".";
        }
        bar += "]" + ui::reset();
    }
    return bar;
}

// Print single transaction row
static void print_tx_row(const TxDetailedEntry& tx, int index, bool selected,
                         const std::vector<AddressBookEntry>& address_book) {
    if (selected) {
        std::cout << ui::cyan() << " > " << ui::reset();
    } else {
        std::cout << "   ";
    }
    std::cout << ui::dim() << std::setw(3) << (index + 1) << ui::reset() << " ";
    if (tx.direction == "sent") {
        std::cout << ui::red() << "[-]" << ui::reset();
    } else if (tx.direction == "received") {
        std::cout << ui::green() << "[+]" << ui::reset();
    } else {
        std::cout << ui::yellow() << "[=]" << ui::reset();
    }
    std::cout << " " << ui::dim() << ui::format_time_short(tx.timestamp) << ui::reset();
    std::string amt_str;
    if (tx.amount >= 0) {
        amt_str = "+" + ui_pro::format_miq_professional((uint64_t)tx.amount);
        std::cout << " " << ui::green() << std::setw(16) << std::right << amt_str << ui::reset();
    } else {
        amt_str = "-" + ui_pro::format_miq_professional((uint64_t)(-tx.amount));
        std::cout << " " << ui::red() << std::setw(16) << std::right << amt_str << ui::reset();
    }
    std::cout << " " << confirmation_bar(tx.confirmations);
    std::string addr = tx.direction == "sent" ? tx.to_address : tx.from_address;
    std::string label;
    for (const auto& entry : address_book) {
        if (entry.address == addr) {
            label = entry.label;
            break;
        }
    }
    if (!label.empty()) {
        std::cout << " " << ui::cyan() << label << ui::reset();
    } else if (!addr.empty()) {
        std::cout << " " << ui::dim() << addr.substr(0, 12) << "..." << ui::reset();
    }
    if (!tx.memo.empty()) {
        std::cout << " " << ui::yellow() << "[M]" << ui::reset();
    }
    std::cout << "\n";
}

// Print detailed transaction view
static void print_tx_details_view(const TxDetailedEntry& tx,
                                   const std::vector<AddressBookEntry>& address_book) {
    std::cout << "\n";
    ui::print_double_header("TRANSACTION DETAILS", 70);
    std::cout << "\n";
    std::cout << "  " << ui::bold() << "Basic Information" << ui::reset() << "\n";
    std::cout << "  " << std::string(66, '-') << "\n";
    ui_pro::print_kv("Transaction ID:", tx.txid_hex, 18);
    ui_pro::print_kv("Status:", tx.confirmations > 0 ?
        (ui::green() + "Confirmed" + ui::reset()) :
        (ui::yellow() + "Pending" + ui::reset()), 18);
    ui_pro::print_kv("Direction:",
        tx.direction == "sent" ? (ui::red() + "Sent" + ui::reset()) :
        tx.direction == "received" ? (ui::green() + "Received" + ui::reset()) :
        (ui::yellow() + "Self" + ui::reset()), 18);
    ui_pro::print_kv("Date/Time:", ui::format_time(tx.timestamp), 18);
    ui_pro::print_kv("Time Ago:", ui::format_time_ago(tx.timestamp), 18);
    std::cout << "\n";
    std::cout << "  " << ui::bold() << "Amount Details" << ui::reset() << "\n";
    std::cout << "  " << std::string(66, '-') << "\n";
    if (tx.amount >= 0) {
        ui_pro::print_kv("Amount:", ui::green() + "+" + ui_pro::format_miq_professional((uint64_t)tx.amount) + " MIQ" + ui::reset(), 18);
    } else {
        ui_pro::print_kv("Amount:", ui::red() + "-" + ui_pro::format_miq_professional((uint64_t)(-tx.amount)) + " MIQ" + ui::reset(), 18);
    }
    ui_pro::print_kv("Fee:", ui_pro::format_miq_professional(tx.fee) + " MIQ", 18);
    if (tx.fee_rate > 0) {
        std::ostringstream fee_rate_ss;
        fee_rate_ss << std::fixed << std::setprecision(2) << tx.fee_rate << " sat/byte";
        ui_pro::print_kv("Fee Rate:", fee_rate_ss.str(), 18);
    }
    std::cout << "\n";
    std::cout << "  " << ui::bold() << "Confirmation Status" << ui::reset() << "\n";
    std::cout << "  " << std::string(66, '-') << "\n";
    ui_pro::print_kv("Confirmations:", std::to_string(tx.confirmations), 18);
    std::cout << "  " << ui::dim() << std::setw(18) << std::left << "Progress:" << ui::reset();
    double conf_percent = tx.confirmations >= 6 ? 100.0 : (tx.confirmations * 100.0 / 6.0);
    std::cout << ui_pro::draw_progress_bar(conf_percent, 20) << " ";
    if (tx.confirmations >= 6) {
        std::cout << ui::green() << "CONFIRMED" << ui::reset();
    } else if (tx.confirmations > 0) {
        std::cout << ui::cyan() << tx.confirmations << "/6" << ui::reset();
    } else {
        std::cout << ui::yellow() << "PENDING" << ui::reset();
    }
    std::cout << "\n\n";
    std::cout << "  " << ui::bold() << "Addresses" << ui::reset() << "\n";
    std::cout << "  " << std::string(66, '-') << "\n";
    auto resolve_label = [&](const std::string& addr) -> std::string {
        for (const auto& entry : address_book) {
            if (entry.address == addr) return entry.label;
        }
        return "";
    };
    if (!tx.to_address.empty()) {
        std::string to_label = resolve_label(tx.to_address);
        if (!to_label.empty()) {
            ui_pro::print_kv("To:", ui::cyan() + to_label + ui::reset(), 18);
            std::cout << "  " << ui::dim() << std::setw(18) << "" << tx.to_address << ui::reset() << "\n";
        } else {
            ui_pro::print_kv("To:", tx.to_address, 18);
        }
    }
    if (!tx.from_address.empty()) {
        std::string from_label = resolve_label(tx.from_address);
        if (!from_label.empty()) {
            ui_pro::print_kv("From:", ui::cyan() + from_label + ui::reset(), 18);
            std::cout << "  " << ui::dim() << std::setw(18) << "" << tx.from_address << ui::reset() << "\n";
        } else {
            ui_pro::print_kv("From:", tx.from_address, 18);
        }
    }
    if (!tx.memo.empty()) {
        std::cout << "\n";
        std::cout << "  " << ui::bold() << "Memo" << ui::reset() << "\n";
        std::cout << "  " << std::string(66, '-') << "\n";
        std::cout << "  " << ui::yellow() << tx.memo << ui::reset() << "\n";
    }
    std::cout << "\n";
}

// Print transaction statistics
static void print_tx_statistics(const std::vector<TxDetailedEntry>& txs) {
    if (txs.empty()) return;
    uint64_t total_sent = 0, total_received = 0, total_fees = 0;
    int sent_count = 0, received_count = 0;
    for (const auto& tx : txs) {
        if (tx.amount < 0) {
            total_sent += (uint64_t)(-tx.amount);
            sent_count++;
        } else {
            total_received += (uint64_t)tx.amount;
            received_count++;
        }
        total_fees += tx.fee;
    }
    std::cout << "\n";
    ui::print_double_header("TRANSACTION STATISTICS", 60);
    std::cout << "\n";
    std::cout << "  " << ui::bold() << "Summary" << ui::reset() << "\n";
    std::cout << "  " << std::string(56, '-') << "\n";
    ui_pro::print_kv("Total Transactions:", std::to_string(txs.size()), 22);
    ui_pro::print_kv("Sent:", std::to_string(sent_count) + " tx", 22);
    ui_pro::print_kv("Received:", std::to_string(received_count) + " tx", 22);
    std::cout << "\n";
    std::cout << "  " << ui::bold() << "Amounts" << ui::reset() << "\n";
    std::cout << "  " << std::string(56, '-') << "\n";
    ui_pro::print_kv("Total Sent:", ui::red() + ui_pro::format_miq_professional(total_sent) + " MIQ" + ui::reset(), 22);
    ui_pro::print_kv("Total Received:", ui::green() + ui_pro::format_miq_professional(total_received) + " MIQ" + ui::reset(), 22);
    ui_pro::print_kv("Total Fees Paid:", ui_pro::format_miq_professional(total_fees) + " MIQ", 22);
    int64_t net = (int64_t)total_received - (int64_t)total_sent - (int64_t)total_fees;
    if (net >= 0) {
        ui_pro::print_kv("Net Change:", ui::green() + "+" + ui_pro::format_miq_professional((uint64_t)net) + " MIQ" + ui::reset(), 22);
    } else {
        ui_pro::print_kv("Net Change:", ui::red() + "-" + ui_pro::format_miq_professional((uint64_t)(-net)) + " MIQ" + ui::reset(), 22);
    }
    std::cout << "\n";
}

// =============================================================================
// FEE PRIORITY LABELS
// =============================================================================
[[maybe_unused]] static std::string fee_priority_label(int priority){
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
    const std::string& cache_dir,
    std::vector<miq::UtxoLite>& out,
    std::string& used_seed,
    std::string& err_out)
{
    // Clear output to prevent accumulation from previous failed attempts
    out.clear();

    for(const auto& [host, port] : seeds){
        std::string seed_str = host + ":" + port;
        ui::print_progress("Connecting to " + seed_str + "...");

        miq::SpvOptions opts;
        opts.recent_block_window = window;
        opts.cache_dir = cache_dir;  // CRITICAL: Set cache directory for proper UTXO caching

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
    std::set<OutpointKey>& pending,
    bool verbose = true)
{
    std::vector<QueuedTransaction> queue;
    load_tx_queue(wdir, queue);

    if(queue.empty()) return 0;

    int broadcasted = 0;
    int failed_or_expired = 0;
    int64_t now = (int64_t)time(nullptr);

    for(auto& tx : queue){
        // Skip if not queued or already too many attempts
        if(tx.status != "queued" && tx.status != "broadcasting") continue;

        if(tx.broadcast_attempts >= wallet_config::MAX_BROADCAST_ATTEMPTS){
            tx.status = "failed";
            tx.error_msg = "Max broadcast attempts exceeded";

            // CRITICAL FIX: Release inputs back to spendable pool
            if(!tx.raw_tx.empty()){
                remove_inputs_from_pending(wdir, tx.raw_tx, pending);
                failed_or_expired++;
                if(verbose){
                    ui::print_warning("TX " + tx.txid_hex.substr(0, 8) + "... failed - inputs released");
                }
            }
            continue;
        }

        // Check expiry
        int64_t age_hours = (now - tx.created_at) / 3600;
        if(age_hours >= wallet_config::TX_EXPIRY_HOURS){
            tx.status = "expired";
            tx.error_msg = "Transaction expired after " + std::to_string(wallet_config::TX_EXPIRY_HOURS) + " hours";

            // CRITICAL FIX: Release inputs back to spendable pool
            if(!tx.raw_tx.empty()){
                remove_inputs_from_pending(wdir, tx.raw_tx, pending);
                failed_or_expired++;
                if(verbose){
                    ui::print_warning("TX " + tx.txid_hex.substr(0, 8) + "... expired - inputs released");
                }
            }
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
            tx.status = "broadcast";  // Changed from "confirmed" - more accurate
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
[[maybe_unused]] static bool check_network_status(
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

// Display function that uses WalletBalance
[[maybe_unused]] static void display_balance_breakdown(const WalletBalance& wb){
    std::cout << "\n";
    ui::print_header("BALANCE BREAKDOWN", 50);
    std::cout << "\n";

    ui_pro::print_kv("Total Balance:",
                     ui_pro::format_miq_professional(wb.total) + " MIQ", 20, ui::green());
    ui_pro::print_kv("Spendable:",
                     ui_pro::format_miq_professional(wb.spendable) + " MIQ", 20, ui::cyan());

    if(wb.immature > 0){
        ui_pro::print_kv("Immature:",
                         ui_pro::format_miq_professional(wb.immature) + " MIQ", 20, ui::yellow());
        std::cout << "  " << ui::dim() << "(Mining rewards need 100 confirmations)" << ui::reset() << "\n";
    }

    if(wb.pending_hold > 0){
        ui_pro::print_kv("Pending:",
                         ui_pro::format_miq_professional(wb.pending_hold) + " MIQ", 20, ui::yellow());
        std::cout << "  " << ui::dim() << "(Awaiting confirmation)" << ui::reset() << "\n";
    }

    std::cout << "\n";
}

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

    // CRITICAL: Verify cache belongs to this wallet, clear if different wallet
    // This prevents using another wallet's cached UTXOs
    verify_cache_ownership(wdir, pkhs);

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

        if(!spv_collect_any_seed(seeds, pkhs, spv_win, wdir, utxos, used_seed, err)){
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

        // Deduplicate UTXOs to prevent counting issues
        {
            std::set<OutpointKey> seen;
            std::vector<miq::UtxoLite> deduped;
            deduped.reserve(utxos.size());
            for(const auto& u : utxos){
                OutpointKey k{ miq::to_hex(u.txid), u.vout };
                if(seen.find(k) == seen.end()){
                    seen.insert(k);
                    deduped.push_back(u);
                }
            }
            if(deduped.size() != utxos.size()){
                // Log deduplication for debugging
                ui::print_warning("Deduplicated " + std::to_string(utxos.size() - deduped.size()) + " duplicate UTXO(s)");
            }
            utxos = std::move(deduped);
        }

        // Prune pending entries that are no longer in current UTXOs (already spent/confirmed)
        {
            std::set<OutpointKey> cur;
            for(const auto& u : utxos) cur.insert(OutpointKey{ miq::to_hex(u.txid), u.vout });
            size_t before_prune = pending.size();
            for(auto it = pending.begin(); it != pending.end(); ){
                if(cur.find(*it) == cur.end()) it = pending.erase(it);
                else ++it;
            }
            if(pending.size() != before_prune){
                // Some pending transactions were confirmed
                size_t confirmed = before_prune - pending.size();
                if(confirmed > 0){
                    ui::print_info(std::to_string(confirmed) + " pending transaction(s) confirmed");
                }
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

            int broadcasted = process_tx_queue(wdir, seeds, pending, true);
            if(broadcasted > 0){
                std::cout << "\n";
                ui::print_success("Successfully broadcasted " + std::to_string(broadcasted) + " transaction(s)");
                // Refresh balance after cleanup
                utxos = refresh_and_print();
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

        // Professional Features
        std::cout << "\n" << ui::dim() << "  Professional:" << ui::reset() << "\n";
        ui::print_menu_item("8", "Export Transactions");
        ui::print_menu_item("9", "Wallet Health Check");
        ui::print_menu_item("0", "Settings & Backup");

        // System
        std::cout << "\n" << ui::dim() << "  System:" << ui::reset() << "\n";
        ui::print_menu_item("r", "Refresh Balance");
        ui::print_menu_item("b", "Broadcast Queue");
        ui::print_menu_item("d", "Network Diagnostics");
        ui::print_menu_item("h", "Help");
        ui::print_menu_item("q", "Back to Main Menu");
        std::cout << "\n";

        std::string c = ui::prompt("Select option: ");
        c = trim(c);

        // =================================================================
        // OPTION 4: Transaction History - Professional Viewer
        // =================================================================
        if(c == "4"){
            std::vector<TxHistoryEntry> history_raw;
            load_tx_history(wdir, history_raw);
            std::vector<AddressBookEntry> address_book;
            load_address_book(wdir, address_book);

            if(history_raw.empty()){
                std::cout << "\n";
                ui::print_double_header("TRANSACTION HISTORY", 60);
                std::cout << "\n";
                std::cout << "  " << ui::dim() << "No transactions yet." << ui::reset() << "\n";
                std::cout << "  " << ui::dim() << "Send or receive MIQ to see transaction history." << ui::reset() << "\n\n";
                continue;
            }

            // Convert to detailed entries
            std::vector<TxDetailedEntry> all_txs;
            for (const auto& raw : history_raw) {
                all_txs.push_back(convert_to_detailed(raw));
            }

            TxHistoryViewState view_state;
            bool history_running = true;

            while (history_running) {
                auto filtered = filter_transactions(all_txs, view_state.filter);
                sort_transactions(filtered, view_state.sort_order);

                view_state.total_count = (int)filtered.size();
                view_state.total_pages = (view_state.total_count + view_state.per_page - 1) / view_state.per_page;
                if (view_state.total_pages == 0) view_state.total_pages = 1;
                if (view_state.page >= view_state.total_pages) view_state.page = view_state.total_pages - 1;
                if (view_state.page < 0) view_state.page = 0;

                std::cout << "\n";
                ui::print_double_header("TRANSACTION HISTORY", 70);
                std::cout << "\n  " << ui::bold() << "Status: " << ui::reset()
                          << ui::cyan() << view_state.total_count << ui::reset() << " transactions";

                if (!view_state.filter.direction.empty()) {
                    std::cout << " | " << ui::yellow() << "Dir:" << view_state.filter.direction << ui::reset();
                }
                if (!view_state.filter.status.empty()) {
                    std::cout << " | " << ui::yellow() << "Status:" << view_state.filter.status << ui::reset();
                }
                if (!view_state.filter.search.empty()) {
                    std::cout << " | " << ui::yellow() << "Search:\"" << view_state.filter.search << "\"" << ui::reset();
                }
                std::cout << "\n";

                std::cout << "\n  " << ui::dim() << "     #   Dir  Date        Amount           Conf   Address" << ui::reset() << "\n";
                std::cout << "  " << std::string(68, '-') << "\n";

                int start_idx = view_state.page * view_state.per_page;
                int end_idx = std::min(start_idx + view_state.per_page, view_state.total_count);

                if (filtered.empty()) {
                    std::cout << "\n  " << ui::dim() << "No transactions match filters." << ui::reset() << "\n";
                } else {
                    for (int i = start_idx; i < end_idx; i++) {
                        print_tx_row(filtered[i], i, (i == view_state.selected), address_book);
                    }
                }

                std::cout << "\n  " << ui::dim() << "Page " << (view_state.page + 1) << "/" << view_state.total_pages
                          << " | " << (end_idx - start_idx) << "/" << view_state.total_count << " shown" << ui::reset() << "\n";

                std::cout << "\n  " << ui::cyan() << "n/p" << ui::reset() << " Page  "
                          << ui::cyan() << "v" << ui::reset() << " View  "
                          << ui::cyan() << "fs/fr/fp/fc" << ui::reset() << " Filter  "
                          << ui::cyan() << "/text" << ui::reset() << " Search  "
                          << ui::cyan() << "s" << ui::reset() << " Stats  "
                          << ui::cyan() << "c" << ui::reset() << " Clear  "
                          << ui::cyan() << "q" << ui::reset() << " Back\n";

                std::string cmd = ui::prompt("Command: ");
                cmd = trim(cmd);

                if (cmd.empty()) continue;
                else if (cmd == "q" || cmd == "Q") history_running = false;
                else if (cmd == "n") { if (view_state.page < view_state.total_pages - 1) view_state.page++; }
                else if (cmd == "p") { if (view_state.page > 0) view_state.page--; }
                else if (cmd == "v" && view_state.selected >= 0 && view_state.selected < (int)filtered.size()) {
                    print_tx_details_view(filtered[view_state.selected], address_book);
                    std::cout << "  " << ui::dim() << "Press ENTER..." << ui::reset();
                    std::string d; std::getline(std::cin, d);
                }
                else if (cmd == "s") {
                    print_tx_statistics(filtered);
                    std::cout << "  " << ui::dim() << "Press ENTER..." << ui::reset();
                    std::string d; std::getline(std::cin, d);
                }
                else if (cmd == "c") { view_state.filter = TxHistoryFilter(); view_state.page = 0; view_state.selected = -1; }
                else if (cmd == "fs") { view_state.filter.direction = "sent"; view_state.page = 0; }
                else if (cmd == "fr") { view_state.filter.direction = "received"; view_state.page = 0; }
                else if (cmd == "fp") { view_state.filter.status = "pending"; view_state.page = 0; }
                else if (cmd == "fc") { view_state.filter.status = "confirmed"; view_state.page = 0; }
                else if (cmd[0] == '/') { view_state.filter.search = cmd.substr(1); view_state.page = 0; }
                else {
                    try {
                        int num = std::stoi(cmd);
                        if (num >= 1 && num <= view_state.total_count) {
                            view_state.selected = num - 1;
                            view_state.page = view_state.selected / view_state.per_page;
                        }
                    } catch (...) {}
                }
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

            // Validate address using comprehensive validation
            {
                std::string addr_error;
                if(!validate_address(to, addr_error)){
                    ui::print_error("Invalid address: " + addr_error);
                    std::cout << ui::dim() << "  Must be a valid MIQ address starting with the correct prefix" << ui::reset() << "\n\n";
                    log_wallet_event(wdir, "Send failed: invalid address - " + addr_error);
                    continue;
                }
            }

            // Decode the validated address
            uint8_t ver = 0;
            std::vector<uint8_t> payload;
            miq::base58check_decode(to, ver, payload);

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

            // WALLET FIX: Prioritize broadcasting to the same node that provided UTXOs
            // This ensures transaction inputs are definitely in that node's UTXO set
            if(last_connected_node != "<offline>" && last_connected_node != "<not connected>"){
                size_t colon = last_connected_node.find(':');
                if(colon != std::string::npos){
                    std::string spv_host = last_connected_node.substr(0, colon);
                    std::string spv_port = last_connected_node.substr(colon + 1);
                    // Remove this seed from list if present, then add to front
                    seeds_b.erase(
                        std::remove_if(seeds_b.begin(), seeds_b.end(),
                            [&](const std::pair<std::string,std::string>& s){
                                return s.first == spv_host && s.second == spv_port;
                            }),
                        seeds_b.end());
                    seeds_b.insert(seeds_b.begin(), {spv_host, spv_port});
                }
            }

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

            // Update wallet statistics
            update_stats_for_send(wdir, amount, fee_final);

            // Log the transaction
            log_wallet_event(wdir, "Sent " + fmt_amount(amount) + " MIQ to " + to + " (txid: " + txid_hex.substr(0, 16) + "...)");

            // Track the transaction for confirmation monitoring
            TrackedTransaction tracked;
            tracked.txid_hex = txid_hex;
            tracked.created_at = (int64_t)time(nullptr);
            tracked.amount = amount;
            tracked.fee = fee_final;
            tracked.direction = "sent";
            tracked.to_address = to;
            save_tracked_transaction(wdir, tracked);

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
                int queued = 0, broadcast = 0, failed = 0, expired = 0;
                for(const auto& tx : queue){
                    if(tx.status == "queued" || tx.status == "broadcasting") queued++;
                    else if(tx.status == "confirmed" || tx.status == "broadcast") broadcast++;
                    else if(tx.status == "failed") failed++;
                    else if(tx.status == "expired") expired++;
                }

                if(queued > 0)
                    std::cout << "  " << ui::yellow() << "Pending: " << queued << ui::reset() << "\n";
                if(broadcast > 0)
                    std::cout << "  " << ui::green() << "Broadcast: " << broadcast << ui::reset() << "\n";
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
                    if(!tx.error_msg.empty() && tx.status != "confirmed" && tx.status != "broadcast"){
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

                int broadcasted = process_tx_queue(wdir, seeds, pending, true);

                std::cout << "\n";
                if(broadcasted > 0){
                    ui::print_success("Successfully broadcasted " + std::to_string(broadcasted) + " transaction(s)");
                    is_online = true;
                    // Refresh balance after broadcast/cleanup
                    utxos = refresh_and_print();
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
                int broadcasted = process_tx_queue(wdir, seeds, pending, false);
                if(broadcasted > 0){
                    std::cout << "  " << ui::green() << "Broadcasted " << broadcasted << " transaction(s)" << ui::reset() << "\n\n";
                    // Refresh balance display
                    utxos = refresh_and_print();
                }
            }
        }
        // =================================================================
        // OPTION 8: Export Transactions
        // =================================================================
        else if(c == "8"){
            std::cout << "\n";
            ui::print_double_header("EXPORT TRANSACTIONS", 60);
            std::cout << "\n";

            std::vector<TxHistoryEntry> history;
            load_tx_history(wdir, history);

            if(history.empty()){
                std::cout << "  " << ui::yellow() << "No transactions to export." << ui::reset() << "\n\n";
            } else {
                std::cout << ui::dim() << "  Export format:" << ui::reset() << "\n";
                ui::print_menu_item("1", "CSV (Spreadsheet compatible)");
                ui::print_menu_item("2", "JSON (Developer format)");
                ui::print_menu_item("3", "Cancel");
                std::cout << "\n";

                std::string fmt = ui::prompt("Select format: ");
                fmt = trim(fmt);

                if(fmt == "1" || fmt == "2"){
                    std::string content;
                    std::string ext;

                    if(fmt == "1"){
                        content = export_transactions_csv(history);
                        ext = ".csv";
                    } else {
                        content = export_transactions_json(history);
                        ext = ".json";
                    }

                    std::string filename = "miqwallet_export_" +
                        std::to_string(std::time(nullptr)) + ext;
                    std::string filepath = join_path(wdir, filename);

                    std::string error;
                    if(export_to_file(filepath, content, error)){
                        std::cout << "\n  " << ui::green() << "Exported " << history.size()
                                  << " transactions to:" << ui::reset() << "\n";
                        std::cout << "  " << ui::cyan() << filepath << ui::reset() << "\n\n";

                        // Log the export
                        log_wallet_event(wdir, "Exported " + std::to_string(history.size()) +
                            " transactions to " + filename);
                    } else {
                        ui::print_error(error);
                    }
                }
            }
        }
        // =================================================================
        // OPTION 9: Wallet Health Check
        // =================================================================
        else if(c == "9"){
            std::cout << "\n";
            ui::print_double_header("WALLET HEALTH CHECK", 60);
            std::cout << "\n";

            ui::print_progress("Analyzing wallet health...");
            std::cout << "\n";

            // Calculate health metrics
            WalletHealth health = check_wallet_health(utxos, pending, 0);

            // Display overall health score
            std::string score_color;
            std::string score_label;
            if(health.health_score >= 90){
                score_color = ui::green();
                score_label = "EXCELLENT";
            } else if(health.health_score >= 70){
                score_color = ui::cyan();
                score_label = "GOOD";
            } else if(health.health_score >= 50){
                score_color = ui::yellow();
                score_label = "FAIR";
            } else {
                score_color = ui::red();
                score_label = "NEEDS ATTENTION";
            }

            std::cout << "  " << ui::bold() << "Overall Health Score: " << ui::reset()
                      << score_color << health.health_score << "/100 (" << score_label << ")"
                      << ui::reset() << "\n\n";

            // UTXO Analysis
            std::cout << ui::dim() << "  UTXO Analysis:" << ui::reset() << "\n";
            ui_pro::print_kv("Total UTXOs:", std::to_string(health.utxo_count), 20);

            if(health.utxo_count > 0){
                uint64_t avg_utxo = health.total_balance / health.utxo_count;
                ui_pro::print_kv("Average UTXO:", ui_pro::format_miq_professional(avg_utxo) + " MIQ", 20);
                ui_pro::print_kv("Largest UTXO:", ui_pro::format_miq_professional(health.largest_utxo) + " MIQ", 20);
                ui_pro::print_kv("Smallest UTXO:", ui_pro::format_miq_professional(health.smallest_utxo) + " MIQ", 20);
            }

            // Dust Analysis
            std::cout << "\n" << ui::dim() << "  Dust Analysis:" << ui::reset() << "\n";
            ui_pro::print_kv("Dust UTXOs:", std::to_string(health.dust_count), 20);
            if(health.dust_count > 0){
                std::cout << "  " << ui::yellow() << "Recommendation: Consider consolidating dust UTXOs"
                          << ui::reset() << "\n";
            }

            // Pending Transactions
            if(health.pending_count > 0){
                std::cout << "\n" << ui::dim() << "  Pending:" << ui::reset() << "\n";
                ui_pro::print_kv("Pending TXs:", std::to_string(health.pending_count), 20, ui::yellow());
                std::cout << "  " << ui::dim() << "Pending transactions may be blocking funds"
                          << ui::reset() << "\n";
            }

            // Issues and Recommendations
            if(!health.issues.empty()){
                std::cout << "\n" << ui::bold() << "  Issues Found:" << ui::reset() << "\n";
                for(const auto& issue : health.issues){
                    std::cout << "  " << ui::red() << "* " << issue << ui::reset() << "\n";
                }
            }

            if(!health.recommendations.empty()){
                std::cout << "\n" << ui::bold() << "  Recommendations:" << ui::reset() << "\n";
                for(const auto& rec : health.recommendations){
                    std::cout << "  " << ui::cyan() << "-> " << rec << ui::reset() << "\n";
                }
            }

            std::cout << "\n";
            log_wallet_event(wdir, "Performed wallet health check - Score: " +
                std::to_string(health.health_score));
        }
        // =================================================================
        // OPTION 0: Settings & Backup
        // =================================================================
        else if(c == "0"){
            std::cout << "\n";
            ui::print_double_header("SETTINGS & BACKUP", 60);
            std::cout << "\n";

            std::cout << ui::dim() << "  Options:" << ui::reset() << "\n";
            ui::print_menu_item("1", "Create Wallet Backup");
            ui::print_menu_item("2", "View Wallet Info");
            ui::print_menu_item("3", "Clear Transaction History");
            ui::print_menu_item("4", "View Audit Log");
            ui::print_menu_item("5", "Network Settings");
            ui::print_menu_item("6", "Back");
            std::cout << "\n";

            std::string opt = ui::prompt("Select option: ");
            opt = trim(opt);

            if(opt == "1"){
                // Create backup
                std::cout << "\n";
                ui::print_progress("Creating wallet backup...");

                std::string backup_path, error;
                if(create_wallet_backup(wdir, backup_path, error)){
                    std::cout << "  " << ui::green() << "Backup created successfully!" << ui::reset() << "\n";
                    std::cout << "  Location: " << ui::cyan() << backup_path << ui::reset() << "\n\n";
                    log_wallet_event(wdir, "Created wallet backup: " + backup_path);
                } else {
                    ui::print_error(error);
                }
            }
            else if(opt == "2"){
                // Wallet info
                std::cout << "\n";
                ui::print_header("WALLET INFORMATION", 50);
                std::cout << "\n";

                ui_pro::print_kv("Wallet Directory:", wdir, 20);
                ui_pro::print_kv("Address Count:", std::to_string(pkhs.size()), 20);
                ui_pro::print_kv("UTXO Count:", std::to_string(utxos.size()), 20);

                // Calculate total received
                uint64_t total_balance = 0;
                for(const auto& u : utxos){
                    total_balance += u.value;
                }
                ui_pro::print_kv("Total Balance:", ui_pro::format_miq_professional(total_balance) + " MIQ", 20);

                // Cache info
                std::string cache_file = join_path(wdir, "utxo_cache.dat");
                std::ifstream cache_check(cache_file);
                if(cache_check.good()){
                    ui_pro::print_kv("Cache Status:", "Active", 20, ui::green());
                } else {
                    ui_pro::print_kv("Cache Status:", "Not found", 20, ui::yellow());
                }

                std::cout << "\n";
            }
            else if(opt == "3"){
                // Clear history
                std::cout << "\n  " << ui::yellow() << "WARNING: This will delete all transaction history."
                          << ui::reset() << "\n";
                std::string confirm = ui::prompt("Type 'DELETE' to confirm: ");

                if(confirm == "DELETE"){
                    std::string history_file = tx_history_path(wdir);
                    std::remove(history_file.c_str());
                    std::cout << "  " << ui::green() << "Transaction history cleared." << ui::reset() << "\n\n";
                    log_wallet_event(wdir, "Cleared transaction history");
                } else {
                    std::cout << "  " << ui::dim() << "Operation cancelled." << ui::reset() << "\n\n";
                }
            }
            else if(opt == "4"){
                // View audit log
                std::cout << "\n";
                ui::print_header("AUDIT LOG", 50);
                std::cout << "\n";

                std::string log_file = join_path(wdir, "wallet_events.log");
                std::ifstream f(log_file);
                if(!f.good()){
                    std::cout << "  " << ui::dim() << "No audit log found." << ui::reset() << "\n\n";
                } else {
                    std::vector<std::string> lines;
                    std::string line;
                    while(std::getline(f, line)){
                        lines.push_back(line);
                    }

                    // Show last 20 entries
                    int start = std::max(0, (int)lines.size() - 20);
                    std::cout << ui::dim() << "  Recent activity (last "
                              << std::min(20, (int)lines.size()) << " entries):" << ui::reset() << "\n\n";

                    for(int i = start; i < (int)lines.size(); i++){
                        std::cout << "  " << lines[i] << "\n";
                    }
                    std::cout << "\n";
                }
            }
            else if(opt == "5"){
                // Network settings
                std::cout << "\n";
                ui::print_header("NETWORK SETTINGS", 50);
                std::cout << "\n";

                std::cout << ui::dim() << "  Current P2P Seeds:" << ui::reset() << "\n";
                for(const auto& seed_entry : seeds){
                    std::cout << "  - " << seed_entry.first << ":" << seed_entry.second << "\n";
                }
                std::cout << "\n";

                if(is_online){
                    std::cout << "  Status: " << ui::green() << "Connected" << ui::reset();
                    if(!last_connected_node.empty()){
                        std::cout << " to " << last_connected_node;
                    }
                    std::cout << "\n\n";
                } else {
                    std::cout << "  Status: " << ui::red() << "Offline" << ui::reset() << "\n\n";
                }
            }
        }
        // =================================================================
        // OPTION d: Network Diagnostics
        // =================================================================
        else if(c == "d" || c == "D"){
            std::cout << "\n";
            ui::print_double_header("NETWORK DIAGNOSTICS", 60);
            std::cout << "\n";

            ui::print_progress("Running network diagnostics...");
            std::cout << "\n";

            NetworkDiagnostics diag;
            diag.timestamp = std::time(nullptr);

            // Test each seed
            std::cout << ui::dim() << "  Testing P2P connections:" << ui::reset() << "\n\n";

            for(const auto& seed_entry : seeds){
                std::cout << "  " << seed_entry.first << ":" << seed_entry.second << " ... ";
                std::cout.flush();

                auto start = std::chrono::steady_clock::now();

                // Try to connect
                miq::SpvOptions opts;
                opts.timeout_ms = 5000;
                std::vector<miq::UtxoLite> test_utxos;
                std::string err;

                bool success = miq::spv_collect_utxos(
                    seed_entry.first, seed_entry.second, pkhs, opts, test_utxos, err);

                auto end = std::chrono::steady_clock::now();
                int latency = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
                    end - start).count();

                if(success){
                    diag.successful_connections++;
                    diag.latency_samples.push_back(latency);
                    std::cout << ui::green() << "OK" << ui::reset()
                              << " (" << latency << "ms)\n";
                } else {
                    diag.failed_connections++;
                    std::cout << ui::red() << "FAILED" << ui::reset() << "\n";
                }
            }

            // Calculate average latency
            if(!diag.latency_samples.empty()){
                int sum = 0;
                for(int l : diag.latency_samples) sum += l;
                diag.avg_latency_ms = sum / (int)diag.latency_samples.size();
            }

            // Summary
            std::cout << "\n" << ui::dim() << "  Summary:" << ui::reset() << "\n";
            ui_pro::print_kv("Successful:", std::to_string(diag.successful_connections), 20, ui::green());
            ui_pro::print_kv("Failed:", std::to_string(diag.failed_connections), 20,
                diag.failed_connections > 0 ? ui::red() : ui::dim());

            if(diag.avg_latency_ms > 0){
                std::string latency_color = diag.avg_latency_ms < 500 ? ui::green() :
                    (diag.avg_latency_ms < 2000 ? ui::yellow() : ui::red());
                ui_pro::print_kv("Avg Latency:", std::to_string(diag.avg_latency_ms) + "ms", 20, latency_color);
            }

            std::cout << "\n";

            // Save diagnostics
            save_diagnostics(wdir, diag);
            log_wallet_event(wdir, "Ran network diagnostics - " +
                std::to_string(diag.successful_connections) + "/" +
                std::to_string(seeds.size()) + " nodes reachable");
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
