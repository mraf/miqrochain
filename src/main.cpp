#ifdef _MSC_VER
  #pragma execution_character_set("utf-8")
  #define _CRT_SECURE_NO_WARNINGS
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Windows portability flags
#ifdef _WIN32
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
#endif

// ─────────────────────────────────────────────────────────────────────────────
// MIQ public headers
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
#include "miner.h"
#include "sha256.h"
#include "hex.h"
#include "tls_proxy.h"
#include "ibd_monitor.h"
#include "utxo_kv.h"

#if __has_include("reindex_utxo.h")
#  include "reindex_utxo.h"
#endif
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
namespace miq {
extern bool ensure_utxo_fully_indexed(Chain&, const std::string&, bool) __attribute__((weak));
}
#  define MIQ_CAN_PROBE_UTXO_REINDEX 1
#else
#  define MIQ_CAN_PROBE_UTXO_REINDEX 0
#endif

// ─────────────────────────────────────────────────────────────────────────────
// STL
#include <thread>
#include <cctype>
#include <fstream>
#include <iostream>
#include <filesystem>
#include <cstdio>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include <cstdlib>
#include <csignal>
#include <atomic>
#include <memory>
#include <algorithm>
#include <ctime>
#include <random>
#include <type_traits>
#include <utility>
#include <cstdint>
#include <exception>
#include <deque>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <iomanip>
#include <limits>
#include <unordered_set>
#include <unordered_map>
#include <map>
#include <set>
#include <array>
#include <optional>
#include <cmath>
#include <cerrno>

// ─────────────────────────────────────────────────────────────────────────────
// OS headers (guarded)
#if defined(_WIN32)
  #include <io.h>
  #include <windows.h>
  #include <conio.h>
  #include <fcntl.h>
  #include <psapi.h>
  #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
  #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
  #endif
  #ifdef _MSC_VER
    #pragma comment(lib, "Psapi.lib")
  #endif
  #define MIQ_ISATTY() (_isatty(_fileno(stdin)) != 0)
#else
  #include <unistd.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <fcntl.h>
  #include <sys/types.h>
  #include <sys/stat.h>
  #include <ifaddrs.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #define MIQ_ISATTY() (::isatty(fileno(stdin)) != 0)
#  if defined(__APPLE__)
#    include <mach/mach.h>
#  endif
#endif



#ifdef _WIN32
  #ifdef min
    #undef min
  #endif
  #ifdef max
    #undef max
  #endif
#include <iphlpapi.h>
  #pragma comment(lib, "Iphlpapi.lib")
#endif

using namespace miq;

static std::atomic<uint64_t> g_genesis_time_s{0};

static std::string g_seed_host = DNS_SEED;
static inline const char* seed_host_cstr(){ return g_seed_host.c_str(); }

static std::atomic<bool> g_assume_seed_hairpin{false};

// ─────────────────────────────────────────────────────────────────────────────
// Versions
#ifndef MIQ_VERSION_MAJOR
#define MIQ_VERSION_MAJOR 0
#endif
#ifndef MIQ_VERSION_MINOR
#define MIQ_VERSION_MINOR 7
#endif
#ifndef MIQ_VERSION_PATCH
#define MIQ_VERSION_PATCH 0
#endif

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                         Global state & helpers                            ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
namespace global {
static std::atomic<bool>    shutdown_requested{false};
static std::atomic<bool>    shutdown_initiated{false};
static std::atomic<uint64_t>last_signal_ms{0};
static std::atomic<bool>    reload_requested{false};   // SIGHUP / hotkey 'r'
static std::string          lockfile_path;
static std::string          pidfile_path;
static std::string          telemetry_path;
static std::atomic<bool>    telemetry_enabled{false};
static std::atomic<bool>    tui_snapshot_requested{false};
static std::atomic<bool>    tui_toggle_theme{false};
[[maybe_unused]] static std::atomic<bool>    tui_pause_logs{false};
static std::atomic<bool>    tui_verbose{false};
#ifdef _WIN32
static HANDLE               lock_handle{NULL};
#else
static int                  lock_fd{-1};
#endif
}

static std::atomic<bool> g_we_are_seed{false};

// time helpers
static inline uint64_t now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
static inline uint64_t now_s() {
    return (uint64_t)std::time(nullptr);
}

// ─────────────────────────────────────────────────────────────────────────────
// Shutdown request w/ escalation (double signal within 2s => hard exit)
static void request_shutdown(const char* why){
    bool first = !global::shutdown_initiated.exchange(true);
    global::shutdown_requested.store(true);
    if (first) {
        log_warn(std::string("Shutdown requested: ") + (why ? why : "signal"));
    } else {
        uint64_t t = now_ms();
        uint64_t last = global::last_signal_ms.load();
        if (last && (t - last) < 2000) {
            log_error("Forced immediate termination (double signal).");
#ifdef _WIN32
            TerminateProcess(GetCurrentProcess(), 1);
#else
            _exit(1);
#endif
        }
    }
    global::last_signal_ms.store(now_ms());
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                              Miner stats                                   ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
struct MinerStats {
    std::atomic<bool> active{false};
    std::atomic<unsigned> threads{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<uint64_t> last_height_ok{0};
    std::atomic<uint64_t> last_height_rx{0};
    std::chrono::steady_clock::time_point start{};
    std::atomic<double>   hps{0.0}; // stays 0 unless miner API exposes tries
} g_miner_stats;

static std::string g_miner_address_b58; // display mined-to address

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                           Telemetry buffers                                ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
struct BlockSummary {
    uint64_t height{0};
    std::string hash_hex;
    uint32_t tx_count{0};
    uint64_t fees{0};
    bool     fees_known{false};
    std::string miner; // base58 if known
};
struct Telemetry {
    std::mutex mu;
    std::deque<BlockSummary> new_blocks;
    std::deque<std::string>  new_txids;
    void push_block(const BlockSummary& b) {
        std::lock_guard<std::mutex> lk(mu);
        new_blocks.push_back(b);
        while (new_blocks.size() > 256) new_blocks.pop_front();
    }
    void push_txids(const std::vector<std::string>& v) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto& t : v) {
            new_txids.push_back(t);
            while (new_txids.size() > 128) new_txids.pop_front();
        }
    }
    void drain(std::vector<BlockSummary>& out_blocks, std::vector<std::string>& out_txids) {
        std::lock_guard<std::mutex> lk(mu);
        out_blocks.assign(new_blocks.begin(), new_blocks.end());
        out_txids.assign(new_txids.begin(), new_txids.end());
        new_blocks.clear();
        new_txids.clear();
    }
} g_telemetry;

static inline void telemetry_flush_disk(const BlockSummary& b){
    if (!global::telemetry_enabled.load()) return;
    try{
        std::ofstream f(global::telemetry_path, std::ios::app);
        if(!f) return;
        f << "{"
          << "\"t\":" << now_s()
          << ",\"h\":" << b.height
          << ",\"hash\":\"" << b.hash_hex << "\""
          << ",\"tx\":" << b.tx_count
          << (b.fees_known ? (std::string(",\"fees\":") + std::to_string(b.fees)) : "")
          << (b.miner.empty()? "" : (std::string(",\"miner\":\"") + b.miner + "\""))
          << "}\n";
    }catch(...){}
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                     External miner heartbeat watch                         ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
struct ExtMinerWatch {
    std::atomic<bool> alive{false};
    std::atomic<bool> running{false};
    std::thread thr;
    std::string path;

    static std::string default_path(const std::string& datadir){
#ifdef _WIN32
        return datadir + "\\miner.heartbeat";
#else
        return datadir + "/miner.heartbeat";
#endif
    }
    void start(const std::string& datadir){
        const char* p = std::getenv("MIQ_MINER_HEARTBEAT");
        path = p && *p ? std::string(p) : default_path(datadir);
        running.store(true);
        thr = std::thread([this]{
            using namespace std::chrono_literals;
            while(running.load()){
                std::error_code ec;
                auto ft = std::filesystem::last_write_time(path, ec);
                bool ok = false;
                if (!ec){
                    auto now = std::filesystem::file_time_type::clock::now();
                    auto diff = now - ft;
                    auto secs = std::chrono::duration_cast<std::chrono::seconds>(diff).count();
                    ok = (secs >= 0 && secs <= 15);
                }
                alive.store(ok);
                std::this_thread::sleep_for(1s);
            }
        });
    }
    void stop(){
        running.store(false);
        if (thr.joinable()) thr.join();
        alive.store(false);
    }
} g_extminer;

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                       Datadir / PID / Lock helpers                         ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
static std::string default_datadir() {
#ifdef _WIN32
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
static inline void trim_inplace(std::string& s){
    auto notspace = [](unsigned char ch){ return !std::isspace(ch); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), notspace));
    s.erase(std::find_if(s.rbegin(), s.rend(), notspace).base(), s.end());
}
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
static inline std::string p_join(const std::string& a, const std::string& b){
#ifdef _WIN32
    return a + "\\" + b;
#else
    return a + "/" + b;
#endif
}

static bool write_text_atomic(const std::string& path, const std::string& body){
    std::error_code ec;
    auto dir = std::filesystem::path(path).parent_path();
    if(!dir.empty()) std::filesystem::create_directories(dir, ec);
    std::string tmp = path + ".tmp";
    std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
    if(!f) return false;
    f.write(body.data(), (std::streamsize)body.size());
    f.flush();
    f.close();
    std::filesystem::rename(tmp, path, ec);
    return !ec;
}

// Utility: is a PID alive?
static bool pid_alive(int pid){
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!h) return false;
    DWORD code = 0;
    BOOL ok = GetExitCodeProcess(h, &code);
    CloseHandle(h);
    if (!ok) return false;
    return (code == STILL_ACTIVE);
#else
    if (pid <= 0) return false;
    int r = kill(pid, 0);
    if (r == 0) return true;
    return errno == EPERM ? true : false; // process exists but no permission
#endif
}

// Purge stale lock/pid files if previous process is not alive.
static void purge_stale_lock(const std::string& datadir){
    std::error_code ec;
    std::string lock = p_join(datadir, ".lock");
    std::string pid  = p_join(datadir, "miqrod.pid");
    bool lock_exists = std::filesystem::exists(lock, ec);
    if (!lock_exists) return;

    bool remove_ok = true;
    int pidnum = -1;
    if (std::filesystem::exists(pid, ec)) {
        std::ifstream f(pid);
        if (f) { f >> pidnum; }
    }
    if (pidnum > 0 && pid_alive(pidnum)) {
        // Running instance; do NOT purge.
        remove_ok = false;
    }
    if (remove_ok) {
        std::filesystem::remove(lock, ec);
        std::filesystem::remove(pid, ec);
        if (!ec) {
            std::fprintf(stderr, "[WARN] Stale .lock detected and removed; continuing.\n");
        }
    }
}

// Lock file (exclusive). Keeps handle open for the entire process lifetime.
static bool acquire_datadir_lock(const std::string& datadir){
    std::error_code ec;
    std::filesystem::create_directories(datadir, ec);
    // Always attempt to purge stale lock first
    purge_stale_lock(datadir);

    std::string lock = p_join(datadir, ".lock");
    std::string pid  = p_join(datadir, "miqrod.pid");
#ifdef _WIN32
    HANDLE h = CreateFileA(lock.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           0,                // no sharing
                           NULL,
                           CREATE_NEW,       // fail if exists
                           FILE_ATTRIBUTE_NORMAL,
                           NULL);
    if (h == INVALID_HANDLE_VALUE) {
        // Retry once after purge (in case another process created it meanwhile)
        purge_stale_lock(datadir);
        h = CreateFileA(lock.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h == INVALID_HANDLE_VALUE) {
            log_error("Another instance appears to be running (lock exists).");
            return false;
        }
    }
    global::lock_handle = h;
#else
    int fd = ::open(lock.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) {
        // Retry once after purge
        purge_stale_lock(datadir);
        fd = ::open(lock.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
        if (fd < 0) {
            log_error("Another instance appears to be running (lock exists).");
            return false;
        }
    }
    global::lock_fd = fd;
#endif
    // write PID file
#ifdef _WIN32
    int pidnum = (int)GetCurrentProcessId();
#else
    int pidnum = (int)getpid();
#endif
    write_text_atomic(pid, std::to_string(pidnum) + "\n");
    global::lockfile_path = lock;
    global::pidfile_path  = pid;
    return true;
}
static void release_datadir_lock(){
    std::error_code ec;
#ifdef _WIN32
    if (global::lock_handle && global::lock_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(global::lock_handle);
        global::lock_handle = NULL;
    }
#else
    if (global::lock_fd >= 0) {
        ::close(global::lock_fd);
        global::lock_fd = -1;
    }
#endif
    if (!global::lockfile_path.empty()) std::filesystem::remove(global::lockfile_path, ec);
    if (!global::pidfile_path.empty())  std::filesystem::remove(global::pidfile_path, ec);
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                    Signals / console control / input                       */
// ╚═══════════════════════════════════════════════════════════════════════════╝
static void sighup_handler(int){ global::reload_requested.store(true); }
static void sigshutdown_handler(int){ request_shutdown("signal"); }

#ifdef _WIN32
static BOOL WINAPI win_ctrl_handler(DWORD evt){
    switch(evt){
        case CTRL_C_EVENT:        request_shutdown("CTRL_C_EVENT");        return TRUE;
        case CTRL_BREAK_EVENT:    request_shutdown("CTRL_BREAK_EVENT");    return TRUE;
        case CTRL_CLOSE_EVENT:    request_shutdown("CTRL_CLOSE_EVENT");    return TRUE;
        case CTRL_LOGOFF_EVENT:   request_shutdown("CTRL_LOGOFF_EVENT");   return TRUE;
        case CTRL_SHUTDOWN_EVENT: request_shutdown("CTRL_SHUTDOWN_EVENT"); return TRUE;
        default: return FALSE;
    }
}
#endif

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                               Resource metrics                              */
// ╚═══════════════════════════════════════════════════════════════════════════╝
static uint64_t get_rss_bytes(){
#if defined(_WIN32)
    PROCESS_MEMORY_COUNTERS info{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), &info, sizeof(info))) {
        return (uint64_t)info.WorkingSetSize;
    }
    return 0;
#elif defined(__APPLE__)
    // /proc/self/statm doesn't exist on macOS; use Mach APIs.
    mach_task_basic_info info;
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    task_t task = mach_task_self();
    if (task_info(task, MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) == KERN_SUCCESS) {
        return (uint64_t)info.resident_size;
    }
    return 0;
#else
    std::ifstream f("/proc/self/statm"); uint64_t rss_pages=0, x=0;
    if (f >> x >> rss_pages){ long p = sysconf(_SC_PAGESIZE); return (uint64_t)rss_pages * (uint64_t)p; }
    return 0;
#endif
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                              Terminal utils                                 */
// ╚═══════════════════════════════════════════════════════════════════════════╝
namespace term {

// Basic tty check remains available
[[maybe_unused]] static inline bool is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}

// ConPTY/Windows Terminal: interactive output even if STDOUT is a pipe
static inline bool supports_interactive_output() {
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut && hOut != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(hOut, &mode)) return true; // real console
    }
    DWORD type = GetFileType(hOut);
    const bool is_pipe = (type == FILE_TYPE_PIPE);
    const bool hinted =
        (std::getenv("WT_SESSION")       ||
         std::getenv("ConEmuANSI")       ||
         std::getenv("TERMINUS_SUBPROC") ||
         std::getenv("MSYS")             ||
         std::getenv("MSYSTEM"));
    return is_pipe && hinted;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}

// Improved window size
static inline void get_winsize(int& cols, int& rows) {
    cols = 120; rows = 38;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!GetConsoleScreenBufferInfo(hOut, &info)) {
        HANDLE hAlt = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hAlt != INVALID_HANDLE_VALUE) {
            if (GetConsoleScreenBufferInfo(hAlt, &info)) {
                cols = info.srWindow.Right - info.srWindow.Left + 1;
                rows = info.srWindow.Bottom - info.srWindow.Top + 1;
            }
            CloseHandle(hAlt);
            return;
        }
    } else {
        cols = info.srWindow.Right - info.srWindow.Left + 1;
        rows = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
#else
    struct winsize ws{};
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col) cols = ws.ws_col;
        if (ws.ws_row) rows = ws.ws_row;
    }
#endif
}

// Enable VT and probe Unicode ability.
static inline void enable_vt_and_probe_u8(bool& vt_ok, bool& u8_ok) {
    vt_ok = true; u8_ok = false;
#ifdef _WIN32
    vt_ok = false; u8_ok = false;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    bool have_console = (h && h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &mode));

    HANDLE hConOut = INVALID_HANDLE_VALUE;
    if (!have_console) {
        hConOut = CreateFileA("CONOUT$", GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hConOut != INVALID_HANDLE_VALUE && GetConsoleMode(hConOut, &mode)) {
            have_console = true;
            h = hConOut;
        }
    }
    if (have_console) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        if (SetConsoleMode(h, mode)) {
            DWORD m2 = 0;
            if (GetConsoleMode(h, &m2) && (m2 & ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
                vt_ok = true;
            }
        }
    } else {
        DWORD type = GetFileType(GetStdHandle(STD_OUTPUT_HANDLE));
        const bool is_pipe = (type == FILE_TYPE_PIPE);
        if (is_pipe) vt_ok = true;
    }

    const bool force_utf8 = []{
        const char* s = std::getenv("MIQ_TUI_UTF8");
        return s && *s ? (std::strcmp(s,"0")!=0 && std::strcmp(s,"false")!=0 && std::strcmp(s,"False")!=0) : false;
    }();
    if (force_utf8 && have_console) {
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
        u8_ok = true;
    }

    if (hConOut != INVALID_HANDLE_VALUE) CloseHandle(hConOut);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOALIGNMENTFAULTEXCEPT);
#else
    vt_ok = true;
    u8_ok = true;
#endif
}

} // namespace term

// Console writer avoids recursion with log capture
class ConsoleWriter {
public:
    ConsoleWriter(){ init(); }
    ~ConsoleWriter(){
#ifdef _WIN32
        if (hFile_ && hFile_ != INVALID_HANDLE_VALUE) CloseHandle(hFile_);
#else
        if (fd_ >= 0 && fd_ != STDOUT_FILENO) ::close(fd_);
#endif
    }
    void write_raw(const std::string& s){
#ifdef _WIN32
        if (hFile_ && hFile_ != INVALID_HANDLE_VALUE) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), NULL, 0);
            if (wlen > 0) {
                std::wstring ws((size_t)wlen, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), ws.data(), wlen);
                DWORD wroteW = 0;
                if (WriteConsoleW(hFile_, ws.c_str(), (DWORD)ws.size(), &wroteW, nullptr)) return;
            }
        }
        DWORD wrote = 0;
        WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), s.c_str(), (DWORD)s.size(), &wrote, nullptr);
#else
        int fd = (fd_ >= 0) ? fd_ : STDOUT_FILENO;
        size_t off = 0; while (off < s.size()) { ssize_t n = ::write(fd, s.data()+off, s.size()-off); if (n<=0) break; off += (size_t)n; }
#endif
    }
private:
    void init(){
#ifdef _WIN32
        hFile_ = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE | FILE_SHARE_READ,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
#else
        fd_ = ::open("/dev/tty", O_WRONLY | O_CLOEXEC);
        if (fd_ < 0) fd_ = STDOUT_FILENO;
#endif
    }
#ifdef _WIN32
    HANDLE hFile_{};
#else
    int fd_ = -1;
#endif
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                              Helper utilities                               */
// ╚═══════════════════════════════════════════════════════════════════════════╝

// small truthy helper reused for ASCII fallbacks
static inline bool env_truthy_local(const char* name){
    const char* v = std::getenv(name);
    if(!v||!*v) return false;
    if(std::strcmp(v,"0")==0 || std::strcmp(v,"false")==0 || std::strcmp(v,"False")==0) return false;
    return true;
}

// Bytes pretty-printer
static inline std::string fmt_bytes(uint64_t v){
    static const char* units[] = {"B","KiB","MiB","GiB","TiB","PiB"};
    double d = (double)v;
    int u = 0;
    while (d >= 1024.0 && u < 5){ d /= 1024.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?1:0)<<d<<" "<<units[u];
    return o.str();
}

// Hashrate pretty-printer
static inline std::string fmt_hs(double v){
    static const char* units[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s","EH/s"};
    double d = (double)v;
    int u = 0;
    while (d >= 1000.0 && u < 6){ d /= 1000.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?2:0)<<d<<" "<<units[u];
    return o.str();
}

// Difficulty pretty
static inline std::string fmt_diff(long double d){
    double x = (double)d;
    static const char* units[] = {"","k","M","G","T","P","E"};
    int u = 0;
    while (x >= 1000.0 && u < 6){ x/=1000.0; ++u; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(u?2:0)<<x<<units[u];
    return o.str();
}

// Spinner & drawing helpers
static inline std::string spinner(int tick, bool fancy){
    if (fancy){
        static const char* frames[] = {"⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"};
        return frames[(size_t)(tick % 10)];
    } else {
        static const char frames[] = {'-','\\','|','/'};
        return std::string(1, frames[(size_t)(tick & 3)]);
    }
}
static inline std::string straight_line(int w){
    if (w <= 0) return {};
    // keep ASCII here for max portability
    return std::string((size_t)w, '-');
}
static inline std::string bar(int width, double frac, bool /*vt_ok*/, bool u8_ok){
    if (width < 3) width = 3;
    if (frac < 0) frac = 0;
    if (frac > 1) frac = 1; // <- split lines to avoid -Wmisleading-indentation
    int inner = width - 2;
    int full  = (int)std::round(frac * inner);
    std::string out; out.reserve((size_t)width);
    out.push_back('[');
    if (u8_ok && env_truthy_local("MIQ_TUI_UTF8")){
        for (int i=0;i<inner;i++) out += (i<full ? "█" : " ");
    } else {
        for (int i=0;i<inner;i++) out.push_back(i<full ? '#' : ' ');
    }
    out.push_back(']');
    return out;
}
static inline std::string short_hex(const std::string& h, int keep){
    if ((int)h.size() <= keep) return h;
    int half = keep/2;
    const char* ell = env_truthy_local("MIQ_TUI_UTF8")? "…" : "...";
    return h.substr(0,(size_t)half) + ell + h.substr(h.size()-(size_t)(keep-half));
}

// ─────────────────────────────────────────────────────────────────────────────
// Net helpers: resolve host, collect local IPs, compare, and compute seed role
// ─────────────────────────────────────────────────────────────────────────────

static inline std::string ip_norm(const std::string& ip){
    if (ip.find('.') != std::string::npos){
        // If there's a colon, assume v6 wrapper and take the tail after last ':'
        size_t pos = ip.rfind(':');
        if (pos != std::string::npos){
            std::string tail = ip.substr(pos + 1);
            // crude check for dotted-quad
            int dots = 0; for(char c: tail) if (c=='.') ++dots;
            if (dots == 3) return tail;
        }
    }
    return ip;
}

static std::vector<std::string> resolve_host_ip_strings(const std::string& host){
    std::vector<std::string> out;
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return out;
    for (auto* p = res; p; p = p->ai_next){
        char buf[INET6_ADDRSTRLEN]{};
        if (p->ai_family == AF_INET) {
            auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) out.emplace_back(ip_norm(buf));
        } else if (p->ai_family == AF_INET6) {
            auto* sa6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            if (inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf))) out.emplace_back(ip_norm(buf));
        }
    }
    freeaddrinfo(res);
    // de-dup
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

static std::vector<std::string> local_ip_strings(){
    std::vector<std::string> out;
#ifdef _WIN32
    ULONG flags = GAA_FLAG_SKIP_FRIENDLY_NAME | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    ULONG sz = 0;
    if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, nullptr, &sz) == ERROR_BUFFER_OVERFLOW){
        std::vector<char> buf(sz);
        IP_ADAPTER_ADDRESSES* aa = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
        if (GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, aa, &sz) == NO_ERROR){
            for (auto* a = aa; a; a = a->Next){
                for (auto* ua = a->FirstUnicastAddress; ua; ua = ua->Next){
                    char tmp[INET6_ADDRSTRLEN]{};
                    if (ua->Address.lpSockaddr->sa_family == AF_INET){
                        auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                        if (inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
                    } else if (ua->Address.lpSockaddr->sa_family == AF_INET6){
                        auto* sa6 = reinterpret_cast<sockaddr_in6*>(ua->Address.lpSockaddr);
                        if (inet_ntop(AF_INET6, &sa6->sin6_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
                    }
                }
            }
        }
    }
#else
    ifaddrs* ifa = nullptr;
    if (getifaddrs(&ifa) == 0 && ifa){
        for (auto* p = ifa; p; p = p->ifa_next){
            if (!p->ifa_addr) continue;
            int fam = p->ifa_addr->sa_family;
            char tmp[INET6_ADDRSTRLEN]{};
            if (fam == AF_INET){
                auto* sa = reinterpret_cast<sockaddr_in*>(p->ifa_addr);
                if (inet_ntop(AF_INET, &sa->sin_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
            } else if (fam == AF_INET6){
                auto* sa6 = reinterpret_cast<sockaddr_in6*>(p->ifa_addr);
                if (inet_ntop(AF_INET6, &sa6->sin6_addr, tmp, sizeof(tmp))) out.emplace_back(ip_norm(tmp));
            }
        }
        freeifaddrs(ifa);
    }
#endif
    // Include optional explicit public IP hint
    if (const char* hint = std::getenv("MIQ_PUBLIC_IP"); hint && *hint) out.emplace_back(ip_norm(hint));
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

[[maybe_unused]] static bool is_loopback_or_linklocal(const std::string& ip){
    if (ip == "127.0.0.1" || ip == "::1") return true;
    if (ip.rfind("169.254.",0)==0) return true;
    if (ip.rfind("fe80:",0)==0 || ip.rfind("FE80:",0)==0) return true;
    return false;
}

static inline bool is_private_v4(const std::string& ip){
    return ip.rfind("10.",0)==0
        || ip.rfind("192.168.",0)==0
        || (ip.rfind("172.",0)==0 && [] (const std::string& s){
              // 172.16.0.0/12
              int a=0; char dot=0;
              if (std::sscanf(s.c_str(),"172.%d%c",&a,&dot)==2 && dot=='.') return (a>=16 && a<=31);
              return false;
           }(ip));
}

struct SeedRole {
    bool we_are_seed{false};
    std::string detail;
    std::vector<std::string> seed_ips;
    std::vector<std::string> local_ips;
};

static SeedRole compute_seed_role(){
    SeedRole r;
    r.seed_ips  = resolve_host_ip_strings(seed_host_cstr());
    r.local_ips = local_ip_strings();
    for (const auto& seed_ip : r.seed_ips){
        for (const auto& lip : r.local_ips){
            if (seed_ip == lip){
                r.we_are_seed = true;
                r.detail = std::string("seed (") + seed_host_cstr() + ") A/AAAA (" + seed_ip + ") matches local IP";
                return r;
            }
        }
    }
    // Heuristic 2: explicit override via env (useful behind NAT/port-forward).
    if (const char* f = std::getenv("MIQ_FORCE_SEED"); f && *f && std::strcmp(f,"0")!=0 &&
        std::strcmp(f,"false")!=0 && std::strcmp(f,"False")!=0){
        r.we_are_seed = true;
        r.detail = "MIQ_FORCE_SEED=1";
        return r;
    }
    r.detail = r.seed_ips.empty() ? "seed host has no A/AAAA records"
                                  : "seed host resolves to different IP(s)";
    return r;
}

static inline bool solo_seed_mode(P2P* p2p){
    auto role = compute_seed_role();
    size_t peers = p2p ? p2p->snapshot_peers().size() : 0;
    return (role.we_are_seed || g_assume_seed_hairpin.load()) && peers == 0;
}

// Traits & helpers used by TUI and elsewhere
template<typename, typename = void> struct has_stats_method : std::false_type{};
template<typename T> struct has_stats_method<T, std::void_t<decltype(std::declval<T&>().stats())>> : std::true_type{};
template<typename, typename = void> struct has_size_method  : std::false_type{};
template<typename T> struct has_size_method<T,  std::void_t<decltype(std::declval<T&>().size())>>  : std::true_type{};
template<typename, typename = void> struct has_count_method : std::false_type{};
template<typename T> struct has_count_method<T, std::void_t<decltype(std::declval<T&>().count())>> : std::true_type{};

struct MempoolView { uint64_t count=0, bytes=0, recent_adds=0; };
template<typename MP>
static MempoolView mempool_view_fallback(MP* mp){
    MempoolView v{};
    if (!mp) return v;
    if constexpr (has_stats_method<MP>::value) {
        auto s = mp->stats();
        v.count = (uint64_t)s.count;
        v.bytes = (uint64_t)s.bytes;
        v.recent_adds = (uint64_t)s.recent_adds;
    } else if constexpr (has_size_method<MP>::value) {
        v.count = (uint64_t)mp->size();
    } else if constexpr (has_count_method<MP>::value) {
        v.count = (uint64_t)mp->count();
    }
    return v;
}

template<typename, typename = void> struct has_time_field : std::false_type{};
template<typename H> struct has_time_field<H, std::void_t<decltype(std::declval<H>().time)>> : std::true_type{};
template<typename, typename = void> struct has_timestamp_field : std::false_type{};
template<typename H> struct has_timestamp_field<H, std::void_t<decltype(std::declval<H>().timestamp)>> : std::true_type{};
template<typename, typename = void> struct has_bits_field : std::false_type{};
template<typename H> struct has_bits_field<H, std::void_t<decltype(std::declval<H>().bits)>> : std::true_type{};
template<typename, typename = void> struct has_nBits_field : std::false_type{};
template<typename H> struct has_nBits_field<H, std::void_t<decltype(std::declval<H>().nBits)>> : std::true_type{};

template<typename H>
static uint64_t hdr_time(const H& h){
    if constexpr (has_time_field<H>::value) return (uint64_t)h.time;
    if constexpr (has_timestamp_field<H>::value) return (uint64_t)h.timestamp;
    return 0;
}
template<typename H>
static uint32_t hdr_bits(const H& h){
    if constexpr (has_bits_field<H>::value) return (uint32_t)h.bits;
    if constexpr (has_nBits_field<H>::value) return (uint32_t)h.nBits;
    return (uint32_t)GENESIS_BITS;
}

// Difficulty helpers
static long double compact_to_target_ld(uint32_t bits){
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffff;
    long double m = (long double)mant;
    int shift = (int)exp - 3;
    return std::ldexp(m, 8 * shift);
}
static long double difficulty_from_bits(uint32_t bits){
    long double t_one = compact_to_target_ld((uint32_t)GENESIS_BITS);
    long double t_cur = compact_to_target_ld(bits);
    if (t_cur <= 0.0L) return 0.0L;
    return t_one / t_cur;
}

[[maybe_unused]] static inline uint64_t estimate_target_height_by_time(uint64_t genesis_ts){
    if (!genesis_ts) return 0;
    uint64_t now = (uint64_t)std::time(nullptr);
    if (now <= genesis_ts) return 1;
    return 1 + (now - genesis_ts) / (uint64_t)BLOCK_TIME_SECS;
}

// Estimate network hashrate (used in TUI loop)
static double estimate_network_hashrate(Chain* chain){
    if (!chain) return 0.0;
    const unsigned k = (unsigned)std::max<int>(MIQ_RETARGET_INTERVAL, 32);
    auto headers = chain->last_headers(k);
    if (headers.size() < 2) return 0.0;

    uint64_t t_first = hdr_time(headers.front());
    uint64_t t_last  = hdr_time(headers.back());
    if (t_last <= t_first) t_last = t_first + 1;
    double avg_block_time = double(t_last - t_first) / double(headers.size()-1);
    if (avg_block_time <= 0.0) avg_block_time = (double)BLOCK_TIME_SECS;

    uint32_t bits = hdr_bits(headers.back());
    long double diff = difficulty_from_bits(bits);
    long double hps = (diff * 4294967296.0L) / avg_block_time; // 2^32
    if (!std::isfinite((double)hps) || hps < 0) return 0.0;
    return (double)hps;
}

// Sparklines
static inline std::string spark_ascii(const std::vector<double>& v){
    if (v.empty()) return std::string("-");
    double mn = v.front(), mx = v.front();
    for (double x : v){ if (x < mn) mn = x; if (x > mx) mx = x; }
    double span = (mx - mn);
    bool fancy = env_truthy_local("MIQ_TUI_UTF8");
    const char* blocks8 = "▁▂▃▄▅▆▇█"; // 8 glyphs, UTF-8 (3 bytes each)
    const char* ascii   = " .:-=+*#%@";
    std::string out; out.reserve(v.size());
    for (double x : v){
        int idx = 0;
        if (span > 0) idx = (int)std::floor((x - mn) / span * 7.999);
        if (idx < 0) idx = 0;
        if (idx > 7) idx = 7; // <- split lines to avoid -Wmisleading-indentation
        out += fancy ? std::string(blocks8 + idx*3, 3)   // <- correct UTF-8 indexing
                     : std::string(1, ascii[(size_t)idx]);
    }
    return out;
}

// Sync gate helper (used both in TUI texts and IBD logic)
static bool compute_sync_gate(Chain& chain, P2P* p2p, std::string& why_out){
    size_t peers = p2p ? p2p->snapshot_peers().size() : 0;
    const bool seed_solo = compute_seed_role().we_are_seed && peers == 0;
    if (!seed_solo && peers == 0) { why_out = "no peers"; return false; }

    uint64_t h = chain.height();
    if (h == 0) {
        if (seed_solo) { why_out.clear(); return true; } // allow solo mining from genesis
        why_out = "headers syncing"; return false;
    }

    auto tip = chain.tip();
    uint64_t tsec = hdr_time(tip);
    if (tsec == 0) { why_out = "waiting for headers time"; return false; }
    uint64_t now = (uint64_t)std::time(nullptr);
    uint64_t age = (now > tsec) ? (now - tsec) : 0;
    const uint64_t fresh = std::max<uint64_t>(BLOCK_TIME_SECS * 3, 300);
    if (age > fresh) { why_out = "tip too old"; return false; }

    why_out.clear();
    return true;
}

static bool any_verack_peer(P2P* p2p){
    if (!p2p) return false;
    auto peers = p2p->snapshot_peers();
    for (const auto& s : peers){
        if (s.verack_ok) return true;
    }
    return false;
}


// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                                 Log capture                                 */
// ╚═══════════════════════════════════════════════════════════════════════════╝
class LogCapture {
public:
    struct Line { std::string text; uint64_t ts_ms; };

    void start() {
        running_ = true;
#ifdef _WIN32
        setvbuf(stdout, nullptr, _IONBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        if (_pipe(out_pipe_, 64 * 1024, _O_BINARY | _O_NOINHERIT) != 0) { running_ = false; return; }
        if (_pipe(err_pipe_, 64 * 1024, _O_BINARY | _O_NOINHERIT) != 0) { running_ = false; return; }
        old_out_ = _dup(_fileno(stdout));
        old_err_ = _dup(_fileno(stderr));
        _dup2(out_pipe_[1], _fileno(stdout));
        _dup2(err_pipe_[1], _fileno(stderr));
        reader_out_ = std::thread([this]{ readerLoop(out_pipe_[0]); });
        reader_err_ = std::thread([this]{ readerLoop(err_pipe_[0]); });
#else
        setvbuf(stdout, nullptr, _IOLBF, 0);
        setvbuf(stderr, nullptr, _IONBF, 0);
        if (pipe(out_pipe_) != 0) { running_ = false; return; }
        if (pipe(err_pipe_) != 0) { running_ = false; return; }
        old_out_ = dup(STDOUT_FILENO);
        old_err_ = dup(STDERR_FILENO);
        dup2(out_pipe_[1], STDOUT_FILENO);
        dup2(err_pipe_[1], STDERR_FILENO);
        reader_out_ = std::thread([this]{ readerLoop(out_pipe_[0]); });
        reader_err_ = std::thread([this]{ readerLoop(err_pipe_[0]); });
#endif
    }
    void stop() {
        if (!running_) return;
        running_ = false;
#ifdef _WIN32
        if (old_out_ != -1) { _dup2(old_out_, _fileno(stdout)); _close(old_out_); old_out_ = -1; }
        if (old_err_ != -1) { _dup2(old_err_, _fileno(stderr)); _close(old_err_); old_err_ = -1; }
        for (int i=0;i<2;i++){ if (out_pipe_[i] != -1) _close(out_pipe_[i]); out_pipe_[i] = -1; }
        for (int i=0;i<2;i++){ if (err_pipe_[i] != -1) _close(err_pipe_[i]); err_pipe_[i] = -1; }
#else
        if (old_out_ != -1) { dup2(old_out_, STDOUT_FILENO); close(old_out_); old_out_ = -1; }
        if (old_err_ != -1) { dup2(old_err_, STDERR_FILENO); close(old_err_); old_err_ = -1; }
        for (int i=0;i<2;i++){ if (out_pipe_[i] != -1) close(out_pipe_[i]); out_pipe_[i] = -1; }
        for (int i=0;i<2;i++){ if (err_pipe_[i] != -1) close(err_pipe_[i]); err_pipe_[i] = -1; }
#endif
        if (reader_out_.joinable()) reader_out_.join();
        if (reader_err_.joinable()) reader_err_.join();
    }
    ~LogCapture(){ stop(); }

    void drain(std::deque<Line>& into, size_t max_keep=2400) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& s : pending_) {
            lines_.push_back({sanitize_line(s), now_ms()});
            if (lines_.size() > max_keep) lines_.pop_front();
        }
        pending_.clear();
        into = lines_;
    }
private:
    static std::string sanitize_line(const std::string& s){
        auto red = s;
        auto scrub = [&](const char* key){
            size_t pos = 0;
            while((pos = red.find(key, pos)) != std::string::npos){
                size_t end = red.find_first_of(" \t\r\n", pos + std::strlen(key));
                if (end == std::string::npos) end = red.size();
                red.replace(pos, end - pos, std::string(key) + "***");
                pos += std::strlen(key) + 3;
            }
        };
        scrub("MIQ_RPC_TOKEN=");
        scrub("Authorization:");
        scrub("X-Auth-Token:");
        return red;
    }
    void readerLoop(int readfd){
        std::string buf; buf.reserve(4096);
        char tmp[1024];
        while (running_) {
#ifdef _WIN32
            int n = _read(readfd, tmp, (unsigned)sizeof(tmp));
            if (n <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue; }
#else
            ssize_t n = ::read(readfd, tmp, sizeof(tmp));
            if (n <= 0) { std::this_thread::sleep_for(std::chrono::milliseconds(5)); continue; }
#endif
            int nn = (int)n;
            for (int i=0; i<nn; ++i) {
                char c = tmp[i];
                if (c == '\r') continue;
                if (c == '\n') {
                    std::lock_guard<std::mutex> lk(mu_);
                    if (!buf.empty()) pending_.push_back(buf);
                    buf.clear();
                } else {
                    buf.push_back(c);
                }
            }
        }
    }
private:
    std::atomic<bool> running_{false};
    int out_pipe_[2]{-1,-1}, err_pipe_[2]{-1,-1};
    int old_out_{-1}, old_err_{-1};
    std::thread reader_out_, reader_err_;
    std::mutex mu_;
    std::vector<std::string> pending_;
    std::deque<Line> lines_;
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                                Pro TUI 3 Ultra                              */
// ╚═══════════════════════════════════════════════════════════════════════════╝
class TUI {
public:
    enum class NodeState { Starting, Syncing, Running, Degraded, Quitting };

    explicit TUI(bool vt_ok, bool u8_ok) : vt_ok_(vt_ok), u8_ok_(u8_ok) { init_step_order(); }
    void set_enabled(bool on){ enabled_ = on; }
    void start() {
        if (!enabled_) return;
        if (vt_ok_) cw_.write_raw("\x1b[2J\x1b[H\x1b[?25l");
        draw_once(true);
        key_thr_ = std::thread([this]{ key_loop(); });
        thr_     = std::thread([this]{ loop(); });
    }
    void stop() {
        if (!enabled_) return;
        running_ = false;
        key_running_ = false;
        if (thr_.joinable()) thr_.join();
        if (key_thr_.joinable()) key_thr_.join();
        if (vt_ok_) cw_.write_raw("\x1b[?25h\x1b[0m\n");
    }
    ~TUI(){ stop(); }

    // startup steps
    void mark_step_started(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); }
    void mark_step_ok(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); set_step(title, true); }
    void mark_step_fail(const std::string& title){ std::lock_guard<std::mutex> lk(mu_); ensure_step(title); failures_.insert(title); }

    // runtime refs
    void set_runtime_refs(P2P* p2p, Chain* chain, Mempool* mempool) { p2p_ = p2p; chain_ = chain; mempool_ = mempool; }
    void set_ports(uint16_t p2pport, uint16_t rpcport) { p2p_port_ = p2pport; rpc_port_ = rpcport; }
    void set_node_state(NodeState st){ std::lock_guard<std::mutex> lk(mu_); nstate_ = st; }
    void set_datadir(const std::string& d){ std::lock_guard<std::mutex> lk(mu_); datadir_ = d; }

    // mining gate
    void set_mining_gate(bool available, const std::string& reason){
        std::lock_guard<std::mutex> lk(mu_);
        mining_gate_available_ = available;
        mining_gate_reason_ = reason;
    }

    // logs in
    void feed_logs(const std::deque<LogCapture::Line>& raw_lines) {
        std::lock_guard<std::mutex> lk(mu_);
        if (!paused_) {
            logs_.clear(); logs_.reserve(raw_lines.size());
            for (auto& L : raw_lines){
                logs_.push_back(stylize_log(L));
            }
        }
        // Drain telemetry
        std::vector<BlockSummary> nb; std::vector<std::string> ntx;
        g_telemetry.drain(nb, ntx);
        for (auto& b : nb) {
            if (recent_blocks_.empty() || recent_blocks_.back().height != b.height || recent_blocks_.back().hash_hex != b.hash_hex) {
                recent_blocks_.push_back(b);
                telemetry_flush_disk(b);
                while (recent_blocks_.size() > 64) recent_blocks_.pop_front();
            }
        }
        for (auto& t : ntx) {
            if (recent_txid_set_.insert(t).second) {
                recent_txids_.push_back(t);
                while (recent_txids_.size() > 18) { recent_txid_set_.erase(recent_txids_.front()); recent_txids_.pop_front(); }
            }
        }
    }

    // HUD
    void set_banner(const std::string& s){ std::lock_guard<std::mutex> lk(mu_); banner_ = s; }
    void set_startup_eta(double secs){ std::lock_guard<std::mutex> lk(mu_); eta_secs_ = secs; }
    void set_shutdown_phase(const std::string& phase, bool ok){
        std::lock_guard<std::mutex> lk(mu_);
        shutdown_phase_ = phase; shutdown_ok_ = ok ? 1 : 0;
    }
    bool is_enabled() const { return enabled_; }

    void set_health_degraded(bool b){ std::lock_guard<std::mutex> lk(mu_); degraded_override_ = b; }
    void set_hot_warning(const std::string& w){ std::lock_guard<std::mutex> lk(mu_); hot_warning_ = w; hot_warn_ts_ = now_ms(); }
    void set_banner_append(const std::string& tail){ std::lock_guard<std::mutex> lk(mu_); if (!banner_.empty()) banner_ += "  "; banner_ += tail; }
    void set_ibd_progress(uint64_t cur, uint64_t target, uint64_t discovered_from_seed,
                          const std::string& stage, const std::string& seed_host,
                          bool finished){
        std::lock_guard<std::mutex> lk(mu_);
        ibd_cur_ = cur; ibd_target_ = std::max(target, cur); ibd_discovered_ = discovered_from_seed;
        ibd_stage_ = stage; ibd_seed_host_ = seed_host; ibd_done_ = finished; ibd_visible_ = !finished;
        ibd_last_update_ms_ = now_ms();
    }

private:
    struct StyledLine { std::string txt; int level; };
    StyledLine stylize_log(const LogCapture::Line& L){
        const std::string& s = L.text;
        StyledLine out{ s, 0 };
        if      (s.find("[FATAL]") != std::string::npos || s.find("[ERROR]") != std::string::npos) out.level=2;
        else if (s.find("[WARN]")  != std::string::npos) out.level=1;
        else if (s.find("accepted block") != std::string::npos || s.find("mined block accepted") != std::string::npos) out.level=4;
        else if (s.find("[TRACE]") != std::string::npos) out.level=3;
        else if (global::tui_verbose.load()) out.level=3;
        return out;
    }
    void init_step_order(){
        static const char* order[] = {
            "Parse CLI / environment",
            "Load config & choose datadir",
            "Config/datadir ready",
            "Open chain data",
            "Load & validate genesis",
            "Genesis OK",
            "Reindex UTXO (full scan)",
            "Initialize mempool & RPC",
            "Start P2P listener",
            "Connect seeds",
            "Peer handshake (verack)",
            "Start IBD monitor",
            "IBD sync phase",         // <── shown explicitly
            "Start RPC server",
            "RPC ready"
        };
        for (const char* s : order) steps_.push_back({s, false});
    }
    void ensure_step(const std::string& title){
        for (auto& s : steps_) if (s.first == title) return;
        steps_.push_back({title, false});
    }
    void set_step(const std::string& title, bool ok){
        for (auto& s : steps_) if (s.first == title){ s.second = ok; return; }
        steps_.push_back({title, ok});
    }

    const char* C_reset() const { return vt_ok_ ? "\x1b[0m" : ""; }
    const char* C_info()  const { return vt_ok_ ? (dark_theme_? "\x1b[36m":"\x1b[34m") : ""; }
    const char* C_warn()  const { return vt_ok_ ? "\x1b[33m" : ""; }
    const char* C_err()   const { return vt_ok_ ? "\x1b[31m" : ""; }
    const char* C_dim()   const { return vt_ok_ ? "\x1b[90m" : ""; }
    const char* C_head()  const { return vt_ok_ ? (dark_theme_? "\x1b[35m":"\x1b[35m") : ""; }
    const char* C_ok()    const { return vt_ok_ ? "\x1b[32m" : ""; }
    const char* C_bold()  const { return vt_ok_ ? "\x1b[1m"  : ""; }

    static std::string fit(const std::string& s, int w){
        if (w <= 0) return std::string();
        if ((int)s.size() <= w) return s;
        if (w <= 3) return std::string((size_t)w, '.');
        return s.substr(0, (size_t)w-3) + "...";
    }

    size_t distinct_miners_recent(size_t window) const {
        std::unordered_set<std::string> uniq;
        size_t n = recent_blocks_.size();
        size_t start = (n > window) ? (n - window) : 0;
        for (size_t i = start; i < n; ++i) {
            const auto& b = recent_blocks_[i];
            if (!b.miner.empty()) uniq.insert(b.miner);
        }
        return uniq.size();
    }

    void key_loop(){
        key_running_ = true;
#ifdef _WIN32
        while (key_running_){
            if (_kbhit()){
                int c = _getch();
                handle_key(c);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(16));
            }
        }
#else
        termios oldt{};
        if (tcgetattr(STDIN_FILENO, &oldt) == 0){
            termios newt = oldt;
            newt.c_lflag &= ~(ICANON | ECHO);
            newt.c_cc[VMIN]  = 0;
            newt.c_cc[VTIME] = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
        }
        while (key_running_){
            unsigned char c=0;
            ssize_t n = ::read(STDIN_FILENO, &c, 1);
            if (n == 1) handle_key((int)c);
            else std::this_thread::sleep_for(std::chrono::milliseconds(16));
        }
        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    }
    void handle_key(int c){
        switch(c){
            case 'q': case 'Q': request_shutdown("key"); break;
            case 't': case 'T': global::tui_toggle_theme.store(true); break;
            case 'p': case 'P': { std::lock_guard<std::mutex> lk(mu_); paused_ = !paused_; } break;
            case 's': case 'S': global::tui_snapshot_requested.store(true); break;
            case 'v': case 'V': global::tui_verbose.store(!global::tui_verbose.load()); break;
            case 'r': case 'R': global::reload_requested.store(true); break;
            default: break;
        }
    }

    void loop(){
        using clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;
        running_ = true;
        auto last_hs_time = clock::now();
        uint64_t last_stats_ms = now_ms();
        uint64_t last_net_ms   = now_ms();
        while (running_) {
            if(global::tui_toggle_theme.exchange(false)) { std::lock_guard<std::mutex> lk(mu_); dark_theme_ = !dark_theme_; }
            draw_once(false);
            std::this_thread::sleep_for(std::chrono::milliseconds(vt_ok_ ? 8 : 75));
            ++tick_;
            if((clock::now()-last_hs_time) > 250ms){
                last_hs_time = clock::now();
                std::lock_guard<std::mutex> lk(mu_);
                spark_hs_.push_back(g_miner_stats.hps.load());
                if(spark_hs_.size() > 90) spark_hs_.erase(spark_hs_.begin());
            }
            if (global::tui_snapshot_requested.exchange(false)) snapshot_to_disk();
            if (now_ms() - last_stats_ms > 1000) last_stats_ms = now_ms();
            if (now_ms() - last_net_ms > 1000){
                last_net_ms = now_ms();
                double nh = estimate_network_hashrate(chain_);
                std::lock_guard<std::mutex> lk(mu_);
                net_hashrate_ = nh;
                net_spark_.push_back(nh);
                if (net_spark_.size() > 90) net_spark_.erase(net_spark_.begin());
            }
        }
    }

    void snapshot_to_disk(){
        if (datadir_.empty()) return;
        int cols, rows; term::get_winsize(cols, rows);
        std::ostringstream out;
        out << "MIQROCHAIN TUI snapshot ("<< now_s() <<")\n";
        out << "Screen: " << cols << "x" << rows << "\n\n";
        out << "[System]\n";
        out << "uptime=" << uptime_s_ << "s  rss=" << get_rss_bytes() << " bytes\n";
        out << "[Chain]\n";
        out << "height=" << (chain_?chain_->height():0) << "\n";
        out << "[Peers]\n";
        if (p2p_){ out << "peers=" << p2p_->snapshot_peers().size() << "\n"; }
        out << "\n[Logs tail]\n";
        int take = 60;
        int start = (int)logs_.size() - take; if (start < 0) start = 0;
        for (int i=start; i<(int)logs_.size(); ++i) out << logs_[i].txt << "\n";
        std::string path = p_join(datadir_, "tui_snapshot.txt");
        write_text_atomic(path, out.str());
        hot_message_ = std::string("Snapshot saved -> ") + path;
        hot_msg_ts_ = now_ms();
    }

    bool miner_running_badge() const {
        const bool miner_on = g_miner_stats.active.load() && g_miner_stats.threads.load() > 0;
        const bool node_run = (nstate_ == NodeState::Running);
        return miner_on && node_run;
    }

    void draw_once(bool first){
        std::lock_guard<std::mutex> lk(mu_);
        int cols, rows; term::get_winsize(cols, rows);
        if (cols < 114) cols = 114;
        if (rows < 34) rows = 34;
        const int rightw = std::max(50, cols / 3);
        const int leftw  = cols - rightw - 3;

        std::vector<std::string> left, right;

        // Header bar
        {
            std::ostringstream h;
            if (!first && vt_ok_) h << "\x1b[H\x1b[0J";
            std::string bullet = u8_ok_ ? " • " : " | ";
            h << C_head() << "MIQROCHAIN" << C_reset()
              << "  " << C_dim()
              << "v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
              << bullet << "Chain: " << CHAIN_NAME
              << bullet << "P2P " << p2p_port_ << bullet << "RPC " << rpc_port_ << C_reset()
              << "  " << spinner(tick_, u8_ok_) ;
            left.push_back(h.str());
            left.push_back("");
            if(!banner_.empty()){
                left.push_back(std::string("  ") + C_info() + banner_ + C_reset());
            }
            if (!hot_message_.empty() && (now_ms() - hot_msg_ts_) < 4000){
                left.push_back(std::string("  ") + C_warn() + hot_message_ + C_reset());
            }
            left.push_back(std::string("  ") + straight_line(leftw-2));
            left.push_back("");
        }

        // System panel
        {
            left.push_back(std::string(C_bold()) + "System" + C_reset());
            uptime_s_ = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_tp_).count();
            uint64_t rss = get_rss_bytes();
            std::ostringstream ln;
            ln << "  uptime: " << uptime_s_ << "s"
               << "   rss: " << fmt_bytes(rss)
               << "   hw-threads: " << std::thread::hardware_concurrency();
            left.push_back(ln.str());
            left.push_back(std::string("  theme: ") + (dark_theme_? "dark":"light")
                          + "   logs: " + (paused_? "paused":"live")
                          + "   verbose: " + (global::tui_verbose.load()? "yes":"no"));
            left.push_back("");
        }

        // Node state panel
        {
            std::ostringstream s;
            s << C_bold() << "Node" << C_reset() << "   State: ";
            NodeState show_state = nstate_;
            if (degraded_override_) show_state = NodeState::Degraded;
            switch(show_state){
                case NodeState::Starting: s << C_warn() << "starting" << C_reset(); break;
                case NodeState::Syncing:  s << C_warn() << "syncing"  << C_reset(); break;
                case NodeState::Running:  s << C_ok()   << "running"  << C_reset(); break;
                case NodeState::Degraded: s << C_err()  << "degraded" << C_reset(); break;
                case NodeState::Quitting: s << C_warn() << "shutting down" << C_reset(); break;
            }
            if (miner_running_badge()){
                s << "   " << C_bold() << (u8_ok_ ? (std::string(C_ok()) + "⛏ RUNNING" + C_reset())
                                                  : (std::string(C_ok()) + "MINER" + C_reset()));
            }
            left.push_back(s.str());
            left.push_back("");
        }

        // Startup progress
        {
            left.push_back(std::string(C_bold()) + "Startup" + C_reset());
            size_t total = steps_.size(), okc = 0;
            for (auto& s : steps_) if (s.second) ++okc;
            int bw = std::max(10, leftw - 20);
            double frac = (double)okc / std::max<size_t>(1,total);
            std::ostringstream progress;
            progress << "  " << bar(bw, frac, vt_ok_, u8_ok_) << "  "
                     << okc << "/" << total << " completed";
            if (eta_secs_ > 0 && frac < 0.999){
                progress << "  " << C_dim() << "(~" << std::fixed << std::setprecision(1) << eta_secs_ << "s)" << C_reset();
            }
            left.push_back(progress.str());
            for (auto& s : steps_) {
                bool ok = s.second;
                bool failed = failures_.count(s.first) > 0;
                std::ostringstream ln;
                ln << "    ";
                if (ok)         ln << C_ok()  << "[OK]    " << C_reset();
                else if (failed)ln << C_err() << "[FAIL]  " << C_reset();
                else            ln << C_dim() << "[..]    " << C_reset();
                ln << s.first;
                left.push_back(ln.str());
            }
            left.push_back("");
        }

        {
            if (nstate_ == NodeState::Syncing || ibd_visible_ || (!ibd_done_ && ibd_target_ > 0)) {
                left.push_back(std::string(C_bold()) + "Initial Block Download" + C_reset());
                std::ostringstream meta;
                if (!ibd_seed_host_.empty()) meta << "  seed: " << ibd_seed_host_ << "   ";
                meta << "stage: " << (ibd_stage_.empty() ? "discovering" : ibd_stage_);
                left.push_back(meta.str());
                if (ibd_target_ > ibd_cur_) {
                int bw = std::max(10, leftw - 20);
                double frac = std::min(1.0, (ibd_target_ ? (double)ibd_cur_ / (double)ibd_target_ : 0.0));
                std::ostringstream p;
                p << "  " << bar(bw, frac, vt_ok_, u8_ok_) << "  "
                  << ibd_cur_ << "/" << ibd_target_ << " blocks  ("
                  << std::fixed << std::setprecision(1) << (frac * 100.0) << "%)";
                left.push_back(p.str());
            } else {
                // Facts only: show what we've actually found so far.
                std::ostringstream p;
                p << "  scanned so far: " << ibd_cur_ << " blocks";
                left.push_back(p.str());
            }
            std::ostringstream d;
            d << "  discovered from seed: " << ibd_discovered_;
                if (ibd_done_) d << "   " << C_ok() << "complete" << C_reset();
                left.push_back(d.str());
                left.push_back("");
            }
        }

        // Chain status
        {
            left.push_back(std::string(C_bold()) + "Chain" + C_reset());
            uint64_t height = chain_ ? chain_->height() : 0;
            std::string tip_hex;
            long double tip_diff = 0.0L;
            uint64_t tip_age_s = 0;
            if (chain_) {
                auto t = chain_->tip();
                tip_hex = to_hex(t.hash);
                tip_diff = difficulty_from_bits(hdr_bits(t));
                uint64_t tsec = hdr_time(t);
                if (tsec) {
                    uint64_t now = (uint64_t)std::time(nullptr);
                    tip_age_s = (now > tsec) ? (now - tsec) : 0;
                }
            }
            left.push_back(std::string("  height: ") + std::to_string(height)
                          + "   tip: " + short_hex(tip_hex, 12));
            left.push_back(std::string("  tip age: ") + std::to_string(tip_age_s) + "s"
                          + "   difficulty: " + fmt_diff(tip_diff));
            left.push_back(std::string("  net hashrate: ") + fmt_hs(net_hashrate_));
            left.push_back(std::string("  trend:        ") + spark_ascii(net_spark_));
            size_t N = recent_blocks_.size();
            size_t show = std::min<size_t>(8, N);
            for (size_t i=0;i<show;i++){
                const auto& b = recent_blocks_[N-1-i];
                std::ostringstream ln;
                ln << "  h=" << b.height
                   << "  txs=" << (b.tx_count ? std::to_string(b.tx_count) : std::string("?"))
                   << "  fees=" << (b.fees_known ? std::to_string(b.fees) : std::string("?"))
                   << "  hash=" << short_hex(b.hash_hex.empty() ? std::string("(?)") : b.hash_hex, 12);
                if (!b.miner.empty()) ln << "  miner=" << b.miner;
                left.push_back(ln.str());
            }
            if (N==0) left.push_back("  (no blocks yet)");
            left.push_back("");
        }

        // Right column: Network/Mempool/Miner/Health/Logs
        if (p2p_) {
            right.push_back(std::string(C_bold()) + "Network" + C_reset());
            auto peers = p2p_->snapshot_peers();

            std::stable_sort(peers.begin(), peers.end(), [](const auto& a, const auto& b){
                if (a.verack_ok != b.verack_ok) return a.verack_ok > b.verack_ok;
                if (a.last_seen_ms != b.last_seen_ms) return a.last_seen_ms < b.last_seen_ms;
                if (a.rx_buf != b.rx_buf) return a.rx_buf < b.rx_buf;
                return a.inflight < b.inflight;
            });

            size_t peers_n = peers.size();
            size_t inflight_tx = 0, rxbuf_sum = 0, awaiting_pongs = 0, verack_ok = 0;
            for (auto& s : peers) { inflight_tx += (size_t)s.inflight; rxbuf_sum += (size_t)s.rx_buf; if (s.awaiting_pong) ++awaiting_pongs; if (s.verack_ok) ++verack_ok; }
            right.push_back(std::string("  peers: ") + std::to_string(peers_n)
                            + "   verack_ok: " + std::to_string(verack_ok)
                            + "   inflight: " + std::to_string(inflight_tx)
                            + "   rxbuf: " + std::to_string(rxbuf_sum)
                            + "   pings-waiting: " + std::to_string(awaiting_pongs));
            std::ostringstream hdr;
            hdr << "    " << std::left << std::setw(18) << "IP"
                << " " << std::setw(5) << "ok"
                << " " << std::setw(8) << "last(ms)"
                << " " << std::setw(7) << "rx"
                << " " << std::setw(8) << "inflight";
            right.push_back(hdr.str());
            size_t showN = std::min(peers.size(), (size_t)8);
            for (size_t i=0;i<showN; ++i) {
                const auto& s = peers[i];
                std::string ip = s.ip; if ((int)ip.size() > 18) ip = ip.substr(0,15) + "...";
                std::ostringstream ln;
                ln << "    " << std::left << std::setw(18) << ip
                   << " " << std::setw(5) << (s.verack_ok ? (std::string(C_ok()) + "ok" + C_reset()) : (std::string(C_warn()) + ".." + C_reset()))
                   << " " << std::right << std::setw(8) << (uint64_t)s.last_seen_ms
                   << " " << std::setw(7) << (uint64_t)s.rx_buf
                   << " " << std::setw(8) << (uint64_t)s.inflight;
                right.push_back(ln.str());
            }
            if (peers.size() > showN) right.push_back(std::string("    ... +") + std::to_string(peers.size()-showN) + " more");
            right.push_back("");
        }

        if (mempool_) {
            right.push_back(std::string(C_bold()) + "Mempool" + C_reset());
            auto stat = mempool_view_fallback(mempool_);
            right.push_back(std::string("  txs: ") + std::to_string(stat.count)
                            + (stat.bytes? (std::string("   bytes: ") + fmt_bytes(stat.bytes)) : std::string())
                            + (stat.recent_adds? (std::string("   recent_adds: ") + std::to_string(stat.recent_adds)) : std::string()));
            right.push_back("");
        }

        {
            right.push_back(std::string(C_bold()) + "Mining" + C_reset());
            bool active = g_miner_stats.active.load();
            unsigned thr = g_miner_stats.threads.load();
            uint64_t ok  = g_miner_stats.accepted.load();
            uint64_t rej = g_miner_stats.rejected.load();
            double   hps = g_miner_stats.hps.load();
            uint64_t miner_uptime = 0;
            if (active) {
                miner_uptime = (uint64_t)std::chrono::duration_cast<std::chrono::seconds>(
                    std::chrono::steady_clock::now() - g_miner_stats.start).count();
            }

            std::ostringstream m0;
            m0 << "  available: " << (mining_gate_available_ ? (std::string(C_ok())+"yes"+C_reset()) :
                                                       (std::string(C_warn())+"no"+C_reset()));
            if (!mining_gate_reason_.empty()) m0 << "  (" << mining_gate_reason_ << ")";
            right.push_back(m0.str());

            std::ostringstream m1;
            m1 << "  status: " << (active ? (std::string(C_ok()) + "running" + C_reset()) : (std::string(C_dim()) + "idle" + C_reset()))
               << "   threads: " << thr
               << "   ext: " << (g_extminer.alive.load() ? (std::string(C_ok()) + "alive" + C_reset()) : (std::string(C_dim()) + "-" + C_reset()));
            right.push_back(m1.str());

            if (!g_miner_address_b58.empty()) {
                right.push_back(std::string("  to: ") + g_miner_address_b58);
            }

            std::ostringstream m2; m2 << "  accepted: " << ok << "   rejected: " << rej; right.push_back(m2.str());
            right.push_back(std::string("  miner hashrate: ") + fmt_hs(hps));
            right.push_back(std::string("  miner uptime: ") + std::to_string(miner_uptime) + "s");
            right.push_back(std::string("  miner trend:    ") + spark_ascii(spark_hs_));
            double share = (net_hashrate_ > 0.0) ? (hps / net_hashrate_) * 100.0 : 0.0;
            if (share < 0.0) share = 0.0;
            if (share > 100.0) share = 100.0;
            std::ostringstream m3; m3 << "  network (est):  " << fmt_hs(net_hashrate_)
                                      << "   your share: " << std::fixed << std::setprecision(3) << share << "%";
            right.push_back(m3.str());
            size_t miners_obs = distinct_miners_recent(64);
            std::ostringstream m4; m4 << "  miners observed (last 64 blks): " << miners_obs;
            right.push_back(m4.str());
            std::ostringstream m5; m5 << "  last ok height: " << g_miner_stats.last_height_ok.load()
                                      << "   last rx height: " << g_miner_stats.last_height_rx.load();
            right.push_back(m5.str());

            right.push_back(std::string("  ") + C_dim() + "* count = distinct coinbase recipients seen by this node" + C_reset());
            right.push_back("");
        }

        {
            right.push_back(std::string(C_bold()) + "Health & Security" + C_reset());
            right.push_back(std::string("  config reload: ")
               + (global::reload_requested.load()? "pending" : (u8_ok_? "—" : "-")));
            if (!hot_warning_.empty() && now_ms()-hot_warn_ts_ < 6000){
                right.push_back(std::string("  ") + C_warn() + hot_warning_ + C_reset());
            }
            if (!datadir_.empty()){
                right.push_back(std::string("  datadir: ") + datadir_);
            }
            right.push_back("");
        }

        {
            right.push_back(std::string(C_bold()) + "Recent TXIDs" + C_reset());
            if (recent_txids_.empty()) right.push_back("  (no txids yet)");
            size_t n = std::min<size_t>(recent_txids_.size(), 10);
            for (size_t i=0;i<n;i++){
                right.push_back(std::string("  ") + short_hex(recent_txids_[recent_txids_.size()-1-i], 20));
            }
            right.push_back("");
        }

        std::ostringstream out;
        size_t NL = left.size(), NR = right.size(), N = std::max(NL, NR);
        for (size_t i=0;i<N;i++){
            std::string l = (i<NL) ? left[i] : "";
            std::string r = (i<NR) ? right[i] : "";
            if ((int)l.size() > leftw)  l = fit(l, leftw);
            if ((int)r.size() > rightw) r = fit(r, rightw);
            out << std::left << std::setw(leftw) << l << " | " << r << "\n";
        }

        out << std::string((size_t)cols, '-') << "\n";
        if (nstate_ == NodeState::Quitting){
            out << C_bold() << "Shutting down" << C_reset() << "  " << C_dim() << "(Ctrl+C again = force)" << C_reset() << "\n";
            std::string phase = shutdown_phase_.empty() ? "initiating..." : shutdown_phase_;
            out << "  phase: " << phase << "\n";
        } else {
            out << C_bold() << "Logs" << C_reset() << "  " << C_dim() << "(q=quit t=theme p=pause r=reload s=snap v=verbose)" << C_reset() << "\n";
        }
        int header_rows = (int)N + 2;
        int remain = rows - header_rows - 3;
        if (remain < 8) remain = 8;
        int start = (int)logs_.size() - remain;
        if (start < 0) start = 0;
        for (int i=start; i<(int)logs_.size(); ++i) {
            const auto& line = logs_[i];
            switch(line.level){
                case 2: out << C_err()  << line.txt << C_reset() << "\n"; break;
                case 1: out << C_warn() << line.txt << C_reset() << "\n"; break;
                case 3: out << C_dim()  << line.txt << C_reset() << "\n"; break;
                case 4: out << C_ok()   << line.txt << C_reset() << "\n"; break;
                default: out << line.txt << "\n"; break;
            }
        }
        int printed = (int)logs_.size() - start;
        for (int i=printed; i<remain; ++i) out << "\n";
        cw_.write_raw(out.str());
    }

private:
    bool enabled_{true};
    bool vt_ok_{true};
    bool u8_ok_{false};
    std::atomic<bool> running_{false};
    std::atomic<bool> key_running_{false};
    std::thread thr_, key_thr_;
    std::mutex mu_;

    std::vector<std::pair<std::string,bool>> steps_;
    std::set<std::string> failures_;
    std::vector<StyledLine> logs_;
    std::string banner_;
    std::string datadir_;
    uint16_t p2p_port_{P2P_PORT};
    uint16_t rpc_port_{RPC_PORT};
    P2P*   p2p_   {nullptr};
    Chain* chain_ {nullptr};
    Mempool* mempool_{nullptr};
    ConsoleWriter cw_;
    int  tick_{0};
    NodeState nstate_{NodeState::Starting};
    std::deque<BlockSummary> recent_blocks_;
    std::deque<std::string>  recent_txids_;
    std::unordered_set<std::string> recent_txid_set_;
    std::vector<double> spark_hs_;
    std::vector<double> net_spark_;
    double net_hashrate_{0.0};
    double eta_secs_{0.0};
    std::string shutdown_phase_;
    int shutdown_ok_{0};
    bool dark_theme_{true};
    bool paused_{false};
    bool degraded_override_{false};
    std::chrono::steady_clock::time_point start_tp_{std::chrono::steady_clock::now()};
    uint64_t uptime_s_{0};
    std::string hot_message_;
    uint64_t hot_msg_ts_{0};
    std::string hot_warning_;
    uint64_t hot_warn_ts_{0};

    bool        ibd_visible_{false};
    bool        ibd_done_{false};
    uint64_t    ibd_cur_{0};
    uint64_t    ibd_target_{0};
    uint64_t    ibd_discovered_{0};
    std::string ibd_stage_;
    std::string ibd_seed_host_;
    uint64_t    ibd_last_update_ms_{0};

    // mining gate status
    bool        mining_gate_available_{false};
    std::string mining_gate_reason_;
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                                Seed Sentinel                                 */
// ╚═══════════════════════════════════════════════════════════════════════════╝
class SeedSentinel {
public:
    void start(P2P* p2p, TUI* tui){
        stop();
        running_.store(true);
        thr_ = std::thread([=]{ loop(p2p, tui); });
    }
    void stop(){
        running_.store(false);
        if (thr_.joinable()) thr_.join();
    }
private:
    void loop(P2P* p2p, TUI* tui){
        using namespace std::chrono_literals;
        uint64_t last_note_ms = 0;
        while (running_.load() && !global::shutdown_requested.load()){
            auto role = compute_seed_role();
            bool prev = g_we_are_seed.load();
            g_we_are_seed.store(role.we_are_seed);
            if ((role.we_are_seed || g_assume_seed_hairpin.load()) && !prev){
                log_warn(std::string("This node matches/assumes ")+seed_host_cstr()+" — acting as seed; keep it healthy.");
                if (tui) tui->set_hot_warning("You are the public seed host");
            }
            // Gentle health checks
            size_t peers = p2p ? p2p->snapshot_peers().size() : 0;
            if ((role.we_are_seed || g_assume_seed_hairpin.load()) && peers == 0){
                if (now_ms() - last_note_ms > 30'000){
                    log_warn("SeedSentinel: 0 peers connected while acting as seed — check firewall/DNS.");
                    last_note_ms = now_ms();
                }
            }
            std::this_thread::sleep_for(10s);
        }
    }
    std::atomic<bool> running_{false};
    std::thread thr_;
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                          Fatal terminate hook                                */
// ╚═══════════════════════════════════════════════════════════════════════════╝
static void fatal_terminate() noexcept {
    std::fputs("[FATAL] std::terminate() called (background) - initiating shutdown\n", stderr);
    request_shutdown("terminate");
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                               Miner worker                                   */
// ╚═══════════════════════════════════════════════════════════════════════════╝
static uint64_t sum_coinbase_outputs(const Block& b) {
    if (b.txs.empty()) return 0;
    uint64_t s = 0; for (const auto& o : b.txs[0].vout) s += o.value; return s;
}
static void miner_worker(Chain* chain, Mempool* mempool, P2P* p2p,
                         const std::vector<uint8_t> mine_pkh,
                         unsigned threads) {
    g_miner_stats.active.store(true);
    g_miner_stats.threads.store(threads);
    g_miner_stats.start = std::chrono::steady_clock::now();

    std::random_device rd;
    const uint64_t seed =
        uint64_t(std::chrono::high_resolution_clock::now().time_since_epoch().count()) ^
        uint64_t(rd()) ^
        uint64_t(std::hash<std::thread::id>{}(std::this_thread::get_id()));
    std::mt19937_64 gen(seed);

    const size_t kBlockMaxBytes = 900 * 1024;

    while (!global::shutdown_requested.load()) {
        try {
            auto t = chain->tip();
            Transaction cbt; TxIn cin; cin.prev.txid = std::vector<uint8_t>(32, 0); cin.prev.vout = 0;
            cbt.vin.push_back(cin);
            TxOut cbout; cbout.value = chain->subsidy_for_height(t.height + 1);
            if (mine_pkh.size() != 20) {
                log_error(std::string("miner assign pkh fatal: pkh size != 20 (got ") + std::to_string(mine_pkh.size()) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(80));
                continue;
            }
            cbout.pkh.resize(20);
            std::memcpy(cbout.pkh.data(), mine_pkh.data(), 20);
            cbt.vout.push_back(cbout);
            cbt.lock_time = static_cast<uint32_t>(t.height + 1);

            const uint32_t ch = static_cast<uint32_t>(t.height + 1);
            const uint32_t now = static_cast<uint32_t>(time(nullptr));
            const uint64_t extraNonce = gen();
            std::vector<uint8_t> tag; tag.reserve(1+4+4+8);
            tag.push_back(0x01);
            tag.push_back(uint8_t(ch      & 0xff)); tag.push_back(uint8_t((ch>>8) & 0xff));
            tag.push_back(uint8_t((ch>>16)& 0xff)); tag.push_back(uint8_t((ch>>24)& 0xff));
            tag.push_back(uint8_t(now      & 0xff)); tag.push_back(uint8_t((now>>8) & 0xff));
            tag.push_back(uint8_t((now>>16)& 0xff)); tag.push_back(uint8_t((now>>24)& 0xff));
            for (int i=0;i<8;i++) tag.push_back(uint8_t((extraNonce >> (8*i)) & 0xff));
            cbt.vin[0].sig = std::move(tag);

            std::vector<Transaction> txs;
            try {
                const size_t coinbase_sz = ser_tx(cbt).size();
                const size_t budget = (kBlockMaxBytes > coinbase_sz) ? (kBlockMaxBytes - coinbase_sz) : 0;
                auto cands = mempool->collect(120000);
                size_t used=0;
                for (auto& tx : cands) {
                    size_t sz = ser_tx(tx).size();
                    if (used + sz > budget) continue;
                    txs.emplace_back(std::move(tx));
                    used += sz;
                    if (used >= budget) break;
                }
            } catch(...) { txs.clear(); }

            Block b;
            try {
                auto last = chain->last_headers(MIQ_RETARGET_INTERVAL);
                uint32_t nb = miq::epoch_next_bits(
                    last, BLOCK_TIME_SECS, GENESIS_BITS,
                    /*next_height=*/ t.height + 1, /*interval=*/ MIQ_RETARGET_INTERVAL);
                b = miq::mine_block(t.hash, nb, cbt, txs, threads);
            } catch (...) {
                log_error("miner mine_block fatal");
                continue;
            }

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
                    g_miner_stats.accepted.fetch_add(1);
                    g_miner_stats.last_height_ok.store(t.height + 1);
                    g_miner_stats.last_height_rx.store(t.height + 1);

                    BlockSummary bs;
                    bs.height    = t.height + 1;
                    bs.hash_hex  = to_hex(b.block_hash());
                    bs.tx_count  = (uint32_t)b.txs.size();
                    uint64_t coinbase_total = sum_coinbase_outputs(b);
                    uint64_t subsidy = chain->subsidy_for_height(bs.height);
                    if (coinbase_total >= subsidy) { bs.fees = coinbase_total - subsidy; bs.fees_known = true; }
                    bs.miner = miner_addr;
                    g_telemetry.push_block(bs);
                    if (noncb > 0) {
                        std::vector<std::string> txids; txids.reserve((size_t)noncb);
                        for (size_t i=1;i<b.txs.size();++i) txids.push_back(to_hex(b.txs[i].txid()));
                        g_telemetry.push_txids(txids);
                    }

                    log_info("mined block accepted, height=" + std::to_string(bs.height)
                             + ", miner=" + miner_addr
                             + ", coinbase_txid=" + cb_txid_hex
                             + ", txs=" + std::to_string(std::max(0, noncb))
                             + (bs.fees_known ? (", fees=" + std::to_string(bs.fees)) : ""));
                    if (!global::shutdown_requested.load() && p2p) {
                        p2p->announce_block_async(b.block_hash());
                    }
                } else {
                    g_miner_stats.rejected.fetch_add(1);
                    log_warn(std::string("mined block rejected: ") + err);
                }
            } catch (...) {
                log_error("miner submit_block fatal");
            }

        } catch (...) {
            log_error("miner outer fatal");
            std::this_thread::sleep_for(std::chrono::milliseconds(80));
        }
    }
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                                     CLI                                     */
// ╚═══════════════════════════════════════════════════════════════════════════╝
static void print_usage(){
    std::cout
      << "miqrod (node) options:\n"
      << "  --conf=<path>                                config file (key=value)\n"
      << "  --datadir=<path>                             data directory (overrides config)\n"
      << "  --no-tui                                     disable the Pro TUI (plain logs)\n"
      << "  --genaddress                                 generate ECDSA-P2PKH address (priv/pk/address)\n"
      << "  --buildtx <priv_hex> <prev_txid_hex> <vout> <value> <to_address>  (prints txhex)\n"
      << "  --reindex_utxo                               rebuild chainstate/UTXO from current chain\n"
      << "  --mine                                       run built-in miner (interactive address prompt; starts when synced)\n"
      << "  --telemetry                                  write block accepts to telemetry.ndjson in datadir\n"
      << "\n"
      << "Env:\n"
      << "  MIQ_NO_TUI=1               disables the TUI; plain logs\n"
      << "  MIQ_MINER_THREADS          overrides miner thread count\n"
      << "  MIQ_RPC_TOKEN              if set, HTTP gate token (synced to .cookie on start)\n"
      << "  MIQ_MINER_HEARTBEAT        path to heartbeat file for external miner presence\n"
      << "  MIQ_TUI_UTF8=1             OPT-IN: enable fancy Unicode UI on Windows consoles\n";
}
static bool is_recognized_arg(const std::string& s){
    if(s.rfind("--conf=",0)==0) return true;
    if(s.rfind("--datadir=",0)==0) return true;
    if(s=="--no-tui") return true;
    if(s=="--genaddress") return true;
    if(s=="--buildtx") return true;
    if(s=="--reindex_utxo") return true;
    if(s=="--mine") return true;
    if(s=="--telemetry") return true;
    if(s=="--help") return true;
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// IBD helpers — smart start/finish + explicit error on failure
// ─────────────────────────────────────────────────────────────────────────────
static inline bool path_exists_nonempty(const std::string& p){
    std::error_code ec;
    if(!std::filesystem::exists(p, ec)) return false;
    for (auto it = std::filesystem::directory_iterator(p, ec);
         it != std::filesystem::directory_iterator(); ++it) return true;
    return false;
}

static bool tip_fresh_enough(Chain& chain);
static bool has_existing_blocks_or_state(const std::string& datadir);

static bool should_enter_ibd_reason(Chain& chain, const std::string& datadir, std::string* why){
    auto tell = [&](const char* s){ if (why) *why = s; };
    // Fresh install / empty state: certainly need IBD.
    if (!path_exists_nonempty(p_join(datadir, "blocks")) &&
        !path_exists_nonempty(p_join(datadir, "chainstate"))) { tell("no local blocks/chainstate"); return true; }
    // No blocks known yet (only genesis): need headers/blocks.
    if (chain.height() == 0) { tell("no headers/blocks yet"); return true; }
    // Stale tip: need a catch-up IBD.
    if (!tip_fresh_enough(chain)) { tell("tip too old"); return true; }
    // Otherwise we are synced enough — skip IBD.
    tell("up to date");
    return false;
}

[[maybe_unused]] static bool has_existing_blocks_or_state(const std::string& datadir){
    return path_exists_nonempty(p_join(datadir, "blocks")) ||
           path_exists_nonempty(p_join(datadir, "chainstate"));
}
static bool tip_fresh_enough(Chain& chain){
    auto tip = chain.tip();
    uint64_t tsec = hdr_time(tip);
    if (tsec == 0) return false;
    uint64_t now = (uint64_t)std::time(nullptr);
    uint64_t age = (now > tsec) ? (now - tsec) : 0;
    const uint64_t fresh = std::max<uint64_t>(BLOCK_TIME_SECS * 3, 300);
    return age <= fresh;
}
static bool should_enter_ibd(Chain& chain, const std::string& datadir){
    return should_enter_ibd_reason(chain, datadir, nullptr);
}

// Active IBD loop: try to reach a "synced" state (compute_sync_gate true).
// Surfaces a concrete error if it can't finish.
static bool perform_ibd_sync(Chain& chain, P2P* p2p, const std::string& datadir,
                             bool can_tui, TUI* tui, std::string& out_err){
    {
        std::string reason;
        if (!should_enter_ibd_reason(chain, datadir, &reason)) {
            return true;
        } else {
            log_info(std::string("IBD: starting (reason: ") + reason + ")");
            if (tui && can_tui) tui->set_banner(std::string("Initial block download — ") + reason);
        }
    }
    bool we_are_seed = compute_seed_role().we_are_seed || g_assume_seed_hairpin.load();

    if (!p2p) {
        out_err = "P2P disabled (cannot sync headers/blocks)";
        return false;
    }

    

    using namespace std::chrono_literals;

    const uint64_t kNoPeerTimeoutMs      = 90 * 1000;
    const uint64_t kNoProgressTimeoutMs  = 180 * 1000;
    const uint64_t kStableOkMs           = 8 * 1000;
    const uint64_t kHandshakeTimeoutMs   = 60 * 1000;
    const uint64_t kSeedNudgeMs          = 10 * 1000;
    const uint64_t kMaxWallMs            = 30 * 60 * 1000;
    const uint64_t t0                    = now_ms();
    uint64_t       lastSeedDialMs        = 0;
    uint64_t       lastProgressMs        = now_ms();
    uint64_t       lastHeight            = chain.height();
    uint64_t       height_at_seed_connect= lastHeight;
    uint32_t       seed_dials            = 0;

    // Make sure we’ve nudged the seed right away.
    if (!we_are_seed) {
        p2p->connect_seed(seed_host_cstr(), P2P_PORT);
        lastSeedDialMs = now_ms();
        ++seed_dials;
    } else {
        log_info(std::string("Seed self-detect: skipping outbound connect to ")
                 + seed_host_cstr() + " (waiting for inbound peers).");
    }
    if (can_tui) tui->set_node_state(TUI::NodeState::Syncing);
    if (tui && can_tui) tui->mark_step_started("Peer handshake (verack)");
    {
        const uint64_t hs_t0 = now_ms();
        const uint64_t handshake_deadline_ms =
            we_are_seed ? (hs_t0 + 5 * 60 * 1000) : (hs_t0 + kHandshakeTimeoutMs);
        if (we_are_seed) {
            log_info("IBD: acting as seed host — waiting for inbound verack (up to ~5 min).");
            if (tui && can_tui) tui->set_banner("Seed mode: waiting for inbound peers…");
        }
        while (!global::shutdown_requested.load()) {
            if (any_verack_peer(p2p)) {
                height_at_seed_connect = chain.height();
                if (tui && can_tui) {
                    tui->mark_step_ok("Peer handshake (verack)");
                    tui->set_banner(std::string("Connected to seed: ") + seed_host_cstr());
                    tui->set_ibd_progress(chain.height(),
                                          chain.height(),
                                          0, "headers", seed_host_cstr(), false);
                }
                break; // proceed to IBD
            }
            // keep nudging the seed if needed
            if (!we_are_seed && (now_ms() - lastSeedDialMs > kSeedNudgeMs)) {
                p2p->connect_seed(seed_host_cstr(), P2P_PORT);
                lastSeedDialMs = now_ms();
                ++seed_dials;
                if (seed_dials >= 5) {
                    auto ips = resolve_host_ip_strings(seed_host_cstr());
                    bool any_public = false;
                    for (auto& ip : ips) { if (!is_private_v4(ip) && !is_loopback_or_linklocal(ip)) { any_public = true; break; } }
                    if (any_public && p2p && p2p->snapshot_peers().empty()){
                        g_assume_seed_hairpin.store(true);
                        we_are_seed = true;
                        log_warn("IBD: assuming SEED mode due to probable NAT hairpin (repeated seed dial fails with 0 peers).");
                        if (tui && can_tui) tui->set_banner("Seed solo mode (hairpin) — waiting for inbound peers…");
                    }
                }
            }

            if (now_ms() > handshake_deadline_ms) {
                if (we_are_seed) {
                    // SOLO-SEED: allow the node to proceed without peers so it can mine the first blocks.
                    log_warn("IBD: seed mode handshake timed out — entering SOLO-SEED mode (no peers yet).");
                    if (tui && can_tui) {
                        tui->mark_step_ok("Peer handshake (verack)");
                        tui->set_banner("Seed solo mode: no peers yet — mining unlocked.");
                        tui->set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                    }
                    return true; // treat IBD as trivially complete to unlock mining
                } else {
                    if (g_assume_seed_hairpin.load()){
                        log_warn("IBD: hairpin seed assumption during handshake — proceeding in SOLO-SEED mode.");
                        if (tui && can_tui) {
                            tui->mark_step_ok("Peer handshake (verack)");
                            tui->set_banner("Seed solo mode (hairpin) — mining unlocked.");
                            tui->set_ibd_progress(chain.height(), chain.height(), 0, "complete", seed_host_cstr(), true);
                        }
                        return true;
                    }
                    out_err = "no peers completed handshake (verack)";
                    if (tui && can_tui) tui->mark_step_fail("Peer handshake (verack)");
                    return false;
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        if (global::shutdown_requested.load()){
            out_err = "shutdown requested during handshake";
            if (tui && can_tui) tui->mark_step_fail("Peer handshake (verack)");
            return false;
        }
    }

    while (!global::shutdown_requested.load()) {
        // Hard wall clock timeout
        if (now_ms() - t0 > kMaxWallMs) { out_err = "IBD timeout (no completion within time budget)"; break; }

        // Ensure we periodically re-nudge the seed if peer count is low.
        size_t peers = p2p->snapshot_peers().size();
        if (!we_are_seed && peers < 2 && now_ms() - lastSeedDialMs > kSeedNudgeMs) {
            p2p->connect_seed(seed_host_cstr(), P2P_PORT);
            lastSeedDialMs = now_ms();
            ++seed_dials;
        }

        // Early no-peer failure
        const uint64_t no_peer_budget =
            we_are_seed ? (5 * 60 * 1000) : kNoPeerTimeoutMs;
        if (peers == 0 && now_ms() - t0 > no_peer_budget) {
            if (we_are_seed) {
                out_err = "no peers reachable while acting as seed (check DNS A/AAAA and firewall/NAT)";
            } else {
                out_err = std::string("no peers reachable (seed: ") + seed_host_cstr() + ":" + std::to_string(P2P_PORT) + ")";
            }
            break;
        }

        {
            uint64_t cur = chain.height();
            uint64_t discovered = (cur >= height_at_seed_connect) ? (cur - height_at_seed_connect) : 0;
            const char* stage = (cur == 0 ? "headers" : "blocks");
            if (tui && can_tui) {
                tui->set_ibd_progress(cur, cur, discovered, stage, seed_host_cstr(), false);
            } else {
                static uint64_t last_note_ms = 0;
                if (now_ms() - last_note_ms > 2500) {
                    log_info(std::string("[IBD] ") + stage + ": height=" +
                             std::to_string(cur) +
                             "  discovered-from-seed=" + std::to_string(discovered) +
                             (we_are_seed ? "  (seed-mode: waiting for inbound peers)" : ""));
                    last_note_ms = now_ms();
                }
            }
        }

        // Track progress by height advancing
        uint64_t h = chain.height();
        if (h > lastHeight) {
            lastHeight = h;
            lastProgressMs = now_ms();
        } else {
            // With peers but no header progress → fail after some time
            if (peers > 0 && now_ms() - lastProgressMs > kNoProgressTimeoutMs) {
                out_err = "no headers/blocks progress from peers";
                break;
            }
        }

        // Check "synced" state and require short stability window
        std::string why;
        if (compute_sync_gate(chain, p2p, why)) {
            const uint64_t okStart = now_ms();
            bool stable = true;
            while (now_ms() - okStart < kStableOkMs) {
                std::this_thread::sleep_for(200ms);
                if (!compute_sync_gate(chain, p2p, why)) { stable = false; break; }
            }
            if (stable) {
            if (tui && can_tui) {
                    tui->set_ibd_progress(chain.height(),
                                          chain.height(),
                                          (chain.height() >= height_at_seed_connect ? (chain.height() - height_at_seed_connect) : 0),
                                          "complete", seed_host_cstr(), true);
                }
                return true;
            }
        }

        std::this_thread::sleep_for(250ms);
    }

    if (global::shutdown_requested.load())
        out_err = "shutdown requested during IBD";

    return false;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                                 IBD Guard                                    */
// ╚═══════════════════════════════════════════════════════════════════════════╝
class IBDGuard {
public:
    void start(Chain* chain, P2P* p2p, const std::string& datadir, bool can_tui, TUI* tui){
        stop();
        running_.store(true);
        thr_ = std::thread([=]{ loop(chain, p2p, datadir, can_tui, tui); });
    }
    void stop(){
        running_.store(false);
        if (thr_.joinable()) thr_.join();
    }
private:
    void loop(Chain* chain, P2P* p2p, const std::string& datadir, bool can_tui, TUI* tui){
        using namespace std::chrono_literals;
        uint64_t backoff_ms = 2'000; // exponential up to 2 minutes
        while (running_.load() && !global::shutdown_requested.load()){
            if (p2p && solo_seed_mode(p2p)) {
                std::this_thread::sleep_for(3s);
                continue;
            }
            std::string why;
            bool gate = compute_sync_gate(*chain, p2p, why);
            if (!gate && should_enter_ibd(*chain, datadir)){
                std::string err;
                if (tui && can_tui){
                    tui->set_node_state(TUI::NodeState::Syncing);
                    tui->set_hot_warning("Re-entering IBD (" + (why.empty()?"stale/empty":why) + ")");
                }
                bool ok = perform_ibd_sync(*chain, p2p, datadir, can_tui, tui, err);
                if (!ok){
                    log_warn(std::string("IBDGuard: IBD attempt failed: ")+err);
                    std::this_thread::sleep_for(std::chrono::milliseconds(backoff_ms));
                    backoff_ms = std::min<uint64_t>(backoff_ms * 2, 120'000);
                } else {
                    log_info("IBDGuard: node resynced.");
                    backoff_ms = 2'000;
                    if (tui && can_tui) tui->set_node_state(TUI::NodeState::Running);
                }
            }
            std::this_thread::sleep_for(3s);
        }
    }
    std::atomic<bool> running_{false};
    std::thread thr_;
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
/*                                     main                                    */
// ╚═══════════════════════════════════════════════════════════════════════════╝
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);

#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT,  sigshutdown_handler);
    std::signal(SIGTERM, sigshutdown_handler);
    std::signal(SIGQUIT, sigshutdown_handler);
    std::signal(SIGABRT, sigshutdown_handler);
    std::signal(SIGHUP,  sighup_handler);
#else
    SetConsoleCtrlHandler(win_ctrl_handler, TRUE);
#endif
    std::set_terminate(&fatal_terminate);

    bool vt_ok = true, u8_ok = false;
    term::enable_vt_and_probe_u8(vt_ok, u8_ok);

    bool disable_tui_flag = false;
    bool telemetry_flag = false;
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a == "--no-tui") disable_tui_flag = true;
        if(a == "--telemetry") telemetry_flag = true;
    }
    const bool want_tui = !disable_tui_flag && !env_truthy_local("MIQ_NO_TUI");
    const bool can_tui  = want_tui && term::supports_interactive_output();

    ConsoleWriter cw;
    if (u8_ok)
        cw.write_raw("Starting miqrod…  (Ctrl+C to exit; Ctrl+C twice = force)\n");
    else
        cw.write_raw("Starting miqrod...  (Ctrl+C to exit; Ctrl+C twice = force)\n");

    LogCapture capture;
    if (can_tui) capture.start();
    else std::fprintf(stderr, "[INFO] TUI disabled (plain logs).\n");

    TUI tui(vt_ok, u8_ok);
    tui.set_enabled(can_tui);
    tui.set_ports(P2P_PORT, RPC_PORT);

    if (const char* sh = std::getenv("MIQ_SEED_HOST"); sh && *sh) {
        g_seed_host = sh;
    }

    // Parse CLI
    Config cfg;
    std::string conf;
    bool genaddr=false, buildtx=false, mine_flag=false, flag_reindex_utxo=false;
    std::string privh, prevtxid_hex, toaddr;
    uint32_t vout=0; uint64_t value=0;
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a.rfind("--",0)==0 && !is_recognized_arg(a)){
            std::fprintf(stderr, "Unknown option: %s\nUse --help to see supported options.\n", argv[i]);
            if (can_tui) { capture.stop(); tui.stop(); }
            return 2;
        }
    }
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a.rfind("--conf=",0)==0){ conf = a.substr(7);
        } else if(a.rfind("--datadir=",0)==0){ cfg.datadir = a.substr(10);
        }
    }
    for(int i=1;i<argc;i++){
        std::string a(argv[i]);
        if(a=="--genaddress"){ genaddr = true;
        } else if(a=="--buildtx" && i+5<argc){
            buildtx     = true;
            privh       = argv[++i];
            prevtxid_hex= argv[++i];
            vout        = (uint32_t)std::stoul(argv[++i]);
            value       = (uint64_t)std::stoull(argv[++i]);
            toaddr      = argv[++i];
        } else if(a=="--reindex_utxo"){ flag_reindex_utxo = true;
        } else if(a=="--mine"){ mine_flag = true;
        } else if(a=="--telemetry"){ telemetry_flag = true;
        } else if(a=="--help"){ print_usage(); if (can_tui){ capture.stop(); tui.stop(); } return 0; }
    }

    // Fast paths (genaddress/ buildtx)
    if(genaddr){
        if (can_tui) tui.stop();
        std::vector<uint8_t> priv;
        if(!crypto::ECDSA::generate_priv(priv)){ std::fprintf(stderr, "keygen failed\n"); if (can_tui) capture.stop(); return 1; }
        std::vector<uint8_t> pub33;
        if(!crypto::ECDSA::derive_pub(priv, pub33)){ std::fprintf(stderr, "derive_pub failed\n"); if (can_tui) capture.stop(); return 1; }
        auto pkh  = hash160(pub33);
        auto addr = base58check_encode(VERSION_P2PKH, pkh);
        std::cout << "priv_hex=" << to_hex(priv) << "\n"
                  << "pub_hex="  << to_hex(pub33) << "\n"
                  << "address="  << addr << "\n";
        if (can_tui) capture.stop();
        return 0;
    }
    if(buildtx){
        if (can_tui) tui.stop();
        std::vector<uint8_t> priv = miq::from_hex(privh);
        std::vector<uint8_t> pub33;
        if(!crypto::ECDSA::derive_pub(priv, pub33)){ std::fprintf(stderr, "derive_pub failed\n"); if (can_tui) capture.stop(); return 1; }
        uint8_t ver=0; std::vector<uint8_t> to_payload;
        if(!base58check_decode(toaddr, ver, to_payload) || to_payload.size()!=20){ std::fprintf(stderr, "bad to_address\n"); if (can_tui) capture.stop(); return 1; }
        Transaction tx; TxIn in; in.prev.txid = miq::from_hex(prevtxid_hex); in.prev.vout = vout; tx.vin.push_back(in);
        TxOut out; out.value = value; out.pkh = to_payload; tx.vout.push_back(out);
        auto h = dsha256(ser_tx(tx)); std::vector<uint8_t> sig64;
        if(!crypto::ECDSA::sign(priv, h, sig64)){ std::fprintf(stderr, "sign failed\n"); if (can_tui) capture.stop(); return 1; }
        tx.vin[0].sig = sig64; tx.vin[0].pubkey = pub33;
        auto raw = ser_tx(tx); std::cout << "txhex=" << to_hex(raw) << "\n";
        if (can_tui) capture.stop();
        return 0;
    }

    // TUI start
    if (can_tui) {
        tui.start();
        tui.set_banner(u8_ok ? "Preparing Miqrochain node…" : "Preparing Miqrochain node...");
        tui.mark_step_ok("Parse CLI / environment");
        tui.set_node_state(TUI::NodeState::Starting);
        tui.set_datadir(cfg.datadir.empty()? default_datadir(): cfg.datadir);
    }

    try {
        if (can_tui) tui.mark_step_started("Load config & choose datadir");
        if(!conf.empty()) load_config(conf, cfg);
        if(cfg.datadir.empty()) cfg.datadir = default_datadir();
        std::error_code ec;
        std::filesystem::create_directories(cfg.datadir, ec);
        if(!acquire_datadir_lock(cfg.datadir)){
            if (can_tui) { capture.stop(); tui.stop(); }
            return 11;
        }
        global::telemetry_path = p_join(cfg.datadir, "telemetry.ndjson");
        global::telemetry_enabled.store(telemetry_flag);
        if (can_tui) {
            tui.mark_step_ok("Load config & choose datadir");
            tui.mark_step_ok("Config/datadir ready");
            tui.set_banner(std::string("Starting services...   Datadir: ") + cfg.datadir);
            tui.set_datadir(cfg.datadir);
        }

        if (can_tui) tui.mark_step_started("Open chain data");
        Chain chain;
        if(!chain.open(cfg.datadir)){ log_error("failed to open chain data"); release_datadir_lock(); if (can_tui) { capture.stop(); tui.stop(); } return 1; }
        if (can_tui) tui.mark_step_ok("Open chain data");

        if (can_tui) tui.mark_step_started("Load & validate genesis");
        {
            std::vector<uint8_t> raw;
            try { raw = miq::from_hex(GENESIS_RAW_BLOCK_HEX); }
            catch (...) { log_error("GENESIS_RAW_BLOCK_HEX invalid hex"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (raw.empty()) { log_error("GENESIS_RAW_BLOCK_HEX empty"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            Block g;
            if (!deser_block(raw, g)) { log_error("Genesis deserialize failed"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            g_genesis_time_s.store(hdr_time(g.header));
            const std::string got_hash = to_hex(g.block_hash());
            const std::string want_hash= std::string(GENESIS_HASH_HEX);
            const std::string got_merkle = to_hex(g.header.merkle_root);
            const std::string want_merkle= std::string(GENESIS_MERKLE_HEX);
            if (got_hash != want_hash){ log_error(std::string("Genesis hash mismatch; got=")+got_hash+" want="+want_hash); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (got_merkle != want_merkle){ log_error(std::string("Genesis merkle mismatch; got=")+got_merkle+" want="+want_merkle); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (!chain.init_genesis(g)) { log_error("genesis init failed"); release_datadir_lock(); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
        }
        if (can_tui) { tui.mark_step_ok("Load & validate genesis"); tui.mark_step_ok("Genesis OK"); }

        if (can_tui) tui.mark_step_started("Reindex UTXO (full scan)");
#if MIQ_CAN_PROBE_UTXO_REINDEX
        {
            bool ok_reindex = true;
            if (ensure_utxo_fully_indexed) {
                ok_reindex = ensure_utxo_fully_indexed(chain, cfg.datadir, flag_reindex_utxo);
            } else {
                log_info("UTXO reindex routine not linked in this build; skipping.");
            }
            if (!ok_reindex){
                if (can_tui) tui.mark_step_fail("Reindex UTXO (full scan)");
                release_datadir_lock();
                if (can_tui) { capture.stop(); tui.stop(); }
                return 12;
            }
            if (can_tui) tui.mark_step_ok("Reindex UTXO (full scan)");
        }
#else
        {
            log_info("UTXO reindex routine not available on this compiler/platform; skipping.");
            if (can_tui) tui.mark_step_ok("Reindex UTXO (full scan)");
        }
#endif
        if (can_tui) tui.mark_step_started("Initialize mempool & RPC");
        Mempool mempool; RpcService rpc(chain, mempool);
        if (can_tui) tui.mark_step_ok("Initialize mempool & RPC");

        P2P p2p(chain);
        p2p.set_inflight_caps(256, 128);
        p2p.set_datadir(cfg.datadir);
        p2p.set_mempool(&mempool);
        rpc.set_p2p(&p2p);
        if (can_tui) tui.set_runtime_refs(&p2p, &chain, &mempool);

        g_extminer.start(cfg.datadir);

        [[maybe_unused]] bool p2p_ok = false;
        if (can_tui) { tui.mark_step_started("Start P2P listener"); tui.set_node_state(TUI::NodeState::Starting); }
        if(!cfg.no_p2p){
            if(p2p.start(P2P_PORT)){
                p2p_ok = true;
                log_info("P2P listening on " + std::to_string(P2P_PORT));
                if (can_tui) { tui.mark_step_ok("Start P2P listener"); tui.mark_step_started("Connect seeds"); }
                if (!(compute_seed_role().we_are_seed || g_assume_seed_hairpin.load())) {
                    p2p.connect_seed(seed_host_cstr(), P2P_PORT);
                    if (can_tui) tui.mark_step_ok("Connect seeds");
                } else {
                    log_info(std::string("Seed self-detect: skipping outbound connect to ")
                             + seed_host_cstr() + " (waiting for inbound peers).");
                    if (can_tui) {
                        tui.mark_step_ok("Connect seeds");
                        tui.set_hot_warning("Running as public seed — ensure port is open");
                    }
                }
            } else {
                log_warn("P2P failed to start on port " + std::to_string(P2P_PORT));
            }
        } else if (can_tui) {
            tui.mark_step_ok("Start P2P listener");
        }
        SeedSentinel seed_sentinel;
        seed_sentinel.start(&p2p, can_tui ? &tui : nullptr);
        if (can_tui) tui.mark_step_started("Start IBD monitor");
        start_ibd_monitor(&chain, &p2p);
        if (can_tui) tui.mark_step_ok("Start IBD monitor");

        // ─────────────────────────────────────────────────────────────────────
        // NEW STEP: IBD sync phase (smart start/finish, surfaces real error)
        // ─────────────────────────────────────────────────────────────────────
        if (can_tui) {
            // Only show what is known at start; no estimated future height.
            tui.set_ibd_progress(chain.height(), chain.height(), 0, "headers", seed_host_cstr(), false);
        }
        if (can_tui) tui.mark_step_started("IBD sync phase");
        std::string ibd_err;
        bool ibd_ok = perform_ibd_sync(chain, cfg.no_p2p ? nullptr : &p2p, cfg.datadir, can_tui, &tui, ibd_err);
        if (ibd_ok) {
            if (can_tui) {
                tui.mark_step_ok("IBD sync phase");
                tui.set_banner("Initial block download complete. Node is synced.");
                tui.set_node_state(TUI::NodeState::Running);
                tui.set_mining_gate(true, "");
            }
            log_info("IBD sync completed successfully.");
        } else {
            if (solo_seed_mode(cfg.no_p2p ? nullptr : &p2p)) {
                // Bootstrap solo: treat as OK so local mining can proceed.
                if (can_tui) {
                    tui.mark_step_ok("IBD sync phase");
                    tui.set_banner("Seed solo mode — no peers yet. Mining enabled.");
                    tui.set_node_state(TUI::NodeState::Running);
                    tui.set_mining_gate(true, "");
                }
                log_info("IBD sync skipped (seed solo mode).");
            } else {
                if (can_tui) {
                    tui.mark_step_fail("IBD sync phase");
                    tui.set_node_state(TUI::NodeState::Degraded);
                    tui.set_hot_warning(std::string("BLOCKS MINED LOCALLY WILL NOT BE VALID — ") + ibd_err);
                    tui.set_mining_gate(false, ibd_err + " — blocks mined locally will not be valid");
                }
                log_error(std::string("IBD sync failed: ") + ibd_err);
                log_error("BLOCKS MINED LOCALLY WILL NOT BE VALID");
            }
        }
        
        IBDGuard ibd_guard;
        ibd_guard.start(&chain, cfg.no_p2p ? nullptr : &p2p, cfg.datadir, can_tui, can_tui ? &tui : nullptr);
        
        [[maybe_unused]] bool rpc_ok = false;
        if (can_tui) tui.mark_step_started("Start RPC server");
        if(!cfg.no_rpc){
            miq::rpc_enable_auth_cookie(cfg.datadir);
            // Friendlier defaults for local miners: allow loopback without token unless the user overrides.
            if (const char* req = std::getenv("MIQ_RPC_REQUIRE_TOKEN"); !(req && *req)) {
#ifdef _WIN32
                _putenv_s("MIQ_RPC_REQUIRE_TOKEN", "0");
                _putenv_s("MIQ_RPC_ALLOW_LOOPBACK", "1");
#else
                setenv("MIQ_RPC_REQUIRE_TOKEN", "0", 1);
                setenv("MIQ_RPC_ALLOW_LOOPBACK", "1", 1);
#endif
            try {
                std::string cookie_path = p_join(cfg.datadir, ".cookie");
                std::vector<uint8_t> buf;
                if (!read_file_all(cookie_path, buf)) throw std::runtime_error("cookie read fail");
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
            }
            rpc.start(RPC_PORT);
            rpc_ok = true;
            log_info("RPC listening on " + std::to_string(RPC_PORT));
            if (can_tui) { tui.mark_step_ok("Start RPC server"); tui.mark_step_ok("RPC ready"); }
        } else if (can_tui) {
            tui.mark_step_ok("Start RPC server");
            tui.mark_step_ok("RPC ready");
            rpc_ok = true;
        }

        // Prepare built-in miner (address prompt), but DO NOT start until synced.
        unsigned thr_count = 0;
        std::vector<uint8_t> mine_pkh;
        bool miner_spawned = false;
        bool miner_armed   = false;

        if (mine_flag) {
            if (cfg.miner_threads) thr_count = cfg.miner_threads;
            if (thr_count == 0) {
                if (const char* s = std::getenv("MIQ_MINER_THREADS")) {
                    char* end = nullptr; long v = std::strtol(s, &end, 10);
                    if (end != s && v > 0 && v <= 256) thr_count = (unsigned)v;
                }
            }
            if (thr_count == 0) thr_count = std::max(1u, std::thread::hardware_concurrency());

            if (MIQ_ISATTY()) {
                std::string addr;
                std::cout << "Enter P2PKH Base58 address to mine to (will start when synced; empty to cancel): ";
                std::getline(std::cin, addr);
                trim_inplace(addr);
                if (!addr.empty()) {
                    uint8_t ver=0; std::vector<uint8_t> payload;
                    if (base58check_decode(addr, ver, payload) && ver==VERSION_P2PKH && payload.size()==20) {
                        mine_pkh = payload;
                        g_miner_address_b58 = addr;
                        miner_armed = true;
                        log_info("Miner armed; waiting for node to finish syncing before start.");
                    } else {
                        log_error("Invalid mining address; built-in miner disabled.");
                    }
                } else {
                    log_info("No address entered; built-in miner disabled.");
                }
            } else {
                log_info("No TTY available; built-in miner disabled.");
            }
        } else {
            log_info("Miner not started (use external miner or pass --mine).");
        }

        log_info(std::string(CHAIN_NAME) + " node running. RPC " + std::to_string(RPC_PORT) +
                 ", P2P " + std::to_string(P2P_PORT));
        if (can_tui) {
            const bool ibd_ok_or_solo = ibd_ok || solo_seed_mode(cfg.no_p2p ? nullptr : &p2p);
            if (ibd_ok_or_solo) {
                tui.set_banner(u8_ok ? "Miqrochain node running — synced & serving peers…" :
                                       "Miqrochain node running - synced & serving peers...");
                auto role = compute_seed_role();
                if (role.we_are_seed) {
                    tui.set_banner_append(std::string("SEED: ") + seed_host_cstr());
                    tui.set_hot_warning("Acting as seed — keep port open");
                }
                tui.set_node_state(TUI::NodeState::Running);
            } else {
                tui.set_banner(u8_ok ? "Node running — IBD failed (see error). Mining disabled." :
                                       "Node running - IBD failed (see error). Mining disabled.");
                tui.set_node_state(TUI::NodeState::Degraded);
            }
        }

        uint64_t last_tip_height_seen = chain.height();
        uint64_t last_tip_change_ms   = now_ms();
        uint64_t last_peer_warn_ms    = 0;
        uint64_t start_of_run_ms      = now_ms();

        // Initial "at height 0" nudge
        if (chain.height() == 0) {
            log_info("Waiting for headers from seed (" + std::string(DNS_SEED) + ":" + std::to_string(P2P_PORT) + ")...");
        }

        while(!global::shutdown_requested.load()){
            std::this_thread::sleep_for(std::chrono::milliseconds(can_tui ? 120 : 500));
            if (can_tui){
                std::deque<LogCapture::Line> lines;
                capture.drain(lines);
                tui.feed_logs(lines);
            }
            uint64_t h = chain.height();
            if (h != last_tip_height_seen){
                g_miner_stats.last_height_rx.store(h);
                last_tip_height_seen = h;
                last_tip_change_ms = now_ms();
            }

            // Sync gate & mining availability
            {
                std::string why;
                bool synced = compute_sync_gate(chain, &p2p, why);
                if (can_tui) tui.set_mining_gate(synced, synced ? "" : why);

                if (synced && miner_armed && !miner_spawned) {
                    // Start miner now
                    P2P* p2p_ptr = cfg.no_p2p ? nullptr : &p2p;
                    std::thread th(miner_worker, &chain, &mempool, p2p_ptr, mine_pkh, thr_count);
                    th.detach();
                    miner_spawned = true;
                    log_info("Sync complete — mining can start.");
                    if (can_tui) tui.set_hot_warning("Mining started");
                }
            }

            bool degraded = false;
            if (!cfg.no_p2p){
                auto n = p2p.snapshot_peers().size();
                if (n == 0 && now_ms() - last_peer_warn_ms > 60'000){
                    if (can_tui) tui.set_hot_warning("No peers connected - check network/firewall?");
                    last_peer_warn_ms = now_ms();
                }
                if (n == 0 && now_ms() - start_of_run_ms > 60'000) degraded = true;
            }
            if (now_ms() - last_tip_change_ms > 10*60*1000) degraded = true;
            if (!miner_armed && std::getenv("MIQ_MINER_HEARTBEAT") && !g_extminer.alive.load()) degraded = true;
            if (g_we_are_seed.load()){
                // Seed host with no peers is definitely degraded
                if (p2p.snapshot_peers().empty()) degraded = true;
            }

            if (can_tui) tui.set_health_degraded(degraded);

            if (global::reload_requested.exchange(false)){
                log_info("Reloading config due to SIGHUP/hotkey...");
                try {
                    if(!conf.empty()) load_config(conf, cfg);
                    log_info("Reload complete.");
                    if (can_tui) tui.set_hot_warning("Config reloaded");
                } catch (...) {
                    log_warn("Config reload failed.");
                    if (can_tui) tui.set_hot_warning("Config reload failed");
                }
            }
        }

        if (can_tui) {
                tui.set_node_state(TUI::NodeState::Quitting);
                tui.set_banner("Shutting down safely...");
            }
        log_info("Shutdown requested - stopping services...");

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping RPC...", false);
            rpc.stop();
            if (can_tui) tui.set_shutdown_phase("Stopping RPC...", true);
        } catch(...) { log_warn("RPC stop threw"); }

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping P2P...", false);
            p2p.stop();
            if (can_tui) tui.set_shutdown_phase("Stopping P2P...", true);
        } catch(...) { log_warn("P2P stop threw"); }

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping IBD/Seed sentinels...", false);
            std::this_thread::sleep_for(std::chrono::milliseconds(30));
            if (can_tui) tui.set_shutdown_phase("Stopping IBD/Seed sentinels...", true);
        } catch(...) { }

        try {
            if (can_tui) tui.set_shutdown_phase("Stopping miner watch...", false);
            g_extminer.stop();
            if (can_tui) tui.set_shutdown_phase("Stopping miner watch...", true);
        } catch(...) { log_warn("Miner watch stop threw"); }

        std::this_thread::sleep_for(std::chrono::milliseconds(140));

        log_info("Shutdown complete.");
        if (can_tui) {
            capture.stop();
            tui.stop();
        }
        release_datadir_lock();
        return 0;

    } catch(const std::exception& ex){
        std::fprintf(stderr, "[FATAL] %s\n", ex.what());
        release_datadir_lock();
        return 13;
    } catch(...){
        std::fprintf(stderr, "[FATAL] unknown exception\n");
        release_datadir_lock();
        return 13;
    }
}
