// src/main.cpp — MIQ core entrypoint with ultra-dynamic Pro TUI (single file, no deps)
// Hardened startup, auto-UTXO reindex, professional logs, miner health badges,
// smooth 120Hz animations (VT-aware), Windows-friendly.

// ─────────────────────────────────────────────────────────────────────────────
// Build-time UTF-8 hints for MSVC
#ifdef _MSC_VER
#pragma execution_character_set("utf-8")
#endif

// ─────────────────────────────────────────────────────────────────────────────
// Minimal Windows portability flags
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX 1
#endif
#endif

// ─────────────────────────────────────────────────────────────────────────────
// MIQ core headers (existing in your repo)
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
#include "reindex_utxo.h"

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
#include <sstream>
#include <iomanip>
#include <limits>
#include <unordered_set>
#include <unordered_map>
#include <map>

// ─────────────────────────────────────────────────────────────────────────────
// Version banner (update freely)
#ifndef MIQ_VERSION_MAJOR
#define MIQ_VERSION_MAJOR 0
#endif
#ifndef MIQ_VERSION_MINOR
#define MIQ_VERSION_MINOR 3
#endif
#ifndef MIQ_VERSION_PATCH
#define MIQ_VERSION_PATCH 0
#endif

// ─────────────────────────────────────────────────────────────────────────────
// OS-specific console bits
#if defined(_WIN32)
  #include <io.h>
  #include <windows.h>
  #include <conio.h>
  #include <fcntl.h>
  #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
  #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
  #endif
  #define MIQ_ISATTY() (_isatty(_fileno(stdin)) != 0)
#else
  #include <unistd.h>
  #include <termios.h>
  #include <sys/ioctl.h>
  #include <fcntl.h>
  #define MIQ_ISATTY() (::isatty(fileno(stdin)) != 0)
#endif

#ifdef _WIN32
#  ifdef min
#    undef min
#  endif
#  ifdef max
#    undef max
#  endif
#endif

using namespace miq;

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                          Global shutdown & helpers                        ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
static std::atomic<bool> g_shutdown_requested{false};
static inline uint64_t now_ms(){
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                          Miner stats (for TUI)                            ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
struct MinerStats {
    std::atomic<bool> active{false};
    std::atomic<unsigned> threads{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<uint64_t> last_height_ok{0}; // last height we mined & accepted
    std::atomic<uint64_t> last_height_rx{0}; // last network accept observed
    std::chrono::steady_clock::time_point start{};
    std::atomic<double>   hps{0.0};
} g_miner_stats;

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                      Accepted-block telemetry buffer                       ║
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
    std::deque<BlockSummary> new_blocks;      // fifo of new accepted blocks
    std::deque<std::string>  new_txids;       // fifo of txids from accepted blocks
    void push_block(const BlockSummary& b) {
        std::lock_guard<std::mutex> lk(mu);
        new_blocks.push_back(b);
        while (new_blocks.size() > 128) new_blocks.pop_front();
    }
    void push_txids(const std::vector<std::string>& v) {
        std::lock_guard<std::mutex> lk(mu);
        for (auto& t : v) {
            new_txids.push_back(t);
            while (new_txids.size() > 64) new_txids.pop_front();
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

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                         Default data-dir resolution                        ║
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
static inline void trim_inplace(std::string& s) {
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

// ╔═══════════════════════════════════════════════════════════════════════════╗
static void handle_signal(int){ g_shutdown_requested.store(true); }

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                           Reindex helper (guarded)                         ║
static bool dir_exists_nonempty(const std::string& path){
    std::error_code ec; if(!std::filesystem::exists(path, ec)) return false;
    for (auto it = std::filesystem::directory_iterator(path, ec);
         it != std::filesystem::directory_iterator(); ++it) return true;
    return false;
}
static bool ensure_utxo_fully_indexed(Chain& chain, const std::string& datadir, bool force){
    const std::string chainstate_dir =
#ifdef _WIN32
        datadir + "\\chainstate";
#else
        datadir + "/chainstate";
#endif

    bool need = force || !dir_exists_nonempty(chainstate_dir);

    if(!need){
        // Optional deep check: if tip looks higher than KV might contain, we still reindex.
        // (Without UTXOKV query APIs, we conservatively skip; ReindexUTXO() itself validates completeness.)
        log_info("UTXO chainstate seems present; quick-skip deep probe.");
    } else {
        log_warn("UTXO chainstate missing/stale — reindex required.");
    }

    if(!need) return true;

    UTXOKV utxo_kv;
    std::string err;
    log_info("ReindexUTXO: starting full scan...");
    const auto t0 = now_ms();
    const bool ok = ReindexUTXO(chain, utxo_kv, /*compact_after=*/true, err);
    const auto t1 = now_ms();
    if(!ok){
        log_error(std::string("ReindexUTXO failed: ") + (err.empty()?"unknown":err));
        return false;
    }
    log_info(std::string("ReindexUTXO: complete in ") + std::to_string((t1 - t0)/1000.0) + "s");

    // Minimal post-check: after a successful run, utxo must exist.
    if(!dir_exists_nonempty(chainstate_dir)){
        log_error("ReindexUTXO claimed success but chainstate is empty — refusing to continue.");
        return false;
    }
    return true;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                         Terminal / Console plumbing                        ║
namespace term {
static inline bool is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}
static inline void get_winsize(int& cols, int& rows) {
    cols = 120; rows = 40;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (GetConsoleScreenBufferInfo(hOut, &info)) {
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
static inline void enable_vt(bool& vt_ok) {
    vt_ok = true;
#ifdef _WIN32
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) { vt_ok = false; return; }
    DWORD mode = 0;
    if (!GetConsoleMode(hOut, &mode)) { vt_ok = false; return; }
    mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    if (!SetConsoleMode(hOut, mode)) { vt_ok = false; return; }
    DWORD mode_after = 0;
    if (!GetConsoleMode(hOut, &mode_after)) { vt_ok = false; return; }
    if ((mode_after & ENABLE_VIRTUAL_TERMINAL_PROCESSING) == 0) vt_ok = false;
#endif
}
} // namespace term

// Write directly to console (not stdout) to avoid log capture recursion.
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
            DWORD wrote = 0;
            WriteFile(hFile_, s.c_str(), (DWORD)s.size(), &wrote, nullptr);
        } else {
            DWORD wrote = 0;
            WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), s.c_str(), (DWORD)s.size(), &wrote, nullptr);
        }
#else
        int fd = (fd_ >= 0) ? fd_ : STDOUT_FILENO;
        size_t off = 0; while (off < s.size()) { ssize_t n = ::write(fd, s.data()+off, s.size()-off); if (n<=0) break; off += (size_t)n; }
#endif
    }
private:
    void init(){
#ifdef _WIN32
        hFile_ = CreateFileA("CONOUT$", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
// ║                         Log capture (stdout/stderr)                        ║
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

    void drain(std::deque<Line>& into, size_t max_keep=1500) {
        std::lock_guard<std::mutex> lk(mu_);
        for (auto& s : pending_) {
            lines_.push_back({s, now_ms()});
            if (lines_.size() > max_keep) lines_.pop_front();
        }
        pending_.clear();
        into = lines_;
    }
private:
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
// ║                               UI widgets                                  ║
static inline std::string short_hex(const std::string& h, size_t n=12){ return h.size()>n ? h.substr(0,n) : h; }
static inline std::string fmt_hs(double v){
    const char* u[] = {"H/s","kH/s","MH/s","GH/s","TH/s","PH/s"};
    int i=0; while(v>=1000.0 && i<5){ v/=1000.0; ++i; }
    std::ostringstream o; o<<std::fixed<<std::setprecision(2)<<v<<" "<<u[i]; return o.str();
}
static inline std::string bar(int width, double frac, bool vt_ok){
    if (width < 6) width = 6;
    if (frac < 0) frac = 0; if (frac > 1) frac = 1;
    int full = (int)((width-2)*frac + 0.5);
    std::ostringstream o;
    o << '[';
    if(vt_ok){
        // gradient 36->34->32
        for(int i=0;i<width-2;i++){
            bool on = i < full;
            int hue = 36 - (i*4)/(width?width:1); if (hue < 32) hue = 32;
            if (on) o << "\x1b["<<hue<<"m" << "█" << "\x1b[0m";
            else    o << "\x1b[90m" << "·" << "\x1b[0m";
        }
    }else{
        for(int i=0;i<width-2;i++) o << (i<full ? '#' : ' ');
    }
    o << ']';
    return o.str();
}
static std::string wave_line(int width, int tick, bool vt_ok){
    static const char* blocks = " ▁▂▃▄▅▆▇█";
    int N = (int)std::strlen(blocks)-1;
    if(width < 4) width = 4;
    std::ostringstream o;
    for(int i=0;i<width;i++){
        double x = (i + tick*0.75) * 0.22;
        double y = 0.5 + 0.5*std::sin(x) * std::cos((tick+i)*0.08);
        int idx = (int)std::round(y * N);
        if(idx<0) idx=0; if(idx>N) idx=N;
        if(vt_ok){
            int hue = 36 - (i*4)/(width?width:1); if (hue < 32) hue = 32;
            o << "\x1b["<<hue<<"m" << blocks[idx] << "\x1b[0m";
        }else{
            o << blocks[idx];
        }
    }
    return o.str();
}
static std::string spark_ascii(const std::vector<double>& xs){
    static const char bars[] = " .:-=+*#%@";
    if(xs.empty()) return "";
    double mn=xs[0], mx=xs[0];
    for(double v: xs){ mn = std::min(mn,v); mx = std::max(mx,v); }
    double span = (mx>mn)? (mx-mn) : 1.0;
    std::string s;
    for(double v: xs){
        int idx = (int)std::round( (v-mn)/span * 9.0 );
        if(idx<0) idx=0;
        if(idx>9) idx=9;
        s.push_back(bars[idx]);
    }
    return s;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                         Pro TUI (two-column, animated)                    ║
class TUI {
public:
    enum class NodeState { Starting, Syncing, Running, Degraded };

    TUI(bool vt_ok) : vt_ok_(vt_ok) { init_step_order(); }
    void set_enabled(bool on){ enabled_ = on; }
    void start() {
        if (!enabled_) return;
        if (vt_ok_) cw_.write_raw("\x1b[2J\x1b[H\x1b[?25l");
        draw_once(true);
        thr_ = std::thread([this]{ loop(); });
    }
    void stop() {
        if (!enabled_) return;
        running_ = false;
        if (thr_.joinable()) thr_.join();
        if (vt_ok_) cw_.write_raw("\x1b[?25h\x1b[0m\n");
    }
    ~TUI(){ stop(); }

    void mark_step_started(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); }
    void mark_step_ok(const std::string& title) { std::lock_guard<std::mutex> lk(mu_); ensure_step(title); set_step(title, true); }
    void mark_step_fail(const std::string& title){ std::lock_guard<std::mutex> lk(mu_); ensure_step(title); failures_.insert(title); }

    void set_runtime_refs(P2P* p2p, Chain* chain) { p2p_ = p2p; chain_ = chain; }
    void feed_logs(const std::deque<LogCapture::Line>& raw_lines) {
        std::lock_guard<std::mutex> lk(mu_);
        logs_.clear(); logs_.reserve(raw_lines.size());
        for (auto& L : raw_lines){
            logs_.push_back(stylize_log(L));
        }
        // Drain block/tx telemetry
        std::vector<BlockSummary> nb; std::vector<std::string> ntx;
        g_telemetry.drain(nb, ntx);
        for (auto& b : nb) {
            if (recent_blocks_.empty() || recent_blocks_.back().height != b.height || recent_blocks_.back().hash_hex != b.hash_hex) {
                recent_blocks_.push_back(b);
                while (recent_blocks_.size() > 64) recent_blocks_.pop_front();
            }
        }
        for (auto& t : ntx) {
            if (recent_txid_set_.insert(t).second) {
                recent_txids_.push_back(t);
                while (recent_txids_.size() > 10) { recent_txid_set_.erase(recent_txids_.front()); recent_txids_.pop_front(); }
            }
        }
    }
    void set_banner(const std::string& s){ std::lock_guard<std::mutex> lk(mu_); banner_ = s; }
    void set_ports(uint16_t p2pport, uint16_t rpcport) { p2p_port_ = p2pport; rpc_port_ = rpcport; }
    void set_node_state(NodeState st){ std::lock_guard<std::mutex> lk(mu_); nstate_ = st; }
    bool is_enabled() const { return enabled_; }

    void set_startup_eta(double secs){ std::lock_guard<std::mutex> lk(mu_); eta_secs_ = secs; }

private:
    struct StyledLine { std::string txt; int level; }; // 0=info 1=warn 2=err 3=trace 4=ok
    StyledLine stylize_log(const LogCapture::Line& L){
        const std::string& s = L.text;
        StyledLine out{ s, 0 };
        if      (s.find("[FATAL]") != std::string::npos || s.find("[ERROR]") != std::string::npos) out.level=2;
        else if (s.find("[WARN]")  != std::string::npos) out.level=1;
        else if (s.find("accepted block") != std::string::npos || s.find("mined block accepted") != std::string::npos) out.level=4;
        else if (s.find("[TRACE]") != std::string::npos) out.level=3;
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
            "Start IBD monitor",
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
    const char* C_info()  const { return vt_ok_ ? "\x1b[36m" : ""; }
    const char* C_warn()  const { return vt_ok_ ? "\x1b[33m" : ""; }
    const char* C_err()   const { return vt_ok_ ? "\x1b[31m" : ""; }
    const char* C_dim()   const { return vt_ok_ ? "\x1b[90m" : ""; }
    const char* C_head()  const { return vt_ok_ ? "\x1b[35m" : ""; }
    const char* C_step()  const { return vt_ok_ ? "\x1b[34m" : ""; }
    const char* C_ok()    const { return vt_ok_ ? "\x1b[32m" : ""; }
    const char* C_bold()  const { return vt_ok_ ? "\x1b[1m"  : ""; }

    static std::string fit(const std::string& s, int w){
        if (w <= 0) return std::string();
        if ((int)s.size() <= w) return s;
        if (w <= 3) return std::string((size_t)w, '.');
        return s.substr(0, (size_t)w-3) + "...";
    }

    void loop(){
        using clock = std::chrono::steady_clock;
        using namespace std::chrono_literals;
        running_ = true;
        auto last_hs_time = clock::now();
        while (running_) {
            draw_once(false);
            // 120 Hz animation for smoother waves
            std::this_thread::sleep_for(8ms);
            ++tick_;
            // sample miner h/s gently to build sparkline
            if((clock::now()-last_hs_time) > 250ms){
                last_hs_time = clock::now();
                std::lock_guard<std::mutex> lk(mu_);
                spark_.push_back(g_miner_stats.hps.load());
                if(spark_.size() > 60) spark_.erase(spark_.begin());
            }
        }
    }

    // Display “100% RUNNING” badge when: node running & (P2P ok || no-p2p) & RPC up & miner active with threads
    bool miner_running_badge() const {
        const bool miner_on = g_miner_stats.active.load() && g_miner_stats.threads.load() > 0;
        const bool node_run = (nstate_ == NodeState::Running);
        return miner_on && node_run;
    }

    void draw_once(bool first){
        std::lock_guard<std::mutex> lk(mu_);
        int cols, rows; term::get_winsize(cols, rows);
        if (cols < 106) cols = 106;
        if (rows < 32) rows = 32;
        const int rightw = std::max(44, cols / 3);
        const int leftw  = cols - rightw - 3;

        std::vector<std::string> left, right;

        // Header
        {
            std::ostringstream h;
            if (!first && vt_ok_) h << "\x1b[H\x1b[0J";
            h << C_head() << "MIQROCHAIN" << C_reset()
              << "  " << C_dim()
              << "v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR << "." << MIQ_VERSION_PATCH
              << "  •  Chain: " << CHAIN_NAME
              << "  •  P2P " << p2p_port_ << "  •  RPC " << rpc_port_ << C_reset();

            left.push_back(h.str());
            left.push_back("");
            if(!banner_.empty()){
                left.push_back(std::string("  ") + C_info() + banner_ + C_reset());
                left.push_back("");
            }
            // Eye-candy top wave
            left.push_back(std::string("  ") + wave_line(leftw-2, tick_, vt_ok_));
            left.push_back("");
        }

        // Node state
        {
            std::ostringstream s;
            s << "  State: ";
            switch(nstate_){
                case NodeState::Starting: s << C_warn() << "starting" << C_reset(); break;
                case NodeState::Syncing:  s << C_warn() << "syncing"  << C_reset(); break;
                case NodeState::Running:  s << C_ok()   << "running"  << C_reset(); break;
                case NodeState::Degraded: s << C_err()  << "degraded" << C_reset(); break;
            }
            if (miner_running_badge()){
                s << "   " << C_bold() << C_ok() << "⛏  100% RUNNING" << C_reset();
            }
            left.push_back(s.str());
            left.push_back("");
        }

        // Startup steps (animated progress)
        {
            left.push_back(std::string(C_bold()) + "Startup" + C_reset());
            size_t total = steps_.size(), okc = 0;
            for (auto& s : steps_) if (s.second) ++okc;
            int bw = std::max(10, leftw - 20);
            double frac = (double)okc / std::max<size_t>(1,total);
            std::ostringstream progress;
            progress << "  " << bar(bw, frac, vt_ok_) << "  "
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
                if (ok)      ln << C_ok()  << "[OK] "     << C_reset();
                else if (failed) ln << C_err() << "[FAIL] "   << C_reset();
                else         ln << C_dim() << "[..] "     << C_reset();
                ln << s.first;
                left.push_back(ln.str());
            }
            left.push_back("");
        }

        // Node status (chain + p2p)
        {
            left.push_back(std::string(C_bold()) + "Node status" + C_reset());
            uint64_t height = chain_ ? chain_->height() : 0;
            std::string tip_hex;
            if (chain_) {
                auto t = chain_->tip();
                tip_hex = to_hex(t.hash);
            }
            size_t peers  = 0, inflight_tx = 0, rxbuf_sum = 0, awaiting_pongs = 0;
            if (p2p_) {
                auto v = p2p_->snapshot_peers(); peers = v.size();
                for (auto& s : v) { inflight_tx += (size_t)s.inflight; rxbuf_sum += (size_t)s.rx_buf; if (s.awaiting_pong) ++awaiting_pongs; }
            }
            left.push_back(std::string("  height: ") + std::to_string(height)
                          + "   tip: " + short_hex(tip_hex, 12)
                          + "   peers: " + std::to_string(peers));
            left.push_back(std::string("  inflight tx: ") + std::to_string(inflight_tx)
                          + "   rx-buf: " + std::to_string(rxbuf_sum)
                          + "   pings-waiting: " + std::to_string(awaiting_pongs));
            left.push_back("");
        }

        // Recent blocks
        {
            left.push_back(std::string(C_bold()) + "Blocks (recent accepts)" + C_reset());
            size_t N = recent_blocks_.size();
            size_t show = std::min<size_t>(10, N);
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

        // Right: peers / miner / sparkline / recent txids
        if (p2p_) {
            right.push_back(std::string(C_bold()) + "Peers" + C_reset());
            std::ostringstream hdr;
            hdr << "  " << std::left << std::setw(16) << "IP"
                << "  verack  " << std::setw(8) << "last(ms)"
                << "  " << std::setw(6) << "rx"
                << "  " << std::setw(8) << "inflight";
            right.push_back(hdr.str());
            auto v = p2p_->snapshot_peers();
            size_t show = std::min(v.size(), (size_t)8);
            for (size_t i=0;i<show; ++i) {
                const auto& s = v[i];
                std::string ip = s.ip; if ((int)ip.size() > 16) ip = ip.substr(0,13) + "...";
                std::ostringstream ln;
                ln << "  " << std::left << std::setw(16) << ip
                   << "  " << (s.verack_ok ? (std::string(C_ok()) + "ok" + C_reset()) : (std::string(C_warn()) + ".." + C_reset())) << "    "
                   << std::right << std::setw(8) << (uint64_t)s.last_seen_ms
                   << "  " << std::setw(6) << (uint64_t)s.rx_buf
                   << "  " << std::setw(8) << (uint64_t)s.inflight;
                right.push_back(ln.str());
            }
            if (v.size() > show) right.push_back(std::string("  ... +") + std::to_string(v.size()-show) + " more");
            right.push_back("");
        }

        // Miner panel + sparkline
        {
            right.push_back(std::string(C_bold()) + "Miner" + C_reset());
            bool active = g_miner_stats.active.load();
            unsigned thr = g_miner_stats.threads.load();
            uint64_t ok  = g_miner_stats.accepted.load();
            uint64_t rej = g_miner_stats.rejected.load();
            double   hps = g_miner_stats.hps.load();

            std::ostringstream m1;
            m1 << "  status: " << (active ? (std::string(C_ok()) + "running" + C_reset()) : (std::string(C_dim()) + "idle" + C_reset()))
               << "   threads: " << thr;
            right.push_back(m1.str());

            std::ostringstream m2;
            m2 << "  accepted: " << ok << "   rejected: " << rej;
            right.push_back(m2.str());

            right.push_back(std::string("  hashrate: ") + fmt_hs(hps));
            right.push_back(std::string("  trend:    ") + spark_ascii(spark_));
            right.push_back("");
        }

        // Recent TXIDs
        {
            right.push_back(std::string(C_bold()) + "Recent TXIDs (verified)" + C_reset());
            if (recent_txids_.empty()) right.push_back("  (no txids yet)");
            size_t n = std::min<size_t>(recent_txids_.size(), 10);
            for (size_t i=0;i<n;i++){
                right.push_back(std::string("  ") + short_hex(recent_txids_[recent_txids_.size()-1-i], 18));
            }
            right.push_back("");
        }

        // Compose columns
        std::ostringstream out;
        size_t N = std::max(left.size(), right.size());
        for (size_t i=0;i<N;i++){
            std::string l = (i<left.size())  ? left[i]  : "";
            std::string r = (i<right.size()) ? right[i] : "";
            if ((int)l.size() > leftw)  l = fit(l, leftw);
            if ((int)r.size() > rightw) r = fit(r, rightw);
            out << std::left << std::setw(leftw) << l << " | " << r << "\n";
        }

        // Footer + logs
        out << std::string((size_t)cols, '-') << "\n";
        out << C_bold() << "Logs" << C_reset() << "  " << C_dim() << "(Ctrl+C to exit)" << C_reset() << "\n";
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
    std::atomic<bool> running_{false};
    std::thread thr_;
    std::mutex mu_;
    std::vector<std::pair<std::string,bool>> steps_;
    std::set<std::string> failures_;
    std::vector<StyledLine> logs_;
    std::string banner_;
    uint16_t p2p_port_{P2P_PORT};
    uint16_t rpc_port_{RPC_PORT};
    P2P*   p2p_   {nullptr};
    Chain* chain_ {nullptr};
    ConsoleWriter cw_;
    int  tick_{0};
    NodeState nstate_{NodeState::Starting};
    std::deque<BlockSummary> recent_blocks_;
    std::deque<std::string>  recent_txids_;
    std::unordered_set<std::string> recent_txid_set_;
    std::vector<double> spark_;
    double eta_secs_{0.0};
};

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                       Fatal terminate hook (node stays up)                ║
static void fatal_terminate() noexcept {
    std::fputs("[FATAL] std::terminate() called from a background thread (suppressed)\n", stderr);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                               Miner worker                                ║
static uint64_t sum_coinbase_outputs(const Block& b) {
    if (b.txs.empty()) return 0;
    uint64_t s = 0; for (const auto& o : b.txs[0].vout) s += o.value; return s;
}
static void miner_worker(Chain* chain,
                         Mempool* mempool,
                         P2P* p2p,
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

    // Simple h/s meter (based on attempts in mine_block)
    std::atomic<uint64_t> last_tries{0};
    std::thread meter([&](){
        using namespace std::chrono_literals;
        uint64_t last = 0;
        auto t0 = std::chrono::steady_clock::now();
        while(!g_shutdown_requested.load()){
            std::this_thread::sleep_for(250ms);
            uint64_t cur = last_tries.load();
            auto t1 = std::chrono::steady_clock::now();
            double dt = std::chrono::duration<double>(t1 - t0).count(); if (dt<=0) dt=1e-3;
            uint64_t delta = (cur>=last) ? (cur-last) : 0;
            g_miner_stats.hps.store((double)delta / dt);
            last = cur; t0 = t1;
        }
    });
    meter.detach();

    while (!g_shutdown_requested.load()) {
        try {
            auto t = chain->tip();
            // Build coinbase
            Transaction cbt;
            TxIn cin; cin.prev.txid = std::vector<uint8_t>(32, 0); cin.prev.vout = 0;
            cbt.vin.push_back(cin);

            TxOut cbout;
            cbout.value = chain->subsidy_for_height(t.height + 1);
            if (mine_pkh.size() != 20) {
                log_error(std::string("miner assign pkh fatal: pkh size != 20 (got ")
                          + std::to_string(mine_pkh.size()) + ")");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                continue;
            }
            cbout.pkh.resize(20);
            std::memcpy(cbout.pkh.data(), mine_pkh.data(), 20);
            cbt.vout.push_back(cbout);
            cbt.lock_time = static_cast<uint32_t>(t.height + 1);

            // Tag
            const uint32_t ch   = static_cast<uint32_t>(t.height + 1);
            const uint32_t now  = static_cast<uint32_t>(time(nullptr));
            const uint64_t extraNonce = gen();
            std::vector<uint8_t> tag; tag.reserve(1+4+4+8);
            tag.push_back(0x01);
            tag.push_back(uint8_t(ch      & 0xff)); tag.push_back(uint8_t((ch>>8) & 0xff));
            tag.push_back(uint8_t((ch>>16)& 0xff)); tag.push_back(uint8_t((ch>>24)& 0xff));
            tag.push_back(uint8_t(now      & 0xff)); tag.push_back(uint8_t((now>>8) & 0xff));
            tag.push_back(uint8_t((now>>16)& 0xff)); tag.push_back(uint8_t((now>>24)& 0xff));
            for (int i=0;i<8;i++) tag.push_back(uint8_t((extraNonce >> (8*i)) & 0xff));
            cbt.vin[0].sig = std::move(tag);

            // Pick mempool
            std::vector<Transaction> txs;
            try {
                txs = [&](){
                    const size_t coinbase_sz = ser_tx(cbt).size();
                    const size_t budget = (kBlockMaxBytes > coinbase_sz) ? (kBlockMaxBytes - coinbase_sz) : 0;
                    auto cands = mempool->collect(100000);
                    std::vector<Transaction> kept; kept.reserve(cands.size());
                    size_t used = 0;
                    for (auto& tx : cands) {
                        size_t sz = ser_tx(tx).size();
                        if (used + sz > budget) continue;
                        kept.push_back(std::move(tx));
                        used += sz;
                        if (used >= budget) break;
                    }
                    return kept;
                }();
            } catch(...) { txs.clear(); }

            // Solve
            Block b;
            try {
                auto last = chain->last_headers(MIQ_RETARGET_INTERVAL);
                uint32_t nb = miq::epoch_next_bits(
                    last, BLOCK_TIME_SECS, GENESIS_BITS,
                    /*next_height=*/ t.height + 1, /*interval=*/ MIQ_RETARGET_INTERVAL);
                b = miq::mine_block_ex(t.hash, nb, cbt, txs, threads, &last_tries); // mine_block_ex: same as mine_block but reports tries into last_tries
            } catch (...) {
                log_error("miner mine_block fatal");
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
                    g_miner_stats.accepted.fetch_add(1);
                    g_miner_stats.last_height_ok.store(t.height + 1);
                    g_miner_stats.last_height_rx.store(t.height + 1);

                    // Telemetry
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
                    if (!g_shutdown_requested.load() && p2p) {
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
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                                   CLI                                     ║
static void print_usage(){
    std::cout
      << "miqrod (node) options:\n"
      << "  --conf=<path>                                config file (key=value)\n"
      << "  --datadir=<path>                             data directory (overrides config)\n"
      << "  --no-tui                                     disable the Pro TUI (plain logs)\n"
      << "  --genaddress                                 generate ECDSA-P2PKH address (priv/pk/address)\n"
      << "  --buildtx <priv_hex> <prev_txid_hex> <vout> <value> <to_address>  (prints txhex)\n"
      << "  --reindex_utxo                               rebuild chainstate/UTXO from current chain\n"
      << "  --mine                                       run built-in miner (interactive address prompt)\n"
      << "\n"
      << "Env:\n"
      << "  MIQ_NO_TUI=1        disables the TUI; plain logs\n"
      << "  MIQ_MINER_THREADS   overrides miner thread count\n"
      << "  MIQ_RPC_TOKEN       if set, HTTP gate token (synced to .cookie on start)\n";
}
static bool is_recognized_arg(const std::string& s){
    if(s.rfind("--conf=",0)==0) return true;
    if(s.rfind("--datadir=",0)==0) return true;
    if(s=="--no-tui") return true;
    if(s=="--genaddress") return true;
    if(s=="--buildtx") return true;
    if(s=="--reindex_utxo") return true;
    if(s=="--mine") return true;
    if(s=="--help") return true;
    return false;
}
static bool env_truthy(const char* name){
    const char* v = std::getenv(name);
    if(!v||!*v) return false;
    if(std::strcmp(v,"0")==0 || std::strcmp(v,"false")==0 || std::strcmp(v,"False")==0) return false;
    return true;
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║                                   main                                    ║
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);
    std::set_terminate(&fatal_terminate);

    bool vt_ok = true;
    term::enable_vt(vt_ok);

    // Discover TUI intent early (so we capture logs only if using TUI)
    bool disable_tui_flag = false;
    for(int i=1;i<argc;i++){
        if(std::string(argv[i]) == "--no-tui") { disable_tui_flag = true; break; }
    }
    const bool want_tui = !disable_tui_flag && !env_truthy("MIQ_NO_TUI");
    const bool console_is_tty = term::is_tty();
    const bool can_tui  = want_tui && console_is_tty;

    ConsoleWriter cw;
    cw.write_raw("Starting miqrod…  (Ctrl+C to exit)\n");

    LogCapture capture;
    if (can_tui) capture.start();
    else std::fprintf(stderr, "[INFO] TUI disabled (plain logs).\n");

    TUI tui(vt_ok);
    tui.set_enabled(can_tui);
    tui.set_ports(P2P_PORT, RPC_PORT);
    if (tui.is_enabled()) {
        tui.start();
        tui.set_banner("Preparing Miqrochain node…");
        tui.mark_step_ok("Parse CLI / environment");
        tui.set_node_state(TUI::NodeState::Starting);
    }

    try {
        // ── CLI parse (fail early on unknown switches)
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
            } else if(a=="--help"){ print_usage(); if (can_tui){ capture.stop(); tui.stop(); } return 0; }
        }

        // Fast paths
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

        // Config & datadir
        if (can_tui) tui.mark_step_started("Load config & choose datadir");
        if(!conf.empty()) load_config(conf, cfg);
        if(cfg.datadir.empty()) cfg.datadir = default_datadir();
        std::error_code ec;
        std::filesystem::create_directories(cfg.datadir, ec);
        if (can_tui) {
            tui.mark_step_ok("Load config & choose datadir");
            tui.mark_step_ok("Config/datadir ready");
            tui.set_banner(std::string("Starting services…   Datadir: ") + cfg.datadir);
        }

        // Chain
        if (can_tui) tui.mark_step_started("Open chain data");
        Chain chain;
        if(!chain.open(cfg.datadir)){ log_error("failed to open chain data"); if (can_tui) { capture.stop(); tui.stop(); } return 1; }
        if (can_tui) tui.mark_step_ok("Open chain data");

        // Genesis
        if (can_tui) tui.mark_step_started("Load & validate genesis");
        {
            std::vector<uint8_t> raw;
            try { raw = miq::from_hex(GENESIS_RAW_BLOCK_HEX); }
            catch (...) { log_error("GENESIS_RAW_BLOCK_HEX invalid hex"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (raw.empty()) { log_error("GENESIS_RAW_BLOCK_HEX empty"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            Block g;
            if (!deser_block(raw, g)) { log_error("Genesis deserialize failed"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            const std::string got_hash = to_hex(g.block_hash());
            const std::string want_hash= std::string(GENESIS_HASH_HEX);
            const std::string got_merkle = to_hex(g.header.merkle_root);
            const std::string want_merkle= std::string(GENESIS_MERKLE_HEX);
            if (got_hash != want_hash){ log_error(std::string("Genesis hash mismatch; got=")+got_hash+" want="+want_hash); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (got_merkle != want_merkle){ log_error(std::string("Genesis merkle mismatch; got=")+got_merkle+" want="+want_merkle); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (!chain.init_genesis(g)) { log_error("genesis init failed"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
        }
        if (can_tui) { tui.mark_step_ok("Load & validate genesis"); tui.mark_step_ok("Genesis OK"); }

        // UTXO reindex: auto when missing AND for --reindex_utxo
        if (can_tui) tui.mark_step_started("Reindex UTXO (full scan)");
        if (!ensure_utxo_fully_indexed(chain, cfg.datadir, flag_reindex_utxo)){
            if (can_tui) tui.mark_step_fail("Reindex UTXO (full scan)");
            if (can_tui) { capture.stop(); tui.stop(); }
            return 1;
        }
        if (can_tui) tui.mark_step_ok("Reindex UTXO (full scan)");

        // Mempool & RPC
        if (can_tui) tui.mark_step_started("Initialize mempool & RPC");
        Mempool mempool; RpcService rpc(chain, mempool);
        if (can_tui) tui.mark_step_ok("Initialize mempool & RPC");

        // P2P
        P2P p2p(chain);
        p2p.set_datadir(cfg.datadir);
        p2p.set_mempool(&mempool);
        rpc.set_p2p(&p2p);
        if (can_tui) tui.set_runtime_refs(&p2p, &chain);

        bool p2p_ok = false;
        if (can_tui) { tui.mark_step_started("Start P2P listener"); tui.set_node_state(TUI::NodeState::Starting); }
        if(!cfg.no_p2p){
            if(p2p.start(P2P_PORT)){
                p2p_ok = true;
                log_info("P2P listening on " + std::to_string(P2P_PORT));
                if (can_tui) { tui.mark_step_ok("Start P2P listener"); tui.mark_step_started("Connect seeds"); }
                p2p.connect_seed(DNS_SEED, P2P_PORT);
                if (can_tui) tui.mark_step_ok("Connect seeds");
            } else {
                log_warn("P2P failed to start on port " + std::to_string(P2P_PORT));
            }
        } else if (can_tui) {
            tui.mark_step_ok("Start P2P listener");
        }

        if (can_tui) tui.mark_step_started("Start IBD monitor");
        start_ibd_monitor(&chain, &p2p);
        if (can_tui) tui.mark_step_ok("Start IBD monitor");

        // RPC
        bool rpc_ok = false;
        if (can_tui) tui.mark_step_started("Start RPC server");
        if(!cfg.no_rpc){
            miq::rpc_enable_auth_cookie(cfg.datadir);
#ifdef _WIN32
            _putenv_s("MIQ_RPC_REQUIRE_TOKEN", "1");
#else
            setenv("MIQ_RPC_REQUIRE_TOKEN", "1", 1);
#endif
            try {
                std::string cookie_path =
#ifdef _WIN32
                    cfg.datadir + "\\.cookie";
#else
                    cfg.datadir + "/.cookie";
#endif
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
            rpc.start(RPC_PORT);
            rpc_ok = true;
            log_info("RPC listening on " + std::to_string(RPC_PORT));
            if (can_tui) { tui.mark_step_ok("Start RPC server"); tui.mark_step_ok("RPC ready"); }
        } else if (can_tui) {
            tui.mark_step_ok("Start RPC server");
            tui.mark_step_ok("RPC ready");
            rpc_ok = true;
        }

        // Optional built-in miner (with address prompt)
        unsigned thr_count = 0;
        if (mine_flag) {
            if (cfg.miner_threads) thr_count = cfg.miner_threads;
            if (thr_count == 0) {
                if (const char* s = std::getenv("MIQ_MINER_THREADS")) {
                    char* end = nullptr; long v = std::strtol(s, &end, 10);
                    if (end != s && v > 0 && v <= 256) thr_count = (unsigned)v;
                }
            }
            if (thr_count == 0) thr_count = std::max(1u, std::thread::hardware_concurrency());

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
                std::thread th(miner_worker, &chain, &mempool, p2p_ptr, mine_pkh, thr_count);
                th.detach();
                log_info("Built-in miner started with " + std::to_string(thr_count) + " thread(s).");
            }
        } else {
            log_info("Miner not started (use external miner or pass --mine).");
        }

        log_info(std::string(CHAIN_NAME) + " node running. RPC " + std::to_string(RPC_PORT) +
                 ", P2P " + std::to_string(P2P_PORT));
        if (can_tui) {
            tui.set_banner("Miqrochain node running — syncing & serving peers…");
            if ((p2p_ok || cfg.no_p2p) && rpc_ok) tui.set_node_state(TUI::NodeState::Running);
            else tui.set_node_state(TUI::NodeState::Syncing);
        }

        // TUI main feed loop
        uint64_t last_tip_height_seen = 0;
        if (can_tui) {
            while(!g_shutdown_requested.load()){
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
                std::deque<LogCapture::Line> lines;
                capture.drain(lines);
                tui.feed_logs(lines);

                uint64_t h = 0;
                if (Chain* c = &chain) h = c->height();
                if (h > last_tip_height_seen){
                    g_miner_stats.last_height_rx.store(h);
                    last_tip_height_seen = h;
                }
            }
        } else {
            while(!g_shutdown_requested.load()){
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }

        log_info("Shutdown requested — stopping services…");
        try { rpc.stop(); } catch(...) {}
        try { p2p.stop(); } catch(...) {}
        log_info("Shutdown complete.");
        if (can_tui) { capture.stop(); tui.stop(); }
        return 0;

    } catch(const std::exception& ex){
        std::fprintf(stderr, "[FATAL] %s\n", ex.what());
        return 1;
    } catch(...){
        std::fprintf(stderr, "[FATAL] unknown exception\n");
        return 1;
    }
}
