// src/main.cpp — MIQ core entrypoint with robust ASCII Pro TUI (single file, no extra deps)

#ifdef _MSC_VER
#pragma execution_character_set("utf-8")
#endif

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
#include "miner.h"
#include "sha256.h"
#include "hex.h"
#include "tls_proxy.h"
#include "ibd_monitor.h"
#include "utxo_kv.h"
#include "reindex_utxo.h"

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

#ifndef MIQ_VERSION_MAJOR
#define MIQ_VERSION_MAJOR 0
#endif
#ifndef MIQ_VERSION_MINOR
#define MIQ_VERSION_MINOR 1
#endif

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

// ========= global shutdown ===================================================
static std::atomic<bool> g_shutdown_requested{false};

// ========= miner stats (for TUI surface) ====================================
struct MinerStats {
    std::atomic<bool> active{false};
    std::atomic<unsigned> threads{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<uint64_t> last_height_ok{0};
    std::atomic<uint64_t> last_height_rx{0}; // any miner
    std::chrono::steady_clock::time_point start{};
} g_miner_stats;

// ---------- default per-user datadir -----------------------------------------
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

// ---------- file helper ------------------------------------------------------
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

// ---------- signals ----------------------------------------------------------
static void handle_signal(int /*sig*/){
    g_shutdown_requested.store(true);
}

// ======== Simple mempool packer =============================================
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

// ---------- terminal helpers (width + VT) ------------------------------------
namespace term {
static inline bool is_tty() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return ::isatty(STDOUT_FILENO) == 1;
#endif
}
static inline void get_winsize(int& cols, int& rows) {
    cols = 110; rows = 36;
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

// ---- Console writer that ALWAYS writes to the real console (not stdout) -----
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

// ---- Log capture (stdout + stderr) ------------------------------------------
class LogCapture {
public:
    struct Line { std::string text; };

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
            lines_.push_back({s});
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

// ---- Pro TUI (ASCII-only visuals; ANSI colors when VT is OK) ----------------
class TUI {
public:
    enum class NodeState { Starting, Syncing, Running };

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

    void mark_step_started(const std::string& title) {
        std::lock_guard<std::mutex> lk(mu_);
        ensure_step(title);
    }
    void mark_step_ok(const std::string& title) {
        std::lock_guard<std::mutex> lk(mu_);
        ensure_step(title);
        for (auto& s : steps_) if (s.first == title) { s.second = true; break; }
    }

    void set_runtime_refs(P2P* p2p, Chain* chain) { p2p_ = p2p; chain_ = chain; }
    void feed_logs(const std::deque<LogCapture::Line>& lines) {
        std::lock_guard<std::mutex> lk(mu_);
        logs_ = lines;
        // lightweight event extraction (any miner accept & our miner accept)
        for (int i=(int)logs_.size()-1; i>=0; --i){
            const auto& L = logs_[i].text;
            if (L.find("accepted block") != std::string::npos || L.find("mined block accepted") != std::string::npos){
                last_accept_line_ = L;
                // try to extract height
                auto hpos = L.find("height=");
                if (hpos != std::string::npos){
                    size_t k=hpos+7, j=k;
                    while (j<L.size() && std::isdigit((unsigned char)L[j])) ++j;
                    last_accept_height_ = L.substr(k, j-k);
                }
                break;
            }
        }
    }
    void set_banner(const std::string& s){ std::lock_guard<std::mutex> lk(mu_); banner_ = s; }
    void set_ports(uint16_t p2pport, uint16_t rpcport) { p2p_port_ = p2pport; rpc_port_ = rpcport; }
    void set_node_state(NodeState st){ std::lock_guard<std::mutex> lk(mu_); nstate_ = st; }
    bool is_enabled() const { return enabled_; }

private:
    void init_step_order(){
        static const char* order[] = {
            "Parse CLI / environment",
            "Load config & choose datadir",
            "Config/datadir ready",
            "Open chain data",
            "Load & validate genesis",
            "Genesis OK",
            "Reindex UTXO (full scan)",
            "Initialize mempool & RPC gate",
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

    static std::string bar(uint64_t cur, uint64_t tot, int width){
        if (tot == 0) tot = 1;
        double frac = (double)cur / (double)tot;
        if (frac < 0) frac = 0;
        if (frac > 1) frac = 1; // (fixed misleading-indentation warning)
        int filled = (int)(frac * width + 0.5);
        if (filled > width) filled = width;
        std::string out = "[";
        for (int i=0;i<width;i++) out.push_back(i < filled ? '=' : ' ');
        out.push_back(']');
        return out;
    }
    static std::string fit(const std::string& s, int w){
        if (w <= 0) return std::string();
        if ((int)s.size() <= w) return s;
        if (w <= 3) return std::string((size_t)w, '.');
        return s.substr(0, (size_t)w-3) + "...";
    }
    const char* reset() const { return vt_ok_ ? "\x1b[0m" : ""; }
    const char* cInfo()  const { return vt_ok_ ? "\x1b[36m" : ""; }
    const char* cWarn()  const { return vt_ok_ ? "\x1b[33m" : ""; }
    const char* cErr()   const { return vt_ok_ ? "\x1b[31m" : ""; }
    const char* cDim()   const { return vt_ok_ ? "\x1b[90m" : ""; }
    const char* cHead()  const { return vt_ok_ ? "\x1b[35m" : ""; }
    const char* cStep()  const { return vt_ok_ ? "\x1b[34m" : ""; }
    const char* cOK()    const { return vt_ok_ ? "\x1b[32m" : ""; }
    const char* cRun()   const { return vt_ok_ ? "\x1b[32m" : ""; }
    const char* cPanel() const { return vt_ok_ ? "\x1b[1;37m" : ""; }

    void loop(){
        using namespace std::chrono_literals;
        running_ = true;
        while (running_) { draw_once(false); std::this_thread::sleep_for(120ms); ++tick_; }
    }

    static std::string short_hash(const std::string& hex, size_t n=10){
        if (hex.size() <= n) return hex;
        return hex.substr(0,n);
    }

    void draw_once(bool gentle){
        std::lock_guard<std::mutex> lk(mu_);
        int cols, rows; term::get_winsize(cols, rows);
        if (cols < 96) cols = 96;
        if (rows < 30) rows = 30;

        const int rightw = std::max(40, cols / 3);
        const int leftw  = cols - rightw - 3;

        std::vector<std::string> left, right;

        // Header
        {
            std::ostringstream h;
            if (!gentle && vt_ok_) h << "\x1b[H\x1b[0J";
            h << cHead() << "Miqrochain" << reset()
              << " " << cDim() << "(v" << MIQ_VERSION_MAJOR << "." << MIQ_VERSION_MINOR
              << " | Chain: " << CHAIN_NAME
              << " | P2P " << p2p_port_ << " | RPC " << rpc_port_ << ")" << reset();
            left.push_back(h.str());
            if (!banner_.empty()) left.push_back(std::string(cInfo()) + banner_ + reset());
            left.push_back("");
        }

        // Node state line
        {
            std::string dots; dots.assign(tick_ % 4, '.');
            std::ostringstream s;
            s << "  State: ";
            if (nstate_ == NodeState::Starting)     s << cWarn() << "starting" << reset() << dots;
            else if (nstate_ == NodeState::Syncing) s << cWarn() << "syncing"  << reset() << dots;
            else                                    s << cRun()  << "node running" << reset() << dots;
            left.push_back(s.str());
            left.push_back("");
        }

        // Startup progress
        {
            left.push_back(std::string(cPanel()) + "Startup" + reset());
            size_t total = steps_.size(), okc = 0;
            for (auto& s : steps_) if (s.second) ++okc;
            int bw = std::max(10, leftw - 20);
            std::ostringstream progress;
            progress << "  " << bar((uint64_t)okc, (uint64_t)std::max<size_t>(total,1), bw)
                     << "  " << okc << "/" << total << " completed";
            left.push_back(progress.str());
            for (auto& s : steps_) {
                left.push_back(std::string("    ") + (s.second ? (std::string(cOK()) + "[OK]" + reset() + " ") :
                        (std::string(cDim()) + "[..]" + reset() + " ")) + s.first);
            }
            left.push_back("");
        }

        // Node status (chain + p2p snapshot)
        {
            left.push_back(std::string(cPanel()) + "Node status" + reset());
            uint64_t height = chain_ ? chain_->height() : 0;
            std::string tip_hex;
            if (chain_) {
                auto t = chain_->tip();
                tip_hex = to_hex(t.hash);
            }

            size_t peers  = 0, inflight_tx = 0, rxbuf_sum = 0, awaiting_pongs = 0;
            if (p2p_) {
                auto v = p2p_->snapshot_peers();
                peers = v.size();
                for (auto& s : v) {
                    inflight_tx += (size_t)s.inflight;
                    rxbuf_sum   += (size_t)s.rx_buf;
                    if (s.awaiting_pong) ++awaiting_pongs;
                }
            }

            std::ostringstream ns1;
            ns1 << "  height: " << height
                << "   tip: " << short_hash(tip_hex, 12)
                << "   peers: " << peers;
            left.push_back(ns1.str());

            std::ostringstream ns2;
            ns2 << "  inflight tx: " << inflight_tx
                << "   rx-buf: " << rxbuf_sum
                << "   pings-waiting: " << awaiting_pongs;
            left.push_back(ns2.str());

            // Last accepted block (any miner)
            if (!last_accept_line_.empty()) {
                left.push_back(std::string("  ") + cOK() + "Last accepted block" + reset() +
                               (last_accept_height_.empty() ? "" : (": height " + last_accept_height_)));
            }
            left.push_back("");
        }

        // Right panel: peers + miner panel
        if (p2p_) {
            right.push_back(std::string(cPanel()) + "Peers" + reset());
            std::ostringstream hdr;
            hdr << "  " << std::left << std::setw(16) << "IP"
                << "  verack  " << std::setw(8) << "last(ms)"
                << "  " << std::setw(6) << "rx"
                << "  " << std::setw(8) << "inflight";
            right.push_back(hdr.str());

            auto v = p2p_->snapshot_peers();
            size_t show = std::min(v.size(), (size_t)std::max(6, (int)((rows-16))));
            for (size_t i=0;i<show; ++i) {
                const auto& s = v[i];
                std::string ip = s.ip; if ((int)ip.size() > 16) ip = ip.substr(0,13) + "...";
                std::ostringstream ln;
                ln << "  " << std::left << std::setw(16) << ip
                   << "  " << (s.verack_ok ? (std::string(cOK()) + "ok" + reset()) : (std::string(cWarn()) + ".." + reset())) << "    "
                   << std::right << std::setw(8) << (uint64_t)s.last_seen_ms
                   << "  " << std::setw(6) << (uint64_t)s.rx_buf
                   << "  " << std::setw(8) << (uint64_t)s.inflight;
                right.push_back(ln.str());
            }
            if (v.size() > show) {
                std::ostringstream more; more << "  ... +" << (v.size() - show) << " more";
                right.push_back(more.str());
            }
            right.push_back("");
        }

        // Miner panel (built-in miner visibility)
        {
            right.push_back(std::string(cPanel()) + "Miner" + reset());
            bool active = g_miner_stats.active.load();
            unsigned thr = g_miner_stats.threads.load();
            uint64_t ok  = g_miner_stats.accepted.load();
            uint64_t rej = g_miner_stats.rejected.load();

            std::ostringstream m1;
            m1 << "  status: " << (active ? (std::string(cOK()) + "running" + reset()) : (std::string(cDim()) + "idle" + reset()))
               << "   threads: " << thr;
            right.push_back(m1.str());

            std::ostringstream m2;
            m2 << "  accepted: " << ok << "   rejected: " << rej;
            right.push_back(m2.str());

            // surface most recent success heights (ours & network)
            uint64_t last_ok = g_miner_stats.last_height_ok.load();
            uint64_t last_rx = g_miner_stats.last_height_rx.load();
            if (last_ok) {
                std::ostringstream m3; m3 << "  last (us): height " << last_ok;
                right.push_back(m3.str());
            }
            if (last_rx) {
                std::ostringstream m4; m4 << "  last (net): height " << last_rx;
                right.push_back(m4.str());
            }
            right.push_back("");
        }

        // Compose two columns
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
        out << cPanel() << "Logs" << reset() << "  " << cDim() << "(Ctrl+C to exit)" << reset() << "\n";
        int header_rows = (int)N + 2;
        int remain = rows - header_rows - 3;
        if (remain < 8) remain = 8;
        int start = (int)logs_.size() - remain;
        if (start < 0) start = 0;
        for (int i=start; i<(int)logs_.size(); ++i) {
            const auto& line = logs_[i].text;
            if      (line.find("[ERROR]") != std::string::npos) out << cErr()  << line << reset() << "\n";
            else if (line.find("[WARN]")  != std::string::npos) out << cWarn() << line << reset() << "\n";
            else if (line.find("[TRACE]") != std::string::npos) out << cDim()  << line << reset() << "\n";
            else if (line.find("mined block accepted") != std::string::npos) out << cOK() << line << reset() << "\n";
            else if (line.find("accepted block") != std::string::npos) out << cOK() << line << reset() << "\n";
            else out << line << "\n";
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
    std::deque<LogCapture::Line> logs_;
    std::string banner_;
    std::string last_accept_line_;
    std::string last_accept_height_;
    uint16_t p2p_port_{P2P_PORT};
    uint16_t rpc_port_{RPC_PORT};
    P2P*   p2p_   {nullptr};
    Chain* chain_ {nullptr};
    ConsoleWriter cw_;
    int  tick_{0};
    NodeState nstate_{NodeState::Starting};
};

// ---------- fatal terminate hook --------------------------------------------
static void fatal_terminate() noexcept {
    std::fputs("[FATAL] std::terminate() called from a background thread (suppressed to keep node alive)\n", stderr);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// ---------- miner worker -----------------------------------------------------
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

    while (!g_shutdown_requested.load()) {
        try {
            auto t = chain->tip();

            Transaction cbt;
            TxIn cin;
            cin.prev.txid = std::vector<uint8_t>(32, 0);
            cin.prev.vout = 0;
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

            std::vector<Transaction> txs;
            try {
                txs = collect_mempool_for_block(*mempool, cbt, kBlockMaxBytes);
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
                    log_info("mined block accepted, height=" + std::to_string(t.height + 1)
                             + ", miner=" + miner_addr
                             + ", coinbase_txid=" + cb_txid_hex
                             + ", txs=" + std::to_string(std::max(0, noncb)));
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

// ---------- usage ------------------------------------------------------------
static void print_usage(){
    std::cout
      << "miqrod (node) options:\n"
      << "  --conf=<path>                                config file (key=value)\n"
      << "  --datadir=<path>                             data directory (overrides config)\n"
      << "  --no-tui                                     disable the fancy console UI\n"
      << "  --genaddress                                 generate ECDSA-P2PKH address (priv/pk/address)\n"
      << "  --buildtx <priv_hex> <prev_txid_hex> <vout> <value> <to_address>  (prints txhex)\n"
      << "  --reindex_utxo                               rebuild chainstate/UTXO from current chain\n"
      << "  --utxo_kv                                    (reserved) enable KV-backed UTXO at runtime if supported\n"
      << "  --mine                                       (optional) run built-in miner [NOT default]\n"
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
    if(s=="--utxo_kv") return true;
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

// ---------- main -------------------------------------------------------------
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

    // Parse just --no-tui FIRST
    bool disable_tui_flag = false;
    for(int i=1;i<argc;i++){
        if(std::string(argv[i]) == "--no-tui") { disable_tui_flag = true; break; }
    }

    // IMPORTANT: decide TUI BEFORE any log-capture redirects
    const bool want_tui = !disable_tui_flag && !env_truthy("MIQ_NO_TUI");
    const bool console_is_tty = term::is_tty();
    const bool can_tui  = want_tui && console_is_tty;

    ConsoleWriter cw;
    cw.write_raw("Starting miqrod... (press Ctrl+C to exit)\n");

    // Start capture ONLY when TUI is enabled; otherwise keep plain logs to console
    LogCapture capture;
    if (can_tui) {
        capture.start();
    } else {
        std::fprintf(stderr, "[INFO] TUI disabled (plain logs).\n");
    }

    TUI tui(vt_ok);
    tui.set_enabled(can_tui);
    tui.set_ports(P2P_PORT, RPC_PORT);
    if (tui.is_enabled()) {
        tui.start();
        tui.set_banner("Preparing Miqrochain node...");
        tui.mark_step_ok("Parse CLI / environment");
        tui.set_node_state(TUI::NodeState::Starting);
    }

    try {
        // ----- Parse CLI (full) ------------------------------------------
        Config cfg;
        std::string conf;
        bool genaddr=false, buildtx=false, mine_flag=false;
        bool flag_reindex_utxo=false, flag_utxo_kv=false;
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
            } else if(a=="--utxo_kv"){ flag_utxo_kv = true;
            } else if(a=="--mine"){ mine_flag = true;
            } else if(a=="--help"){ print_usage(); if (can_tui){ capture.stop(); tui.stop(); } return 0; }
        }

        // ===== FAST PATHS =================================================
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
        // =================================================================

        if (can_tui) tui.mark_step_started("Load config & choose datadir");
        if(!conf.empty()) load_config(conf, cfg);
        if(cfg.datadir.empty()) cfg.datadir = default_datadir();
        std::error_code ec;
        std::filesystem::create_directories(cfg.datadir, ec);
        if (can_tui) {
            tui.mark_step_ok("Load config & choose datadir");
            tui.mark_step_ok("Config/datadir ready");
            tui.set_banner(std::string("Starting services...  Datadir: ") + cfg.datadir);
        }

        if (can_tui) tui.mark_step_started("Open chain data");
        Chain chain;
        if(!chain.open(cfg.datadir)){ log_error("failed to open chain data"); if (can_tui) { capture.stop(); tui.stop(); } return 1; }
        if (can_tui) tui.mark_step_ok("Open chain data");

        if (can_tui) tui.mark_step_started("Load & validate genesis");
        {
            std::vector<uint8_t> raw;
            try { raw = miq::from_hex(GENESIS_RAW_BLOCK_HEX); }
            catch (...) { log_error("GENESIS_RAW_BLOCK_HEX is not valid hex"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (raw.empty()) { log_error("GENESIS_RAW_BLOCK_HEX is empty"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            Block g;
            if (!deser_block(raw, g)) { log_error("Failed to deserialize GENESIS_RAW_BLOCK_HEX"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            const std::string got_hash = to_hex(g.block_hash());
            const std::string want_hash= std::string(GENESIS_HASH_HEX);
            const std::string got_merkle = to_hex(g.header.merkle_root);
            const std::string want_merkle= std::string(GENESIS_MERKLE_HEX);
            if (got_hash != want_hash)    { log_error(std::string("Genesis hash mismatch. got=")+got_hash+" want="+want_hash); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (got_merkle != want_merkle){ log_error(std::string("Genesis merkle mismatch. got=")+got_merkle+" want="+want_merkle); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
            if (!chain.init_genesis(g))   { log_error("genesis init failed"); if (can_tui){ capture.stop(); tui.stop(); } return 1; }
        }
        if (can_tui) { tui.mark_step_ok("Load & validate genesis"); tui.mark_step_ok("Genesis OK"); }

        if (flag_utxo_kv) { log_info("Flag --utxo_kv set (runtime no-op; UTXO KV backend is compiled-in)."); }
        if (flag_reindex_utxo) {
            if (can_tui) tui.mark_step_started("Reindex UTXO (full scan)");
            log_info("ReindexUTXO: rebuilding chainstate from active chain...");
            UTXOKV utxo_kv; std::string err;
            if (!ReindexUTXO(chain, utxo_kv, /*compact_after=*/true, err)) {
                log_error(std::string("ReindexUTXO failed: ") + (err.empty() ? "unknown error" : err));
                if (can_tui) { capture.stop(); tui.stop(); }
                return 1;
            }
            log_info("ReindexUTXO: done");
            if (can_tui) tui.mark_step_ok("Reindex UTXO (full scan)");
        }

        if (can_tui) tui.mark_step_started("Initialize mempool & RPC gate");
        Mempool mempool; RpcService rpc(chain, mempool);
        if (can_tui) tui.mark_step_ok("Initialize mempool & RPC gate");

        P2P p2p(chain);
        p2p.set_datadir(cfg.datadir);
        p2p.set_mempool(&mempool);
        rpc.set_p2p(&p2p);
        if (can_tui) tui.set_runtime_refs(&p2p, &chain);

        if (can_tui) { tui.mark_step_started("Start P2P listener"); tui.set_node_state(TUI::NodeState::Starting); }
        bool p2p_ok = false;
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

        // surface accepted blocks coming from the network (not just our miner)
        // by watching chain tip in the main loop below; update g_miner_stats.last_height_rx

        // Optional built-in miner
        unsigned threads = 0;
        if (mine_flag) {
            if (cfg.miner_threads) threads = cfg.miner_threads;
            if (threads == 0) {
                if (const char* s = std::getenv("MIQ_MINER_THREADS")) {
                    char* end = nullptr; long v = std::strtol(s, &end, 10);
                    if (end != s && v > 0 && v <= 256) threads = (unsigned)v;
                }
            }
            if (threads == 0) threads = std::max(1u, std::thread::hardware_concurrency());

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
        if (can_tui) {
            tui.set_banner("Miqrochain node running - syncing & serving peers...");
            if ((p2p_ok || cfg.no_p2p) && rpc_ok) tui.set_node_state(TUI::NodeState::Running);
            else tui.set_node_state(TUI::NodeState::Syncing);
        }

        // main loop: feed logs & track network accept events by tip height drift
        uint64_t last_tip_height_seen = 0;
        if (can_tui) {
            while(!g_shutdown_requested.load()){
                std::this_thread::sleep_for(std::chrono::milliseconds(150));
                std::deque<LogCapture::Line> lines;
                capture.drain(lines);
                tui.feed_logs(lines);

                // update "any miner accepted" by watching chain height advance
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

        log_info("Shutdown requested — stopping services...");
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
