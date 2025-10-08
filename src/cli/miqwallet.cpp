// src/cli/miqwallet.cpp
// Portable MIQ wallet CLI (create/recover/send + live confirmations) with
// robust remote RPC support and multi-source token discovery.
//
// It can run on any PC without a local node. It talks to a remote node via RPC.
// Token discovery order:
//   1) --token / MIQW_TOKEN
//   2) --cookie / MIQW_COOKIE_PATH (any path, including UNC)
//   3) CWD: .cookie / miqwallet.token / miqrpc.token
//   4) EXE dir: .cookie / miqwallet.token / miqrpc.token
//   5) OS default datadirs (Roaming on Windows etc.)

#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <fstream>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #include <windows.h>
  #pragma comment(lib, "ws2_32.lib")
#elif __APPLE__
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <mach-o/dyld.h>
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <limits.h>
#endif

#include "constants.h"  // miq::RPC_PORT, miq::CHAIN_NAME, miq::COIN

// -------------------- runtime RPC target --------------------
static std::string g_rpc_host = "127.0.0.1";
static std::string g_rpc_port = std::to_string(miq::RPC_PORT);

// -------------------- tiny helpers --------------------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
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

static bool read_first_line(const std::string& full_path, std::string& out_tok) {
    std::ifstream f(full_path, std::ios::in | std::ios::binary);
    if (!f.good()) return false;
    std::string line;
    std::getline(f, line);
    out_tok = trim(line);
    return !out_tok.empty();
}

static std::string json_escape(const std::string& s) {
    std::ostringstream o;
    o << '"';
    for (char c: s) {
        switch(c){
            case '"':  o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b";  break;
            case '\f': o << "\\f";  break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if ((unsigned char)c < 0x20) { o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c; }
                else o << c;
        }
    }
    o << '"';
    return o.str();
}

// very small JSON field helpers (good enough for known responses)
static bool json_get_string_field(const std::string& json, const std::string& key, std::string& out) {
    std::string pattern = "\"" + key + "\"";
    auto p = json.find(pattern);
    if (p == std::string::npos) return false;
    p = json.find(':', p);
    if (p == std::string::npos) return false;
    while (p < json.size() && (json[p]==':' || std::isspace((unsigned char)json[p]))) ++p;
    if (p >= json.size() || json[p] != '"') return false;
    ++p;
    std::ostringstream v;
    while (p < json.size()) {
        char c = json[p++];
        if (c == '\\') {
            if (p < json.size()) {
                char n = json[p++];
                if (n=='"'||n=='\\'||n=='/') v<<n;
                else if (n=='b') v<<'\b';
                else if (n=='f') v<<'\f';
                else if (n=='n') v<<'\n';
                else if (n=='r') v<<'\r';
                else if (n=='t') v<<'\t';
                else v<<n;
            }
        } else if (c == '"') break;
        else v << c;
    }
    out = v.str();
    return true;
}
static bool json_get_number_field_ll(const std::string& json, const std::string& key, long long& out) {
    std::string pattern = "\"" + key + "\"";
    auto p = json.find(pattern);
    if (p == std::string::npos) return false;
    p = json.find(':', p);
    if (p == std::string::npos) return false;
    ++p;
    while (p < json.size() && std::isspace((unsigned char)json[p])) ++p;
    bool neg=false; if (p < json.size() && json[p]=='-') { neg=true; ++p; }
    long long v=0; bool any=false;
    while (p < json.size() && std::isdigit((unsigned char)json[p])) { any=true; v = v*10 + (json[p]-'0'); ++p; }
    if (!any) return false;
    out = neg ? -v : v;
    return true;
}
static bool json_is_string_value(const std::string& body, std::string& out) {
    std::string s = trim(body);
    if (s.size() >= 2 && s.front()=='"' && s.back()=='"') {
        out = s.substr(1, s.size()-2);
        return true;
    }
    return false;
}

// -------------------- HTTP POST --------------------
static bool http_post(const std::string& host, const std::string& port,
                      const std::string& path, const std::string& token,
                      const std::string& body, std::string& out_body, std::string* out_status=nullptr)
{
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
    addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
    addrinfo* res=nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }
    int fd = -1; addrinfo* rp=res;
    for (; rp; rp=rp->ai_next) {
        fd = (int)socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, (int)rp->ai_addrlen) == 0) break;
#ifdef _WIN32
        closesocket(fd);
#else
        close(fd);
#endif
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }

    std::ostringstream req;
    req << "POST " << path << " HTTP/1.1\r\n"
        << "Host: " << host << ":" << port << "\r\n"
        << "Connection: close\r\n"
        << "Content-Type: application/json\r\n";
    if (!token.empty()) req << "Authorization: " << token << "\r\n";
    req << "Content-Length: " << body.size() << "\r\n\r\n"
        << body;

    std::string data = req.str();
    size_t sent = 0;
    while (sent < data.size()) {
#ifdef _WIN32
        int n = send(fd, data.data() + sent, (int)(data.size() - sent), 0);
#else
        ssize_t n = send(fd, data.data() + sent, data.size() - sent, 0);
#endif
        if (n <= 0) break;
        sent += (size_t)n;
    }

    std::string resp;
    char buf[4096];
    for (;;) {
#ifdef _WIN32
        int n = recv(fd, buf, sizeof(buf), 0);
#else
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
#endif
        if (n <= 0) break;
        resp.append(buf, buf+n);
    }
#ifdef _WIN32
    closesocket(fd); WSACleanup();
#else
    close(fd);
#endif

    auto p = resp.find("\r\n\r\n");
    if (p == std::string::npos) return false;
    std::string headers = resp.substr(0, p);
    std::string bodyOut = resp.substr(p+4);

    if (out_status) {
        auto sp = headers.find(' ');
        if (sp != std::string::npos) {
            auto sp2 = headers.find(' ', sp+1);
            if (sp2 != std::string::npos) *out_status = headers.substr(sp+1, sp2-sp-1);
        }
    }
    out_body = bodyOut;
    return true;
}

static std::string rpc_call(const std::string& method, const std::vector<std::string>& params_json,
                            const std::string& token)
{
    std::ostringstream b;
    b << "{\"method\":" << json_escape(method);
    if (!params_json.empty()) {
        b << ",\"params\":[";
        for (size_t i=0;i<params_json.size();++i) {
            if (i) b << ',';
            b << params_json[i];
        }
        b << "]";
    }
    b << "}";
    std::string resp, status;
    if (!http_post(g_rpc_host, g_rpc_port, "/", token, b.str(), resp, &status)) return "";
    return trim(resp);
}

static std::string jstrp(const std::string& s) { return json_escape(s); }

// -------------------- EXE directory --------------------
static std::string g_exe_dir = ".";
static void init_exe_dir(const char* argv0) {
#ifdef _WIN32
    char path[MAX_PATH+4] = {0};
    DWORD n = GetModuleFileNameA(NULL, path, MAX_PATH);
    std::string p = (n>0) ? std::string(path, path+n) : std::string(argv0?argv0:"");
#elif __APPLE__
    uint32_t size = 0; _NSGetExecutablePath(NULL, &size);
    std::string p;
    if (size > 0) {
        std::vector<char> buf(size+2, 0);
        if (_NSGetExecutablePath(buf.data(), &size) == 0) p.assign(buf.data());
        else p = argv0 ? argv0 : "";
    } else p = argv0 ? argv0 : "";
#else
    char path[4096]; ssize_t n = readlink("/proc/self/exe", path, sizeof(path)-1);
    std::string p = (n>0) ? std::string(path, path+n) : std::string(argv0?argv0:"");
#endif
    size_t pos = p.find_last_of("/\\");
    g_exe_dir = (pos!=std::string::npos) ? p.substr(0,pos) : std::string(".");
}

// -------------------- cookie discovery --------------------
static std::string detect_default_datadir() {
    const char* dd = std::getenv("MIQ_DATADIR");
    if (dd && *dd) return std::string(dd);
    const char* wdd = std::getenv("MIQW_DATADIR");
    if (wdd && *wdd) return std::string(wdd);

#ifdef _WIN32
    const char* appdata = std::getenv("APPDATA"); // C:\Users\<user>\AppData\Roaming
    if (appdata && *appdata) return join_path(appdata, "miqrochain");
    return "C:\\miqrochain";
#elif __APPLE__
    const char* home = std::getenv("HOME");
    if (home && *home) return join_path(join_path(home, "Library/Application Support"), "miqrochain");
    return "miqrochain";
#else
    const char* xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg) return join_path(xdg, "miqrochain");
    const char* home = std::getenv("HOME");
    if (home && *home) return join_path(home, ".miqrochain");
    return ".";
#endif
}

static bool find_token_multi(std::string& out_token, std::string& used_path,
                             const std::string& cli_token,
                             const std::string& cli_cookie_path)
{
    // 1) Direct token (CLI/env)
    if (!cli_token.empty()) { out_token = cli_token; used_path = "<direct token>"; return true; }
    if (const char* et = std::getenv("MIQW_TOKEN"); et && *et) { out_token = et; used_path = "<env:MIQW_TOKEN>"; return true; }

    // 2) Explicit cookie path (CLI/env) — can be local or UNC
    std::string cp = cli_cookie_path;
    if (cp.empty()) { if (const char* ec = std::getenv("MIQW_COOKIE_PATH"); ec && *ec) cp = ec; }
    if (!cp.empty()) {
        if (read_first_line(cp, out_token)) { used_path = cp; return true; }
    }

    // 3) Current working directory candidates
    const char* cwd_candidates[] = { ".cookie", "miqwallet.token", "miqrpc.token" };
    for (const char* c : cwd_candidates) {
        if (read_first_line(c, out_token)) { used_path = c; return true; }
    }

    // 4) EXE directory candidates
    if (!g_exe_dir.empty()) {
        for (const char* nm : cwd_candidates) {
            std::string p = join_path(g_exe_dir, nm);
            if (read_first_line(p, out_token)) { used_path = p; return true; }
        }
    }

    // 5) OS default datadir
    {
        std::string dd = detect_default_datadir();
        std::string ck = join_path(dd, ".cookie");
        if (read_first_line(ck, out_token)) { used_path = ck; return true; }
    }

    return false;
}

// -------------------- wallet ops --------------------
static bool unlock_if_needed(const std::string& token) {
    std::cout << "\nWallet passphrase (leave blank if not encrypted): ";
    std::string pass; std::getline(std::cin, pass);
    if (trim(pass).empty()) return true;
    std::string r = rpc_call("walletunlock", { jstrp(pass), "600" }, token);
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Unlock failed: " << r << "\n";
        return false;
    }
    return true;
}

static bool show_balance(const std::string& token) {
    std::string bal = rpc_call("getbalance", {}, token);
    if (bal.empty()) { std::cout << "RPC failed (getbalance)\n"; return false; }
    long long miqron=0; std::string pretty;
    json_get_number_field_ll(bal, "miqron", miqron);
    json_get_string_field(bal, "miq", pretty);
    if (pretty.empty()) {
        std::ostringstream s;
        s << (miqron / (long long)miq::COIN) << "."
          << std::setw(8) << std::setfill('0') << (miqron % (long long)miq::COIN);
        pretty = s.str();
    }
    std::cout << "Balance: " << pretty << " MIQ (" << miqron << " miqron)\n";
    return true;
}

static bool op_create_wallet(const std::string& token) {
    std::cout << "\n-- Create new HD wallet --\n";
    std::cout << "Optional wallet passphrase (ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string r = rpc_call("createhdwallet", { "\"\"", "\"\"", jstrp(wpass) }, token);
    if (r.empty() || r.find("\"error\"") != std::string::npos) {
        std::cout << "Create failed: " << r << "\n";
        return false;
    }
    std::string mnemonic;
    if (!json_get_string_field(r, "mnemonic", mnemonic)) {
        std::cout << "Unexpected response: " << r << "\n";
        return false;
    }

    std::cout << "\nYour mnemonic (WRITE IT DOWN, keep offline!):\n\n  " << mnemonic << "\n\n";

    if (!wpass.empty()) {
        std::string ur = rpc_call("walletunlock", { jstrp(wpass), "600" }, token);
        if (ur.find("\"error\"") != std::string::npos) {
            std::cout << "Unlock failed: " << ur << "\n";
            return false;
        }
    }

    std::string addr = rpc_call("getnewaddress", {}, token);
    if (!json_is_string_value(addr, addr)) {
        std::cout << "Could not get receive address: " << addr << "\n";
        return false;
    }
    std::cout << "First receive address:\n  " << addr << "\n";

    show_balance(token);
    return true;
}

static bool op_recover_wallet(const std::string& token) {
    std::cout << "\n-- Recover HD wallet --\n";
    std::cout << "Paste 12 or 24-word mnemonic:\n> ";
    std::string mnemonic; std::getline(std::cin, mnemonic);
    mnemonic = trim(mnemonic);

    std::cout << "BIP39 mnemonic passphrase (ENTER if none): ";
    std::string mpass; std::getline(std::cin, mpass);

    std::cout << "Wallet encryption passphrase (new; ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string r = rpc_call("restorehdwallet", { jstrp(mnemonic), jstrp(mpass), jstrp(wpass) }, token);
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Restore failed: " << r << "\n";
        return false;
    }
    std::cout << "Restored.\n";

    if (!wpass.empty()) {
        std::string ur = rpc_call("walletunlock", { jstrp(wpass), "600" }, token);
        if (ur.find("\"error\"") != std::string::npos) {
            std::cout << "Unlock failed: " << ur << "\n";
        }
    }

    show_balance(token);
    return true;
}

static bool tx_in_mempool(const std::string& token, const std::string& txid) {
    std::string mp = rpc_call("getrawmempool", {}, token);
    std::string needle = "\"" + txid + "\"";
    return mp.find(needle) != std::string::npos;
}

static bool op_send_flow(const std::string& token) {
    std::cout << "\n-- Send MIQ --\n";
    if (!unlock_if_needed(token)) return false;

    std::cout << "Recipient address: ";
    std::string addr; std::getline(std::cin, addr); addr = trim(addr);
    if (addr.empty()) { std::cout << "Canceled.\n"; return false; }

    std::cout << "Amount (MIQ, e.g. 1.23456789): ";
    std::string amt; std::getline(std::cin, amt); amt = trim(amt);
    if (amt.empty()) { std::cout << "Canceled.\n"; return false; }

    std::cout << "Sending " << amt << " MIQ to " << addr << " ...\n";
    std::string r = rpc_call("sendfromhd", { jstrp(addr), jstrp(amt) }, token);
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Send failed: " << r << "\n";
        return false;
    }
    std::string txid;
    if (!json_is_string_value(r, txid)) {
        std::cout << "Unexpected send response: " << r << "\n";
        return false;
    }
    std::cout << "Broadcasted. Txid: " << txid << "\n";

    // Live confirmations up to 3 (recipient-UTXO method)
    std::cout << "Waiting for confirmations (target: 3). Press Ctrl+C to stop watching.\n";
    int lastPrinted = -99;
    for (;;) {
        // query address utxos to get height
        std::string utx = rpc_call("getaddressutxos", { jstrp(addr) }, token);
        int txHeight = -1;
        size_t pos = 0;
        while (true) {
            auto p = utx.find("\"txid\"", pos);
            if (p == std::string::npos) break;
            auto pcol = utx.find(':', p);
            if (pcol == std::string::npos) break;
            auto pquo = utx.find('"', pcol+1);
            if (pquo == std::string::npos) break;
            auto pquo2 = utx.find('"', pquo+1);
            if (pquo2 == std::string::npos) break;
            std::string tid = utx.substr(pquo+1, pquo2-pquo-1);
            pos = pquo2+1;
            if (tid == txid) {
                auto ph = utx.find("\"height\"", pquo2);
                if (ph != std::string::npos) {
                    long long h=0;
                    if (json_get_number_field_ll(utx.substr(ph-20, 80), "height", h)) txHeight = (int)h;
                }
                break;
            }
        }

        int confs = 0;
        if (txHeight < 0) {
            confs = tx_in_mempool(token, txid) ? 0 : 0;
        } else {
            std::string hjson = rpc_call("getblockcount", {}, token);
            std::string hs; if (!json_is_string_value(hjson, hs)) hs = hjson;
            int curH = (hs.empty() ? 0 : std::stoi(hs));
            confs = (curH - txHeight + 1);
            if (confs < 0) confs = 0;
        }

        if (confs != lastPrinted) {
            if (confs == 0) std::cout << "  0-conf (in mempool or not yet seen)\n";
            else std::cout << "  confirmations: " << confs << "\n";
            lastPrinted = confs;
        }
        if (confs >= 3) break;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    std::cout << "Reached 3 confirmations.\n";
    return true;
}

// -------------------- CLI args --------------------
static void parse_args(int argc, char** argv, std::string& host, std::string& port, std::string& token, std::string& cookie_path) {
    if (const char* h = std::getenv("MIQW_RPC_HOST")) host = h;
    if (const char* p = std::getenv("MIQW_RPC_PORT")) port = p;
    if (const char* t = std::getenv("MIQW_TOKEN")) token = t;
    if (const char* c = std::getenv("MIQW_COOKIE_PATH")) cookie_path = c;

    for (int i=1;i<argc;i++){
        std::string a = argv[i];
        auto need = [&](const char* what)->const char*{
            if (i+1>=argc) { std::cerr << "Missing value for " << what << "\n"; std::exit(2); }
            return argv[++i];
        };
        if (a=="--host" || a=="-H") host = need("--host");
        else if (a=="--port" || a=="-P") port = need("--port");
        else if (a=="--token" || a=="-t") token = need("--token");
        else if (a=="--cookie" || a=="-c") cookie_path = need("--cookie");
        else if (a=="--help" || a=="-h") {
            std::cout <<
                "miqwallet options:\n"
                "  -H, --host   <host>    RPC host (default 127.0.0.1)\n"
                "  -P, --port   <port>    RPC port (default from constants)\n"
                "  -c, --cookie <path>    Path to .cookie (local or UNC)\n"
                "  -t, --token  <tok>     Authorization token string\n"
                "Env vars: MIQW_RPC_HOST, MIQW_RPC_PORT, MIQW_COOKIE_PATH, MIQW_TOKEN\n";
            std::exit(0);
        }
    }
}

// -------------------- main --------------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);
    init_exe_dir(argc>0 ? argv[0] : nullptr);

    std::string host = g_rpc_host;
    std::string port = g_rpc_port;
    std::string token;
    std::string cookie_path;

    parse_args(argc, argv, host, port, token, cookie_path);
    g_rpc_host = host;
    g_rpc_port = port;

    std::string used_source;
    if (!find_token_multi(token, used_source, token, cookie_path)) {
        std::cout << "Could not locate RPC token automatically.\n";
        std::cout << "Enter RPC token manually (or run with --cookie / --token): ";
        std::getline(std::cin, token);
        token = trim(token);
        if (token.empty()) {
            std::cerr << "No RPC token. Exiting.\n";
            return 1;
        }
        used_source = "<entered>";
    }

    std::cout << "Target: " << miq::CHAIN_NAME << " RPC at " << g_rpc_host << ":" << g_rpc_port << "\n";
    std::cout << "Auth source: " << used_source << "\n";

    for (;;) {
        std::cout << "\n==== MIQ Wallet ====\n";
        std::cout << "1) Create wallet (mnemonic + address)\n";
        std::cout << "2) Recover wallet (from 12/24 words) and show balance\n";
        std::cout << "3) Send MIQ (auto-fee) + live confirmations to 3\n";
        std::cout << "4) Show balance\n";
        std::cout << "q) Quit\n";
        std::cout << "> ";
        std::string choice; std::getline(std::cin, choice);
        choice = trim(choice);
        if (choice=="1") { (void)op_create_wallet(token); }
        else if (choice=="2") { (void)op_recover_wallet(token); }
        else if (choice=="3") { (void)op_send_flow(token); }
        else if (choice=="4") { (void)show_balance(token); }
        else if (choice=="q" || choice=="Q" || choice=="exit") break;
    }

    return 0;
}
