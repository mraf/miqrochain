// src/cli/miqwallet.cpp
// Menu-driven MIQ wallet CLI (create/recover/send + live confirmations).
// Auto-discovers RPC token and can work remotely (no local node required).

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
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#include "constants.h"  // RPC_PORT, CHAIN_NAME, COIN

// ---------- trim ----------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}

// ---------- default datadir ----------
static std::string default_datadir(){
#ifdef _WIN32
    // %APPDATA%\miqrochain
    char* appdata = nullptr;
    size_t sz=0;
    _dupenv_s(&appdata, &sz, "APPDATA");
    std::string r = appdata ? std::string(appdata) : std::string(".");
    if (appdata) free(appdata);
    if (!r.empty() && r.back()!='\\') r.push_back('\\');
    r += "miqrochain";
    return r;
#elif __APPLE__
    const char* home = std::getenv("HOME");
    std::string r = home ? std::string(home) : std::string(".");
    if (!r.empty() && r.back()!='/') r.push_back('/');
    r += "Library/Application Support/miqrochain";
    return r;
#else
    const char* home = std::getenv("HOME");
    std::string r = home ? std::string(home) : std::string(".");
    if (!r.empty() && r.back()!='/') r.push_back('/');
    r += ".miqrochain";
    return r;
#endif
}

static bool read_first_line_trim(const std::string& path, std::string& out){
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if(!f.good()) return false;
    std::string s; std::getline(f, s);
    while(!s.empty() && (s.back()=='\r'||s.back()=='\n'||s.back()==' '||s.back()=='\t')) s.pop_back();
    out = s;
    return !out.empty();
}

// ---------- token discovery ----------
struct AuthInfo{
    std::string token;
    std::string source;
};

static bool read_token_from_conf(const std::string& conf_path, std::string& out){
    std::ifstream f(conf_path, std::ios::in | std::ios::binary);
    if(!f.good()) return false;
    std::string line;
    while (std::getline(f, line)) {
        if(!line.empty() && line.back()=='\r') line.pop_back();
        size_t i=0; while(i<line.size() && (line[i]==' '||line[i]=='\t')) ++i;
        if(i>=line.size() || line[i]=='#' || line[i]==';') continue;
        size_t eq = line.find('=', i);
        if (eq==std::string::npos) continue;
        std::string key = line.substr(i, eq-i);
        while(!key.empty() && (key.back()==' '||key.back()=='\t')) key.pop_back();
        if (key != "rpc_static_token") continue;
        std::string val = line.substr(eq+1);
        size_t a=0,b=val.size();
        while(a<b && (val[a]==' '||val[a]=='\t')) ++a;
        while(b>a && (val[b-1]==' '||val[b-1]=='\t')) --b;
        out = val.substr(a,b-a);
        return !out.empty();
    }
    return false;
}

static AuthInfo auto_load_token(std::string datadir, const std::string& token_file_hint){
    AuthInfo ai;

    // 1) explicit token file hint
    if(!token_file_hint.empty()){
        if (read_first_line_trim(token_file_hint, ai.token)) {
            ai.source = token_file_hint;
            return ai;
        }
    }

    // 2) env MIQ_RPC_TOKEN or MIQ_RPC_STATIC_TOKEN
    if(const char* t = std::getenv("MIQ_RPC_TOKEN"); t && *t){
        ai.token = t; ai.source = "env:MIQ_RPC_TOKEN"; return ai;
    }
    if(const char* t2 = std::getenv("MIQ_RPC_STATIC_TOKEN"); t2 && *t2){
        ai.token = t2; ai.source = "env:MIQ_RPC_STATIC_TOKEN"; return ai;
    }

    // 3) env MIQ_RPC_TOKEN_FILE
    if(const char* tf = std::getenv("MIQ_RPC_TOKEN_FILE"); tf && *tf){
        if (read_first_line_trim(tf, ai.token)) { ai.source = tf; return ai; }
    }

    // 4) datadir files (if present on this machine)
    if(datadir.empty()){
        const char* d = std::getenv("MIQ_DATADIR");
        if(d && *d) datadir = d;
        else datadir = default_datadir();
    }

#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    auto join=[&](const std::string& a, const std::string& b)->std::string{
        if(a.empty()) return b;
        if(a.back()==sep) return a+b;
        return a + sep + b;
    };

    // .cookie
    {
        std::string p = join(datadir, ".cookie");
        if (read_first_line_trim(p, ai.token)) { ai.source = p; return ai; }
    }
    // .rpctoken
    {
        std::string p = join(datadir, ".rpctoken");
        if (read_first_line_trim(p, ai.token)) { ai.source = p; return ai; }
    }
    // miq.conf -> rpc_static_token
    {
        std::string p = join(datadir, "miq.conf");
        if (read_token_from_conf(p, ai.token)) { ai.source = p; return ai; }
    }

    // 5) none found
    ai.token.clear();
    ai.source.clear();
    return ai;
}

// ---------- tiny JSON helpers ----------
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

// ---------- very small HTTP POST ----------
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

    // split headers/body
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
                            const std::string& token,
                            const std::string& host, const std::string& port)
{
    std::ostringstream b;
    b << "{\"method\":" << json_escape(method);
    if (!params_json.empty()) {
        b << ",\"params\":[";
        for (size_t i=0;i<params_json.size();++i) {
            if (i) b << ',';
            b << params_json[i]; // already JSON-escaped by caller if string
        }
        b << "]";
    }
    b << "}";
    std::string resp, status;
    if (!http_post(host, port, "/", token, b.str(), resp, &status)) return "";
    return trim(resp);
}

static std::string jstrp(const std::string& s) { return json_escape(s); }

// ---------- wallet ops ----------
static bool unlock_if_needed(const std::string& token, const std::string& host, const std::string& port) {
    std::cout << "\nWallet passphrase (leave blank if not encrypted): ";
    std::string pass; std::getline(std::cin, pass);
    if (trim(pass).empty()) return true;
    std::string r = rpc_call("walletunlock", { jstrp(pass), "600" }, token, host, port);
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Unlock failed: " << r << "\n";
        return false;
    }
    return true;
}

static bool op_show_balance(const std::string& token, const std::string& host, const std::string& port){
    std::string bal = rpc_call("getbalance", {}, token, host, port);
    if (bal.empty()) { std::cout << "RPC error.\n"; return false; }
    long long miqron=0; std::string miqPretty;
    json_get_number_field_ll(bal, "miqron", miqron);
    json_get_string_field(bal, "miq", miqPretty);
    if (miqPretty.empty()) {
        // fallback formatting
        std::ostringstream s; s << (miqron / (long long)COIN) << "." << std::setw(8) << std::setfill('0') << (miqron % (long long)COIN);
        miqPretty = s.str();
    }
    std::cout << "Balance: " << miqPretty << " MIQ (" << miqron << " miqron)\n";
    return true;
}

static bool op_create_wallet(const std::string& token, const std::string& host, const std::string& port) {
    std::cout << "\n-- Create new HD wallet --\n";
    std::cout << "Optional wallet passphrase (ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string r = rpc_call("createhdwallet", { "\"\"", "\"\"", jstrp(wpass) }, token, host, port);
    if (r.empty() || r.find("\"error\"") != std::string::npos) {
        std::cout << "Create failed: " << r << "\n";
        return false;
    }
    std::string mnemonic;
    if (!json_get_string_field(r, "mnemonic", mnemonic)) {
        std::cout << "Unexpected response: " << r << "\n";
        return false;
    }

    std::cout << "\nYour mnemonic (WRITE IT DOWN, offline!):\n\n";
    std::cout << "  " << mnemonic << "\n\n";

    // unlock if pass set
    if (!wpass.empty()) {
        std::string ur = rpc_call("walletunlock", { jstrp(wpass), "600" }, token, host, port);
        if (ur.find("\"error\"") != std::string::npos) {
            std::cout << "Unlock failed: " << ur << "\n";
            return false;
        }
    }

    std::string addr = rpc_call("getnewaddress", {}, token, host, port);
    if (!json_is_string_value(addr, addr)) {
        std::cout << "Could not get receive address: " << addr << "\n";
        return false;
    }
    std::cout << "First receive address:\n";
    std::cout << "  " << addr << "\n";

    (void)op_show_balance(token, host, port);
    return true;
}

static bool op_recover_wallet(const std::string& token, const std::string& host, const std::string& port) {
    std::cout << "\n-- Recover HD wallet --\n";
    std::cout << "Paste 12 or 24-word mnemonic:\n> ";
    std::string mnemonic; std::getline(std::cin, mnemonic);
    mnemonic = trim(mnemonic);

    std::cout << "BIP39 mnemonic passphrase (ENTER if none): ";
    std::string mpass; std::getline(std::cin, mpass);

    std::cout << "Wallet encryption passphrase (new; ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string r = rpc_call("restorehdwallet", { jstrp(mnemonic), jstrp(mpass), jstrp(wpass) }, token, host, port);
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Restore failed: " << r << "\n";
        return false;
    }
    std::cout << "Restored.\n";

    if (!wpass.empty()) {
        std::string ur = rpc_call("walletunlock", { jstrp(wpass), "600" }, token, host, port);
        if (ur.find("\"error\"") != std::string::npos) {
            std::cout << "Unlock failed: " << ur << "\n";
        }
    }

    return op_show_balance(token, host, port);
}

static bool tx_in_mempool(const std::string& token, const std::string& host, const std::string& port, const std::string& txid) {
    std::string mp = rpc_call("getrawmempool", {}, token, host, port);
    std::string needle = "\"" + txid + "\"";
    return mp.find(needle) != std::string::npos;
}

static int tx_confirmations_via_recipient(const std::string& token,
                                          const std::string& host,
                                          const std::string& port,
                                          const std::string& txid,
                                          const std::string& recipient_addr)
{
    if (tx_in_mempool(token, host, port, txid)) return 0;

    std::string utx = rpc_call("getaddressutxos", { jstrp(recipient_addr) }, token, host, port);
    size_t pos = 0;
    int txHeight = -1;
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
                else {
                    auto col = utx.find(':', ph);
                    if (col != std::string::npos) {
                        ++col; while (col<utx.size() && std::isspace((unsigned char)utx[col])) ++col;
                        int v=0; while (col<utx.size() && std::isdigit((unsigned char)utx[col])) { v = v*10 + (utx[col]-'0'); ++col; }
                        txHeight = v;
                    }
                }
            }
            break;
        }
    }
    if (txHeight < 0) return 0;

    std::string hjson = rpc_call("getblockcount", {}, token, host, port);
    std::string hs; if (!json_is_string_value(hjson, hs)) hs = hjson;
    int curH = std::stoi(hs);
    int confs = (curH - txHeight + 1);
    if (confs < 0) confs = 0;
    return confs;
}

static bool op_send_flow(const std::string& token, const std::string& host, const std::string& port) {
    std::cout << "\n-- Send MIQ --\n";
    if (!unlock_if_needed(token, host, port)) return false;

    std::cout << "Recipient address: ";
    std::string addr; std::getline(std::cin, addr); addr = trim(addr);
    if (addr.empty()) { std::cout << "Canceled.\n"; return false; }

    std::cout << "Amount (MIQ, e.g. 1.23456789): ";
    std::string amt; std::getline(std::cin, amt); amt = trim(amt);
    if (amt.empty()) { std::cout << "Canceled.\n"; return false; }

    std::cout << "Sending " << amt << " MIQ to " << addr << " ...\n";
    std::string r = rpc_call("sendfromhd", { jstrp(addr), jstrp(amt) }, token, host, port);
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

    std::cout << "Waiting for confirmations (target: 3). Press Ctrl+C to stop watching.\n";
    int last = -1;
    for (;;) {
        int c = tx_confirmations_via_recipient(token, host, port, txid, addr);
        if (c != last) {
            if (c == 0) std::cout << "  0-conf (in mempool or not yet seen)\n";
            else std::cout << "  confirmations: " << c << "\n";
            last = c;
        }
        if (c >= 3) break;
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    std::cout << "Reached 3 confirmations.\n";
    return true;
}

// ---------- arg/env parsing ----------
struct Conn {
    std::string host = "127.0.0.1";
    std::string port = std::to_string(RPC_PORT);
    std::string datadir;          // optional
    std::string token_file_hint;  // optional
    std::string token;            // resolved
    std::string token_source;     // for display
};

static void apply_env(Conn& c){
    if(const char* h = std::getenv("MIQ_RPC_HOST"); h && *h) c.host = h;
    if(const char* p = std::getenv("MIQ_RPC_PORT"); p && *p) c.port = p;
    if(const char* d = std::getenv("MIQ_DATADIR");  d && *d) c.datadir = d;
    if(const char* tf= std::getenv("MIQ_RPC_TOKEN_FILE"); tf && *tf) c.token_file_hint = tf;
    if(const char* t = std::getenv("MIQ_RPC_TOKEN"); t && *t){ c.token = t; c.token_source = "env:MIQ_RPC_TOKEN"; }
    if(c.token.empty()){
        if(const char* t2 = std::getenv("MIQ_RPC_STATIC_TOKEN"); t2 && *t2){ c.token = t2; c.token_source = "env:MIQ_RPC_STATIC_TOKEN"; }
    }
}

static void apply_args(Conn& c, int argc, char** argv){
    for (int i=1;i<argc;i++){
        std::string a = argv[i];
        auto next = [&](std::string& dst){
            if (i+1 < argc) { dst = argv[++i]; return true; }
            return false;
        };
        if (a=="--host") { next(c.host); }
        else if (a=="--port") { next(c.port); }
        else if (a=="--datadir") { next(c.datadir); }
        else if (a=="--token-file") { next(c.token_file_hint); }
        else if (a=="--token") { next(c.token); c.token_source="--token"; }
        else if (a=="-h" || a=="--help") {
            std::cout <<
              "Usage: miqwallet [--host HOST] [--port PORT] [--datadir PATH]\n"
              "                 [--token TOKEN] [--token-file FILE]\n";
        }
    }
}

// ---------- main menu ----------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    Conn C;
    apply_env(C);
    apply_args(C, argc, argv);

    if (C.datadir.empty()) C.datadir = default_datadir();

    // If no inline/env token, auto-load from file/env/datadir
    if (C.token.empty()) {
        auto ai = auto_load_token(C.datadir, C.token_file_hint);
        C.token = ai.token; C.token_source = ai.source;
    }

    // If still none, we'll continue and let RPC fail (prints helpful error),
    // but try to show where we looked:
    std::cout << "Target: miqrochain RPC at " << C.host << ":" << C.port << "\n";
    if (!C.token.empty()) {
        std::cout << "Auth source: " << (C.token_source.empty()? "(unknown)" : C.token_source) << "\n";
    } else {
        std::cout << "Auth source: (none auto-discovered)\n";
        std::cout << "Tip: set MIQ_RPC_TOKEN env var, or pass --token, or use --token-file, or place a .cookie/.rpctoken/miq.conf in " << C.datadir << "\n";
    }

    // Light ping to detect auth issues early
    if (!C.token.empty()){
        std::string ping = rpc_call("ping", {}, C.token, C.host, C.port);
        if (trim(ping) != "\"pong\"") {
            std::cout << "Warning: RPC not reachable or token invalid. Server replied: " << ping << "\n";
        }
    }

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

        if (choice=="1") { (void)op_create_wallet(C.token, C.host, C.port); }
        else if (choice=="2") { (void)op_recover_wallet(C.token, C.host, C.port); }
        else if (choice=="3") { (void)op_send_flow(C.token, C.host, C.port); }
        else if (choice=="4") { (void)op_show_balance(C.token, C.host, C.port); }
        else if (choice=="q" || choice=="Q" || choice=="exit") break;
    }

    return 0;
}
