// src/cli/miqwallet.cpp
// MIQ wallet CLI with Bitcoin-like cookie-based HTTP Basic auth.
// - Works locally or remotely (no node required on the same machine).
// - Finds cookie automatically in common paths OR via env/flags.
// - Supports direct user/password if server uses rpcauth-style creds.
// Menu: 1) Create wallet  2) Recover  3) Send  4) Show balance  q) Quit

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
  #include <windows.h>
  #include <shlobj.h>
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #ifndef NOMINMAX
  #define NOMINMAX 1
  #endif
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
#endif

#include "constants.h"  // miq::RPC_PORT, miq::CHAIN_NAME, miq::COIN

using miq::RPC_PORT;
using miq::CHAIN_NAME;
using miq::COIN;

// ----------------- tiny helpers -----------------
static std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace((unsigned char)s[a])) ++a;
    while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    return s.substr(a, b-a);
}

static bool read_first_line(const std::string& path, std::string& out) {
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if (!f.good()) return false;
    std::getline(f, out);
    out = trim(out);
    return !out.empty();
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

// --------------- Base64 for HTTP Basic ---------------
static std::string b64_encode(const std::string& in){
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; out.reserve(((in.size()+2)/3)*4);
    size_t i=0;
    while(i+3 <= in.size()){
        unsigned v = (unsigned((unsigned char)in[i])<<16) | (unsigned((unsigned char)in[i+1])<<8) | unsigned((unsigned char)in[i+2]);
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]); out.push_back(T[(v>>6)&63]); out.push_back(T[v&63]);
        i += 3;
    }
    if(i+1 == in.size()){
        unsigned v = (unsigned((unsigned char)in[i])<<16);
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]); out.push_back('='); out.push_back('=');
    } else if(i+2 == in.size()){
        unsigned v = (unsigned((unsigned char)in[i])<<16) | (unsigned((unsigned char)in[i+1])<<8);
        out.push_back(T[(v>>18)&63]); out.push_back(T[(v>>12)&63]); out.push_back(T[(v>>6)&63]); out.push_back('=');
    }
    return out;
}
static std::string make_basic_auth(const std::string& userpass){
    return "Basic " + b64_encode(userpass);
}

// --------------- Cookie discovery (Bitcoin-like) ---------------
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

#ifdef _WIN32
static std::string win_get_known_folder(REFKNOWNFOLDERID rfid) {
    PWSTR p = nullptr;
    std::string out;
    if (SHGetKnownFolderPath(rfid, KF_FLAG_DEFAULT, NULL, &p) == S_OK && p) {
        int len = WideCharToMultiByte(CP_UTF8, 0, p, -1, nullptr, 0, nullptr, nullptr);
        if (len > 0) {
            std::string s; s.resize((size_t)len-1);
            WideCharToMultiByte(CP_UTF8, 0, p, -1, &s[0], len, nullptr, nullptr);
            out = s;
        }
        CoTaskMemFree(p);
    }
    return out;
}
#endif

struct RpcEndpoint {
    std::string host = "127.0.0.1";
    std::string port = std::to_string(RPC_PORT);
    std::string auth_header;      // "Authorization: Basic <...>"
    std::string auth_source;      // human-readable (cookie path, env, user:pass)
};

static bool find_cookie_auto(std::string& out_userpass, std::string& source_hint,
                             const std::string& cmd_cookiefile,
                             const std::string& cmd_datadir)
{
    // 1) MIQ_RPC_COOKIE (contents like "__cookie__:abcdef...")
    const char* env_cookie_line = std::getenv("MIQ_RPC_COOKIE");
    if(env_cookie_line && *env_cookie_line){
        out_userpass = env_cookie_line;
        source_hint  = "env:MIQ_RPC_COOKIE";
        return true;
    }

    // 2) Explicit cookie file via flag or env
    std::string cf;
    if(!cmd_cookiefile.empty()) cf = cmd_cookiefile;
    else {
        const char* e = std::getenv("MIQ_RPC_COOKIEFILE");
        if(e && *e) cf = e;
    }
    if(!cf.empty()){
        if(read_first_line(cf, out_userpass)) { source_hint = cf; return true; }
    }

    // 3) datadir/.cookie via flag
    if(!cmd_datadir.empty()){
        std::string p = join_path(cmd_datadir, ".cookie");
        if(read_first_line(p, out_userpass)) { source_hint = p; return true; }
    }

    // 4) Default locations (Windows-first)
#ifdef _WIN32
    {
        std::vector<std::string> cands;

        // %APPDATA%\miqrochain\.cookie
        char* appdata = nullptr; size_t _sz=0;
        _dupenv_s(&appdata, &_sz, "APPDATA");
        if(appdata && *appdata) cands.push_back(join_path(std::string(appdata), "miqrochain\\.cookie"));
        if(appdata) free(appdata);

        // %LOCALAPPDATA%\miqrochain\.cookie
        char* lad = nullptr; _dupenv_s(&lad, &_sz, "LOCALAPPDATA");
        if(lad && *lad) cands.push_back(join_path(std::string(lad), "miqrochain\\.cookie"));
        if(lad) free(lad);

        // KnownFolder Roaming
        auto roaming = win_get_known_folder(FOLDERID_RoamingAppData);
        if(!roaming.empty()) cands.push_back(join_path(roaming, "miqrochain\\.cookie"));

        // %USERPROFILE%\.miqrochain\.cookie
        char* up = nullptr; _dupenv_s(&up, &_sz, "USERPROFILE");
        if(up && *up) cands.push_back(join_path(std::string(up), ".miqrochain\\.cookie"));
        if(up) free(up);

        for(const auto& p : cands){
            if(read_first_line(p, out_userpass)) { source_hint = p; return true; }
        }
    }
#else
    {
        std::vector<std::string> cands;
        const char* home = std::getenv("HOME");
        if(home && *home){
            cands.push_back(std::string(home) + "/.miqrochain/.cookie");
            cands.push_back(std::string(home) + "/.config/miqrochain/.cookie");
            cands.push_back(std::string(home) + "/.local/share/miqrochain/.cookie");
        }
        const char* xdg = std::getenv("XDG_DATA_HOME");
        if(xdg && *xdg) cands.push_back(std::string(xdg) + "/miqrochain/.cookie");
        cands.push_back("/var/lib/miqrochain/.cookie");

        for(const auto& p : cands){
            if(read_first_line(p, out_userpass)) { source_hint = p; return true; }
        }
    }
#endif
    return false;
}

static void parse_argv(int argc, char** argv,
                       std::string& host, std::string& port,
                       std::string& cookiefile, std::string& datadir,
                       std::string& user, std::string& pass)
{
    // Env defaults
    if(const char* eh = std::getenv("MIQ_RPC_HOST")) host = eh;
    if(const char* ep = std::getenv("MIQ_RPC_PORT")) port = ep;
    if(const char* ed = std::getenv("MIQ_DATADIR"))  datadir = ed;
    if(const char* ec = std::getenv("MIQ_RPC_COOKIEFILE")) cookiefile = ec;
    if(const char* eu = std::getenv("MIQ_RPC_USER")) user = eu;
    if(const char* ew = std::getenv("MIQ_RPC_PASSWORD")) pass = ew;

    for(int i=1;i<argc;i++){
        std::string a = argv[i];
        auto eat = [&](const char* k, std::string& dst)->bool{
            if(a.rfind(k, 0)==0){
                if(a.size()>std::strlen(k) && a[std::strlen(k)]=='='){ dst = a.substr(std::strlen(k)+1); return true; }
                if(i+1<argc){ dst = argv[++i]; return true; }
            }
            return false;
        };
        if(eat("--rpcconnect", host)) continue;
        if(eat("--rpcport",    port)) continue;
        if(eat("--cookiefile", cookiefile)) continue;
        if(eat("--datadir",    datadir)) continue;
        if(eat("--rpcuser",    user)) continue;
        if(eat("--rpcpassword",pass)) continue;
    }
}

// --------------- very small HTTP POST (with Basic auth) ---------------
static bool http_post(const std::string& host, const std::string& port,
                      const std::string& path, const std::string& auth_header,
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
    if (!auth_header.empty()) req << "Authorization: " << auth_header << "\r\n";
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
    out_body = trim(bodyOut);
    return true;
}

// convenience
static std::string jstrp(const std::string& s) { return json_escape(s); }

struct Rpc {
    std::string host = "127.0.0.1";
    std::string port = std::to_string(RPC_PORT);
    std::string auth_header; // "Basic ..."

    std::string call(const std::string& method, const std::vector<std::string>& params_json) const {
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
        if (!http_post(host, port, "/", auth_header, b.str(), resp, &status)) return "";
        return trim(resp);
    }
};

// ---------------- wallet ops -----------------
static bool unlock_if_needed(const Rpc& rpc) {
    std::cout << "\nWallet passphrase (leave blank if not encrypted): ";
    std::string pass; std::getline(std::cin, pass);
    if (trim(pass).empty()) return true;
    std::string r = rpc.call("walletunlock", { jstrp(pass), "600" });
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Unlock failed: " << r << "\n";
        return false;
    }
    return true;
}

static bool op_create_wallet(const Rpc& rpc) {
    std::cout << "\n-- Create new HD wallet --\n";
    std::cout << "Optional wallet passphrase (ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string r = rpc.call("createhdwallet", { "\"\"", "\"\"", jstrp(wpass) });
    if (r.empty() || r.find("\"error\"") != std::string::npos) {
        std::cout << "Create failed: " << r << "\n";
        return false;
    }
    std::string mnemonic;
    if (!json_get_string_field(r, "mnemonic", mnemonic)) {
        std::cout << "Unexpected response: " << r << "\n";
        return false;
    }

    std::cout << "\nYour 12-word mnemonic (WRITE IT DOWN, keep offline!):\n\n";
    std::cout << "  " << mnemonic << "\n\n";

    if (!wpass.empty()) {
        std::string ur = rpc.call("walletunlock", { jstrp(wpass), "600" });
        if (ur.find("\"error\"") != std::string::npos) {
            std::cout << "Unlock failed: " << ur << "\n";
            return false;
        }
    }

    std::string addr = rpc.call("getnewaddress", {});
    if (!json_is_string_value(addr, addr)) {
        std::cout << "Could not get receive address: " << addr << "\n";
        return false;
    }
    std::cout << "First receive address:\n  " << addr << "\n";

    std::string bal = rpc.call("getbalance", {});
    long long miqron=0; std::string miqPretty;
    json_get_number_field_ll(bal, "miqron", miqron);
    json_get_string_field(bal, "miq", miqPretty);
    std::cout << "Balance: " << miqPretty << " MIQ (" << miqron << " miqron)\n";
    return true;
}

static bool op_recover_wallet(const Rpc& rpc) {
    std::cout << "\n-- Recover HD wallet --\n";
    std::cout << "Paste 12 or 24-word mnemonic:\n> ";
    std::string mnemonic; std::getline(std::cin, mnemonic);
    mnemonic = trim(mnemonic);

    std::cout << "BIP39 mnemonic passphrase (ENTER if none): ";
    std::string mpass; std::getline(std::cin, mpass);

    std::cout << "Wallet encryption passphrase (new; ENTER for none): ";
    std::string wpass; std::getline(std::cin, wpass);

    std::string r = rpc.call("restorehdwallet", { jstrp(mnemonic), jstrp(mpass), jstrp(wpass) });
    if (r.find("\"error\"") != std::string::npos) {
        std::cout << "Restore failed: " << r << "\n";
        return false;
    }
    std::cout << "Restored.\n";

    if (!wpass.empty()) {
        std::string ur = rpc.call("walletunlock", { jstrp(wpass), "600" });
        if (ur.find("\"error\"") != std::string::npos) {
            std::cout << "Unlock failed: " << ur << "\n";
        }
    }

    // Simple balance after restore
    std::string bal = rpc.call("getbalance", {});
    long long miqron=0; std::string miqPretty;
    json_get_number_field_ll(bal, "miqron", miqron);
    json_get_string_field(bal, "miq", miqPretty);
    std::cout << "Discovered balance: " << miqPretty << " MIQ (" << miqron << " miqron)\n";
    return true;
}

static bool tx_in_mempool(const Rpc& rpc, const std::string& txid) {
    std::string mp = rpc.call("getrawmempool", {});
    std::string needle = "\"" + txid + "\"";
    return mp.find(needle) != std::string::npos;
}

static int tx_confirmations_via_recipient(const Rpc& rpc,
                                          const std::string& txid,
                                          const std::string& recipient_addr)
{
    if (tx_in_mempool(rpc, txid)) return 0;

    std::string utx = rpc.call("getaddressutxos", { jstrp(recipient_addr) });
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

    std::string hjson = rpc.call("getblockcount", {});
    std::string hs; if (!json_is_string_value(hjson, hs)) hs = hjson;
    int curH = std::stoi(hs);
    int confs = (curH - txHeight + 1);
    if (confs < 0) confs = 0;
    return confs;
}

static bool op_send_flow(const Rpc& rpc) {
    std::cout << "\n-- Send MIQ --\n";
    if (!unlock_if_needed(rpc)) return false;

    std::cout << "Recipient address: ";
    std::string addr; std::getline(std::cin, addr); addr = trim(addr);
    if (addr.empty()) { std::cout << "Canceled.\n"; return false; }

    std::cout << "Amount (MIQ, e.g. 1.23456789): ";
    std::string amt; std::getline(std::cin, amt); amt = trim(amt);
    if (amt.empty()) { std::cout << "Canceled.\n"; return false; }

    std::cout << "Sending " << amt << " MIQ to " << addr << " ...\n";
    std::string r = rpc.call("sendfromhd", { jstrp(addr), jstrp(amt) });
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
        int c = tx_confirmations_via_recipient(rpc, txid, addr);
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

static bool op_show_balance(const Rpc& rpc){
    std::string bal = rpc.call("getbalance", {});
    if (bal.empty()) { std::cout << "RPC failed.\n"; return false; }
    long long miqron=0; std::string miqPretty;
    json_get_number_field_ll(bal, "miqron", miqron);
    json_get_string_field(bal, "miq", miqPretty);
    if(miqPretty.empty()){
        std::ostringstream s; s << (miqron / (long long)COIN) << "." << std::setw(8) << std::setfill('0') << (miqron % (long long)COIN);
        miqPretty = s.str();
    }
    std::cout << "Balance: " << miqPretty << " MIQ (" << miqron << " miqron)\n";
    return true;
}

// ---------------- main -----------------
int main(int argc, char** argv){
    std::ios::sync_with_stdio(false);

    // Parse endpoint/auth options (env + flags)
    std::string host = "127.0.0.1";
    std::string port = std::to_string(RPC_PORT);
    std::string cookiefile, datadir, user, pass;
    parse_argv(argc, argv, host, port, cookiefile, datadir, user, pass);

    // Build auth: prefer cookie; else user/pass; else prompt once.
    std::string userpass;
    std::string source_hint;
    if(!find_cookie_auto(userpass, source_hint, cookiefile, datadir)){
        if(!user.empty() || !pass.empty()){
            userpass = user + ":" + pass;
            source_hint = "rpcuser/rpcpassword";
        } else {
            // Last resort: interactive paste (keeps "click & run" if env/flags set)
            std::cout << "No cookie/userpass found automatically.\n";
            std::cout << "Paste cookie line (user:pass) or press ENTER to abort:\n> ";
            std::string line; std::getline(std::cin, line); line = trim(line);
            if(line.empty()){
                std::cerr << "No credentials provided. Exiting.\n";
                return 1;
            }
            userpass = line;
            source_hint = "stdin";
        }
    }

    Rpc rpc;
    rpc.host = host;
    rpc.port = port;
    rpc.auth_header = make_basic_auth(userpass);

    std::cout << "Target: " << CHAIN_NAME << " RPC at " << host << ":" << port << "\n";
    std::cout << "Auth source: " << source_hint << "\n";

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
        if (choice=="1") { (void)op_create_wallet(rpc); }
        else if (choice=="2") { (void)op_recover_wallet(rpc); }
        else if (choice=="3") { (void)op_send_flow(rpc); }
        else if (choice=="4") { (void)op_show_balance(rpc); }
        else if (choice=="q" || choice=="Q" || choice=="exit") break;
    }
    return 0;
}
