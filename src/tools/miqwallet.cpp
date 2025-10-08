// tools/miqwallet.cpp
// Robust standalone CLI wallet for Miqrochain.
//
// NEW IN THIS VERSION
// - `balance` works for new/restored wallets. If the wallet is locked, the CLI
//   prompts for your pass, unlocks on the node (temporary), then retries.
// - Uses RPC method `getbalance` if present; otherwise falls back to `listutxos`
//   and sums values locally.
// - Send flow still preflights fees locally and shows plan; then uses node
//   `sendfromhd` to build/sign/broadcast.
//
// Build (Linux/macOS):
//   g++ -std=c++17 -O2 -o miqwallet tools/miqwallet.cpp
//
// Build (Windows MSVC):
//   cl /std:c++17 /O2 tools\\miqwallet.cpp /Fe:miqwallet.exe
//
// Build (Windows MinGW):
//   g++ -std=c++17 -O2 -o miqwallet.exe tools/miqwallet.cpp -lws2_32
//
// Usage examples:
//   ./miqwallet info
//   ./miqwallet init
//   ./miqwallet restore
//   ./miqwallet unlock 600
//   ./miqwallet newaddr
//   ./miqwallet balance
//   ./miqwallet send <MIQaddress> 0.10               # 0.10 MIQ
//   ./miqwallet send <MIQaddress> 10000000 --dry-run # 10,000,000 miqron (dry run)

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#ifdef _WIN32
  #define _WINSOCK_DEPRECATED_NO_WARNINGS
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib,"ws2_32.lib")
  #include <conio.h>
#else
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <termios.h>
#endif

// ---- Defaults (keep consistent with your node) ----
static constexpr uint16_t DEFAULT_RPC_PORT = 7332;        // RPC_PORT in constants.h
static constexpr uint64_t DEFAULT_FEERATE  = 1000;        // miqron/kB (MIN_RELAY_FEE_RATE)
static constexpr uint64_t DUST_THRESHOLD   = 1000;        // miqron
static constexpr uint64_t COIN             = 100000000ULL;// 1 MIQ = 1e8 miqron

// ----------------- small helpers -----------------
static std::string json_escape(const std::string& s){
    std::ostringstream o; o << '"';
    for(char c : s){
        switch(c){
            case '\\': o << "\\\\"; break;
            case '"':  o << "\\\""; break;
            case '\n': o << "\\n";  break;
            case '\r': o << "\\r";  break;
            case '\t': o << "\\t";  break;
            default:
                if((unsigned char)c < 0x20) { o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c; }
                else o << c;
        }
    }
    o << '"';
    return o.str();
}

static bool read_first_line_trim(const std::string& p, std::string& out){
    std::ifstream f(p, std::ios::in | std::ios::binary);
    if(!f.good()) return false;
    std::string s; std::getline(f, s);
    while(!s.empty() && (s.back()=='\r'||s.back()=='\n'||s.back()==' '||s.back()=='\t')) s.pop_back();
    out = s;
    return true;
}

// Minimal parsing helpers for our RPC responses (defensive but small).
static bool json_find_error(const std::string& body, std::string& out_err){
    auto pos = body.find("\"error\"");
    if(pos == std::string::npos) return false;
    auto colon = body.find(':', pos);
    if(colon == std::string::npos) return false;

    // If it's literally `null`, treat as no error:
    auto after = body.find_first_not_of(" \t\r\n", colon+1);
    if(after != std::string::npos && body.compare(after, 4, "null") == 0) return false;

    // Extract string value "...."
    auto s1 = body.find('"', colon);
    if(s1 == std::string::npos) return false;
    auto s2 = body.find('"', s1+1);
    if(s2 == std::string::npos) return false;
    out_err = body.substr(s1+1, s2-(s1+1));
    return true;
}

static bool json_extract_string_field(const std::string& body, const char* key, std::string& out){
    // finds "key":"value"
    std::string pat = std::string("\"")+key+"\"";
    auto p = body.find(pat);
    if(p==std::string::npos) return false;
    p = body.find('"', body.find(':', p));
    if(p==std::string::npos) return false;
    auto q = body.find('"', p+1);
    if(q==std::string::npos) return false;
    out = body.substr(p+1, q-(p+1));
    return true;
}

static bool json_extract_uint64_field(const std::string& body, const char* key, uint64_t& out){
    // finds "key":1234  (stops at first non-digit or dot)
    std::string pat = std::string("\"")+key+"\"";
    auto p = body.find(pat);
    if(p==std::string::npos) return false;
    p = body.find(':', p);
    if(p==std::string::npos) return false;
    ++p;
    while(p<body.size() && (body[p]==' '||body[p]=='\t')) ++p;
    size_t q = p;
    while(q<body.size() && (isdigit((unsigned char)body[q]) || body[q]=='.')) ++q;
    if(q==p) return false;
    std::string num = body.substr(p, q-p);
    auto dot = num.find('.');
    if(dot != std::string::npos) num.erase(dot);
    try { out = (uint64_t)std::stoull(num); } catch(...){ return false; }
    return true;
}

// For listutxos/getaddressutxos arrays
static std::vector<uint64_t> json_extract_all_values_fields(const std::string& body){
    std::vector<uint64_t> res;
    const std::string key = "\"value\"";
    size_t p = 0;
    while(true){
        p = body.find(key, p);
        if(p == std::string::npos) break;
        p = body.find(':', p);
        if(p == std::string::npos) break;
        ++p;
        while(p<body.size() && (body[p]==' '||body[p]=='\t')) ++p;
        size_t q=p;
        while(q<body.size() && (isdigit((unsigned char)body[q]) || body[q]=='.')) ++q;
        if(q>p){
            std::string num = body.substr(p, q-p);
            auto dot = num.find('.');
            if(dot != std::string::npos) num.erase(dot);
            try { res.push_back((uint64_t)std::stoull(num)); } catch(...){}
        }
    }
    return res;
}

static uint64_t parse_amount_like_node(const std::string& s){
    if(s.find('.') != std::string::npos){
        long double v = std::stold(s);
        long double sat = v * (long double)COIN;
        if(sat < 0) throw std::runtime_error("negative");
        return (uint64_t) llround(sat);
    }else{
        return (uint64_t)std::stoull(s);
    }
}

static std::string format_miqron(uint64_t v){
    std::ostringstream o;
    o << (v/COIN) << "." << std::setw(8) << std::setfill('0') << (v%COIN);
    return o.str();
}

// --- password prompt (no-echo) ---
static std::string prompt_hidden(const char* prompt){
    std::string pass;
    std::cerr << prompt;
#ifdef _WIN32
    int ch;
    while((ch = _getch()) != '\r' && ch != '\n'){
        if(ch == 3) { std::cerr << "\n"; std::exit(1); }
        if(ch == 8){ if(!pass.empty()){ pass.pop_back(); std::cerr << "\b \b"; } }
        else { pass.push_back((char)ch); std::cerr << '*'; }
    }
    std::cerr << "\n";
#else
    termios oldt; tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt; newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pass);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    std::cerr << "\n";
#endif
    return pass;
}

// ----------------- HTTP tiny client -----------------
struct HttpClient {
    std::string host = "127.0.0.1";
    uint16_t    port = DEFAULT_RPC_PORT;
    std::string token;              // MIQ_RPC_TOKEN
    std::string xtra_path = "/";

    bool load_token_from_cookie(const std::string& path){
        std::string t;
        if(!read_first_line_trim(path, t) || t.empty()) return false;
        token = t; return true;
    }

    std::string post_json(const std::string& body){
        std::ostringstream req;
        req << "POST " << xtra_path << " HTTP/1.1\r\n"
            << "Host: " << host << ":" << port << "\r\n"
            << "Connection: close\r\n"
            << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n";
        if(!token.empty()){
            req << "Authorization: Bearer " << token << "\r\n"
                << "X-Auth-Token: " << token << "\r\n";
        }
        req << "\r\n" << body;

        const std::string wire = req.str();

#ifdef _WIN32
        WSADATA wsa; WSAStartup(MAKEWORD(2,2), &wsa);
#endif
        addrinfo hints{}; hints.ai_socktype = SOCK_STREAM; hints.ai_family = AF_UNSPEC;
        addrinfo* res = nullptr;
        std::string portstr = std::to_string(port);
        if(getaddrinfo(host.c_str(), portstr.c_str(), &hints, &res) != 0){
#ifdef _WIN32
            WSACleanup();
#endif
            throw std::runtime_error("getaddrinfo failed");
        }
        int fd=-1;
        for(addrinfo* p=res;p;p=p->ai_next){
            fd = (int)socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            if(fd < 0) continue;
            if(connect(fd, p->ai_addr, (int)p->ai_addrlen) == 0){
#ifdef _WIN32
                int sent = ::send(fd, wire.c_str(), (int)wire.size(), 0);
#else
                ssize_t sent = ::send(fd, wire.c_str(), wire.size(), 0);
#endif
                if(sent < 0){
#ifdef _WIN32
                    closesocket(fd); WSACleanup();
#else
                    close(fd);
#endif
                    freeaddrinfo(res);
                    throw std::runtime_error("send failed");
                }
                std::string resp; resp.reserve(4096);
                char buf[4096];
                while(true){
#ifdef _WIN32
                    int n = ::recv(fd, buf, (int)sizeof(buf), 0);
#else
                    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
#endif
                    if(n <= 0) break;
                    resp.append(buf, buf+n);
                }
#ifdef _WIN32
                closesocket(fd); WSACleanup();
#else
                close(fd);
#endif
                freeaddrinfo(res);
                auto p2 = resp.find("\r\n\r\n");
                if(p2 == std::string::npos) return resp;
                return resp.substr(p2+4);
            }
#ifdef _WIN32
            closesocket(fd);
#else
            close(fd);
#endif
            fd=-1;
        }
        freeaddrinfo(res);
#ifdef _WIN32
        WSACleanup();
#endif
        throw std::runtime_error("connect failed");
    }
};

// --------------- RPC wrappers ---------------
static std::string rpc_build_call(const std::string& method, const std::string& params_json){
    std::ostringstream b;
    b << "{\"method\":" << json_escape(method);
    if(!params_json.empty()) b << ",\"params\":" << params_json;
    b << "}";
    return b.str();
}
static std::string rpc_call(HttpClient& c, const std::string& method, const std::string& params_json){
    return c.post_json(rpc_build_call(method, params_json));
}

// Try an RPC; if it errors with "locked"/"pass"/"decrypt", prompt and unlock, then retry once.
static std::string rpc_call_maybe_unlock(HttpClient& c, const std::string& method, const std::string& params_json, uint64_t unlock_secs = 300){
    std::string r = rpc_call(c, method, params_json);
    std::string e;
    if(!json_find_error(r, e)) return r;

    std::string elow = e; std::transform(elow.begin(), elow.end(), elow.begin(), [](unsigned char ch){ return (char)tolower(ch); });
    bool looks_locked = (elow.find("pass")!=std::string::npos) || (elow.find("decrypt")!=std::string::npos) || (elow.find("locked")!=std::string::npos);

    if(!looks_locked) return r;

    std::cerr << "Wallet appears locked. Unlocking to proceed...\n";
    std::string pass = prompt_hidden("Wallet passphrase: ");
    if(pass.empty()){
        std::cerr << "Empty passphrase refused.\n";
        return r; // original error
    }
    // walletunlock RPC: [pass, timeout_sec]
    std::ostringstream ps; ps << "[" << json_escape(pass) << "," << unlock_secs << "]";
    auto ur = rpc_call(c, "walletunlock", ps.str());
    std::string ue; if(json_find_error(ur, ue)){
        std::cerr << "Unlock failed: " << ue << "\n";
        return r;
    }
    // Retry original call once
    return rpc_call(c, method, params_json);
}

// --------------- Fee preflight (local) ---------------
static size_t estimate_size_bytes(size_t nin, size_t nout){ return nin*148 + nout*34 + 10; }
static uint64_t fee_for_size(uint64_t sz_bytes, uint64_t feerate){
    uint64_t kb = (sz_bytes + 999) / 1000;
    if(kb==0) kb=1;
    return kb * feerate;
}

struct SpendPlan {
    bool ok{false};
    size_t inputs{0};
    uint64_t in_sum{0};
    uint64_t fee{0};
    uint64_t change{0};
    size_t outputs{1};
};

static SpendPlan plan_spend(std::vector<uint64_t> utxo_values, uint64_t amount, uint64_t feerate){
    std::sort(utxo_values.begin(), utxo_values.end());
    SpendPlan P;
    uint64_t acc=0;
    for(size_t i=0;i<utxo_values.size();++i){
        acc += utxo_values[i];
        size_t nin = i+1;
        uint64_t fee2 = fee_for_size(estimate_size_bytes(nin, 2), feerate);
        if(acc >= amount + fee2){
            uint64_t ch = acc - amount - fee2;
            if(ch < DUST_THRESHOLD){
                uint64_t fee1 = fee_for_size(estimate_size_bytes(nin, 1), feerate);
                if(acc >= amount + fee1){
                    P.ok=true; P.inputs=nin; P.in_sum=acc; P.fee=fee1; P.change=0; P.outputs=1; return P;
                }
            }
            P.ok=true; P.inputs=nin; P.in_sum=acc; P.fee=fee2; P.change=ch; P.outputs=2; return P;
        }
    }
    return P; // ok=false
}

// --------------- CLI ---------------
static void usage(){
    std::cout <<
R"(miqwallet — simple Miqrochain wallet CLI

Usage:
  miqwallet [--rpc HOST:PORT] [--cookie FILE] <command> [args]
  (auth: MIQ_RPC_TOKEN env or --cookie FILE; otherwise tries ./.cookie)

Commands:
  info                         Show wallet unlock status and cursors
  init                         Create new HD wallet (prints mnemonic once)
  restore                      Restore wallet from mnemonic
  unlock [seconds]             Cache wallet passphrase in node (default 300s)
  lock                         Clear cached wallet passphrase in node
  newaddr                      Get a new receive address (advances index)
  addresses [N]                List up to N derived receive addresses
  utxos                        List wallet UTXOs
  balance                      Sum wallet UTXOs (auto-unlock if needed)
  send <to> <amount> [--feerate X] [--dry-run]
                               Send MIQ (e.g. 0.25 or 25000000)

Examples:
  miqwallet init && miqwallet unlock 600 && miqwallet newaddr
  miqwallet balance
  miqwallet send MIQ1abc... 0.05
)";
}

struct Args {
    std::string host = "127.0.0.1";
    uint16_t    port = DEFAULT_RPC_PORT;
    std::string cookie_file;
    std::string cmd;
    std::vector<std::string> rest;
    bool dry_run=false;
    uint64_t feerate = DEFAULT_FEERATE;
};

static bool parse_hostport(const std::string& hp, std::string& host, uint16_t& port){
    auto c = hp.find(':');
    if(c==std::string::npos) return false;
    host = hp.substr(0,c);
    try{
        unsigned long p = std::stoul(hp.substr(c+1));
        if(p==0 || p>65535) return false;
        port = (uint16_t)p; return true;
    }catch(...){ return false; }
}

static Args parse_args(int argc, char** argv){
    Args a;
    for(int i=1;i<argc;i++){
        std::string s = argv[i];
        if(s=="--rpc" && i+1<argc){
            if(!parse_hostport(argv[++i], a.host, a.port)) throw std::runtime_error("bad --rpc HOST:PORT");
        } else if(s=="--cookie" && i+1<argc){
            a.cookie_file = argv[++i];
        } else if(s=="--dry-run"){
            a.dry_run = true;
        } else if(s=="--feerate" && i+1<argc){
            a.feerate = (uint64_t)std::stoull(argv[++i]);
            if(a.feerate==0) a.feerate = DEFAULT_FEERATE;
        } else if(s=="-h" || s=="--help"){
            usage(); std::exit(0);
        } else if(a.cmd.empty()){
            a.cmd = s;
        } else {
            a.rest.push_back(s);
        }
    }
    return a;
}

// ------- High-level command handlers -------
static int cmd_info(HttpClient& c){
    auto r = rpc_call(c, "getwalletinfo", "[]");
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n";
    return 0;
}

static int cmd_init(HttpClient& c){
    std::cerr << "Creating a NEW wallet...\n";
    std::string pass = prompt_hidden("Set wallet encryption passphrase: ");
    if(pass.empty()){ std::cerr << "Refusing empty passphrase.\n"; return 1; }

    std::ostringstream ps; ps << "[\"\",\"\","
                              << json_escape(pass) << "]";
    auto r = rpc_call(c, "createhdwallet", ps.str());
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }

    std::string words;
    if(!json_extract_string_field(r, "mnemonic", words)){
        std::cerr << "Unexpected response (no mnemonic):\n" << r << "\n";
        return 1;
    }
    std::cout << "=== WRITE THESE WORDS DOWN (one-time display) ===\n";
    std::cout << words << "\n";
    std::cout << "=================================================\n";
    std::cout << "Wallet created & encrypted. Next: `miqwallet unlock 600`, then `newaddr`.\n";
    return 0;
}

static int cmd_restore(HttpClient& c){
    std::cerr << "Paste your mnemonic (single line):\n> ";
    std::string mnemonic; std::getline(std::cin, mnemonic);
    if(mnemonic.empty()){ std::cerr<<"empty mnemonic\n"; return 1; }
    std::string pass = prompt_hidden("Set wallet encryption passphrase for the restored wallet: ");
    if(pass.empty()){ std::cerr<<"Refusing empty passphrase.\n"; return 1; }

    std::ostringstream ps; ps << "[" << json_escape(mnemonic) << ",\"\","
                              << json_escape(pass) << "]";
    auto r = rpc_call(c, "restorehdwallet", ps.str());
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n";
    return 0;
}

static int cmd_unlock(HttpClient& c, const std::vector<std::string>& rest){
    uint64_t secs = 300;
    if(!rest.empty()){
        try { secs = (uint64_t)std::stoull(rest[0]); } catch(...){ std::cerr<<"bad seconds\n"; return 1; }
    }
    std::string pass = prompt_hidden("Wallet passphrase: ");
    if(pass.empty()){ std::cerr<<"empty passphrase refused\n"; return 1; }

    std::ostringstream ps; ps << "[" << json_escape(pass) << "," << secs << "]";
    auto r = rpc_call(c, "walletunlock", ps.str());
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n";
    return 0;
}

static int cmd_lock(HttpClient& c){
    auto r = rpc_call(c, "walletlock", "[]");
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n"; return 0;
}

static int cmd_newaddr(HttpClient& c){
    auto r = rpc_call_maybe_unlock(c, "getnewaddress", "[]");
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n";
    return 0;
}

static int cmd_addresses(HttpClient& c, const std::vector<std::string>& rest){
    int n = -1;
    if(!rest.empty()){
        try { n = std::stoi(rest[0]); } catch(...){ std::cerr<<"bad count\n"; return 1; }
    }
    std::ostringstream ps; if(n>=0) ps<<"["<<n<<"]"; else ps<<"[]";
    auto r = rpc_call_maybe_unlock(c, "listaddresses", ps.str());
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n"; return 0;
}

static int cmd_utxos(HttpClient& c){
    auto r = rpc_call_maybe_unlock(c, "listutxos", "[]");
    std::string err; if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    std::cout << r << "\n"; return 0;
}

// Try getbalance; if unknown, fall back to listutxos and sum.
static int cmd_balance(HttpClient& c){
    // 1) Prefer a native getbalance if present
    {
        auto r = rpc_call_maybe_unlock(c, "getbalance", "[]");
        std::string err;
        if(json_find_error(r, err)){
            // keep going; we may not have this RPC
        } else {
            // Try canonical fields
            uint64_t v=0;
            if(json_extract_uint64_field(r, "miqron", v)){
                std::cout << r << "\n";
                return 0;
            }
            // Or maybe it returned a raw number or a string: print as-is
            std::cout << r << "\n";
            return 0;
        }
    }

    // 2) Fallback: listutxos and sum values
    auto ut = rpc_call_maybe_unlock(c, "listutxos", "[]");
    std::string err;
    if(json_find_error(ut, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    auto vals = json_extract_all_values_fields(ut);
    uint64_t sum = 0;
    for(auto v: vals) sum += v;
    std::cout << "{\"miqron\":" << sum
              << ",\"miq\":\"" << format_miqron(sum) << "\"}\n";
    return 0;
}

static int cmd_send(HttpClient& c, const std::vector<std::string>& rest, bool dry_run, uint64_t feerate){
    if(rest.size() < 2){
        std::cerr << "usage: send <to_address> <amount> [--feerate X] [--dry-run]\n";
        return 1;
    }
    const std::string to = rest[0];
    const std::string amt = rest[1];

    // Preflight: fetch wallet UTXOs and estimate fees/inputs
    auto ut = rpc_call_maybe_unlock(c, "listutxos", "[]");
    std::string err;
    if(json_find_error(ut, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }
    auto vals = json_extract_all_values_fields(ut);
    if(vals.empty()){ std::cerr<<"no funds\n"; return 1; }

    uint64_t amount = 0;
    try { amount = parse_amount_like_node(amt); } catch(...){ std::cerr<<"bad amount\n"; return 1; }

    auto plan = plan_spend(vals, amount, feerate);
    if(!plan.ok){
        uint64_t have = std::accumulate(vals.begin(), vals.end(), (uint64_t)0);
        std::cerr << "insufficient funds. have=" << format_miqron(have)
                  << " need>=" << format_miqron(amount) << " + fee\n";
        return 1;
    }

    // Show plan
    std::cout << "{"
              << "\"inputs\":" << plan.inputs
              << ",\"outputs\":" << plan.outputs
              << ",\"amount_miq\":\"" << format_miqron(amount) << "\""
              << ",\"fee_miq\":\"" << format_miqron(plan.fee) << "\""
              << ",\"change_miq\":\"" << format_miqron(plan.change) << "\""
              << ",\"feerate\":" << feerate
              << "}\n";

    if(dry_run){
        std::cout << "(dry-run) Not broadcasting.\n";
        return 0;
    }

    // Broadcast via node builder (sendfromhd)
    std::ostringstream ps;
    ps << "[" << json_escape(to) << "," << json_escape(amt) << "," << feerate << "]";
    auto r = rpc_call_maybe_unlock(c, "sendfromhd", ps.str());
    if(json_find_error(r, err)){ std::cerr<<"error: "<<err<<"\n"; return 1; }

    std::string txid;
    if(!json_extract_string_field(r, "result", txid)){
        if(!r.empty() && r.front()=='"' && r.back()=='"') txid = r.substr(1, r.size()-2);
    }
    if(txid.empty()){
        std::cout << r << "\n";
    } else {
        std::cout << "{\"txid\":\"" << txid << "\"}\n";
    }
    return 0;
}

int main(int argc, char** argv){
    try{
        Args a = parse_args(argc, argv);
        if(a.cmd.empty()){ usage(); return 1; }

        HttpClient c;
        c.host = a.host; c.port = a.port;

        // token preference: env > --cookie > ./.cookie
        const char* env_tok = std::getenv("MIQ_RPC_TOKEN");
        if(env_tok && *env_tok) c.token = env_tok;
        else if(!a.cookie_file.empty()){
            if(!c.load_token_from_cookie(a.cookie_file)){
                std::cerr << "Failed to read token from --cookie file.\n"; return 1;
            }
        } else {
            c.load_token_from_cookie(".cookie"); // best-effort
        }

        if(a.cmd=="info")             return cmd_info(c);
        else if(a.cmd=="init")        return cmd_init(c);
        else if(a.cmd=="restore")     return cmd_restore(c);
        else if(a.cmd=="unlock")      return cmd_unlock(c, a.rest);
        else if(a.cmd=="lock")        return cmd_lock(c);
        else if(a.cmd=="newaddr")     return cmd_newaddr(c);
        else if(a.cmd=="addresses")   return cmd_addresses(c, a.rest);
        else if(a.cmd=="utxos")       return cmd_utxos(c);
        else if(a.cmd=="balance")     return cmd_balance(c);
        else if(a.cmd=="send")        return cmd_send(c, a.rest, a.dry_run, a.feerate);
        else {
            std::cerr << "unknown command: " << a.cmd << "\n";
            usage(); return 1;
        }
    }catch(const std::exception& ex){
        std::cerr << "fatal: " << ex.what() << "\n"; return 1;
    }catch(...){
        std::cerr << "fatal: unknown error\n"; return 1;
    }
}
