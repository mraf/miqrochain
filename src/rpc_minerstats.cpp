#include "miner.h"
#include "rpc_minerstats.h"

#include <string>
#include <cstdio>

namespace miq {

// minimal, dependency-free JSON string finder: finds value of "key":"...".
static std::string json_find_string(const std::string& s, const std::string& key){
    const std::string pat = "\"" + key + "\"";
    size_t p = s.find(pat);
    if(p == std::string::npos) return std::string();
    p = s.find(':', p + pat.size());
    if(p == std::string::npos) return std::string();
    ++p;
    while(p < s.size() && (s[p]==' '||s[p]=='\t'||s[p]=='\r'||s[p]=='\n')) ++p;
    if(p>=s.size() || s[p] != '"') return std::string();
    ++p; // opening quote
    std::string out;
    out.reserve(32);
    while(p < s.size()){
        char c = s[p++];
        if(c == '\\'){
            if(p < s.size()){
                char e = s[p++];
                if(e=='"' || e=='\\') out.push_back(e);
                else { out.push_back('\\'); out.push_back(e); }
            } else break;
        } else if(c == '"'){
            break;
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::string rpc_maybe_handle_minerstats(const std::string& body, bool& handled){
    handled = false;
    if(body.find("\"method\"") == std::string::npos) return std::string();
    const std::string method = json_find_string(body, "method");
    if(method != "getminerstats") return std::string<>();

    const MinerStats st = miner_stats_now();

    // {"hps":<float>,"hashes":<uint64>,"seconds":<float>}
    char buf[256];
    int n = std::snprintf(buf, sizeof(buf),
        "{\"hps\":%.6f,\"hashes\":%llu,\"seconds\":%.3f}",
        (st.hps >= 0.0 ? st.hps : 0.0),
        static_cast<unsigned long long>(st.hashes),
        (st.seconds >= 0.0 ? st.seconds : 0.0));
    std::string resp = (n > 0)
        ? std::string(buf, static_cast<size_t>(n))
        : std::string("{\"hps\":0.0,\"hashes\":0,\"seconds\":0.0}");
    handled = true;
    return resp;
}

} // namespace miq
