#include "bans.h"
#include "serialize.h"
#include "log.h"
#include <cstdio>
#include <cstring>
#include <algorithm>

// tiny JSON (hand-rolled) to avoid new deps; format: [{"ip": "...", "until_ms": 123, "strikes": 2, "reason": "..."}]

namespace miq {

static constexpr int64_t kBaseBanMinutes = 5; // grows with strikes

bool BanList::is_banned(const std::string& ip, int64_t now_ms) const {
    auto it = m_.find(ip);
    if (it == m_.end()) return false;
    return it->second.until_ms > now_ms;
}

void BanList::strike(const std::string& ip, const std::string& reason, int64_t now_ms) {
    auto& e = m_[ip];
    e.strikes = std::min(10, e.strikes + 1);
    int64_t mins = kBaseBanMinutes;
    for (int i=1;i<e.strikes;i++) mins = std::min<int64_t>(mins*2, 24*60);
    e.until_ms = now_ms + mins*60*1000;
    e.reason   = reason;
}

void BanList::unban_expired(int64_t now_ms) {
    for (auto it=m_.begin(); it!=m_.end(); ) {
        if (it->second.until_ms <= now_ms) it = m_.erase(it); else ++it;
    }
}

bool BanList::save_json(const std::string& path) const {
    FILE* f = std::fopen(path.c_str(), "wb"); if (!f) return false;
    std::fputs("[", f);
    bool first=true;
    for (auto& kv : m_) {
        if (!first) std::fputs(",", f); first=false;
        const auto& ip = kv.first; const auto& e = kv.second;
        std::fprintf(f,
          "{\"ip\":\"%s\",\"until_ms\":%lld,\"strikes\":%d,\"reason\":\"%s\"}",
          ip.c_str(), (long long)e.until_ms, e.strikes, e.reason.c_str());
    }
    std::fputs("]\n", f);
    std::fclose(f);
    return true;
}

bool BanList::load_json(const std::string& path) {
    m_.clear();
    FILE* f = std::fopen(path.c_str(), "rb"); if (!f) return false;
    std::string s; char buf[4096];
    while (size_t n = std::fread(buf,1,sizeof(buf),f)) s.append(buf, n);
    std::fclose(f);
    // very small parser tolerant to this file’s own format:
    size_t i=0;
    while ((i = s.find("{\"ip\":\"", i)) != std::string::npos) {
        i += 7; size_t j = s.find("\"", i); if (j==std::string::npos) break; std::string ip=s.substr(i,j-i);
        size_t k = s.find("\"until_ms\":", j); if (k==std::string::npos) break; k += 11;
        long long until=std::atoll(s.c_str()+k);
        k = s.find("\"strikes\":", k); if (k==std::string::npos) break; k += 10; int strikes=std::atoi(s.c_str()+k);
        k = s.find("\"reason\":\"", k); if (k==std::string::npos) break; k += 10; size_t m = s.find("\"", k); std::string reason=s.substr(k,m-k);
        m_[ip] = BanEntry{(int64_t)until, strikes, reason};
        i = m+1;
    }
    return true;
}

}
