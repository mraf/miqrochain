#pragma once
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace miq {

struct BanEntry {
    int64_t until_ms = 0;     // epoch ms
    int     strikes  = 0;     // exponential backoff
    std::string reason;
};

class BanList {
public:
    bool is_banned(const std::string& ip, int64_t now_ms) const;
    void strike(const std::string& ip, const std::string& reason, int64_t now_ms);
    void unban_expired(int64_t now_ms);
    bool save_json(const std::string& path) const;
    bool load_json(const std::string& path);

private:
    std::unordered_map<std::string, BanEntry> m_;
};

}
