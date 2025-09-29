#pragma once
#include <cstdint>
#include <string>
#include <functional>
#include <vector>
#include <optional>

namespace miq {

// Minimal key/value API with forward-only scan and compaction.
class KV {
public:
    virtual ~KV() = default;
    virtual bool open(const std::string& path, std::string& err) = 0;
    virtual void close() = 0;

    virtual bool get(const std::string& key, std::string& out) const = 0;
    virtual bool put(const std::string& key, const std::string& val, std::string& err) = 0;
    virtual bool del(const std::string& key, std::string& err) = 0;

    // Iterate all live keys (undefined order). Return false to stop early.
    virtual void scan(const std::function<bool(const std::string&, const std::string&)>& fn) const = 0;

    // Rewrite storage compactly (drops tombstoned keys).
    virtual bool compact(std::string& err) = 0;

    // Stats
    struct Stats {
        uint64_t live_keys{0};
        uint64_t file_bytes{0};
        uint64_t log_records{0};
    };
    virtual Stats stats() const = 0;
};

}
