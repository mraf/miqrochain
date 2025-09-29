#pragma once
#include "kv.h"
#include <unordered_map>
#include <fstream>
#include <mutex>

namespace miq {

// Append-only log KV (single file). In-memory index -> file offsets/values.
// Format:
//   magic "MIQK" (4) | version u32
//   then records: [op u8][klen u32][vlen u32][key][val][crc32 u32]
//   op: 1 = put, 0 = del. vlen==0 for del.
class LogKV : public KV {
public:
    LogKV() = default;
    ~LogKV() override { close(); }

    bool open(const std::string& path, std::string& err) override;
    void close() override;

    bool get(const std::string& key, std::string& out) const override;
    bool put(const std::string& key, const std::string& val, std::string& err) override;
    bool del(const std::string& key, std::string& err) override;

    void scan(const std::function<bool(const std::string&, const std::string&)>& fn) const override;
    bool compact(std::string& err) override;

    Stats stats() const override;

private:
    struct Entry { std::string val; bool tomb{false}; };
    mutable std::mutex mu_;
    std::unordered_map<std::string, Entry> map_;
    std::string path_;
    std::fstream f_;
    uint64_t log_records_{0};
    uint64_t file_bytes_{0};

    bool append_record(uint8_t op, const std::string& k, const std::string& v, std::string& err);
    static uint32_t crc32(const uint8_t* p, size_t n);
};

}
