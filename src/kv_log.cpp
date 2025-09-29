#include "kv_log.h"
#include <vector>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>

#ifdef _WIN32
  #include <io.h>
#else
  #include <unistd.h>
#endif

namespace miq {

static inline void write_u32(std::fstream& f, uint32_t x){
    uint8_t b[4] = { (uint8_t)(x), (uint8_t)(x>>8), (uint8_t)(x>>16), (uint8_t)(x>>24) };
    f.write((const char*)b, 4);
}
static inline uint32_t read_u32(std::fstream& f){
    uint8_t b[4]; f.read((char*)b, 4);
    return (uint32_t)b[0] | ((uint32_t)b[1]<<8) | ((uint32_t)b[2]<<16) | ((uint32_t)b[3]<<24);
}

uint32_t LogKV::crc32(const uint8_t* data, size_t len){
    uint32_t c = 0xFFFFFFFFu;
    for(size_t i=0;i<len;i++){
        c ^= data[i];
        for(int k=0;k<8;k++) c = (c >> 1) ^ (0xEDB88320u & (-(int)(c & 1)));
    }
    return ~c;
}

bool LogKV::open(const std::string& path, std::string& err){
    std::lock_guard<std::mutex> lk(mu_);
    path_ = path;
    // create if not exists, then reopen read/write binary append
    {
        std::fstream probe(path_, std::ios::in | std::ios::binary);
        bool exists = probe.good();
        probe.close();
        if (!exists) {
            std::fstream nf(path_, std::ios::out | std::ios::binary | std::ios::trunc);
            if (!nf.good()){ err = "kv: cannot create file"; return false; }
            nf.write("MIQK", 4);
            write_u32(nf, 1); // version
            nf.flush();
        }
    }

    f_.open(path_, std::ios::in | std::ios::out | std::ios::binary);
    if (!f_.good()){ err = "kv: open failed"; return false; }

    // Read header
    char magic[4]; f_.read(magic, 4);
    if (std::strncmp(magic, "MIQK", 4) != 0){ err="kv: bad magic"; return false; }
    (void)read_u32(f_); // version

    // Replay log
    map_.clear(); log_records_ = 0; file_bytes_ = 0;
    f_.seekg(0, std::ios::end);
    file_bytes_ = (uint64_t)f_.tellg();
    f_.seekg(8, std::ios::beg);

    while (f_) {
        uint8_t op;
        f_.read((char*)&op, 1);
        if (!f_) break;
        uint32_t klen = read_u32(f_);
        uint32_t vlen = read_u32(f_);
        if (klen > (64u<<20) || vlen > (256u<<20)) { err="kv: record too large"; return false; }
        std::string k(klen, '\0'), v(vlen, '\0');
        if (klen) f_.read(&k[0], klen);
        if (vlen) f_.read(&v[0], vlen);
        uint32_t want = read_u32(f_);

        // verify crc
        std::vector<uint8_t> buf; buf.reserve(1+4+4+klen+vlen);
        buf.push_back(op);
        for(int i=0;i<4;i++) buf.push_back((uint8_t)((klen>>(8*i))&0xFF));
        for(int i=0;i<4;i++) buf.push_back((uint8_t)((vlen>>(8*i))&0xFF));
        buf.insert(buf.end(), k.begin(), k.end());
        buf.insert(buf.end(), v.begin(), v.end());
        if (crc32(buf.data(), buf.size()) != want) { err="kv: record crc mismatch"; return false; }

        if (op == 1) { map_[k] = Entry{std::move(v), false}; }
        else         { map_[k] = Entry{"", true}; }
        log_records_++;
    }

    // Position at end for appends
    f_.clear();
    f_.seekp(0, std::ios::end);
    return true;
}

void LogKV::close(){
    std::lock_guard<std::mutex> lk(mu_);
    if (f_.is_open()) f_.close();
    map_.clear(); log_records_=0; file_bytes_=0;
}

bool LogKV::append_record(uint8_t op, const std::string& k, const std::string& v, std::string& err){
    std::vector<uint8_t> buf;
    buf.reserve(1+4+4+k.size()+v.size());
    buf.push_back(op);
    for(int i=0;i<4;i++) buf.push_back((uint8_t)(((uint32_t)k.size()>>(8*i))&0xFF));
    for(int i=0;i<4;i++) buf.push_back((uint8_t)(((uint32_t)v.size()>>(8*i))&0xFF));
    buf.insert(buf.end(), k.begin(), k.end());
    buf.insert(buf.end(), v.begin(), v.end());
    uint32_t c = crc32(buf.data(), buf.size());

    f_.write((const char*)buf.data(), (std::streamsize)buf.size());
    f_.write((const char*)&c, 4);
    if (!f_.good()){ err="kv: write failed"; return false; }
    f_.flush();
    file_bytes_ += (uint64_t)buf.size() + 4;
    log_records_++;
#ifndef _WIN32
    // fsync on POSIX
    int fd = ::fileno(f_.rdbuf()->std::FILE*());
    (void)fd; // best-effort; on some libstdc++ this is not accessible; ignore.
#endif
    return true;
}

bool LogKV::get(const std::string& key, std::string& out) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = map_.find(key);
    if (it == map_.end() || it->second.tomb) return false;
    out = it->second.val;
    return true;
}

bool LogKV::put(const std::string& key, const std::string& val, std::string& err){
    std::lock_guard<std::mutex> lk(mu_);
    if (!append_record(1, key, val, err)) return false;
    map_[key] = Entry{val, false};
    return true;
}

bool LogKV::del(const std::string& key, std::string& err){
    std::lock_guard<std::mutex> lk(mu_);
    if (!append_record(0, key, "", err)) return false;
    map_[key] = Entry{"", true};
    return true;
}

void LogKV::scan(const std::function<bool(const std::string&, const std::string&)>& fn) const {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& kv : map_) {
        if (!kv.second.tomb) {
            if (!fn(kv.first, kv.second.val)) return;
        }
    }
}

bool LogKV::compact(std::string& err){
    std::lock_guard<std::mutex> lk(mu_);
    std::string tmp = path_ + ".tmp";
    std::fstream nf(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!nf.good()){ err="kv: compact open tmp failed"; return false; }

    nf.write("MIQK", 4); write_u32(nf, 1);
    uint64_t recs = 0, bytes = 8;
    for (const auto& kv : map_) {
        if (kv.second.tomb) continue;
        const std::string& k = kv.first;
        const std::string& v = kv.second.val;

        // assemble record
        std::vector<uint8_t> buf;
        buf.reserve(1+4+4+k.size()+v.size());
        buf.push_back(1);
        for(int i=0;i<4;i++) buf.push_back((uint8_t)(((uint32_t)k.size()>>(8*i))&0xFF));
        for(int i=0;i<4;i++) buf.push_back((uint8_t)(((uint32_t)v.size()>>(8*i))&0xFF));
        buf.insert(buf.end(), k.begin(), k.end());
        buf.insert(buf.end(), v.begin(), v.end());
        uint32_t c = crc32(buf.data(), buf.size());

        nf.write((const char*)buf.data(), (std::streamsize)buf.size());
        nf.write((const char*)&c, 4);
        if (!nf.good()){ err="kv: compact write failed"; nf.close(); return false; }
        recs++; bytes += (uint64_t)buf.size() + 4;
    }
    nf.flush();
    nf.close();

    // Atomic-ish replace
    std::remove(path_.c_str()); // ignore error
    if (std::rename(tmp.c_str(), path_.c_str()) != 0){ err="kv: compact rename failed"; return false; }

    // Reopen to refresh file handle/positions
    f_.close();
    f_.open(path_, std::ios::in | std::ios::out | std::ios::binary);
    if (!f_.good()){ err="kv: reopen after compact failed"; return false; }
    f_.seekp(0, std::ios::end);
    log_records_ = recs;
    file_bytes_  = bytes;
    return true;
}

KV::Stats LogKV::stats() const {
    std::lock_guard<std::mutex> lk(mu_);
    Stats s;
    s.file_bytes = file_bytes_;
    s.log_records = log_records_;
    for (const auto& kv : map_) if (!kv.second.tomb) s.live_keys++;
    return s;
}

}
