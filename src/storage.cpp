#include "storage.h"
#include "hex.h"
#include <cstdint>
#include <fstream>
#include <filesystem>

#if defined(_WIN32)
  #include <windows.h>
  static inline void flush_path(const std::string& p){
      HANDLE h = CreateFileA(p.c_str(), GENERIC_WRITE,
                             FILE_SHARE_READ|FILE_SHARE_WRITE, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      if (h != INVALID_HANDLE_VALUE) { FlushFileBuffers(h); CloseHandle(h); }
  }
#else
  #include <unistd.h>
  #include <fcntl.h>
  static inline void flush_path(const std::string& p){
      int fd = ::open(p.c_str(), O_RDWR | O_CLOEXEC);
      if (fd >= 0) { ::fsync(fd); ::close(fd); }
  }
#endif

namespace fs = std::filesystem;
namespace miq {

static bool fast_sync_enabled() {
    const char* e = std::getenv("MIQ_FAST_SYNC");
    return e && (e[0]=='1' || e[0]=='t' || e[0]=='T' || e[0]=='y' || e[0]=='Y');
}
static inline int64_t now_ms_steady(){
    using clock = std::chrono::steady_clock;
    return std::chrono::duration_cast<std::chrono::milliseconds>(clock::now().time_since_epoch()).count();
}

bool Storage::open(const std::string& dir){
    fs::create_directories(dir);
    path_blocks_ = dir + "/blocks.dat";
    path_state_  = dir + "/state.dat";
    path_index_  = dir + "/blocks.idx";
    path_hashmap_ = dir + "/hash.map";
    offsets_.clear(); hash_to_index_.clear();
    std::ofstream ensure(path_blocks_, std::ios::app|std::ios::binary); ensure.close();
    std::ifstream f(path_blocks_, std::ios::binary);
    uint64_t off=0; uint32_t idx=0;
    while(true){
        uint32_t sz=0; f.read((char*)&sz,sizeof(sz)); if(!f) break;
        offsets_.push_back(off);
        f.seekg(sz, std::ios::cur); off = (uint64_t)f.tellg(); idx++;
    }
    // load hashmap
    std::ifstream hm(path_hashmap_, std::ios::binary);
    while(hm){
        uint32_t ksz=0; hm.read((char*)&ksz,sizeof(ksz)); if(!hm) break;
        std::string k(ksz,'\0'); hm.read(&k[0], ksz); uint32_t vi=0; hm.read((char*)&vi,sizeof(vi)); hash_to_index_[k]=vi;
    }
    return true;
}
// Append a block, update offsets and hash->index, then fsync all files.
bool miq::Storage::append_block(const std::vector<uint8_t>& raw,
                                const std::vector<uint8_t>& hash){
    std::ofstream f(path_blocks_, std::ios::app|std::ios::binary);
    if(!f) return false;

    uint64_t off = (uint64_t)std::filesystem::file_size(path_blocks_);
    uint32_t sz  = (uint32_t)raw.size();
    f.write((const char*)&sz, sizeof(sz));
    f.write((const char*)raw.data(), sz);
    f.flush();
    if (!fast_sync_enabled()) { flush_path(path_blocks_); }

    offsets_.push_back(off);
    uint32_t idx = (uint32_t)offsets_.size()-1;
    const std::string hexh = miq::to_hex(hash);
    hash_to_index_[hexh] = idx;

    // persist index and hashmap append-only (with flush)
    {
        std::ofstream idxf(path_index_, std::ios::app|std::ios::binary);
        idxf.write((const char*)&off, sizeof(off));
        idxf.flush();
        flush_path(path_index_);
    }
    {
        std::ofstream hm(path_hashmap_, std::ios::app|std::ios::binary);
        uint32_t ksz = (uint32_t)hexh.size();
        hm.write((const char*)&ksz, sizeof(ksz));
        hm.write(hexh.c_str(), ksz);
        hm.write((const char*)&idx, sizeof(idx));
        hm.flush(); if (!fast_sync_enabled()) { flush_path(path_hashmap_); }
    }
    return true;
}

bool miq::Storage::read_block_by_index(size_t index, std::vector<uint8_t>& out) const{
    if(index >= offsets_.size()) return false;
    std::ifstream f(path_blocks_, std::ios::binary);
    if(!f) return false;

    f.seekg((std::streamoff)offsets_[index], std::ios::beg);
    uint32_t sz = 0;
    if(!f.read((char*)&sz, sizeof(sz))) return false;
    out.resize(sz);
    return (bool)f.read((char*)out.data(), sz);
}

bool miq::Storage::read_block_by_hash(const std::vector<uint8_t>& hash,
                                      std::vector<uint8_t>& out) const{
    auto it = hash_to_index_.find(miq::to_hex(hash));
    if(it == hash_to_index_.end()) return false;
    return read_block_by_index(it->second, out);
}

bool miq::Storage::write_state(const std::vector<uint8_t>& b){
    std::ofstream f(path_state_, std::ios::binary|std::ios::trunc);
    if(!f) return false;
    f.write((const char*)b.data(), b.size());
    f.flush();
    flush_path(path_state_);
    return true;
}

bool miq::Storage::read_state(std::vector<uint8_t>& out) const {
    std::ifstream f(path_state_, std::ios::binary);
    if (!f) return false;                 // no state file → caller may treat as "fresh"
    f.seekg(0, std::ios::end);
    std::streamoff end = f.tellg();
    if (end < 0) return false;
    size_t sz = static_cast<size_t>(end);
    f.seekg(0, std::ios::beg);
    out.resize(sz);
    if (sz == 0) return true;             // empty state is valid
    return (bool)f.read(reinterpret_cast<char*>(out.data()), sz);
}

} // namespace miq
