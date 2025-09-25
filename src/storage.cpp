#include "storage.h"
#include "hex.h"
#include <cstdint>
#include <fstream>
#include <filesystem>
namespace fs = std::filesystem;
namespace miq {
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
bool Storage::append_block(const std::vector<uint8_t>& raw, const std::vector<uint8_t>& hash){
    std::ofstream f(path_blocks_, std::ios::app|std::ios::binary);
    if(!f) return false;
    auto off = (uint64_t)std::filesystem::file_size(path_blocks_);
    uint32_t sz=(uint32_t)raw.size();
    f.write((const char*)&sz,sizeof(sz)); f.write((const char*)raw.data(), sz);
    offsets_.push_back(off);
    uint32_t idx = (uint32_t)offsets_.size()-1;
    hash_to_index_[to_hex(hash)] = idx;
    // persist index and hashmap append-only
    std::ofstream idxf(path_index_, std::ios::app|std::ios::binary); idxf.write((const char*)&off, sizeof(off));
    std::ofstream hm(path_hashmap_, std::ios::app|std::ios::binary); uint32_t ksz=(uint32_t)to_hex(hash).size(); hm.write((const char*)&ksz,sizeof(ksz)); hm.write(to_hex(hash).c_str(), ksz); hm.write((const char*)&idx,sizeof(idx));
    return true;
}
bool Storage::read_block_by_index(size_t index, std::vector<uint8_t>& out) const{
    if(index>=offsets_.size()) return false;
    std::ifstream f(path_blocks_, std::ios::binary); f.seekg(offsets_[index]);
    uint32_t sz=0; f.read((char*)&sz,sizeof(sz)); out.resize(sz); f.read((char*)out.data(), sz); return (bool)f;
}
bool Storage::read_block_by_hash(const std::vector<uint8_t>& hash, std::vector<uint8_t>& out) const{
    auto it = hash_to_index_.find(to_hex(hash)); if(it==hash_to_index_.end()) return false;
    return read_block_by_index(it->second, out);
}
bool Storage::write_state(const std::vector<uint8_t>& b){ std::ofstream f(path_state_, std::ios::binary|std::ios::trunc); if(!f) return false; f.write((const char*)b.data(), b.size()); return true; }
bool Storage::read_state(std::vector<uint8_t>& b) const{ std::ifstream f(path_state_, std::ios::binary); if(!f) return false; b.assign((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>()); return true; }
}
