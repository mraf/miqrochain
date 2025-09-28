#include "kvdb.h"
#include <sys/stat.h>

#ifdef _WIN32
  #include <direct.h>
  static inline void miq_mkdir(const std::string& p){ _mkdir(p.c_str()); }
#else
  #include <unistd.h>
  static inline void miq_mkdir(const std::string& p){ mkdir(p.c_str(), 0755); }
#endif

namespace miq {

KVDB::~KVDB(){ close(); }

bool KVDB::open(const std::string& path, std::string* err){
    close();
    path_ = path;
    miq_mkdir(path_);

#if MIQ_USE_ROCKSDB
    options_ = miqdb_backend::Options();
    options_.create_if_missing = true;
    options_.paranoid_checks = true;
    options_.enable_pipelined_write = true;
    options_.bytes_per_sync = 1<<20; // 1MB
    miqdb_backend::DB* db=nullptr;
    auto s = miqdb_backend::DB::Open(options_, path_, &db);
    if(!s.ok()){
        if(err) *err = s.ToString();
        return false;
    }
    db_ = db;
#else
    options_ = miqdb_backend::Options();
    options_.create_if_missing = true;
    options_.paranoid_checks = true;
    block_cache_.reset(miqdb_backend::NewLRUCache(64*1024*1024)); // 64MB
    bloom_ = miqdb_backend::NewBloomFilterPolicy(10);
    options_.block_cache = block_cache_.get();
    options_.filter_policy = bloom_;
    miqdb_backend::DB* db=nullptr;
    auto s = miqdb_backend::DB::Open(options_, path_, &db);
    if(!s.ok()){
        if(err) *err = s.ToString();
        return false;
    }
    db_ = db;
#endif
    return true;
}

bool KVDB::get(const std::string& k, std::string& v, std::string* err) const {
    if(!db_) { if(err)*err="db not open"; return false; }
#if MIQ_USE_ROCKSDB
    auto s = db_->Get(miqdb_backend::ReadOptions(), k, &v);
#else
    auto s = db_->Get(miqdb_backend::ReadOptions(), k, &v);
#endif
#if MIQ_USE_ROCKSDB
    if(s.IsNotFound()) return false;
    if(!s.ok()){ if(err) *err = s.ToString(); return false; }
#else
    if(!s.ok()){
        if(s.IsNotFound()) return false;
        if(err) *err = s.ToString();
        return false;
    }
#endif
    return true;
}

bool KVDB::put(const std::string& k, const std::string& v, bool sync, std::string* err){
    if(!db_) { if(err)*err="db not open"; return false; }
    miqdb_backend::WriteOptions wo;
    wo.sync = sync;
    auto s = db_->Put(wo, k, v);
#if MIQ_USE_ROCKSDB
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
#else
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
#endif
    return true;
}

bool KVDB::del(const std::string& k, bool sync, std::string* err){
    if(!db_) { if(err)*err="db not open"; return false; }
    miqdb_backend::WriteOptions wo;
    wo.sync = sync;
    auto s = db_->Delete(wo, k);
#if MIQ_USE_ROCKSDB
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
#else
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
#endif
    return true;
}

KVDB::Batch::Batch(KVDB& db) : db_(db) {}

void KVDB::Batch::put(const std::string& k, const std::string& v){
    wb_.Put(k, v);
}
void KVDB::Batch::del(const std::string& k){
    wb_.Delete(k);
}
bool KVDB::Batch::commit(bool sync, std::string* err){
    if(!db_.db_){ if(err)*err="db not open"; return false; }
    miqdb_backend::WriteOptions wo;
    wo.sync = sync;
    auto s = db_.db_->Write(wo, &wb_);
#if MIQ_USE_ROCKSDB
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
#else
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
#endif
    return true;
}

bool KVDB::flush_wal(std::string* err){
    if(!db_) { if(err)*err="db not open"; return false; }
#if MIQ_USE_ROCKSDB
    auto s = db_->FlushWAL(true); // wait=true
    if(!s.ok()){ if(err)*err=s.ToString(); return false; }
    return true;
#else
    // LevelDB has no explicit WAL flush; sync writes already fsync when sync=true.
    (void)err;
    return true;
#endif
}

void KVDB::close(){
    if(!db_) return;
#if !MIQ_USE_ROCKSDB
    if (options_.filter_policy && options_.filter_policy == bloom_) {
        delete bloom_;
        bloom_ = nullptr;
    }
#endif
    delete db_;
    db_ = nullptr;
}

}
