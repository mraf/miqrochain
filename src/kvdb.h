#pragma once
#include <string>
#include <vector>
#include <cstdint>
#include <memory>

// Select backend (default: LevelDB)
#ifndef MIQ_USE_ROCKSDB
#define MIQ_USE_LEVELDB 1
#endif

#if MIQ_USE_ROCKSDB
  #include <rocksdb/db.h>
  #include <rocksdb/options.h>
  #include <rocksdb/slice.h>
  #include <rocksdb/write_batch.h>
  #include <rocksdb/utilities/checkpoint.h>
  namespace miqdb_backend = rocksdb;
#else
  #include <leveldb/db.h>
  #include <leveldb/write_batch.h>
  #include <leveldb/cache.h>
  #include <leveldb/filter_policy.h>
  #include <leveldb/env.h>
  namespace miqdb_backend = leveldb;
#endif

namespace miq {

class KVDB {
public:
    KVDB() = default;
    ~KVDB();

    // Create/open a database directory. Creates it if missing.
    bool open(const std::string& path, std::string* err = nullptr);

    // Get/Put/Delete single keys (immediate, not batched)
    bool get(const std::string& k, std::string& v, std::string* err = nullptr) const;
    bool put(const std::string& k, const std::string& v, bool sync=true, std::string* err = nullptr);
    bool del(const std::string& k, bool sync=true, std::string* err = nullptr);

    // Batched writer (atomic).
    class Batch {
    public:
        explicit Batch(KVDB& db);
        void put(const std::string& k, const std::string& v);
        void del(const std::string& k);
        bool commit(bool sync=true, std::string* err = nullptr);
    private:
        KVDB& db_;
    #if MIQ_USE_ROCKSDB
        miqdb_backend::WriteBatch wb_;
    #else
        miqdb_backend::WriteBatch wb_;
    #endif
    };

    // Manual fsync of manifest/WAL (if supported)
    bool flush_wal(std::string* err = nullptr);

    // Close DB
    void close();

private:
    KVDB(const KVDB&) = delete;
    KVDB& operator=(const KVDB&) = delete;

#if MIQ_USE_ROCKSDB
    miqdb_backend::DB* db_ = nullptr;
    miqdb_backend::Options options_;
#else
    miqdb_backend::DB* db_ = nullptr;
    miqdb_backend::Options options_;
    std::unique_ptr<miqdb_backend::Cache> block_cache_;
    const miqdb_backend::FilterPolicy* bloom_ = nullptr;
#endif
    std::string path_;
};

}
