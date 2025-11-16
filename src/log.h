#pragma once
#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <mutex>
#include <chrono>
#include <fstream>
#include <filesystem>
#include <queue>
#include <thread>
#include <condition_variable>
#include <unordered_map>
#include <sstream>
#include <iomanip>

namespace miq {

enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO = 2,
    WARNING = 3,
    ERROR = 4,
    CRITICAL = 5,
    FATAL = 6
};

enum class LogCategory {
    GENERAL,
    NET,
    P2P,
    MEMPOOL,
    CHAIN,
    VALIDATION,
    MINER,
    RPC,
    WALLET,
    DB,
    SCRIPT,
    BENCH,
    PROXY
};

struct LogMetrics {
    std::atomic<uint64_t> total_messages{0};
    std::atomic<uint64_t> dropped_messages{0};
    std::atomic<uint64_t> bytes_written{0};
    std::atomic<uint64_t> rotations{0};
    std::chrono::steady_clock::time_point start_time;
    
    LogMetrics() : start_time(std::chrono::steady_clock::now()) {}
    
    std::string GetStats() const {
        auto now = std::chrono::steady_clock::now();
        auto uptime = std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count();
        
        std::stringstream ss;
        ss << "Log Statistics:\n"
           << "  Total Messages: " << total_messages.load() << "\n"
           << "  Dropped Messages: " << dropped_messages.load() << "\n"
           << "  Bytes Written: " << FormatBytes(bytes_written.load()) << "\n"
           << "  File Rotations: " << rotations.load() << "\n"
           << "  Uptime: " << uptime << " seconds\n"
           << "  Messages/sec: " << (uptime > 0 ? total_messages.load() / uptime : 0);
        return ss.str();
    }
    
private:
    static std::string FormatBytes(uint64_t bytes) {
        const char* units[] = {"B", "KB", "MB", "GB"};
        int unit_idx = 0;
        double size = bytes;
        
        while (size >= 1024 && unit_idx < 3) {
            size /= 1024;
            unit_idx++;
        }
        
        std::stringstream ss;
        ss << std::fixed << std::setprecision(2) << size << " " << units[unit_idx];
        return ss.str();
    }
};

struct LogConfig {
    LogLevel min_level = LogLevel::INFO;
    bool enable_console = true;
    bool enable_file = true;
    bool enable_syslog = false;
    bool enable_async = true;
    bool enable_color = true;
    bool include_timestamp = true;
    bool include_thread_id = true;
    bool include_source_location = true;
    
    std::string log_directory = "./logs";
    std::string log_file_prefix = "miqro";
    size_t max_file_size = 100 * 1024 * 1024;  // 100MB
    size_t max_files = 10;
    size_t async_queue_size = 10000;
    
    std::unordered_map<LogCategory, LogLevel> category_levels;
    
    static LogConfig Default() {
        LogConfig config;
        // Set default category levels
        config.category_levels[LogCategory::GENERAL] = LogLevel::INFO;
        config.category_levels[LogCategory::NET] = LogLevel::INFO;
        config.category_levels[LogCategory::P2P] = LogLevel::INFO;
        config.category_levels[LogCategory::MEMPOOL] = LogLevel::INFO;
        config.category_levels[LogCategory::CHAIN] = LogLevel::INFO;
        config.category_levels[LogCategory::VALIDATION] = LogLevel::DEBUG;
        config.category_levels[LogCategory::MINER] = LogLevel::INFO;
        config.category_levels[LogCategory::RPC] = LogLevel::INFO;
        config.category_levels[LogCategory::WALLET] = LogLevel::INFO;
        config.category_levels[LogCategory::DB] = LogLevel::WARNING;
        config.category_levels[LogCategory::SCRIPT] = LogLevel::DEBUG;
        config.category_levels[LogCategory::BENCH] = LogLevel::DEBUG;
        config.category_levels[LogCategory::PROXY] = LogLevel::INFO;
        return config;
    }
};

class LogMessage {
public:
    LogLevel level;
    LogCategory category;
    std::string message;
    std::string file;
    std::string function;
    int line;
    std::thread::id thread_id;
    std::chrono::system_clock::time_point timestamp;
    
    LogMessage(LogLevel lvl, LogCategory cat, const std::string& msg,
               const std::string& f = "", const std::string& func = "", int l = 0)
        : level(lvl), category(cat), message(msg), file(f), function(func), line(l),
          thread_id(std::this_thread::get_id()),
          timestamp(std::chrono::system_clock::now()) {}
    
    std::string Format(bool color = false, bool include_timestamp = true,
                      bool include_thread = false, bool include_source = false) const;
};

class LogOutput {
public:
    virtual ~LogOutput() = default;
    virtual void Write(const LogMessage& msg) = 0;
    virtual void Flush() = 0;
    virtual void Rotate() {}
};

class ConsoleOutput : public LogOutput {
private:
    std::mutex mutex_;
    bool enable_color_;
    
public:
    explicit ConsoleOutput(bool enable_color = true);
    void Write(const LogMessage& msg) override;
    void Flush() override;
};

class FileOutput : public LogOutput {
private:
    std::mutex mutex_;
    std::ofstream file_;
    std::filesystem::path log_dir_;
    std::string file_prefix_;
    size_t max_size_;
    size_t max_files_;
    size_t current_size_;
    int current_index_;
    
    void OpenNewFile();
    void CheckRotation();
    void CleanOldFiles();
    std::string GenerateFilename(int index) const;
    
public:
    FileOutput(const std::string& dir, const std::string& prefix,
               size_t max_size, size_t max_files);
    ~FileOutput();
    void Write(const LogMessage& msg) override;
    void Flush() override;
    void Rotate() override;
};

class AsyncLogWriter {
private:
    std::queue<LogMessage> queue_;
    std::mutex queue_mutex_;
    std::condition_variable cv_;
    std::thread writer_thread_;
    std::atomic<bool> stop_{false};
    size_t max_queue_size_;
    std::vector<std::unique_ptr<LogOutput>> outputs_;
    LogMetrics& metrics_;
    
    void WriterLoop();
    
public:
    AsyncLogWriter(size_t max_queue_size, LogMetrics& metrics);
    ~AsyncLogWriter();
    
    void AddOutput(std::unique_ptr<LogOutput> output);
    void Enqueue(const LogMessage& msg);
    void Flush();
    void Stop();
};

class Logger {
private:
    static Logger* instance_;
    LogConfig config_;
    LogMetrics metrics_;
    std::vector<std::unique_ptr<LogOutput>> sync_outputs_;
    std::unique_ptr<AsyncLogWriter> async_writer_;
    std::mutex config_mutex_;
    std::atomic<bool> initialized_{false};
    
    Logger() = default;
    void InitOutputs();
    
public:
    static Logger& Instance();
    
    void Initialize(const LogConfig& config);
    void Log(const LogMessage& msg);
    void SetLevel(LogLevel level);
    void SetCategoryLevel(LogCategory category, LogLevel level);
    LogLevel GetCategoryLevel(LogCategory category) const;
    void Flush();
    void Rotate();
    LogMetrics GetMetrics() const { return metrics_; }
    std::string GetStats() const { return metrics_.GetStats(); }
    void Shutdown();
    
    // Convenience logging methods
    template<typename... Args>
    void LogFormat(LogLevel level, LogCategory category, 
                  const std::string& format, Args... args) {
        if (!ShouldLog(level, category)) return;
        
        char buffer[4096];
        snprintf(buffer, sizeof(buffer), format.c_str(), args...);
        Log(LogMessage(level, category, buffer));
    }
    
    bool ShouldLog(LogLevel level, LogCategory category) const {
        auto cat_level = GetCategoryLevel(category);
        return level >= cat_level && level >= config_.min_level;
    }
};

// Macros for convenient logging with source location
#define LOG_TRACE(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::TRACE, cat, msg, __FILE__, __FUNCTION__, __LINE__))

#define LOG_DEBUG(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::DEBUG, cat, msg, __FILE__, __FUNCTION__, __LINE__))

#define LOG_INFO(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::INFO, cat, msg, __FILE__, __FUNCTION__, __LINE__))

#define LOG_WARNING(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::WARNING, cat, msg, __FILE__, __FUNCTION__, __LINE__))

#define LOG_ERROR(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::ERROR, cat, msg, __FILE__, __FUNCTION__, __LINE__))

#define LOG_CRITICAL(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::CRITICAL, cat, msg, __FILE__, __FUNCTION__, __LINE__))

#define LOG_FATAL(cat, msg) \
    miq::Logger::Instance().Log(miq::LogMessage(miq::LogLevel::FATAL, cat, msg, __FILE__, __FUNCTION__, __LINE__))

// Format logging macros
#define LOGF_TRACE(cat, fmt, ...) \
    miq::Logger::Instance().LogFormat(miq::LogLevel::TRACE, cat, fmt, ##__VA_ARGS__)

#define LOGF_DEBUG(cat, fmt, ...) \
    miq::Logger::Instance().LogFormat(miq::LogLevel::DEBUG, cat, fmt, ##__VA_ARGS__)

#define LOGF_INFO(cat, fmt, ...) \
    miq::Logger::Instance().LogFormat(miq::LogLevel::INFO, cat, fmt, ##__VA_ARGS__)

#define LOGF_WARNING(cat, fmt, ...) \
    miq::Logger::Instance().LogFormat(miq::LogLevel::WARNING, cat, fmt, ##__VA_ARGS__)

#define LOGF_ERROR(cat, fmt, ...) \
    miq::Logger::Instance().LogFormat(miq::LogLevel::ERROR, cat, fmt, ##__VA_ARGS__)

// Performance logging helper
class LogTimer {
private:
    LogCategory category_;
    std::string operation_;
    std::chrono::high_resolution_clock::time_point start_;
    LogLevel level_;
    
public:
    LogTimer(LogCategory cat, const std::string& op, LogLevel level = LogLevel::DEBUG)
        : category_(cat), operation_(op), level_(level),
          start_(std::chrono::high_resolution_clock::now()) {}
    
    ~LogTimer() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_).count();
        
        std::stringstream ss;
        ss << operation_ << " took " << duration << " µs";
        Logger::Instance().Log(LogMessage(level_, category_, ss.str()));
    }
};

#define LOG_TIMER(cat, op) miq::LogTimer _timer_##__LINE__(cat, op)
#define LOG_TIMER_LEVEL(cat, op, level) miq::LogTimer _timer_##__LINE__(cat, op, level)

}
