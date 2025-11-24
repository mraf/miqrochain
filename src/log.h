// =============================================================================
// PRODUCTION-GRADE LOGGING SYSTEM
// =============================================================================

#pragma once
#include <string>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <sstream>

namespace miq {

// Log levels (production-grade)
// Note: Using ERR instead of ERROR to avoid conflict with Windows ERROR macro
enum class LogLevel : int {
    TRACE = 0,    // Extremely verbose
    DEBUG = 1,    // Debug information
    INFO = 2,     // General information
    WARN = 3,     // Warnings
    ERR = 4,      // Errors (named ERR to avoid Windows macro conflict)
    FATAL = 5,    // Fatal errors
    NONE = 6      // Disable all logging
};

// Log categories for filtering
enum class LogCategory : uint32_t {
    GENERAL    = 0x0001,
    NET        = 0x0002,
    MEMPOOL    = 0x0004,
    VALIDATION = 0x0008,
    MINING     = 0x0010,
    RPC        = 0x0020,
    WALLET     = 0x0040,
    DB         = 0x0080,
    BENCH      = 0x0100,
    ALL        = 0xFFFF
};

// Configuration
void log_set_level(LogLevel level);
void log_set_categories(uint32_t categories);
void log_enable_timestamps(bool enable);
void log_enable_file(const std::string& filepath);
void log_set_max_file_size(size_t bytes);  // Rotate when exceeded

// Get current configuration
LogLevel log_get_level();
uint32_t log_get_categories();

// Basic logging functions (keep backward compatible)
void log_info(const std::string& s);
void log_warn(const std::string& s);
void log_error(const std::string& s);

// Production logging with categories
void log_trace(LogCategory cat, const std::string& s);
void log_debug(LogCategory cat, const std::string& s);
void log_info(LogCategory cat, const std::string& s);
void log_warn(LogCategory cat, const std::string& s);
void log_error(LogCategory cat, const std::string& s);
void log_fatal(LogCategory cat, const std::string& s);

// Conditional logging (avoids string construction if level is disabled)
// Use MIQ_LOG_* to avoid conflicts with existing log_* functions
#define MIQ_LOG_TRACE(cat, msg) do { \
    if (miq::log_get_level() <= miq::LogLevel::TRACE && \
        (miq::log_get_categories() & static_cast<uint32_t>(cat))) { \
        miq::log_trace(cat, msg); \
    } \
} while(0)

#define MIQ_LOG_DEBUG(cat, msg) do { \
    if (miq::log_get_level() <= miq::LogLevel::DEBUG && \
        (miq::log_get_categories() & static_cast<uint32_t>(cat))) { \
        miq::log_debug(cat, msg); \
    } \
} while(0)

#define MIQ_LOG_INFO(cat, msg) do { \
    if (miq::log_get_level() <= miq::LogLevel::INFO && \
        (miq::log_get_categories() & static_cast<uint32_t>(cat))) { \
        miq::log_info(cat, msg); \
    } \
} while(0)

#define MIQ_LOG_WARN(cat, msg) do { \
    if (miq::log_get_level() <= miq::LogLevel::WARN && \
        (miq::log_get_categories() & static_cast<uint32_t>(cat))) { \
        miq::log_warn(cat, msg); \
    } \
} while(0)

#define MIQ_LOG_ERROR(cat, msg) do { \
    if (miq::log_get_level() <= miq::LogLevel::ERR && \
        (miq::log_get_categories() & static_cast<uint32_t>(cat))) { \
        miq::log_error(cat, msg); \
    } \
} while(0)

// Structured log entry for production monitoring
struct LogEntry {
    int64_t timestamp_ms;
    LogLevel level;
    LogCategory category;
    std::string message;
    std::string source_file;
    int source_line;
    std::string thread_id;
};

// Metrics logging (for production monitoring)
void log_metric(const std::string& name, double value);
void log_metric(const std::string& name, int64_t value);
void log_counter_inc(const std::string& name, int64_t delta = 1);
void log_gauge_set(const std::string& name, double value);
void log_histogram(const std::string& name, double value);

// Flush all buffered logs
void log_flush();

// Production initialization
void log_init(LogLevel level = LogLevel::INFO,
              uint32_t categories = static_cast<uint32_t>(LogCategory::ALL),
              const std::string& log_file = "");

// Shutdown logging (flush and close files)
void log_shutdown();

// Enable/disable async logging mode (for high-throughput scenarios)
void log_set_async(bool enable);

// Rate limiting helper - returns true if this log call should be suppressed
bool log_rate_limited(const char* file, int line);

// Rate-limited logging macro - only logs once per second from same source location
#define MIQ_LOG_RATE_LIMITED(level, msg) do { \
    if (!miq::log_rate_limited(__FILE__, __LINE__)) { \
        miq::log_##level(msg); \
    } \
} while(0)

}  // namespace miq
