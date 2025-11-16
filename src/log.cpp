#include "log_enhanced.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#include <io.h>
#else
#include <unistd.h>
#include <syslog.h>
#endif

namespace miq {

Logger* Logger::instance_ = nullptr;

// LogMessage implementation
std::string LogMessage::Format(bool color, bool include_timestamp, 
                              bool include_thread, bool include_source) const {
    std::stringstream ss;
    
    // Add timestamp
    if (include_timestamp) {
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            timestamp.time_since_epoch()) % 1000;
        
        struct tm tm_info;
#ifdef _WIN32
        localtime_s(&tm_info, &time_t);
#else
        localtime_r(&time_t, &tm_info);
#endif
        
        ss << std::put_time(&tm_info, "%Y-%m-%d %H:%M:%S");
        ss << '.' << std::setfill('0') << std::setw(3) << ms.count();
        ss << " ";
    }
    
    // Add log level
    const char* level_str = nullptr;
    const char* color_code = "";
    
    switch (level) {
        case LogLevel::TRACE:    
            level_str = "TRACE"; 
            color_code = "\033[37m";  // White
            break;
        case LogLevel::DEBUG:    
            level_str = "DEBUG"; 
            color_code = "\033[36m";  // Cyan
            break;
        case LogLevel::INFO:     
            level_str = "INFO "; 
            color_code = "\033[32m";  // Green
            break;
        case LogLevel::WARNING:  
            level_str = "WARN "; 
            color_code = "\033[33m";  // Yellow
            break;
        case LogLevel::ERROR:    
            level_str = "ERROR"; 
            color_code = "\033[31m";  // Red
            break;
        case LogLevel::CRITICAL: 
            level_str = "CRIT "; 
            color_code = "\033[35m";  // Magenta
            break;
        case LogLevel::FATAL:    
            level_str = "FATAL"; 
            color_code = "\033[91m";  // Bright Red
            break;
    }
    
    if (color) ss << color_code;
    ss << "[" << level_str << "]";
    if (color) ss << "\033[0m";  // Reset
    ss << " ";
    
    // Add category
    const char* cat_str = nullptr;
    switch (category) {
        case LogCategory::GENERAL:    cat_str = "general"; break;
        case LogCategory::NET:        cat_str = "net"; break;
        case LogCategory::P2P:        cat_str = "p2p"; break;
        case LogCategory::MEMPOOL:    cat_str = "mempool"; break;
        case LogCategory::CHAIN:      cat_str = "chain"; break;
        case LogCategory::VALIDATION: cat_str = "validation"; break;
        case LogCategory::MINER:      cat_str = "miner"; break;
        case LogCategory::RPC:        cat_str = "rpc"; break;
        case LogCategory::WALLET:     cat_str = "wallet"; break;
        case LogCategory::DB:         cat_str = "db"; break;
        case LogCategory::SCRIPT:     cat_str = "script"; break;
        case LogCategory::BENCH:      cat_str = "bench"; break;
        case LogCategory::PROXY:      cat_str = "proxy"; break;
    }
    
    ss << "[" << cat_str << "] ";
    
    // Add thread ID
    if (include_thread) {
        ss << "[" << thread_id << "] ";
    }
    
    // Add source location
    if (include_source && !file.empty()) {
        // Extract just filename, not full path
        size_t slash = file.find_last_of("/\\");
        std::string filename = (slash != std::string::npos) ? 
                              file.substr(slash + 1) : file;
        ss << filename << ":" << line << " ";
        if (!function.empty()) {
            ss << "(" << function << ") ";
        }
    }
    
    // Add message
    ss << message;
    
    return ss.str();
}

// ConsoleOutput implementation
ConsoleOutput::ConsoleOutput(bool enable_color) 
    : enable_color_(enable_color) {
#ifdef _WIN32
    // Enable ANSI color codes on Windows
    if (enable_color_) {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD dwMode = 0;
        GetConsoleMode(hOut, &dwMode);
        dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(hOut, dwMode);
    }
#endif
}

void ConsoleOutput::Write(const LogMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    bool use_color = enable_color_;
#ifdef _WIN32
    use_color = use_color && _isatty(_fileno(stdout));
#else
    use_color = use_color && isatty(fileno(stdout));
#endif
    
    std::string formatted = msg.Format(use_color, true, false, true);
    
    if (msg.level >= LogLevel::ERROR) {
        std::cerr << formatted << std::endl;
    } else {
        std::cout << formatted << std::endl;
    }
}

void ConsoleOutput::Flush() {
    std::cout.flush();
    std::cerr.flush();
}

// FileOutput implementation
FileOutput::FileOutput(const std::string& dir, const std::string& prefix,
                      size_t max_size, size_t max_files)
    : log_dir_(dir), file_prefix_(prefix), max_size_(max_size),
      max_files_(max_files), current_size_(0), current_index_(0) {
    
    // Create log directory if it doesn't exist
    std::filesystem::create_directories(log_dir_);
    
    // Find the latest log file index
    for (const auto& entry : std::filesystem::directory_iterator(log_dir_)) {
        if (entry.path().filename().string().find(file_prefix_) == 0) {
            std::string filename = entry.path().filename().string();
            size_t pos = filename.find_last_of('.');
            if (pos != std::string::npos) {
                std::string num_str = filename.substr(file_prefix_.length() + 1, 
                                                      pos - file_prefix_.length() - 1);
                try {
                    int index = std::stoi(num_str);
                    current_index_ = std::max(current_index_, index);
                } catch (...) {}
            }
        }
    }
    
    OpenNewFile();
}

FileOutput::~FileOutput() {
    if (file_.is_open()) {
        file_.close();
    }
}

void FileOutput::OpenNewFile() {
    if (file_.is_open()) {
        file_.close();
    }
    
    std::string filename = GenerateFilename(current_index_);
    std::filesystem::path filepath = log_dir_ / filename;
    
    // Check if file exists and get its size
    if (std::filesystem::exists(filepath)) {
        current_size_ = std::filesystem::file_size(filepath);
        file_.open(filepath, std::ios::app);
    } else {
        current_size_ = 0;
        file_.open(filepath);
    }
    
    if (!file_.is_open()) {
        throw std::runtime_error("Failed to open log file: " + filepath.string());
    }
}

std::string FileOutput::GenerateFilename(int index) const {
    std::stringstream ss;
    ss << file_prefix_ << "_" << std::setfill('0') << std::setw(5) << index << ".log";
    return ss.str();
}

void FileOutput::CheckRotation() {
    if (current_size_ >= max_size_) {
        Rotate();
    }
}

void FileOutput::Rotate() {
    current_index_++;
    OpenNewFile();
    CleanOldFiles();
}

void FileOutput::CleanOldFiles() {
    std::vector<std::filesystem::path> log_files;
    
    for (const auto& entry : std::filesystem::directory_iterator(log_dir_)) {
        if (entry.path().filename().string().find(file_prefix_) == 0) {
            log_files.push_back(entry.path());
        }
    }
    
    // Sort by modification time
    std::sort(log_files.begin(), log_files.end(),
              [](const auto& a, const auto& b) {
                  return std::filesystem::last_write_time(a) < 
                         std::filesystem::last_write_time(b);
              });
    
    // Remove old files if we exceed max_files
    while (log_files.size() > max_files_) {
        std::filesystem::remove(log_files.front());
        log_files.erase(log_files.begin());
    }
}

void FileOutput::Write(const LogMessage& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    CheckRotation();
    
    std::string formatted = msg.Format(false, true, true, true) + "\n";
    file_ << formatted;
    current_size_ += formatted.length();
}

void FileOutput::Flush() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_.is_open()) {
        file_.flush();
    }
}

// AsyncLogWriter implementation
AsyncLogWriter::AsyncLogWriter(size_t max_queue_size, LogMetrics& metrics)
    : max_queue_size_(max_queue_size), metrics_(metrics) {
    writer_thread_ = std::thread(&AsyncLogWriter::WriterLoop, this);
}

AsyncLogWriter::~AsyncLogWriter() {
    Stop();
}

void AsyncLogWriter::AddOutput(std::unique_ptr<LogOutput> output) {
    outputs_.push_back(std::move(output));
}

void AsyncLogWriter::Enqueue(const LogMessage& msg) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        if (queue_.size() >= max_queue_size_) {
            metrics_.dropped_messages++;
            return;
        }
        
        queue_.push(msg);
        metrics_.total_messages++;
    }
    
    cv_.notify_one();
}

void AsyncLogWriter::WriterLoop() {
    while (!stop_) {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        
        cv_.wait(lock, [this] { return !queue_.empty() || stop_; });
        
        while (!queue_.empty()) {
            LogMessage msg = queue_.front();
            queue_.pop();
            lock.unlock();
            
            for (auto& output : outputs_) {
                output->Write(msg);
            }
            
            lock.lock();
        }
    }
    
    // Flush remaining messages
    std::unique_lock<std::mutex> lock(queue_mutex_);
    while (!queue_.empty()) {
        LogMessage msg = queue_.front();
        queue_.pop();
        
        for (auto& output : outputs_) {
            output->Write(msg);
        }
    }
}

void AsyncLogWriter::Flush() {
    // Wait for queue to empty
    std::unique_lock<std::mutex> lock(queue_mutex_);
    cv_.wait(lock, [this] { return queue_.empty(); });
    
    // Flush all outputs
    for (auto& output : outputs_) {
        output->Flush();
    }
}

void AsyncLogWriter::Stop() {
    stop_ = true;
    cv_.notify_one();
    
    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }
}

// Logger implementation
Logger& Logger::Instance() {
    static Logger instance;
    instance_ = &instance;
    return instance;
}

void Logger::Initialize(const LogConfig& config) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    
    if (initialized_) {
        return;
    }
    
    config_ = config;
    InitOutputs();
    initialized_ = true;
}

void Logger::InitOutputs() {
    sync_outputs_.clear();
    
    if (config_.enable_async) {
        async_writer_ = std::make_unique<AsyncLogWriter>(
            config_.async_queue_size, metrics_);
        
        if (config_.enable_console) {
            async_writer_->AddOutput(
                std::make_unique<ConsoleOutput>(config_.enable_color));
        }
        
        if (config_.enable_file) {
            async_writer_->AddOutput(
                std::make_unique<FileOutput>(
                    config_.log_directory,
                    config_.log_file_prefix,
                    config_.max_file_size,
                    config_.max_files));
        }
    } else {
        if (config_.enable_console) {
            sync_outputs_.push_back(
                std::make_unique<ConsoleOutput>(config_.enable_color));
        }
        
        if (config_.enable_file) {
            sync_outputs_.push_back(
                std::make_unique<FileOutput>(
                    config_.log_directory,
                    config_.log_file_prefix,
                    config_.max_file_size,
                    config_.max_files));
        }
    }
}

void Logger::Log(const LogMessage& msg) {
    if (!initialized_) {
        // Auto-initialize with defaults if needed
        Initialize(LogConfig::Default());
    }
    
    if (!ShouldLog(msg.level, msg.category)) {
        return;
    }
    
    if (async_writer_) {
        async_writer_->Enqueue(msg);
    } else {
        for (auto& output : sync_outputs_) {
            output->Write(msg);
        }
    }
}

void Logger::SetLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_.min_level = level;
}

void Logger::SetCategoryLevel(LogCategory category, LogLevel level) {
    std::lock_guard<std::mutex> lock(config_mutex_);
    config_.category_levels[category] = level;
}

LogLevel Logger::GetCategoryLevel(LogCategory category) const {
    auto it = config_.category_levels.find(category);
    if (it != config_.category_levels.end()) {
        return it->second;
    }
    return config_.min_level;
}

void Logger::Flush() {
    if (async_writer_) {
        async_writer_->Flush();
    } else {
        for (auto& output : sync_outputs_) {
            output->Flush();
        }
    }
}

void Logger::Rotate() {
    metrics_.rotations++;
    
    if (async_writer_) {
        // Note: This is simplified - in production you'd want proper synchronization
        for (auto& output : sync_outputs_) {
            output->Rotate();
        }
    } else {
        for (auto& output : sync_outputs_) {
            output->Rotate();
        }
    }
}

void Logger::Shutdown() {
    if (async_writer_) {
        async_writer_->Stop();
    }
    
    Flush();
    sync_outputs_.clear();
    async_writer_.reset();
    initialized_ = false;
}

}
