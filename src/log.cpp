// src/log.cpp
#include "log.h"
#include <mutex>
#include <iostream>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <string>

namespace miq {

static std::mutex g_log_mutex;

static void write_line(const char* level, const std::string& msg) noexcept {
    std::lock_guard<std::mutex> lk(g_log_mutex);
    try {
        const auto now = std::chrono::system_clock::now();
        const std::time_t tt = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
    #if defined(_WIN32)
        localtime_s(&tm, &tt);
    #else
        localtime_r(&tt, &tm);
    #endif
        std::ostream& os = (std::string(level) == "ERROR") ? std::cerr : std::cout;
        os << "[" << level << "]["
           << std::put_time(&tm, "%Y-%m-%d %H:%M:%S")
           << "] " << msg << std::endl;
    } catch (...) {
        // never let logging crash the process
        std::ostream& os = (std::string(level) == "ERROR") ? std::cerr : std::cout;
        os << "[" << level << "] " << msg << std::endl;
    }
}

void log_info(const std::string& m)  { write_line("INFO",  m); }
void log_warn(const std::string& m)  { write_line("WARN",  m); }
void log_error(const std::string& m) { write_line("ERROR", m); }

}

