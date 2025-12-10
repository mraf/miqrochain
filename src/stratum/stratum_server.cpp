// src/stratum/stratum_server.cpp
#include "stratum_server.h"
#include "../chain.h"
#include "../mempool.h"
#include "../sha256.h"
#include "../merkle.h"
#include "../hex.h"
#include "../serialize.h"
#include "../constants.h"
#include "../log.h"
#include "../tx.h"
#include "../block.h"
#include "../difficulty.h"  // epoch_next_bits for proper difficulty calculation

#include <algorithm>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <cmath>
#include <random>

#ifdef _WIN32
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <netinet/in.h>
  #include <netinet/tcp.h>  // TCP_NODELAY
  #include <arpa/inet.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #include <fcntl.h>
  #include <poll.h>
#endif

namespace miq {

// =============================================================================
// Constants
// =============================================================================
static constexpr uint8_t EXTRANONCE1_SIZE = 4;  // 4 bytes (8 hex chars)

// =============================================================================
// Helper functions
// =============================================================================

static std::string hex_encode(const std::vector<uint8_t>& data) {
    return to_hex(data);
}

static std::vector<uint8_t> hex_decode(const std::string& hex) {
    return from_hex(hex);
}

static std::string reverse_hex(const std::string& hex) {
    if (hex.length() % 2 != 0) return hex;
    std::string result;
    result.reserve(hex.length());
    for (size_t i = hex.length(); i >= 2; i -= 2) {
        result += hex.substr(i - 2, 2);
    }
    return result;
}

static std::string json_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

// Simple JSON parsing (minimal implementation)
static bool parse_json_string(const std::string& json, size_t& pos, std::string& out) {
    if (pos >= json.size() || json[pos] != '"') return false;
    pos++;
    out.clear();
    while (pos < json.size() && json[pos] != '"') {
        if (json[pos] == '\\' && pos + 1 < json.size()) {
            pos++;
            switch (json[pos]) {
                case '"': out += '"'; break;
                case '\\': out += '\\'; break;
                case 'n': out += '\n'; break;
                case 'r': out += '\r'; break;
                case 't': out += '\t'; break;
                default: out += json[pos];
            }
        } else {
            out += json[pos];
        }
        pos++;
    }
    // CRITICAL FIX: Validate string was properly terminated with closing quote
    if (pos >= json.size() || json[pos] != '"') {
        return false;  // Unterminated string
    }
    pos++; // skip closing quote
    return true;
}

static bool parse_json_number(const std::string& json, size_t& pos, int64_t& out) {
    size_t start = pos;
    if (pos < json.size() && (json[pos] == '-' || json[pos] == '+')) pos++;
    while (pos < json.size() && (json[pos] >= '0' && json[pos] <= '9')) pos++;
    if (pos == start) return false;
    out = std::stoll(json.substr(start, pos - start));
    return true;
}

static void skip_whitespace(const std::string& json, size_t& pos) {
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t' || json[pos] == '\n' || json[pos] == '\r')) {
        pos++;
    }
}

// =============================================================================
// StratumServer implementation
// =============================================================================

StratumServer::StratumServer(Chain& chain, Mempool& mempool)
    : chain_(chain), mempool_(mempool) {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

StratumServer::~StratumServer() {
    stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

int64_t StratumServer::now_ms() {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

bool StratumServer::start() {
    if (running_) return false;

    // Create listening socket
    listen_sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_sock_ == STRATUM_INVALID_SOCKET) {
        log_error("Stratum: Failed to create socket");
        return false;
    }

    // Set socket options
    int opt = 1;
#ifdef _WIN32
    setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));
#else
    setsockopt(listen_sock_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    // Bind
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);

    if (bind(listen_sock_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        log_error("Stratum: Failed to bind to port " + std::to_string(port_));
#ifdef _WIN32
        closesocket(listen_sock_);
#else
        close(listen_sock_);
#endif
        listen_sock_ = STRATUM_INVALID_SOCKET;
        return false;
    }

    if (listen(listen_sock_, 128) < 0) {
        log_error("Stratum: Failed to listen");
#ifdef _WIN32
        closesocket(listen_sock_);
#else
        close(listen_sock_);
#endif
        listen_sock_ = STRATUM_INVALID_SOCKET;
        return false;
    }

    running_ = true;

    // CRITICAL FIX: Create initial job BEFORE starting threads
    // This eliminates the race condition where miners connect before a job exists
    {
        log_info("Stratum: Creating initial job before accepting miners...");
        auto job = create_job();
        {
            std::lock_guard<std::mutex> lock(jobs_mutex_);
            jobs_[job.job_id] = job;
            job_order_.push_back(job.job_id);
            current_job_id_ = job.job_id;
        }
        log_info("Stratum: Initial job ready: " + job.job_id + " height=" + std::to_string(job.height));
    }

    // Start threads - now miners will always have a job available
    accept_thread_ = std::thread(&StratumServer::accept_loop, this);
    work_thread_ = std::thread(&StratumServer::work_loop, this);

    log_info("Stratum server started on port " + std::to_string(port_));
    return true;
}

void StratumServer::stop() {
    if (!running_) return;
    running_ = false;

    // Close listening socket
    if (listen_sock_ != STRATUM_INVALID_SOCKET) {
#ifdef _WIN32
        closesocket(listen_sock_);
#else
        close(listen_sock_);
#endif
        listen_sock_ = STRATUM_INVALID_SOCKET;
    }

    // Join threads
    if (accept_thread_.joinable()) accept_thread_.join();
    if (work_thread_.joinable()) work_thread_.join();

    // Close all miner connections
    {
        std::lock_guard<std::mutex> lock(miners_mutex_);
        for (auto& kv : miners_) {
#ifdef _WIN32
            closesocket(kv.first);
#else
            close(kv.first);
#endif
        }
        miners_.clear();
    }

    log_info("Stratum server stopped");
}

void StratumServer::accept_loop() {
    while (running_) {
        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

#ifdef _WIN32
        StratumSock client = accept(listen_sock_, (sockaddr*)&client_addr, &client_len);
        if (client == INVALID_SOCKET) {
            if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
#else
        StratumSock client = accept(listen_sock_, (sockaddr*)&client_addr, &client_len);
        if (client < 0) {
            if (running_) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
#endif

        // Get client IP
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        std::string ip(ip_str);

        // Check connection limits
        {
            std::lock_guard<std::mutex> lock(miners_mutex_);

            // Check total miner limit
            if (miners_.size() >= MAX_MINERS) {
                log_warn("Stratum: Connection rejected - max miners reached (" + std::to_string(MAX_MINERS) + ")");
#ifdef _WIN32
                closesocket(client);
#else
                close(client);
#endif
                continue;
            }

            // Check per-IP limit
            size_t ip_count = 0;
            for (const auto& kv : miners_) {
                if (kv.second.ip == ip) {
                    ip_count++;
                }
            }
            if (ip_count >= MAX_PER_IP) {
                log_warn("Stratum: Connection rejected from " + ip + " - max per-IP reached (" + std::to_string(MAX_PER_IP) + ")");
#ifdef _WIN32
                closesocket(client);
#else
                close(client);
#endif
                continue;
            }
        }

        // CRITICAL FIX: Set TCP_NODELAY to disable Nagle's algorithm
        // This ensures subscribe responses are sent immediately without buffering
        int nodelay = 1;
#ifdef _WIN32
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

        // CRITICAL FIX: Increase send buffer size for Windows to avoid WSA 10053
        // Default buffer is often too small for rapid message sending
        int sndbuf = 65536;  // 64KB send buffer
        setsockopt(client, SOL_SOCKET, SO_SNDBUF, (const char*)&sndbuf, sizeof(sndbuf));

        // Set SO_LINGER to ensure clean socket shutdown
        struct linger ling = {1, 5};  // Linger on close for 5 seconds
        setsockopt(client, SOL_SOCKET, SO_LINGER, (const char*)&ling, sizeof(ling));
#else
        setsockopt(client, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

        // Increase send buffer on Linux too
        int sndbuf = 65536;
        setsockopt(client, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
#endif

        // Set non-blocking
#ifdef _WIN32
        u_long mode = 1;
        ioctlsocket(client, FIONBIO, &mode);
#else
        int flags = fcntl(client, F_GETFL, 0);
        fcntl(client, F_SETFL, flags | O_NONBLOCK);
#endif

        // Create miner state
        StratumMiner miner;
        miner.sock = client;
        miner.ip = ip;
        miner.extranonce1 = generate_extranonce1();
        miner.difficulty = default_difficulty_;
        miner.target_difficulty = default_difficulty_;
        miner.connected_ms = now_ms();
        miner.last_activity_ms = now_ms();
        miner.vardiff_last_adjust_ms = now_ms();

        {
            std::lock_guard<std::mutex> lock(miners_mutex_);
            miners_[client] = std::move(miner);
        }

        log_info("Stratum: New miner connected from " + ip + " (total: " + std::to_string(miners_.size()) + ")");
    }
}

void StratumServer::work_loop() {
    // Initial job is now created in start() before threads are started
    // This eliminates the race condition where miners connect before a job exists
    int64_t last_job_time = now_ms();  // Start timer from now since job already exists
    int64_t last_cleanup_time = 0;

    log_info("Stratum: work_loop started");

    while (running_) {
        int64_t now = now_ms();

        // Create periodic job update (every 30 seconds) or when tip changes
        if (now - last_job_time > 30000) {
            auto job = create_job();
            {
                std::lock_guard<std::mutex> lock(jobs_mutex_);
                jobs_[job.job_id] = job;
                job_order_.push_back(job.job_id);
                current_job_id_ = job.job_id;
            }
            // Count subscribed miners for logging
            size_t subscribed_count = 0;
            {
                std::lock_guard<std::mutex> lock(miners_mutex_);
                for (const auto& kv : miners_) {
                    if (kv.second.subscribed) subscribed_count++;
                }
            }
            log_info("Stratum: Created job " + job.job_id + " height=" + std::to_string(job.height) +
                     " fees=" + std::to_string(job.total_fees) + " broadcasting to " +
                     std::to_string(subscribed_count) + " miners");
            broadcast_job(job);
            last_job_time = now;
        }

        // Cleanup old jobs periodically
        if (now - last_cleanup_time > 60000) {
            cleanup_old_jobs();
            last_cleanup_time = now;
        }

        // Process miner data
        std::vector<StratumSock> to_process;
        {
            std::lock_guard<std::mutex> lock(miners_mutex_);
            for (auto& kv : miners_) {
                to_process.push_back(kv.first);
            }
        }

        for (StratumSock sock : to_process) {
            std::lock_guard<std::mutex> lock(miners_mutex_);
            auto it = miners_.find(sock);
            if (it == miners_.end()) continue;

            handle_miner_data(it->second);

            // Re-check iterator validity after handle_miner_data (may have disconnected)
            it = miners_.find(sock);
            if (it == miners_.end()) continue;

            // CRITICAL FIX: Check for pending disconnect after message processing
            if (it->second.pending_disconnect) {
                disconnect_miner(sock, "send failed");
                continue; // Iterator invalidated
            }

            // Check for timeout (2 minutes of inactivity)
            if (now - it->second.last_activity_ms > 120000) {
                disconnect_miner(sock, "timeout");
                continue; // Iterator invalidated
            }

            // Update vardiff
            if (vardiff_enabled_ && it->second.authorized) {
                update_vardiff(it->second);
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void StratumServer::handle_miner_data(StratumMiner& miner) {
    // CRITICAL FIX: Increased buffer from 4KB to 16KB for large job messages
    // Jobs with many merkle branches can exceed 4KB
    char buf[16384];
#ifdef _WIN32
    int n = recv(miner.sock, buf, sizeof(buf) - 1, 0);
    if (n == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEWOULDBLOCK) {
            disconnect_miner(miner.sock, "recv error");
        }
        return;
    }
#else
    ssize_t n = recv(miner.sock, buf, sizeof(buf) - 1, 0);
    if (n < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            disconnect_miner(miner.sock, "recv error");
        }
        return;
    }
#endif

    if (n == 0) {
        disconnect_miner(miner.sock, "connection closed");
        return;
    }

    buf[n] = '\0';
    miner.rx_buffer += buf;
    miner.last_activity_ms = now_ms();

    // Process complete lines (JSON-RPC messages)
    size_t pos;
    while ((pos = miner.rx_buffer.find('\n')) != std::string::npos) {
        std::string line = miner.rx_buffer.substr(0, pos);
        miner.rx_buffer.erase(0, pos + 1);

        // Trim \r if present
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        if (!line.empty()) {
            process_message(miner, line);
        }
    }

    // Prevent buffer overflow
    if (miner.rx_buffer.size() > 65536) {
        disconnect_miner(miner.sock, "buffer overflow");
    }
}

void StratumServer::process_message(StratumMiner& miner, const std::string& line) {
    // Parse JSON-RPC message
    // Format: {"id": N, "method": "...", "params": [...]}

    size_t pos = 0;
    skip_whitespace(line, pos);
    if (pos >= line.size() || line[pos] != '{') return;
    pos++;

    uint64_t id = 0;
    std::string method;
    std::vector<std::string> params;

    while (pos < line.size() && line[pos] != '}') {
        skip_whitespace(line, pos);
        if (line[pos] == ',') { pos++; continue; }

        std::string key;
        if (!parse_json_string(line, pos, key)) break;

        skip_whitespace(line, pos);
        if (pos >= line.size() || line[pos] != ':') break;
        pos++;
        skip_whitespace(line, pos);

        if (key == "id") {
            if (line[pos] == '"') {
                std::string id_str;
                parse_json_string(line, pos, id_str);
                try {
                    id = std::stoull(id_str);
                } catch (...) {
                    id = 0;
                }
            } else {
                int64_t num = 0;
                parse_json_number(line, pos, num);
                id = (uint64_t)num;
            }
        } else if (key == "method") {
            parse_json_string(line, pos, method);
        } else if (key == "params") {
            // Parse array
            if (line[pos] == '[') {
                pos++;
                while (pos < line.size() && line[pos] != ']') {
                    skip_whitespace(line, pos);
                    if (line[pos] == ',') { pos++; continue; }
                    if (line[pos] == '"') {
                        std::string param;
                        parse_json_string(line, pos, param);
                        params.push_back(param);
                    } else if (line[pos] == 'n') {
                        // null
                        params.push_back("");
                        pos += 4;
                    } else {
                        // Skip other types
                        while (pos < line.size() && line[pos] != ',' && line[pos] != ']') pos++;
                    }
                }
                if (pos < line.size()) pos++; // skip ]
            }
        } else {
            // Skip unknown value
            int depth = 0;
            bool in_string = false;
            while (pos < line.size()) {
                char c = line[pos];
                if (in_string) {
                    if (c == '\\') pos++;
                    else if (c == '"') in_string = false;
                } else {
                    if (c == '"') in_string = true;
                    else if (c == '{' || c == '[') depth++;
                    else if (c == '}' || c == ']') {
                        if (depth == 0) break;
                        depth--;
                    } else if (c == ',' && depth == 0) break;
                }
                pos++;
            }
        }
    }

    // Handle methods
    if (method == "mining.subscribe") {
        handle_subscribe(miner, id, params);
    } else if (method == "mining.authorize") {
        handle_authorize(miner, id, params);
    } else if (method == "mining.submit") {
        handle_submit(miner, id, params);
    } else if (method == "mining.extranonce.subscribe") {
        handle_extranonce_subscribe(miner, id);
    } else {
        // CRITICAL FIX: Check send_error return value
        if (!send_error(miner, id, 20, "Unknown method")) {
            miner.pending_disconnect = true;
        }
    }
}

void StratumServer::handle_subscribe(StratumMiner& miner, uint64_t id, const std::vector<std::string>& /*params*/) {
    log_info("Stratum: Received subscribe request from " + miner.ip + " id=" + std::to_string(id));

    // CRITICAL FIX: Batch all initial messages into a single send to avoid
    // WSA error 10053 on Windows when sending multiple messages rapidly on non-blocking sockets
    // We combine: subscribe_response + set_difficulty + job_notify into one buffer

    // 1. Build subscribe response
    std::ostringstream batch;
    batch << "{\"id\":" << id << ",\"result\":[[";
    batch << "[\"mining.set_difficulty\",\"" << miner.extranonce1 << "\"],";
    batch << "[\"mining.notify\",\"" << miner.extranonce1 << "\"]";
    batch << "],\"" << miner.extranonce1 << "\"," << (int)extranonce2_size_ << "],\"error\":null}\n";

    // 2. Add set_difficulty message
    batch << "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[" << miner.difficulty << "]}\n";

    // 3. Add job notify if available
    StratumJob job_copy;
    bool has_job = false;
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        if (!current_job_id_.empty() && jobs_.count(current_job_id_)) {
            job_copy = jobs_[current_job_id_];
            has_job = true;
        }
    }

    if (has_job) {
        // Build mining.notify message
        batch << "{\"id\":null,\"method\":\"mining.notify\",\"params\":[";
        batch << "\"" << job_copy.job_id << "\",";
        batch << "\"" << reverse_hex(hex_encode(job_copy.prev_hash)) << "\",";
        batch << "\"" << job_copy.coinb1 << "\",";
        batch << "\"" << job_copy.coinb2 << "\",";
        batch << "[";
        for (size_t i = 0; i < job_copy.merkle_branches.size(); i++) {
            if (i > 0) batch << ",";
            batch << "\"" << job_copy.merkle_branches[i] << "\"";
        }
        batch << "],";
        batch << "\"" << std::hex << std::setw(8) << std::setfill('0') << job_copy.version << "\",";
        batch << "\"" << std::hex << std::setw(8) << std::setfill('0') << job_copy.bits << "\",";
        batch << "\"" << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)(job_copy.time & 0xFFFFFFFF) << "\",";
        batch << std::dec << (job_copy.clean_jobs ? "true" : "false");
        batch << "]}\n";
    }

    std::string batch_str = batch.str();
    log_info("Stratum: Sending batched subscribe+difficulty+job to " + miner.ip + " (" + std::to_string(batch_str.size()) + " bytes)");

    if (!send_json(miner, batch_str)) {
        log_warn("Stratum: Failed to send batched response to " + miner.ip);
        miner.pending_disconnect = true;
        return;
    }

    miner.subscribed = true;
    log_info("Stratum: Miner subscribed from " + miner.ip + " extranonce1=" + miner.extranonce1 + (has_job ? " with job" : " (no job)"));
}

void StratumServer::handle_authorize(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params) {
    if (params.empty()) {
        // CRITICAL FIX: Check send_error return value
        if (!send_error(miner, id, 20, "Missing worker name")) {
            miner.pending_disconnect = true;
        }
        return;
    }

    miner.worker_name = params[0];
    miner.authorized = true;

    // CRITICAL FIX: Check send_result return value
    if (!send_result(miner, id, "true")) {
        log_warn("Stratum: Failed to send authorize response to " + miner.ip);
        miner.pending_disconnect = true;
        return;
    }
    log_info("Stratum: Worker authorized: " + miner.worker_name + " from " + miner.ip);

    // Copy job data while holding mutex, then send OUTSIDE mutex
    // This avoids holding jobs_mutex_ during blocking I/O
    StratumJob job_copy;
    bool should_send_job = false;
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        if (miner.subscribed && !current_job_id_.empty() && jobs_.count(current_job_id_)) {
            job_copy = jobs_[current_job_id_];
            should_send_job = true;
        }
    }

    // Send job outside the mutex
    if (should_send_job) {
        if (!send_job_to_miner(miner, job_copy)) {
            miner.pending_disconnect = true;
        }
    }
}

void StratumServer::handle_submit(StratumMiner& miner, uint64_t id, const std::vector<std::string>& params) {
    if (!miner.authorized) {
        // CRITICAL FIX: Check send_error return value
        if (!send_error(miner, id, 24, "Not authorized")) {
            miner.pending_disconnect = true;
        }
        return;
    }

    // params: [worker_name, job_id, extranonce2, ntime, nonce]
    if (params.size() < 5) {
        // CRITICAL FIX: Check send_error return value
        if (!send_error(miner, id, 20, "Invalid params")) {
            miner.pending_disconnect = true;
        }
        return;
    }

    const std::string& job_id = params[1];
    const std::string& extranonce2 = params[2];
    const std::string& ntime = params[3];
    const std::string& nonce = params[4];

    std::string error;
    bool valid = validate_share(miner, job_id, extranonce2, ntime, nonce, error);

    miner.shares_submitted++;
    miner.last_share_ms = now_ms();
    miner.vardiff_shares_since_adjust++;

    {
        std::lock_guard<std::mutex> lock(stats_mutex_);
        stats_.total_shares++;
    }

    if (valid) {
        miner.shares_accepted++;
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.accepted_shares++;
        }
        // CRITICAL FIX: Check send status and mark miner for disconnect on failure
        if (!send_result(miner, id, "true")) {
            miner.pending_disconnect = true;
        }
    } else {
        miner.shares_rejected++;
        {
            std::lock_guard<std::mutex> lock(stats_mutex_);
            stats_.rejected_shares++;
        }
        // CRITICAL FIX: Check send status and mark miner for disconnect on failure
        if (!send_error(miner, id, 21, error)) {
            miner.pending_disconnect = true;
        }
    }
}

void StratumServer::handle_extranonce_subscribe(StratumMiner& miner, uint64_t id) {
    // CRITICAL FIX: Check send_result return value
    if (!send_result(miner, id, "true")) {
        miner.pending_disconnect = true;
    }
}

bool StratumServer::validate_share(StratumMiner& miner, const std::string& job_id,
                                    const std::string& extranonce2, const std::string& ntime,
                                    const std::string& nonce, std::string& error) {
    // Find job
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    auto it = jobs_.find(job_id);
    if (it == jobs_.end()) {
        error = "Job not found";
        return false;
    }

    const StratumJob& job = it->second;

    // Validate extranonce2 length
    if (extranonce2.length() != extranonce2_size_ * 2) {
        error = "Invalid extranonce2 size";
        return false;
    }

    // CRITICAL FIX: Validate extranonce2 is valid hex
    for (char c : extranonce2) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            error = "Invalid extranonce2 format (not hex)";
            return false;
        }
    }

    // Build coinbase
    std::string coinbase_hex = job.coinb1 + miner.extranonce1 + extranonce2 + job.coinb2;
    std::vector<uint8_t> coinbase = hex_decode(coinbase_hex);

    // CRITICAL FIX: Validate hex decode succeeded
    if (coinbase.empty() && !coinbase_hex.empty()) {
        error = "Invalid coinbase hex";
        return false;
    }

    // Calculate coinbase hash
    auto coinbase_hash = dsha256(coinbase);

    // CRITICAL FIX: Validate coinbase hash is 32 bytes
    if (coinbase_hash.size() != 32) {
        error = "Invalid coinbase hash size";
        return false;
    }

    // Build merkle root
    std::vector<uint8_t> merkle_root = coinbase_hash;
    for (const auto& branch : job.merkle_branches) {
        // CRITICAL FIX: Validate merkle root is exactly 32 bytes
        if (merkle_root.size() != 32) {
            error = "Invalid merkle root size";
            return false;
        }

        auto branch_bytes = hex_decode(branch);
        // CRITICAL FIX: Validate branch is exactly 32 bytes
        if (branch_bytes.size() != 32) {
            error = "Invalid merkle branch size";
            return false;
        }

        std::vector<uint8_t> combined;
        combined.reserve(64); // Reserve space for two 32-byte hashes
        combined.insert(combined.end(), merkle_root.begin(), merkle_root.end());
        combined.insert(combined.end(), branch_bytes.begin(), branch_bytes.end());
        merkle_root = dsha256(combined);
    }

    // Build header (88 bytes - MIQ uses 8-byte time and 8-byte nonce)
    std::vector<uint8_t> header;
    header.reserve(88);

    // Version (4 bytes, little-endian)
    uint32_t ver = job.version;
    header.push_back((ver >> 0) & 0xff);
    header.push_back((ver >> 8) & 0xff);
    header.push_back((ver >> 16) & 0xff);
    header.push_back((ver >> 24) & 0xff);

    // Prev hash (32 bytes)
    if (!job.prev_hash.empty()) {
        header.insert(header.end(), job.prev_hash.begin(), job.prev_hash.end());
    }

    // Merkle root (32 bytes)
    if (!merkle_root.empty()) {
        header.insert(header.end(), merkle_root.begin(), merkle_root.end());
    }

    // Time (8 bytes, little-endian) - MIQ uses 8-byte timestamps
    // STRATUM COMPAT FIX: Accept both 8-char (32-bit) and 16-char (64-bit) ntime
    // For 8-char ntime, use the job's original 64-bit time (we sent truncated value)
    uint64_t time_val;
    try {
        if (ntime.length() <= 8) {
            // Standard miner sent 32-bit ntime back - use job's original 64-bit time
            // The miner can only modify lower 32 bits anyway
            time_val = job.time;
        } else {
            // Custom miner sent full 64-bit ntime
            time_val = std::stoull(ntime, nullptr, 16);
        }
    } catch (...) {
        error = "Invalid ntime format";
        return false;
    }
    for (int i = 0; i < 8; i++) {
        header.push_back((time_val >> (8 * i)) & 0xff);
    }

    // Bits (4 bytes, little-endian)
    uint32_t bits = job.bits;
    header.push_back((bits >> 0) & 0xff);
    header.push_back((bits >> 8) & 0xff);
    header.push_back((bits >> 16) & 0xff);
    header.push_back((bits >> 24) & 0xff);

    // Nonce (8 bytes, little-endian) - MIQ uses 8-byte nonces
    // STRATUM COMPAT FIX: Accept both 8-char (32-bit) and 16-char (64-bit) nonces
    // For 8-char nonce, pad upper 32 bits with zeros
    uint64_t nonce_val;
    try {
        nonce_val = std::stoull(nonce, nullptr, 16);
        // If nonce is 8 chars or less, it's a 32-bit value - upper bits are zero (already handled by stoull)
    } catch (...) {
        error = "Invalid nonce format";
        return false;
    }
    for (int i = 0; i < 8; i++) {
        header.push_back((nonce_val >> (8 * i)) & 0xff);
    }

    // Hash header
    auto header_hash = dsha256(header);

    // Check against share difficulty
    if (!check_pow(header_hash, job.bits, miner.difficulty)) {
        error = "Share difficulty too low";
        return false;
    }

    // Check if meets block target
    if (check_pow(header_hash, job.bits, 1.0)) {
        // Block found!
        log_info("Stratum: BLOCK FOUND by " + miner.worker_name + "!");

        // Build the full block and submit to chain
        try {
            // CRITICAL FIX: Deserialize the actual coinbase bytes that were used
            // to compute the merkle root, instead of creating a new empty coinbase.
            // The merkle_root was computed from dsha256(coinbase) where coinbase
            // includes the extranonce as the "sig" field. If we create a new coinbase
            // with empty sig, the txid won't match and merkle verification will fail.
            Transaction coinbase_tx;
            if (!deser_tx(coinbase, coinbase_tx)) {
                log_error("Stratum: Failed to deserialize coinbase for block submission");
                error = "coinbase deser failed";
                return false;
            }

            // Build block
            Block block;
            block.header.version = job.version;
            block.header.prev_hash = job.prev_hash;
            block.header.merkle_root = merkle_root;
            block.header.time = time_val;
            block.header.bits = bits;
            block.header.nonce = nonce_val;
            block.txs.push_back(coinbase_tx);

            // PRODUCTION FIX: Add mempool transactions from the job
            for (const auto& tx : job.mempool_txs) {
                block.txs.push_back(tx);
            }

            // CRITICAL DEBUG: Log exactly how many transactions are being submitted
            log_info("Stratum: Submitting block " + std::to_string(job.height) +
                     " with " + std::to_string(block.txs.size()) + " txs (1 coinbase + " +
                     std::to_string(job.mempool_txs.size()) + " mempool)");

            // Submit to chain
            std::string submit_err;
            if (chain_.submit_block(block, submit_err)) {
                // CRITICAL FIX: Notify mempool and promote orphan TXs
                mempool_.on_block_connect(block, chain_.utxo(), (uint32_t)chain_.height());
                log_info("Stratum: Block " + std::to_string(job.height) + " accepted with " +
                         std::to_string(block.txs.size() - 1) + " transactions!");
                {
                    std::lock_guard<std::mutex> stats_lock(stats_mutex_);
                    stats_.blocks_found++;
                }
            } else {
                log_error("Stratum: Block " + std::to_string(job.height) + " rejected: " + submit_err);
            }
        } catch (const std::exception& e) {
            log_error("Stratum: Failed to build/submit block: " + std::string(e.what()));
        }
    }

    return true;
}

bool StratumServer::check_pow(const std::vector<uint8_t>& header_hash, uint32_t bits, double difficulty) {
    // Calculate target from bits (compact format)
    uint32_t exp = bits >> 24;
    uint32_t mant = bits & 0x007fffff;

    // Expand compact target to 256-bit
    std::vector<uint8_t> target(32, 0);
    if (exp <= 3) {
        uint32_t val = mant >> (8 * (3 - exp));
        target[0] = val & 0xff;
        if (exp >= 1) target[1] = (val >> 8) & 0xff;
        if (exp >= 2) target[2] = (val >> 16) & 0xff;
    } else {
        size_t offset = exp - 3;
        if (offset < 32) {
            target[offset] = mant & 0xff;
            if (offset + 1 < 32) target[offset + 1] = (mant >> 8) & 0xff;
            if (offset + 2 < 32) target[offset + 2] = (mant >> 16) & 0xff;
        }
    }

    // Scale target by difficulty factor (share_target = network_target / difficulty)
    // For share validation, we allow hashes up to target/difficulty
    // So we compare: hash < target / difficulty

    // CRITICAL FIX: Proper 256-bit division by difficulty using long division
    // The previous log2 truncation lost precision for difficulties like 1.5
    if (difficulty > 1.0) {
        // Convert target to 256-bit integer, divide by difficulty, convert back
        // Use double precision for reasonable accuracy up to difficulty ~2^52
        std::vector<uint8_t> scaled_target(32, 0);

        // Process in 64-bit chunks from most significant to least significant
        // We accumulate a remainder as we go (standard long division)
        double remainder = 0.0;
        for (int i = 31; i >= 0; i--) {
            // Bring down the next byte
            double value = remainder * 256.0 + target[i];
            // Divide by difficulty
            double quotient = std::floor(value / difficulty);
            remainder = value - quotient * difficulty;
            // Clamp to byte range (should always be 0-255 but be safe)
            if (quotient > 255.0) quotient = 255.0;
            if (quotient < 0.0) quotient = 0.0;
            scaled_target[i] = (uint8_t)quotient;
        }
        target = scaled_target;
    }

    // Compare hash < target (both in little-endian)
    // Hash bytes are already little-endian, compare from high byte to low
    for (int i = 31; i >= 0; i--) {
        if (header_hash[i] < target[i]) return true;
        if (header_hash[i] > target[i]) return false;
    }
    return true; // Equal, accept
}

StratumJob StratumServer::create_job() {
    StratumJob job;

    auto tip = chain_.tip();

    job.job_id = generate_job_id();
    job.prev_hash = tip.hash;
    job.version = 1;

    // CRITICAL FIX: Calculate proper next block difficulty (retarget-aware)
    // Using tip.bits directly is wrong at difficulty adjustment boundaries
    uint32_t next_bits = tip.bits;
    try {
        auto last = chain_.last_headers(MIQ_RETARGET_INTERVAL);
        next_bits = miq::epoch_next_bits(
            last,
            BLOCK_TIME_SECS,
            GENESIS_BITS,
            tip.height + 1,
            MIQ_RETARGET_INTERVAL
        );
    } catch (const std::exception& e) {
        log_error(std::string("Stratum: epoch_next_bits failed: ") + e.what());
        // Fall back to tip.bits on error
    } catch (...) {
        log_error("Stratum: epoch_next_bits failed with unknown error");
    }
    job.bits = next_bits;

    job.time = (uint64_t)std::time(nullptr);  // MIQ uses 64-bit timestamps
    job.height = tip.height + 1;
    job.clean_jobs = true;

    // V1 FIX: Use collect_for_block with proper size limit instead of count limit
    // This ensures we collect transactions up to block size limit, not arbitrary count
    static constexpr size_t COINBASE_RESERVED_SIZE = 1024;
    static constexpr size_t BLOCK_TX_SIZE_LIMIT = MAX_BLOCK_SIZE - COINBASE_RESERVED_SIZE;
    mempool_.collect_for_block(job.mempool_txs, BLOCK_TX_SIZE_LIMIT);
    job.total_fees = 0;

    for (const auto& tx : job.mempool_txs) {
        uint64_t in_sum = 0, out_sum = 0;

        // V1 FIX: Check mempool for parent transactions first (for chained tx fee calculation)
        for (const auto& in : tx.vin) {
            // First check if parent is in mempool (for chained transactions)
            Transaction parent_tx;
            if (mempool_.get_transaction(in.prev.txid, parent_tx)) {
                if (in.prev.vout < parent_tx.vout.size()) {
                    in_sum += parent_tx.vout[in.prev.vout].value;
                    continue;
                }
            }
            // Fallback to UTXO set
            UTXOEntry e;
            if (chain_.utxo().get(in.prev.txid, in.prev.vout, e)) {
                in_sum += e.value;
            }
        }

        // Calculate output sum
        for (const auto& o : tx.vout) {
            out_sum += o.value;
        }

        // Fee = inputs - outputs (positive value)
        if (in_sum > out_sum) {
            job.total_fees += (in_sum - out_sum);
        }
    }

    // Calculate subsidy
    uint64_t subsidy = INITIAL_SUBSIDY;
    uint64_t halvings = job.height / HALVING_INTERVAL;
    if (halvings < 64) subsidy = INITIAL_SUBSIDY >> halvings;
    else subsidy = 0;

    // Build coinbase parts using MIQ's transaction serialization format
    // Format: version(4) + input_count(4) + [txid_len(4) + txid + vout(4) + sig_len(4) + sig + pubkey_len(4) + pubkey]
    //         + output_count(4) + [value(8) + pkh_len(4) + pkh] + lock_time(4)

    // Helper lambda for little-endian u32
    auto put_u32_le = [](std::vector<uint8_t>& v, uint32_t x) {
        v.push_back((x >> 0) & 0xff);
        v.push_back((x >> 8) & 0xff);
        v.push_back((x >> 16) & 0xff);
        v.push_back((x >> 24) & 0xff);
    };

    // Helper lambda for little-endian u64
    auto put_u64_le = [](std::vector<uint8_t>& v, uint64_t x) {
        for (int i = 0; i < 8; i++) {
            v.push_back((x >> (8 * i)) & 0xff);
        }
    };

    // CRITICAL FIX: Proper coinbase construction for MIQ stratum
    // MIQ transaction format:
    // version(4) + input_count(4) + [txid_len(4) + txid(32) + vout(4) + sig_len(4) + sig + pubkey_len(4) + pubkey]
    //            + output_count(4) + [value(8) + pkh_len(4) + pkh] + lock_time(4)
    //
    // For stratum:
    // coinb1 = version + input_count + txid_len + txid + vout + sig_len
    // [extranonce1 + extranonce2 inserted here as the sig data]
    // coinb2 = pubkey_len + pubkey + output_count + outputs + lock_time

    uint32_t total_extranonce_size = EXTRANONCE1_SIZE + extranonce2_size_;

    std::vector<uint8_t> coinb1_bytes;
    put_u32_le(coinb1_bytes, 1);  // version
    put_u32_le(coinb1_bytes, 1);  // input count
    put_u32_le(coinb1_bytes, 32); // prev.txid length
    for (int i = 0; i < 32; i++) coinb1_bytes.push_back(0); // prev.txid (zeros for coinbase)
    put_u32_le(coinb1_bytes, 0);  // prev.vout (0 for coinbase)
    // CRITICAL FIX: sig_len must equal the extranonce size so the miner's extranonce becomes the sig
    put_u32_le(coinb1_bytes, total_extranonce_size);  // sig length = extranonce1 + extranonce2 bytes

    job.coinb1 = hex_encode(coinb1_bytes);

    // coinb2: pubkey_len + pubkey + outputs + lock_time
    // The extranonce (sig data) was already accounted for in coinb1's sig_len
    std::vector<uint8_t> coinb2_bytes;
    put_u32_le(coinb2_bytes, 0);  // pubkey length (no pubkey for coinbase)

    put_u32_le(coinb2_bytes, 1);  // output count
    // PRODUCTION FIX: Include fees in coinbase value (subsidy + fees)
    uint64_t coinbase_value = subsidy + job.total_fees;
    put_u64_le(coinb2_bytes, coinbase_value);
    put_u32_le(coinb2_bytes, 20); // pkh length

    // PKH
    if (reward_pkh_.size() == 20) {
        coinb2_bytes.insert(coinb2_bytes.end(), reward_pkh_.begin(), reward_pkh_.end());
    } else {
        for (int i = 0; i < 20; i++) coinb2_bytes.push_back(0);
    }

    put_u32_le(coinb2_bytes, 0);  // lock_time

    job.coinb2 = hex_encode(coinb2_bytes);

    // PRODUCTION FIX: Compute merkle branches from mempool transactions
    // CRITICAL FIX: Correct merkle branch algorithm for stratum protocol
    // Each branch[i] is the sibling hash needed at level i to compute merkle root
    job.merkle_branches.clear();
    if (!job.mempool_txs.empty()) {
        // Compute tx hashes (these are siblings of coinbase path at level 0)
        std::vector<std::vector<uint8_t>> tx_hashes;
        for (const auto& tx : job.mempool_txs) {
            tx_hashes.push_back(tx.txid());
        }

        log_info("Stratum: Job created with " + std::to_string(job.mempool_txs.size()) +
                 " mempool txs for height " + std::to_string(job.height));

        // Build merkle branches for stratum (coinbase is at index 0)
        // Algorithm: At each level, first hash is the sibling, then remove it
        // and pair up remaining hashes for the next level
        while (!tx_hashes.empty()) {
            // First hash is always the sibling at this level
            job.merkle_branches.push_back(hex_encode(tx_hashes[0]));

            if (tx_hashes.size() == 1) {
                // Only one element left, we're done
                break;
            }

            // CRITICAL FIX: Remove the first element BEFORE computing next level
            // The first element was the sibling of our path, now we need to compute
            // what the sibling subtree hashes to at the next level
            tx_hashes.erase(tx_hashes.begin());

            // Pair up remaining elements for next level
            std::vector<std::vector<uint8_t>> next_level;
            for (size_t i = 0; i < tx_hashes.size(); i += 2) {
                std::vector<uint8_t> combined;
                combined.reserve(64);
                combined.insert(combined.end(), tx_hashes[i].begin(), tx_hashes[i].end());
                if (i + 1 < tx_hashes.size()) {
                    // Two elements to combine
                    combined.insert(combined.end(), tx_hashes[i+1].begin(), tx_hashes[i+1].end());
                } else {
                    // Odd element - duplicate for merkle tree
                    combined.insert(combined.end(), tx_hashes[i].begin(), tx_hashes[i].end());
                }
                next_level.push_back(dsha256(combined));
            }
            tx_hashes = std::move(next_level);
        }
    }

    return job;
}

void StratumServer::broadcast_job(const StratumJob& job) {
    // CRITICAL FIX: Track miners with failed sends to disconnect them after iteration
    // This prevents a single broken miner from blocking broadcasts to others
    std::vector<StratumSock> failed_miners;

    {
        std::lock_guard<std::mutex> lock(miners_mutex_);
        for (auto& kv : miners_) {
            if (kv.second.subscribed) {
                if (!send_job_to_miner(kv.second, job)) {
                    failed_miners.push_back(kv.first);
                }
            }
        }
    }

    // Disconnect failed miners outside of the loop to avoid iterator invalidation
    for (StratumSock sock : failed_miners) {
        disconnect_miner(sock, "broadcast send failed");
    }
}

bool StratumServer::send_job_to_miner(StratumMiner& miner, const StratumJob& job) {
    // mining.notify params:
    // [job_id, prev_hash, coinb1, coinb2, merkle_branches[], version, nbits, ntime, clean_jobs]

    std::ostringstream ss;
    ss << "{\"id\":null,\"method\":\"mining.notify\",\"params\":[";
    ss << "\"" << job.job_id << "\",";
    ss << "\"" << reverse_hex(hex_encode(job.prev_hash)) << "\",";
    ss << "\"" << job.coinb1 << "\",";
    ss << "\"" << job.coinb2 << "\",";
    ss << "[";
    for (size_t i = 0; i < job.merkle_branches.size(); i++) {
        if (i > 0) ss << ",";
        ss << "\"" << job.merkle_branches[i] << "\"";
    }
    ss << "],";
    ss << "\"" << std::hex << std::setw(8) << std::setfill('0') << job.version << "\",";
    ss << "\"" << std::hex << std::setw(8) << std::setfill('0') << job.bits << "\",";
    // STRATUM COMPAT FIX: Send ntime as 8 hex chars (32-bit) for standard miner compatibility
    // MIQ internally uses 64-bit time but standard stratum protocol expects 32-bit
    // The miner will send back 8 chars which we'll handle in validate_share
    ss << "\"" << std::hex << std::setw(8) << std::setfill('0') << (uint32_t)(job.time & 0xFFFFFFFF) << "\",";
    ss << (job.clean_jobs ? "true" : "false");
    ss << "]}\n";

    std::string json_msg = ss.str();
    log_info("Stratum: Sending mining.notify to " + miner.ip + " (" + std::to_string(json_msg.size()) + " bytes)");

    // CRITICAL FIX: Return send status so broadcast_job can track failures
    bool result = send_json(miner, json_msg);
    if (!result) {
        log_warn("Stratum: send_json failed for mining.notify to " + miner.ip);
    }
    return result;
}

void StratumServer::cleanup_old_jobs() {
    std::lock_guard<std::mutex> lock(jobs_mutex_);
    while (job_order_.size() > 10) {
        jobs_.erase(job_order_.front());
        job_order_.pop_front();
    }
}

void StratumServer::update_vardiff(StratumMiner& miner) {
    int64_t now = now_ms();
    int64_t elapsed = now - miner.vardiff_last_adjust_ms;

    if (elapsed < 30000 || miner.vardiff_shares_since_adjust < 5) {
        return; // Need more data
    }

    // Calculate actual share rate
    double actual_rate = (double)miner.vardiff_shares_since_adjust / (elapsed / 1000.0);
    double target_rate = 1.0 / vardiff_target_secs_;

    // Adjust difficulty
    double ratio = actual_rate / target_rate;
    double new_diff = miner.difficulty * ratio;

    // Clamp to limits
    new_diff = (std::max)(min_difficulty_, (std::min)(max_difficulty_, new_diff));

    // Only change if significant (>10% change)
    if (std::abs(new_diff - miner.difficulty) / miner.difficulty > 0.1) {
        miner.difficulty = new_diff;
        // CRITICAL FIX: Check send_set_difficulty return value
        if (!send_set_difficulty(miner, new_diff)) {
            miner.pending_disconnect = true;
            return;
        }
    }

    miner.vardiff_last_adjust_ms = now;
    miner.vardiff_shares_since_adjust = 0;
}

bool StratumServer::send_set_difficulty(StratumMiner& miner, double difficulty) {
    std::ostringstream ss;
    ss << "{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[" << difficulty << "]}\n";
    return send_json(miner, ss.str());
}

void StratumServer::disconnect_miner(StratumSock sock, const std::string& reason) {
    auto it = miners_.find(sock);
    if (it != miners_.end()) {
        log_info("Stratum: Disconnecting " + it->second.ip + ": " + reason);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        miners_.erase(it);
    }
}

bool StratumServer::send_json(StratumMiner& miner, const std::string& json) {
    size_t total_sent = 0;
    size_t remaining = json.size();
    const char* data = json.c_str();

    // CRITICAL FIX: Use proper socket write-readiness checking via select()
    // instead of blind retries. This is more robust on Windows.
    static constexpr int MAX_SEND_TIMEOUT_MS = 2000;  // 2 second total timeout
    auto start_time = std::chrono::steady_clock::now();

    while (remaining > 0) {
        // Check if we've exceeded timeout
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();
        if (elapsed > MAX_SEND_TIMEOUT_MS) {
            log_warn("Stratum: send_json timeout after " + std::to_string(elapsed) + "ms to " + miner.ip);
            return false;
        }

#ifdef _WIN32
        int sent = send(miner.sock, data + total_sent, (int)remaining, 0);
        if (sent == SOCKET_ERROR) {
            int err = WSAGetLastError();
            if (err == WSAEWOULDBLOCK) {
                // Use select() to wait for socket to be writable
                fd_set write_fds;
                FD_ZERO(&write_fds);
                FD_SET(miner.sock, &write_fds);
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 50000;  // 50ms wait
                int sel_result = select(0, nullptr, &write_fds, nullptr, &tv);
                if (sel_result < 0) {
                    log_warn("Stratum: select failed for " + miner.ip + " WSA error=" + std::to_string(WSAGetLastError()));
                    return false;
                }
                // If select returned 0 (timeout) or >0 (ready), retry send
                continue;
            }
            log_warn("Stratum: send_json failed to " + miner.ip + " WSA error=" + std::to_string(err));
            return false;
        }
#else
        ssize_t sent = send(miner.sock, data + total_sent, remaining, 0);
        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Use poll() to wait for socket to be writable
                struct pollfd pfd;
                pfd.fd = miner.sock;
                pfd.events = POLLOUT;
                int poll_result = poll(&pfd, 1, 50);  // 50ms wait
                if (poll_result < 0) {
                    log_warn("Stratum: poll failed for " + miner.ip + " errno=" + std::to_string(errno));
                    return false;
                }
                // If poll returned 0 (timeout) or >0 (ready), retry send
                continue;
            }
            log_warn("Stratum: send_json failed to " + miner.ip + " errno=" + std::to_string(errno) +
                     " (" + std::string(strerror(errno)) + ")");
            return false;
        }
#endif
        if (sent == 0) {
            log_warn("Stratum: send_json connection closed by " + miner.ip);
            return false;
        }
        total_sent += sent;
        remaining -= sent;
    }
    return true;
}

bool StratumServer::send_result(StratumMiner& miner, uint64_t id, const std::string& result) {
    std::ostringstream ss;
    ss << "{\"id\":" << id << ",\"result\":" << result << ",\"error\":null}\n";
    // CRITICAL FIX: Return send status so caller can disconnect on failure
    return send_json(miner, ss.str());
}

bool StratumServer::send_error(StratumMiner& miner, uint64_t id, int code, const std::string& message) {
    std::ostringstream ss;
    ss << "{\"id\":" << id << ",\"result\":null,\"error\":[" << code << ",\"" << json_escape(message) << "\",null]}\n";
    // CRITICAL FIX: Return send status so caller can disconnect on failure
    return send_json(miner, ss.str());
}

std::string StratumServer::generate_extranonce1() {
    uint32_t val = extranonce_counter_++;
    std::ostringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << val;
    return ss.str();
}

std::string StratumServer::generate_job_id() {
    std::ostringstream ss;
    ss << std::hex << job_counter_++;
    return ss.str();
}

void StratumServer::notify_new_block() {
    auto job = create_job();
    job.clean_jobs = true;
    {
        std::lock_guard<std::mutex> lock(jobs_mutex_);
        jobs_[job.job_id] = job;
        job_order_.push_back(job.job_id);
        current_job_id_ = job.job_id;
    }
    broadcast_job(job);
}

PoolStats StratumServer::get_stats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    PoolStats stats = stats_;
    {
        std::lock_guard<std::mutex> mlock(miners_mutex_);
        stats.connected_miners = miners_.size();
    }
    return stats;
}

size_t StratumServer::miner_count() const {
    std::lock_guard<std::mutex> lock(miners_mutex_);
    return miners_.size();
}

}
