#include "node_client.h"
#include "http_client.h"
#include "log.h"
#include "constants.h"

#include <sstream>
#include <thread>
#include <chrono>
#include <algorithm>
#include <atomic>

namespace miq {

// =============================================================================
// BULLETPROOF NODE CLIENT v1.0 - Production-grade RPC with robust error handling
// =============================================================================

// Configuration constants for retry behavior
static constexpr int MAX_RETRIES_PER_ENDPOINT = 3;
static constexpr int BASE_BACKOFF_MS = 100;
static constexpr int MAX_BACKOFF_MS = 2000;
static constexpr int CIRCUIT_BREAKER_THRESHOLD = 5;  // consecutive failures before temporary disable
static constexpr int CIRCUIT_BREAKER_RESET_MS = 30000;  // 30 seconds

// Thread-safe endpoint health tracking
struct EndpointHealth {
    std::atomic<int> consecutive_failures{0};
    std::atomic<int64_t> last_failure_time{0};
    std::atomic<int64_t> last_success_time{0};
    std::atomic<int64_t> total_calls{0};
    std::atomic<int64_t> successful_calls{0};

    bool is_healthy() const {
        if (consecutive_failures.load() >= CIRCUIT_BREAKER_THRESHOLD) {
            // Check if we should reset the circuit breaker
            int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            if (now - last_failure_time.load() < CIRCUIT_BREAKER_RESET_MS) {
                return false;  // Still in backoff period
            }
        }
        return true;
    }

    void record_success() {
        consecutive_failures.store(0);
        last_success_time.store(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        total_calls.fetch_add(1);
        successful_calls.fetch_add(1);
    }

    void record_failure() {
        consecutive_failures.fetch_add(1);
        last_failure_time.store(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
        total_calls.fetch_add(1);
    }
};

// Global health tracker (per endpoint by host:port)
static std::map<std::string, EndpointHealth> g_endpoint_health;
static std::mutex g_health_mutex;

static EndpointHealth& get_endpoint_health(const std::string& host, uint16_t port) {
    std::string key = host + ":" + std::to_string(port);
    std::lock_guard<std::mutex> lk(g_health_mutex);
    return g_endpoint_health[key];
}

NodeClient NodeClient::Auto(const std::string& datadir, int timeout_ms){
    auto eps = discover_nodes(datadir, timeout_ms);
    return NodeClient(std::move(eps), timeout_ms);
}

NodeClient::NodeClient(std::vector<NodeEndpoint> endpoints, int timeout_ms)
: eps_(std::move(endpoints)), timeout_ms_(timeout_ms)
{
    if(eps_.empty()){
        // Default endpoints with fallback chain
        eps_.push_back(NodeEndpoint{"62.38.73.147", (uint16_t)9834, std::string(), -1});
        eps_.push_back(NodeEndpoint{"127.0.0.1", (uint16_t)RPC_PORT, std::string(), -1});
    }
}

NodeEndpoint NodeClient::current() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return eps_[cursor_ % eps_.size()];
}

// IMPROVED: Single call with detailed error reporting
bool NodeClient::call_once(size_t idx, const std::string& body, JNode& out, std::string& err){
    if (idx >= eps_.size()) {
        err = "invalid endpoint index";
        return false;
    }

    const auto& ep = eps_[idx];
    auto& health = get_endpoint_health(ep.host, ep.port);

    // Check circuit breaker before attempting call
    if (!health.is_healthy()) {
        err = "endpoint temporarily disabled (circuit breaker open)";
        return false;
    }

    std::vector<std::pair<std::string,std::string>> hdrs;
    if(!ep.token.empty()){
        hdrs.emplace_back("X-Auth-Token", ep.token);
    }

    HttpResponse r;
    if(!http_post(ep.host, ep.port, "/", body, hdrs, r, timeout_ms_)){
        health.record_failure();
        err = "connect failed to " + ep.host + ":" + std::to_string(ep.port);
        return false;
    }

    // Handle HTTP errors
    if(r.code == 401 || r.code == 403){
        health.record_failure();
        err = "unauthorized (check RPC token)";
        return false;
    }
    if(r.code == 500 || r.code == 502 || r.code == 503 || r.code == 504){
        health.record_failure();
        err = "server error (HTTP " + std::to_string(r.code) + ")";
        return false;
    }
    if(r.code != 200){
        health.record_failure();
        std::ostringstream s;
        s << "unexpected HTTP " << r.code;
        err = s.str();
        return false;
    }

    // Parse JSON response
    JNode resp;
    if(!json_parse(r.body, resp)){
        health.record_failure();
        err = "malformed JSON response";
        return false;
    }

    // Check for RPC-level errors in response
    if (auto* obj = std::get_if<std::map<std::string, JNode>>(&resp.v)) {
        auto it = obj->find("error");
        if (it != obj->end()) {
            if (auto* errObj = std::get_if<std::map<std::string, JNode>>(&it->second.v)) {
                auto msgIt = errObj->find("message");
                if (msgIt != errObj->end()) {
                    if (auto* msgStr = std::get_if<std::string>(&msgIt->second.v)) {
                        health.record_failure();
                        err = "RPC error: " + *msgStr;
                        return false;
                    }
                }
            }
            health.record_failure();
            err = "RPC error in response";
            return false;
        }
    }

    health.record_success();
    out = std::move(resp);
    return true;
}

// IMPROVED: Main call method with exponential backoff retry and endpoint rotation
bool NodeClient::call(const std::string& method,
                      const std::vector<JNode>& params,
                      JNode& out,
                      std::string& err)
{
    // Build JSON-RPC request
    std::map<std::string,JNode> o;
    o["method"].v = std::string(method);
    if(!params.empty()){
        JNode p;
        p.v = params;
        o["params"] = p;
    }
    JNode req;
    req.v = o;
    std::string body = json_dump(req);

    size_t N = eps_.size();
    if (N == 0) {
        err = "no endpoints configured";
        return false;
    }

    // Get starting cursor position
    size_t start;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        start = cursor_ % N;
        cursor_ = (cursor_ + 1) % N;
    }

    std::string last_error;
    int total_attempts = 0;

    // Try each endpoint with retries and exponential backoff
    for(size_t i = 0; i < N; i++){
        size_t idx = (start + i) % N;
        const auto& ep = eps_[idx];

        // Skip unhealthy endpoints (unless it's our only option)
        auto& health = get_endpoint_health(ep.host, ep.port);
        if (!health.is_healthy() && i < N - 1) {
            continue;  // Try next endpoint
        }

        // Retry loop with exponential backoff
        for(int retry = 0; retry < MAX_RETRIES_PER_ENDPOINT; retry++){
            total_attempts++;

            JNode tmp;
            std::string e;
            if(call_once(idx, body, tmp, e)){
                out = std::move(tmp);
                err.clear();
                return true;  // SUCCESS!
            }

            last_error = e;

            // Don't retry for certain errors
            if (e.find("unauthorized") != std::string::npos ||
                e.find("circuit breaker") != std::string::npos) {
                break;  // Move to next endpoint
            }

            // Exponential backoff before retry (if not last retry)
            if (retry < MAX_RETRIES_PER_ENDPOINT - 1) {
                int backoff = std::min(BASE_BACKOFF_MS * (1 << retry), MAX_BACKOFF_MS);
                std::this_thread::sleep_for(std::chrono::milliseconds(backoff));
            }
        }

        // Log failure for this endpoint
        log_warn("RPC [" + method + "] to " + ep.host + ":" + std::to_string(ep.port) +
                 " failed after retries: " + last_error);
    }

    err = "all " + std::to_string(total_attempts) + " attempts failed: " + last_error;
    return false;
}

bool NodeClient::call_str(const std::string& method,
                          const std::vector<JNode>& params,
                          std::string& out_str,
                          std::string& err)
{
    JNode r;
    if(!call(method, params, r, err)) return false;
    out_str = json_dump(r);
    return true;
}

// NEW: Health check method to verify endpoint connectivity
bool NodeClient::health_check(std::string& status) {
    JNode out;
    std::string err;

    // Try a lightweight RPC call to check connectivity
    std::vector<JNode> params;
    if (call("getinfo", params, out, err)) {
        status = "healthy";
        return true;
    }

    status = "unhealthy: " + err;
    return false;
}

// NEW: Get endpoint statistics for debugging
std::vector<std::pair<std::string, std::string>> NodeClient::get_endpoint_stats() const {
    std::vector<std::pair<std::string, std::string>> stats;
    std::lock_guard<std::mutex> lk(mtx_);

    for (const auto& ep : eps_) {
        std::string key = ep.host + ":" + std::to_string(ep.port);
        auto& health = get_endpoint_health(ep.host, ep.port);

        std::ostringstream ss;
        ss << "calls=" << health.total_calls.load()
           << " success=" << health.successful_calls.load()
           << " failures=" << health.consecutive_failures.load()
           << " healthy=" << (health.is_healthy() ? "yes" : "no");

        stats.emplace_back(key, ss.str());
    }
    return stats;
}

}
