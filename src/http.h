#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <cstdint>
#include <vector>
#include <utility>

namespace miq {

class HttpServer {
public:
    // Back-compat: existing signature (ignores headers)
    // on_json is called with the request body and should return a JSON string.
    void start(uint16_t port, std::function<std::string(const std::string&)> on_json);

    // NEW: headers-aware variant. You get the raw headers as (name,value) pairs.
    // Names are as-received (not lowercased); normalize if you need.
    void start(uint16_t port,
               std::function<std::string(
                   const std::string&,
                   const std::vector<std::pair<std::string,std::string>>&)> on_json);

    void stop();
private:
    std::atomic<bool> running_{false};
};

}
