#pragma once
#include <string>
#include <functional>
#include <atomic>
#include <cstdint>

namespace miq {

class HttpServer {
public:
    // Starts a tiny HTTP server that accepts JSON bodies and returns JSON strings.
    // on_json is called with the request body and should return a JSON string.
    void start(uint16_t port, std::function<std::string(const std::string&)> on_json);
    void stop();
private:
    std::atomic<bool> running_{false};
};

}
