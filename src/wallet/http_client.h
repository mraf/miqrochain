#pragma once
#include <string>
#include <vector>
#include <map>
#include <cstdint>

namespace miq {

struct HttpResponse {
    int code{0};
    std::string body;
    std::map<std::string,std::string> headers; // lowercased keys
};

bool http_post(const std::string& host,
               uint16_t port,
               const std::string& path,
               const std::string& body,
               const std::vector<std::pair<std::string,std::string>>& headers,
               HttpResponse& out,
               int timeout_ms = 5000);

}
