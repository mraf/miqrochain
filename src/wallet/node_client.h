#pragma once
#include "node_discovery.h"
#include "serialize.h"   // JNode/json_parse/json_dump
#include <string>
#include <vector>
#include <mutex>

namespace miq {

class NodeClient {
public:
    static NodeClient Auto(const std::string& datadir, int timeout_ms = 3000);
    explicit NodeClient(std::vector<NodeEndpoint> endpoints, int timeout_ms = 3000);

    bool call(const std::string& method,
              const std::vector<JNode>& params,
              JNode& out,
              std::string& err);

    bool call_str(const std::string& method,
                  const std::vector<JNode>& params,
                  std::string& out_str,
                  std::string& err);

    NodeEndpoint current() const;

private:
    bool call_once(size_t idx, const std::string& body, JNode& out, std::string& err);

    std::vector<NodeEndpoint> eps_;
    int timeout_ms_{3000};
    mutable std::mutex mtx_;
    size_t cursor_{0};
};

}
