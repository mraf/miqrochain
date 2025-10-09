#include "node_client.h"
#include "http_client.h"
#include "log.h"
#include "constants.h"

#include <sstream>

namespace miq {

NodeClient NodeClient::Auto(const std::string& datadir, int timeout_ms){
    auto eps = discover_nodes(datadir, timeout_ms);
    return NodeClient(std::move(eps), timeout_ms);
}

NodeClient::NodeClient(std::vector<NodeEndpoint> endpoints, int timeout_ms)
: eps_(std::move(endpoints)), timeout_ms_(timeout_ms)
{
    if(eps_.empty()){
        eps_.push_back(NodeEndpoint{"62.38.73.147", (uint16_t)9834, std::string(), -1});
        eps_.push_back(NodeEndpoint{"127.0.0.1", (uint16_t)RPC_PORT, std::string(), -1});
    }
}

NodeEndpoint NodeClient::current() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return eps_[cursor_ % eps_.size()];
}

bool NodeClient::call_once(size_t idx, const std::string& body, JNode& out, std::string& err){
    const auto& ep = eps_[idx];

    std::vector<std::pair<std::string,std::string>> hdrs;
    if(!ep.token.empty()){
        hdrs.emplace_back("X-Auth-Token", ep.token);
    }

    HttpResponse r;
    if(!http_post(ep.host, ep.port, "/", body, hdrs, r, timeout_ms_)){
        err = "connect failed";
        return false;
    }
    if(r.code==401 || r.code==403){ err = "unauthorized"; return false; }
    if(r.code!=200){ std::ostringstream s; s << "http " << r.code; err = s.str(); return false; }

    JNode resp;
    if(!json_parse(r.body, resp)){ err = "bad json"; return false; }
    out = std::move(resp);
    return true;
}

bool NodeClient::call(const std::string& method,
                      const std::vector<JNode>& params,
                      JNode& out,
                      std::string& err)
{
    std::map<std::string,JNode> o;
    o["method"].v = std::string(method);
    if(!params.empty()){ JNode p; p.v = params; o["params"] = p; }
    JNode req; req.v = o;
    std::string body = json_dump(req);

    size_t N = eps_.size();
    size_t start;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        start = cursor_ % N;
        cursor_ = (cursor_ + 1) % N;
    }

    for(size_t i=0;i<N;i++){
        size_t idx = (start + i) % N;
        JNode tmp; std::string e;
        if(call_once(idx, body, tmp, e)){
            out = std::move(tmp);
            err.clear();
            return true;
        }
        log_warn("RPC call to " + eps_[idx].host + ":" + std::to_string(eps_[idx].port) + " failed: " + e);
    }
    err = "all endpoints failed";
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

}
