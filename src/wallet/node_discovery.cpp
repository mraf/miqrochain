#include "node_discovery.h"
#include "http_client.h"
#include "constants.h"   // RPC_PORT
#include "serialize.h"   // JNode/json_parse/json_dump
#include "log.h"

#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <algorithm>
#include <cctype>
#include <chrono>

namespace miq {

static inline std::string trim(std::string s){
    size_t i=0, j=s.size();
    while(i<j && (s[i]==' '||s[i]=='\t'||s[i]=='\r'||s[i]=='\n')) ++i;
    while(j>i && (s[j-1]==' '||s[j-1]=='\t'||s[j-1]=='\r'||s[j-1]=='\n')) --j;
    return s.substr(i, j-i);
}

static void parse_list_add(const std::string& spec, std::vector<NodeEndpoint>& out, uint16_t defport){
    std::string s = trim(spec);
    if(s.empty() || s[0]=='#') return;
    std::string host; uint16_t port=defport; std::string token;

    size_t at = s.find('@');
    std::string a = s, b;
    if(at!=std::string::npos){ a = s.substr(0,at); b = s.substr(at+1); token = trim(b); }

    size_t c = a.rfind(':');
    if(c==std::string::npos){ host = trim(a); }
    else {
        host = trim(a.substr(0,c));
        port = (uint16_t)std::stoi(a.substr(c+1));
    }
    if(host.empty()) return;
    out.push_back(NodeEndpoint{host,port,token,-1});
}

static std::vector<NodeEndpoint> sources_from_env_and_file(const std::string& datadir){
    std::vector<NodeEndpoint> v;

    if(const char* e = std::getenv("MIQ_NODE_URLS"); e && *e){
        std::string s(e);
        size_t p=0;
        while(p<s.size()){
            size_t q = s.find(',', p);
            if(q==std::string::npos) q = s.size();
            parse_list_add(s.substr(p, q-p), v, (uint16_t)RPC_PORT);
            p = q+1;
        }
    }

    // <datadir>/nodes.txt
    std::string path = datadir;
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(!path.empty() && path.back()!=sep) path.push_back(sep);
    path += "nodes.txt";
    std::ifstream f(path, std::ios::in | std::ios::binary);
    if(f.good()){
        std::string line;
        while(std::getline(f, line)){
            auto s = trim(line);
            if(s.empty() || s[0]=='#') continue;
            parse_list_add(s, v, (uint16_t)RPC_PORT);
        }
    }

    // --- compiled default seeds ---
    // Your public node:
    v.push_back(NodeEndpoint{"62.38.73.147", (uint16_t)9834, std::string(), -1});
    // Always include local as a last resort:
    v.push_back(NodeEndpoint{"127.0.0.1", (uint16_t)RPC_PORT, std::string(), -1});

    // dedupe by (host,port,token)
    std::sort(v.begin(), v.end(), [](const NodeEndpoint& A, const NodeEndpoint& B){
        if(A.host!=B.host) return A.host < B.host;
        if(A.port!=B.port) return A.port < B.port;
        return A.token < B.token;
    });
    v.erase(std::unique(v.begin(), v.end(), [](const NodeEndpoint& A, const NodeEndpoint& B){
        return A.host==B.host && A.port==B.port && A.token==B.token;
    }), v.end());
    return v;
}

static int probe_latency(NodeEndpoint& ep, int timeout_ms){
    // POST {"method":"ping"}
    JNode req; std::map<std::string,JNode> o; o["method"].v = std::string("ping"); req.v = o;
    std::string body = json_dump(req);

    std::vector<std::pair<std::string,std::string>> hdrs;
    if(!ep.token.empty()){
        hdrs.emplace_back("X-Auth-Token", ep.token);
    }

    auto t0 = std::chrono::steady_clock::now();
    HttpResponse r;
    if(!http_post(ep.host, ep.port, "/", body, hdrs, r, timeout_ms)){
        return -1;
    }
    auto ms = (int)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    if(r.code==200){ ep.last_ms = ms; return ms; }
    if(r.code==401 || r.code==403){ ep.last_ms = -2; return -2; }
    return -1;
}

std::vector<NodeEndpoint> discover_nodes(const std::string& datadir, int timeout_ms){
    auto eps = sources_from_env_and_file(datadir);

    std::vector<NodeEndpoint> good, unknown, bad;
    for(auto ep : eps){
        int ms = probe_latency(ep, timeout_ms);
        if(ms>=0) good.push_back(ep);
        else if(ms==-2) unknown.push_back(ep);
        else bad.push_back(ep);
    }
    std::sort(good.begin(), good.end(), [](const NodeEndpoint& A, const NodeEndpoint& B){
        return A.last_ms < B.last_ms;
    });
    good.insert(good.end(), unknown.begin(), unknown.end());
    good.insert(good.end(), bad.begin(), bad.end());
    return good;
}

}
