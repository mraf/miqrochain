#include "wallet/spv_simple.h"
#include "wallet/p2p_light.h"
#include "serialize.h"
#include "hex.h"
#include "tx.h"
#include <set>
#include <map>
#include <fstream>
#include <sstream>

namespace miq {

// -------- tiny cache (JSONL) --------
static std::string join_path(const std::string& a, const std::string& b){
#ifdef _WIN32
    const char sep='\\';
#else
    const char sep='/';
#endif
    if(a.empty()) return b;
    if(a.back()==sep) return a+b;
    return a + sep + b;
}
static std::string cache_file(const SpvOptions& opt){
    return join_path(opt.cache_dir, "utxo.cache.jsonl");
}
static void cache_save(const std::string& path, const std::vector<UtxoLite>& v){
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if(!f.good()) return;
    for(const auto& u: v){
        f << "{"
          << "\"txid\":\"" << to_hex(u.txid) << "\","
          << "\"vout\":" << u.vout << ","
          << "\"value\":" << u.value << ","
          << "\"pkh\":\"" << to_hex(u.pkh) << "\","
          << "\"height\":" << u.height << ","
          << "\"coinbase\":" << (u.coinbase?"true":"false")
          << "}\n";
    }
}
static void cache_load(const std::string& path, std::vector<UtxoLite>& v){
    std::ifstream f(path, std::ios::binary);
    if(!f.good()) return;
    std::string line;
    while(std::getline(f, line)){
        if(line.empty()) continue;
        UtxoLite u{};
        auto s = line;
        auto get = [&](const char* k)->std::string{
            auto p = s.find(std::string("\"")+k+"\"");
            if(p==std::string::npos) return "";
            p = s.find(':', p); if(p==std::string::npos) return "";
            ++p; while(p<s.size() && (s[p]==' ')) ++p;
            if(s[p]=='"'){ auto q=s.find('"', p+1); return s.substr(p+1, q-p-1); }
            auto q=p; while(q<s.size() && (isdigit((unsigned char)s[q])||s[q]=='-')) ++q; return s.substr(p,q-p);
        };
        auto txid_hex=get("txid");
        auto pkh_hex=get("pkh");
        auto vout_str=get("vout");
        auto val_str=get("value");
        auto h_str=get("height");
        auto cb_str=get("coinbase");
        if(txid_hex.size()==64 && pkh_hex.size()==40){
            u.txid = from_hex(txid_hex);
            u.pkh  = from_hex(pkh_hex);
            u.vout = (uint32_t)std::stoul(vout_str);
            u.value= (uint64_t)std::stoull(val_str);
            u.height=(uint32_t)std::stoul(h_str);
            u.coinbase = (cb_str=="true");
            v.push_back(u);
        }
    }
}

// -------- SPV via P2PLight --------
// We try filters first (if the peer supports them). If not, scan recent blocks.
bool spv_collect_utxos(
    const std::string& host, const std::string& port,
    const std::vector<std::vector<uint8_t>>& pkhs,
    const SpvOptions& opt,
    std::vector<UtxoLite>& out,
    std::string& err)
{
    out.clear();

    // Start connection
    P2POpts o; o.host=host; o.port=port; o.user_agent="/miqwallet-spv:0.1/";
    P2PLight p2p;
    if(!p2p.connect_and_handshake(o, err)) return false;

    // 1) Get tip
    uint32_t tip_height=0; std::vector<uint8_t> tip_hash;
    if(!p2p.get_best_header(tip_height, tip_hash, err)){ p2p.close(); return false; }

    // 2a) Preferred: compact filters
    std::vector<std::pair<std::vector<uint8_t>, uint32_t>> matched_blocks; // (blockhash,height)
    if(p2p.has_compact_filters()){
        if(!p2p.scan_blocks_with_filters(pkhs, tip_height, matched_blocks, err)){ p2p.close(); return false; }
    } else {
        // 2b) Fallback: scan recent blocks (window)
        uint32_t from_h = (tip_height > opt.recent_block_window) ? (tip_height - opt.recent_block_window) : 0;
        if(!p2p.match_recent_blocks(pkhs, from_h, tip_height, matched_blocks, err)){ p2p.close(); return false; }
    }

    // 3) Fetch and parse matched blocks; collect UTXO set for our PKHs and remove spends
    // We also start from cached view to speed up repeat runs.
    std::vector<UtxoLite> view;
    cache_load(cache_file(opt), view);

    // quick index of our view by outpoint
    auto key_of = [](const std::vector<uint8_t>& txid, uint32_t vout){
        std::string k; k.reserve(36);
        k.assign((const char*)txid.data(), txid.size());
        k.push_back(char((vout>>0)&0xFF)); k.push_back(char((vout>>8)&0xFF));
        k.push_back(char((vout>>16)&0xFF)); k.push_back(char((vout>>24)&0xFF));
        return k;
    };
    std::map<std::string,size_t> idx;
    for(size_t i=0;i<view.size();++i){
        idx[key_of(view[i].txid, view[i].vout)] = i;
    }
    // set of our PKHs
    std::set<std::vector<uint8_t>> pkhset(pkhs.begin(), pkhs.end());

    for(const auto& [bh, h] : matched_blocks){
        std::vector<uint8_t> raw;
        if(!p2p.get_block_by_hash(bh, raw, err)){ p2p.close(); return false; }
        Block b; if(!Block::deserialize(raw, b)){ continue; }

        // 3a. consume spends
        for(const auto& tx : b.vtx){
            for(const auto& in : tx.vin){
                auto k = key_of(in.prev.txid, in.prev.vout);
                auto it = idx.find(k);
                if(it!=idx.end()){
                    // remove from view by swapping with back
                    size_t pos = it->second;
                    size_t last = view.size()-1;
                    if(pos!=last){
                        idx[key_of(view[last].txid, view[last].vout)] = pos;
                        std::swap(view[pos], view[last]);
                    }
                    view.pop_back();
                    idx.erase(it);
                }
            }
        }
        // 3b. add our outputs
        for(const auto& tx : b.vtx){
            bool is_cb = tx.is_coinbase();
            for(uint32_t i=0;i<(uint32_t)tx.vout.size();++i){
                const auto& o = tx.vout[i];
                if(pkhset.count(o.pkh)){
                    UtxoLite u; u.txid = tx.txid(); u.vout=i; u.value=o.value; u.pkh=o.pkh; u.height=h; u.coinbase=is_cb;
                    idx[key_of(u.txid, u.vout)] = (uint32_t)view.size();
                    view.push_back(std::move(u));
                }
            }
        }
    }

    p2p.close();

    // Save & return
    cache_save(cache_file(opt), view);
    out = std::move(view);
    return true;
}

uint64_t spv_sum_value(const std::vector<UtxoLite>& v){
    uint64_t s=0; for(auto& u: v) s+=u.value; return s;
}

}
