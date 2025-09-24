#pragma once
#include <string>
namespace miq {
struct Config {
    std::string datadir = "./miqdata";
    unsigned miner_threads = 0;
    bool no_mine=false, no_p2p=false, no_rpc=false;
    std::string mining_address; // NEW: Base58Check P2PKH address to mine to
};
bool load_config(const std::string& path, Config& cfg);
}
