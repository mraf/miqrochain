#pragma once
#include <cstdint>
#include <string>

namespace miq {
class Chain;
class P2P;

struct IBDInfo {
    bool       ibd_active = true;
    uint32_t   best_block_height = 0;
    uint32_t   est_best_header_height = 0;
    uint32_t   headers_ahead = 0;
    uint32_t   peers = 0;
    std::string phase; // "headers","blocks","steady"
    uint64_t   started_ms = 0;
    uint64_t   last_update_ms = 0;
};

void   start_ibd_monitor(Chain* chain, P2P* p2p);
IBDInfo get_ibd_info_snapshot();

}
