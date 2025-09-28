#include "ibd_monitor.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

#include "chain.h"
#include "p2p.h"

namespace {
std::mutex g_mtx;
miq::IBDInfo g_info;
std::atomic<bool> g_run{false};

static uint64_t now_ms(){
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}
}

namespace miq {

void start_ibd_monitor(Chain* chain, P2P* p2p){
    (void)p2p; // not used yet; keep for future peer metrics
    if(g_run.exchange(true)) return;
    g_info.started_ms = now_ms();

    std::thread([chain](){
        for(;;){
            if(!g_run.load()) break;

            IBDInfo cur{};
            // Minimal safe sampling: only use methods we know exist.
            try {
                auto t = chain->tip(); // your tip struct has .height
                cur.best_block_height = t.height;
            } catch(...) {
                cur.best_block_height = 0;
            }

            // Without a header-tip API, use block height as conservative estimate.
            cur.est_best_header_height = cur.best_block_height;
            cur.headers_ahead = 0;
            cur.peers = 0;

            cur.phase = (cur.best_block_height==0) ? "blocks" : "steady";
            cur.ibd_active = (cur.phase!="steady");
            cur.last_update_ms = now_ms();

            {
                std::lock_guard<std::mutex> lk(g_mtx);
                g_info = cur;
                if(g_info.started_ms==0) g_info.started_ms = cur.last_update_ms;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(800));
        }
    }).detach();
}

IBDInfo get_ibd_info_snapshot(){
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_info;
}

}
