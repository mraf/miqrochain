#include "ibd_monitor.h"
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>

// Forward-declared types are from your codebase:
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
    if(g_run.exchange(true)) return;
    g_info.started_ms = now_ms();

    // We only rely on methods that exist in your current main.cpp usage:
    // - chain.tip() returns a struct with .height
    // If you later add header-tip or peer counters, feel free to extend here.
    std::thread([chain,p2p](){
        for(;;){
            if(!g_run.load()) break;
            IBDInfo cur{};
            cur.best_block_height = 0;
            try {
                auto t = chain->tip();
                cur.best_block_height = t.height;
            } catch(...) {}

            // Conservative defaults (we don't assume header-tip API exists)
            cur.est_best_header_height = cur.best_block_height;
            cur.headers_ahead = 0;
            cur.peers = 0; // if P2P exposes a getter later, wire it here.

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
