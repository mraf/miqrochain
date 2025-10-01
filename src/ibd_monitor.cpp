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
} // anonymous namespace

namespace miq {

void start_ibd_monitor(Chain* chain, P2P* p2p){
    if (g_run.exchange(true)) return; // already running
    g_info.started_ms = now_ms();

    std::thread([chain, p2p](){
        for(;;){
            if(!g_run.load()) break;

            IBDInfo cur{};

            // Tip height (best block)
            try {
                auto t = chain->tip();
                cur.best_block_height = static_cast<uint32_t>(t.height);
            } catch (...) {
                cur.best_block_height = 0;
            }

            // Peer count (best-effort)
            try {
                cur.peers = p2p ? static_cast<uint32_t>(p2p->connection_count()) : 0u;
            } catch (...) {
                cur.peers = 0;
            }

            // Without a public header-tip API, keep conservative estimates.
            cur.est_best_header_height = cur.best_block_height;
            cur.headers_ahead = 0;

            // Simple phase heuristic
            cur.phase = (cur.best_block_height == 0) ? "blocks" : "steady";
            cur.ibd_active = (cur.phase != "steady");
            cur.last_update_ms = now_ms();

            {
                std::lock_guard<std::mutex> lk(g_mtx);
                if (g_info.started_ms == 0) g_info.started_ms = cur.last_update_ms;
                g_info = cur;
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
