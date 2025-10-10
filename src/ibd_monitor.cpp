// src/ibd_monitor.cpp — crash-proof, headers-only (best-effort) IBD sampler

#include "ibd_monitor.h"
#include "chain.h"
#include "p2p.h"
#include "log.h"

#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <exception>

namespace {

// Shared snapshot
std::mutex g_mtx;
miq::IBDInfo g_info;
std::atomic<bool> g_run{false};

static inline uint64_t now_ms(){
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

} // anon

namespace miq {

void start_ibd_monitor(Chain* chain, P2P* p2p){
    if (g_run.exchange(true)) return;

    {
        std::lock_guard<std::mutex> lk(g_mtx);
        g_info = {};
        g_info.started_ms = now_ms();
        g_info.last_update_ms = g_info.started_ms;
        g_info.phase = "steady";
        g_info.ibd_active = false;
    }

    std::thread([chain, p2p](){
        try {
            while (g_run.load()) {
                IBDInfo cur{};
                cur.best_block_height = (uint32_t)(chain ? chain->height() : 0);
                // We don’t currently expose a separate best-header height from Chain.
                // Report a conservative equal value (no “headers ahead”) until the header
                // index is exposed via a getter.
                cur.est_best_header_height = cur.best_block_height;
                cur.headers_ahead = 0;

                cur.peers = (uint32_t)(p2p ? p2p->connection_count() : 0);
                cur.phase = cur.headers_ahead ? "headers" : "steady";
                cur.ibd_active = (cur.headers_ahead > 0);
                cur.last_update_ms = now_ms();

                {
                    std::lock_guard<std::mutex> lk(g_mtx);
                    // keep original start time
                    cur.started_ms = g_info.started_ms ? g_info.started_ms : cur.last_update_ms;
                    g_info = cur;
                }

                std::this_thread::sleep_for(std::chrono::milliseconds(800));
            }
        } catch (const std::exception& e) {
            log_error(std::string("IBD monitor thread exception: ") + e.what());
        } catch (...) {
            log_error("IBD monitor thread exception (unknown)");
        }
    }).detach();
}

IBDInfo get_ibd_info_snapshot(){
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_info;
}

}
