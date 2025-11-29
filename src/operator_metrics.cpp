#include "operator_metrics.h"
#include "log.h"
#include <sstream>
#include <iomanip>
#include <ctime>

namespace miq {

OperatorMetrics& OperatorMetrics::instance() {
    static OperatorMetrics inst;
    return inst;
}

void OperatorMetrics::log_summary() const {
    std::lock_guard<std::mutex> lk(mtx_);

    // Chain status
    log_info(LogCategory::GENERAL,
        "[METRICS] Chain: height=" + std::to_string(chain.height.load()) +
        " utxos=" + std::to_string(chain.utxo_count.load()));

    // Peer status
    log_info(LogCategory::NET,
        "[METRICS] Peers: total=" + std::to_string(peer.total_connected.load()) +
        " in=" + std::to_string(peer.inbound_count.load()) +
        " out=" + std::to_string(peer.outbound_count.load()) +
        " stalls=" + std::to_string(peer.stall_count.load()) +
        " bans=" + std::to_string(peer.ban_count.load()));

    // Traffic
    double sent_mb = peer.bytes_sent.load() / (1024.0 * 1024.0);
    double recv_mb = peer.bytes_recv.load() / (1024.0 * 1024.0);
    std::ostringstream traffic;
    traffic << std::fixed << std::setprecision(2);
    traffic << "[METRICS] Traffic: sent=" << sent_mb << "MB recv=" << recv_mb << "MB";
    log_info(LogCategory::NET, traffic.str());

    // Validation
    uint64_t total_ms = validation.total_validation_ms.load();
    uint64_t blocks = validation.blocks_validated.load();
    double avg_ms = blocks > 0 ? (double)total_ms / blocks : 0.0;
    std::ostringstream val;
    val << std::fixed << std::setprecision(1);
    val << "[METRICS] Validation: blocks=" << blocks
        << " txs=" << validation.txs_validated.load()
        << " rejected_blocks=" << validation.blocks_rejected.load()
        << " avg_block_ms=" << avg_ms;
    log_info(LogCategory::VALIDATION, val.str());

    // Mempool
    log_info(LogCategory::MEMPOOL,
        "[METRICS] Mempool: size=" + std::to_string(mempool.size.load()) +
        " bytes=" + std::to_string(mempool.bytes.load()) +
        " added=" + std::to_string(mempool.txs_added.load()) +
        " expired=" + std::to_string(mempool.txs_expired.load()));

    // Reorg
    if (reorg.reorg_count.load() > 0) {
        log_info(LogCategory::VALIDATION,
            "[METRICS] Reorgs: count=" + std::to_string(reorg.reorg_count.load()) +
            " max_depth=" + std::to_string(reorg.max_reorg_depth.load()) +
            " disconnected=" + std::to_string(reorg.blocks_disconnected.load()) +
            " reconnected=" + std::to_string(reorg.blocks_reconnected.load()));
    }

    // RPC
    uint64_t rpc_total = rpc.requests_total.load();
    uint64_t rpc_latency = rpc.total_latency_ms.load();
    double rpc_avg = rpc_total > 0 ? (double)rpc_latency / rpc_total : 0.0;
    std::ostringstream rpc_ss;
    rpc_ss << std::fixed << std::setprecision(1);
    rpc_ss << "[METRICS] RPC: requests=" << rpc_total
           << " failed=" << rpc.requests_failed.load()
           << " avg_latency_ms=" << rpc_avg;
    log_info(LogCategory::RPC, rpc_ss.str());
}

void OperatorMetrics::log_reorg(uint64_t depth, uint64_t old_height, uint64_t new_height) {
    reorg.reorg_count.fetch_add(1);
    reorg.blocks_disconnected.fetch_add(depth);

    // Update max reorg depth
    uint64_t cur_max = reorg.max_reorg_depth.load();
    while (depth > cur_max && !reorg.max_reorg_depth.compare_exchange_weak(cur_max, depth)) {}

    reorg.last_reorg_time.store(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());

    // Log the reorg event
    std::ostringstream ss;
    ss << "[REORG] Chain reorganization detected! depth=" << depth
       << " old_height=" << old_height << " new_height=" << new_height;
    log_warn(LogCategory::VALIDATION, ss.str());
}

void OperatorMetrics::log_difficulty_epoch(uint64_t height, uint64_t old_diff, uint64_t new_diff) {
    double change = old_diff > 0 ? (100.0 * (double)new_diff / (double)old_diff - 100.0) : 0.0;

    std::ostringstream ss;
    ss << std::fixed << std::setprecision(2);
    ss << "[DIFFICULTY] Epoch at height=" << height
       << " old=" << old_diff << " new=" << new_diff
       << " change=" << (change >= 0 ? "+" : "") << change << "%";
    log_info(LogCategory::VALIDATION, ss.str());
}

void OperatorMetrics::log_peer_stall(const std::string& ip, uint64_t stall_duration_ms) {
    peer.stall_count.fetch_add(1);

    std::ostringstream ss;
    ss << "[PEER STALL] Peer " << ip << " stalled for " << stall_duration_ms << "ms";
    log_warn(LogCategory::NET, ss.str());
}

void OperatorMetrics::log_block_validated(uint64_t height, uint64_t validation_ms, uint64_t tx_count) {
    validation.blocks_validated.fetch_add(1);
    validation.txs_validated.fetch_add(tx_count);
    validation.total_validation_ms.fetch_add(validation_ms);
    validation.last_block_ms.store(validation_ms);
    chain.height.store(height);

    // Log slow blocks
    if (validation_ms > 1000) {
        std::ostringstream ss;
        ss << "[SLOW BLOCK] Block " << height << " took " << validation_ms
           << "ms to validate (" << tx_count << " txs)";
        log_warn(LogCategory::VALIDATION, ss.str());
    }
}

std::string OperatorMetrics::to_json() const {
    std::lock_guard<std::mutex> lk(mtx_);

    std::ostringstream ss;
    ss << "{"
       << "\"chain\":{\"height\":" << chain.height.load()
       << ",\"utxo_count\":" << chain.utxo_count.load()
       << ",\"tip_time\":" << chain.tip_time.load()
       << "},"
       << "\"peers\":{\"total\":" << peer.total_connected.load()
       << ",\"inbound\":" << peer.inbound_count.load()
       << ",\"outbound\":" << peer.outbound_count.load()
       << ",\"stalls\":" << peer.stall_count.load()
       << ",\"bans\":" << peer.ban_count.load()
       << ",\"bytes_sent\":" << peer.bytes_sent.load()
       << ",\"bytes_recv\":" << peer.bytes_recv.load()
       << "},"
       << "\"validation\":{\"blocks\":" << validation.blocks_validated.load()
       << ",\"txs\":" << validation.txs_validated.load()
       << ",\"rejected_blocks\":" << validation.blocks_rejected.load()
       << ",\"rejected_txs\":" << validation.txs_rejected.load()
       << ",\"total_ms\":" << validation.total_validation_ms.load()
       << "},"
       << "\"mempool\":{\"size\":" << mempool.size.load()
       << ",\"bytes\":" << mempool.bytes.load()
       << ",\"added\":" << mempool.txs_added.load()
       << ",\"expired\":" << mempool.txs_expired.load()
       << "},"
       << "\"reorg\":{\"count\":" << reorg.reorg_count.load()
       << ",\"max_depth\":" << reorg.max_reorg_depth.load()
       << ",\"disconnected\":" << reorg.blocks_disconnected.load()
       << "},"
       << "\"rpc\":{\"requests\":" << rpc.requests_total.load()
       << ",\"failed\":" << rpc.requests_failed.load()
       << ",\"total_latency_ms\":" << rpc.total_latency_ms.load()
       << "}"
       << "}";
    return ss.str();
}

void OperatorMetrics::reset() {
    std::lock_guard<std::mutex> lk(mtx_);

    peer.total_connected = 0;
    peer.inbound_count = 0;
    peer.outbound_count = 0;
    peer.stall_count = 0;
    peer.ban_count = 0;
    peer.bytes_sent = 0;
    peer.bytes_recv = 0;
    peer.messages_sent = 0;
    peer.messages_recv = 0;

    validation.blocks_validated = 0;
    validation.txs_validated = 0;
    validation.blocks_rejected = 0;
    validation.txs_rejected = 0;
    validation.total_validation_ms = 0;

    mempool.size = 0;
    mempool.bytes = 0;
    mempool.txs_added = 0;
    mempool.txs_removed = 0;
    mempool.txs_expired = 0;

    reorg.reorg_count = 0;
    reorg.max_reorg_depth = 0;
    reorg.blocks_disconnected = 0;
    reorg.blocks_reconnected = 0;

    rpc.requests_total = 0;
    rpc.requests_failed = 0;
    rpc.total_latency_ms = 0;
}

}  // namespace miq
