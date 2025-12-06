#include "chain.h"
#include "utxo_kv.h"
#include "reindex_utxo.h"
#include "log.h"
#include <string>
#include <fstream>
#include <cstdio>

#ifndef _WIN32
#include <unistd.h>
#include <fcntl.h>
#endif

namespace miq {

// CRITICAL FIX: Check if chainstate is consistent with blockchain tip
// Returns true if reindex is needed
static bool detect_chainstate_mismatch(Chain& chain, UTXOKV& kv) {
    (void)kv;  // Reserved for future chainstate validation
    // Read stored chainstate tip from marker file
    std::string marker_path = chain.datadir() + "/chainstate/tip.dat";
    std::ifstream marker(marker_path, std::ios::binary);
    if (!marker.good()) {
        // No marker file - could be first run or corruption
        // Check if we have significant chain height but empty UTXO
        if (chain.height() > 10) {
            log_warn("Chainstate tip marker missing with chain height " +
                     std::to_string(chain.height()) + " - may need reindex");
            return true;
        }
        return false;
    }

    std::vector<uint8_t> stored_tip(32);
    marker.read(reinterpret_cast<char*>(stored_tip.data()), 32);
    marker.close();

    // Compare with actual chain tip
    auto tip = chain.tip();
    if (stored_tip != tip.hash) {
        log_warn("Chainstate tip mismatch detected - stored tip differs from chain tip");
        log_warn("Chain tip: height=" + std::to_string(tip.height));
        return true;
    }

    return false;
}

// Save chainstate tip marker after successful operations
static void save_chainstate_tip_marker(Chain& chain) {
    std::string marker_path = chain.datadir() + "/chainstate/tip.dat";

    // Use FILE* for portable fsync
    FILE* fp = std::fopen(marker_path.c_str(), "wb");
    if (fp) {
        auto tip = chain.tip();
        std::fwrite(tip.hash.data(), 1, tip.hash.size(), fp);
        std::fflush(fp);
#ifndef _WIN32
        // fsync for durability
        int fd = fileno(fp);
        if (fd >= 0) fsync(fd);
#endif
        std::fclose(fp);
    }
}

// This function is declared as weak in main.cpp and linked only if this file is compiled.
// It wraps the ReindexUTXO function to provide UTXO reindexing capability.
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
__attribute__((weak))
#endif
bool ensure_utxo_fully_indexed(Chain& chain, const std::string& datadir, bool force_reindex) {
    // Open the UTXO key-value store
    UTXOKV kv;
    std::string err;
    if (!kv.open(datadir, &err)) {
        log_error("Failed to open UTXO database: " + err);
        return false;
    }

    // CRITICAL FIX: Auto-detect chainstate corruption on startup
    bool needs_reindex = force_reindex;
    if (!force_reindex) {
        if (detect_chainstate_mismatch(chain, kv)) {
            log_warn("Automatic chainstate reconstruction triggered due to mismatch");
            needs_reindex = true;
        }
    }

    if (!needs_reindex) {
        // Update tip marker for consistency tracking
        save_chainstate_tip_marker(chain);
        return true;
    }

    log_info("Starting UTXO reindex...");
    log_info("This may take a while depending on chain height (" +
             std::to_string(chain.height()) + " blocks)");

    // Perform the full reindex with progress reporting
    auto progress = [](uint64_t current, uint64_t total, const char* phase) {
        if (total > 0 && (current % 1000 == 0 || current == total)) {
            double pct = 100.0 * current / total;
            log_info(std::string(phase) + ": " + std::to_string(current) + "/" +
                     std::to_string(total) + " (" + std::to_string((int)pct) + "%)");
        }
    };

    if (!ReindexUTXOWithProgress(chain, kv, true, progress, err)) {
        log_error("UTXO reindex failed: " + err);
        return false;
    }

    // Save tip marker after successful reindex
    save_chainstate_tip_marker(chain);

    log_info("UTXO reindex completed successfully");
    return true;
}

}  // namespace miq

