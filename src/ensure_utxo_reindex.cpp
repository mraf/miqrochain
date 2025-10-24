#include "chain.h"
#include "utxo_kv.h"
#include "reindex_utxo.h"
#include "log.h"
#include <string>

namespace miq {

// This function is declared as weak in main.cpp and linked only if this file is compiled.
// It wraps the ReindexUTXO function to provide UTXO reindexing capability.
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
__attribute__((weak))
#endif
bool ensure_utxo_fully_indexed(Chain& chain, const std::string& datadir, bool force_reindex) {
    if (!force_reindex) {
        // If not forcing reindex, just return success (UTXO will be built incrementally)
        return true;
    }

    log_info("Starting UTXO reindex...");

    // Open the UTXO key-value store
    UTXOKV kv;
    std::string err;
    if (!kv.open(datadir, &err)) {
        log_error("Failed to open UTXO database: " + err);
        return false;
    }

    // Perform the full reindex
    if (!ReindexUTXO(chain, kv, true, err)) {
        log_error("UTXO reindex failed: " + err);
        return false;
    }

    log_info("UTXO reindex completed successfully");
    return true;
}

}  // namespace miq

