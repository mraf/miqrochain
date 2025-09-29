#pragma once
#include "chain.h"
#include "utxo_kv.h"
#include <string>

namespace miq {

// Rebuilds the UTXO set into <datadir>/chainstate using UTXOKV.
// - Reads blocks from the active chain (index 0..tip).
// - Best-effort spend: ignores missing coins from old forks.
// - Batched writes for throughput; fsync at commit.
// - `compact_after` is kept for future use (no-op unless you expose KV compaction).
//
// Returns true on success; false and sets `err` on failure.
bool ReindexUTXO(Chain& chain, UTXOKV& kv, bool compact_after, std::string& err);

}
