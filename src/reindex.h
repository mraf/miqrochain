#pragma once
#include "kv.h"
#include "utxo_kv.h"
#include "chain.h"
#include <string>

namespace miq {

// Rebuild UTXO from the active chain into a fresh KV at `path`.
// - Leaves the existing chainstate untouched.
// - Returns true on success; `err` filled otherwise.
// - If `compact_after` is true, runs KV compaction at end.
bool reindex_utxo_from_chain(Chain& chain, const std::string& kv_path, bool compact_after, std::string& err);

}
