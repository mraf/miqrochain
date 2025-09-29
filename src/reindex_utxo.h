#pragma once
#include "chain.h"
#include "utxo_kv.h"
#include <string>

namespace miq {

// Rebuilds the UTXO set into <datadir>/chainstate using UTXOKV.
// - Reads blocks from the active chain (from index 0..tip).
// - Ignores double-spend noise on old forks (spend() best-effort).
// - Uses batched writes for speed; fsync at end.
// - If compact_after is true, calls db_.compact() if your KVDB supports it (noop otherwise).
//
// Returns true on success; false and sets `err` on failure.
bool ReindexUTXO(Chain& chain, UTXOKV& kv, bool compact_after, std::string& err);

}
