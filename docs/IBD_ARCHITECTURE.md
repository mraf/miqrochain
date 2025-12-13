# IBD Architecture: Bitcoin Core-Aligned Sync

## Root Causes of Current Issues

### 1. No Explicit State Machine
**Current**: Sync state managed via scattered booleans:
- `g_logged_headers_started`
- `g_logged_headers_done`
- `ps.syncing`
- `miq::is_ibd_mode()`

**Problem**: State can become inconsistent. Headers phase can restart. No single source of truth.

**Bitcoin Core Reference**: `ChainstateManager::IsInitialBlockDownload()` combined with `HeadersSyncState` in `headerssync.cpp` provides authoritative state.

### 2. Multiple Overlapping Recovery Mechanisms
**Current** (p2p.cpp):
- Global stall recovery (lines 5808-5887)
- Nuclear recovery (every 200ms-10s)
- Per-peer timeout recovery
- Headers fallback to index-by-height
- Peer tip recovery
- Gap detection with broadcast

**Problem**: These mechanisms fight each other. Nuclear recovery cancels good inflight requests. Gap detection broadcasts to all peers creating duplicate work.

**Bitcoin Core Reference**: Single `TipMayBeStale()` check in `net_processing.cpp:4467`. No "nuclear" resets.

### 3. Level-Triggered Stall Detection
**Current**: Based on `g_last_progress_ms` which tracks commit height progress.

**Problem**: Out-of-order blocks cause false stalls. Block 100 arrives, then block 99 - height doesn't increase but we're making progress.

**Bitcoin Core Reference**: `net_processing.cpp` tracks `m_last_block_announcement` per peer. Stall detection is edge-triggered on ANY data reception.

### 4. Pipeline Resets on Gaps
**Current**: When gap detected, clears global tracking and re-requests.

**Problem**: Cancels potentially valid inflight requests. Creates duplicate work.

**Bitcoin Core Reference**: `BlockRequested()` and `BlockReceived()` in `net_processing.cpp` use hole-filling without clearing other inflight.

### 5. No Minimum Inflight Guarantee
**Current**: Inflight can drop to 0 when all requests timeout.

**Problem**: No blocks downloading = guaranteed stall.

**Bitcoin Core Reference**: `MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16`. Always maintains inflight window.

### 6. Timing-Dependent Behavior
**Current**: Recovery timing, fallback timing, peer tip recovery timing all affect outcome.

**Problem**: Same peers + same network = different sync paths depending on timing.

**Bitcoin Core Reference**: Deterministic block request ordering via `GetBlocksToFetch()`.

---

## Corrected Sync Architecture

### State Machine
```
CONNECTING → HEADERS → BLOCKS → DONE
     │          │         │        │
     │          │         │        └── Monotonic: never goes back
     │          │         └── Headers complete, downloading blocks
     │          └── Downloading headers (headers-first)
     └── Finding peers
```

### Key Invariants

1. **Monotonic Heights**: `header_height` and `block_height` NEVER decrease
2. **Monotonic State**: State only transitions forward
3. **Inflight Minimum**: Always maintain ≥16 blocks inflight per peer during IBD
4. **No Pipeline Reset**: Never cancel valid inflight requests
5. **Edge-Triggered Stall**: Based on reception timestamps, not commit height
6. **Hole-Filling**: Fill gaps without resetting pipeline

### Block Request Scheduling

```
for each peer with inflight < MIN_INFLIGHT_PER_PEER:
    holes = get_unfilled_indices(block_height + 1, header_height)
    for hole in holes[:MIN_INFLIGHT_PER_PEER - peer.inflight]:
        if not is_inflight(hole):
            request_block(peer, hole)
```

### Stall Detection

```
// Edge-triggered: did ANY peer send us data recently?
if now - last_recv_timestamp > STALL_THRESHOLD:
    for each hole in get_holes():
        assign_to_different_peer(hole)
    // DO NOT reset pipeline
    // DO NOT clear inflight
```

---

## Bitcoin Core References

| Miqrochain Concept | Bitcoin Core File | Function/Class |
|-------------------|-------------------|----------------|
| Sync state machine | headerssync.cpp | `HeadersSyncState` |
| IBD detection | validation.cpp | `IsInitialBlockDownload()` |
| Block requests | net_processing.cpp | `BlockRequested()` |
| Inflight tracking | net_processing.cpp | `MarkBlockAsInFlight()` |
| Stall detection | net_processing.cpp | `ConsiderEviction()` |
| Hole-filling | net_processing.cpp | `FindNextBlocksToDownload()` |
| Peer state | net_processing.cpp | `CNodeState` |

---

## Implementation Changes

### 1. Add State Machine Header
```cpp
#include "ibd_state.h"
```

### 2. Replace Scattered Booleans
```cpp
// OLD
if (g_logged_headers_done) { ... }

// NEW
if (miq::ibd::IBDState::instance().current_state() >= miq::ibd::SyncState::BLOCKS) { ... }
```

### 3. Edge-Triggered Stall Detection
```cpp
// OLD: Based on commit height
if ((tnow - g_last_progress_ms) > STALL_RECOVERY_MS) { ... }

// NEW: Based on reception timestamps
if (!miq::ibd::IBDState::instance().has_recent_activity(STALL_THRESHOLD_MS)) { ... }
```

### 4. Hole-Filling Without Reset
```cpp
// OLD: Nuclear recovery
g_global_requested_indices.clear();
for (auto& peer : peers_) {
    peer.inflight_index = 0;
    peer.next_index = chain_height + 1;
    fill_index_pipeline(peer);
}

// NEW: Hole-filling
auto holes = miq::ibd::IBDState::instance().get_holes(16);
for (uint64_t hole : holes) {
    auto peer = select_best_peer_for(hole);
    if (peer) request_block_from(peer, hole);
}
```

### 5. Minimum Inflight Guarantee
```cpp
// In fill_index_pipeline:
while (peer.inflight_count() < MIN_INFLIGHT_PER_PEER) {
    // Request next hole
}
```

### 6. Never Disconnect for Pre-Handshake Messages
```cpp
// OLD
if (!ps.verack_ok && cmd != "ping" && cmd != "pong") {
    if (++ps.mis > 5) { dead.push_back(s); break; }
    continue;
}

// NEW: During IBD, be tolerant
if (!ps.verack_ok && cmd != "ping" && cmd != "pong") {
    // Log but don't count toward disconnection during IBD
    if (miq::ibd::IBDState::instance().current_state() < miq::ibd::SyncState::DONE) {
        P2P_TRACE("IBD: Ignoring pre-handshake " + cmd + " from " + ps.ip);
        continue;
    }
    if (++ps.mis > 5) { dead.push_back(s); break; }
    continue;
}
```

---

## Validation Criteria

1. **Cold start 6k blocks**: Must complete in minutes
2. **Warm datadir 16 blocks**: Must complete in < 1 second
3. **Determinism**: Same peers → same block request sequence
4. **No deadlocks**: Inflight never drops to 0 during IBD
5. **Invariant checks**: All logged invariants pass
