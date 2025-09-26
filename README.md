
# miqrochain C++ core v1

**Coin:** MIQ (unit: miqron, 1e-8)  
**Hard cap:** 26,280,000 MIQ • **Block time:** 8 minutes  
**Ports:** P2P 9833, RPC 9834  
**DNS seeder:** miqroseed1.freeddns.org

### ECC backend: how to plug in (2 files)
1. Remove `src/crypto/ecdsa_stub.*` from the target in `CMakeLists.txt` and add your backend files.
2. Provide definitions for the 4 functions in `src/crypto/ecdsa_iface.h`:
   - `generate_priv`, `derive_pub (compressed 33B)`, `sign (64B)`, `verify`.

Good options:
- **micro-ecc (uECC)** (BSD-2), curve **secp256k1** â€” tiny and fast
- **ed25519-donna** (public domain) â€” Ed25519 signatures (adjust naming as needed)

> Until you plug a real backend, the node mines blocks and relays, but **wonâ€™t accept spends** (signatures are rejected). This is intentional for safety.

Build:
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel
ctest --test-dir build --output-on-failure
./build/miqrod
```

License: Apache-2.0. Clean-room: no Bitcoin Core code.


## v1.1
- Switch ECDSA backend to **micro-ecc-compatible secp256k1** with RFC6979 (bundled).
- You can drop-in upstream `uECC.c/uECC.h` (BSD-2) under `vendor/microecc/` to use the official micro-ecc.


### Swap to official micro-ecc (upstream)
```
python3 scripts/vendor_microecc.py
cmake -S . -B build -DMIQ_USE_UPSTREAM_MICROECC=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```
This will compile against the **actual** upstream `uECC.c/uECC.h/uECC_vli.c/uECC_vli.h` (BSD-2). Your core remains under your license; keep upstream's BSD-2 notice for those files.

