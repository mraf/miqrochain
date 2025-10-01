# Miqrochain Core (MIQ)

Miqrochain Core is the reference implementation of the **MIQ** peer‑to‑peer cryptocurrency. It includes:

- A full validating node (`miqrod`) with JSON‑RPC
- A wallet (HD, P2PKH) with optional at‑rest encryption
- A built‑in CPU miner
- Utility tools (e.g., `miq-keygen` for address generation)

**Default ports**

- P2P: `9833/tcp`
- JSON‑RPC: `9834/tcp`

Miqrochain Core uses **libsecp256k1** (the Bitcoin Core secp256k1 library) for ECDSA. The build system will automatically fetch it at configure time if a system package is not available. LevelDB is used by default for the chainstate (RocksDB optional).

---

## What is Miqrochain?

Miqrochain (MIQ) is a Proof‑of‑Work blockchain with:
- Block target: **8 minutes**
- Consensus: **SHA‑256 PoW**
- Initial block subsidy: **50 MIQ**
- Coinbase maturity: **100 blocks**
- Supply cap & halving schedule defined in `src/constants.h`

The repository ships a **fixed genesis**. Nodes compiled from this repo (unmodified constants) all join the same public MIQ network.

---

## License

Miqrochain Core is open source under the **MIT** license. See `LICENSE`.

---

## Quick start (build & run)

```bash
# Linux/macOS (Release build)
git clone <your-repo-url> miqrochain
cd miqrochain
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --parallel

# Start node without networking/mining/RPC (smoke test)
./miqrod --no_p2p=1 --no_mine=1 --no_rpc=1

# Generate an address for mining or receiving funds
./miqrod --genaddress
# or
./miq-keygen
```

Windows instructions are in the next section.

---

## Build prerequisites

**Required**
- CMake ≥ 3.16
- A C++17 compiler (GCC/Clang/MSVC)
- OpenSSL (libcrypto, libssl)
- POSIX threads (Linux/macOS) or Win32 (Windows)

**Bundled / auto‑fetched**
- **libsecp256k1** (Bitcoin Core): fetched via CMake `FetchContent` if not found on the system
- **LevelDB** (system or auto‑fetch; RocksDB optional)

> Meson/Autotools are **not** required for libsecp; CMake fetches and builds it for you.

---

## Building from source

### Linux/macOS

```bash
# 0) Install OpenSSL headers via your package manager
#    Ubuntu/Debian: sudo apt-get install -y build-essential cmake pkg-config libssl-dev
#    Fedora:        sudo dnf install -y cmake gcc-c++ openssl-devel
#    macOS (brew):  brew install cmake openssl@3

# 1) Configure
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..

# 2) Build
cmake --build . --parallel

# 3) Binaries
#   build/miqrod      -> daemon (node + miner + RPC)
#   build/miq-keygen  -> address generator
```

### Windows (MSVC)

```powershell
# 0) Prereqs: Visual Studio 2022 (Desktop C++), CMake, OpenSSL (vcpkg recommended)

# 1) Configure + build
mkdir build; cd build
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --parallel

# 2) Binaries:
#   build\Release\miqrod.exe
#   build\Release\miq-keygen.exe
```

**Notes**
- The build will try to use a system `secp256k1` if present (vcpkg/Conan, etc.). Otherwise, it fetches the official bitcoin‑core repo at the configured tag and builds it as part of your tree.
- If you’re offline on first configure, provide `secp256k1` locally or re‑run configure when online.

---

## Initial configuration

You can run `miqrod` with flags or a config file. A typical `miq.conf`:

```
# miq.conf
# Data directory (recommended to set explicitly)
datadir=/var/lib/miq

# Networking
no_p2p=0
p2p_port=9833
# Bootstrap peers (example):
addnode=seed1.yourdomain.example:9833
addnode=seed2.yourdomain.example:9833

# RPC
no_rpc=0
rpc_bind=127.0.0.1:9834

# Mining
no_mine=0
miner_threads=4
# Set your coinbase recipient (P2PKH)
# Alternatively set env: MIQ_MINING_ADDR=...
mining_addr=YOUR_MIQ_ADDRESS
```

**Windows**: paths like `C:\miq\miq.conf` work the same.

---

## Running the node

Examples:

```bash
# Point to explicit datadir and conf:
./miqrod --conf /etc/miq/miq.conf

# Minimal local test (no peers/mining/RPC):
./miqrod --no_p2p=1 --no_mine=1 --no_rpc=1
```

The node logs to stdout and its datadir. Use `--help` for all flags.

---

## Generating addresses

Two equivalent ways:

```bash
# 1) Built into the daemon:
./miqrod --genaddress

# 2) Standalone tool:
./miq-keygen
```

Both print a **P2PKH** address and a 32‑byte private key hex. Keep your private key safe.

---

## Mining

1) Make or pick a payout address (above).  
2) Ensure you have at least one peer (public seed, `-addnode`, or port‑forwarding).  
3) Start the node with mining enabled:

```bash
# Example: 6 threads, explicit coinbase recipient via env
export MIQ_MINING_ADDR=<YOUR_MIQ_ADDRESS>
./miqrod --miner_threads=6
```

**Heads‑up**: mining without peers can put you on a partition; later, the chain with the most cumulative work wins and your blocks could be orphaned. Connect peers **first**, then mine.

---

## JSON‑RPC examples

Default RPC bind: `127.0.0.1:9834`. POST JSON to `/`.

```bash
# Chain tip info
curl -s -H "Content-Type: application/json" \
  -d '{"method":"gettipinfo","params":[]}' http://127.0.0.1:9834/

# List your known addresses (if wallet loaded)
curl -s -H "Content-Type: application/json" \
  -d '{"method":"listaddresses","params":[]}' http://127.0.0.1:9834/

# Get wallet info (balances, etc.)
curl -s -H "Content-Type: application/json" \
  -d '{"method":"getwalletinfo","params":[]}' http://127.0.0.1:9834/

# Create and send from HD (example)
curl -s -H "Content-Type: application/json" \
  -d '{"method":"sendfromhd","params":["<dest_addr>", 100000]}' \
  http://127.0.0.1:9834/

# Temporarily unlock wallet (if encryption enabled at build)
curl -s -H "Content-Type: application/json" \
  -d '{"method":"walletunlock","params":["passphrase", 60]}' \
  http://127.0.0.1:9834/
```

> RPC set may evolve; run `--help` or consult `src/rpc.cpp` for current methods and parameters.

---

## Wallet encryption (optional)

If compiled with `-DMIQ_ENABLE_WALLET_ENC=ON`, the wallet supports at‑rest encryption (OpenSSL). Typical flow:

1. Encrypt or set passphrase via RPC (see wallet methods in `src/rpc.cpp`).  
2. Use `walletunlock <passphrase> <timeout_seconds>` to cache a passphrase for signing/spending.  
3. `walletlock` to clear cache.

If built **without** wallet encryption (default), these RPCs are no‑ops.

---

## Networking

- **P2P port**: 9833/tcp. Open or port‑forward this on your router for a public node.  
- **RPC port**: 9834/tcp (binds to loopback by default).  
- Seeds / bootstrapping are defined in `src/seeds.cpp`. You can add bootstrap DNS names or IPs.

Optional UPnP/NAT‑PMP support is available with `-DMIQ_ENABLE_UPNP=ON` if `miniupnpc` is installed.

---

## Data directories

Use `--datadir=/path/to/miqdata` or set `datadir=` in `miq.conf`.

- **Linux**: e.g., `/var/lib/miq`, `~/.miq`  
- **Windows**: e.g., `C:\miqdata`

The chainstate, blocks, wallet store, and logs live under the datadir.

---

## Testing

Enable with `-DMIQ_BUILD_TESTS=ON`:

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -DMIQ_BUILD_TESTS=ON ..
cmake --build . --parallel
ctest --output-on-failure
```

---

## Security disclosure

If you discover a security issue, **please report it responsibly**. Avoid opening a public issue for vulnerabilities. Contact the maintainers privately (e.g., via the repository’s security policy or a dedicated security contact).

---

## Contributing

PRs are welcome. Please keep changes focused and avoid consensus‑affecting modifications without prior discussion. Prefer modern C++17, small focused commits, green CI, and changes that do not break existing RPC or network behavior unless explicitly intended.

---

### Troubleshooting

- **Genesis deserialization failed / exits on boot**  
  Ensure you are building this repo **unmodified** (the pinned `GENESIS_RAW_BLOCK_HEX` in `src/constants.h` is correct). If you have local edits, the serialized length must match exactly.

- **Address generation appears “stuck”**  
  The project uses **libsecp256k1**; keygen is instant in Release. If you see a hang, confirm you’re running `miqrod --genaddress` or `miq-keygen` and not inadvertently starting the miner.

- **“Connection refused” on RPC**  
  Start with `no_rpc=0` or omit it; ensure `rpc_bind` is correct (default `127.0.0.1:9834`) and your client connects to the same host/port.
