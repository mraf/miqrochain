# Miqrochain

A compact blockchain codebase written in modern C++.

> **Status:** Core node is stable. Wallet is in active development to become fully stable.

---

## Quick Facts

| Component | Description |
|-----------|-------------|
| **P2P Port** | `9883` (TCP) |
| **RPC Port** | `9834` (JSON-RPC over HTTP) |
| **Node Daemon** | `miqrod` |
| **Wallet** | `miqwallet` (WIP) |
| **Miner** | `miqminer_rpc` (standalone RPC miner) |
| **Key Generator** | `miq-keygen` |
| **Build System** | CMake + C++17 |

---

## Table of Contents

- [Features](#features)
- [Build](#build)
  - [Linux / Ubuntu](#linux--ubuntu)
  - [Windows (MSVC)](#windows-msvc)
  - [macOS](#macos)
- [Quick Start](#quick-start)
  - [Run a Node](#run-a-node)
  - [Mining](#mining)
  - [JSON-RPC API](#json-rpc-api)
- [Configuration](#configuration)
- [Architecture](#architecture)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

---

## Features

### Networking
- Dual-stack IPv4/IPv6 with non-blocking sockets
- Headers-first initial block download (IBD) with stall detection
- Per-peer rate limiting and transaction trickle relay
- NAT/UPnP port mapping for home setups
- Peer address manager with persistence

### Consensus & Validation
- LWMA difficulty adjustment algorithm
- Full UTXO set tracking with LevelDB backend
- Orphan block management with memory caps
- Chain reorganization handling with metrics

### Wallet (WIP)
- HD key derivation (BIP32-style)
- BIP158 compact block filter support for SPV
- Encrypted wallet storage (optional)
- Multi-endpoint RPC failover

### Monitoring & Observability
- Prometheus-compatible metrics export (`/metrics`)
- Real-time TUI dashboard in `miqrod`
- Operator metrics: peer stalls, bans, reorgs, validation times
- JSON metrics API for dashboards

### Mining
- Standalone `miqminer_rpc` client (connects via RPC)
- Stratum protocol support
- Multi-threaded CPU mining
- Optional OpenCL GPU support

---

## Build

### Prerequisites

- CMake ≥ 3.16
- C++17 compiler (GCC ≥ 9, Clang ≥ 10, or MSVC 2019+)
- OpenSSL development libraries
- LevelDB (bundled)

### Linux / Ubuntu

```bash
# Install dependencies
sudo apt update
sudo apt install -y build-essential cmake git libssl-dev

# Clone and build
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

Binaries will be in `build/`:
- `miqrod` - Node daemon
- `miqwallet` - Wallet CLI
- `miqminer_rpc` - Standalone miner
- `miq-keygen` - Key generation tool

### Windows (MSVC)

Use "x64 Native Tools Command Prompt" or "Developer PowerShell for VS":

```powershell
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Artifacts will be in `build\Release\`.

### macOS

```bash
# Install Xcode CLI tools and cmake
xcode-select --install
brew install cmake openssl

# Build
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
cmake --build build -j
```

---

## Quick Start

### Run a Node

```bash
# Start node with data in ./data directory
./build/miqrod --datadir ./data --p2p 9883 --rpc 9834
```

The node will:
- Listen for P2P connections on port 9883
- Serve RPC on 127.0.0.1:9834 (localhost only by default)
- Display a real-time TUI dashboard

### Mining

Mining is done with the standalone `miqminer_rpc` client:

```bash
# Generate a mining address first
./build/miq-keygen

# Start mining (connects to local node RPC)
./build/miqminer_rpc --rpc http://127.0.0.1:9834 --address <your-address> --threads 4
```

Options:
- `--rpc <url>` - Node RPC endpoint
- `--address <addr>` - Reward address (base58check)
- `--threads <n>` - Number of mining threads (0 = auto)
- `--stratum <host:port>` - Connect to stratum pool instead

### JSON-RPC API

```bash
# Get blockchain info
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:9834

# Get best block hash
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:9834
```

#### Available RPC Methods

**Chain:**
- `getblockchaininfo` - Chain height, difficulty, sync status
- `getbestblockhash` - Current tip hash
- `getblock <hash|height>` - Block data
- `getblockheader <hash|height>` - Header only
- `gettxout <txid> <vout>` - UTXO lookup

**Network:**
- `getnetworkinfo` - Node version, connections
- `getpeerinfo` - Connected peers detail
- `peers` - Simple peer list
- `getnodeinfo` - Comprehensive node status

**Mempool:**
- `getmempoolinfo` - Size, bytes, fee stats
- `getrawmempool` - List of txids
- `sendrawtransaction <hex>` - Broadcast transaction

**Mining:**
- `getblocktemplate` - Template for mining
- `submitblock <hex>` - Submit mined block
- `getminerstats` - Hash rate statistics

**BIP158 Filters:**
- `getcfilterheaders <start> <count>` - Filter header chain
- `getcfilter <start> <count>` - Compact block filters
- `getfiltercount` - Number of indexed filters

**Admin:**
- `ban <ip>` / `unban <ip>` - Manage bans
- `getbans` - List banned peers
- `stop` - Shutdown node

---

## Configuration

### Command-Line Flags

| Flag | Description |
|------|-------------|
| `--datadir <path>` | Data directory (default: `./data`) |
| `--p2p <port>` | P2P listen port (default: 9883) |
| `--rpc <port>` | RPC listen port (default: 9834) |
| `--rpc-bind <ip>` | RPC bind address (default: 127.0.0.1) |
| `--upnp 1` | Enable UPnP port mapping |
| `--seed 1` | Run in seed mode |
| `--reindex` | Rebuild UTXO set from blocks |
| `--loglevel <n>` | Log verbosity (0=trace, 5=fatal) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `MIQ_IS_SEED=1` | Enable seed node mode |
| `MIQ_MIN_RELAY_FEE_RATE=<rate>` | Minimum relay fee (miqr/kB) |
| `MIQ_SELF_IP=<ip1,ip2>` | Self IP addresses (prevent self-dial) |

---

## Architecture

```
src/
├── main.cpp          # Node entry point with TUI
├── chain.h/cpp       # Blockchain state machine
├── block.h           # Block/header structures
├── tx.h              # Transaction structures
├── mempool.h/cpp     # Transaction pool
├── p2p.h/cpp         # P2P networking layer
├── rpc.h/cpp         # JSON-RPC server
├── metrics.h         # Prometheus metrics
├── utxo_kv.h/cpp     # UTXO database (LevelDB)
├── filters/          # BIP158 compact block filters
├── wallet/           # Wallet components (WIP)
└── cli/
    └── miqminer_rpc.cpp  # Standalone miner
```

### Data Directory Structure

```
data/
├── blocks/           # Raw block storage
├── chainstate/       # UTXO set (LevelDB)
├── filters/          # BIP158 filter cache
├── peers.dat         # Known peer addresses
├── bans.txt          # Banned peer list
└── debug.log         # Node logs
```

---

## Security

### RPC Security

⚠️ **Warning:** RPC is unauthenticated by default. Always:

1. Bind to localhost only (`--rpc-bind 127.0.0.1`)
2. Use firewall rules if exposing remotely
3. Consider a reverse proxy with TLS for production

```bash
# UFW example - allow P2P, restrict RPC
sudo ufw allow 9883/tcp           # P2P
sudo ufw deny 9834/tcp            # Block remote RPC
```

### Cookie Authentication

For local auth, the node can use cookie-based authentication:
```
data/.cookie    # Auto-generated auth token
```

---

## Metrics

The node exports Prometheus-compatible metrics:

```bash
curl http://127.0.0.1:9834/metrics
```

Key metrics:
- `miq_chain_height` - Current block height
- `miq_peers_count` - Connected peers
- `miq_mempool_txs` - Mempool transaction count
- `miq_blocks_validated_total` - Blocks validated
- `miq_peer_stalls_total` - Peer stall events
- `miq_reorgs_total` - Chain reorganizations

---

## Contributing

PRs and issues welcome! Please include:
- OS & compiler version
- Build steps and logs
- Small, focused changes

---

## License

MIT License - see LICENSE file.
