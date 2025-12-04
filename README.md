# Miqrochain

<div align="center">

**A lightweight, high-performance blockchain implementation in modern C++17**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://isocpp.org/std/the-standard)
[![Platform](https://img.shields.io/badge/Platform-Linux%20|%20macOS%20|%20Windows-brightgreen.svg)](#build)

</div>

---

## Overview

Miqrochain is a compact, full-featured cryptocurrency node designed for efficiency and reliability. Built from the ground up with a focus on clean architecture and robust P2P networking, it provides everything needed to participate in the Miqrochain network.

### Key Highlights

- **Compact Codebase** - Single-binary node with ~10k lines of core consensus code
- **Headers-First IBD** - Fast initial sync with intelligent stall detection
- **Real-Time Dashboard** - Built-in TUI for monitoring sync, peers, and mempool
- **Separation of Concerns** - Mining is handled by external `miqminer_rpc` client
- **Prometheus Metrics** - Production-ready observability out of the box

---

## Quick Reference

| Component | Port | Description |
|-----------|------|-------------|
| **P2P** | 9883 | Peer-to-peer networking |
| **RPC** | 9834 | JSON-RPC API (localhost only) |
| **miqrod** | - | Full node daemon |
| **miqwallet** | - | Wallet CLI |
| **miqminer_rpc** | - | Standalone RPC miner |
| **miq-keygen** | - | Key generation utility |

### Network Economics

| Parameter | Value |
|-----------|-------|
| Block Time | 8 minutes |
| Initial Reward | 50 MIQ |
| Halving Interval | 262,800 blocks (~4 years) |
| Coinbase Maturity | 100 confirmations |
| Maximum Supply | 26,280,000 MIQ |

---

## Table of Contents

- [Build](#build)
- [Running the Node](#running-the-node)
  - [With TUI (Default)](#with-tui-default)
  - [Without TUI (Headless/Daemon Mode)](#without-tui-headlessdaemon-mode)
- [Mining](#mining)
- [JSON-RPC API](#json-rpc-api)
- [Configuration](#configuration)
- [Security](#security)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Build

### Prerequisites

| Requirement | Version |
|-------------|---------|
| CMake | 3.16+ |
| C++ Compiler | GCC 9+, Clang 10+, or MSVC 2019+ |
| OpenSSL | Development libraries |

LevelDB is bundled and built automatically.

### Linux (Ubuntu/Debian)

```bash
# Install dependencies
sudo apt update && sudo apt install -y build-essential cmake git libssl-dev

# Clone and build
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

### macOS

```bash
xcode-select --install
brew install cmake openssl

git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DOPENSSL_ROOT_DIR=$(brew --prefix openssl)
cmake --build build -j$(sysctl -n hw.ncpu)
```

### Windows (MSVC)

Use "x64 Native Tools Command Prompt" or "Developer PowerShell":

```powershell
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

### Build Output

| Binary | Location | Description |
|--------|----------|-------------|
| `miqrod` | `build/` | Node daemon |
| `miqwallet` | `build/` | Wallet CLI |
| `miqminer_rpc` | `build/` | Standalone miner |
| `miq-keygen` | `build/` | Key generator |

---

## Running the Node

### With TUI (Default)

The default mode displays an interactive terminal dashboard:

```bash
./build/miqrod --datadir ./data
```

The TUI shows:
- Sync progress (headers/blocks)
- Peer connections and health
- Mempool statistics
- Recent log messages
- Mining status

### Without TUI (Headless/Daemon Mode)

For servers, containers, or scripted environments, run without the TUI:

```bash
# Using command-line flag
./build/miqrod --datadir ./data --no-tui

# Or using environment variable
MIQ_NO_TUI=1 ./build/miqrod --datadir ./data
```

This outputs plain log messages to stderr, suitable for:
- **Systemd services** - Clean journalctl integration
- **Docker containers** - Standard log aggregation
- **CI/CD pipelines** - Machine-parseable output
- **Background daemons** - No terminal required

#### Systemd Service Example

```ini
[Unit]
Description=Miqrochain Node
After=network.target

[Service]
Type=simple
User=miqro
ExecStart=/opt/miqrochain/miqrod --datadir /var/lib/miqrochain --no-tui
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

#### Docker Example

```dockerfile
FROM ubuntu:22.04
COPY miqrod /usr/local/bin/
ENV MIQ_NO_TUI=1
ENTRYPOINT ["miqrod", "--datadir", "/data"]
```

---

## Mining

Mining is intentionally separated from the node for security and flexibility.

### Quick Start

```bash
# Terminal 1: Start node
./build/miqrod --datadir ./data

# Terminal 2: Generate address
./build/miq-keygen
# → Address: NAbc123...  Private Key: 5xyz...

# Terminal 3: Start mining
./build/miqminer_rpc --rpc http://127.0.0.1:9834 --address NAbc123... --threads 4
```

### Miner Options

| Flag | Description |
|------|-------------|
| `--rpc <url>` | Node RPC endpoint (default: `http://127.0.0.1:9834`) |
| `--address <addr>` | Reward address (starts with `N` or `M`) |
| `--threads <n>` | CPU threads (0 = auto-detect) |
| `--stratum <host:port>` | Connect to stratum pool |
| `--gpu` | Enable OpenCL GPU mining |

### Why Separate Mining?

- **Security** - Private keys never touch the node
- **Flexibility** - Mine remotely or on different hardware
- **Stability** - Miner crashes don't affect node operation
- **Simplicity** - Node focuses solely on consensus/networking

---

## JSON-RPC API

### Basic Usage

```bash
# Get blockchain info
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:9834

# Get peer info
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getpeerinfo","params":[]}' \
  http://127.0.0.1:9834
```

### RPC Methods

<details>
<summary><strong>Chain Methods</strong></summary>

| Method | Description |
|--------|-------------|
| `getblockchaininfo` | Chain height, difficulty, sync status |
| `getbestblockhash` | Current tip hash |
| `getblock <hash\|height>` | Full block data |
| `getblockheader <hash\|height>` | Header only |
| `gettxout <txid> <vout>` | UTXO lookup |

</details>

<details>
<summary><strong>Network Methods</strong></summary>

| Method | Description |
|--------|-------------|
| `getnetworkinfo` | Node version, connections |
| `getpeerinfo` | Detailed peer list |
| `peers` | Simple peer list |
| `getnodeinfo` | Comprehensive node status |

</details>

<details>
<summary><strong>Mempool Methods</strong></summary>

| Method | Description |
|--------|-------------|
| `getmempoolinfo` | Size, bytes, fee stats |
| `getrawmempool` | Transaction ID list |
| `sendrawtransaction <hex>` | Broadcast transaction |

</details>

<details>
<summary><strong>Mining Methods</strong></summary>

| Method | Description |
|--------|-------------|
| `getblocktemplate` | Template for miners |
| `submitblock <hex>` | Submit mined block |
| `getminerstats` | Hash rate statistics |

</details>

<details>
<summary><strong>BIP158 Filter Methods</strong></summary>

| Method | Description |
|--------|-------------|
| `getcfilterheaders <start> <count>` | Filter header chain |
| `getcfilter <start> <count>` | Compact block filters |
| `getfiltercount` | Number of indexed filters |

</details>

<details>
<summary><strong>Admin Methods</strong></summary>

| Method | Description |
|--------|-------------|
| `ban <ip>` / `unban <ip>` | Manage peer bans |
| `getbans` | List banned peers |
| `stop` | Shutdown node |

</details>

### Prometheus Metrics

```bash
curl http://127.0.0.1:9834/metrics
```

Key metrics: `miq_chain_height`, `miq_peers_count`, `miq_mempool_txs`, `miq_blocks_validated_total`

---

## Configuration

### Command-Line Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--datadir <path>` | `./data` | Data directory |
| `--p2p <port>` | `9883` | P2P listen port |
| `--rpc <port>` | `9834` | RPC listen port |
| `--rpc-bind <ip>` | `127.0.0.1` | RPC bind address |
| `--no-tui` | - | Disable TUI dashboard |
| `--upnp 1` | - | Enable UPnP port mapping |
| `--seed 1` | - | Run as seed node |
| `--reindex` | - | Rebuild UTXO set |
| `--network <net>` | `mainnet` | mainnet/testnet/regtest |
| `--loglevel <n>` | - | Verbosity (0=trace to 5=fatal) |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `MIQ_NO_TUI=1` | Disable TUI |
| `MIQ_RPC_TOKEN=<token>` | RPC authentication token |
| `MIQ_SEED_HOST=<host>` | Override DNS seed |
| `MIQ_IS_SEED=1` | Enable seed mode |
| `MIQ_SELF_IP=<ip1,ip2>` | Self IP addresses |

### Networks

| Network | P2P Port | RPC Port | Use Case |
|---------|----------|----------|----------|
| mainnet | 9883 | 9834 | Production |
| testnet | 19883 | 19834 | Public testing |
| regtest | 29883 | 29834 | Local development |

```bash
# Testnet
./build/miqrod --datadir ./testnet-data --network testnet

# Regtest (instant mining)
./build/miqrod --datadir ./regtest-data --network regtest
```

---

## Security

### Quick Checklist

- [ ] RPC bound to `127.0.0.1` only (default)
- [ ] P2P port (9883) open for network participation
- [ ] RPC port (9834) blocked from internet
- [ ] Node running as non-root user

### RPC Authentication

**Cookie-based** (auto-generated):
```bash
curl -u "$(cat data/.cookie)" http://127.0.0.1:9834/...
```

**Token-based** (for remote access):
```bash
export MIQ_RPC_TOKEN="your-secret-token"
./build/miqrod --datadir ./data
# Use: curl -H "Authorization: Bearer your-secret-token" ...
```

### Firewall Example (UFW)

```bash
sudo ufw allow 9883/tcp   # P2P (required for network)
sudo ufw deny 9834/tcp    # Block remote RPC access
```

For comprehensive security documentation, see **[FIREWALL.md](FIREWALL.md)**.

---

## Architecture

```
src/
├── main.cpp           # Node entry + TUI
├── chain.cpp          # Consensus state machine
├── p2p.cpp            # P2P networking layer
├── rpc.cpp            # JSON-RPC server
├── mempool.cpp        # Transaction pool
├── utxo_kv.cpp        # UTXO database (LevelDB)
├── filters/           # BIP158 compact filters
├── wallet/            # Wallet components
└── cli/
    ├── miqwallet.cpp  # Wallet CLI
    └── miqminer_rpc.cpp  # Standalone miner
```

### Data Directory

```
data/
├── blocks/            # Raw block storage
├── chainstate/        # UTXO set (LevelDB)
├── filters/           # BIP158 filter cache
├── peers.dat          # Known peer addresses
├── bans.txt           # Banned peer list
└── debug.log          # Node logs
```

---

## Contributing

Contributions are welcome! Please:

1. Open an issue to discuss significant changes
2. Include OS/compiler version in bug reports
3. Keep PRs focused and well-tested

---

## License

MIT License - see [LICENSE](LICENSE) for details.
