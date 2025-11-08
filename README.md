# Miqrochain

A compact, experimental blockchain node written in modern C++.

> **Wallet status:** wallets are still being forged and actively in progress. Expect breaking changes until the first tagged wallet preview.

---

## Quick Facts

- **P2P port:** `9883` (TCP)
- **RPC port:** `9834` (JSON-RPC over HTTP)
- **Default daemons:** `miqrod` (node), `miqwallet` (WIP)
- **Build:** CMake + C++17
- **Status:** Experimental (not production-ready)

---

## Table of Contents

- [Features](#features)
- [Build](#build)
  - [Linux / Ubuntu](#linux--ubuntu)
  - [Windows (MSVC)](#windows-msvc)
  - [macOS](#macos)
- [Quick Start](#quick-start)
  - [Run a node](#run-a-node)
  - [Use JSON-RPC](#use-json-rpc)
  - [Mining (testing only)](#mining-testing-only)
- [Configuration](#configuration)
  - [Command-line flags](#command-line-flags)
  - [Environment variables](#environment-variables)
- [Networking Notes](#networking-notes)
- [Data & Logs](#data--logs)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Security & Production Readiness](#security--production-readiness)
- [License](#license)

---

## Features

- Dual-stack networking (IPv4/IPv6), non-blocking sockets; hardened for Windows & POSIX
- Headers-first initial sync with automatic fallback to by-index on stalls
- Per-peer rate limiting; transaction trickle relay; fee filtering (min relay fee)
- Orphan block manager with memory/entry caps
- Optional peer address manager (if compiled in), legacy peer store compatibility
- NAT/UPnP try-open for friendlier home setups
- Minimal JSON-RPC interface for node control and inspection

> Source layout lives under `src/` (e.g., `p2p.*`, `chain.*`, `mempool.*`, `rpc.*`, `wallet/*` [WIP]).

---

## Build

### Prerequisites

- CMake ≥ 3.16
- A C++17 compiler
  - Linux/macOS: GCC ≥ 9 or Clang ≥ 10
  - Windows: Visual Studio 2019/2022 (MSVC)
- Standard system threads (pthread on POSIX; Win32 on Windows)

> If your environment uses a package manager, install **cmake** and a **C++ toolchain** first.

### Linux / Ubuntu

Tested on Ubuntu 20.04/22.04+.

```bash
# 1) Install toolchain
sudo apt update
sudo apt install -y build-essential cmake git

# 2) Clone
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain

# 3) Configure + build (Release)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j

# (optional) Install to /usr/local
# sudo cmake --install build
Windows (MSVC)
Requires Visual Studio with the Desktop development with C++ workload.

powershell

# Use "x64 Native Tools Command Prompt" or "Developer PowerShell for VS"
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain

cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
Artifacts will be under build\Release\.

macOS
Tested on macOS 12+ (Apple Silicon & Intel).

bash

# 1) Install Xcode command line tools
xcode-select --install

# 2) Install cmake via Homebrew (recommended)
brew install cmake

# 3) Clone + build
git clone https://github.com/takumichronen/miqrochain.git
cd miqrochain
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
Quick Start
Run a node
bash

# stores chain data in ./data, listens on P2P 9883 and RPC 9833
./build/miqrod --datadir ./data --p2p 9883 --rpc 9833
Keep RPC bound to 127.0.0.1 unless you know what you’re doing. If you expose it, protect it (auth, firewall, or a TLS reverse proxy).

Use JSON-RPC
From the same machine:

bash

# Basic chain info
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:9833

# Best block hash
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":2,"method":"getbestblockhash","params":[]}' \
  http://127.0.0.1:9833
Common methods (non-exhaustive):

getblockchaininfo, getnetworkinfo, getbestblockhash

getblock <hash|height>, getrawblock <hash|height>

getmempoolinfo, getrawmempool

submitblock <hex>, sendrawtransaction <hex>

peers, ban <ip>, unban <ip>, getbans

Mining helpers: setgenerate <on> <threads>, getminerstats

Mining (testing only)
bash

# Enable 2 mining threads (development/testing only)
curl -s -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"setgenerate","params":[true, 2]}' \
  http://127.0.0.1:9833
Configuration
Command-line flags
Flag	Description
--datadir <path>	Where to store chain state and logs (e.g., ./data).
--p2p <port>	P2P listen port (default used here: 9883).
--rpc <port>	RPC listen port (default used here: 9833).
--seed 1	Seed mode (reduced outbound target; also settable via env).
--upnp 1	Attempt to open the P2P port via UPnP/NAT-PMP.
--loglevel <lvl>	Adjust logging verbosity (if available in your build).

Run miqrod --help to see the exact flags exposed by your build.

Environment variables
Variable	Meaning
MIQ_IS_SEED=1	Enable seed mode (affects outbound connection targets).
MIQ_MIN_RELAY_FEE_RATE=<miqr/kB>	Local fee filter for transaction relay.
MIQ_SELF_IP=<ip1,ip2,...>	Mark local/self IPv4s to avoid self-dials/hairpins.

Networking Notes
Open/forward P2P TCP 9883 if you want to accept inbound peers.

RPC runs on TCP 9833. Keep it localhost-only unless you have strong protections.

The node avoids dialing loopback/self and limits outbound peers per /16 to reduce eclipse risk.

IPv4 and IPv6 are supported; sockets are non-blocking with keep-alive.

Ubuntu UFW example:

bash:

sudo ufw allow 9883/tcp     # P2P
# rpc is typically local only; if you must expose:
# sudo ufw allow from <your-ip> to any port 9833 proto tcp
Data & Logs
Chain data and logs live under --datadir (e.g., ./data).

Peer addresses persist to peers.dat / peers2.dat (if addrman is compiled in).

Bans are stored in bans.txt (supports permanent and timed entries).

Troubleshooting
No peers? Ensure TCP 9883 is reachable (firewall/NAT). Consider --upnp 1 for home networks. Give DNS seeds some time.

RPC errors? Confirm the node is running and you’re calling http://127.0.0.1:9833. Check logs under --datadir.

Sync stalls? The node auto-falls back from headers-first to by-index; ensure multiple peers and stable connectivity.

Contributing
PRs and issues are welcome! Please include:

OS & compiler (e.g., Ubuntu 22.04 + GCC 13, Windows 11 + MSVC 2022, macOS 14 + Apple Clang)

Exact build steps and relevant logs

Small, focused PRs for easier review

Security & Production Readiness
This repository is experimental.
Wallet components are in flux and not production-ready yet. Still being forged to work 100% with miqrochain and sending miq successfully.
