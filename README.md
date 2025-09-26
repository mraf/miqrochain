miqrochain — C++ PoW node (single-binary)

Minimal Bitcoin-style UTXO blockchain in modern C++ with a bundled secp256k1 ECDSA implementation and a lightweight HTTP JSON-RPC server. One executable: miqrod.

Protocol & economics (as coded)

Ticker / unit: MIQ (smallest unit miqron = 1e-8 MIQ)

Hard cap: 26,280,000 MIQ (MAX_MONEY = 26,280,000 * COIN)

Block time target: 480 s (8 minutes)

Difficulty: LWMA over recent blocks (difficulty.cpp)

Initial subsidy: 50 MIQ (INITIAL_SUBSIDY)

Halving interval: 262,800 blocks (≈4 years at 8 min)

Coinbase maturity: 100 blocks

Address type: P2PKH, version byte 0x35 (addresses typically start with 5)

Network magic: 0xA3FB9E21 (4-byte header constant on the wire)

Default ports: P2P 443, RPC 9834 (see security notes)

ℹ️ Genesis behavior (important): On first boot, the node creates and stores a block at height 0 (“genesis”) with a single coinbase paying 50 MIQ to a genesis key. If GENESIS_ECDSA_PRIV_HEX is empty (default), a random 32-byte key is generated. That means each clean node will produce a different genesis unless you pin the same key everywhere. Peers with different genesis blocks will not interoperate.

What’s included

Consensus & validation

UTXO set with replay on load, coinbase maturity, value overflows prevented, max-money guards

LWMA difficulty; Median-Time-Past & future-time bounds

Low-S signature rule behind compile-time switch (MIQ_RULE_ENFORCE_LOW_S)

Size caps: block ≤ 1 MiB, tx ≤ 100 KiB

P2P (TCP)

Message framing with magic/command/length/checksum (netmsg.*)

INV/GETDATA/BLOCK/TX/ADDR, ping/pong, basic headers-first helpers

Token-bucket rate limits (blocks ~1 MB/s, tx ~256 KB/s, 2s bursts)

Orphan cache with bounded bytes & eviction, simple ban-score

Seed connect: one boot seed is used (DNS_SEED = 185.162.238.19)

Mining

Multi-threaded header hasher (SHA-256), SHA-NI fast path on x86

On each start (if mining enabled) it prompts for a mining address

RPC getminerstats for hashrate snapshots

RPC (HTTP JSON)

Endpoints:
getnetworkinfo, getblockchaininfo, getblockcount, getbestblockhash,
getblockhash, getblock (by height or hash),
getcoinbaserecipient (first output of coinbase), gettipinfo,
decodeaddress, getrawmempool, gettxout,
sendrawtransaction, getminerstats,
sendtoaddress (single-key, auto-fee & change)

Storage

Append-only blocks.dat with blocks.idx offsets and hash.map (hash→index)

state.dat persists tip hash/height/bits/time/issued

Security defaults (read before exposing)

RPC bind: by default binds 0.0.0.0:9834 (all interfaces).
Auth is off unless you set a token.

Enable auth: set MIQ_RPC_TOKEN (checked as Authorization: Bearer <token>).

Local-only modes:

MIQ_RPC_BIND_LOOPBACK=1 → bind 127.0.0.1 only

MIQ_RPC_LOCALONLY=1 → reject non-loopback remote peers even if bound wider

P2P port 443: on Linux, binding <1024 usually requires root. Consider running behind a firewall/NAT or changing the port at build time if needed.

Recommended for development:
Run RPC on localhost only and set a token:

export MIQ_RPC_BIND_LOOPBACK=1
export MIQ_RPC_TOKEN="superlongrandom"

Build
Windows (VS 2022)

Requirements: Visual Studio 2022 C++ Build Tools, CMake 3.20+, Windows SDK.

# From a "x64 Native Tools" shell in repo root
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release --target miqrod --parallel
.\build\Release\miqrod.exe --help


Optional tests:

cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DMIQ_BUILD_TESTS=ON
cmake --build build --config Release --target RUN_TESTS

Linux (GCC/Clang)
sudo apt-get update && sudo apt-get install -y build-essential cmake
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel --target miqrod
./build/miqrod --help

Running the node

Create a mining address (two options)

Quick via node:

./miqrod --genaddress
# prints: priv_hex=..., pub_hex=..., address=...


Or via tool (uses micro-ecc directly):

cmake --build build --target miq-keygen
./build/miq-keygen


Write a config file (note: --conf= uses equals, not a space)

# miq.conf
datadir=./miqdata
miner_threads=0          # 0 = auto (all logical CPUs)
no_p2p=0
no_rpc=0
no_mine=0
mining_address=5...      # Base58 P2PKH


Start

./build/miqrod --conf=miq.conf


Startup sequence (fresh data dir):

Initializes storage

Creates genesis (height 0) with 50 MIQ to the genesis key

Starts RPC (9834) and P2P (443), connects the single seed

Prompts for mining address (if no_mine=0)

RPC quickstart

Default URL: http://<host>:9834/ (POST, JSON body).
If MIQ_RPC_TOKEN is set, include header: Authorization: Bearer <token>.

Examples:

# Tip info
curl -s -H 'Content-Type: application/json' \
  -d '{"method":"gettipinfo","params":[]}' http://127.0.0.1:9834/

# Miner stats (hashes since last call, seconds, hps, total)
curl -s -H 'Content-Type: application/json' \
  -d '{"method":"getminerstats","params":[]}' http://127.0.0.1:9834/

# Send coins from a single private key (auto-fee & change)
curl -s -H 'Content-Type: application/json' \
  -d '{"method":"sendtoaddress","params":["<priv_hex>","<to_address>", 123456789]}' \
  http://127.0.0.1:9834/


Supported methods:
getnetworkinfo, getblockchaininfo, getblockcount, getbestblockhash, getblockhash,
getblock (height or hash), getcoinbaserecipient, gettipinfo, decodeaddress,
getrawmempool, gettxout, sendrawtransaction, getminerstats, sendtoaddress.

Data & files

datadir (default ./miqdata):

blocks.dat — append-only raw blocks

blocks.idx — u32 offsets into blocks.dat

hash.map — hash(hex) → block index

state.dat — tip hash/height/bits/time/issued

Wallet (helper store): %APPDATA%\miqro\wallets\…\wallet.kv (Windows helper for address persistence; node primarily asks interactively each run when mining)

P2P details

Header magic: 4 bytes (MAGIC), command (12 bytes, ASCII), length (LE u32), checksum (4 bytes of dSHA256(payload))

Commands implemented: version, verack, ping, pong, inv, getdata, block, tx, addr (+ scaffolding for headers)

Rate limits (per peer, token bucket):

Blocks ≈ 1 MB/s (burst 2 MB)

Tx ≈ 256 KB/s (burst 512 KB)

Orphans: cached with bounded memory & LRU-like eviction

Seed used at boot: 185.162.238.19 (the DNS_SEEDS[] list is present but not used on startup)

Known behaviors & caveats (current code)

Genesis must be pinned for a public network. With default empty GENESIS_ECDSA_PRIV_HEX, each node mints a different genesis block on first run → networks will not connect. To share a network, set the same 32-byte hex key in src/constants.h, rebuild, and start all nodes from a clean data dir.

RPC exposure is open by default (binds all interfaces, no auth). Use MIQ_RPC_BIND_LOOPBACK=1 and set MIQ_RPC_TOKEN before running anywhere untrusted.

P2P port 443 may require elevated privileges on Linux. If you don’t want that, change the constant and rebuild (or run behind NAT/port-forwarding).

Building tests

Enable with -DMIQ_BUILD_TESTS=ON:

test_crypto (ECDSA backend sanity)

test_ser (serializer)

fuzz_json (tiny JSON fuzzer)

License

Apache-2.0 for project code (see LICENSE).

Bundled/optional micro-ecc sources are BSD-2 (kept under their original license when fetched).
