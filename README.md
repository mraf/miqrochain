# miqrochain

> Updated overview generated 2025-09-27 from repository scan.

## Overview
A minimal, Bitcoin-inspired PoW blockchain in C++ with:

- Full node (validation, UTXO, mempool, miner, P2P, HTTP+JSON-RPC)
- Base58Check P2PKH addresses & ECDSA
- LWMA difficulty retarget
- CMake builds for Windows & Linux

## Chain Parameters

- BLOCK_TIME_SECS: **480**
- INITIAL_SUBSIDY: **50**
- HALVING_INTERVAL: **262800**
- COINBASE_MATURITY: **100**
- MAX_SUPPLY: **26.280.000**
- GENESIS_BITS: **0x1d00ffff**
- GENESIS_NONCE: **0xd3dda73c**
- GENESIS_TIME: **1758890000**
- GENESIS_HASH_HEX: **00000000a5e8a7eb02a83fb9693bc2dccbf14ee69d67315c1f151a25cb43fce8**
- GENESIS_MERKLE_HEX: **97a08487d57f8e55c4368308978703ad51e733df73950d4bcded07b8cdf3d2c5**
- P2P_PORT: **55001**
- RPC_PORT: **9834**

## Build
### Windows (MSVC)
```
cmake -S . -B build -A x64 -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j 8
```
### Linux
```
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j $(nproc)
```

## Run
Create `miq.conf`:
```
datadir=./miqdata
no_p2p=0
no_rpc=0
no_mine=0
miner_threads=2
```
Run:
```
./build/Release/miqrod --conf ./miq.conf
```

## RPC Methods (discovered)

`decoderawtx`, `getbestblockhash`, `getblock`, `getblockchaininfo`, `getblockcount`, `getblockhash`, `getchaintips`, `getcoinbaserecipient`, `getconnectioncount`, `getdifficulty`, `getminerstats`, `getnetworkinfo`, `getpeerinfo`, `getrawmempool`, `gettipinfo`, `gettxout`, `sendrawtransaction`, `sendtoaddress`, `validateaddress`

## Modules

- Chain/Validation: ✅
- UTXO: ✅
- Mempool: ✅
- Miner: ✅
- P2P: ✅
- HTTP: ✅
- RPC: ✅
- Serialization: ✅
- Hashes: ✅
- Base58: ✅
- Wallet store: ✅
- ECDSA: ✅
- Difficulty (LWMA): ✅
- Reorg manager: ✅
- Block storage/index: ✅
- Tests: ✅

## Security Defaults
- RPC binds to localhost by default; avoid WAN exposure.
- Use small request size caps and socket timeouts.
- Keep datadir secure; consider encrypting wallet secrets.


## Roadmap
- Wallet CLI (create/send, fees, change)
- RPC auth (cookie/token), rate limits, request caps
- GUI wrapper for Windows
- CI tests (ser/tx/difficulty)
