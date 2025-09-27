README — Windows Quickstart (MIQROCHAIN)

This guide helps you run a full node on Windows safely, with correct ports and locked-down RPC.

Defaults (confirmed)

RPC: 127.0.0.1:9834

P2P: 55001/tcp

Block time target: 8 minutes

Coinbase maturity: 100 blocks

Max supply: 26,280,000 MIQ

Difficulty: LWMA

Wallet: basic (keygen + send/receive); (advanced features WIP)

If you see any old docs that say P2P 442, ignore them. Use 55001.

1) Install & first run

Unzip the release somewhere like C:\miqrochain\.

(Recommended) Set an RPC token so tools can authenticate:

setx MIQ_RPC_TOKEN "PUT-A-LONG-RANDOM-TOKEN-HERE"
# Keep default: require token unless bound to loopback; to always require:
# setx MIQ_RPC_REQUIRE_TOKEN "1"


Start the node (PowerShell):

cd C:\miqrochain\build\Release
.\miqrod


If you use a config file:

.\miqrod --conf "C:\miqrochain\miq.conf"


Minimal miq.conf example:

# C:\miqrochain\miq.conf
datadir=C:\miqrochain\miqdata
rpc_port=9834
p2p_port=55001
# no_p2p=0
# no_rpc=0
# no_mine=0
# miner_threads=6


Tip: The node binds RPC to loopback by default. If you expose RPC beyond your PC, always keep a token and put RPC behind TLS (reverse proxy).

2) Allow through Windows Firewall (P2P only)

RPC is local-only by default; you don’t need a firewall rule for it.

To accept inbound peers:

New-NetFirewallRule -DisplayName "MIQ P2P 55001" -Direction Inbound -Protocol TCP -LocalPort 55001 -Action Allow


If you forward from your router, forward TCP 55001 → your PC.

3) RPC usage

Authenticated call (PowerShell):

$env:MIQ_RPC_TOKEN  # should show your token if set with setx and new shell
curl.exe -s -H @{"Authorization"="Bearer $env:MIQ_RPC_TOKEN";"Content-Type"="application/json"} `
  -d '{"method":"getblockcount","params":[]}' http://127.0.0.1:9834/


Alternate header supported:

X-Auth-Token: <your token>


Optional CORS for local web UIs (off by default). To enable:

setx MIQ_RPC_CORS "1"

4) Data directory

Default (if set in conf):

C:\miqrochain\miqdata


Typical layout:

miqdata\
  blocks\          # append-only block files
  chainstate\      # UTXO/state DB
  indexes\         # header/block indexes
  peers.dat        # (future) persisted peers/banlist
  miq.log          # node log (if enabled)
  miq.conf         # your config (optional)


Back up the wallet keys (if you generate any) and your miq.conf.

5) Mining (CPU, basic)

Use built-in miner via config:

no_mine=0
miner_threads=6


Or toggle at runtime via RPC (token required). Example:

curl.exe -s -H @{"Authorization"="Bearer $env:MIQ_RPC_TOKEN";"Content-Type"="application/json"} `
  -d '{"method":"getminerstats","params":[]}' http://127.0.0.1:9834/


You should see hashrate, template info, and tip height.

6) Safe remote access (optional)

If you must access RPC remotely:

Keep MIQ_RPC_TOKEN set (don’t use blank tokens).

Do not bind RPC on 0.0.0.0 directly to the internet.

Put it behind a TLS reverse proxy (e.g., Caddy/Nginx) with an allowlist/VPN.

7) Troubleshooting

“Unauthorized” → Set MIQ_RPC_TOKEN and send Authorization: Bearer <token> or X-Auth-Token.

Port mismatch → Ensure p2p_port=55001 everywhere (docs, conf, firewall, router).

“Unknown option: --conf” → Use the correct flag set for your build; or just run without --conf and place miq.conf in the data dir.

No peers → Open/forward TCP 55001; confirm you can reach DNS seeds; try adding a known peer via addnode RPC (if available).

8) Security model (quick)

RPC is loopback-only by default; token is required if bound wider.

Read-only RPC methods can be allowed without a token on loopback.

P2P accepts inbound on 55001/tcp; mine and relay blocks/txs.

9) Version & build info

C++17, single-binary node miqrod

JSON-RPC over minimal HTTP with rate limiting

LWMA difficulty, 8-minute targets

Coinbase maturity: 100
