# Miqrochain Firewall & Network Security Guide

This document provides comprehensive guidance for securing your Miqrochain node deployment.

## Quick Reference

| Port | Service | Protocol | Default Binding | Recommended Firewall Rule |
|------|---------|----------|-----------------|---------------------------|
| 9883 | P2P     | TCP      | 0.0.0.0         | Allow from internet       |
| 9834 | RPC     | HTTP     | 127.0.0.1       | Block from internet       |

---

## RPC Security

### Default Configuration

By default, the RPC server binds to `127.0.0.1:9834`, which means:
- Only local connections are accepted
- Remote machines cannot access RPC directly
- This is the recommended configuration for most deployments

### RPC Authentication

Miqrochain supports multiple RPC authentication methods:

#### 1. Cookie-Based Authentication (Recommended for Local)

The node automatically generates a cookie file at `<datadir>/.cookie` on startup:

```bash
# Cookie file format: __cookie__:random_password
cat ./data/.cookie
```

Use the cookie for local RPC calls:

```bash
# Read cookie and use for authentication
COOKIE=$(cat ./data/.cookie)
curl -u "$COOKIE" -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}' \
  http://127.0.0.1:9834
```

#### 2. Token-Based Authentication (For Remote Access)

Set the `MIQ_RPC_TOKEN` environment variable:

```bash
export MIQ_RPC_TOKEN="your-secret-token"
./build/miqrod --datadir ./data
```

Then use the token in requests:

```bash
curl -H 'content-type: application/json' \
  -H 'Authorization: Bearer your-secret-token' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo"}' \
  http://127.0.0.1:9834
```

#### 3. No Authentication (Local Only - Default)

For localhost-only access, authentication is optional but recommended for production.

### Binding RPC to External Interface

**Warning:** Only do this if you understand the security implications.

```bash
# Bind RPC to all interfaces (dangerous without auth!)
./build/miqrod --datadir ./data --rpc-bind 0.0.0.0

# Bind to specific interface
./build/miqrod --datadir ./data --rpc-bind 192.168.1.100
```

Always use token authentication when binding to external interfaces:

```bash
export MIQ_RPC_TOKEN="strong-random-token-here"
./build/miqrod --datadir ./data --rpc-bind 0.0.0.0
```

---

## Firewall Configuration

### Linux (UFW)

```bash
# Allow P2P from anywhere
sudo ufw allow 9883/tcp comment "Miqrochain P2P"

# Block RPC from external (redundant if binding to localhost)
sudo ufw deny 9834/tcp comment "Miqrochain RPC - block external"

# Enable firewall
sudo ufw enable
sudo ufw status
```

### Linux (iptables)

```bash
# Allow P2P
sudo iptables -A INPUT -p tcp --dport 9883 -j ACCEPT

# Allow RPC only from localhost
sudo iptables -A INPUT -p tcp --dport 9834 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9834 -j DROP

# Save rules (Debian/Ubuntu)
sudo iptables-save > /etc/iptables/rules.v4
```

### Linux (firewalld - CentOS/RHEL)

```bash
# Allow P2P
sudo firewall-cmd --permanent --add-port=9883/tcp

# Reload
sudo firewall-cmd --reload

# Verify
sudo firewall-cmd --list-ports
```

### Windows Firewall (PowerShell)

Run as Administrator:

```powershell
# Allow P2P inbound
New-NetFirewallRule -DisplayName "Miqrochain P2P" `
  -Direction Inbound -Protocol TCP -LocalPort 9883 -Action Allow

# Block RPC from external
New-NetFirewallRule -DisplayName "Miqrochain RPC Block" `
  -Direction Inbound -Protocol TCP -LocalPort 9834 -Action Block

# Verify rules
Get-NetFirewallRule -DisplayName "Miqrochain*" | Format-Table
```

To remove rules:

```powershell
Remove-NetFirewallRule -DisplayName "Miqrochain P2P"
Remove-NetFirewallRule -DisplayName "Miqrochain RPC Block"
```

### macOS (pf)

Edit `/etc/pf.conf`:

```
# Allow P2P
pass in on en0 proto tcp from any to any port 9883

# Block RPC from external
block in on en0 proto tcp from any to any port 9834
```

Apply rules:

```bash
sudo pfctl -f /etc/pf.conf
sudo pfctl -e
```

---

## Reverse Proxy (Production Deployment)

For production deployments requiring remote RPC access, use a reverse proxy with TLS.

### Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name rpc.example.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        # Rate limiting
        limit_req zone=rpc burst=20 nodelay;

        # Authentication (basic auth example)
        auth_basic "Miqrochain RPC";
        auth_basic_user_file /etc/nginx/.htpasswd;

        # Proxy to local RPC
        proxy_pass http://127.0.0.1:9834;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
    }
}

# Rate limiting zone (in http block)
limit_req_zone $binary_remote_addr zone=rpc:10m rate=10r/s;
```

### Create htpasswd file

```bash
sudo apt install apache2-utils
htpasswd -c /etc/nginx/.htpasswd rpcuser
```

---

## Docker Deployment

### docker-compose.yml

```yaml
version: '3.8'
services:
  miqrod:
    image: miqrochain/miqrod:latest
    container_name: miqrod
    ports:
      - "9883:9883"  # P2P - exposed
      # RPC not exposed externally
    volumes:
      - ./data:/data
    environment:
      - MIQ_RPC_TOKEN=${MIQ_RPC_TOKEN}
    restart: unless-stopped
    command: ["--datadir", "/data", "--rpc-bind", "0.0.0.0"]
    networks:
      - miq-internal

  # Only if you need external RPC access
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - miqrod
    networks:
      - miq-internal

networks:
  miq-internal:
    internal: false
```

---

## P2P Network Security

### Connection Limits

The node enforces several connection limits to prevent DoS:

| Limit | Value | Description |
|-------|-------|-------------|
| `MIQ_MAX_INBOUND_CONNECTIONS` | 125 | Max inbound peers |
| `MIQ_MAX_OUTBOUND_CONNECTIONS` | 12 | Max outbound peers |
| `MIQ_MAX_SAME_IP_CONNECTIONS` | 3 | Max connections per IP |
| `MIQ_MAX_SUBNET24_CONNECTIONS` | 6 | Max connections per /24 subnet |

### Ban Management

Peers are banned for misbehavior:

| Action | Ban Score | Description |
|--------|-----------|-------------|
| Invalid block | 100 | Immediate ban |
| Invalid header | 100 | Immediate ban |
| Header flooding | 50 | Progressive ban |
| Stalled sync | 20 | After timeout |

Ban duration: 24 hours (configurable via `MIQ_BAN_DURATION_SECS`)

### Manual Ban/Unban

Via RPC:

```bash
# Ban an IP
curl -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"ban","params":["192.168.1.100"]}' \
  http://127.0.0.1:9834

# Unban an IP
curl -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"unban","params":["192.168.1.100"]}' \
  http://127.0.0.1:9834

# List bans
curl -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"listbanned","params":[]}' \
  http://127.0.0.1:9834
```

---

## Security Checklist

### Minimum Security

- [ ] RPC bound to 127.0.0.1 only
- [ ] P2P port (9883) open
- [ ] RPC port (9834) blocked from internet
- [ ] Node running as non-root user

### Production Security

- [ ] All of the above
- [ ] RPC token authentication enabled
- [ ] Reverse proxy with TLS for remote RPC
- [ ] Rate limiting on RPC
- [ ] Monitoring and alerting configured
- [ ] Regular backups of wallet data
- [ ] Firewall rules audited

### High-Security Deployment

- [ ] All of the above
- [ ] Dedicated machine/VM
- [ ] Network segmentation
- [ ] Intrusion detection (fail2ban, etc.)
- [ ] Log aggregation and analysis
- [ ] Regular security updates

---

## Monitoring

### Prometheus Metrics

The node exports metrics at `http://127.0.0.1:9834/metrics`:

```bash
curl http://127.0.0.1:9834/metrics
```

Key security-related metrics:

- `miq_peer_bans_total` - Total bans issued
- `miq_peer_stalls_total` - Peer stall events
- `miq_peers_count` - Current peer count
- `miq_blocks_rejected_total` - Rejected blocks

### Log Monitoring

Important log entries to monitor:

```
P2P: banned <ip> for <reason>
P2P: peer <ip> stalled
RPC: auth failed from <ip>
Chain: reorg detected (depth=N)
```

---

## Troubleshooting

### Cannot connect to RPC

1. Check binding: `netstat -tlnp | grep 9834`
2. Check firewall: `sudo ufw status` or `iptables -L`
3. Verify token: `echo $MIQ_RPC_TOKEN`

### Too few peers

1. Check P2P port is open: `netstat -tlnp | grep 9883`
2. Check firewall allows 9883
3. Check not behind strict NAT
4. Enable UPnP: `--upnp 1`

### Peer keeps getting banned

Check ban list and reason:

```bash
curl -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"listbanned","params":[]}' \
  http://127.0.0.1:9834
```

---

## Network Ports Summary

| Network | P2P Port | RPC Port |
|---------|----------|----------|
| Mainnet | 9883     | 9834     |
| Testnet | 19883    | 19834    |
| Regtest | 29883    | 29834    |
