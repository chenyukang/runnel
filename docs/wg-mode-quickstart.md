# `pipit` WG Mode Quickstart

This note covers the experimental `wg-client` / `wg-server` path built on `boringtun`.

The goal is to make a first real smoke test repeatable without hand-writing keys or accidentally installing routes before checking the plan.

## Generate A Paired Config

Run this on your local machine and replace the endpoint with the public server IP and UDP port:

```bash
pipit wg-config \
  --server-endpoint 203.0.113.10:51820 \
  --client-tunnel-ip 10.8.0.2 \
  --server-tunnel-ip 10.8.0.1 \
  --dns 1.1.1.1 \
  --dns-capture \
  --exclude-lan \
  --nat-out-interface eth0
```

The command prints two YAML sections:

- `wg_client`: use this on the client machine.
- `wg_server`: use this on the server machine.

Use `--json` if another tool needs to consume the generated material.

## Check Before Running

Before creating devices or touching routes, run both sides with `--dry-run` or `--print-hooks`.

Client:

```bash
pipit --config pipit.wg.client.yaml wg-client --dry-run
```

Server:

```bash
pipit --config pipit.wg.server.yaml wg-server --dry-run
```

This validates keys, endpoint parsing, allowed IPs, and prints the hook plan. It does not create the TUN device.

## Run

Server first:

```bash
sudo pipit --config pipit.wg.server.yaml wg-server
```

Client second:

```bash
sudo pipit --config pipit.wg.client.yaml wg-client
```

`wg-client` defaults to full-tunnel IPv4 routing through `0.0.0.0/0`, which is installed as split routes internally. The server endpoint gets a bypass route so the encrypted UDP transport does not loop into the tunnel.

Startup performs a preflight before creating the device or running hooks. It checks the platform tools and privileges needed for the selected role, for example `/dev/net/tun`, `ip`, `sysctl`, and `iptables` on Linux, and `ifconfig`, `route`, and `networksetup` on macOS. `--dry-run` still skips privileged preflight so plans can be inspected as a normal user.

## Split Tunnel And Exclusions

Only proxy specific CIDRs:

```bash
pipit --config pipit.wg.client.yaml wg-client \
  --allowed-ip 203.0.113.0/24 \
  --allowed-ip 198.18.0.2/32
```

Full tunnel but keep private LAN routes local:

```bash
pipit --config pipit.wg.client.yaml wg-client \
  --exclude-lan
```

Full tunnel but exclude explicit CIDRs:

```bash
pipit --config pipit.wg.client.yaml wg-client \
  --exclude-ip 192.168.0.0/16 \
  --exclude-ip 100.64.0.0/10
```

`--exclude-lan` currently excludes `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.0.0/16` from the client-side auto routes.

For IPv6-only tunnel addresses, the default client allowed route becomes `::/0`, internally installed as `::/1` and `8000::/1`. `--exclude-lan` also excludes `fc00::/7` and `fe80::/10` for IPv6 routes. Mixing IPv4 tunnel addresses with IPv6 `allowed_ips` or IPv6 tunnel addresses with IPv4 `allowed_ips` requires explicit custom hooks for now.

## DNS Domain Capture

By default WG mode can see aggregate tunnel bytes, not domains. To populate TUI Recent Domains from DNS queries, enable DNS capture:

```bash
sudo pipit --config pipit.wg.client.yaml wg-client --dns 1.1.1.1 --dns-capture --tui
```

This starts a local UDP DNS forwarder on `127.0.0.1:53`, points macOS DNS at `127.0.0.1`, records query names, and forwards packets to the configured `--dns` upstream through the tunnel.

## Minimal Connectivity Smoke

After both processes start:

```bash
ping 10.8.0.1
```

Then try an IP-level check that avoids DNS first:

```bash
curl --connect-timeout 5 https://1.1.1.1/
```

If `--dns` was set on the client config, try a normal hostname lookup next.

For a repeatable diagnostic run, use the smoke script on both machines:

```bash
# server machine
sudo scripts/pipit-wg-smoke.sh --role server --config pipit.wg.yaml --start

# client machine
sudo scripts/pipit-wg-smoke.sh --role client --config pipit.wg.yaml --start
```

The client role checks `ping 10.8.0.1`, `curl https://ifconfig.me`, DNS resolution, and `tcpdump` evidence that the transport to the endpoint is UDP on the configured WireGuard port.

## Current Limits

- Automatic hooks support IPv4-only or IPv6-only tunnel routing. True dual-stack needs a schema extension such as separate IPv4 and IPv6 tunnel address pairs before it should be treated as production-ready.
- Linux server `nat_out_interface` default hooks are IPv4 NAT only. IPv6 routing/NAT still needs explicit hooks.
- macOS server NAT is not implemented by default yet.
- The transport is standard WireGuard-style UDP via `boringtun`; it is not AmneziaWG obfuscation.
- Real TUN/NAT execution usually requires root or equivalent network privileges.
