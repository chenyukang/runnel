# `pipit` WG Mode Quickstart

This note covers the recommended `client.mode: wg` / `server.mode: wg` path
built on `boringtun`.

The goal is to make a first real smoke test repeatable without hand-writing
keys or accidentally installing routes before checking the plan.

## Generate A Paired Config

Run this on your local machine. Replace `SERVER-IP` with the public server IP
and UDP port before running it:

```bash
pipit wg-config \
  --server-endpoint SERVER-IP:51820 \
  --client-tunnel-ip 10.8.0.2 \
  --server-tunnel-ip 10.8.0.1 \
  --dns 1.1.1.1 \
  --dns-capture \
  --exclude-lan \
  --nat-out-interface eth0 > pipit.wg.yaml
```

The command prints one YAML file containing both sides:

- `client.mode: wg` plus `client.wg`: use this on the client machine.
- `server.mode: wg` plus `server.wg`: use this on the server machine.

Use `--json` if another tool needs to consume the generated material.

## Check Before Running

The `client` / `server` commands read WG settings from `client.wg` /
`server.wg`. To preview hooks without creating the TUN device, temporarily add
`print_hooks: true` and `dry_run: true` under the side you want to inspect.

Client:

```yaml
client:
  wg:
    print_hooks: true
    dry_run: true
```

```bash
pipit --config pipit.wg.yaml client
```

Server:

```yaml
server:
  wg:
    print_hooks: true
    dry_run: true
```

```bash
pipit --config pipit.wg.yaml server
```

This validates keys, endpoint parsing, allowed IPs, and prints the hook plan. It
does not create the TUN device. Remove `dry_run: true` before real startup.

## Run

Server first:

```bash
sudo pipit --config pipit.wg.yaml server
```

Client second:

```bash
sudo pipit --config pipit.wg.yaml --tui client
```

`client.mode: wg` defaults to full-tunnel IPv4 routing through `0.0.0.0/0`,
which is installed as split routes internally. The server endpoint gets a bypass
route so the encrypted UDP transport does not loop into the tunnel.

Startup performs a preflight before creating the device or running hooks. It
checks the platform tools and privileges needed for the selected role, for
example `/dev/net/tun`, `ip`, `sysctl`, and `iptables` on Linux, and `ifconfig`,
`route`, and `networksetup` on macOS. `dry_run: true` still skips privileged
preflight so plans can be inspected as a normal user.

The client also sends a short WireGuard handshake probe before creating the
device. If the server is unreachable or either side has the wrong WG key, the
client fails early with a startup error instead of silently installing routes.
Set `client.wg.skip_handshake_probe: true` only when you intentionally need to
start before the server is reachable.

The server cannot actively probe a client because it normally starts first and
does not know the client's UDP endpoint. Instead, it watches the WireGuard
handshake state after startup and logs a warning if no successful handshake is
observed within 30 seconds. Set `server.wg.handshake_watchdog_secs: 0` to
disable that warning for intentionally idle servers.

## Split Tunnel And Exclusions

Only proxy specific CIDRs:

```yaml
client:
  mode: wg
  wg:
    allowed_ips:
      - 203.0.113.0/24
      - 198.18.0.2/32
```

Full tunnel but keep private LAN routes local:

```yaml
client:
  mode: wg
  wg:
    allowed_ips:
      - 0.0.0.0/0
    exclude_lan: true
```

Full tunnel but exclude explicit CIDRs:

```yaml
client:
  mode: wg
  wg:
    allowed_ips:
      - 0.0.0.0/0
    excluded_ips:
      - 192.168.0.0/16
      - 100.64.0.0/10
```

`exclude_lan` currently excludes `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, and `169.254.0.0/16` from the client-side auto routes.

For IPv6-only tunnel addresses, the default client allowed route becomes
`::/0`, internally installed as `::/1` and `8000::/1`. `exclude_lan` also
excludes `fc00::/7`, `fe80::/10`, and `ff00::/8` for IPv6 routes. Mixing IPv4
tunnel addresses with IPv6 `allowed_ips` or IPv6 tunnel addresses with IPv4
`allowed_ips` requires explicit custom hooks for now.

## DNS Domain Capture

By default WG mode can see aggregate tunnel bytes, not domains. To populate TUI
Recent Domains from DNS queries, enable DNS capture in the client config:

```yaml
client:
  mode: wg
  wg:
    dns: 1.1.1.1
    dns_capture: true
```

This starts a local UDP DNS forwarder on `127.0.0.1:53`, points macOS DNS at
`127.0.0.1`, records query names, and forwards packets to the configured `dns`
upstream through the tunnel.

## Minimal Connectivity Smoke

After both processes start:

```bash
ping 10.8.0.1
```

Then try an IP-level check that avoids DNS first:

```bash
curl --connect-timeout 5 https://1.1.1.1/
```

If `client.wg.dns` was set, try a normal hostname lookup next.

For a repeatable diagnostic run, use the smoke script on both machines:

```bash
# server machine
sudo scripts/pipit-wg-smoke.sh --role server --config pipit.wg.yaml --start

# client machine
sudo scripts/pipit-wg-smoke.sh --role client --config pipit.wg.yaml --start
```

The client role checks `ping 10.8.0.1`, `curl https://ifconfig.me`, DNS
resolution, and `tcpdump` evidence that the transport to the endpoint is UDP on
the configured WireGuard port.

## Current Limits

- Automatic hooks support IPv4-only or IPv6-only tunnel routing. True dual-stack
  needs a schema extension such as separate IPv4 and IPv6 tunnel address pairs
  before it should be treated as production-ready.
- Linux server `nat_out_interface` default hooks are IPv4 NAT only. IPv6
  routing/NAT still needs explicit hooks.
- macOS server NAT is not implemented by default yet.
- The transport is standard WireGuard-style UDP via `boringtun`; it is not
  AmneziaWG obfuscation.
- Real TUN/NAT execution usually requires root or equivalent network privileges.
