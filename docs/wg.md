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
  --direct-ip "10.*" \
  --direct-ip "172.16.0.0/12" \
  --direct-ip "192.168.*" \
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

## Split Tunnel Rules

WG mode uses the same `ip_rules` shape as other client modes. Put routing rules
under `client:`, not under `client.wg`. Proxy is the default, so a minimal WG
client does not need any route rules:

```yaml
client:
  mode: wg
```

Full tunnel but keep private LAN routes local:

```yaml
client:
  mode: wg
  ip_rules:
    direct:
      - "10.*"
      - "172.16.*"
      - "172.17.*"
      - "172.18.*"
      - "172.19.*"
      - "172.20.*"
      - "172.21.*"
      - "172.22.*"
      - "172.23.*"
      - "172.24.*"
      - "172.25.*"
      - "172.26.*"
      - "172.27.*"
      - "172.28.*"
      - "172.29.*"
      - "172.30.*"
      - "172.31.*"
      - "192.168.*"
      - "169.254.*"
```

For IPv6-only tunnel addresses, the default proxy route is IPv6. To keep common
local IPv6 ranges direct, add `fc00::/7`, `fe80::/10`, and `ff00::/8` under
`ip_rules.direct`.

For WG, `ip_rules.direct` becomes local-route exclusions from the default
tunnel route. `ip_rules.block` is parsed, but WG cannot enforce it yet without
firewall or blackhole-route hooks.

WG domain rules are DNS driven. Configure them under `client:` and set a WG DNS
upstream:

```yaml
client:
  mode: wg
  domain_rules:
    direct:
      - "*.qq.com"
      - "*.cn"
    block:
      - "*.xxx.com"
  wg:
    dns: 1.1.1.1
    dns_capture: true
```

`domain_rules.direct` routes resolved A/AAAA host IPs outside the tunnel.
`domain_rules.block` replies NXDOMAIN from the local DNS capture listener.
If `domain_rules` are configured with `client.wg.dns`, config
loading enables `dns_capture` automatically.

Because this is DNS based, it only applies to DNS queries that pass through the
local capture listener. DoH/DoT, browser private DNS, cached answers, or direct
IP connections will not trigger domain routing. CDN/shared IP answers can also
affect other domains that resolve to the same host IP while the client is
running.

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
`127.0.0.1`, records query names, applies WG domain rules when configured, and
forwards packets to the configured `dns` upstream through the tunnel.

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
