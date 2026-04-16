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

## Current Limits

- Automatic hooks are IPv4-first.
- macOS server NAT is not implemented by default yet.
- The transport is standard WireGuard-style UDP via `boringtun`; it is not AmneziaWG obfuscation.
- Real TUN/NAT execution usually requires root or equivalent network privileges.
