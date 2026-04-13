# Pipit

Pipit is a compact Rust proxy built around a simple idea:

- local `SOCKS5` on the client side
- selectable transport modes
- a TLS tunnel to the server for native modes
- an HTTP-like handshake inside TLS for native modes
- a shared-secret HMAC proof to avoid exposing an unauthenticated open proxy

The design is inspired by lightweight remote proxies such as [daze](https://github.com/libraries/daze), but this first version intentionally keeps the protocol small and the defaults conservative.

## Goals

- simple enough to audit
- stable enough to run as a small personal tunnel
- harder to fingerprint than a naked custom binary protocol
- safe by default

## What It Does Today

- `pipit client` exposes a local SOCKS5 proxy
- `pipit server` accepts either TLS-native or daze-style connections depending on `--mode`
- the tunnel request looks like normal HTTP over TLS instead of a bespoke plaintext protocol
- the hidden tunnel handshake looks like a small JSON API call instead of custom proxy headers
- an optional multiplexed mode can reuse one TLS session for many local SOCKS connections
- optional client-side proxy control can decide per target whether to connect directly, proxy remotely, or block it
- an optional `daze-ashe` mode speaks a daze-style RC4 stream protocol over raw TCP
- an optional `daze-baboon` mode wraps the daze handshake in an HTTP-looking `/sync` exchange
- an optional `daze-czar` mode multiplexes many daze-ashe streams over one raw TCP session
- the server rejects replayed authentication proofs
- the server denies literal private IP targets by default
- the server can proxy unmatched requests to a real upstream website
- unmatched requests default to `https://www.qq.com`
- `pipit cert` generates a self-signed certificate for quick setup

## Quick Start

1. Generate a certificate for your server name:

```bash
cargo run -- cert --name example.com --cert server.crt --key server.key
```

2. Start the server in the default `native-http` mode:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- server \
  --mode native-http \
  --listen 0.0.0.0:1443 \
  --cert server.crt \
  --key server.key
```

3. Start the local client in the same mode:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --mode native-http \
  --listen 127.0.0.1:1080 \
  --server example.com:1443 \
  --server-name example.com \
  --ca-cert server.crt
```

4. Point your browser or tools at `socks5://127.0.0.1:1080`.

## Config File

You can move most CLI flags into a YAML config file and load it with `--config`.

Example:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- --config ./pipit.example.yaml client
```

The repository includes a ready-to-copy example at [`pipit.example.yaml`](./pipit.example.yaml).

Config precedence is:

- explicit CLI flags
- environment variables
- YAML config
- built-in defaults

Relative paths inside the YAML file are resolved relative to the config file itself, so this works well for portable bundles.

## Modes

- `native-http`: one TLS tunnel per local SOCKS connection. This is the default mode.
- `native-mux`: one persistent TLS session carrying many logical streams.
- `daze-ashe`: a daze-style raw TCP mode using the ashe handshake and RC4 stream encryption.
- `daze-baboon`: daze-ashe hidden behind an HTTP-looking `POST /sync` request plus fallback website masking.
- `daze-czar`: daze-ashe running on top of a compact raw TCP multiplexing layer.

Native modes require `--cert` and `--key` on the server. `daze-ashe`, `daze-baboon`, and `daze-czar` ignore those TLS settings.

## Proxy Control

The client can now do daze-style proxy control before it decides whether a target should use the remote tunnel.

- `--filter proxy`: always use the remote proxy. This is the default and preserves the old behavior.
- `--filter direct`: always connect directly from the client machine.
- `--filter rule`: evaluate glob rules first, then CIDR rules, then fall back to remote.

When `--filter rule` is enabled:

- `--rule-file` loads hostname glob rules in the same `L / R / B` style used by daze.
- `--cidr-file` loads CIDR rules in the same `L / R / B` style.
- reserved and loopback IP ranges are treated as direct by default, similar to daze's local-network shortcut.

Example `rule.ls`:

```text
L *.lan *.local printer.home
R *.example.com
B ads.example.net
```

Example `rule.cidr`:

```text
L 192.168.0.0/16
R 1.1.1.0/24
B 203.0.113.0/24
```

Example client command:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --mode native-http \
  --listen 127.0.0.1:1080 \
  --server example.com:1443 \
  --server-name example.com \
  --ca-cert server.crt \
  --filter rule \
  --rule-file ./rule.ls \
  --cidr-file ./rule.cidr
```

## Optional Multiplexing

For short-lived connections, you can reuse one TLS session and multiplex multiple SOCKS streams through it:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- server \
  --mode native-mux \
  --listen 0.0.0.0:1443 \
  --cert server.crt \
  --key server.key
```

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --mode native-mux \
  --listen 127.0.0.1:1080 \
  --server example.com:1443 \
  --server-name example.com \
  --ca-cert server.crt
```

In `native-mux` mode, the client keeps a persistent TLS session and opens lightweight logical streams inside it instead of paying the full TCP + TLS + HTTP handshake cost for every SOCKS connection.
Both sides default to `--mux-path /mux`, so you only need to set it when you want a custom path.

For backward compatibility, `--mux` still maps to `--mode native-mux`.

## Daze Ashe Mode

If you want a daze-style raw TCP transport:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- server \
  --mode daze-ashe \
  --listen 0.0.0.0:1081
```

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --mode daze-ashe \
  --listen 127.0.0.1:1080 \
  --server example.com:1081
```

This mode skips TLS entirely and uses a daze-style per-connection handshake plus RC4 stream encryption. It is useful as an alternate strategy layer, but it does not provide the camouflage properties of the native HTTP-over-TLS modes.

## Daze Baboon Mode

If you want the daze handshake to be hidden behind a normal-looking HTTP request:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- server \
  --mode daze-baboon \
  --listen 0.0.0.0:1081 \
  --fallback-url https://www.qq.com
```

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --mode daze-baboon \
  --listen 127.0.0.1:1080 \
  --server example.com:1081
```

`daze-baboon` starts with a `POST /sync` request carrying an `Authorization` signature. Unmatched requests are proxied to `--fallback-url`, so the server can still look like a normal website from the outside.

## Daze Czar Mode

If you want a daze-style multiplexed transport over one long-lived raw TCP session:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- server \
  --mode daze-czar \
  --listen 0.0.0.0:1081
```

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --mode daze-czar \
  --listen 127.0.0.1:1080 \
  --server example.com:1081
```

`daze-czar` keeps one raw TCP connection open to the server and multiplexes many logical streams over it. Each logical stream still uses the daze-ashe encrypted open handshake before switching into relay mode.

## Security Notes

- TLS certificate verification is enabled by default.
- For self-signed deployments, pass the server certificate with `--ca-cert`.
- The shared secret is read from `PIPIT_PASSWORD` or `--password`; prefer the environment variable in practice.
- Authentication includes a timestamp and nonce. Replays outside the allowed window are rejected.
- Literal private IP targets are blocked unless `--allow-private-targets` is set on the server.
- `--fallback-url` lets the server mimic a different HTTPS site when requests do not match the tunnel handshake.
- if you do not set it, unmatched requests default to `https://www.qq.com`
- the client handshake uses a normal `POST` with JSON body and a configurable `--user-agent`

## Protocol Shape

The `native-http` handshake is intentionally small:

1. client accepts a local SOCKS5 `CONNECT`
2. client opens TLS to the server
3. client sends `POST /connect HTTP/1.1` with a small JSON body carrying target and auth proof
4. server validates the HMAC proof and opens the outbound TCP connection
5. server replies `200 Connection Established`
6. both sides switch to raw byte relay

Requests that do not match the tunnel path are forwarded to a real upstream website. By default that upstream is `https://www.qq.com`, and you can override it with `--fallback-url`.

When `native-mux` is enabled on the client, it first establishes an authenticated `POST /mux HTTP/1.1` session inside TLS, then carries multiple logical `open/data/close` streams over a compact binary frame protocol on that single TLS connection.

When `daze-ashe` is enabled, the client and server speak a daze-style raw TCP handshake using a password-derived key, a random salt, an encrypted timestamp, and then an encrypted target open request.

When `daze-baboon` is enabled, the client first sends a signed `POST /sync HTTP/1.1` request. After the server returns `200 OK`, both sides immediately switch into the daze-ashe handshake on that same socket.

When `daze-czar` is enabled, the client keeps one raw TCP session open and exchanges 4-byte `open/data/close/probe` frames. Each logical stream then runs the daze-ashe handshake inside that multiplexed channel.

## Current Scope

This first implementation is deliberately narrow:

- TCP only
- SOCKS5 `CONNECT` only
- one upstream tunnel per local connection
- no UDP relay
- optional multiplexing via `--mode native-mux`
- optional daze-style raw TCP transports via `--mode daze-ashe`, `--mode daze-baboon`, and `--mode daze-czar`
- no traffic shaping yet

That keeps the code smaller and makes reliability easier to reason about before we add more protocol surface.

## Development

```bash
cargo check
cargo test
```
