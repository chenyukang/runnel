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
- an optional `daze-ashe` mode speaks a daze-style RC4 stream protocol over raw TCP
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

## Modes

- `native-http`: one TLS tunnel per local SOCKS connection. This is the default mode.
- `native-mux`: one persistent TLS session carrying many logical streams.
- `daze-ashe`: a daze-style raw TCP mode using the ashe handshake and RC4 stream encryption.

Native modes require `--cert` and `--key` on the server. `daze-ashe` ignores those TLS settings.

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

## Current Scope

This first implementation is deliberately narrow:

- TCP only
- SOCKS5 `CONNECT` only
- one upstream tunnel per local connection
- no UDP relay
- optional multiplexing via `--mode native-mux`
- optional daze-style raw TCP transport via `--mode daze-ashe`
- no traffic shaping yet

That keeps the code smaller and makes reliability easier to reason about before we add more protocol surface.

## Development

```bash
cargo check
cargo test
```
