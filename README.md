# Pipit

Pipit is a compact Rust proxy built around a simple idea:

- local `SOCKS5` on the client side
- a TLS tunnel to the server
- an HTTP-like handshake inside TLS for camouflage
- a shared-secret HMAC proof to avoid exposing an unauthenticated open proxy

The design is inspired by lightweight remote proxies such as [daze](https://github.com/libraries/daze), but this first version intentionally keeps the protocol small and the defaults conservative.

## Goals

- simple enough to audit
- stable enough to run as a small personal tunnel
- harder to fingerprint than a naked custom binary protocol
- safe by default

## What It Does Today

- `pipit client` exposes a local SOCKS5 proxy
- `pipit server` accepts TLS connections and relays authenticated tunnels
- the tunnel request looks like normal HTTP over TLS instead of a bespoke plaintext protocol
- the hidden tunnel handshake looks like a small JSON API call instead of custom proxy headers
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

2. Start the server:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- server \
  --listen 0.0.0.0:1443 \
  --cert server.crt \
  --key server.key
```

3. Start the local client:

```bash
PIPIT_PASSWORD='replace-me' cargo run -- client \
  --listen 127.0.0.1:1080 \
  --server example.com:1443 \
  --server-name example.com \
  --ca-cert server.crt
```

4. Point your browser or tools at `socks5://127.0.0.1:1080`.

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

The current handshake is intentionally small:

1. client accepts a local SOCKS5 `CONNECT`
2. client opens TLS to the server
3. client sends `POST /connect HTTP/1.1` with a small JSON body carrying target and auth proof
4. server validates the HMAC proof and opens the outbound TCP connection
5. server replies `200 Connection Established`
6. both sides switch to raw byte relay

Requests that do not match the tunnel path are forwarded to a real upstream website. By default that upstream is `https://www.qq.com`, and you can override it with `--fallback-url`.

## Current Scope

This first implementation is deliberately narrow:

- TCP only
- SOCKS5 `CONNECT` only
- one upstream tunnel per local connection
- no UDP relay
- no multiplexing
- no traffic shaping yet

That keeps the code smaller and makes reliability easier to reason about before we add more protocol surface.

## Development

```bash
cargo check
cargo test
```
