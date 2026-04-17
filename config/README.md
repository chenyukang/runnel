# Sample Configs

These files are safe templates. They intentionally use documentation-only
placeholders such as `SERVER-IP`, `SERVER-IPv6`, and `SERVER-NAME`.

Do not put production passwords or real WG private keys in these files. Prefer:

```bash
export PIPIT_PASSWORD='replace-me-with-your-secret'
```

## Files

Recommended WG mode samples:

- `wg-ipv4.yaml`: WireGuard-style IPv4 template.
- `wg-ipv6.yaml`: WireGuard-style IPv6-only template.

Classic client/server transport samples:

- `native-http.yaml`: TLS + HTTP-looking SOCKS transport.
- `native-mux.yaml`: native TLS transport with multiplexed streams.
- `daze-ashe.yaml`: raw TCP daze-style transport.
- `daze-baboon.yaml`: HTTP-looking daze-style transport with fallback site.
- `daze-czar.yaml`: raw TCP daze-style multiplexing.

Client traffic intake sample:

- `tun.yaml`: VPN-style TUN capture. TUN is a client-side intake layer, not a
  separate server transport. The current implementation pairs it with
  `client.mode: native-http`.

## WG Keys

The WG templates contain obvious `REPLACE_WITH_*` placeholders. Generate real
keys/configs instead of reusing sample material. Replace `SERVER-IP` with the
real server address before running:

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
  --nat-out-interface eth0
```
