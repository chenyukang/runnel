# Proxy Mode Performance

This page records local end-to-end proxy mode benchmark results from `mode_perf`.
The benchmark starts a local HTTP target, proxy endpoints, and a client path,
then measures each proxy mode. Non-WG modes use the SOCKS request path. WG
uses separate target/server/client child processes plus direct tunnel-IP HTTP
requests, and is disabled by default because it creates real TUN/device
interfaces.

Run it with:

```bash
cargo bench --bench mode_perf
```

Default workload:

- Warmup: 100 requests
- Small request run: 1000 new TCP/SOCKS requests
- Large response run: 8 downloads of 1 MiB each
- Host: localhost loopback
- Build profile: Cargo bench/release profile

## Latest Result

Measured on 2026-04-17.

Command:

```bash
sudo PIPIT_PERF_WG=1 cargo bench --bench mode_perf
```

| Mode | Small req/s | Avg ms | P50 ms | P95 ms | Large throughput MiB/s | Large response | Notes |
|---|---:|---:|---:|---:|---:|---:|---|
| native-http | 2064.6 | 0.48 | 0.48 | 0.51 | 631.2 | 1.00 MiB |  |
| native-mux | 3365.1 | 0.30 | 0.26 | 0.38 | 540.2 | 1.00 MiB |  |
| daze-ashe | 3148.2 | 0.32 | 0.29 | 0.40 | 294.2 | 1.00 MiB |  |
| daze-baboon | 2842.1 | 0.35 | 0.31 | 0.44 | 306.2 | 1.00 MiB |  |
| daze-czar | 3425.7 | 0.29 | 0.27 | 0.34 | 206.8 | 1.00 MiB |  |
| wg | 2545.7 | 0.39 | 0.39 | 0.44 | 43.8 | 1.00 MiB | real TUN/device |

## WG Mode

WG mode is opt-in. The benchmark driver spawns separate child processes for the
HTTP target, WG server, and WG client, assigns tunnel IPs, and measures HTTP
requests to the server tunnel IP from the parent process. Run it from a terminal
with host privileges:

```bash
sudo PIPIT_PERF_WG=1 cargo bench --bench mode_perf
```

To run only WG:

```bash
sudo PIPIT_PERF_MODES=wg cargo bench --bench mode_perf
```

Optional WG-specific settings:

```bash
sudo \
  PIPIT_PERF_MODES=wg \
  PIPIT_PERF_WG_CLIENT_IP=10.88.0.2 \
  PIPIT_PERF_WG_SERVER_IP=10.88.0.1 \
  PIPIT_PERF_WG_MTU=1420 \
  PIPIT_PERF_WG_READY_TIMEOUT=15 \
  cargo bench --bench mode_perf
```

Device names can also be overridden:

```bash
sudo \
  PIPIT_PERF_MODES=wg \
  PIPIT_PERF_WG_SERVER_DEVICE=pipitwgs0 \
  PIPIT_PERF_WG_CLIENT_DEVICE=pipitwgc0 \
  cargo bench --bench mode_perf
```

On macOS the default device setting is `auto`. On Linux the default managed
device names are `pipitwgs0` and `pipitwgc0`.

## Tuning

The benchmark can be adjusted with environment variables:

```bash
PIPIT_PERF_REQUESTS=500 \
PIPIT_PERF_LARGE_DOWNLOADS=16 \
PIPIT_PERF_LARGE_BYTES=4194304 \
cargo bench --bench mode_perf
```

Available variables:

- `PIPIT_PERF_MODES`: comma-separated mode list, for example `native-http,daze-czar`
- `PIPIT_PERF_WG`: include WG in the default mode list when set to `1`
- `PIPIT_PERF_WARMUP`: warmup request count
- `PIPIT_PERF_REQUESTS`: small request count
- `PIPIT_PERF_LARGE_DOWNLOADS`: large download count
- `PIPIT_PERF_LARGE_BYTES`: bytes per large response
- `PIPIT_PERF_LOG=1`: enable benchmark logging
- `PIPIT_PERF_WG_CLIENT_IP`: WG client tunnel IP, default `10.88.0.2`
- `PIPIT_PERF_WG_SERVER_IP`: WG server tunnel IP, default `10.88.0.1`
- `PIPIT_PERF_WG_CLIENT_DEVICE`: WG client device name
- `PIPIT_PERF_WG_SERVER_DEVICE`: WG server device name
- `PIPIT_PERF_WG_MTU`: WG tunnel MTU, default `1420`
- `PIPIT_PERF_WG_READY_TIMEOUT`: seconds to wait for the WG target to become reachable

## Notes

These numbers are useful for comparing modes on the same machine and build,
not as absolute network throughput claims. The benchmark is intentionally
localhost-only to reduce external network noise.

WG is omitted from the default end-to-end run because the production WG mode
creates real TUN/devices. The opt-in WG benchmark is intended to be run
manually with `sudo`.
