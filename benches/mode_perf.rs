use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use pipit::{
    client::{self, ClientArgs},
    mode::ProxyMode,
    proxy::route::FilterMode,
    server::{self, ServerArgs},
    wg::{client::WgClientArgs, server::WgServerArgs},
};
use rand::rngs::OsRng;
use rcgen::generate_simple_self_signed;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing_subscriber::EnvFilter;

const DEFAULT_WARMUP_REQUESTS: usize = 100;
const DEFAULT_SMALL_REQUESTS: usize = 1000;
const DEFAULT_LARGE_DOWNLOADS: usize = 8;
const DEFAULT_LARGE_BODY_BYTES: usize = 1024 * 1024;
const CHILD_ROLE_ENV: &str = "PIPIT_PERF_CHILD_ROLE";
static NEXT_CERT_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
struct BenchConfig {
    warmup_requests: usize,
    small_requests: usize,
    large_downloads: usize,
    large_body_bytes: usize,
}

struct BenchEnv {
    target_handle: JoinHandle<()>,
    server_handle: JoinHandle<()>,
    client_handle: JoinHandle<()>,
    target_port: u16,
    socks_port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

struct WgBenchEnv {
    target_child: Child,
    server_child: Child,
    client_child: Child,
    target_addr: SocketAddr,
    client_source_ip: IpAddr,
}

struct ChildGuard {
    child: Option<Child>,
}

struct ModeResult {
    mode: &'static str,
    requests_per_second: f64,
    avg_latency_ms: f64,
    p50_latency_ms: f64,
    p95_latency_ms: f64,
    throughput_mib_s: f64,
    bytes_per_large_response: usize,
    notes: &'static str,
}

impl Drop for BenchEnv {
    fn drop(&mut self) {
        self.target_handle.abort();
        self.server_handle.abort();
        self.client_handle.abort();
        if let Some(path) = &self.cert_path {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = &self.key_path {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for WgBenchEnv {
    fn drop(&mut self) {
        terminate_child(&mut self.client_child);
        terminate_child(&mut self.server_child);
        terminate_child(&mut self.target_child);
    }
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn as_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("child guard still owns child")
    }

    fn take(mut self) -> Child {
        self.child.take().expect("child guard still owns child")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            terminate_child(child);
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if let Ok(role) = std::env::var(CHILD_ROLE_ENV) {
        init_optional_tracing();
        let _ = rustls::crypto::ring::default_provider().install_default();
        return run_child_role(&role).await;
    }

    if cfg!(debug_assertions) && std::env::var_os("PIPIT_RUN_PERF_BENCH").is_none() {
        println!("mode_perf bench is skipped in debug/test profile");
        println!("run `cargo bench --bench mode_perf` for release-profile results");
        return Ok(());
    }

    let config = BenchConfig {
        warmup_requests: env_usize("PIPIT_PERF_WARMUP", DEFAULT_WARMUP_REQUESTS),
        small_requests: env_usize("PIPIT_PERF_REQUESTS", DEFAULT_SMALL_REQUESTS),
        large_downloads: env_usize("PIPIT_PERF_LARGE_DOWNLOADS", DEFAULT_LARGE_DOWNLOADS),
        large_body_bytes: env_usize("PIPIT_PERF_LARGE_BYTES", DEFAULT_LARGE_BODY_BYTES),
    };

    init_optional_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let modes = selected_modes();
    let mut results = Vec::new();
    for mode in modes {
        results.push(bench_mode(mode, config).await?);
    }

    print_table(&results, config);
    Ok(())
}

async fn bench_mode(mode: ProxyMode, config: BenchConfig) -> Result<ModeResult> {
    if matches!(mode, ProxyMode::Wg) {
        return bench_wg_mode(config).await;
    }

    let env = start_env(mode, config.large_body_bytes).await?;

    for _ in 0..config.warmup_requests {
        let body = fetch_via_socks_path(env.socks_port, env.target_port, "/small")
            .await
            .with_context(|| format!("{} warmup request failed", mode))?;
        anyhow::ensure!(
            body.ends_with(b"ok"),
            "unexpected warmup response for {}",
            mode
        );
    }

    let mut latencies = Vec::with_capacity(config.small_requests);
    let started = Instant::now();
    for _ in 0..config.small_requests {
        let request_started = Instant::now();
        let body = fetch_via_socks_path(env.socks_port, env.target_port, "/small")
            .await
            .with_context(|| format!("{} small request failed", mode))?;
        anyhow::ensure!(
            body.ends_with(b"ok"),
            "unexpected small response for {}",
            mode
        );
        latencies.push(request_started.elapsed());
    }
    let small_elapsed = started.elapsed();
    let requests_per_second = config.small_requests as f64 / small_elapsed.as_secs_f64();

    let mut large_bytes = 0usize;
    let started = Instant::now();
    for _ in 0..config.large_downloads {
        let body = fetch_via_socks_path(env.socks_port, env.target_port, "/large")
            .await
            .with_context(|| format!("{} large download failed", mode))?;
        anyhow::ensure!(
            body.len() >= config.large_body_bytes,
            "large response for {} was too small: {} bytes",
            mode,
            body.len()
        );
        large_bytes += body.len();
    }
    let large_elapsed = started.elapsed();
    let throughput_mib_s = bytes_to_mib(large_bytes) / large_elapsed.as_secs_f64();

    Ok(ModeResult {
        mode: mode.as_str(),
        requests_per_second,
        avg_latency_ms: average_latency_ms(&latencies),
        p50_latency_ms: percentile_latency_ms(&latencies, 0.50),
        p95_latency_ms: percentile_latency_ms(&latencies, 0.95),
        throughput_mib_s,
        bytes_per_large_response: large_bytes / config.large_downloads.max(1),
        notes: "",
    })
}

async fn bench_wg_mode(config: BenchConfig) -> Result<ModeResult> {
    let env = start_wg_env(config.large_body_bytes).await?;

    for _ in 0..config.warmup_requests {
        let body = fetch_via_wg_path(env.target_addr, env.client_source_ip, "/small")
            .await
            .context("wg warmup request failed")?;
        anyhow::ensure!(body.ends_with(b"ok"), "unexpected warmup response for wg");
    }

    let mut latencies = Vec::with_capacity(config.small_requests);
    let started = Instant::now();
    for _ in 0..config.small_requests {
        let request_started = Instant::now();
        let body = fetch_via_wg_path(env.target_addr, env.client_source_ip, "/small")
            .await
            .context("wg small request failed")?;
        anyhow::ensure!(body.ends_with(b"ok"), "unexpected small response for wg");
        latencies.push(request_started.elapsed());
    }
    let small_elapsed = started.elapsed();
    let requests_per_second = config.small_requests as f64 / small_elapsed.as_secs_f64();

    let mut large_bytes = 0usize;
    let started = Instant::now();
    for _ in 0..config.large_downloads {
        let body = fetch_via_wg_path(env.target_addr, env.client_source_ip, "/large")
            .await
            .context("wg large download failed")?;
        anyhow::ensure!(
            body.len() >= config.large_body_bytes,
            "large response for wg was too small: {} bytes",
            body.len()
        );
        large_bytes += body.len();
    }
    let large_elapsed = started.elapsed();
    let throughput_mib_s = bytes_to_mib(large_bytes) / large_elapsed.as_secs_f64();

    Ok(ModeResult {
        mode: ProxyMode::Wg.as_str(),
        requests_per_second,
        avg_latency_ms: average_latency_ms(&latencies),
        p50_latency_ms: percentile_latency_ms(&latencies, 0.50),
        p95_latency_ms: percentile_latency_ms(&latencies, 0.95),
        throughput_mib_s,
        bytes_per_large_response: large_bytes / config.large_downloads.max(1),
        notes: "real TUN/device",
    })
}

async fn start_env(mode: ProxyMode, large_body_bytes: usize) -> Result<BenchEnv> {
    anyhow::ensure!(
        !matches!(mode, ProxyMode::Wg),
        "wg mode must use start_wg_env"
    );

    let target_port = free_port()?;
    let server_port = free_port()?;
    let socks_port = free_port()?;

    let target_handle = tokio::spawn(run_http_target(target_port, large_body_bytes));
    wait_for_tcp_listener(target_port).await?;

    let (cert_path, key_path) = if matches!(mode, ProxyMode::NativeHttp | ProxyMode::NativeMux) {
        let (cert, key) = write_temp_cert_pair()?;
        (Some(cert), Some(key))
    } else {
        (None, None)
    };

    let server_args = ServerArgs {
        listen: format!("127.0.0.1:{server_port}"),
        cert: cert_path.clone(),
        key: key_path.clone(),
        mode,
        password: "hello-world".to_owned(),
        path: "/connect".to_owned(),
        mux_path: "/mux".to_owned(),
        auth_window_secs: 120,
        handshake_timeout_secs: 10,
        connect_timeout_secs: 10,
        max_header_size: 16 * 1024,
        max_tunnel_body_size: 8 * 1024,
        allow_private_targets: true,
        fallback_url: "http://127.0.0.1:1".to_owned(),
        fallback_timeout_secs: 1,
        max_fallback_body_size: 1024,
        wg: Default::default(),
    };

    let client_args = ClientArgs {
        listen: format!("127.0.0.1:{socks_port}"),
        server: format!("127.0.0.1:{server_port}"),
        server_name: cert_path.as_ref().map(|_| "example.com".to_owned()),
        ca_cert: cert_path.clone(),
        mode,
        password: "hello-world".to_owned(),
        path: "/connect".to_owned(),
        mux_path: "/mux".to_owned(),
        mux: false,
        filter: FilterMode::Proxy,
        rule_file: None,
        cidr_file: None,
        user_agent: "pipit-bench".to_owned(),
        handshake_timeout_secs: 10,
        connect_timeout_secs: 10,
        max_header_size: 16 * 1024,
        system_proxy: false,
        system_proxy_services: Vec::new(),
        tun_dns_redirect_ip: None,
        tun_dns_upstream: None,
        wg: Default::default(),
    };

    let server_handle = tokio::spawn(async move {
        if let Err(err) = server::run(server_args).await {
            eprintln!("{} benchmark server exited: {err:#}", mode.as_str());
        }
    });
    sleep(Duration::from_millis(150)).await;

    let client_handle = tokio::spawn(async move {
        if let Err(err) = client::run(client_args).await {
            eprintln!("{} benchmark client exited: {err:#}", mode.as_str());
        }
    });
    wait_for_tcp_listener(socks_port).await?;

    Ok(BenchEnv {
        target_handle,
        server_handle,
        client_handle,
        target_port,
        socks_port,
        cert_path,
        key_path,
    })
}

async fn start_wg_env(large_body_bytes: usize) -> Result<WgBenchEnv> {
    let client_tunnel_ip = env_ip("PIPIT_PERF_WG_CLIENT_IP", "10.88.0.2")?;
    let server_tunnel_ip = env_ip("PIPIT_PERF_WG_SERVER_IP", "10.88.0.1")?;
    anyhow::ensure!(
        client_tunnel_ip.is_ipv4() == server_tunnel_ip.is_ipv4(),
        "PIPIT_PERF_WG_CLIENT_IP and PIPIT_PERF_WG_SERVER_IP must use the same IP version"
    );

    let target_port = free_port()?;
    let wg_port = free_udp_port()?;
    let mtu = env_usize("PIPIT_PERF_WG_MTU", 1420) as u16;
    let server_device = env_string("PIPIT_PERF_WG_SERVER_DEVICE", default_wg_server_device());
    let client_device = env_string("PIPIT_PERF_WG_CLIENT_DEVICE", default_wg_client_device());
    let (client_private_key, client_public_key) = wg_key_pair();
    let (server_private_key, server_public_key) = wg_key_pair();

    let mut target_child = ChildGuard::new(spawn_mode_perf_child(
        "wg-target",
        &[
            ("PIPIT_PERF_WG_TARGET_PORT", target_port.to_string()),
            ("PIPIT_PERF_LARGE_BYTES", large_body_bytes.to_string()),
            ("PIPIT_PERF_WG_SERVER_IP", server_tunnel_ip.to_string()),
        ],
    )?);
    let target_probe_ip = if server_tunnel_ip.is_ipv6() {
        IpAddr::V6(Ipv6Addr::LOCALHOST)
    } else {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    };
    wait_for_tcp_addr(SocketAddr::new(target_probe_ip, target_port)).await?;
    ensure_child_running(target_child.as_mut(), "wg target")?;

    let mut server_child = ChildGuard::new(spawn_mode_perf_child(
        "wg-server",
        &[
            ("PIPIT_PERF_WG_PORT", wg_port.to_string()),
            ("PIPIT_PERF_WG_SERVER_PRIVATE_KEY", server_private_key),
            ("PIPIT_PERF_WG_CLIENT_PUBLIC_KEY", client_public_key),
            ("PIPIT_PERF_WG_SERVER_DEVICE", server_device),
            ("PIPIT_PERF_WG_SERVER_IP", server_tunnel_ip.to_string()),
            ("PIPIT_PERF_WG_CLIENT_IP", client_tunnel_ip.to_string()),
            ("PIPIT_PERF_WG_MTU", mtu.to_string()),
        ],
    )?);
    sleep(Duration::from_millis(500)).await;
    ensure_child_running(server_child.as_mut(), "wg server")?;

    let mut client_child = ChildGuard::new(spawn_mode_perf_child(
        "wg-client",
        &[
            ("PIPIT_PERF_WG_PORT", wg_port.to_string()),
            ("PIPIT_PERF_WG_CLIENT_PRIVATE_KEY", client_private_key),
            ("PIPIT_PERF_WG_SERVER_PUBLIC_KEY", server_public_key),
            ("PIPIT_PERF_WG_CLIENT_DEVICE", client_device),
            ("PIPIT_PERF_WG_CLIENT_IP", client_tunnel_ip.to_string()),
            ("PIPIT_PERF_WG_SERVER_IP", server_tunnel_ip.to_string()),
            ("PIPIT_PERF_WG_MTU", mtu.to_string()),
        ],
    )?);
    sleep(Duration::from_millis(500)).await;
    ensure_child_running(client_child.as_mut(), "wg client")?;

    let target_addr = SocketAddr::new(server_tunnel_ip, target_port);
    wait_for_wg_target(target_addr, client_tunnel_ip).await?;

    Ok(WgBenchEnv {
        target_child: target_child.take(),
        server_child: server_child.take(),
        client_child: client_child.take(),
        target_addr,
        client_source_ip: client_tunnel_ip,
    })
}

async fn run_child_role(role: &str) -> Result<()> {
    match role {
        "wg-target" => {
            let port = env_u16("PIPIT_PERF_WG_TARGET_PORT")?;
            let large_body_bytes = env_usize("PIPIT_PERF_LARGE_BYTES", DEFAULT_LARGE_BODY_BYTES);
            let server_tunnel_ip = env_ip("PIPIT_PERF_WG_SERVER_IP", "10.88.0.1")?;
            let bind_ip = if server_tunnel_ip.is_ipv6() {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            };
            run_http_target_on(SocketAddr::new(bind_ip, port), large_body_bytes).await;
            Ok(())
        }
        "wg-server" => {
            let client_tunnel_ip = env_ip("PIPIT_PERF_WG_CLIENT_IP", "10.88.0.2")?;
            let server_tunnel_ip = env_ip("PIPIT_PERF_WG_SERVER_IP", "10.88.0.1")?;
            let wg_port = env_u16("PIPIT_PERF_WG_PORT")?;
            let mtu = env_usize("PIPIT_PERF_WG_MTU", 1420) as u16;
            let args = ServerArgs {
                listen: String::new(),
                cert: None,
                key: None,
                mode: ProxyMode::Wg,
                password: "unused".to_owned(),
                path: "/connect".to_owned(),
                mux_path: "/mux".to_owned(),
                auth_window_secs: 120,
                handshake_timeout_secs: 10,
                connect_timeout_secs: 10,
                max_header_size: 16 * 1024,
                max_tunnel_body_size: 8 * 1024,
                allow_private_targets: true,
                fallback_url: "http://127.0.0.1:1".to_owned(),
                fallback_timeout_secs: 1,
                max_fallback_body_size: 1024,
                wg: WgServerArgs {
                    listen: format!("0.0.0.0:{wg_port}"),
                    private_key: env_required("PIPIT_PERF_WG_SERVER_PRIVATE_KEY")?,
                    peer_public_key: env_required("PIPIT_PERF_WG_CLIENT_PUBLIC_KEY")?,
                    device: env_string("PIPIT_PERF_WG_SERVER_DEVICE", default_wg_server_device()),
                    tunnel_ip: server_tunnel_ip,
                    peer_tunnel_ip: client_tunnel_ip,
                    peer_allowed_ips: vec![host_cidr(client_tunnel_ip)],
                    nat_out_interface: None,
                    mtu,
                    up: Vec::new(),
                    down: Vec::new(),
                    print_hooks: false,
                    dry_run: false,
                    handshake_watchdog_secs: 30,
                },
            };
            server::run(args).await
        }
        "wg-client" => {
            let client_tunnel_ip = env_ip("PIPIT_PERF_WG_CLIENT_IP", "10.88.0.2")?;
            let server_tunnel_ip = env_ip("PIPIT_PERF_WG_SERVER_IP", "10.88.0.1")?;
            let wg_port = env_u16("PIPIT_PERF_WG_PORT")?;
            let mtu = env_usize("PIPIT_PERF_WG_MTU", 1420) as u16;
            let args = ClientArgs {
                listen: String::new(),
                server: String::new(),
                server_name: None,
                ca_cert: None,
                mode: ProxyMode::Wg,
                password: "unused".to_owned(),
                path: "/connect".to_owned(),
                mux_path: "/mux".to_owned(),
                mux: false,
                filter: FilterMode::Proxy,
                rule_file: None,
                cidr_file: None,
                user_agent: "pipit-bench".to_owned(),
                handshake_timeout_secs: 10,
                connect_timeout_secs: 10,
                max_header_size: 16 * 1024,
                system_proxy: false,
                system_proxy_services: Vec::new(),
                tun_dns_redirect_ip: None,
                tun_dns_upstream: None,
                wg: WgClientArgs {
                    bind: "0.0.0.0:0".to_owned(),
                    endpoint: format!("127.0.0.1:{wg_port}"),
                    private_key: env_required("PIPIT_PERF_WG_CLIENT_PRIVATE_KEY")?,
                    peer_public_key: env_required("PIPIT_PERF_WG_SERVER_PUBLIC_KEY")?,
                    device: env_string("PIPIT_PERF_WG_CLIENT_DEVICE", default_wg_client_device()),
                    tunnel_ip: client_tunnel_ip,
                    peer_tunnel_ip: server_tunnel_ip,
                    mtu,
                    persistent_keepalive_secs: Some(25),
                    dns: None,
                    dns_capture: false,
                    allowed_ips: vec![host_cidr(server_tunnel_ip)],
                    excluded_ips: Vec::new(),
                    exclude_lan: false,
                    up: Vec::new(),
                    down: Vec::new(),
                    print_hooks: false,
                    dry_run: false,
                    skip_handshake_probe: false,
                },
            };
            client::run(args).await
        }
        other => anyhow::bail!("unknown mode_perf child role {other}"),
    }
}

fn spawn_mode_perf_child(role: &str, vars: &[(&str, String)]) -> Result<Child> {
    let mut command =
        Command::new(std::env::current_exe().context("failed to locate bench binary")?);
    command
        .env(CHILD_ROLE_ENV, role)
        .env("PIPIT_RUN_PERF_BENCH", "1")
        .stderr(Stdio::inherit());

    if env_bool("PIPIT_PERF_LOG") {
        command.stdout(Stdio::inherit());
    } else {
        command.stdout(Stdio::null());
    }

    for (name, value) in vars {
        command.env(name, value);
    }

    command
        .spawn()
        .with_context(|| format!("failed to spawn mode_perf child role {role}"))
}

fn ensure_child_running(child: &mut Child, label: &str) -> Result<()> {
    if let Some(status) = child
        .try_wait()
        .with_context(|| format!("failed to inspect {label} child status"))?
    {
        anyhow::bail!("{label} child exited before benchmark was ready: {status}");
    }
    Ok(())
}

async fn run_http_target(port: u16, large_body_bytes: usize) {
    run_http_target_on(
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        large_body_bytes,
    )
    .await
}

async fn run_http_target_on(bind: SocketAddr, large_body_bytes: usize) {
    let large_body = Arc::new(vec![b'x'; large_body_bytes]);
    let listener = TcpListener::bind(bind).await.unwrap();

    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        let large_body = large_body.clone();
        tokio::spawn(async move {
            let mut request = Vec::with_capacity(1024);
            let mut buf = [0_u8; 4096];

            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        request.extend_from_slice(&buf[..n]);
                        if request.windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }

            let path = extract_path(&request);
            let body: &[u8] = if path == "/large" {
                large_body.as_slice()
            } else {
                b"ok"
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(body).await;
            let _ = socket.shutdown().await;
        });
    }
}

async fn fetch_via_socks_path(socks_port: u16, target_port: u16, path: &str) -> Result<Vec<u8>> {
    timeout(Duration::from_secs(30), async move {
        let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
            .await
            .context("failed to connect to local SOCKS listener")?;

        stream.write_all(&[0x05, 0x01, 0x00]).await?;
        let mut method_reply = [0_u8; 2];
        stream
            .read_exact(&mut method_reply)
            .await
            .context("failed to read SOCKS method reply")?;
        anyhow::ensure!(method_reply == [0x05, 0x00], "unexpected SOCKS auth reply");

        let mut connect = vec![0x05, 0x01, 0x00, 0x01];
        connect.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
        connect.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&connect).await?;

        let mut connect_reply = [0_u8; 10];
        stream
            .read_exact(&mut connect_reply)
            .await
            .context("failed to read SOCKS connect reply")?;
        anyhow::ensure!(
            connect_reply[1] == 0x00,
            "unexpected SOCKS connect reply {}",
            connect_reply[1]
        );

        let request =
            format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .context("failed to read proxied HTTP response")?;
        Ok(response)
    })
    .await
    .context("timed out waiting for SOCKS benchmark request")?
}

async fn fetch_via_wg_path(
    target_addr: SocketAddr,
    client_source_ip: IpAddr,
    path: &str,
) -> Result<Vec<u8>> {
    timeout(Duration::from_secs(30), async move {
        let socket = match target_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }
        .context("failed to create WG benchmark TCP socket")?;
        socket
            .bind(SocketAddr::new(client_source_ip, 0))
            .with_context(|| format!("failed to bind WG benchmark source {client_source_ip}:0"))?;
        let mut stream = socket
            .connect(target_addr)
            .await
            .with_context(|| format!("failed to connect to WG benchmark target {target_addr}"))?;
        let request =
            format!("GET {path} HTTP/1.1\r\nHost: wg-benchmark\r\nConnection: close\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .context("failed to read WG benchmark HTTP response")?;
        Ok(response)
    })
    .await
    .context("timed out waiting for WG benchmark request")?
}

async fn wait_for_wg_target(target_addr: SocketAddr, client_source_ip: IpAddr) -> Result<()> {
    timeout(Duration::from_secs(env_usize("PIPIT_PERF_WG_READY_TIMEOUT", 15) as u64), async move {
        loop {
            match fetch_via_wg_path(target_addr, client_source_ip, "/small").await {
                Ok(body) if body.ends_with(b"ok") => return Ok::<(), anyhow::Error>(()),
                Ok(_) => sleep(Duration::from_millis(100)).await,
                Err(_) => sleep(Duration::from_millis(100)).await,
            }
        }
    })
    .await
    .with_context(|| {
        format!(
            "timed out waiting for WG benchmark target {target_addr}; run with sudo and set PIPIT_PERF_LOG=1 for details"
        )
    })?
}

fn print_table(results: &[ModeResult], config: BenchConfig) {
    println!("# Proxy Mode Performance");
    println!();
    println!(
        "Localhost end-to-end benchmark, release bench profile. Non-WG modes use the SOCKS path; WG uses child processes and direct tunnel-IP HTTP requests. Warmup: {} requests. Small run: {} requests. Large run: {} downloads of {}.",
        config.warmup_requests,
        config.small_requests,
        config.large_downloads,
        human_bytes(config.large_body_bytes),
    );
    println!();
    println!(
        "| Mode | Small req/s | Avg ms | P50 ms | P95 ms | Large throughput MiB/s | Large response | Notes |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---|");
    for result in results {
        println!(
            "| {} | {:.1} | {:.2} | {:.2} | {:.2} | {:.1} | {} | {} |",
            result.mode,
            result.requests_per_second,
            result.avg_latency_ms,
            result.p50_latency_ms,
            result.p95_latency_ms,
            result.throughput_mib_s,
            human_bytes(result.bytes_per_large_response),
            result.notes,
        );
    }
    if !results
        .iter()
        .any(|result| result.mode == ProxyMode::Wg.as_str())
    {
        println!(
            "| wg | - | - | - | - | - | - | skipped unless PIPIT_PERF_WG=1 or PIPIT_PERF_MODES=wg is set because real WG mode creates a TUN/device and needs host privileges |"
        );
    }
    println!();
    println!("Tune with environment variables:");
    println!(
        "`PIPIT_PERF_MODES`, `PIPIT_PERF_WG`, `PIPIT_PERF_WARMUP`, `PIPIT_PERF_REQUESTS`, `PIPIT_PERF_LARGE_DOWNLOADS`, `PIPIT_PERF_LARGE_BYTES`."
    );
}

fn selected_modes() -> Vec<ProxyMode> {
    let non_wg = [
        ProxyMode::NativeHttp,
        ProxyMode::NativeMux,
        ProxyMode::DazeAshe,
        ProxyMode::DazeBaboon,
        ProxyMode::DazeCzar,
    ];
    let all = [
        ProxyMode::NativeHttp,
        ProxyMode::NativeMux,
        ProxyMode::DazeAshe,
        ProxyMode::DazeBaboon,
        ProxyMode::DazeCzar,
        ProxyMode::Wg,
    ];

    let Some(selected) = std::env::var("PIPIT_PERF_MODES").ok() else {
        return if env_bool("PIPIT_PERF_WG") {
            all.to_vec()
        } else {
            non_wg.to_vec()
        };
    };
    let selected: Vec<_> = selected
        .split(',')
        .map(str::trim)
        .filter(|mode| !mode.is_empty())
        .collect();
    all.into_iter()
        .filter(|mode| selected.iter().any(|selected| *selected == mode.as_str()))
        .collect()
}

fn average_latency_ms(samples: &[Duration]) -> f64 {
    let total_secs: f64 = samples.iter().map(Duration::as_secs_f64).sum();
    (total_secs / samples.len().max(1) as f64) * 1000.0
}

fn percentile_latency_ms(samples: &[Duration], percentile: f64) -> f64 {
    if samples.is_empty() {
        return 0.0;
    }

    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = ((sorted.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    sorted[rank.min(sorted.len() - 1)].as_secs_f64() * 1000.0
}

fn bytes_to_mib(bytes: usize) -> f64 {
    bytes as f64 / 1024.0 / 1024.0
}

fn human_bytes(bytes: usize) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes_to_mib(bytes))
    } else if bytes >= 1024 {
        format!("{:.2} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

fn env_required(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn env_u16(name: &str) -> Result<u16> {
    let value = env_required(name)?;
    value
        .parse()
        .with_context(|| format!("failed to parse {name}={value} as a u16"))
}

fn env_bool(name: &str) -> bool {
    std::env::var(name)
        .map(|value| {
            matches!(
                value.as_str(),
                "1" | "true" | "TRUE" | "yes" | "YES" | "on" | "ON"
            )
        })
        .unwrap_or(false)
}

fn env_ip(name: &str, default: &str) -> Result<IpAddr> {
    let value = std::env::var(name).unwrap_or_else(|_| default.to_owned());
    value
        .parse()
        .with_context(|| format!("failed to parse {name}={value} as an IP address"))
}

fn env_string(name: &str, default: &'static str) -> String {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| default.to_owned())
}

fn default_wg_server_device() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "auto"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "pipitwgs0"
    }
}

fn default_wg_client_device() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "auto"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "pipitwgc0"
    }
}

fn host_cidr(ip: IpAddr) -> String {
    if ip.is_ipv6() {
        format!("{ip}/128")
    } else {
        format!("{ip}/32")
    }
}

fn wg_key_pair() -> (String, String) {
    let private_key = StaticSecret::random_from_rng(OsRng).to_bytes();
    let public_key = *PublicKey::from(&StaticSecret::from(private_key)).as_bytes();
    (STANDARD.encode(private_key), STANDARD.encode(public_key))
}

fn init_optional_tracing() {
    if std::env::var_os("PIPIT_PERF_LOG").is_none() {
        return;
    }

    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .try_init();
}

fn extract_path(request_buf: &[u8]) -> &str {
    std::str::from_utf8(request_buf)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}

fn free_port() -> Result<u16> {
    let listener = StdTcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("failed to allocate local port")?;
    Ok(listener.local_addr()?.port())
}

fn free_udp_port() -> Result<u16> {
    let socket = std::net::UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("failed to allocate local UDP port")?;
    Ok(socket.local_addr()?.port())
}

async fn wait_for_tcp_listener(port: u16) -> Result<()> {
    wait_for_tcp_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port))).await
}

async fn wait_for_tcp_addr(addr: SocketAddr) -> Result<()> {
    timeout(Duration::from_secs(2), async move {
        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    drop(stream);
                    return Ok::<(), anyhow::Error>(());
                }
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .with_context(|| format!("timed out waiting for {addr} to accept connections"))??;

    Ok(())
}

fn terminate_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
        for _ in 0..50 {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => thread::sleep(Duration::from_millis(100)),
                Err(_) => return,
            }
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

fn write_temp_cert_pair() -> Result<(PathBuf, PathBuf)> {
    let certified = generate_simple_self_signed(vec!["example.com".to_owned()])
        .context("failed to generate self-signed certificate")?;
    let id = NEXT_CERT_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("pipit-mode-perf-{}-{id}", std::process::id()));
    let cert_path = base.with_extension("crt");
    let key_path = base.with_extension("key");
    fs::write(&cert_path, certified.cert.pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    fs::write(&key_path, certified.key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok((cert_path, key_path))
}
