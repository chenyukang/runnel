use anyhow::{Context, Result};
use pipit::{
    client::{self, ClientArgs},
    mode::ProxyMode,
    route::FilterMode,
    server::{self, ServerArgs},
    socks5,
};
use rcgen::generate_simple_self_signed;
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    sync::{Once, OnceLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing_subscriber::EnvFilter;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static TRACING: Once = Once::new();
static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct TestEnv {
    _target_handle: JoinHandle<()>,
    _udp_target_handle: JoinHandle<()>,
    _server_handle: JoinHandle<()>,
    _client_handle: JoinHandle<()>,
    target_port: u16,
    udp_target_port: u16,
    socks_port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

struct LocalClientEnv {
    _upstream_handle: JoinHandle<()>,
    _server_handle: JoinHandle<()>,
    _client_handle: JoinHandle<()>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        self._target_handle.abort();
        self._server_handle.abort();
        self._client_handle.abort();
        if let Some(path) = &self.cert_path {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = &self.key_path {
            let _ = fs::remove_file(path);
        }
    }
}

impl Drop for LocalClientEnv {
    fn drop(&mut self) {
        self._upstream_handle.abort();
        self._server_handle.abort();
        self._client_handle.abort();
        let _ = fs::remove_file(&self.cert_path);
        let _ = fs::remove_file(&self.key_path);
    }
}

#[tokio::test]
async fn native_http_mode_round_trip_works() {
    let _guard = test_lock().lock().await;
    assert_mode_round_trip(ProxyMode::NativeHttp).await.unwrap();
}

#[tokio::test]
async fn native_http_mode_udp_associate_round_trip_works() {
    let _guard = test_lock().lock().await;
    let env = start_env(ProxyMode::NativeHttp).await.unwrap();
    let response = timeout(
        Duration::from_secs(5),
        exchange_udp_via_socks(env.socks_port, env.udp_target_port, b"hello over udp"),
    )
    .await
    .context("timed out waiting for SOCKS UDP round trip")
    .unwrap()
    .unwrap();
    assert_eq!(response, b"hello over udp");
}

#[tokio::test]
async fn native_http_mode_tun_dns_tcp_override_relays_via_remote_tunnel() {
    let _guard = test_lock().lock().await;
    init_test_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_port = free_port().unwrap();
    let echo_handle = tokio::spawn(run_tcp_echo_target(upstream_port));
    let (_env, socks_port) = start_local_dns_client(echo_handle, upstream_port).await.unwrap();

    let payload = b"\x00\x05hello";
    let response = timeout(
        Duration::from_secs(5),
        exchange_tcp_via_socks_target(
            socks_port,
            socks5::TargetAddr::Ip(Ipv4Addr::new(198, 18, 0, 1).into(), 53),
            payload,
        ),
    )
    .await
    .context("timed out waiting for tun DNS TCP override round trip")
    .unwrap()
    .unwrap();

    assert_eq!(response, payload);
}

#[tokio::test]
async fn native_http_mode_tun_dns_udp_override_relays_via_remote_tcp_tunnel() {
    let _guard = test_lock().lock().await;
    init_test_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let upstream_port = free_port().unwrap();
    let echo_handle = tokio::spawn(run_tcp_echo_target(upstream_port));
    let (_env, socks_port) = start_local_dns_client(echo_handle, upstream_port).await.unwrap();

    let payload = b"\x12\x34hello over dns";
    let response = timeout(
        Duration::from_secs(5),
        exchange_udp_via_socks_target(
            socks_port,
            socks5::TargetAddr::Ip(Ipv4Addr::new(198, 18, 0, 1).into(), 53),
            payload,
        ),
    )
    .await
    .context("timed out waiting for tun DNS UDP override round trip")
    .unwrap()
    .unwrap();

    assert_eq!(response, payload);
}

#[tokio::test]
async fn native_mux_mode_round_trip_works() {
    let _guard = test_lock().lock().await;
    assert_mode_round_trip(ProxyMode::NativeMux).await.unwrap();
}

#[tokio::test]
async fn native_mux_mode_survives_concurrent_large_responses() {
    let _guard = test_lock().lock().await;
    let env = start_env(ProxyMode::NativeMux).await.unwrap();
    let mut tasks = Vec::new();

    for _ in 0..32 {
        let socks_port = env.socks_port;
        let target_port = env.target_port;
        tasks.push(tokio::spawn(async move {
            timeout(
                Duration::from_secs(10),
                fetch_via_socks_path(socks_port, target_port, "/large"),
            )
            .await
            .context("timed out waiting for large SOCKS round trip")?
        }));
    }

    for task in tasks {
        let body = task.await.unwrap().unwrap();
        assert!(
            body.ends_with(large_body().as_bytes()),
            "unexpected response body suffix: {:?}",
            String::from_utf8_lossy(&body[body.len().saturating_sub(64)..])
        );
    }
}

#[tokio::test]
async fn daze_ashe_mode_round_trip_works() {
    let _guard = test_lock().lock().await;
    assert_mode_round_trip(ProxyMode::DazeAshe).await.unwrap();
}

#[tokio::test]
async fn daze_baboon_mode_round_trip_works() {
    let _guard = test_lock().lock().await;
    assert_mode_round_trip(ProxyMode::DazeBaboon).await.unwrap();
}

#[tokio::test]
async fn daze_czar_mode_round_trip_works() {
    let _guard = test_lock().lock().await;
    assert_mode_round_trip(ProxyMode::DazeCzar).await.unwrap();
}

async fn assert_mode_round_trip(mode: ProxyMode) -> Result<()> {
    let env = start_env(mode).await?;
    let body = timeout(
        Duration::from_secs(5),
        fetch_via_socks_path(env.socks_port, env.target_port, "/"),
    )
    .await
    .context("timed out waiting for SOCKS round trip")??;

    assert!(
        body.ends_with(b"ok"),
        "unexpected response body: {:?}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

async fn start_env(mode: ProxyMode) -> Result<TestEnv> {
    init_test_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let target_port = free_port()?;
    let udp_target_port = free_port()?;
    let server_port = free_port()?;
    let socks_port = free_port()?;
    let fallback_port = free_port()?;

    let target_handle = tokio::spawn(run_http_target(target_port));
    let udp_target_handle = tokio::spawn(run_udp_target(udp_target_port));
    let fallback_url = format!("http://127.0.0.1:{fallback_port}");

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
        fallback_url,
        fallback_timeout_secs: 5,
        max_fallback_body_size: 1024 * 1024,
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
        user_agent: "pipit-test".to_owned(),
        handshake_timeout_secs: 10,
        connect_timeout_secs: 10,
        max_header_size: 16 * 1024,
        system_proxy: false,
        system_proxy_services: Vec::new(),
        tun_dns_redirect_ip: None,
        tun_dns_upstream: None,
    };

    let server_handle = tokio::spawn(async move {
        let _ = server::run(server_args).await;
    });
    sleep(Duration::from_millis(150)).await;

    let client_handle = tokio::spawn(async move {
        let _ = client::run(client_args).await;
    });
    wait_for_tcp_listener(socks_port).await?;

    Ok(TestEnv {
        _target_handle: target_handle,
        _udp_target_handle: udp_target_handle,
        _server_handle: server_handle,
        _client_handle: client_handle,
        target_port,
        udp_target_port,
        socks_port,
        cert_path,
        key_path,
    })
}

fn init_test_tracing() {
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("info"))
            .with_target(false)
            .with_test_writer()
            .try_init();
    });
}

fn test_lock() -> &'static Mutex<()> {
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

async fn run_http_target(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => {
                        if buf[..n].windows(4).any(|window| window == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => return,
                }
            }

            let body = if extract_path(&buf) == "/large" {
                large_body().into_bytes()
            } else {
                b"ok".to_vec()
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(response.as_bytes()).await;
            let _ = socket.write_all(&body).await;
            let _ = socket.shutdown().await;
        });
    }
}

async fn run_udp_target(port: u16) {
    let socket = UdpSocket::bind(("127.0.0.1", port)).await.unwrap();
    let mut buf = vec![0_u8; 64 * 1024];

    loop {
        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
        let _ = socket.send_to(&buf[..n], peer).await;
    }
}

async fn run_tcp_echo_target(port: u16) {
    let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
    loop {
        let (mut socket, _) = listener.accept().await.unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0_u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => {
                        let _ = socket.shutdown().await;
                        return;
                    }
                    Ok(n) => {
                        if socket.write_all(&buf[..n]).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }
}

async fn fetch_via_socks_path(socks_port: u16, target_port: u16, path: &str) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .context("failed to connect to local SOCKS listener")?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "unexpected SOCKS auth reply");

    let mut connect = vec![0x05, 0x01, 0x00, 0x01];
    connect.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    connect.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect).await?;

    let mut connect_reply = [0_u8; 10];
    stream.read_exact(&mut connect_reply).await?;
    anyhow::ensure!(connect_reply[1] == 0x00, "unexpected SOCKS connect reply");

    let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn exchange_tcp_via_socks_target(
    socks_port: u16,
    target: socks5::TargetAddr,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .context("failed to connect to local SOCKS listener")?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "unexpected SOCKS auth reply");

    let mut connect = vec![0x05, 0x01, 0x00];
    match &target {
        socks5::TargetAddr::Ip(std::net::IpAddr::V4(addr), port) => {
            connect.push(0x01);
            connect.extend_from_slice(&addr.octets());
            connect.extend_from_slice(&port.to_be_bytes());
        }
        socks5::TargetAddr::Domain(host, port) => {
            connect.push(0x03);
            connect.push(host.len() as u8);
            connect.extend_from_slice(host.as_bytes());
            connect.extend_from_slice(&port.to_be_bytes());
        }
        socks5::TargetAddr::Ip(std::net::IpAddr::V6(addr), port) => {
            connect.push(0x04);
            connect.extend_from_slice(&addr.octets());
            connect.extend_from_slice(&port.to_be_bytes());
        }
    }
    stream.write_all(&connect).await?;
    let _ = read_socks_reply_addr(&mut stream).await?;

    stream.write_all(payload).await?;
    let mut response = vec![0_u8; payload.len()];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

async fn exchange_udp_via_socks(
    socks_port: u16,
    target_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    exchange_udp_via_socks_target(
        socks_port,
        socks5::TargetAddr::Ip(Ipv4Addr::LOCALHOST.into(), target_port),
        payload,
    )
    .await
}

async fn exchange_udp_via_socks_target(
    socks_port: u16,
    target: socks5::TargetAddr,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let mut control = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .context("failed to connect to local SOCKS listener")?;

    control.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_reply = [0_u8; 2];
    control.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "unexpected SOCKS auth reply");

    let udp_associate = [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    control.write_all(&udp_associate).await?;

    let relay_addr = read_socks_reply_addr(&mut control).await?;
    let relay = UdpSocket::bind(("127.0.0.1", 0))
        .await
        .context("failed to bind local UDP client socket")?;
    let packet = socks5::build_udp_packet(&target, payload);
    relay
        .send_to(&packet, relay_addr)
        .await
        .context("failed to send UDP packet to SOCKS relay")?;

    let mut buf = vec![0_u8; 64 * 1024];
    let (n, _) = relay
        .recv_from(&mut buf)
        .await
        .context("failed to receive UDP packet from SOCKS relay")?;
    let response = socks5::parse_udp_packet(&buf[..n]).context("invalid SOCKS UDP response")?;
    anyhow::ensure!(
        response.target == target,
        "unexpected UDP response target: {}",
        response.target
    );
    Ok(response.payload)
}

async fn read_socks_reply_addr(stream: &mut TcpStream) -> Result<SocketAddr> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    anyhow::ensure!(head[0] == 0x05, "unexpected SOCKS reply version");
    anyhow::ensure!(head[1] == 0x00, "unexpected SOCKS reply code {}", head[1]);

    let addr = match head[3] {
        0x01 => {
            let mut ip = [0_u8; 4];
            let mut port = [0_u8; 2];
            stream.read_exact(&mut ip).await?;
            stream.read_exact(&mut port).await?;
            SocketAddr::from((ip, u16::from_be_bytes(port)))
        }
        0x04 => {
            let mut ip = [0_u8; 16];
            let mut port = [0_u8; 2];
            stream.read_exact(&mut ip).await?;
            stream.read_exact(&mut port).await?;
            SocketAddr::new(ip.into(), u16::from_be_bytes(port))
        }
        atyp => anyhow::bail!("unexpected SOCKS reply address type {atyp}"),
    };

    Ok(addr)
}

fn extract_path(request_buf: &[u8]) -> &str {
    std::str::from_utf8(request_buf)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}

fn large_body() -> String {
    "0123456789abcdef".repeat(8192)
}

fn free_port() -> Result<u16> {
    let listener = StdTcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("failed to allocate local port")?;
    Ok(listener.local_addr()?.port())
}

async fn wait_for_tcp_listener(port: u16) -> Result<()> {
    timeout(Duration::from_secs(2), async move {
        loop {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => {
                    drop(stream);
                    return Ok::<(), anyhow::Error>(());
                }
                Err(_) => sleep(Duration::from_millis(25)).await,
            }
        }
    })
    .await
    .context("timed out waiting for test listener to accept connections")??;

    Ok(())
}

async fn start_local_dns_client(
    upstream_handle: JoinHandle<()>,
    upstream_port: u16,
) -> Result<(LocalClientEnv, u16)> {
    let server_port = free_port()?;
    let socks_port = free_port()?;
    let (cert_path, key_path) = write_temp_cert_pair()?;

    let server_args = ServerArgs {
        listen: format!("127.0.0.1:{server_port}"),
        cert: Some(cert_path.clone()),
        key: Some(key_path.clone()),
        mode: ProxyMode::NativeHttp,
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
    };
    let client_args = ClientArgs {
        listen: format!("127.0.0.1:{socks_port}"),
        server: format!("127.0.0.1:{server_port}"),
        server_name: Some("example.com".to_owned()),
        ca_cert: Some(cert_path.clone()),
        mode: ProxyMode::NativeHttp,
        password: "hello-world".to_owned(),
        path: "/connect".to_owned(),
        mux_path: "/mux".to_owned(),
        mux: false,
        filter: FilterMode::Proxy,
        rule_file: None,
        cidr_file: None,
        user_agent: "pipit-test".to_owned(),
        handshake_timeout_secs: 10,
        connect_timeout_secs: 10,
        max_header_size: 16 * 1024,
        system_proxy: false,
        system_proxy_services: Vec::new(),
        tun_dns_redirect_ip: Some(Ipv4Addr::new(198, 18, 0, 1).into()),
        tun_dns_upstream: Some(SocketAddr::from((Ipv4Addr::LOCALHOST, upstream_port))),
    };

    let server_handle = tokio::spawn(async move {
        let _ = server::run(server_args).await;
    });
    wait_for_tcp_listener(server_port).await?;
    sleep(Duration::from_millis(50)).await;

    let client_handle = tokio::spawn(async move {
        let _ = client::run(client_args).await;
    });
    wait_for_tcp_listener(socks_port).await?;

    Ok((
        LocalClientEnv {
            _upstream_handle: upstream_handle,
            _server_handle: server_handle,
            _client_handle: client_handle,
            cert_path,
            key_path,
        },
        socks_port,
    ))
}

fn write_temp_cert_pair() -> Result<(PathBuf, PathBuf)> {
    let certified = generate_simple_self_signed(vec!["example.com".to_owned()])
        .context("failed to generate self-signed certificate")?;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("pipit-e2e-{id}"));
    let cert_path = base.with_extension("crt");
    let key_path = base.with_extension("key");
    fs::write(&cert_path, certified.cert.pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    fs::write(&key_path, certified.key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok((cert_path, key_path))
}
