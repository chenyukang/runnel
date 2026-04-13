use anyhow::{Context, Result};
use pipit::{
    client::{self, ClientArgs},
    mode::ProxyMode,
    route::FilterMode,
    server::{self, ServerArgs},
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
    net::{TcpListener, TcpStream},
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
    _server_handle: JoinHandle<()>,
    _client_handle: JoinHandle<()>,
    target_port: u16,
    socks_port: u16,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
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

#[tokio::test]
async fn native_http_mode_round_trip_works() {
    let _guard = test_lock().lock().await;
    assert_mode_round_trip(ProxyMode::NativeHttp).await.unwrap();
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
    let server_port = free_port()?;
    let socks_port = free_port()?;
    let fallback_port = free_port()?;

    let target_handle = tokio::spawn(run_http_target(target_port));
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
        _server_handle: server_handle,
        _client_handle: client_handle,
        target_port,
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
