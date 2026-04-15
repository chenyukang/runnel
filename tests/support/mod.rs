#![allow(dead_code)]

use anyhow::{Context, Result};
use rcgen::generate_simple_self_signed;
use std::{
    fs,
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    path::{Path, PathBuf},
    sync::Once,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tracing_subscriber::EnvFilter;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static TRACING: Once = Once::new();

pub struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Result<Self> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{id}"));
        fs::create_dir_all(&path)
            .with_context(|| format!("failed to create temp dir {}", path.display()))?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, name: impl AsRef<Path>) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub fn init_test_tracing() {
    TRACING.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::new("info"))
            .with_target(false)
            .with_test_writer()
            .try_init();
    });
}

pub fn free_port() -> Result<u16> {
    let listener = StdTcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("failed to allocate local port")?;
    Ok(listener.local_addr()?.port())
}

pub async fn wait_for_tcp_listener(port: u16) -> Result<()> {
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

pub fn spawn_http_target<F>(port: u16, responder: F) -> JoinHandle<()>
where
    F: Fn(&str, &[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    let responder = std::sync::Arc::new(responder);
    tokio::spawn(async move {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        loop {
            let (mut socket, _) = listener.accept().await.unwrap();
            let responder = responder.clone();
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 4096];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) => return,
                        Ok(n) => {
                            if buf[..n].windows(4).any(|window| window == b"\r\n\r\n") {
                                let path = extract_path(&buf[..n]);
                                let body = responder(path, &buf[..n]);
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    body.len()
                                );
                                let _ = socket.write_all(response.as_bytes()).await;
                                let _ = socket.write_all(&body).await;
                                let _ = socket.shutdown().await;
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    })
}

pub async fn fetch_plain_http(addr: &str, path: &str) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("failed to connect to {addr}"))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

pub async fn fetch_tls_http_path(
    addr: &str,
    server_name: &str,
    path: &str,
    ca_cert: &Path,
) -> Result<Vec<u8>> {
    let connector = TlsConnector::from(pipit::tls::load_client_config(Some(ca_cert))?);
    let socket = TcpStream::connect(addr)
        .await
        .with_context(|| format!("failed to connect to {addr}"))?;
    let tls_server_name = pipit::tls::server_name(server_name)?;
    let mut stream = connector
        .connect(tls_server_name, socket)
        .await
        .context("failed to complete TLS handshake")?;
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {server_name}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let mut buf = [0_u8; 4096];
    loop {
        match stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buf[..n]),
            Err(err)
                if err.kind() == std::io::ErrorKind::UnexpectedEof
                    || err.to_string().contains("close_notify") =>
            {
                break;
            }
            Err(err) => return Err(err).context("failed to read TLS response body"),
        }
    }
    Ok(response)
}

pub async fn fetch_via_socks_ip_path(
    socks_port: u16,
    target_port: u16,
    path: &str,
) -> Result<Vec<u8>> {
    let mut stream = connect_socks_listener(socks_port).await?;
    write_socks_ip_connect(&mut stream, target_port).await?;
    let reply_code = read_socks_connect_reply_code(&mut stream).await?;
    anyhow::ensure!(
        reply_code == 0x00,
        "unexpected SOCKS connect reply {reply_code}"
    );

    let request = format!("GET {path} HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

pub async fn fetch_via_socks_domain_path(
    socks_port: u16,
    host: &str,
    target_port: u16,
    path: &str,
) -> Result<Vec<u8>> {
    let mut stream = connect_socks_listener(socks_port).await?;
    write_socks_domain_connect(&mut stream, host, target_port).await?;
    let reply_code = read_socks_connect_reply_code(&mut stream).await?;
    anyhow::ensure!(
        reply_code == 0x00,
        "unexpected SOCKS connect reply {reply_code}"
    );

    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

pub async fn socks_connect_ip_reply(socks_port: u16, target_port: u16) -> Result<u8> {
    let mut stream = connect_socks_listener(socks_port).await?;
    write_socks_ip_connect(&mut stream, target_port).await?;
    read_socks_connect_reply_code(&mut stream).await
}

pub async fn socks_connect_domain_reply(
    socks_port: u16,
    host: &str,
    target_port: u16,
) -> Result<u8> {
    let mut stream = connect_socks_listener(socks_port).await?;
    write_socks_domain_connect(&mut stream, host, target_port).await?;
    read_socks_connect_reply_code(&mut stream).await
}

pub fn write_temp_cert_pair(prefix: &str) -> Result<(PathBuf, PathBuf)> {
    let certified = generate_simple_self_signed(vec!["example.com".to_owned()])
        .context("failed to generate self-signed certificate")?;
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let base = std::env::temp_dir().join(format!("{prefix}-{id}"));
    let cert_path = base.with_extension("crt");
    let key_path = base.with_extension("key");
    fs::write(&cert_path, certified.cert.pem())
        .with_context(|| format!("failed to write {}", cert_path.display()))?;
    fs::write(&key_path, certified.key_pair.serialize_pem())
        .with_context(|| format!("failed to write {}", key_path.display()))?;
    Ok((cert_path, key_path))
}

async fn connect_socks_listener(socks_port: u16) -> Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))
        .await
        .context("failed to connect to local SOCKS listener")?;

    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut method_reply = [0_u8; 2];
    stream.read_exact(&mut method_reply).await?;
    anyhow::ensure!(method_reply == [0x05, 0x00], "unexpected SOCKS auth reply");
    Ok(stream)
}

async fn write_socks_ip_connect(stream: &mut TcpStream, target_port: u16) -> Result<()> {
    let mut connect = vec![0x05, 0x01, 0x00, 0x01];
    connect.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
    connect.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect).await?;
    Ok(())
}

async fn write_socks_domain_connect(
    stream: &mut TcpStream,
    host: &str,
    target_port: u16,
) -> Result<()> {
    anyhow::ensure!(
        host.len() <= u8::MAX as usize,
        "host is too long for SOCKS5 domain encoding"
    );
    let mut connect = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    connect.extend_from_slice(host.as_bytes());
    connect.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect).await?;
    Ok(())
}

async fn read_socks_connect_reply_code(stream: &mut TcpStream) -> Result<u8> {
    let mut head = [0_u8; 4];
    stream.read_exact(&mut head).await?;
    anyhow::ensure!(
        head[0] == 0x05,
        "unexpected SOCKS reply version {}",
        head[0]
    );

    match head[3] {
        0x01 => {
            let mut buf = [0_u8; 6];
            stream.read_exact(&mut buf).await?;
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0_u8; len[0] as usize + 2];
            stream.read_exact(&mut buf).await?;
        }
        0x04 => {
            let mut buf = [0_u8; 18];
            stream.read_exact(&mut buf).await?;
        }
        atyp => anyhow::bail!("unexpected SOCKS reply address type {atyp}"),
    }

    Ok(head[1])
}

fn extract_path(request_buf: &[u8]) -> &str {
    std::str::from_utf8(request_buf)
        .ok()
        .and_then(|text| text.lines().next())
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/")
}
