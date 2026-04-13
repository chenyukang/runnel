use crate::{client::ClientArgs, http, mode::ProxyMode, route, route::RouteDecision, server::ServerArgs, socks5};
use anyhow::{Context, Result, bail};
use md5::Context as Md5Context;
use reqwest::{
    Client as HttpClient, Method, Url,
    header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING},
};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{info, warn};

const ASHE_LIFE_EXPIRED_SECS: u64 = 120;
const ASHE_NET_TCP: u8 = 0x01;
const BABOON_PATH: &str = "/sync";

pub async fn run_client(args: ClientArgs) -> Result<()> {
    match args.effective_mode()? {
        ProxyMode::DazeAshe => {}
        ProxyMode::DazeBaboon => return run_baboon_client(args).await,
        _ => bail!("unsupported daze client mode"),
    }

    let router = route::Router::from_args(&args)?;
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        server = %args.server,
        mode = "daze-ashe",
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(socket, peer, router, args).await {
                warn!(peer = %peer, error = %err, "daze-ashe client session ended with error");
            }
        });
    }
}

pub async fn run_server(args: ServerArgs) -> Result<()> {
    match args.mode {
        ProxyMode::DazeAshe => {}
        ProxyMode::DazeBaboon => return run_baboon_server(args).await,
        _ => bail!("unsupported daze server mode"),
    }

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        mode = "daze-ashe",
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(socket, peer, args).await {
                warn!(peer = %peer, error = %err, "daze-ashe server session ended with error");
            }
        });
    }
}

async fn handle_client_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    router: Arc<route::Router>,
    args: ClientArgs,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let target = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        socks5::accept(&mut inbound),
    )
    .await
    .context("SOCKS handshake timed out")??;
    let target_string = target.to_string();

    match router.decide(&target).await? {
        RouteDecision::Direct => {
            let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
            let _ = route::relay_direct_socks(inbound, &target, connect_timeout).await?;
            info!(peer = %peer, target = %target_string, route = "direct", mode = "daze-ashe", "relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    if target_string.len() > u8::MAX as usize {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("destination address too long");
    }

    let mut upstream = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&args.server),
    )
    .await
    .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let (upload, download) = client_establish_ashe(&mut upstream, &args.password, &target_string).await?;

    socks5::send_success(&mut inbound).await?;
    relay_rc4(inbound, upstream, upload, download).await?;

    info!(peer = %peer, target = %target_string, mode = "daze-ashe", "relay completed");
    Ok(())
}

async fn handle_server_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    args: ServerArgs,
) -> Result<()> {
    inbound.set_nodelay(true)?;

    let (download, upload, target) = server_accept_ashe(&mut inbound, &args).await?;

    let outbound = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&target),
    )
    .await
    .context("upstream connect timed out")??;
    outbound.set_nodelay(true)?;

    let mut code = [0_u8];
    let mut upload = upload;
    upload.apply_keystream(&mut code);
    inbound.write_all(&code).await?;

    relay_rc4(inbound, outbound, download, upload).await?;

    info!(peer = %peer, target = %target, mode = "daze-ashe", "relay completed");
    Ok(())
}

async fn run_baboon_client(args: ClientArgs) -> Result<()> {
    let router = route::Router::from_args(&args)?;
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        server = %args.server,
        mode = "daze-baboon",
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_baboon_client_connection(socket, peer, router, args).await {
                warn!(peer = %peer, error = %err, "daze-baboon client session ended with error");
            }
        });
    }
}

async fn run_baboon_server(args: ServerArgs) -> Result<()> {
    let fallback = BaboonFallback::new(
        &args.fallback_url,
        Duration::from_secs(args.fallback_timeout_secs),
        args.max_fallback_body_size,
    )?;
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        mode = "daze-baboon",
        fallback = %args.fallback_url,
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        let fallback = fallback.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_baboon_server_connection(socket, peer, args, fallback).await {
                warn!(peer = %peer, error = %err, "daze-baboon server session ended with error");
            }
        });
    }
}

async fn handle_baboon_client_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    router: Arc<route::Router>,
    args: ClientArgs,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let target = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        socks5::accept(&mut inbound),
    )
    .await
    .context("SOCKS handshake timed out")??;
    let target_string = target.to_string();

    match router.decide(&target).await? {
        RouteDecision::Direct => {
            let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
            let _ = route::relay_direct_socks(inbound, &target, connect_timeout).await?;
            info!(peer = %peer, target = %target_string, route = "direct", mode = "daze-baboon", "relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    if target_string.len() > u8::MAX as usize {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("destination address too long");
    }

    let mut upstream = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&args.server),
    )
    .await
    .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let request = build_baboon_request(&args.password, &args.server);
    upstream.write_all(request.as_bytes()).await?;

    let (head, _) = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        http::read_head(&mut upstream, args.max_header_size),
    )
    .await
    .context("baboon response timed out")??;
    let (is_http1, status, reason) =
        http::parse_tunnel_response(&head).context("invalid baboon response")?;
    if !is_http1 || status != 200 {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("daze-baboon server refused sync with status {} {}", status, reason);
    }

    let (upload, download) = client_establish_ashe(&mut upstream, &args.password, &target_string).await?;

    socks5::send_success(&mut inbound).await?;
    relay_rc4(inbound, upstream, upload, download).await?;

    info!(peer = %peer, target = %target_string, mode = "daze-baboon", "relay completed");
    Ok(())
}

async fn handle_baboon_server_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    args: ServerArgs,
    fallback: BaboonFallback,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let (head, body_prefix) = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        http::read_head(&mut inbound, args.max_header_size),
    )
    .await
    .context("baboon request head timed out")??;

    let request = match http::parse_request(&head) {
        Ok(request) => request,
        Err(err) => {
            inbound
                .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
                .await?;
            return Err(err.context("invalid baboon request"));
        }
    };

    if request.method == "POST" && request.path == BABOON_PATH && validate_baboon_request(&request, &args.password) {
        inbound
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\n\r\n",
            )
            .await?;

        let (download, upload, target) = server_accept_ashe(&mut inbound, &args).await?;
        let outbound = timeout(
            Duration::from_secs(args.connect_timeout_secs),
            TcpStream::connect(&target),
        )
        .await
        .context("upstream connect timed out")??;
        outbound.set_nodelay(true)?;

        let mut code = [0_u8];
        let mut upload = upload;
        upload.apply_keystream(&mut code);
        inbound.write_all(&code).await?;

        relay_rc4(inbound, outbound, download, upload).await?;
        info!(peer = %peer, target = %target, mode = "daze-baboon", "relay completed");
        return Ok(());
    }

    fallback.proxy(&mut inbound, request, &body_prefix).await?;
    Ok(())
}

pub(crate) async fn client_establish_ashe<S>(
    stream: &mut S,
    password: &str,
    target: &str,
) -> Result<(Rc4State, Rc4State)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let password = salt(password);
    let mut random = [0_u8; 32];
    fill_random(&mut random);
    stream.write_all(&random).await?;

    let session_key = xor_key(&random, &password);
    let mut dec = Rc4State::new(&session_key);
    let mut enc = Rc4State::new(&session_key);

    let timestamp = unix_timestamp()?;
    let mut ts = timestamp.to_be_bytes();
    enc.apply_keystream(&mut ts);
    stream.write_all(&ts).await?;

    let mut open = Vec::with_capacity(2 + target.len());
    open.push(ASHE_NET_TCP);
    open.push(target.len() as u8);
    open.extend_from_slice(target.as_bytes());
    enc.apply_keystream(&mut open);
    stream.write_all(&open).await?;

    let mut code = [0_u8; 1];
    stream.read_exact(&mut code).await?;
    dec.apply_keystream(&mut code);
    if code[0] != 0 {
        bail!("daze-ashe server refused target");
    }

    Ok((enc, dec))
}

pub(crate) async fn server_accept_ashe<S>(
    stream: &mut S,
    args: &ServerArgs,
) -> Result<(Rc4State, Rc4State, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut random = [0_u8; 32];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        stream.read_exact(&mut random),
    )
    .await
    .context("daze-ashe salt read timed out")??;

    let password = salt(&args.password);
    let session_key = xor_key(&random, &password);
    let mut dec = Rc4State::new(&session_key);
    let enc = Rc4State::new(&session_key);

    let mut ts = [0_u8; 8];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        stream.read_exact(&mut ts),
    )
    .await
    .context("daze-ashe timestamp read timed out")??;
    dec.apply_keystream(&mut ts);
    let timestamp = u64::from_be_bytes(ts) as i64;
    validate_timestamp(timestamp)?;

    let mut open_head = [0_u8; 2];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        stream.read_exact(&mut open_head),
    )
    .await
    .context("daze-ashe request read timed out")??;
    dec.apply_keystream(&mut open_head);
    if open_head[0] != ASHE_NET_TCP {
        bail!("only tcp is supported in daze-ashe mode");
    }

    let addr_len = open_head[1] as usize;
    let mut address = vec![0_u8; addr_len];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        stream.read_exact(&mut address),
    )
    .await
    .context("daze-ashe address read timed out")??;
    dec.apply_keystream(&mut address);
    let target = String::from_utf8(address).context("daze-ashe address is not valid UTF-8")?;

    if !args.allow_private_targets && is_private_literal_target(&target) {
        bail!("literal private IP targets are disabled by default");
    }

    Ok((dec, enc, target))
}

fn build_baboon_request(password: &str, server: &str) -> String {
    let mut random = [0_u8; 16];
    fill_random(&mut random);
    let cipher = salt(password);
    let mut auth = [0_u8; 32];
    auth[..16].copy_from_slice(&random);

    let mut md5 = Md5Context::new();
    md5.consume(random);
    md5.consume(&cipher[..16]);
    auth[16..].copy_from_slice(&md5.compute().0);

    format!(
        concat!(
            "POST {} HTTP/1.1\r\n",
            "Host: {}\r\n",
            "Authorization: {}\r\n",
            "Content-Length: 0\r\n",
            "Connection: keep-alive\r\n",
            "\r\n"
        ),
        BABOON_PATH,
        server,
        hex::encode(auth),
    )
}

fn validate_baboon_request(request: &http::HttpRequest, password: &str) -> bool {
    let auth = match http::header(&request.headers, "authorization") {
        Some(value) => value,
        None => return false,
    };
    let auth = match hex::decode(auth) {
        Ok(value) if value.len() == 32 => value,
        _ => return false,
    };

    let cipher = salt(password);
    let mut md5 = Md5Context::new();
    md5.consume(&auth[..16]);
    md5.consume(&cipher[..16]);
    auth[16..] == md5.compute().0
}

#[derive(Clone)]
struct BaboonFallback {
    client: HttpClient,
    base_url: Url,
    max_body_size: usize,
}

impl BaboonFallback {
    fn new(base_url: &str, timeout: Duration, max_body_size: usize) -> Result<Self> {
        let base_url = Url::parse(base_url).context("invalid fallback URL")?;
        let client = HttpClient::builder()
            .timeout(timeout)
            .build()
            .context("failed to build baboon fallback HTTP client")?;

        Ok(Self {
            client,
            base_url,
            max_body_size,
        })
    }

    async fn proxy<S>(
        &self,
        stream: &mut S,
        request: http::HttpRequest,
        body_prefix: &[u8],
    ) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if http::is_chunked(&request.headers) {
            bail!("chunked request bodies are not supported for baboon fallback");
        }

        let body_length = http::content_length(&request.headers)?.unwrap_or(0);
        let body = if body_length == 0 {
            Vec::new()
        } else {
            http::read_body(stream, body_prefix, body_length, self.max_body_size).await?
        };

        let method =
            Method::from_bytes(request.method.as_bytes()).context("invalid request method")?;
        let url = baboon_fallback_request_url(&self.base_url, &request.path)?;
        let mut builder = self.client.request(method, url).body(body);
        let mut headers = HeaderMap::new();

        for (name, value) in &request.headers {
            if should_skip_request_header(name) {
                continue;
            }

            let name = HeaderName::from_bytes(name.as_bytes()).context("invalid header name")?;
            let value = HeaderValue::from_str(value).context("invalid header value")?;
            headers.append(name, value);
        }

        builder = builder.headers(headers);
        let response = builder
            .send()
            .await
            .context("baboon fallback upstream request failed")?;
        let status = response.status();
        let reason = status.canonical_reason().unwrap_or("OK").to_owned();
        let mut response_headers = Vec::new();

        for (name, value) in response.headers() {
            if should_skip_response_header(name.as_str()) {
                continue;
            }
            if let Ok(value) = value.to_str() {
                response_headers.push((name.as_str().to_owned(), value.to_owned()));
            }
        }

        let body = response
            .bytes()
            .await
            .context("failed to read baboon fallback response body")?;
        let encoded = http::build_response(status.as_u16(), &reason, &response_headers, &body);
        stream.write_all(&encoded).await?;
        Ok(())
    }
}

fn baboon_fallback_request_url(base: &Url, request_target: &str) -> Result<Url> {
    if request_target == "*" {
        return Ok(base.clone());
    }

    if request_target.starts_with('/') {
        return base
            .join(request_target)
            .with_context(|| format!("failed to join baboon fallback URL with {request_target}"));
    }

    if let Ok(url) = Url::parse(request_target) {
        let mut target = base.clone();
        target.set_path(url.path());
        target.set_query(url.query());
        return Ok(target);
    }

    base.join("/")
        .context("failed to build root baboon fallback request URL")
}

fn should_skip_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(HOST.as_str())
        || name.eq_ignore_ascii_case(CONNECTION.as_str())
        || name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("keep-alive")
        || name.eq_ignore_ascii_case("upgrade")
}

fn should_skip_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(CONNECTION.as_str())
        || name.eq_ignore_ascii_case(CONTENT_LENGTH.as_str())
        || name.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
        || name.eq_ignore_ascii_case("keep-alive")
}

pub(crate) async fn relay_rc4<A, B>(
    inbound: A,
    outbound: B,
    mut upload_cipher: Rc4State,
    mut download_cipher: Rc4State,
) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(inbound);
    let (mut outbound_reader, mut outbound_writer) = tokio::io::split(outbound);

    let uplink = async {
        let mut buf = vec![0_u8; 32 * 1024];
        loop {
            let n = inbound_reader.read(&mut buf).await?;
            if n == 0 {
                let _ = outbound_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }

            let mut chunk = buf[..n].to_vec();
            upload_cipher.apply_keystream(&mut chunk);
            outbound_writer.write_all(&chunk).await?;
        }
    };

    let downlink = async {
        let mut buf = vec![0_u8; 32 * 1024];
        loop {
            let n = outbound_reader.read(&mut buf).await?;
            if n == 0 {
                let _ = inbound_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }

            let mut chunk = buf[..n].to_vec();
            download_cipher.apply_keystream(&mut chunk);
            inbound_writer.write_all(&chunk).await?;
        }
    };

    tokio::select! {
        res = uplink => res,
        res = downlink => res,
    }
}

fn salt(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

fn xor_key(random: &[u8; 32], password: &[u8; 32]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = random[idx] ^ password[idx];
    }
    key
}

fn validate_timestamp(timestamp: i64) -> Result<()> {
    let now = unix_timestamp()?;
    let skew = now.abs_diff(timestamp);
    if skew > ASHE_LIFE_EXPIRED_SECS {
        bail!("daze-ashe request expired");
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    Ok(now.as_secs() as i64)
}

fn fill_random(buf: &mut [u8]) {
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(buf);
}

fn is_private_literal_target(target: &str) -> bool {
    match host_from_target(target).and_then(|host| host.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip == Ipv4Addr::BROADCAST
        }
        Some(IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
        None => false,
    }
}

fn host_from_target(target: &str) -> Option<&str> {
    if let Some(rest) = target.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }

    target.rsplit_once(':').map(|(host, _)| host)
}

#[derive(Clone)]
pub(crate) struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0_u8; 256];
        for (idx, byte) in s.iter_mut().enumerate() {
            *byte = idx as u8;
        }

        let mut j = 0_u8;
        for i in 0..256 {
            j = j
                .wrapping_add(s[i])
                .wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    pub(crate) fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            *byte ^= self.s[idx as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http;

    #[test]
    fn rc4_round_trip() {
        let key = [7_u8; 32];
        let mut enc = Rc4State::new(&key);
        let mut dec = Rc4State::new(&key);
        let mut data = b"hello world".to_vec();
        enc.apply_keystream(&mut data);
        dec.apply_keystream(&mut data);
        assert_eq!(data, b"hello world");
    }

    #[test]
    fn baboon_authorization_round_trip() {
        let request = build_baboon_request("secret", "example.com:443");
        let parsed = http::parse_request(request.as_bytes()).expect("request should parse");
        assert!(validate_baboon_request(&parsed, "secret"));
        assert!(!validate_baboon_request(&parsed, "wrong-secret"));
    }
}
