use crate::{
    mode::ProxyMode,
    proxy::{
        auth::{AUTH_FAILURE_BODY, AUTH_FAILURE_HINT, AuthProof, ReplayProtector},
        http, mux, netlog, tls, traffic, udp,
    },
    wg,
};
use anyhow::{Context, Result, bail};
use clap::Args;
use reqwest::{
    Client as HttpClient, Method, Url,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING,
    },
};
use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

#[derive(Clone, Debug, Args)]
pub struct ServerArgs {
    #[arg(long, default_value = "0.0.0.0:1443")]
    pub listen: String,
    #[arg(long)]
    pub cert: Option<PathBuf>,
    #[arg(long)]
    pub key: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ProxyMode::NativeHttp)]
    pub mode: ProxyMode,
    #[arg(long, env = "PIPIT_PASSWORD")]
    #[arg(default_value = "")]
    pub password: String,
    #[arg(long, default_value = "/connect")]
    pub path: String,
    #[arg(long, default_value = "/mux")]
    pub mux_path: String,
    #[arg(long, default_value_t = 120)]
    pub auth_window_secs: u64,
    #[arg(long, default_value_t = 10)]
    pub handshake_timeout_secs: u64,
    #[arg(long, default_value_t = 10)]
    pub connect_timeout_secs: u64,
    #[arg(long, default_value_t = 16 * 1024)]
    pub max_header_size: usize,
    #[arg(long, default_value_t = 8 * 1024)]
    pub max_tunnel_body_size: usize,
    #[arg(long)]
    pub allow_private_targets: bool,
    #[arg(long, default_value = "https://www.qq.com")]
    pub fallback_url: String,
    #[arg(long, default_value_t = 15)]
    pub fallback_timeout_secs: u64,
    #[arg(long, default_value_t = 1024 * 1024)]
    pub max_fallback_body_size: usize,
    #[arg(skip)]
    pub wg: wg::server::WgServerArgs,
}

pub async fn run(args: ServerArgs) -> Result<()> {
    if matches!(args.mode, ProxyMode::Wg) {
        return wg::server::run(args.wg).await;
    }

    args.validate_required()?;

    match args.mode {
        ProxyMode::NativeHttp | ProxyMode::NativeMux => {}
        ProxyMode::DazeAshe | ProxyMode::DazeBaboon | ProxyMode::DazeCzar => {
            return crate::daze::run_server(args).await;
        }
        ProxyMode::Wg => unreachable!("wg mode is dispatched before native server startup"),
    }

    let cert = args
        .cert
        .as_deref()
        .context("--cert is required for native modes")?;
    let key = args
        .key
        .as_deref()
        .context("--key is required for native modes")?;
    let acceptor = TlsAcceptor::from(tls::load_server_config(cert, key)?);
    let replay = Arc::new(ReplayProtector::new(Duration::from_secs(
        args.auth_window_secs,
    )));
    let fallback = Arc::new(Fallback::new(
        &args.fallback_url,
        Duration::from_secs(args.fallback_timeout_secs),
        args.max_fallback_body_size,
    )?);
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        path = %args.path,
        fallback = %args.fallback_url,
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let replay = replay.clone();
        let fallback = fallback.clone();
        let args = args.clone();

        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(socket, peer, acceptor, replay, fallback, args).await
            {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "server connection ended");
                } else {
                    warn!(peer = %peer, error = %err, "server connection ended with error");
                }
            }
        });
    }
}

impl ServerArgs {
    pub fn validate_required(&self) -> Result<()> {
        if self.password.trim().is_empty() {
            bail!(
                "server password is required; pass --password, set PIPIT_PASSWORD, or set it in --config"
            );
        }
        Ok(())
    }
}

async fn handle_connection(
    socket: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    replay: Arc<ReplayProtector>,
    fallback: Arc<Fallback>,
    args: ServerArgs,
) -> Result<()> {
    socket.set_nodelay(true)?;

    let mut stream = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        acceptor.accept(socket),
    )
    .await
    .context("TLS handshake timed out")??;

    let head = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        http::read_head(&mut stream, args.max_header_size),
    )
    .await
    .context("request head timed out")??;
    let (head, body_prefix) = head;

    if matches!(args.mode, ProxyMode::NativeMux)
        && let Some(mux_head) = http::parse_tunnel_request_head(&head, &args.mux_path)?
    {
        return mux::run_server_session(stream, peer, mux_head, &body_prefix, args, replay).await;
    }

    if matches!(args.mode, ProxyMode::NativeHttp)
        && let Some(tunnel_head) = http::parse_tunnel_request_head(&head, &args.path)?
    {
        if let Some(tunnel) =
            authorize_tunnel_request(&mut stream, tunnel_head, &body_prefix, &args, &replay).await?
        {
            if !args.allow_private_targets && is_private_literal_target(&tunnel.target) {
                let response = http::build_error_response(
                    403,
                    "Forbidden",
                    "literal private IP targets are disabled by default\n",
                );
                stream.write_all(&response).await?;
                return Ok(());
            }

            match tunnel.transport {
                http::TunnelTransport::Tcp => {
                    let outbound = match timeout(
                        Duration::from_secs(args.connect_timeout_secs),
                        TcpStream::connect(&tunnel.target),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(err)) => {
                            let response =
                                http::build_error_response(502, "Bad Gateway", &format!("{err}\n"));
                            stream.write_all(&response).await?;
                            return Ok(());
                        }
                        Err(_) => {
                            let response = http::build_error_response(
                                504,
                                "Gateway Timeout",
                                "upstream connect timed out\n",
                            );
                            stream.write_all(&response).await?;
                            return Ok(());
                        }
                    };
                    outbound.set_nodelay(true)?;

                    stream.write_all(&http::build_tunnel_established()).await?;
                    let stats = traffic::relay_with_telemetry(
                        stream,
                        outbound,
                        traffic::RelayLabels {
                            target: tunnel.target.clone(),
                            route: Some("remote".to_owned()),
                            mode: Some("native-http".to_owned()),
                        },
                    )
                    .await?;

                    info!(
                        peer = %peer,
                        target = %stats.display_target,
                        uploaded = stats.uploaded,
                        downloaded = stats.downloaded,
                        sampled = stats.sampled,
                        "relay completed"
                    );
                }
                http::TunnelTransport::Udp => {
                    handle_udp_tunnel(stream, peer, &args, &tunnel.target).await?;
                }
            }

            return Ok(());
        }

        send_not_found(&mut stream).await?;
        return Ok(());
    }

    let request = match http::parse_request(&head) {
        Ok(request) => request,
        Err(err) => {
            send_not_found(&mut stream).await?;
            return Err(err.context("invalid HTTP request"));
        }
    };

    if !request.version.starts_with("HTTP/1.") {
        serve_public_request(&mut stream, request, &body_prefix, &fallback).await?;
        return Ok(());
    }

    serve_public_request(&mut stream, request, &body_prefix, &fallback).await?;
    Ok(())
}

async fn serve_public_request<S>(
    stream: &mut S,
    request: http::HttpRequest,
    body_prefix: &[u8],
    fallback: &Fallback,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match fallback.proxy(stream, request, body_prefix).await {
        Ok(()) => return Ok(()),
        Err(err) => warn!(error = %err, "fallback request failed, serving 404"),
    }

    send_not_found(stream).await?;
    Ok(())
}

async fn send_not_found<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
        .await?;
    Ok(())
}

async fn authorize_tunnel_request<S>(
    stream: &mut S,
    request: http::TunnelRequestHead,
    body_prefix: &[u8],
    args: &ServerArgs,
    replay: &ReplayProtector,
) -> Result<Option<AuthorizedTunnel>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if request.chunked {
        return Ok(None);
    }

    let body_length = match request.content_length {
        Some(length) => length,
        None => return Ok(None),
    };
    let body = http::read_body(stream, body_prefix, body_length, args.max_tunnel_body_size).await?;
    let payload = match http::parse_tunnel_payload(&body) {
        Ok(payload) => payload,
        Err(_) => return Ok(None),
    };
    let target = payload.target;
    let proof = AuthProof {
        timestamp: payload.timestamp,
        nonce: payload.nonce,
        signature: payload.signature,
    };

    if let Err(err) = replay.validate(&args.password, "POST", &args.path, &target, &proof) {
        stream
            .write_all(&http::build_error_response(
                401,
                "Unauthorized",
                AUTH_FAILURE_BODY,
            ))
            .await?;
        bail!("native-http authentication failed: {err}; {AUTH_FAILURE_HINT}");
    }

    Ok(Some(AuthorizedTunnel {
        target,
        transport: payload.transport,
    }))
}

#[derive(Clone, Debug)]
struct AuthorizedTunnel {
    target: String,
    transport: http::TunnelTransport,
}

async fn handle_udp_tunnel<S>(
    mut stream: S,
    peer: SocketAddr,
    args: &ServerArgs,
    target: &str,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let outbound = bind_udp_socket_for_target(target)
        .await
        .with_context(|| format!("failed to bind UDP socket for {target}"))?;
    match timeout(
        Duration::from_secs(args.connect_timeout_secs),
        outbound.connect(target),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let response = http::build_error_response(502, "Bad Gateway", &format!("{err}\n"));
            stream.write_all(&response).await?;
            return Ok(());
        }
        Err(_) => {
            let response = http::build_error_response(
                504,
                "Gateway Timeout",
                "upstream UDP connect timed out\n",
            );
            stream.write_all(&response).await?;
            return Ok(());
        }
    }

    stream.write_all(&http::build_tunnel_established()).await?;

    let (reader, writer) = tokio::io::split(stream);
    let mut reader = Cursor::new(Vec::new()).chain(reader);
    let mut writer = writer;
    let mut recv_buf = vec![0_u8; udp::MAX_UDP_FRAME_SIZE];

    let client_to_upstream = async {
        loop {
            match udp::read_frame(&mut reader, udp::MAX_UDP_FRAME_SIZE).await {
                Ok(payload) => {
                    outbound
                        .send(&payload)
                        .await
                        .with_context(|| format!("failed to send UDP payload to {target}"))?;
                }
                Err(err) if udp::is_eof(&err) => return Ok::<(), anyhow::Error>(()),
                Err(err) => return Err(err.context("failed to read UDP tunnel frame")),
            }
        }
    };

    let upstream_to_client = async {
        loop {
            let n = outbound
                .recv(&mut recv_buf)
                .await
                .with_context(|| format!("failed to receive UDP payload from {target}"))?;
            udp::write_frame(&mut writer, &recv_buf[..n]).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = client_to_upstream => result?,
        result = upstream_to_client => result?,
    }

    info!(peer = %peer, target = %target, "UDP relay completed");
    Ok(())
}

async fn bind_udp_socket_for_target(target: &str) -> Result<UdpSocket> {
    let (host, _port) = tls::split_host_port(target)?;
    let bind_addr = if host.parse::<Ipv6Addr>().is_ok() {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind UDP socket for {target}"))
}

#[derive(Clone)]
struct Fallback {
    client: HttpClient,
    base_url: Url,
    max_body_size: usize,
}

impl Fallback {
    fn new(base_url: &str, timeout: Duration, max_body_size: usize) -> Result<Self> {
        let base_url = Url::parse(base_url).context("invalid fallback URL")?;
        let client = HttpClient::builder()
            .timeout(timeout)
            .build()
            .context("failed to build fallback HTTP client")?;

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
            bail!("chunked request bodies are not supported for fallback");
        }

        let body_length = http::content_length(&request.headers)?.unwrap_or(0);
        let body = if body_length == 0 {
            Vec::new()
        } else {
            http::read_body(stream, body_prefix, body_length, self.max_body_size).await?
        };

        let method =
            Method::from_bytes(request.method.as_bytes()).context("invalid request method")?;
        let url = fallback_request_url(&self.base_url, &request.path)?;
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
            .context("fallback upstream request failed")?;
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
            .context("failed to read fallback response body")?;
        let encoded = http::build_response(status.as_u16(), &reason, &response_headers, &body);
        stream.write_all(&encoded).await?;
        Ok(())
    }
}

fn fallback_request_url(base: &Url, request_target: &str) -> Result<Url> {
    if request_target == "*" {
        return Ok(base.clone());
    }

    if request_target.starts_with('/') {
        return base
            .join(request_target)
            .with_context(|| format!("failed to join fallback URL with {request_target}"));
    }

    if let Ok(url) = Url::parse(request_target) {
        let mut target = base.clone();
        target.set_path(url.path());
        target.set_query(url.query());
        return Ok(target);
    }

    base.join("/")
        .context("failed to build root fallback request URL")
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

fn is_private_literal_target(target: &str) -> bool {
    let Some(host) = extract_host(target) else {
        return false;
    };

    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(addr)) => is_private_v4(addr),
        Ok(IpAddr::V6(addr)) => is_private_v6(addr),
        Err(_) => false,
    }
}

fn extract_host(target: &str) -> Option<String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, _) = rest.split_once(']')?;
        return Some(host.to_owned());
    }

    let (host, _) = target.rsplit_once(':')?;
    Some(host.to_owned())
}

fn is_private_v4(addr: Ipv4Addr) -> bool {
    addr.is_private() || addr.is_loopback() || addr.is_link_local() || addr.is_unspecified()
}

fn is_private_v6(addr: Ipv6Addr) -> bool {
    addr.is_loopback()
        || addr.is_unique_local()
        || addr.is_unicast_link_local()
        || addr.is_unspecified()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wg::server::WgServerArgs;
    use tokio::io::{AsyncReadExt, duplex};

    #[tokio::test]
    async fn tunnel_auth_failure_writes_unauthorized_response() {
        let proof = AuthProof::sign("client-secret", "POST", "/connect", "example.com:443")
            .expect("proof should sign");
        let payload = http::TunnelPayload {
            target: "example.com:443".to_owned(),
            transport: http::TunnelTransport::Tcp,
            timestamp: proof.timestamp,
            nonce: proof.nonce,
            signature: proof.signature,
        };
        let body = serde_json::to_vec(&payload).expect("payload should serialize");
        let args = ServerArgs {
            listen: "127.0.0.1:0".to_owned(),
            cert: None,
            key: None,
            mode: ProxyMode::NativeHttp,
            password: "server-secret".to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            auth_window_secs: 120,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 16 * 1024,
            max_tunnel_body_size: 8 * 1024,
            allow_private_targets: false,
            fallback_url: "https://www.qq.com".to_owned(),
            fallback_timeout_secs: 15,
            max_fallback_body_size: 1024 * 1024,
            wg: WgServerArgs::default(),
        };
        let replay = ReplayProtector::new(Duration::from_secs(args.auth_window_secs));
        let (mut server_io, mut client_io) = duplex(4096);

        let err = authorize_tunnel_request(
            &mut server_io,
            http::TunnelRequestHead {
                content_length: Some(body.len()),
                chunked: false,
            },
            &body,
            &args,
            &replay,
        )
        .await
        .expect_err("wrong password should reject tunnel auth")
        .to_string();
        assert!(err.contains(AUTH_FAILURE_HINT), "{err}");
        drop(server_io);

        let mut response = Vec::new();
        client_io.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(
            response.starts_with("HTTP/1.1 401 Unauthorized"),
            "{response}"
        );
        assert!(response.contains(AUTH_FAILURE_BODY.trim()), "{response}");
    }
}
