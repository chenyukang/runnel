use super::wire::{client_establish_ashe, fill_random, relay_rc4, salt, server_accept_ashe};
use crate::{
    proxy::{
        auth::{AUTH_FAILURE_BODY, AUTH_FAILURE_HINT},
        http, netlog, route,
        route::RouteDecision,
        socks5, traffic,
    },
    runtime::{ClientRuntime, ServerRuntime},
};
use anyhow::{Context, Result, bail};
use md5::Context as Md5Context;
use reqwest::{
    Client as HttpClient, Method, Url,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderMap, HeaderName, HeaderValue, TRANSFER_ENCODING,
    },
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{info, warn};

const BABOON_PATH: &str = "/sync";

pub(super) async fn run_client(runtime: ClientRuntime) -> Result<()> {
    let router = route::Router::from_runtime(&runtime).await?;
    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        server = %runtime.server,
        mode = "daze-baboon",
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(socket, peer, router, runtime).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-baboon client session ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-baboon client session ended with error");
                }
            }
        });
    }
}

pub(super) async fn run_server(runtime: ServerRuntime) -> Result<()> {
    let fallback = BaboonFallback::new(
        &runtime.fallback_url,
        runtime.fallback_timeout,
        runtime.max_fallback_body_size,
    )?;
    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        mode = "daze-baboon",
        fallback = %runtime.fallback_url,
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        let fallback = fallback.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(socket, peer, runtime, fallback).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-baboon server session ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-baboon server session ended with error");
                }
            }
        });
    }
}

async fn handle_client_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    router: Arc<route::Router>,
    runtime: ClientRuntime,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let target = timeout(runtime.handshake_timeout, socks5::accept(&mut inbound))
        .await
        .context("SOCKS handshake timed out")??;
    let target_string = target.to_string();

    match router.decide(&target).await? {
        RouteDecision::Direct => {
            let stats = route::relay_direct_socks(
                inbound,
                &target,
                runtime.connect_timeout,
                Some("daze-baboon"),
            )
            .await?;
            info!(peer = %peer, target = %stats.display_target, route = "direct", mode = "daze-baboon", "relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            info!(peer = %peer, target = %target_string, route = "block", mode = "daze-baboon", "route decision");
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    if target_string.len() > u8::MAX as usize {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("destination address too long");
    }

    let mut upstream = timeout(runtime.connect_timeout, TcpStream::connect(&runtime.server))
        .await
        .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let request = build_baboon_request(&runtime.password, &runtime.server);
    upstream.write_all(request.as_bytes()).await?;

    let (head, body_prefix) = timeout(
        runtime.handshake_timeout,
        http::read_head(&mut upstream, runtime.max_header_size),
    )
    .await
    .context("baboon response timed out")??;
    let response = http::parse_response_head(&head).context("invalid baboon response")?;
    if !response.is_http1 || response.status != 200 {
        let detail = http::read_response_body_text(
            &mut upstream,
            &body_prefix,
            response.content_length,
            runtime.max_header_size,
        )
        .await;
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        if let Some(detail) = detail {
            bail!(
                "daze-baboon server refused sync with status {} {}: {}",
                response.status,
                response.reason,
                detail
            );
        }
        bail!(
            "daze-baboon server refused sync with status {} {}",
            response.status,
            response.reason
        );
    }

    let (upload, download) =
        client_establish_ashe(&mut upstream, &runtime.password, &target_string)
            .await
            .with_context(|| format!("daze-baboon ashe handshake failed; {AUTH_FAILURE_HINT}"))?;

    socks5::send_success(&mut inbound).await?;
    let stats = relay_rc4(
        inbound,
        upstream,
        upload,
        download,
        traffic::RelayLabels {
            target: target_string.clone(),
            route: Some("remote".to_owned()),
            mode: Some("daze-baboon".to_owned()),
        },
    )
    .await?;

    info!(
        peer = %peer,
        target = %stats.display_target,
        uploaded = stats.uploaded,
        downloaded = stats.downloaded,
        sampled = stats.sampled,
        mode = "daze-baboon",
        "relay completed"
    );
    Ok(())
}

async fn handle_server_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    runtime: ServerRuntime,
    fallback: BaboonFallback,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let (head, body_prefix) = timeout(
        runtime.handshake_timeout,
        http::read_head(&mut inbound, runtime.max_header_size),
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

    if request.method == "POST" && request.path == BABOON_PATH {
        if !validate_baboon_request(&request, &runtime.password) {
            inbound
                .write_all(&http::build_error_response(
                    401,
                    "Unauthorized",
                    AUTH_FAILURE_BODY,
                ))
                .await?;
            bail!("daze-baboon authentication failed; {AUTH_FAILURE_HINT}");
        }

        inbound
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: keep-alive\r\n\r\n",
            )
            .await?;

        let (download, upload, target) = server_accept_ashe(&mut inbound, &runtime).await?;
        let outbound = timeout(runtime.connect_timeout, TcpStream::connect(&target))
            .await
            .context("upstream connect timed out")??;
        outbound.set_nodelay(true)?;

        let mut code = [0_u8];
        let mut upload = upload;
        upload.apply_keystream(&mut code);
        inbound.write_all(&code).await?;

        let stats = relay_rc4(
            inbound,
            outbound,
            download,
            upload,
            traffic::RelayLabels {
                target: target.clone(),
                route: Some("remote".to_owned()),
                mode: Some("daze-baboon".to_owned()),
            },
        )
        .await?;
        info!(
            peer = %peer,
            target = %stats.display_target,
            uploaded = stats.uploaded,
            downloaded = stats.downloaded,
            sampled = stats.sampled,
            mode = "daze-baboon",
            "relay completed"
        );
        return Ok(());
    }

    fallback.proxy(&mut inbound, request, &body_prefix).await?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baboon_authorization_round_trip() {
        let request = build_baboon_request("secret", "example.com:443");
        let parsed = http::parse_request(request.as_bytes()).expect("request should parse");
        assert!(validate_baboon_request(&parsed, "secret"));
        assert!(!validate_baboon_request(&parsed, "wrong-secret"));
    }
}
