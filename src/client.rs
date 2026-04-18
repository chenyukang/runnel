use crate::{
    mode::ProxyMode,
    proxy::{
        adblock::AdblockConfig,
        auth::AuthProof,
        http, mux, netlog, route,
        route::{FilterMode, RouteDecision},
        socks5, tls, traffic, udp_assoc,
    },
    system_proxy, wg,
};
use anyhow::{Context, Result, bail};
use clap::Args;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tracing::{info, warn};

const TUN_DNS_PORT: u16 = 53;

#[derive(Clone, Debug, Args)]
pub struct ClientArgs {
    #[arg(long, default_value = "127.0.0.1:1080")]
    pub listen: String,
    #[arg(long)]
    #[arg(default_value = "")]
    pub server: String,
    #[arg(long)]
    pub server_name: Option<String>,
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ProxyMode::NativeHttp)]
    pub mode: ProxyMode,
    #[arg(long, env = "PIPIT_PASSWORD")]
    #[arg(default_value = "")]
    pub password: String,
    #[arg(long, default_value = "/connect")]
    pub path: String,
    #[arg(long, default_value = "/mux")]
    pub mux_path: String,
    #[arg(long)]
    pub mux: bool,
    #[arg(long, value_enum, default_value_t = FilterMode::Proxy)]
    pub filter: FilterMode,
    #[arg(long)]
    pub rule_file: Option<PathBuf>,
    #[arg(long)]
    pub cidr_file: Option<PathBuf>,
    #[arg(skip)]
    pub domain_rules: route::RouteRuleConfig,
    #[arg(skip)]
    pub ip_rules: route::RouteRuleConfig,
    #[arg(skip)]
    pub adblock: AdblockConfig,
    #[arg(long, default_value = "Mozilla/5.0")]
    pub user_agent: String,
    #[arg(long, default_value_t = 10)]
    pub handshake_timeout_secs: u64,
    #[arg(long, default_value_t = 10)]
    pub connect_timeout_secs: u64,
    #[arg(long, default_value_t = 8 * 1024)]
    pub max_header_size: usize,
    #[arg(long)]
    pub system_proxy: bool,
    #[arg(long = "system-proxy-service")]
    pub system_proxy_services: Vec<String>,
    #[arg(skip)]
    pub tun_dns_redirect_ip: Option<IpAddr>,
    #[arg(skip)]
    pub tun_dns_upstream: Option<SocketAddr>,
    #[arg(skip)]
    pub wg: wg::client::WgClientArgs,
}

pub async fn run(args: ClientArgs) -> Result<()> {
    run_with_signal_handling(args, true).await
}

pub async fn run_embedded(args: ClientArgs) -> Result<()> {
    run_with_signal_handling(args, false).await
}

async fn run_with_signal_handling(args: ClientArgs, handle_signals: bool) -> Result<()> {
    if matches!(args.effective_mode()?, ProxyMode::Wg) {
        return wg::client::run(args.wg).await;
    }

    args.validate_required()?;
    let _system_proxy = system_proxy::maybe_activate(&args)?;

    let run_client = async move {
        match args.effective_mode()? {
            ProxyMode::NativeHttp => run_native_http(args).await,
            ProxyMode::NativeMux => mux::run_client(args).await,
            ProxyMode::DazeAshe | ProxyMode::DazeBaboon | ProxyMode::DazeCzar => {
                crate::daze::run_client(args).await
            }
            ProxyMode::Wg => unreachable!("wg mode is dispatched before SOCKS client startup"),
        }
    };

    if handle_signals {
        tokio::select! {
            result = run_client => result,
            signal = wait_for_shutdown_signal() => {
                signal?;
                info!("client shutting down");
                Ok(())
            }
        }
    } else {
        run_client.await
    }
}

async fn run_native_http(args: ClientArgs) -> Result<()> {
    match args.effective_mode()? {
        ProxyMode::NativeHttp => {}
        _ => bail!("run_native_http only supports native-http mode"),
    }

    let router = route::Router::from_args(&args).await?;
    let connector = TlsConnector::from(tls::load_client_config(args.ca_cert.as_deref())?);
    let (default_host, _) = tls::split_host_port(&args.server)?;
    let server_name = args
        .server_name
        .clone()
        .unwrap_or_else(|| default_host.clone());

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        server = %args.server,
        server_name = %server_name,
        path = %args.path,
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        let connector = connector.clone();
        let host_header = default_host.clone();
        let server_name = server_name.clone();
        let router = router.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                socket,
                peer,
                args,
                router,
                connector,
                host_header,
                server_name,
            )
            .await
            {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "client session ended");
                } else {
                    warn!(peer = %peer, error = %err, "client session ended with error");
                }
            }
        });
    }
}

impl ClientArgs {
    pub fn effective_mode(&self) -> Result<ProxyMode> {
        ProxyMode::from_legacy_mux(self.mux, self.mode)
    }

    pub fn validate_required(&self) -> Result<()> {
        if self.server.trim().is_empty() {
            bail!("client server is required; pass --server or set it in --config");
        }
        if self.password.trim().is_empty() {
            bail!(
                "client password is required; pass --password, set PIPIT_PASSWORD, or set it in --config"
            );
        }
        Ok(())
    }

    pub(crate) fn tun_dns_tcp_upstream(&self, target: &socks5::TargetAddr) -> Option<SocketAddr> {
        let redirect_ip = self.tun_dns_redirect_ip?;
        let upstream = self.tun_dns_upstream?;
        match target {
            socks5::TargetAddr::Ip(ip, port) if *ip == redirect_ip && *port == TUN_DNS_PORT => {
                Some(upstream)
            }
            _ => None,
        }
    }

    pub(crate) fn tun_dns_udp_upstream(
        &self,
        target: &socks5::TargetAddr,
    ) -> Option<socks5::TargetAddr> {
        let upstream = self.tun_dns_upstream?;
        match target {
            socks5::TargetAddr::Ip(ip, port)
                if (*port == TUN_DNS_PORT || *port == upstream.port())
                    && (self.tun_dns_redirect_ip == Some(*ip) || *ip == upstream.ip()) =>
            {
                Some(socks5::TargetAddr::Ip(upstream.ip(), upstream.port()))
            }
            _ => None,
        }
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    peer: std::net::SocketAddr,
    args: ClientArgs,
    router: Arc<route::Router>,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<()> {
    inbound.set_nodelay(true)?;

    let request = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        socks5::accept_request(&mut inbound),
    )
    .await
    .context("SOCKS handshake timed out")??;
    let target = match request {
        socks5::Request::Connect(target) => target,
        socks5::Request::UdpAssociate(_bind) => {
            if !matches!(args.effective_mode()?, ProxyMode::NativeHttp) {
                let _ = socks5::send_failure(&mut inbound, socks5::REP_COMMAND_NOT_SUPPORTED).await;
                bail!("UDP ASSOCIATE is only supported in native-http mode");
            }
            return udp_assoc::handle_native_http_udp_associate(
                inbound,
                peer,
                args,
                router,
                connector,
                host_header,
                server_name,
            )
            .await;
        }
    };
    let target_string = target.to_string();
    if let Some(dns_upstream) = args.tun_dns_tcp_upstream(&target) {
        let upstream_target = dns_upstream.to_string();
        let tunnel = match establish_remote_tunnel(
            &args,
            &connector,
            &host_header,
            &server_name,
            &upstream_target,
            http::TunnelTransport::Tcp,
        )
        .await
        {
            Ok(tunnel) => tunnel,
            Err(err) => {
                let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
                return Err(err).with_context(|| {
                    format!("failed to open remote tun DNS tunnel to {upstream_target}")
                });
            }
        };
        socks5::send_success(&mut inbound).await?;
        let stats = traffic::relay_with_telemetry(
            inbound,
            tunnel,
            traffic::RelayLabels {
                target: target_string.clone(),
                route: Some("remote".to_owned()),
                mode: Some("native-http".to_owned()),
            },
        )
        .await
        .context("tun DNS remote relay failed")?;
        info!(
            peer = %peer,
            target = %stats.display_target,
            upstream = %dns_upstream,
            uploaded = stats.uploaded,
            downloaded = stats.downloaded,
            sampled = stats.sampled,
            "client tun DNS relay completed"
        );
        return Ok(());
    }

    match router.decide(&target).await? {
        RouteDecision::Direct => {
            let connect_timeout = Duration::from_secs(args.connect_timeout_secs);
            let stats =
                route::relay_direct_socks(inbound, &target, connect_timeout, Some("native-http"))
                    .await?;
            info!(
                peer = %peer,
                target = %stats.display_target,
                route = "direct",
                "client relay completed"
            );
            return Ok(());
        }
        RouteDecision::Block => {
            info!(peer = %peer, target = %target_string, route = "block", mode = "native-http", "route decision");
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    let tunnel = match establish_remote_tunnel(
        &args,
        &connector,
        &host_header,
        &server_name,
        &target_string,
        http::TunnelTransport::Tcp,
    )
    .await
    {
        Ok(tunnel) => tunnel,
        Err(err) => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            return Err(err).context("failed to establish remote tunnel");
        }
    };

    socks5::send_success(&mut inbound).await?;
    let stats = traffic::relay_with_telemetry(
        inbound,
        tunnel,
        traffic::RelayLabels {
            target: target_string.clone(),
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
        "client relay completed"
    );

    Ok(())
}

pub(crate) async fn establish_remote_tunnel(
    args: &ClientArgs,
    connector: &TlsConnector,
    host_header: &str,
    server_name: &str,
    target: &str,
    transport: http::TunnelTransport,
) -> Result<TlsStream<TcpStream>> {
    let upstream = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&args.server),
    )
    .await
    .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let server_name = tls::server_name(server_name)?;
    let mut tunnel = match timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        connector.connect(server_name, upstream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(err).context("TLS handshake with server failed"),
        Err(_) => bail!("TLS handshake with server timed out"),
    };

    let proof = AuthProof::sign(&args.password, "POST", &args.path, target)?;
    let payload = http::TunnelPayload {
        target: target.to_owned(),
        transport,
        timestamp: proof.timestamp,
        nonce: proof.nonce,
        signature: proof.signature,
    };
    let request = http::build_tunnel_request(host_header, &args.path, &payload, &args.user_agent)?;
    tunnel.write_all(&request).await?;

    let response_head = match timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        http::read_head(&mut tunnel, args.max_header_size),
    )
    .await
    {
        Ok(Ok((head, body_prefix))) => (head, body_prefix),
        Ok(Err(err)) => return Err(err).context("failed to read server response"),
        Err(_) => bail!("server response timed out"),
    };

    let response =
        http::parse_response_head(&response_head.0).context("invalid server response")?;
    if !response.is_http1 {
        bail!("server returned an unsupported HTTP version");
    }
    if response.status != 200 {
        let detail = http::read_response_body_text(
            &mut tunnel,
            &response_head.1,
            response.content_length,
            args.max_header_size,
        )
        .await;
        if let Some(detail) = detail {
            bail!(
                "server refused tunnel with status {} {}: {}",
                response.status,
                response.reason,
                detail
            );
        }
        bail!(
            "server refused tunnel with status {} {}",
            response.status,
            response.reason
        );
    }

    Ok(tunnel)
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to wait for Ctrl-C")?;
            }
            _ = terminate.recv() => {}
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to wait for Ctrl-C")?;
        Ok(())
    }
}
