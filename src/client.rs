use crate::{
    mode::ProxyMode,
    proxy::{
        adblock::AdblockConfig,
        http, mux, netlog, remote, route,
        route::{FilterMode, RouteDecision},
        socks5, tls, traffic, udp_assoc,
    },
    runtime::ClientRuntime,
    system_proxy, wg,
};
use anyhow::{Context, Result, bail};
use clap::Args;
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

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
    #[arg(long, env = "RUNNEL_PASSWORD")]
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
    let runtime = ClientRuntime::from_args(&args);

    let run_client = async move {
        let mode = args.effective_mode()?;
        match mode {
            ProxyMode::NativeHttp => run_native_http(runtime).await,
            ProxyMode::NativeMux => mux::run_client(runtime).await,
            ProxyMode::DazeAshe | ProxyMode::DazeBaboon | ProxyMode::DazeCzar => {
                crate::daze::run_client(runtime, mode).await
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

async fn run_native_http(runtime: ClientRuntime) -> Result<()> {
    let router = route::Router::from_runtime(&runtime).await?;
    let connector = TlsConnector::from(tls::load_client_config(runtime.ca_cert.as_deref())?);
    let (default_host, _) = tls::split_host_port(&runtime.server)?;
    let server_name = runtime
        .server_name
        .clone()
        .unwrap_or_else(|| default_host.clone());

    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        server = %runtime.server,
        server_name = %server_name,
        path = %runtime.path,
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        let connector = connector.clone();
        let host_header = default_host.clone();
        let server_name = server_name.clone();
        let router = router.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_connection(
                socket,
                peer,
                runtime,
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
                "client password is required; pass --password, set RUNNEL_PASSWORD, or set it in --config"
            );
        }
        Ok(())
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    peer: std::net::SocketAddr,
    runtime: ClientRuntime,
    router: Arc<route::Router>,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<()> {
    inbound.set_nodelay(true)?;

    let request = timeout(
        runtime.handshake_timeout,
        socks5::accept_request(&mut inbound),
    )
    .await
    .context("SOCKS handshake timed out")??;
    let target = match request {
        socks5::Request::Connect(target) => target,
        socks5::Request::UdpAssociate(_bind) => {
            return udp_assoc::handle_native_http_udp_associate(
                inbound,
                peer,
                runtime,
                router,
                connector,
                host_header,
                server_name,
            )
            .await;
        }
    };
    let target_string = target.to_string();
    if let Some(dns_upstream) = runtime.tun_dns_tcp_upstream(&target) {
        let upstream_target = dns_upstream.to_string();
        let tunnel = match remote::establish_remote_tunnel(
            &runtime,
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
            let stats = route::relay_direct_socks(
                inbound,
                &target,
                runtime.connect_timeout,
                Some("native-http"),
            )
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

    let tunnel = match remote::establish_remote_tunnel(
        &runtime,
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
