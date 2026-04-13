use crate::{
    auth::AuthProof, http, mode::ProxyMode, netlog, route, route::FilterMode, route::RouteDecision,
    socks5, tls, traffic,
};
use anyhow::{Context, Result, bail};
use clap::Args;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
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
    pub server: String,
    #[arg(long)]
    pub server_name: Option<String>,
    #[arg(long)]
    pub ca_cert: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = ProxyMode::NativeHttp)]
    pub mode: ProxyMode,
    #[arg(long, env = "PIPIT_PASSWORD")]
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
    #[arg(long, default_value = "Mozilla/5.0")]
    pub user_agent: String,
    #[arg(long, default_value_t = 10)]
    pub handshake_timeout_secs: u64,
    #[arg(long, default_value_t = 10)]
    pub connect_timeout_secs: u64,
    #[arg(long, default_value_t = 8 * 1024)]
    pub max_header_size: usize,
}

pub async fn run(args: ClientArgs) -> Result<()> {
    match args.effective_mode()? {
        ProxyMode::NativeHttp => {}
        ProxyMode::NativeMux => return crate::mux::run_client(args).await,
        ProxyMode::DazeAshe | ProxyMode::DazeBaboon => return crate::daze::run_client(args).await,
        ProxyMode::DazeCzar => return crate::czar::run_client(args).await,
    }

    let router = route::Router::from_args(&args)?;
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
            let _ =
                route::relay_direct_socks(inbound, &target, connect_timeout, Some("native-http"))
                    .await?;
            info!(peer = %peer, target = %target_string, route = "direct", "client relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    let upstream = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&args.server),
    )
    .await
    .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let server_name = tls::server_name(&server_name)?;
    let mut tunnel = match timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        connector.connect(server_name, upstream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            return Err(err).context("TLS handshake with server failed");
        }
        Err(_) => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("TLS handshake with server timed out");
        }
    };

    let proof = AuthProof::sign(&args.password, "POST", &args.path, &target_string)?;
    let payload = http::TunnelPayload {
        target: target_string.clone(),
        timestamp: proof.timestamp,
        nonce: proof.nonce,
        signature: proof.signature,
    };
    let request = http::build_tunnel_request(&host_header, &args.path, &payload, &args.user_agent)?;
    tunnel.write_all(&request).await?;

    let response_head = match timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        http::read_head(&mut tunnel, args.max_header_size),
    )
    .await
    {
        Ok(Ok((head, _body_prefix))) => head,
        Ok(Err(err)) => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            return Err(err).context("failed to read server response");
        }
        Err(_) => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("server response timed out");
        }
    };

    let (is_http1, status, reason) =
        http::parse_tunnel_response(&response_head).context("invalid server response")?;
    if !is_http1 {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("server returned an unsupported HTTP version");
    }
    if status != 200 {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("server refused tunnel with status {} {}", status, reason);
    }

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
        target = %target_string,
        uploaded = stats.uploaded,
        downloaded = stats.downloaded,
        sampled = stats.sampled,
        "client relay completed"
    );

    Ok(())
}
