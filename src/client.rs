use crate::{auth::AuthProof, http, socks5, tls};
use anyhow::{Context, Result, bail};
use clap::Args;
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
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
    #[arg(long, env = "PIPIT_PASSWORD")]
    pub password: String,
    #[arg(long, default_value = "/connect")]
    pub path: String,
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

        tokio::spawn(async move {
            if let Err(err) =
                handle_connection(socket, peer, args, connector, host_header, server_name).await
            {
                warn!(peer = %peer, error = %err, "client session ended with error");
            }
        });
    }
}

async fn handle_connection(
    mut inbound: TcpStream,
    peer: std::net::SocketAddr,
    args: ClientArgs,
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
    let (uploaded, downloaded) = copy_bidirectional(&mut inbound, &mut tunnel).await?;

    info!(
        peer = %peer,
        target = %target_string,
        uploaded,
        downloaded,
        "client relay completed"
    );

    Ok(())
}
