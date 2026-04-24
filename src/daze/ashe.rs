use super::wire::{client_establish_ashe, relay_rc4, server_accept_ashe};
use crate::{
    proxy::{auth::AUTH_FAILURE_HINT, netlog, route, route::RouteDecision, socks5, traffic},
    runtime::{ClientRuntime, ServerRuntime},
};
use anyhow::{Context, Result, bail};
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{info, warn};

pub(super) async fn run_client(runtime: ClientRuntime) -> Result<()> {
    let router = route::Router::from_runtime(&runtime).await?;
    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        server = %runtime.server,
        mode = "daze-ashe",
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(socket, peer, router, runtime).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-ashe client session ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-ashe client session ended with error");
                }
            }
        });
    }
}

pub(super) async fn run_server(runtime: ServerRuntime) -> Result<()> {
    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        mode = "daze-ashe",
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(socket, peer, runtime).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-ashe server session ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-ashe server session ended with error");
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
                Some("daze-ashe"),
            )
            .await?;
            info!(peer = %peer, target = %stats.display_target, route = "direct", mode = "daze-ashe", "relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            info!(peer = %peer, target = %target_string, route = "block", mode = "daze-ashe", "route decision");
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

    let (upload, download) =
        client_establish_ashe(&mut upstream, &runtime.password, &target_string)
            .await
            .with_context(|| format!("daze-ashe handshake failed; {AUTH_FAILURE_HINT}"))?;

    socks5::send_success(&mut inbound).await?;
    let stats = relay_rc4(
        inbound,
        upstream,
        upload,
        download,
        traffic::RelayLabels {
            target: target_string.clone(),
            route: Some("remote".to_owned()),
            mode: Some("daze-ashe".to_owned()),
        },
    )
    .await?;

    info!(
        peer = %peer,
        target = %stats.display_target,
        uploaded = stats.uploaded,
        downloaded = stats.downloaded,
        sampled = stats.sampled,
        mode = "daze-ashe",
        "relay completed"
    );
    Ok(())
}

async fn handle_server_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    runtime: ServerRuntime,
) -> Result<()> {
    inbound.set_nodelay(true)?;

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
            mode: Some("daze-ashe".to_owned()),
        },
    )
    .await?;

    info!(
        peer = %peer,
        target = %stats.display_target,
        uploaded = stats.uploaded,
        downloaded = stats.downloaded,
        sampled = stats.sampled,
        mode = "daze-ashe",
        "relay completed"
    );
    Ok(())
}
