use crate::{
    auth::AuthProof,
    client::ClientArgs,
    http::{self, TunnelTransport},
    route::{RouteDecision, Router},
    socks5::{self, TargetAddr},
    tls, udp,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

type SessionMap = Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>;
type BackgroundTasks = Arc<Mutex<Vec<JoinHandle<()>>>>;

pub async fn handle_native_http_udp_associate(
    mut inbound: TcpStream,
    peer: SocketAddr,
    args: ClientArgs,
    router: Arc<Router>,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<()> {
    let bind_ip = match inbound.local_addr()?.ip() {
        IpAddr::V4(ip) if !ip.is_unspecified() => IpAddr::V4(ip),
        IpAddr::V6(ip) if !ip.is_unspecified() => IpAddr::V6(ip),
        _ => IpAddr::V4(Ipv4Addr::LOCALHOST),
    };
    let relay = Arc::new(
        UdpSocket::bind(SocketAddr::new(bind_ip, 0))
            .await
            .context("failed to bind SOCKS UDP relay socket")?,
    );
    let relay_addr = relay.local_addr()?;
    socks5::send_success_bound(&mut inbound, relay_addr)
        .await
        .context("failed to send SOCKS UDP associate reply")?;

    info!(peer = %peer, bind = %relay_addr, "UDP associate established");

    let client_addr = Arc::new(Mutex::new(None::<SocketAddr>));
    let direct_sessions = Arc::new(Mutex::new(HashMap::new()));
    let remote_sessions = Arc::new(Mutex::new(HashMap::new()));
    let tasks = Arc::new(Mutex::new(Vec::new()));

    let result = tokio::select! {
        result = run_udp_association(
            relay,
            client_addr,
            direct_sessions,
            remote_sessions,
            tasks.clone(),
            args,
            router,
            connector,
            host_header,
            server_name,
        ) => result,
        result = wait_for_control_close(&mut inbound) => result,
    };

    abort_background_tasks(tasks).await;
    result
}

async fn run_udp_association(
    relay: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    direct_sessions: SessionMap,
    remote_sessions: SessionMap,
    tasks: BackgroundTasks,
    args: ClientArgs,
    router: Arc<Router>,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<()> {
    let mut buf = vec![0_u8; udp::MAX_UDP_FRAME_SIZE];

    loop {
        let (len, sender) = relay
            .recv_from(&mut buf)
            .await
            .context("failed to receive UDP datagram from local SOCKS client")?;
        *client_addr.lock().await = Some(sender);

        let packet = match socks5::parse_udp_packet(&buf[..len]) {
            Ok(packet) => packet,
            Err(err) => {
                warn!(peer = %sender, error = %err, "dropping invalid SOCKS UDP packet");
                continue;
            }
        };

        let target = packet.target;
        let key = target.to_string();

        match router.decide(&target).await? {
            RouteDecision::Direct => {
                send_via_session(&direct_sessions, &key, packet.payload, || {
                    create_direct_udp_session(
                        target.clone(),
                        relay.clone(),
                        client_addr.clone(),
                        tasks.clone(),
                    )
                })
                .await?;
            }
            RouteDecision::Remote => {
                send_via_session(&remote_sessions, &key, packet.payload, || {
                    create_remote_udp_session(
                        target.clone(),
                        relay.clone(),
                        client_addr.clone(),
                        tasks.clone(),
                        args.clone(),
                        connector.clone(),
                        host_header.clone(),
                        server_name.clone(),
                    )
                })
                .await?;
            }
            RouteDecision::Block => {
                debug!(target = %key, "dropping blocked UDP target");
            }
        }
    }
}

async fn send_via_session<F, Fut>(
    sessions: &SessionMap,
    key: &str,
    payload: Vec<u8>,
    create: F,
) -> Result<()>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<mpsc::Sender<Vec<u8>>>>,
{
    if let Some(tx) = sessions.lock().await.get(key).cloned() {
        if tx.send(payload.clone()).await.is_ok() {
            return Ok(());
        }
        sessions.lock().await.remove(key);
    }

    let tx = create().await?;
    tx.send(payload)
        .await
        .with_context(|| format!("UDP session for {key} closed before sending payload"))?;
    sessions.lock().await.insert(key.to_owned(), tx);
    Ok(())
}

async fn create_direct_udp_session(
    target: TargetAddr,
    relay: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    tasks: BackgroundTasks,
) -> Result<mpsc::Sender<Vec<u8>>> {
    let outbound = Arc::new(
        UdpSocket::bind(target_bind_addr(&target))
            .await
            .with_context(|| format!("failed to bind direct UDP socket for {}", target))?,
    );
    outbound
        .connect(target.to_string())
        .await
        .with_context(|| format!("failed to connect direct UDP socket for {}", target))?;

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let response_target = target.clone();
    let handle = tokio::spawn(async move {
        let mut buf = vec![0_u8; udp::MAX_UDP_FRAME_SIZE];
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(payload) => {
                            if let Err(err) = outbound.send(&payload).await {
                                warn!(target = %response_target, error = %err, "direct UDP send failed");
                                break;
                            }
                        }
                        None => break,
                    }
                }
                result = outbound.recv(&mut buf) => {
                    match result {
                        Ok(n) => {
                            if let Err(err) = forward_udp_response(&relay, &client_addr, &response_target, &buf[..n]).await {
                                warn!(target = %response_target, error = %err, "direct UDP response forwarding failed");
                                break;
                            }
                        }
                        Err(err) => {
                            warn!(target = %response_target, error = %err, "direct UDP receive failed");
                            break;
                        }
                    }
                }
            }
        }
    });

    tasks.lock().await.push(handle);
    Ok(tx)
}

async fn create_remote_udp_session(
    target: TargetAddr,
    relay: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    tasks: BackgroundTasks,
    args: ClientArgs,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<mpsc::Sender<Vec<u8>>> {
    let target_string = target.to_string();
    let upstream = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&args.server),
    )
    .await
    .context("server connect timed out for UDP session")??;
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
            return Err(err).context("TLS handshake with server failed for UDP session");
        }
        Err(_) => bail!("TLS handshake with server timed out for UDP session"),
    };

    let proof = AuthProof::sign(&args.password, "POST", &args.path, &target_string)?;
    let payload = http::TunnelPayload {
        target: target_string.clone(),
        transport: TunnelTransport::Udp,
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
        Ok(Ok((head, body_prefix))) => (head, body_prefix),
        Ok(Err(err)) => return Err(err).context("failed to read server response for UDP session"),
        Err(_) => bail!("server response timed out for UDP session"),
    };

    let response = http::parse_response_head(&response_head.0)
        .context("invalid server response for UDP session")?;
    if !response.is_http1 {
        bail!("server returned an unsupported HTTP version for UDP session");
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
                "server refused UDP tunnel with status {} {}: {}",
                response.status,
                response.reason,
                detail
            );
        }
        bail!(
            "server refused UDP tunnel with status {} {}",
            response.status,
            response.reason
        );
    }

    let (reader, writer) = tokio::io::split(tunnel);
    let mut reader = Cursor::new(response_head.1).chain(reader);
    let mut writer = writer;
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let response_target = target.clone();

    let read_handle = tokio::spawn({
        let relay = relay.clone();
        let client_addr = client_addr.clone();
        let response_target = response_target.clone();
        async move {
            loop {
                match udp::read_frame(&mut reader, udp::MAX_UDP_FRAME_SIZE).await {
                    Ok(payload) => {
                        if let Err(err) =
                            forward_udp_response(&relay, &client_addr, &response_target, &payload)
                                .await
                        {
                            warn!(target = %response_target, error = %err, "remote UDP response forwarding failed");
                            break;
                        }
                    }
                    Err(err) => {
                        if udp::is_eof(&err) {
                            debug!(target = %response_target, "remote UDP tunnel closed");
                        } else {
                            warn!(target = %response_target, error = %err, "remote UDP receive failed");
                        }
                        break;
                    }
                }
            }
        }
    });

    let write_handle = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            if let Err(err) = udp::write_frame(&mut writer, &payload).await {
                warn!(target = %response_target, error = %err, "remote UDP send failed");
                return;
            }
        }
        let _ = writer.shutdown().await;
    });

    let mut handles = tasks.lock().await;
    handles.push(read_handle);
    handles.push(write_handle);
    Ok(tx)
}

async fn forward_udp_response(
    relay: &UdpSocket,
    client_addr: &Mutex<Option<SocketAddr>>,
    target: &TargetAddr,
    payload: &[u8],
) -> Result<()> {
    let packet = socks5::build_udp_packet(target, payload);
    let client = match *client_addr.lock().await {
        Some(addr) => addr,
        None => return Ok(()),
    };

    relay
        .send_to(&packet, client)
        .await
        .with_context(|| format!("failed to forward UDP response for {}", target))?;
    Ok(())
}

async fn wait_for_control_close(stream: &mut TcpStream) -> Result<()> {
    let mut buf = [0_u8; 1];
    loop {
        if stream.read(&mut buf).await? == 0 {
            return Ok(());
        }
    }
}

async fn abort_background_tasks(tasks: BackgroundTasks) {
    let mut tasks = tasks.lock().await;
    for handle in tasks.drain(..) {
        handle.abort();
    }
}

fn target_bind_addr(target: &TargetAddr) -> SocketAddr {
    match target {
        TargetAddr::Ip(IpAddr::V6(_), _) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    }
}
