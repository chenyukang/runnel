use super::{
    http::TunnelTransport,
    remote::establish_remote_tunnel,
    route::{RouteDecision, Router},
    socks5::{self, TargetAddr},
    udp,
};
use crate::runtime::ClientRuntime;
use anyhow::{Context, Result, bail};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::{Mutex, mpsc},
    task::JoinHandle,
};
use tokio_rustls::TlsConnector;
use tracing::{debug, info, warn};

type SessionMap = Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>;
type BackgroundTasks = Arc<Mutex<Vec<JoinHandle<()>>>>;

pub(crate) async fn handle_native_http_udp_associate(
    mut inbound: TcpStream,
    peer: SocketAddr,
    args: ClientRuntime,
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
    args: ClientRuntime,
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

        if let Some(dns_upstream) = args.tun_dns_udp_upstream(&target) {
            let dns_key = format!("dns-tcp:{dns_upstream}");
            send_via_session(&remote_sessions, &dns_key, packet.payload, || {
                create_remote_tcp_dns_session(
                    target.clone(),
                    dns_upstream.clone(),
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
            continue;
        }

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
                info!(target = %key, route = "block", mode = "native-http", "route decision");
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
    args: ClientRuntime,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<mpsc::Sender<Vec<u8>>> {
    let target_string = target.to_string();
    let tunnel = establish_remote_tunnel(
        &args,
        &connector,
        &host_header,
        &server_name,
        &target_string,
        TunnelTransport::Udp,
    )
    .await
    .with_context(|| format!("failed to establish remote UDP tunnel for {target_string}"))?;

    let (mut reader, writer) = tokio::io::split(tunnel);
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

async fn create_remote_tcp_dns_session(
    response_target: TargetAddr,
    upstream_target: TargetAddr,
    relay: Arc<UdpSocket>,
    client_addr: Arc<Mutex<Option<SocketAddr>>>,
    tasks: BackgroundTasks,
    args: ClientRuntime,
    connector: TlsConnector,
    host_header: String,
    server_name: String,
) -> Result<mpsc::Sender<Vec<u8>>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(256);
    let handle = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            match exchange_remote_dns_over_tcp(
                &args,
                &connector,
                &host_header,
                &server_name,
                &upstream_target,
                &payload,
            )
            .await
            {
                Ok(response) => {
                    if let Err(err) =
                        forward_udp_response(&relay, &client_addr, &response_target, &response)
                            .await
                    {
                        warn!(
                            target = %response_target,
                            upstream = %upstream_target,
                            error = %err,
                            "remote TCP DNS response forwarding failed"
                        );
                        break;
                    }
                }
                Err(err) => {
                    warn!(
                        target = %response_target,
                        upstream = %upstream_target,
                        error = %err,
                        "remote TCP DNS exchange failed"
                    );
                }
            }
        }
    });

    tasks.lock().await.push(handle);
    Ok(tx)
}

async fn exchange_remote_dns_over_tcp(
    args: &ClientRuntime,
    connector: &TlsConnector,
    host_header: &str,
    server_name: &str,
    upstream_target: &TargetAddr,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let target_string = upstream_target.to_string();
    let mut tunnel = establish_remote_tunnel(
        args,
        connector,
        host_header,
        server_name,
        &target_string,
        TunnelTransport::Tcp,
    )
    .await
    .with_context(|| format!("failed to establish remote TCP DNS tunnel for {target_string}"))?;

    if payload.len() > u16::MAX as usize {
        bail!("DNS payload exceeded {} bytes", u16::MAX);
    }
    tunnel
        .write_all(&(payload.len() as u16).to_be_bytes())
        .await
        .context("failed to write TCP DNS request length")?;
    tunnel
        .write_all(payload)
        .await
        .context("failed to write TCP DNS request body")?;
    tunnel
        .flush()
        .await
        .context("failed to flush TCP DNS request")?;

    let mut length = [0_u8; 2];
    tunnel
        .read_exact(&mut length)
        .await
        .context("failed to read TCP DNS response length")?;
    let response_len = u16::from_be_bytes(length) as usize;
    let mut response = vec![0_u8; response_len];
    tunnel
        .read_exact(&mut response)
        .await
        .context("failed to read TCP DNS response body")?;
    Ok(response)
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
