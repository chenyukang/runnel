use super::wire::{Rc4State, client_establish_ashe, relay_rc4, server_accept_ashe};
use crate::{
    proxy::{netlog, route, route::RouteDecision, socks5, traffic},
    runtime::{ClientRuntime, ServerRuntime},
};
use anyhow::{Context, Result, bail};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, duplex},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
    time::{Instant, MissedTickBehavior, interval_at, sleep, timeout},
};
use tracing::{info, warn};

const FRAME_OPEN: u8 = 0x00;
const FRAME_DATA: u8 = 0x01;
const FRAME_CLOSE: u8 = 0x02;
const FRAME_PROBE: u8 = 0x03;

const STREAM_POOL_SIZE: usize = 256;
const FRAME_HEADER_LEN: usize = 4;
const MAX_FRAME_PAYLOAD: usize = 2048 - FRAME_HEADER_LEN;
const STREAM_BUFFER_SIZE: usize = 64 * 1024;
const SESSION_CHANNEL_SIZE: usize = 256;
const STREAM_CHANNEL_SIZE: usize = 32;
const SESSION_KEEPALIVE_SECS: u64 = 32;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 48;

#[derive(Debug)]
enum CzarFrame {
    Open { stream_id: u8 },
    Data { stream_id: u8, payload: Vec<u8> },
    Close { stream_id: u8, reply: bool },
    Probe { reply: bool },
}

#[derive(Debug)]
enum StreamEvent {
    Data(Vec<u8>),
    Close,
}

#[derive(Clone)]
struct ClientSession {
    frame_tx: mpsc::Sender<CzarFrame>,
    streams: Arc<Mutex<HashMap<u8, mpsc::Sender<StreamEvent>>>>,
    ids: Arc<Mutex<Vec<u8>>>,
    closed: watch::Receiver<bool>,
}

impl ClientSession {
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}

struct CzarClient {
    server: String,
    password: String,
    connect_timeout: Duration,
    handshake_timeout: Duration,
    session: Mutex<Option<ClientSession>>,
}

impl CzarClient {
    fn new(runtime: &ClientRuntime) -> Self {
        Self {
            server: runtime.server.clone(),
            password: runtime.password.clone(),
            connect_timeout: runtime.connect_timeout,
            handshake_timeout: runtime.handshake_timeout,
            session: Mutex::new(None),
        }
    }

    async fn ensure_session(&self) -> Result<ClientSession> {
        let mut current = self.session.lock().await;
        if let Some(session) = current.as_ref()
            && !session.is_closed()
        {
            return Ok(session.clone());
        }

        let session = self.connect_session().await?;
        *current = Some(session.clone());
        Ok(session)
    }

    async fn clear_session(&self) {
        let mut current = self.session.lock().await;
        *current = None;
    }

    async fn connect_session(&self) -> Result<ClientSession> {
        let socket = timeout(self.connect_timeout, TcpStream::connect(&self.server))
            .await
            .context("czar server connect timed out")??;
        socket.set_nodelay(true)?;

        let (reader, writer) = tokio::io::split(socket);
        let (frame_tx, frame_rx) = mpsc::channel(SESSION_CHANNEL_SIZE);
        let (closed_tx, closed_rx) = watch::channel(false);
        let streams = Arc::new(Mutex::new(HashMap::new()));
        let ids = Arc::new(Mutex::new(
            (0..STREAM_POOL_SIZE as u16)
                .rev()
                .map(|id| id as u8)
                .collect(),
        ));

        tokio::spawn(run_client_session(
            reader,
            writer,
            frame_rx,
            streams.clone(),
            closed_tx,
        ));

        info!(server = %self.server, "czar session established");

        Ok(ClientSession {
            frame_tx,
            streams,
            ids,
            closed: closed_rx,
        })
    }

    async fn open_stream(&self) -> Result<DuplexStream> {
        let mut retried = false;
        loop {
            let session = self.ensure_session().await?;
            let Some(stream_id) = take_stream_id(&session.ids).await else {
                if retried {
                    bail!("czar session ran out of stream ids");
                }
                let mut current = self.session.lock().await;
                *current = None;
                retried = true;
                continue;
            };

            return self.open_stream_with_id(session, stream_id).await;
        }
    }

    async fn open_stream_with_id(
        &self,
        session: ClientSession,
        stream_id: u8,
    ) -> Result<DuplexStream> {
        let (user_stream, mux_stream) = duplex(STREAM_BUFFER_SIZE);
        let (event_tx, event_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);

        {
            let mut streams = session.streams.lock().await;
            streams.insert(stream_id, event_tx);
        }

        tokio::spawn(run_stream_bridge(
            stream_id,
            mux_stream,
            event_rx,
            session.frame_tx.clone(),
            session.streams.clone(),
        ));

        if session
            .frame_tx
            .send(CzarFrame::Open { stream_id })
            .await
            .is_err()
        {
            cleanup_client_stream(&session, stream_id).await;
            bail!("czar session closed before stream open");
        }

        Ok(user_stream)
    }
}

pub async fn run_client(runtime: ClientRuntime) -> Result<()> {
    let client = Arc::new(CzarClient::new(&runtime));
    let router = route::Router::from_runtime(&runtime).await?;
    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        server = %runtime.server,
        mode = "daze-czar",
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();
        let client = client.clone();
        let router = router.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(socket, peer, client, router, runtime).await
            {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-czar client session ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-czar client session ended with error");
                }
            }
        });
    }
}

pub async fn run_server(runtime: ServerRuntime) -> Result<()> {
    let listener = TcpListener::bind(&runtime.listen)
        .await
        .with_context(|| format!("failed to bind {}", runtime.listen))?;

    info!(
        listen = %runtime.listen,
        mode = "daze-czar",
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let runtime = runtime.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(socket, peer, runtime).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-czar server connection ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-czar server connection ended with error");
                }
            }
        });
    }
}

async fn handle_client_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    client: Arc<CzarClient>,
    router: Arc<route::Router>,
    runtime: ClientRuntime,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let target = timeout(client.handshake_timeout, socks5::accept(&mut inbound))
        .await
        .context("SOCKS handshake timed out")??;
    let target_string = target.to_string();

    match router.decide(&target).await? {
        RouteDecision::Direct => {
            let stats = route::relay_direct_socks(
                inbound,
                &target,
                runtime.connect_timeout,
                Some("daze-czar"),
            )
            .await?;
            info!(peer = %peer, target = %stats.display_target, route = "direct", mode = "daze-czar", "relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            info!(peer = %peer, target = %target_string, route = "block", mode = "daze-czar", "route decision");
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    if target_string.len() > u8::MAX as usize {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("destination address too long");
    }

    let (upstream, upload, download) = match open_czar_target_stream(&client, &target_string).await
    {
        Ok(opened) => opened,
        Err(first_err) => {
            client.clear_session().await;
            match open_czar_target_stream(&client, &target_string).await {
                Ok(opened) => opened,
                Err(second_err) => {
                    let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
                    return Err(second_err).context(format!(
                        "failed to open czar stream after reconnect attempt; first error: {first_err:#}"
                    ));
                }
            }
        }
    };

    socks5::send_success(&mut inbound).await?;
    let stats = relay_rc4(
        inbound,
        upstream,
        upload,
        download,
        traffic::RelayLabels {
            target: target_string.clone(),
            route: Some("remote".to_owned()),
            mode: Some("daze-czar".to_owned()),
        },
    )
    .await?;

    info!(
        peer = %peer,
        target = %stats.display_target,
        uploaded = stats.uploaded,
        downloaded = stats.downloaded,
        sampled = stats.sampled,
        mode = "daze-czar",
        "relay completed"
    );
    Ok(())
}

async fn open_czar_target_stream(
    client: &CzarClient,
    target_string: &str,
) -> Result<(DuplexStream, Rc4State, Rc4State)> {
    let mut upstream = client.open_stream().await?;
    let (upload, download) =
        client_establish_ashe(&mut upstream, &client.password, target_string).await?;
    Ok((upstream, upload, download))
}

async fn handle_server_connection(
    socket: TcpStream,
    peer: SocketAddr,
    runtime: ServerRuntime,
) -> Result<()> {
    socket.set_nodelay(true)?;

    let (reader, writer) = tokio::io::split(socket);
    let (frame_tx, frame_rx) = mpsc::channel(SESSION_CHANNEL_SIZE);
    let (accept_tx, mut accept_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
    let (closed_tx, _closed_rx) = watch::channel(false);
    let streams = Arc::new(Mutex::new(HashMap::new()));

    tokio::spawn(run_server_session(
        reader,
        writer,
        frame_tx.clone(),
        frame_rx,
        streams.clone(),
        accept_tx,
        closed_tx,
    ));

    while let Some(stream) = accept_rx.recv().await {
        let runtime = runtime.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_stream(stream, runtime).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "daze-czar stream ended");
                } else {
                    warn!(peer = %peer, error = %err, "daze-czar stream ended with error");
                }
            }
        });
    }

    Ok(())
}

async fn handle_server_stream(mut inbound: DuplexStream, runtime: ServerRuntime) -> Result<()> {
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
            mode: Some("daze-czar".to_owned()),
        },
    )
    .await?;

    info!(
        target = %stats.display_target,
        uploaded = stats.uploaded,
        downloaded = stats.downloaded,
        sampled = stats.sampled,
        mode = "daze-czar",
        "relay completed"
    );
    Ok(())
}

async fn run_client_session<R, W>(
    mut reader: R,
    mut writer: W,
    mut frame_rx: mpsc::Receiver<CzarFrame>,
    streams: Arc<Mutex<HashMap<u8, mpsc::Sender<StreamEvent>>>>,
    closed_tx: watch::Sender<bool>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let keepalive = Duration::from_secs(SESSION_KEEPALIVE_SECS);
    let idle_timeout = Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS);
    let mut heartbeat = interval_at(Instant::now() + keepalive, keepalive);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let idle_deadline = sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let result: Result<()> = async {
        loop {
            tokio::select! {
                maybe_frame = frame_rx.recv() => {
                    let Some(frame) = maybe_frame else {
                        break;
                    };
                    write_frame(&mut writer, frame).await?;
                }
                frame = read_frame(&mut reader) => {
                    match frame? {
                        CzarFrame::Data { stream_id, payload } => {
                            dispatch_stream_event(&streams, stream_id, StreamEvent::Data(payload)).await;
                        }
                        CzarFrame::Close { stream_id, .. } => {
                            dispatch_stream_event(&streams, stream_id, StreamEvent::Close).await;
                        }
                        CzarFrame::Probe { reply: false } => {
                            write_frame(&mut writer, CzarFrame::Probe { reply: true }).await?;
                        }
                        CzarFrame::Probe { reply: true } => {}
                        CzarFrame::Open { .. } => bail!("unexpected stream open from czar server"),
                    }
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
                _ = heartbeat.tick() => {
                    write_frame(&mut writer, CzarFrame::Probe { reply: false }).await?;
                }
                _ = &mut idle_deadline => {
                    bail!("czar session timed out waiting for peer activity");
                }
            }
        }

        Ok(())
    }
    .await;

    if let Err(err) = result {
        if netlog::is_noisy_disconnect(&err) {
            info!(error = %err, "czar client session closed");
        } else {
            warn!(error = %err, "czar client session closed");
        }
    }

    close_session(streams, closed_tx).await;
}

async fn run_server_session<R, W>(
    mut reader: R,
    mut writer: W,
    frame_tx: mpsc::Sender<CzarFrame>,
    mut frame_rx: mpsc::Receiver<CzarFrame>,
    streams: Arc<Mutex<HashMap<u8, mpsc::Sender<StreamEvent>>>>,
    accept_tx: mpsc::Sender<DuplexStream>,
    closed_tx: watch::Sender<bool>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let keepalive = Duration::from_secs(SESSION_KEEPALIVE_SECS);
    let idle_timeout = Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS);
    let mut heartbeat = interval_at(Instant::now() + keepalive, keepalive);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let idle_deadline = sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let result: Result<()> = async {
        loop {
            tokio::select! {
                maybe_frame = frame_rx.recv() => {
                    let Some(frame) = maybe_frame else {
                        break;
                    };
                    write_frame(&mut writer, frame).await?;
                }
                frame = read_frame(&mut reader) => {
                    match frame? {
                        CzarFrame::Open { stream_id } => {
                            let (user_stream, mux_stream) = duplex(STREAM_BUFFER_SIZE);
                            let (event_tx, event_rx) = mpsc::channel(STREAM_CHANNEL_SIZE);
                            {
                                let mut map = streams.lock().await;
                                if map.contains_key(&stream_id) {
                                    bail!("duplicate czar stream id {}", stream_id);
                                }
                                map.insert(stream_id, event_tx);
                            }
                            tokio::spawn(run_stream_bridge(
                                stream_id,
                                mux_stream,
                                event_rx,
                                frame_tx.clone(),
                                streams.clone(),
                            ));
                            if accept_tx.send(user_stream).await.is_err() {
                                bail!("failed to accept incoming czar stream");
                            }
                        }
                        CzarFrame::Data { stream_id, payload } => {
                            dispatch_stream_event(&streams, stream_id, StreamEvent::Data(payload)).await;
                        }
                        CzarFrame::Close { stream_id, .. } => {
                            dispatch_stream_event(&streams, stream_id, StreamEvent::Close).await;
                        }
                        CzarFrame::Probe { reply: false } => {
                            write_frame(&mut writer, CzarFrame::Probe { reply: true }).await?;
                        }
                        CzarFrame::Probe { reply: true } => {}
                    }
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
                _ = heartbeat.tick() => {
                    write_frame(&mut writer, CzarFrame::Probe { reply: false }).await?;
                }
                _ = &mut idle_deadline => {
                    bail!("czar session timed out waiting for peer activity");
                }
            }
        }

        Ok(())
    }
    .await;

    if let Err(err) = result {
        if netlog::is_noisy_disconnect(&err) {
            info!(error = %err, "czar server session closed");
        } else {
            warn!(error = %err, "czar server session closed");
        }
    }

    close_session(streams, closed_tx).await;
}

async fn run_stream_bridge(
    stream_id: u8,
    stream: DuplexStream,
    mut event_rx: mpsc::Receiver<StreamEvent>,
    frame_tx: mpsc::Sender<CzarFrame>,
    streams: Arc<Mutex<HashMap<u8, mpsc::Sender<StreamEvent>>>>,
) {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let uplink_tx = frame_tx.clone();
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0_u8; MAX_FRAME_PAYLOAD];
        loop {
            let n = match reader.read(&mut buf).await {
                Ok(n) => n,
                Err(_) => {
                    let _ = uplink_tx
                        .send(CzarFrame::Close {
                            stream_id,
                            reply: false,
                        })
                        .await;
                    return;
                }
            };

            if n == 0 {
                let _ = uplink_tx
                    .send(CzarFrame::Close {
                        stream_id,
                        reply: false,
                    })
                    .await;
                return;
            }

            if uplink_tx
                .send(CzarFrame::Data {
                    stream_id,
                    payload: buf[..n].to_vec(),
                })
                .await
                .is_err()
            {
                return;
            }
        }
    });

    while let Some(event) = event_rx.recv().await {
        match event {
            StreamEvent::Data(data) => {
                if writer.write_all(&data).await.is_err() {
                    break;
                }
            }
            StreamEvent::Close => {
                let _ = writer.shutdown().await;
                break;
            }
        }
    }

    let _ = writer.shutdown().await;
    uplink.abort();
    let _ = uplink.await;

    {
        let mut map = streams.lock().await;
        map.remove(&stream_id);
    }
}

async fn cleanup_client_stream(session: &ClientSession, stream_id: u8) {
    {
        let mut streams = session.streams.lock().await;
        streams.remove(&stream_id);
    }
}

async fn dispatch_stream_event(
    streams: &Arc<Mutex<HashMap<u8, mpsc::Sender<StreamEvent>>>>,
    stream_id: u8,
    event: StreamEvent,
) {
    let sender = {
        let map = streams.lock().await;
        map.get(&stream_id).cloned()
    };

    if let Some(sender) = sender {
        let _ = sender.send(event).await;
    }
}

async fn close_session(
    streams: Arc<Mutex<HashMap<u8, mpsc::Sender<StreamEvent>>>>,
    closed_tx: watch::Sender<bool>,
) {
    let _ = closed_tx.send(true);
    let channels = {
        let mut map = streams.lock().await;
        map.drain().map(|(_, tx)| tx).collect::<Vec<_>>()
    };

    for tx in channels {
        let _ = tx.send(StreamEvent::Close).await;
    }
}

async fn take_stream_id(ids: &Arc<Mutex<Vec<u8>>>) -> Option<u8> {
    let mut ids = ids.lock().await;
    ids.pop()
}

async fn read_frame<R>(reader: &mut R) -> Result<CzarFrame>
where
    R: AsyncRead + Unpin,
{
    let mut head = [0_u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut head).await?;

    match head[0] {
        FRAME_OPEN => Ok(CzarFrame::Open { stream_id: head[1] }),
        FRAME_DATA => {
            let len = u16::from_be_bytes([head[2], head[3]]) as usize;
            let mut payload = vec![0_u8; len];
            reader.read_exact(&mut payload).await?;
            Ok(CzarFrame::Data {
                stream_id: head[1],
                payload,
            })
        }
        FRAME_CLOSE => Ok(CzarFrame::Close {
            stream_id: head[1],
            reply: head[2] != 0,
        }),
        FRAME_PROBE => Ok(CzarFrame::Probe {
            reply: head[1] != 0,
        }),
        kind => bail!("unknown czar frame type {}", kind),
    }
}

async fn write_frame<W>(writer: &mut W, frame: CzarFrame) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    match frame {
        CzarFrame::Open { stream_id } => {
            writer.write_all(&[FRAME_OPEN, stream_id, 0, 0]).await?;
        }
        CzarFrame::Data { stream_id, payload } => {
            let len = u16::try_from(payload.len()).context("czar payload too large")?;
            let mut head = [0_u8; FRAME_HEADER_LEN];
            head[0] = FRAME_DATA;
            head[1] = stream_id;
            head[2..4].copy_from_slice(&len.to_be_bytes());
            writer.write_all(&head).await?;
            writer.write_all(&payload).await?;
        }
        CzarFrame::Close { stream_id, reply } => {
            writer
                .write_all(&[FRAME_CLOSE, stream_id, if reply { 1 } else { 0 }, 0])
                .await?;
        }
        CzarFrame::Probe { reply } => {
            writer
                .write_all(&[FRAME_PROBE, if reply { 1 } else { 0 }, 0, 0])
                .await?;
        }
    }

    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut left, mut right) = duplex(1024);
        let frame = CzarFrame::Data {
            stream_id: 7,
            payload: b"hello".to_vec(),
        };

        let writer = tokio::spawn(async move {
            write_frame(&mut left, frame).await.expect("write frame");
        });

        let decoded = read_frame(&mut right).await.expect("read frame");
        writer.await.expect("join writer");

        match decoded {
            CzarFrame::Data { stream_id, payload } => {
                assert_eq!(stream_id, 7);
                assert_eq!(payload, b"hello");
            }
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}
