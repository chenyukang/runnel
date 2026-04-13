use crate::{
    auth::{AuthProof, ReplayProtector},
    client::ClientArgs, netlog,
    http, route, route::RouteDecision, server::ServerArgs, socks5, tls,
};
use anyhow::{Context, Result, bail};
use std::{
    io::Cursor,
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, watch},
    time::{Instant, MissedTickBehavior, interval_at, sleep, timeout},
};
use tokio_rustls::TlsConnector;
use tracing::{info, warn};

const FRAME_OPEN: u8 = 1;
const FRAME_OPEN_OK: u8 = 2;
const FRAME_OPEN_ERR: u8 = 3;
const FRAME_DATA: u8 = 4;
const FRAME_CLOSE: u8 = 5;
const FRAME_PING: u8 = 6;
const FRAME_PONG: u8 = 7;
const FRAME_MAGIC: [u8; 2] = *b"PM";

// Keep mux data frames conservative. Local stress tests reproduced bad headers in the
// ~32 KiB regime before frames carried a magic prefix, and even with magic + resync
// the concurrent large-response stress test still regresses at 32 KiB. 16 KiB is the
// current largest payload size that remains stable under the local stress suite.
const MAX_FRAME_PAYLOAD: usize = 16 * 1024;
const MAX_CONTROL_PAYLOAD: usize = 8 * 1024;
const FRAME_HEADER_LEN: usize = 11;
const SESSION_AUTH_TARGET: &str = "__mux__";
const SESSION_KEEPALIVE_SECS: u64 = 32;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 48;

#[derive(Debug)]
struct Frame {
    kind: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

impl Frame {
    fn open(stream_id: u32, target: String) -> Self {
        Self {
            kind: FRAME_OPEN,
            stream_id,
            payload: target.into_bytes(),
        }
    }

    fn open_ok(stream_id: u32) -> Self {
        Self {
            kind: FRAME_OPEN_OK,
            stream_id,
            payload: Vec::new(),
        }
    }

    fn open_err(stream_id: u32, message: impl Into<String>) -> Self {
        let mut payload = message.into().into_bytes();
        payload.truncate(MAX_CONTROL_PAYLOAD);
        Self {
            kind: FRAME_OPEN_ERR,
            stream_id,
            payload,
        }
    }

    fn data(stream_id: u32, payload: Vec<u8>) -> Self {
        Self {
            kind: FRAME_DATA,
            stream_id,
            payload,
        }
    }

    fn close(stream_id: u32) -> Self {
        Self {
            kind: FRAME_CLOSE,
            stream_id,
            payload: Vec::new(),
        }
    }

    fn ping() -> Self {
        Self {
            kind: FRAME_PING,
            stream_id: 0,
            payload: Vec::new(),
        }
    }

    fn pong() -> Self {
        Self {
            kind: FRAME_PONG,
            stream_id: 0,
            payload: Vec::new(),
        }
    }
}

#[derive(Debug)]
enum StreamEvent {
    Opened,
    OpenError(String),
    Data(Vec<u8>),
    Closed,
}

#[derive(Debug)]
enum ServerStreamCommand {
    Data(Vec<u8>),
    Close,
}

#[derive(Clone)]
struct ClientSession {
    frame_tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    closed: watch::Receiver<bool>,
}

impl ClientSession {
    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }
}

struct MuxClient {
    connector: TlsConnector,
    server: String,
    server_name: String,
    host_header: String,
    password: String,
    mux_path: String,
    user_agent: String,
    handshake_timeout: Duration,
    connect_timeout: Duration,
    max_header_size: usize,
    session: Mutex<Option<ClientSession>>,
    next_stream_id: AtomicU32,
}

impl MuxClient {
    fn new(args: &ClientArgs) -> Result<Self> {
        let connector = TlsConnector::from(tls::load_client_config(args.ca_cert.as_deref())?);
        let (default_host, _) = tls::split_host_port(&args.server)?;
        let server_name = args
            .server_name
            .clone()
            .unwrap_or_else(|| default_host.clone());

        Ok(Self {
            connector,
            server: args.server.clone(),
            server_name,
            host_header: default_host,
            password: args.password.clone(),
            mux_path: args.mux_path.clone(),
            user_agent: args.user_agent.clone(),
            handshake_timeout: Duration::from_secs(args.handshake_timeout_secs),
            connect_timeout: Duration::from_secs(args.connect_timeout_secs),
            max_header_size: args.max_header_size,
            session: Mutex::new(None),
            next_stream_id: AtomicU32::new(1),
        })
    }

    async fn ensure_session(&self) -> Result<ClientSession> {
        let mut current = self.session.lock().await;
        if let Some(session) = current.as_ref() {
            if !session.is_closed() {
                return Ok(session.clone());
            }
        }

        let session = self.connect_session().await?;
        *current = Some(session.clone());
        Ok(session)
    }

    async fn connect_session(&self) -> Result<ClientSession> {
        let upstream = timeout(self.connect_timeout, TcpStream::connect(&self.server))
            .await
            .context("mux server connect timed out")??;
        upstream.set_nodelay(true)?;

        let server_name = tls::server_name(&self.server_name)?;
        let mut tunnel = timeout(
            self.handshake_timeout,
            self.connector.connect(server_name, upstream),
        )
        .await
        .context("mux TLS handshake timed out")??;

        let proof = AuthProof::sign(
            &self.password,
            "POST",
            &self.mux_path,
            SESSION_AUTH_TARGET,
        )?;
        let payload = http::TunnelPayload {
            target: SESSION_AUTH_TARGET.to_owned(),
            timestamp: proof.timestamp,
            nonce: proof.nonce,
            signature: proof.signature,
        };
        let request =
            http::build_tunnel_request(&self.host_header, &self.mux_path, &payload, &self.user_agent)?;
        tunnel.write_all(&request).await?;

        let (head, body_prefix) = timeout(
            self.handshake_timeout,
            http::read_head(&mut tunnel, self.max_header_size),
        )
        .await
        .context("mux session response timed out")??;

        let (is_http1, status, reason) =
            http::parse_tunnel_response(&head).context("invalid mux session response")?;
        if !is_http1 {
            bail!("mux server returned an unsupported HTTP version");
        }
        if status != 200 {
            bail!("mux server refused session with status {} {}", status, reason);
        }

        let (reader, writer) = tokio::io::split(tunnel);
        let reader = Cursor::new(body_prefix).chain(reader);
        let (frame_tx, frame_rx) = mpsc::channel(256);
        let (closed_tx, closed_rx) = watch::channel(false);
        let streams = Arc::new(Mutex::new(HashMap::new()));

        tokio::spawn(run_client_session(
            reader,
            writer,
            frame_tx.clone(),
            frame_rx,
            streams.clone(),
            closed_tx,
        ));

        info!(server = %self.server, path = %self.mux_path, "mux session established");

        Ok(ClientSession {
            frame_tx,
            streams,
            closed: closed_rx,
        })
    }

    fn next_stream_id(&self) -> u32 {
        self.next_stream_id.fetch_add(1, Ordering::Relaxed)
    }
}

pub async fn run_client(args: ClientArgs) -> Result<()> {
    let session = Arc::new(MuxClient::new(&args)?);
    let router = route::Router::from_args(&args)?;
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        server = %args.server,
        mux_path = %args.mux_path,
        "client listening with mux"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let session = session.clone();
        let args = args.clone();
        let router = router.clone();

        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(socket, peer, session, router, args).await {
                if netlog::is_noisy_disconnect(&err) {
                    info!(peer = %peer, error = %err, "mux client session ended");
                } else {
                    warn!(peer = %peer, error = %err, "mux client session ended with error");
                }
            }
        });
    }
}

async fn handle_client_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    mux: Arc<MuxClient>,
    router: Arc<route::Router>,
    args: ClientArgs,
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
            let _ = route::relay_direct_socks(inbound, &target, connect_timeout).await?;
            info!(peer = %peer, target = %target_string, route = "direct", "mux relay completed");
            return Ok(());
        }
        RouteDecision::Block => {
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("target blocked by proxy control: {}", target_string);
        }
        RouteDecision::Remote => {}
    }

    let session = mux.ensure_session().await?;
    let stream_id = mux.next_stream_id();
    let (stream_tx, mut stream_rx) = mpsc::channel(64);

    {
        let mut streams = session.streams.lock().await;
        streams.insert(stream_id, stream_tx);
    }

    if session
        .frame_tx
        .send(Frame::open(stream_id, target_string.clone()))
        .await
        .is_err()
    {
        remove_client_stream(&session, stream_id).await;
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("mux session is not available");
    }

    let first_event = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        stream_rx.recv(),
    )
    .await
    .context("mux stream open timed out")?;

    match first_event {
        Some(StreamEvent::Opened) => {
            socks5::send_success(&mut inbound).await?;
        }
        Some(StreamEvent::OpenError(message)) => {
            remove_client_stream(&session, stream_id).await;
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("mux server refused stream: {message}");
        }
        Some(StreamEvent::Closed) | None => {
            remove_client_stream(&session, stream_id).await;
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("mux session closed while opening stream");
        }
        Some(StreamEvent::Data(_)) => {
            remove_client_stream(&session, stream_id).await;
            let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
            bail!("mux session sent data before stream open completed");
        }
    }

    let (mut reader, mut writer) = inbound.into_split();
    let frame_tx = session.frame_tx.clone();

    let upload_task = tokio::spawn(async move {
        let mut buf = vec![0_u8; MAX_FRAME_PAYLOAD];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                let _ = frame_tx.send(Frame::close(stream_id)).await;
                return Ok::<(), anyhow::Error>(());
            }

            if frame_tx
                .send(Frame::data(stream_id, buf[..n].to_vec()))
                .await
                .is_err()
            {
                bail!("mux session closed while uploading");
            }
        }
    });

    let download_result = async {
        while let Some(event) = stream_rx.recv().await {
            match event {
                StreamEvent::Opened => {}
                StreamEvent::OpenError(message) => bail!("mux stream failed after open: {message}"),
                StreamEvent::Data(chunk) => writer.write_all(&chunk).await?,
                StreamEvent::Closed => break,
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    upload_task.abort();
    let _ = upload_task.await;

    remove_client_stream(&session, stream_id).await;
    let _ = session.frame_tx.send(Frame::close(stream_id)).await;

    download_result?;

    info!(peer = %peer, target = %target_string, stream_id, "mux relay completed");

    Ok(())
}

pub async fn run_server_session<S>(
    mut stream: S,
    peer: SocketAddr,
    request_head: http::TunnelRequestHead,
    body_prefix: &[u8],
    args: ServerArgs,
    replay: Arc<ReplayProtector>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if request_head.chunked {
        stream
            .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
            .await?;
        return Ok(());
    }

    let body_length = match request_head.content_length {
        Some(length) => length,
        None => {
            stream
                .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
                .await?;
            return Ok(());
        }
    };

    let body = http::read_body(&mut stream, body_prefix, body_length, args.max_tunnel_body_size)
        .await?;
    let payload = match http::parse_tunnel_payload(&body) {
        Ok(payload) => payload,
        Err(_) => {
            stream
                .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
                .await?;
            return Ok(());
        }
    };

    if payload.target != SESSION_AUTH_TARGET {
        stream
            .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
            .await?;
        return Ok(());
    }

    let proof = AuthProof {
        timestamp: payload.timestamp,
        nonce: payload.nonce,
        signature: payload.signature,
    };

    if replay
        .validate(
            &args.password,
            "POST",
            &args.mux_path,
            SESSION_AUTH_TARGET,
            &proof,
        )
        .is_err()
    {
        stream
            .write_all(&http::build_error_response(404, "Not Found", "not found\n"))
            .await?;
        return Ok(());
    }

    stream.write_all(&http::build_tunnel_established()).await?;
    info!(peer = %peer, path = %args.mux_path, "mux session accepted");

    let (reader, writer) = tokio::io::split(stream);
    let (frame_tx, frame_rx) = mpsc::channel(256);
    let streams = Arc::new(Mutex::new(HashMap::new()));

    run_server_io(reader, writer, frame_rx, frame_tx, streams, args).await
}

async fn run_client_session<R, W>(
    mut reader: R,
    mut writer: W,
    frame_tx: mpsc::Sender<Frame>,
    mut frame_rx: mpsc::Receiver<Frame>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
    closed_tx: watch::Sender<bool>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let keepalive = Duration::from_secs(SESSION_KEEPALIVE_SECS);
    let idle_timeout = Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS);
    let mut heartbeat = interval_at(Instant::now() + keepalive, keepalive);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let idle_deadline = sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let result = async {
        loop {
            tokio::select! {
                maybe_frame = frame_rx.recv() => {
                    let Some(frame) = maybe_frame else {
                        break;
                    };
                    write_frame(&mut writer, &frame).await?;
                }
                frame = read_frame(&mut reader, MAX_FRAME_PAYLOAD) => {
                    let frame = frame?;
                    match frame.kind {
                        FRAME_PING => {
                            let _ = frame_tx.send(Frame::pong()).await;
                        }
                        FRAME_PONG => {}
                        _ => dispatch_client_frame(frame, &streams).await?,
                    }
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
                _ = heartbeat.tick() => {
                    if frame_tx.send(Frame::ping()).await.is_err() {
                        bail!("mux session closed while sending keepalive");
                    }
                }
                _ = &mut idle_deadline => {
                    bail!("mux session timed out waiting for peer activity");
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(err) = result {
        if netlog::is_noisy_disconnect(&err) {
            info!(error = %err, "mux client session closed");
        } else {
            warn!(error = %err, "mux client session closed");
        }
    }

    close_client_streams(&streams).await;
    let _ = closed_tx.send(true);
}

async fn run_server_io<R, W>(
    mut reader: R,
    mut writer: W,
    mut frame_rx: mpsc::Receiver<Frame>,
    frame_tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<ServerStreamCommand>>>>,
    args: ServerArgs,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let keepalive = Duration::from_secs(SESSION_KEEPALIVE_SECS);
    let idle_timeout = Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS);
    let mut heartbeat = interval_at(Instant::now() + keepalive, keepalive);
    heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let idle_deadline = sleep(idle_timeout);
    tokio::pin!(idle_deadline);

    let result = async {
        loop {
            tokio::select! {
                maybe_frame = frame_rx.recv() => {
                    let Some(frame) = maybe_frame else {
                        break;
                    };
                    write_frame(&mut writer, &frame).await?;
                }
                frame = read_frame(&mut reader, MAX_FRAME_PAYLOAD) => {
                    let frame = frame?;
                    match frame.kind {
                        FRAME_OPEN => {
                            let target = String::from_utf8(frame.payload)
                                .context("mux stream target is not valid UTF-8")?;
                            let existing = {
                                let streams = streams.lock().await;
                                streams.contains_key(&frame.stream_id)
                            };
                            if existing {
                                let _ = frame_tx
                                    .send(Frame::open_err(frame.stream_id, "duplicate stream id"))
                                    .await;
                                continue;
                            }

                            let frame_tx = frame_tx.clone();
                            let streams = streams.clone();
                            let args = args.clone();

                            tokio::spawn(async move {
                                if let Err(err) =
                                    handle_server_open(frame.stream_id, target, frame_tx, streams, args).await
                                {
                                    if netlog::is_noisy_disconnect(&err) {
                                        info!(stream_id = frame.stream_id, error = %err, "mux stream ended");
                                    } else {
                                        warn!(stream_id = frame.stream_id, error = %err, "mux stream failed");
                                    }
                                }
                            });
                        }
                        FRAME_DATA => {
                            let tx = {
                                let streams = streams.lock().await;
                                streams.get(&frame.stream_id).cloned()
                            };

                            if let Some(tx) = tx {
                                let _ = tx.send(ServerStreamCommand::Data(frame.payload)).await;
                            }
                        }
                        FRAME_CLOSE => {
                            close_server_stream(&streams, frame.stream_id).await;
                        }
                        FRAME_PING => {
                            let _ = frame_tx.send(Frame::pong()).await;
                        }
                        FRAME_PONG => {}
                        _ => bail!("unexpected mux frame type {}", frame.kind),
                    }
                    idle_deadline.as_mut().reset(Instant::now() + idle_timeout);
                }
                _ = heartbeat.tick() => {
                    if frame_tx.send(Frame::ping()).await.is_err() {
                        bail!("mux session closed while sending keepalive");
                    }
                }
                _ = &mut idle_deadline => {
                    bail!("mux session timed out waiting for peer activity");
                }
            }
        }

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(err) = result {
        if netlog::is_noisy_disconnect(&err) {
            info!(error = %err, "mux server session closed");
        } else {
            warn!(error = %err, "mux server session closed");
        }
    }

    close_all_server_streams(&streams).await;
    Ok(())
}

async fn handle_server_open(
    stream_id: u32,
    target: String,
    frame_tx: mpsc::Sender<Frame>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<ServerStreamCommand>>>>,
    args: ServerArgs,
) -> Result<()> {
    if !args.allow_private_targets && is_private_literal_target(&target) {
        let _ = frame_tx
            .send(Frame::open_err(
                stream_id,
                "literal private IP targets are disabled by default",
            ))
            .await;
        return Ok(());
    }

    let outbound = match timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&target),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            let _ = frame_tx
                .send(Frame::open_err(stream_id, format!("connect failed: {err}")))
                .await;
            return Ok(());
        }
        Err(_) => {
            let _ = frame_tx
                .send(Frame::open_err(stream_id, "upstream connect timed out"))
                .await;
            return Ok(());
        }
    };
    outbound.set_nodelay(true)?;

    let (command_tx, mut command_rx) = mpsc::channel(64);
    {
        let mut active = streams.lock().await;
        active.insert(stream_id, command_tx);
    }

    if frame_tx.send(Frame::open_ok(stream_id)).await.is_err() {
        let mut active = streams.lock().await;
        active.remove(&stream_id);
        return Ok(());
    }

    let (mut reader, mut writer) = outbound.into_split();
    let frame_tx_reader = frame_tx.clone();
    let read_loop = async move {
        let mut buf = vec![0_u8; MAX_FRAME_PAYLOAD];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }

            if frame_tx_reader
                .send(Frame::data(stream_id, buf[..n].to_vec()))
                .await
                .is_err()
            {
                bail!("mux session closed while sending upstream data");
            }
        }

        Ok::<(), anyhow::Error>(())
    };

    let write_loop = async move {
        while let Some(command) = command_rx.recv().await {
            match command {
                ServerStreamCommand::Data(chunk) => writer.write_all(&chunk).await?,
                ServerStreamCommand::Close => break,
            }
        }

        let _ = writer.shutdown().await;
        Ok::<(), anyhow::Error>(())
    };

    let result = tokio::select! {
        res = read_loop => res,
        res = write_loop => res,
    };

    if let Err(err) = result {
        if netlog::is_noisy_disconnect(&err) {
            info!(stream_id, target = %target, error = %err, "mux upstream stream closed");
        } else {
            warn!(stream_id, target = %target, error = %err, "mux upstream stream closed with error");
        }
    }

    {
        let mut active = streams.lock().await;
        active.remove(&stream_id);
    }
    let _ = frame_tx.send(Frame::close(stream_id)).await;

    Ok(())
}

async fn dispatch_client_frame(
    frame: Frame,
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
) -> Result<()> {
    let event = match frame.kind {
        FRAME_OPEN_OK => StreamEvent::Opened,
        FRAME_OPEN_ERR => StreamEvent::OpenError(
            String::from_utf8(frame.payload).context("mux error is not valid UTF-8")?,
        ),
        FRAME_DATA => StreamEvent::Data(frame.payload),
        FRAME_CLOSE => StreamEvent::Closed,
        FRAME_PING | FRAME_PONG => return Ok(()),
        _ => bail!("unexpected mux frame type {}", frame.kind),
    };

    let tx = {
        let streams = streams.lock().await;
        streams.get(&frame.stream_id).cloned()
    };

    if let Some(tx) = tx {
        let _ = tx.send(event).await;
    }

    Ok(())
}

async fn remove_client_stream(session: &ClientSession, stream_id: u32) {
    let mut streams = session.streams.lock().await;
    streams.remove(&stream_id);
}

async fn close_client_streams(
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<StreamEvent>>>>,
) {
    let channels = {
        let mut active = streams.lock().await;
        active.drain().map(|(_, tx)| tx).collect::<Vec<_>>()
    };

    for tx in channels {
        let _ = tx.send(StreamEvent::Closed).await;
    }
}

async fn close_server_stream(
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<ServerStreamCommand>>>>,
    stream_id: u32,
) {
    let tx = {
        let mut active = streams.lock().await;
        active.remove(&stream_id)
    };

    if let Some(tx) = tx {
        let _ = tx.send(ServerStreamCommand::Close).await;
    }
}

async fn close_all_server_streams(
    streams: &Arc<Mutex<HashMap<u32, mpsc::Sender<ServerStreamCommand>>>>,
) {
    let channels = {
        let mut active = streams.lock().await;
        active.drain().map(|(_, tx)| tx).collect::<Vec<_>>()
    };

    for tx in channels {
        let _ = tx.send(ServerStreamCommand::Close).await;
    }
}

async fn read_frame<R>(reader: &mut R, max_payload: usize) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut magic = [0_u8; FRAME_MAGIC.len()];
    reader.read_exact(&mut magic).await?;
    let mut skipped = 0_usize;
    while magic != FRAME_MAGIC {
        skipped += 1;
        magic[0] = magic[1];
        reader.read_exact(&mut magic[1..]).await?;
    }
    if skipped > 0 {
        info!(skipped, "mux frame reader resynchronized after skipping bytes");
    }

    let mut header = [0_u8; FRAME_HEADER_LEN - FRAME_MAGIC.len()];
    reader.read_exact(&mut header).await?;

    let kind = header[0];
    let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let payload_len =
        u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if payload_len > max_payload {
        bail!(
            "mux frame exceeded {} bytes (kind={} stream_id={} payload_len={} raw_magic={:02x?} raw={:02x?})",
            max_payload,
            kind,
            stream_id,
            payload_len,
            magic,
            header,
        );
    }

    let mut payload = vec![0_u8; payload_len];
    reader.read_exact(&mut payload).await?;

    Ok(Frame {
        kind,
        stream_id,
        payload,
    })
}

async fn write_frame<W>(writer: &mut W, frame: &Frame) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header = [0_u8; FRAME_HEADER_LEN];
    header[..FRAME_MAGIC.len()].copy_from_slice(&FRAME_MAGIC);
    header[FRAME_MAGIC.len()] = frame.kind;
    header[FRAME_MAGIC.len() + 1..FRAME_MAGIC.len() + 5]
        .copy_from_slice(&frame.stream_id.to_be_bytes());
    header[FRAME_MAGIC.len() + 5..FRAME_MAGIC.len() + 9]
        .copy_from_slice(&(frame.payload.len() as u32).to_be_bytes());
    let mut encoded = Vec::with_capacity(FRAME_HEADER_LEN + frame.payload.len());
    encoded.extend_from_slice(&header);
    encoded.extend_from_slice(&frame.payload);
    writer.write_all(&encoded).await?;
    writer.flush().await
}

fn is_private_literal_target(target: &str) -> bool {
    match host_from_target(target).and_then(|host| host.parse::<std::net::IpAddr>().ok()) {
        Some(std::net::IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast()
        }
        Some(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
        None => false,
    }
}

fn host_from_target(target: &str) -> Option<&str> {
    if let Some(rest) = target.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }

    target.rsplit_once(':').map(|(host, _)| host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn frame_round_trip() {
        let (mut left, mut right) = tokio::io::duplex(128);
        let frame = Frame::data(7, b"hello".to_vec());

        let writer = tokio::spawn(async move {
            write_frame(&mut left, &frame).await.unwrap();
        });

        let read = read_frame(&mut right, 64).await.unwrap();
        writer.await.unwrap();

        assert_eq!(read.kind, FRAME_DATA);
        assert_eq!(read.stream_id, 7);
        assert_eq!(read.payload, b"hello");
    }

    #[tokio::test]
    async fn read_frame_with_prefetched_prefix() {
        let frame = Frame::data(9, b"hello world".to_vec());
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &frame).await.unwrap();

        let prefix_len = 5;
        let prefix = encoded[..prefix_len].to_vec();
        let suffix = encoded[prefix_len..].to_vec();
        let mut reader = Cursor::new(prefix).chain(Cursor::new(suffix));

        let read = read_frame(&mut reader, 64).await.unwrap();
        assert_eq!(read.kind, FRAME_DATA);
        assert_eq!(read.stream_id, 9);
        assert_eq!(read.payload, b"hello world");
    }

    #[tokio::test]
    async fn read_frame_resynchronizes_after_garbage_prefix() {
        let frame = Frame::data(11, b"resync me".to_vec());
        let mut encoded = b"garbage-before-frame".to_vec();
        write_frame(&mut encoded, &frame).await.unwrap();

        let read = read_frame(&mut Cursor::new(encoded), 64).await.unwrap();
        assert_eq!(read.kind, FRAME_DATA);
        assert_eq!(read.stream_id, 11);
        assert_eq!(read.payload, b"resync me");
    }

    #[tokio::test]
    async fn read_frame_resynchronizes_between_frames() {
        let first = Frame::data(21, b"first".to_vec());
        let second = Frame::data(22, b"second".to_vec());
        let mut encoded = Vec::new();
        write_frame(&mut encoded, &first).await.unwrap();
        encoded.extend_from_slice(b"desync");
        write_frame(&mut encoded, &second).await.unwrap();

        let mut reader = Cursor::new(encoded);
        let read_first = read_frame(&mut reader, 64).await.unwrap();
        let read_second = read_frame(&mut reader, 64).await.unwrap();

        assert_eq!(read_first.stream_id, 21);
        assert_eq!(read_first.payload, b"first");
        assert_eq!(read_second.stream_id, 22);
        assert_eq!(read_second.payload, b"second");
    }
}
