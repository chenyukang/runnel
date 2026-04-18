use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context as AnyhowContext, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};
use tracing::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

const HISTORY_LEN: usize = 48;
const RECENT_EVENTS: usize = 40;
const RECENT_TARGETS: usize = RECENT_EVENTS;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TraceEvent {
    pub at: SystemTime,
    pub level: String,
    pub message: String,
    pub fields: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MonitorContext {
    pub command_label: String,
    pub mode_label: String,
    pub listen: Option<String>,
    pub upstream: Option<String>,
    pub path: Option<String>,
    pub log_file: PathBuf,
    pub log_filter: String,
    pub pid: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DashboardSnapshot {
    pub context: MonitorContext,
    pub uptime_secs: u64,
    pub total_relays: u64,
    pub total_errors: u64,
    pub total_warnings: u64,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub upload_history: Vec<u64>,
    pub download_history: Vec<u64>,
    pub recent_targets: Vec<RecentTargetSnapshot>,
    pub recent_events: Vec<String>,
    pub last_event_age_ms: Option<u64>,
    pub last_warning_age_ms: Option<u64>,
    pub last_traffic_age_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentTargetSnapshot {
    pub seen_at: String,
    pub target: String,
    pub route: String,
    pub link: String,
    #[serde(default)]
    pub detail: String,
    pub uploaded: u64,
    pub downloaded: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum WireMessage {
    Snapshot(DashboardSnapshot),
    Event(TraceEvent),
}

static TELEMETRY: OnceLock<TelemetryHub> = OnceLock::new();

struct TelemetryHub {
    sender: broadcast::Sender<TraceEvent>,
    snapshot: Arc<Mutex<SnapshotState>>,
}

struct SnapshotState {
    context: Option<MonitorContext>,
    started_at: Instant,
    total_relays: u64,
    total_errors: u64,
    total_warnings: u64,
    total_uploaded: u64,
    total_downloaded: u64,
    upload_history: Vec<u64>,
    download_history: Vec<u64>,
    last_bucket_at: Instant,
    last_event_at: Option<Instant>,
    last_warning_at: Option<Instant>,
    last_traffic_at: Option<Instant>,
    recent_targets: VecDeque<RecentTargetSnapshot>,
    recent_events: VecDeque<String>,
}

impl Default for SnapshotState {
    fn default() -> Self {
        Self {
            context: None,
            started_at: Instant::now(),
            total_relays: 0,
            total_errors: 0,
            total_warnings: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            upload_history: vec![0; HISTORY_LEN],
            download_history: vec![0; HISTORY_LEN],
            last_bucket_at: Instant::now(),
            last_event_at: None,
            last_warning_at: None,
            last_traffic_at: None,
            recent_targets: VecDeque::with_capacity(RECENT_TARGETS),
            recent_events: VecDeque::with_capacity(RECENT_EVENTS),
        }
    }
}

impl SnapshotState {
    fn set_context(&mut self, context: MonitorContext) {
        self.context = Some(context);
    }

    fn ingest(&mut self, event: &TraceEvent) {
        self.rotate_history();
        self.last_event_at = Some(Instant::now());

        let impacts_health = event_impacts_health(
            self.context.as_ref().map(|ctx| ctx.command_label.as_str()),
            event,
        );
        if event.level == "WARN" {
            self.total_warnings += 1;
        }
        if event.level == "ERROR" || event.message.contains("with error") {
            self.total_errors += 1;
        }
        if impacts_health {
            self.last_warning_at = Some(Instant::now());
        }

        self.capture_recent_event(event);
        self.capture_recent_domain_ip(event);

        if event.message == "dns query" {
            self.capture_recent_domain(event);
            return;
        }

        if event.message == "traffic sample" {
            self.last_traffic_at = Some(Instant::now());
            let uploaded = parse_u64(event.fields.get("uploaded"));
            let downloaded = parse_u64(event.fields.get("downloaded"));
            if traffic_sample_is_aggregate(event) {
                self.total_uploaded += uploaded;
                self.total_downloaded += downloaded;
            }
            if let Some(last) = self.upload_history.last_mut() {
                *last += uploaded;
            }
            if let Some(last) = self.download_history.last_mut() {
                *last += downloaded;
            }
            return;
        }

        if event.message.contains("relay completed") {
            self.total_relays += 1;
            let uploaded = parse_u64(event.fields.get("uploaded"));
            let downloaded = parse_u64(event.fields.get("downloaded"));
            self.total_uploaded += uploaded;
            self.total_downloaded += downloaded;
            if uploaded > 0 || downloaded > 0 {
                self.last_traffic_at = Some(Instant::now());
            }

            let sampled = parse_bool(event.fields.get("sampled"));
            if !sampled {
                if let Some(last) = self.upload_history.last_mut() {
                    *last += uploaded;
                }
                if let Some(last) = self.download_history.last_mut() {
                    *last += downloaded;
                }
            }

            let target = event
                .fields
                .get("target")
                .cloned()
                .unwrap_or_else(|| "-".to_owned());
            let route = event
                .fields
                .get("route")
                .cloned()
                .unwrap_or_else(|| "remote".to_owned());

            self.recent_targets.push_front(RecentTargetSnapshot {
                seen_at: clock_stamp(event.at),
                link: link_from_target(&target),
                target,
                route,
                detail: String::new(),
                uploaded,
                downloaded,
            });
            self.recent_targets.truncate(RECENT_TARGETS);
        }
    }

    fn capture_recent_domain(&mut self, event: &TraceEvent) {
        let target = event
            .fields
            .get("target")
            .cloned()
            .unwrap_or_else(|| "-".to_owned());
        let link = event
            .fields
            .get("link")
            .cloned()
            .unwrap_or_else(|| link_from_target(&target));
        let route = event
            .fields
            .get("route")
            .cloned()
            .unwrap_or_else(|| "remote".to_owned());
        let detail = event
            .fields
            .get("detail")
            .cloned()
            .unwrap_or_else(|| recent_domain_default_detail(&route));

        self.recent_targets.push_front(RecentTargetSnapshot {
            seen_at: clock_stamp(event.at),
            link,
            target,
            route,
            detail,
            uploaded: 0,
            downloaded: 0,
        });
        self.recent_targets.truncate(RECENT_TARGETS);
    }

    fn capture_recent_domain_ip(&mut self, event: &TraceEvent) {
        let (Some(domain), Some(ip)) = (event.fields.get("domain"), event.fields.get("ip")) else {
            return;
        };

        let dns_link = format!("dns://{domain}");
        if let Some(target) = self
            .recent_targets
            .iter_mut()
            .find(|target| target.link == dns_link || target.target == domain.as_str())
        {
            append_recent_domain_ip(&mut target.detail, ip);
        }
    }

    fn snapshot(&self) -> Option<DashboardSnapshot> {
        let context = self.context.clone()?;
        Some(DashboardSnapshot {
            context,
            uptime_secs: self.started_at.elapsed().as_secs(),
            total_relays: self.total_relays,
            total_errors: self.total_errors,
            total_warnings: self.total_warnings,
            total_uploaded: self.total_uploaded,
            total_downloaded: self.total_downloaded,
            upload_history: self.upload_history.clone(),
            download_history: self.download_history.clone(),
            recent_targets: self.recent_targets.iter().cloned().collect(),
            recent_events: self.recent_events.iter().cloned().collect(),
            last_event_age_ms: self.last_event_at.map(age_millis),
            last_warning_age_ms: self.last_warning_at.map(age_millis),
            last_traffic_age_ms: self.last_traffic_at.map(age_millis),
        })
    }

    fn rotate_history(&mut self) {
        while self.last_bucket_at.elapsed() >= Duration::from_secs(1) {
            rotate_history(&mut self.upload_history);
            rotate_history(&mut self.download_history);
            self.last_bucket_at += Duration::from_secs(1);
        }
    }

    fn capture_recent_event(&mut self, event: &TraceEvent) {
        if event.message == "traffic sample" || event.message == "dns query" {
            return;
        }
        if event.message.contains("relay completed") && self.recent_events.len() >= RECENT_EVENTS {
            return;
        }

        let suffix = recent_event_suffix(event);

        self.recent_events.push_front(format!(
            "{} [{}] {}{}",
            clock_stamp(event.at),
            event.level,
            event.message,
            suffix
        ));
        self.recent_events.truncate(RECENT_EVENTS);
    }
}

fn recent_event_suffix(event: &TraceEvent) -> String {
    if let Some(target) = event.fields.get("target") {
        return format!(" {target}");
    }
    if let Some(error) = event.fields.get("error") {
        return format!(" {error}");
    }
    if let Some(listen) = event.fields.get("listen") {
        return format!(" {listen}");
    }
    match (event.fields.get("domain"), event.fields.get("ip")) {
        (Some(domain), Some(ip)) => format!(" {domain} -> {ip}"),
        (Some(domain), None) => format!(" {domain}"),
        (None, Some(ip)) => format!(" {ip}"),
        (None, None) => String::new(),
    }
}

fn recent_domain_default_detail(route: &str) -> String {
    match route {
        "wg-dns-direct" | "direct" => "pending".to_owned(),
        "wg-dns-block" | "block" => "blocked".to_owned(),
        "wg-dns" | "wg-dns-remote" | "remote" => "wg tunnel".to_owned(),
        _ => "-".to_owned(),
    }
}

fn append_recent_domain_ip(detail: &mut String, ip: &str) {
    if matches!(
        detail.as_str(),
        "" | "-" | "pending" | "blocked" | "wg tunnel"
    ) {
        *detail = ip.to_owned();
        return;
    }

    if detail
        .split(", ")
        .any(|known| known == ip || known == "...")
    {
        return;
    }
    if detail.split(", ").count() >= 3 {
        detail.push_str(", ...");
        return;
    }
    detail.push_str(", ");
    detail.push_str(ip);
}

pub fn init_channel(capacity: usize) {
    let _ = TELEMETRY.set(TelemetryHub {
        sender: broadcast::channel(capacity).0,
        snapshot: Arc::new(Mutex::new(SnapshotState::default())),
    });
}

pub fn set_context(context: MonitorContext) {
    let Some(hub) = TELEMETRY.get() else {
        return;
    };
    if let Ok(mut snapshot) = hub.snapshot.lock() {
        snapshot.set_context(context);
    }
}

pub fn subscribe() -> Option<broadcast::Receiver<TraceEvent>> {
    TELEMETRY.get().map(|hub| hub.sender.subscribe())
}

pub fn has_live_subscribers() -> bool {
    TELEMETRY
        .get()
        .is_some_and(|hub| hub.sender.receiver_count() > 0)
}

pub fn emit(
    level: impl Into<String>,
    message: impl Into<String>,
    fields: BTreeMap<String, String>,
) {
    let Some(hub) = TELEMETRY.get() else {
        return;
    };

    let traced = TraceEvent {
        at: SystemTime::now(),
        level: level.into(),
        message: message.into(),
        fields,
    };
    record_snapshot(hub, &traced);
    let _ = hub.sender.send(traced);
}

pub fn layer() -> TelemetryLayer {
    TelemetryLayer
}

pub struct TelemetryLayer;

impl<S> Layer<S> for TelemetryLayer
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let Some(hub) = TELEMETRY.get() else {
            return;
        };

        let mut visitor = EventVisitor::default();
        event.record(&mut visitor);

        let mut fields = visitor.fields;
        let message = fields
            .remove("message")
            .unwrap_or_else(|| event.metadata().name().to_owned());

        let traced = TraceEvent {
            at: SystemTime::now(),
            level: event.metadata().level().as_str().to_owned(),
            message,
            fields,
        };

        record_snapshot(hub, &traced);
        let _ = hub.sender.send(traced);
    }
}

#[cfg(unix)]
pub async fn start_socket_server(path: PathBuf) -> Result<()> {
    use tokio::net::UnixListener;

    let hub = TELEMETRY
        .get()
        .context("telemetry channel is not initialized")?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if tokio::fs::metadata(&path).await.is_ok() {
        let _ = tokio::fs::remove_file(&path).await;
    }
    let listener = UnixListener::bind(&path)
        .with_context(|| format!("failed to bind telemetry socket {}", path.display()))?;
    prepare_attachable_socket(&path)?;
    let sender = hub.sender.clone();
    let snapshot = hub.snapshot.clone();

    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let sender = sender.clone();
            let snapshot = snapshot.clone();
            tokio::spawn(async move {
                let _ = handle_subscriber(stream, sender, snapshot).await;
            });
        }
    });

    Ok(())
}

#[cfg(unix)]
fn prepare_attachable_socket(path: &Path) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(());
    }

    if let (Some(uid), Some(gid)) = (sudo_uid(), sudo_gid())
        && chown_socket_to_user(path, uid, gid).is_ok()
    {
        return set_socket_mode(path, 0o660);
    }

    // Root-launched daemons should still be inspectable from the invoking user.
    set_socket_mode(path, 0o666)
}

#[cfg(unix)]
fn sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
}

#[cfg(unix)]
fn sudo_gid() -> Option<u32> {
    std::env::var("SUDO_GID")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
}

#[cfg(unix)]
fn chown_socket_to_user(path: &Path, uid: u32, gid: u32) -> std::io::Result<()> {
    use std::{ffi::CString, os::unix::ffi::OsStrExt};

    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid socket path")
    })?;
    let rc = unsafe { libc::chown(path.as_ptr(), uid, gid) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn set_socket_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).with_context(|| {
        format!(
            "failed to update telemetry socket permissions {}",
            path.display()
        )
    })
}

#[cfg(not(unix))]
pub async fn start_socket_server(_path: PathBuf) -> Result<()> {
    anyhow::bail!("telemetry attach is only supported on Unix platforms")
}

#[cfg(unix)]
pub async fn attach_socket(
    path: &Path,
) -> Result<(DashboardSnapshot, mpsc::UnboundedReceiver<TraceEvent>)> {
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        net::UnixStream,
    };

    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("failed to connect telemetry socket {}", path.display()))?;
    let mut lines = BufReader::new(stream).lines();
    let first = lines
        .next_line()
        .await
        .context("failed to read telemetry snapshot")?
        .context("telemetry socket closed before snapshot")?;
    let snapshot = match serde_json::from_str::<WireMessage>(&first)
        .context("failed to parse telemetry snapshot")?
    {
        WireMessage::Snapshot(snapshot) => snapshot,
        WireMessage::Event(_) => anyhow::bail!("telemetry stream did not start with a snapshot"),
    };

    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok(Some(line)) = lines.next_line().await else {
                break;
            };
            let Ok(message) = serde_json::from_str::<WireMessage>(&line) else {
                continue;
            };
            if let WireMessage::Event(event) = message {
                if tx.send(event).is_err() {
                    break;
                }
            }
        }
    });

    Ok((snapshot, rx))
}

#[cfg(not(unix))]
pub async fn attach_socket(
    _path: &Path,
) -> Result<(DashboardSnapshot, mpsc::UnboundedReceiver<TraceEvent>)> {
    anyhow::bail!("telemetry attach is only supported on Unix platforms")
}

#[derive(Default)]
struct EventVisitor {
    fields: BTreeMap<String, String>,
}

impl tracing::field::Visit for EventVisitor {
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields
            .insert(field.name().to_owned(), value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.fields
            .insert(field.name().to_owned(), format!("{value:?}"));
    }
}

fn record_snapshot(hub: &TelemetryHub, traced: &TraceEvent) {
    if let Ok(mut snapshot) = hub.snapshot.lock() {
        snapshot.ingest(traced);
    }
}

fn age_millis(instant: Instant) -> u64 {
    instant.elapsed().as_millis() as u64
}

fn rotate_history(history: &mut Vec<u64>) {
    history.rotate_left(1);
    if let Some(last) = history.last_mut() {
        *last = 0;
    }
}

fn parse_u64(value: Option<&String>) -> u64 {
    value
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

fn parse_bool(value: Option<&String>) -> bool {
    value
        .map(|value| matches!(value.as_str(), "true" | "1" | "yes"))
        .unwrap_or(false)
}

fn traffic_sample_is_aggregate(event: &TraceEvent) -> bool {
    parse_bool(event.fields.get("aggregate"))
        || event.fields.get("mode").is_some_and(|mode| mode == "wg")
}

pub(crate) fn event_impacts_health(command_label: Option<&str>, event: &TraceEvent) -> bool {
    if event.level != "WARN" && event.level != "ERROR" && !event.message.contains("with error") {
        return false;
    }

    !is_known_recoverable_tun_dns_failure(command_label, event)
}

fn is_known_recoverable_tun_dns_failure(command_label: Option<&str>, event: &TraceEvent) -> bool {
    if command_label != Some("tun") {
        return false;
    }

    if event.message == "client session ended with error"
        && event
            .fields
            .get("error")
            .is_some_and(|error| error == "server response timed out")
        && event
            .fields
            .get("peer")
            .is_some_and(|peer| is_loopback_peer(peer))
    {
        return true;
    }

    let general_failure = "SOCKS connection failed: Reply::GeneralFailure";
    let tunneled_dns_target = "198.18.0.1:53";
    event.level == "ERROR"
        && ((event.message.contains(tunneled_dns_target)
            && event.message.contains(general_failure))
            || event
                .fields
                .get("target")
                .is_some_and(|target| target == tunneled_dns_target)
                && event
                    .fields
                    .get("error")
                    .is_some_and(|error| error.contains(general_failure)))
}

fn is_loopback_peer(peer: &str) -> bool {
    peer.parse::<SocketAddr>()
        .map(|addr| addr.ip().is_loopback())
        .unwrap_or_else(|_| {
            peer.parse::<IpAddr>()
                .map(|ip| ip.is_loopback())
                .unwrap_or(false)
        })
}

fn clock_stamp(at: SystemTime) -> String {
    let elapsed = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let seconds = elapsed % 60;
    let minutes = (elapsed / 60) % 60;
    let hours = (elapsed / 3600) % 24;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

fn link_from_target(target: &str) -> String {
    let (host, port) = split_target(target);
    match port {
        Some(80) => format!("http://{host}"),
        Some(443) => format!("https://{host}"),
        Some(port) => format!("tcp://{host}:{port}"),
        None => format!("tcp://{target}"),
    }
}

fn split_target(target: &str) -> (String, Option<u16>) {
    if let Some(rest) = target.strip_prefix('[')
        && let Some((host, suffix)) = rest.split_once(']')
    {
        let port = suffix.strip_prefix(':').and_then(|port| port.parse().ok());
        return (host.to_owned(), port);
    }

    if let Some((host, port)) = target.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_owned(), Some(port));
    }

    (target.to_owned(), None)
}

#[cfg(unix)]
async fn handle_subscriber(
    mut stream: tokio::net::UnixStream,
    sender: broadcast::Sender<TraceEvent>,
    snapshot: Arc<Mutex<SnapshotState>>,
) -> Result<()> {
    if let Some(snapshot) = current_snapshot(&snapshot) {
        write_wire_message(&mut stream, &WireMessage::Snapshot(snapshot)).await?;
    } else {
        anyhow::bail!("telemetry context is not ready yet");
    }

    let mut receiver = sender.subscribe();
    loop {
        match receiver.recv().await {
            Ok(event) => {
                if write_wire_message(&mut stream, &WireMessage::Event(event))
                    .await
                    .is_err()
                {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn write_wire_message(
    stream: &mut tokio::net::UnixStream,
    message: &WireMessage,
) -> Result<()> {
    use tokio::io::AsyncWriteExt;

    let mut encoded = serde_json::to_vec(message).context("failed to encode telemetry message")?;
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .context("failed to write telemetry message")?;
    Ok(())
}

fn current_snapshot(snapshot: &Arc<Mutex<SnapshotState>>) -> Option<DashboardSnapshot> {
    snapshot.lock().ok()?.snapshot()
}

#[cfg(test)]
mod tests {
    use super::{
        MonitorContext, SnapshotState, TraceEvent, event_impacts_health, is_loopback_peer,
    };
    use std::{collections::BTreeMap, path::PathBuf, time::SystemTime};

    #[test]
    fn tun_dns_timeout_does_not_impact_health() {
        let event = trace_event(
            "WARN",
            "client session ended with error",
            &[
                ("peer", "127.0.0.1:53000"),
                ("error", "server response timed out"),
            ],
        );
        assert!(!event_impacts_health(Some("tun"), &event));
    }

    #[test]
    fn same_timeout_still_impacts_client_health() {
        let event = trace_event(
            "WARN",
            "client session ended with error",
            &[
                ("peer", "127.0.0.1:53000"),
                ("error", "server response timed out"),
            ],
        );
        assert!(event_impacts_health(Some("client"), &event));
    }

    #[test]
    fn unrelated_tun_errors_still_impact_health() {
        let event = trace_event(
            "WARN",
            "client session ended with error",
            &[
                ("peer", "127.0.0.1:53000"),
                ("error", "TLS handshake with server timed out"),
            ],
        );
        assert!(event_impacts_health(Some("tun"), &event));
    }

    #[test]
    fn tun_dns_general_failure_does_not_impact_health() {
        let event = trace_event(
            "ERROR",
            "#3080 TCP 198.18.0.1:52190 -> 198.18.0.1:53 error \"SOCKS connection failed: Reply::GeneralFailure\"",
            &[],
        );
        assert!(!event_impacts_health(Some("tun"), &event));
    }

    #[test]
    fn suppressed_tun_dns_timeout_keeps_snapshot_ready() {
        let mut snapshot = SnapshotState::default();
        snapshot.set_context(MonitorContext {
            command_label: "tun".to_owned(),
            mode_label: "native-http".to_owned(),
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("proxy.log"),
            log_filter: "info".to_owned(),
            pid: 1,
        });
        let event = trace_event(
            "WARN",
            "client session ended with error",
            &[
                ("peer", "127.0.0.1:53000"),
                ("error", "server response timed out"),
            ],
        );

        snapshot.ingest(&event);

        assert_eq!(snapshot.total_warnings, 1);
        assert!(snapshot.last_warning_at.is_none());
    }

    #[test]
    fn traffic_sample_updates_snapshot_history_without_totals_by_default() {
        let mut snapshot = SnapshotState::default();
        let event = trace_event(
            "INFO",
            "traffic sample",
            &[("uploaded", "12"), ("downloaded", "34")],
        );

        snapshot.ingest(&event);

        assert_eq!(snapshot.total_uploaded, 0);
        assert_eq!(snapshot.total_downloaded, 0);
        assert_eq!(snapshot.total_relays, 0);
        assert_eq!(snapshot.upload_history.last().copied(), Some(12));
        assert_eq!(snapshot.download_history.last().copied(), Some(34));
        assert!(snapshot.last_traffic_at.is_some());
    }

    #[test]
    fn wg_traffic_sample_updates_snapshot_totals_without_recent_target() {
        let mut snapshot = SnapshotState::default();
        let event = trace_event(
            "INFO",
            "traffic sample",
            &[
                ("uploaded", "12"),
                ("downloaded", "34"),
                ("mode", "wg"),
                ("target", "wireguard"),
                ("link", "wg://wireguard"),
                ("route", "wg-client"),
            ],
        );

        snapshot.ingest(&event);

        assert_eq!(snapshot.total_uploaded, 12);
        assert_eq!(snapshot.total_downloaded, 34);
        assert_eq!(snapshot.total_relays, 0);
        assert!(snapshot.recent_targets.is_empty());
    }

    #[test]
    fn traffic_sample_does_not_fill_recent_events_or_targets() {
        let mut snapshot = SnapshotState::default();
        let event = trace_event(
            "INFO",
            "traffic sample",
            &[
                ("uploaded", "12"),
                ("downloaded", "34"),
                ("mode", "wg"),
                ("target", "wireguard"),
            ],
        );

        snapshot.ingest(&event);

        assert!(snapshot.recent_events.is_empty());
        assert!(snapshot.recent_targets.is_empty());
    }

    #[test]
    fn dns_query_updates_recent_domain_without_recent_event_spam() {
        let mut snapshot = SnapshotState::default();
        let event = trace_event(
            "INFO",
            "dns query",
            &[
                ("target", "example.com"),
                ("link", "dns://example.com"),
                ("route", "wg-dns"),
            ],
        );

        snapshot.ingest(&event);

        assert!(snapshot.recent_events.is_empty());
        assert_eq!(snapshot.recent_targets.len(), 1);
        assert_eq!(snapshot.recent_targets[0].target, "example.com");
        assert_eq!(snapshot.recent_targets[0].link, "dns://example.com");
        assert_eq!(snapshot.recent_targets[0].route, "wg-dns");
        assert_eq!(snapshot.recent_targets[0].detail, "wg tunnel");
    }

    #[test]
    fn recent_event_shows_domain_and_ip_fields() {
        let mut snapshot = SnapshotState::default();
        let event = trace_event(
            "INFO",
            "running wg hook",
            &[("domain", "baidu.com"), ("ip", "110.242.74.102")],
        );

        snapshot.ingest(&event);

        assert_eq!(snapshot.recent_events.len(), 1);
        assert!(
            snapshot.recent_events[0].contains("baidu.com -> 110.242.74.102"),
            "{}",
            snapshot.recent_events[0]
        );
    }

    #[test]
    fn wg_hook_updates_recent_domain_resolved_ips() {
        let mut snapshot = SnapshotState::default();
        snapshot.ingest(&trace_event(
            "INFO",
            "dns query",
            &[
                ("target", "baidu.com"),
                ("link", "dns://baidu.com"),
                ("route", "wg-dns-direct"),
            ],
        ));
        snapshot.ingest(&trace_event(
            "INFO",
            "running wg hook",
            &[("domain", "baidu.com"), ("ip", "110.242.74.102")],
        ));

        assert_eq!(snapshot.recent_targets.len(), 1);
        assert_eq!(snapshot.recent_targets[0].detail, "110.242.74.102");
    }

    #[test]
    fn loopback_peer_detection_handles_ipv4_and_ipv6() {
        assert!(is_loopback_peer("127.0.0.1:53000"));
        assert!(is_loopback_peer("[::1]:53000"));
        assert!(!is_loopback_peer("192.168.1.2:53000"));
    }

    fn trace_event(level: &str, message: &str, fields: &[(&str, &str)]) -> TraceEvent {
        TraceEvent {
            at: SystemTime::UNIX_EPOCH,
            level: level.to_owned(),
            message: message.to_owned(),
            fields: fields
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<BTreeMap<_, _>>(),
        }
    }
}
