use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime},
};

use anyhow::{Context as AnyhowContext, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc, oneshot};
use tracing::{Event, Subscriber};
use tracing_subscriber::{Layer, layer::Context, registry::LookupSpan};

const HISTORY_LEN: usize = 48;
const RECENT_EVENTS: usize = 40;
const RECENT_TARGETS: usize = RECENT_EVENTS;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

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
    #[serde(default)]
    pub traffic_state: TrafficState,
    pub listen: Option<String>,
    pub upstream: Option<String>,
    pub path: Option<String>,
    pub log_file: PathBuf,
    pub log_filter: String,
    #[serde(default)]
    pub log_timezone_offset_secs: i32,
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
    #[serde(default)]
    pub route_stats: RouteStats,
    #[serde(default)]
    pub tunnel_health: TunnelHealth,
    pub upload_history: Vec<u64>,
    pub download_history: Vec<u64>,
    pub recent_targets: Vec<RecentTargetSnapshot>,
    pub recent_events: Vec<String>,
    pub last_event_age_ms: Option<u64>,
    pub last_warning_age_ms: Option<u64>,
    pub last_traffic_age_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
pub struct RouteStats {
    pub proxy: u64,
    pub direct: u64,
    pub blocked: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteBucket {
    Proxy,
    Direct,
    Blocked,
}

impl RouteStats {
    pub fn record(&mut self, bucket: RouteBucket) {
        match bucket {
            RouteBucket::Proxy => self.proxy += 1,
            RouteBucket::Direct => self.direct += 1,
            RouteBucket::Blocked => self.blocked += 1,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub struct TunnelHealth {
    pub state: TunnelState,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub dns: TunnelCheckState,
    #[serde(default)]
    pub connectivity: TunnelCheckState,
    pub handshake_age_secs: Option<u64>,
}

impl Default for TunnelHealth {
    fn default() -> Self {
        Self {
            state: TunnelState::Unknown,
            detail: String::new(),
            dns: TunnelCheckState::Unknown,
            connectivity: TunnelCheckState::Unknown,
            handshake_age_secs: None,
        }
    }
}

impl TunnelHealth {
    pub fn stage(state: TunnelState, detail: impl Into<String>) -> Self {
        Self {
            state,
            detail: detail.into(),
            ..Self::default()
        }
    }

    pub fn as_fields(&self) -> BTreeMap<String, String> {
        let mut fields = BTreeMap::new();
        fields.insert("state".to_owned(), self.state.as_str().to_owned());
        if !self.detail.is_empty() {
            fields.insert("detail".to_owned(), self.detail.clone());
        }
        fields.insert("dns".to_owned(), self.dns.as_str().to_owned());
        fields.insert(
            "connectivity".to_owned(),
            self.connectivity.as_str().to_owned(),
        );
        if let Some(age) = self.handshake_age_secs {
            fields.insert("handshake_age_secs".to_owned(), age.to_string());
        }
        fields
    }

    fn from_event(event: &TraceEvent) -> Option<Self> {
        if event.message != "tunnel health" {
            return None;
        }
        let state = event
            .fields
            .get("state")
            .and_then(|state| TunnelState::from_str(state))?;
        let detail = event.fields.get("detail").cloned().unwrap_or_default();
        let dns = event
            .fields
            .get("dns")
            .and_then(|state| TunnelCheckState::from_str(state))
            .unwrap_or_default();
        let connectivity = event
            .fields
            .get("connectivity")
            .and_then(|state| TunnelCheckState::from_str(state))
            .unwrap_or_default();
        let handshake_age_secs = event
            .fields
            .get("handshake_age_secs")
            .and_then(|age| age.parse::<u64>().ok());

        Some(Self {
            state,
            detail,
            dns,
            connectivity,
            handshake_age_secs,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelState {
    #[default]
    Unknown,
    Starting,
    InterfaceUp,
    RoutesApplied,
    DnsApplied,
    ConnectivityOk,
    Active,
    Bypass,
    Degraded,
    Stopping,
}

impl TunnelState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Starting => "starting",
            Self::InterfaceUp => "interface-up",
            Self::RoutesApplied => "routes-applied",
            Self::DnsApplied => "dns-applied",
            Self::ConnectivityOk => "connectivity-ok",
            Self::Active => "active",
            Self::Bypass => "bypass",
            Self::Degraded => "degraded",
            Self::Stopping => "stopping",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "starting" => Some(Self::Starting),
            "interface-up" => Some(Self::InterfaceUp),
            "routes-applied" => Some(Self::RoutesApplied),
            "dns-applied" => Some(Self::DnsApplied),
            "connectivity-ok" => Some(Self::ConnectivityOk),
            "active" => Some(Self::Active),
            "bypass" => Some(Self::Bypass),
            "degraded" => Some(Self::Degraded),
            "stopping" => Some(Self::Stopping),
            _ => None,
        }
    }
}

impl fmt::Display for TunnelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TunnelCheckState {
    #[default]
    Unknown,
    Disabled,
    Ok,
    Warn,
    Error,
}

impl TunnelCheckState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Disabled => "disabled",
            Self::Ok => "ok",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "unknown" => Some(Self::Unknown),
            "disabled" => Some(Self::Disabled),
            "ok" => Some(Self::Ok),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentTargetSnapshot {
    pub seen_at: String,
    pub target: String,
    pub route: String,
    pub link: String,
    #[serde(default)]
    pub detail: String,
    #[serde(default)]
    pub repeat_count: u64,
    pub uploaded: u64,
    pub downloaded: u64,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TrafficState {
    #[default]
    Proxying,
    Bypass,
}

impl TrafficState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proxying => "proxying",
            Self::Bypass => "bypass",
        }
    }
}

impl fmt::Display for TrafficState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TrafficSwitchTarget {
    Toggle,
    Proxying,
    Bypass,
}

impl TrafficSwitchTarget {
    pub fn resolve(self, current: TrafficState) -> TrafficState {
        match self {
            Self::Toggle => match current {
                TrafficState::Proxying => TrafficState::Bypass,
                TrafficState::Bypass => TrafficState::Proxying,
            },
            Self::Proxying => TrafficState::Proxying,
            Self::Bypass => TrafficState::Bypass,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlRequest {
    pub command: ControlCommand,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum ControlCommand {
    Switch { target: TrafficSwitchTarget },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(default)]
    pub previous_state: Option<TrafficState>,
    pub state: Option<TrafficState>,
    pub message: String,
}

impl ControlResponse {
    pub fn ok(previous_state: TrafficState, state: TrafficState) -> Self {
        Self {
            ok: true,
            previous_state: Some(previous_state),
            state: Some(state),
            message: format!(
                "traffic state switched {} -> {}",
                previous_state.as_str(),
                state.as_str()
            ),
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            ok: false,
            previous_state: None,
            state: None,
            message: message.into(),
        }
    }
}

pub struct ControlEnvelope {
    pub request: ControlRequest,
    response: oneshot::Sender<ControlResponse>,
}

impl ControlEnvelope {
    pub fn respond(self, response: ControlResponse) {
        let _ = self.response.send(response);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
enum WireMessage {
    Snapshot(DashboardSnapshot),
    Event(TraceEvent),
    Control(ControlRequest),
    ControlResponse(ControlResponse),
}

static TELEMETRY: OnceLock<TelemetryHub> = OnceLock::new();
static CONTROL: OnceLock<Mutex<Option<mpsc::Sender<ControlEnvelope>>>> = OnceLock::new();

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
    route_stats: RouteStats,
    tunnel_health: TunnelHealth,
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
            route_stats: RouteStats::default(),
            tunnel_health: TunnelHealth::default(),
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

    fn set_traffic_state(&mut self, state: TrafficState) {
        if let Some(context) = &mut self.context {
            context.traffic_state = state;
        }
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
        if let Some(health) = TunnelHealth::from_event(event) {
            self.tunnel_health = health;
        }
        if let Some(bucket) = route_bucket_for_event(event) {
            self.route_stats.record(bucket);
        }

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
                seen_at: clock_stamp(event.at, self.log_timezone_offset_secs()),
                link: link_from_target(&target),
                target,
                route,
                detail: String::new(),
                repeat_count: 1,
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
        let seen_at = clock_stamp(event.at, self.log_timezone_offset_secs());

        if let Some(index) = self
            .recent_targets
            .iter()
            .position(|recent| recent.link == link && recent.route == route)
        {
            if let Some(mut recent) = self.recent_targets.remove(index) {
                recent.seen_at = seen_at;
                recent.detail = merge_recent_domain_detail(&recent.detail, &detail, &route);
                recent.repeat_count = recent.repeat_count.saturating_add(1).max(2);
                self.recent_targets.push_front(recent);
            }
            return;
        }

        self.recent_targets.push_front(RecentTargetSnapshot {
            seen_at,
            link,
            target,
            route,
            detail,
            repeat_count: 1,
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
            route_stats: self.route_stats,
            tunnel_health: self.tunnel_health.clone(),
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
        if event.message == "traffic sample"
            || event.message == "dns query"
            || (event.message == "tunnel health" && event.level != "WARN")
        {
            return;
        }
        if event.message.contains("relay completed") && self.recent_events.len() >= RECENT_EVENTS {
            return;
        }

        let suffix = recent_event_suffix(event);

        self.recent_events.push_front(format!(
            "{} [{}] {}{}",
            clock_stamp(event.at, self.log_timezone_offset_secs()),
            event.level,
            event.message,
            suffix
        ));
        self.recent_events.truncate(RECENT_EVENTS);
    }

    fn log_timezone_offset_secs(&self) -> i32 {
        self.context
            .as_ref()
            .map(|context| context.log_timezone_offset_secs)
            .unwrap_or_default()
    }
}

pub fn route_bucket_for_event(event: &TraceEvent) -> Option<RouteBucket> {
    if event.message == "dns query" {
        return route_bucket_from_label(
            event
                .fields
                .get("route")
                .map(String::as_str)
                .unwrap_or("remote"),
        );
    }
    if event.message.contains("relay completed") {
        return route_bucket_from_label(
            event
                .fields
                .get("route")
                .map(String::as_str)
                .unwrap_or("remote"),
        );
    }
    if event.message == "route decision" {
        return event
            .fields
            .get("route")
            .and_then(|route| route_bucket_from_label(route));
    }
    None
}

fn route_bucket_from_label(route: &str) -> Option<RouteBucket> {
    match route {
        "direct" | "wg-dns-direct" => Some(RouteBucket::Direct),
        "block" | "blocked" | "wg-dns-block" => Some(RouteBucket::Blocked),
        "remote" | "proxy" | "wg-dns" | "wg-dns-remote" => Some(RouteBucket::Proxy),
        _ => None,
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

fn merge_recent_domain_detail(current: &str, next: &str, route: &str) -> String {
    if current.is_empty() || current == "-" || current == recent_domain_default_detail(route) {
        return next.to_owned();
    }
    current.to_owned()
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

pub fn set_traffic_state(state: TrafficState) {
    let Some(hub) = TELEMETRY.get() else {
        return;
    };
    if let Ok(mut snapshot) = hub.snapshot.lock() {
        snapshot.set_traffic_state(state);
    }
}

pub fn set_tunnel_health(health: TunnelHealth) {
    let level = if health.state == TunnelState::Degraded {
        "WARN"
    } else {
        "INFO"
    };
    emit(level, "tunnel health", health.as_fields());
}

pub fn init_control_channel() -> mpsc::Receiver<ControlEnvelope> {
    let (sender, receiver) = mpsc::channel(8);
    let slot = CONTROL.get_or_init(|| Mutex::new(None));
    if let Ok(mut slot) = slot.lock() {
        *slot = Some(sender);
    }
    receiver
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
        WireMessage::Control(_) | WireMessage::ControlResponse(_) => {
            anyhow::bail!("telemetry stream did not start with a snapshot")
        }
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

#[cfg(unix)]
pub async fn switch_socket(path: &Path, target: TrafficSwitchTarget) -> Result<ControlResponse> {
    use tokio::{
        io::{AsyncBufReadExt, BufReader},
        net::UnixStream,
    };

    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("failed to connect telemetry socket {}", path.display()))?;
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let first = lines
        .next_line()
        .await
        .context("failed to read telemetry snapshot")?
        .context("telemetry socket closed before snapshot")?;
    let previous_state = match serde_json::from_str::<WireMessage>(&first)
        .context("failed to parse telemetry snapshot")?
    {
        WireMessage::Snapshot(snapshot) => snapshot.context.traffic_state,
        WireMessage::Event(_) | WireMessage::Control(_) | WireMessage::ControlResponse(_) => {
            anyhow::bail!("telemetry stream did not start with a snapshot")
        }
    };

    write_wire_message(
        &mut writer,
        &WireMessage::Control(ControlRequest {
            command: ControlCommand::Switch { target },
        }),
    )
    .await?;

    let started_at = Instant::now();
    loop {
        let remaining = CONTROL_TIMEOUT
            .checked_sub(started_at.elapsed())
            .context("timed out waiting for switch response")?;
        let line = tokio::time::timeout(remaining, lines.next_line())
            .await
            .context("timed out waiting for switch response")?
            .context("failed to read switch response")?
            .context("telemetry socket closed before switch response")?;
        match serde_json::from_str::<WireMessage>(&line)
            .context("failed to parse switch response")?
        {
            WireMessage::ControlResponse(response) => {
                return Ok(control_response_with_state_fallback(
                    response,
                    previous_state,
                    target,
                ));
            }
            WireMessage::Event(_) | WireMessage::Snapshot(_) => continue,
            WireMessage::Control(_) => continue,
        }
    }
}

#[cfg(not(unix))]
pub async fn switch_socket(_path: &Path, _target: TrafficSwitchTarget) -> Result<ControlResponse> {
    anyhow::bail!("telemetry control is only supported on Unix platforms")
}

fn control_response_with_state_fallback(
    mut response: ControlResponse,
    previous_state: TrafficState,
    target: TrafficSwitchTarget,
) -> ControlResponse {
    if response.previous_state.is_none() {
        response.previous_state = Some(previous_state);
    }
    if response.ok && response.state.is_none() {
        response.state = Some(target.resolve(previous_state));
    }
    response
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

fn rotate_history(history: &mut [u64]) {
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

fn clock_stamp(at: SystemTime, offset_secs: i32) -> String {
    let elapsed = at
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let local_elapsed = (elapsed as i64 + i64::from(offset_secs)).rem_euclid(86_400);
    let seconds = local_elapsed % 60;
    let minutes = (local_elapsed / 60) % 60;
    let hours = local_elapsed / 3600;
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
    stream: tokio::net::UnixStream,
    sender: broadcast::Sender<TraceEvent>,
    snapshot: Arc<Mutex<SnapshotState>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let (reader, mut writer) = stream.into_split();
    if let Some(snapshot) = current_snapshot(&snapshot) {
        write_wire_message(&mut writer, &WireMessage::Snapshot(snapshot)).await?;
    } else {
        anyhow::bail!("telemetry context is not ready yet");
    }

    let mut lines = BufReader::new(reader).lines();
    let mut receiver = sender.subscribe();
    loop {
        tokio::select! {
            line = lines.next_line() => {
                let Some(line) = line.context("failed to read telemetry control message")? else {
                    break;
                };
                let Ok(message) = serde_json::from_str::<WireMessage>(&line) else {
                    continue;
                };
                if let WireMessage::Control(request) = message {
                    let response = dispatch_control(request).await;
                    if write_wire_message(&mut writer, &WireMessage::ControlResponse(response)).await.is_err() {
                        break;
                    }
                }
            }
            event = receiver.recv() => {
                match event {
                    Ok(event) => {
                        if write_wire_message(&mut writer, &WireMessage::Event(event)).await.is_err() {
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn write_wire_message<W>(stream: &mut W, message: &WireMessage) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut encoded = serde_json::to_vec(message).context("failed to encode telemetry message")?;
    encoded.push(b'\n');
    stream
        .write_all(&encoded)
        .await
        .context("failed to write telemetry message")?;
    Ok(())
}

async fn dispatch_control(request: ControlRequest) -> ControlResponse {
    let sender = CONTROL
        .get()
        .and_then(|slot| slot.lock().ok().and_then(|slot| slot.clone()));
    let Some(sender) = sender else {
        return ControlResponse::error("runtime switch is not supported by this daemon");
    };
    let (response, receiver) = oneshot::channel();
    if sender
        .send(ControlEnvelope { request, response })
        .await
        .is_err()
    {
        return ControlResponse::error("runtime switch handler is not available");
    }
    match tokio::time::timeout(CONTROL_TIMEOUT, receiver).await {
        Ok(Ok(response)) => response,
        Ok(Err(_)) => ControlResponse::error("runtime switch handler closed"),
        Err(_) => ControlResponse::error("runtime switch handler timed out"),
    }
}

fn current_snapshot(snapshot: &Arc<Mutex<SnapshotState>>) -> Option<DashboardSnapshot> {
    snapshot.lock().ok()?.snapshot()
}

#[cfg(test)]
mod tests {
    use super::{
        ControlResponse, MonitorContext, SnapshotState, TraceEvent, TrafficState,
        TrafficSwitchTarget, clock_stamp, control_response_with_state_fallback,
        event_impacts_health, is_loopback_peer,
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
    fn clock_stamp_applies_timezone_offset() {
        assert_eq!(clock_stamp(SystemTime::UNIX_EPOCH, 8 * 60 * 60), "08:00:00");
        assert_eq!(
            clock_stamp(SystemTime::UNIX_EPOCH, -(5 * 60 * 60 + 30 * 60)),
            "18:30:00"
        );
    }

    #[test]
    fn switch_response_uses_snapshot_state_as_old_daemon_fallback() {
        let response = control_response_with_state_fallback(
            ControlResponse {
                ok: true,
                previous_state: None,
                state: Some(TrafficState::Bypass),
                message: "ok".to_owned(),
            },
            TrafficState::Proxying,
            TrafficSwitchTarget::Toggle,
        );

        assert_eq!(response.previous_state, Some(TrafficState::Proxying));
        assert_eq!(response.state, Some(TrafficState::Bypass));
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
            traffic_state: TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("proxy.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 0,
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
    fn recent_events_use_monitor_timezone() {
        let mut snapshot = SnapshotState::default();
        snapshot.set_context(MonitorContext {
            command_label: "client".to_owned(),
            mode_label: "native-http".to_owned(),
            traffic_state: TrafficState::Proxying,
            listen: None,
            upstream: None,
            path: None,
            log_file: PathBuf::from("proxy.log"),
            log_filter: "info".to_owned(),
            log_timezone_offset_secs: 8 * 60 * 60,
            pid: 1,
        });

        snapshot.ingest(&trace_event(
            "INFO",
            "client listening",
            &[("listen", "127.0.0.1:1080")],
        ));

        assert!(
            snapshot.recent_events[0].starts_with("08:00:00 [INFO]"),
            "{}",
            snapshot.recent_events[0]
        );
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
        assert_eq!(snapshot.recent_targets[0].repeat_count, 1);
        assert_eq!(snapshot.route_stats.proxy, 1);
        assert_eq!(snapshot.route_stats.direct, 0);
        assert_eq!(snapshot.route_stats.blocked, 0);
    }

    #[test]
    fn repeated_dns_queries_update_one_recent_domain_row() {
        let mut snapshot = SnapshotState::default();

        for _ in 0..3 {
            snapshot.ingest(&trace_event(
                "INFO",
                "dns query",
                &[
                    ("target", "tracker.example"),
                    ("link", "dns://tracker.example"),
                    ("route", "wg-dns-block"),
                ],
            ));
        }

        assert_eq!(snapshot.recent_targets.len(), 1);
        assert_eq!(snapshot.recent_targets[0].target, "tracker.example");
        assert_eq!(snapshot.recent_targets[0].detail, "blocked");
        assert_eq!(snapshot.recent_targets[0].repeat_count, 3);
        assert_eq!(snapshot.route_stats.blocked, 3);
    }

    #[test]
    fn route_stats_count_proxy_direct_and_blocked_decisions() {
        let mut snapshot = SnapshotState::default();

        snapshot.ingest(&trace_event(
            "INFO",
            "client relay completed",
            &[("target", "example.com:443")],
        ));
        snapshot.ingest(&trace_event(
            "INFO",
            "client relay completed",
            &[("target", "qq.com:443"), ("route", "direct")],
        ));
        snapshot.ingest(&trace_event(
            "INFO",
            "dns query",
            &[("target", "ads.example"), ("route", "wg-dns-block")],
        ));
        snapshot.ingest(&trace_event(
            "INFO",
            "route decision",
            &[("target", "tracker.example:443"), ("route", "block")],
        ));
        snapshot.ingest(&trace_event(
            "INFO",
            "traffic sample",
            &[("target", "wireguard"), ("route", "wg-client")],
        ));

        assert_eq!(snapshot.route_stats.proxy, 1);
        assert_eq!(snapshot.route_stats.direct, 1);
        assert_eq!(snapshot.route_stats.blocked, 2);
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
