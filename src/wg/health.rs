use super::uapi::read_last_handshake_age;
use crate::{
    system_proxy::SystemDnsMonitor,
    telemetry::{self, TrafficState, TunnelCheckState, TunnelHealth, TunnelState},
};
use anyhow::{Context, Result};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::UdpSocket,
    process::Command,
    sync::watch,
    task::JoinHandle,
    time::{MissedTickBehavior, interval, timeout},
};

const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(5);
const DNS_CAPTURE_TIMEOUT: Duration = Duration::from_secs(2);
const CONNECTIVITY_TIMEOUT: Duration = Duration::from_secs(3);
const FRESH_HANDSHAKE_MAX_AGE: Duration = Duration::from_secs(180);
const DNS_PROBE_DOMAIN: &str = "runnel-health-check.invalid";

pub(crate) struct WgClientHealthMonitorConfig {
    pub role: &'static str,
    pub peer_tunnel_ip: IpAddr,
    pub uapi_socket: Option<PathBuf>,
    pub dns_monitor: Option<SystemDnsMonitor>,
    pub dns_capture: bool,
    pub traffic_state: watch::Receiver<TrafficState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HealthCheckResult {
    state: TunnelCheckState,
    detail: String,
}

impl HealthCheckResult {
    fn disabled(detail: impl Into<String>) -> Self {
        Self {
            state: TunnelCheckState::Disabled,
            detail: detail.into(),
        }
    }

    fn ok(detail: impl Into<String>) -> Self {
        Self {
            state: TunnelCheckState::Ok,
            detail: detail.into(),
        }
    }

    fn error(detail: impl Into<String>) -> Self {
        Self {
            state: TunnelCheckState::Error,
            detail: detail.into(),
        }
    }

    fn is_degraded(&self) -> bool {
        matches!(self.state, TunnelCheckState::Warn | TunnelCheckState::Error)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ConnectivityCheck {
    state: TunnelCheckState,
    detail: String,
    handshake_age_secs: Option<u64>,
}

impl ConnectivityCheck {
    fn ok(detail: impl Into<String>, handshake_age_secs: Option<u64>) -> Self {
        Self {
            state: TunnelCheckState::Ok,
            detail: detail.into(),
            handshake_age_secs,
        }
    }

    fn error(detail: impl Into<String>, handshake_age_secs: Option<u64>) -> Self {
        Self {
            state: TunnelCheckState::Error,
            detail: detail.into(),
            handshake_age_secs,
        }
    }

    fn is_degraded(&self) -> bool {
        matches!(self.state, TunnelCheckState::Warn | TunnelCheckState::Error)
    }
}

pub(crate) fn report_tunnel_stage(state: TunnelState, detail: impl Into<String>) {
    telemetry::set_tunnel_health(TunnelHealth::stage(state, detail));
}

pub(crate) fn start_client_health_monitor(config: WgClientHealthMonitorConfig) -> JoinHandle<()> {
    tokio::spawn(run_client_health_monitor(config))
}

async fn run_client_health_monitor(config: WgClientHealthMonitorConfig) {
    let mut reporter = HealthReporter::default();
    let mut checks = interval(HEALTH_CHECK_INTERVAL);
    checks.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        checks.tick().await;

        let health = if *config.traffic_state.borrow() == TrafficState::Bypass {
            TunnelHealth {
                state: TunnelState::Bypass,
                detail: format!("{} traffic switch is bypassing the tunnel", config.role),
                dns: TunnelCheckState::Disabled,
                connectivity: TunnelCheckState::Disabled,
                handshake_age_secs: None,
            }
        } else {
            let dns = check_dns(&config.dns_monitor, config.dns_capture).await;
            let connectivity =
                check_connectivity(config.peer_tunnel_ip, config.uapi_socket.clone()).await;
            compose_client_health(config.role, dns, connectivity)
        };

        reporter.report(health);
    }
}

async fn check_dns(
    system_monitor: &Option<SystemDnsMonitor>,
    dns_capture: bool,
) -> HealthCheckResult {
    let mut checks = Vec::new();

    if let Some(system_monitor) = system_monitor.clone() {
        checks.push(check_system_dns(system_monitor).await);
    }
    if dns_capture {
        checks.push(check_loopback_dns_capture().await);
    }

    if checks.is_empty() {
        return HealthCheckResult::disabled("DNS monitor disabled");
    }

    combine_checks(checks)
}

async fn check_system_dns(monitor: SystemDnsMonitor) -> HealthCheckResult {
    match tokio::task::spawn_blocking(move || monitor.check()).await {
        Ok(Ok(check)) if check.ok => HealthCheckResult::ok(check.detail),
        Ok(Ok(check)) => HealthCheckResult::error(check.detail),
        Ok(Err(error)) => HealthCheckResult::error(format!("system DNS check failed: {error:#}")),
        Err(error) => HealthCheckResult::error(format!("system DNS check panicked: {error}")),
    }
}

fn combine_checks(checks: Vec<HealthCheckResult>) -> HealthCheckResult {
    let state = if checks
        .iter()
        .any(|check| check.state == TunnelCheckState::Error)
    {
        TunnelCheckState::Error
    } else if checks
        .iter()
        .any(|check| check.state == TunnelCheckState::Warn)
    {
        TunnelCheckState::Warn
    } else {
        TunnelCheckState::Ok
    };
    let detail = checks
        .into_iter()
        .map(|check| check.detail)
        .collect::<Vec<_>>()
        .join("; ");

    HealthCheckResult { state, detail }
}

async fn check_loopback_dns_capture() -> HealthCheckResult {
    match probe_loopback_dns_capture().await {
        Ok(()) => HealthCheckResult::ok("loopback DNS capture answered"),
        Err(error) => HealthCheckResult::error(format!("loopback DNS capture failed: {error:#}")),
    }
}

async fn probe_loopback_dns_capture() -> Result<()> {
    let query_id = dns_probe_id();
    let query = build_dns_query(query_id, DNS_PROBE_DOMAIN)?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .context("failed to bind DNS health probe socket")?;
    socket
        .send_to(&query, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53))
        .await
        .context("failed to send DNS health probe")?;

    let mut buf = [0u8; 512];
    let len = match timeout(DNS_CAPTURE_TIMEOUT, socket.recv(&mut buf)).await {
        Ok(Ok(len)) => len,
        Ok(Err(error)) => return Err(error).context("failed to receive DNS health response"),
        Err(_) => anyhow::bail!(
            "timed out after {}s waiting for 127.0.0.1:53",
            DNS_CAPTURE_TIMEOUT.as_secs()
        ),
    };
    if dns_response_matches(query_id, &buf[..len]) {
        Ok(())
    } else {
        anyhow::bail!("received a DNS response that did not match the health probe")
    }
}

fn dns_probe_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    (nanos ^ (std::process::id() & 0xffff)) as u16
}

fn build_dns_query(id: u16, domain: &str) -> Result<Vec<u8>> {
    let mut query = Vec::with_capacity(12 + domain.len() + 6);
    query.extend_from_slice(&id.to_be_bytes());
    query.extend_from_slice(&0x0100u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());
    query.extend_from_slice(&0u16.to_be_bytes());

    for label in domain.split('.') {
        if label.is_empty() {
            anyhow::bail!("DNS probe domain contains an empty label");
        }
        if label.len() > 63 {
            anyhow::bail!("DNS probe domain label is too long");
        }
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes());
    query.extend_from_slice(&1u16.to_be_bytes());
    Ok(query)
}

fn dns_response_matches(query_id: u16, response: &[u8]) -> bool {
    response.len() >= 12 && response[..2] == query_id.to_be_bytes() && response[2] & 0x80 == 0x80
}

async fn check_connectivity(
    peer_tunnel_ip: IpAddr,
    uapi_socket: Option<PathBuf>,
) -> ConnectivityCheck {
    let ping = check_peer_ping(peer_tunnel_ip).await;
    let handshake = match uapi_socket {
        Some(socket_path) => read_handshake_health(socket_path).await,
        None => HandshakeHealth::Disabled,
    };
    let handshake_age_secs = handshake.age_secs();

    if ping.state == TunnelCheckState::Ok {
        return ConnectivityCheck::ok(
            format!("{}; {}", ping.detail, handshake.detail()),
            handshake_age_secs,
        );
    }

    if handshake.is_fresh() {
        return ConnectivityCheck::ok(
            format!("{}; {}", ping.detail, handshake.detail()),
            handshake_age_secs,
        );
    }

    ConnectivityCheck::error(
        format!("{}; {}", ping.detail, handshake.detail()),
        handshake_age_secs,
    )
}

async fn check_peer_ping(peer_tunnel_ip: IpAddr) -> HealthCheckResult {
    let mut child = match ping_command(peer_tunnel_ip).spawn() {
        Ok(child) => child,
        Err(error) => {
            return HealthCheckResult::error(format!(
                "failed to start ping to {peer_tunnel_ip}: {error}"
            ));
        }
    };

    match timeout(CONNECTIVITY_TIMEOUT, child.wait()).await {
        Ok(Ok(status)) if status.success() => {
            HealthCheckResult::ok(format!("peer tunnel IP {peer_tunnel_ip} answered ping"))
        }
        Ok(Ok(status)) => HealthCheckResult::error(format!(
            "peer tunnel IP {peer_tunnel_ip} ping exited with {status}"
        )),
        Ok(Err(error)) => HealthCheckResult::error(format!(
            "peer tunnel IP {peer_tunnel_ip} ping failed: {error}"
        )),
        Err(_) => {
            let _ = child.start_kill();
            let _ = child.wait().await;
            HealthCheckResult::error(format!(
                "peer tunnel IP {peer_tunnel_ip} ping timed out after {}s",
                CONNECTIVITY_TIMEOUT.as_secs()
            ))
        }
    }
}

fn ping_command(peer_tunnel_ip: IpAddr) -> Command {
    let mut command = if cfg!(target_os = "macos") && peer_tunnel_ip.is_ipv6() {
        Command::new("ping6")
    } else {
        Command::new("ping")
    };
    command.arg("-n").arg("-c").arg("1");
    if peer_tunnel_ip.is_ipv6() && !cfg!(target_os = "macos") {
        command.arg("-6");
    }
    command
        .arg(peer_tunnel_ip.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}

async fn read_handshake_health(socket_path: PathBuf) -> HandshakeHealth {
    match tokio::task::spawn_blocking(move || read_last_handshake_age(&socket_path)).await {
        Ok(Ok(Some(age))) if age <= FRESH_HANDSHAKE_MAX_AGE => HandshakeHealth::Fresh(age),
        Ok(Ok(Some(age))) => HandshakeHealth::Stale(age),
        Ok(Ok(None)) => HandshakeHealth::Missing,
        Ok(Err(error)) => HandshakeHealth::Error(format!("{error:#}")),
        Err(error) => HandshakeHealth::Error(error.to_string()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum HandshakeHealth {
    Disabled,
    Fresh(Duration),
    Stale(Duration),
    Missing,
    Error(String),
}

impl HandshakeHealth {
    fn is_fresh(&self) -> bool {
        matches!(self, Self::Fresh(_))
    }

    fn age_secs(&self) -> Option<u64> {
        match self {
            Self::Fresh(age) | Self::Stale(age) => Some(age.as_secs()),
            Self::Disabled | Self::Missing | Self::Error(_) => None,
        }
    }

    fn detail(&self) -> String {
        match self {
            Self::Disabled => "WireGuard handshake monitor disabled".to_owned(),
            Self::Fresh(_) => "last WireGuard handshake is fresh".to_owned(),
            Self::Stale(_) => "last WireGuard handshake is stale".to_owned(),
            Self::Missing => "WireGuard peer has no recorded handshake".to_owned(),
            Self::Error(error) => format!("WireGuard handshake check failed: {error}"),
        }
    }
}

fn compose_client_health(
    role: &str,
    dns: HealthCheckResult,
    connectivity: ConnectivityCheck,
) -> TunnelHealth {
    let degraded = dns.is_degraded() || connectivity.is_degraded();
    TunnelHealth {
        state: if degraded {
            TunnelState::Degraded
        } else {
            TunnelState::Active
        },
        detail: format!(
            "{role}: dns: {}; connectivity: {}",
            dns.detail, connectivity.detail
        ),
        dns: dns.state,
        connectivity: connectivity.state,
        handshake_age_secs: connectivity.handshake_age_secs,
    }
}

#[derive(Default)]
struct HealthReporter {
    last_key: Option<HealthKey>,
}

impl HealthReporter {
    fn report(&mut self, health: TunnelHealth) {
        let key = HealthKey::from(&health);
        if self.last_key.as_ref() != Some(&key) {
            telemetry::set_tunnel_health(health);
            self.last_key = Some(key);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HealthKey {
    state: TunnelState,
    detail: String,
    dns: TunnelCheckState,
    connectivity: TunnelCheckState,
}

impl From<&TunnelHealth> for HealthKey {
    fn from(health: &TunnelHealth) -> Self {
        Self {
            state: health.state,
            detail: health.detail.clone(),
            dns: health.dns,
            connectivity: health.connectivity,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_query_and_response_use_matching_id() {
        let query = build_dns_query(0x1234, DNS_PROBE_DOMAIN).unwrap();
        assert_eq!(&query[..2], &[0x12, 0x34]);

        let mut response = vec![0u8; 12];
        response[..2].copy_from_slice(&0x1234u16.to_be_bytes());
        response[2] = 0x80;

        assert!(dns_response_matches(0x1234, &response));
        assert!(!dns_response_matches(0x4321, &response));
    }

    #[test]
    fn compose_health_is_active_when_checks_are_ok_or_disabled() {
        let health = compose_client_health(
            "wg-client",
            HealthCheckResult::disabled("DNS monitor disabled"),
            ConnectivityCheck::ok("peer answered ping", Some(2)),
        );

        assert_eq!(health.state, TunnelState::Active);
        assert_eq!(health.dns, TunnelCheckState::Disabled);
        assert_eq!(health.connectivity, TunnelCheckState::Ok);
        assert_eq!(health.handshake_age_secs, Some(2));
    }

    #[test]
    fn compose_health_degrades_on_dns_error() {
        let health = compose_client_health(
            "wg-client",
            HealthCheckResult::error("system DNS changed"),
            ConnectivityCheck::ok("peer answered ping", None),
        );

        assert_eq!(health.state, TunnelState::Degraded);
        assert_eq!(health.dns, TunnelCheckState::Error);
        assert_eq!(health.connectivity, TunnelCheckState::Ok);
    }

    #[test]
    fn compose_health_degrades_on_connectivity_error() {
        let health = compose_client_health(
            "wg-client",
            HealthCheckResult::ok("DNS ok"),
            ConnectivityCheck::error("peer did not answer ping", None),
        );

        assert_eq!(health.state, TunnelState::Degraded);
        assert_eq!(health.dns, TunnelCheckState::Ok);
        assert_eq!(health.connectivity, TunnelCheckState::Error);
    }

    #[test]
    fn combine_checks_reports_the_worst_state() {
        let combined = combine_checks(vec![
            HealthCheckResult::ok("system DNS ok"),
            HealthCheckResult::error("capture failed"),
        ]);

        assert_eq!(combined.state, TunnelCheckState::Error);
        assert_eq!(combined.detail, "system DNS ok; capture failed");
    }
}
