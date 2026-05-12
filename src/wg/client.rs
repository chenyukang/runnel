use super::{
    DEFAULT_TUNNEL_MTU, WgEngine, WgObfsMode, WgObfsProfile, WgRuntimeConfig, create_device_handle,
    default_client_allowed_ips_for,
    dns::{DnsCaptureController, DomainRuleEngine, start_dns_capture},
    hooks::{
        DynamicRouteManager, EgressRouteNotReady, SwitchableHookGuard, effective_hook_plan,
        log_plan_lines, plan_client_hooks, print_plan, run_hooks,
    },
    noise, normalize_allowed_ips, parse_key, parse_socket_addr,
    preflight::{WgPreflightRole, check as check_preflight},
    select_device_name,
    stats::start_stats_poller,
    tcpdump::{self, TcpdumpFilter},
    uapi::{apply_device_config, control_socket_path},
    wait_for_shutdown_signal,
};
use anyhow::{Context, Result, bail};
use boringtun::noise::TunnResult;
use clap::Args;
use std::{
    collections::BTreeMap,
    error::Error as StdError,
    fmt, io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Mutex, time::timeout};
use tracing::{info, warn};

use crate::{
    proxy::{adblock::AdblockConfig, adblock::Adblocker, route::RouteRuleConfig},
    system_proxy, telemetry,
};

const HANDSHAKE_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const WG_CLIENT_RECOVERY_INITIAL_DELAY: Duration = Duration::from_secs(1);
const WG_CLIENT_RECOVERY_MAX_DELAY: Duration = Duration::from_secs(10);

#[derive(Debug)]
struct WgClientNetworkNotReady {
    operation: &'static str,
    endpoint: SocketAddr,
    os_error: Option<i32>,
    os_error_name: &'static str,
    last_error: String,
}

impl WgClientNetworkNotReady {
    fn from_udp_error(operation: &'static str, endpoint: SocketAddr, error: &io::Error) -> Self {
        let os_error = error.raw_os_error();
        Self {
            operation,
            endpoint,
            os_error,
            os_error_name: os_error.and_then(udp_os_error_name).unwrap_or("unknown"),
            last_error: error.to_string(),
        }
    }
}

impl fmt::Display for WgClientNetworkNotReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "wg client network is not ready while {} to {}",
            self.operation, self.endpoint
        )?;
        if let Some(os_error) = self.os_error {
            write!(f, " ({} / os error {os_error})", self.os_error_name)?;
        }
        write!(f, ": {}", self.last_error)
    }
}

impl StdError for WgClientNetworkNotReady {}

#[derive(Clone, Debug, Args)]
pub struct WgClientArgs {
    #[arg(long, value_enum, default_value_t = WgEngine::Device)]
    pub engine: WgEngine,
    #[arg(long, value_enum, default_value_t = WgObfsMode::Off)]
    pub obfs: WgObfsMode,
    #[arg(long, default_value_t = WgObfsProfile::default().padding_min)]
    pub obfs_padding_min: u16,
    #[arg(long, default_value_t = WgObfsProfile::default().padding_max)]
    pub obfs_padding_max: u16,
    #[arg(long)]
    pub obfs_handshake_padding: Option<u16>,
    #[arg(long)]
    pub obfs_response_padding: Option<u16>,
    #[arg(long, default_value_t = WgObfsProfile::default().junk_packets)]
    pub obfs_junk_packets: u8,
    #[arg(long, default_value_t = WgObfsProfile::default().jitter_ms)]
    pub obfs_jitter_ms: u16,
    #[arg(long, default_value = "0.0.0.0:0")]
    pub bind: String,
    #[arg(long)]
    #[arg(default_value = "")]
    pub endpoint: String,
    #[arg(long, env = "RUNNEL_WG_PRIVATE_KEY")]
    #[arg(default_value = "")]
    pub private_key: String,
    #[arg(long)]
    #[arg(default_value = "")]
    pub peer_public_key: String,
    #[arg(long, default_value = "auto")]
    pub device: String,
    #[arg(long, default_value = "10.8.0.2")]
    pub tunnel_ip: IpAddr,
    #[arg(long, default_value = "10.8.0.1")]
    pub peer_tunnel_ip: IpAddr,
    #[arg(long, default_value_t = DEFAULT_TUNNEL_MTU)]
    pub mtu: u16,
    #[arg(long)]
    pub persistent_keepalive_secs: Option<u16>,
    #[arg(long)]
    pub dns: Option<IpAddr>,
    #[arg(long)]
    pub dns_capture: bool,
    #[arg(skip)]
    pub proxy_ips: Vec<String>,
    #[arg(skip)]
    pub direct_ips: Vec<String>,
    #[arg(skip)]
    pub domain_rules: RouteRuleConfig,
    #[arg(skip)]
    pub adblock: AdblockConfig,
    #[arg(long)]
    pub up: Vec<String>,
    #[arg(long)]
    pub down: Vec<String>,
    #[arg(long)]
    pub print_hooks: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub skip_handshake_probe: bool,
    #[arg(long)]
    pub tcpdump: bool,
    #[arg(long)]
    pub tcpdump_interface: Option<String>,
}

impl Default for WgClientArgs {
    fn default() -> Self {
        Self {
            engine: WgEngine::Device,
            obfs: WgObfsMode::Off,
            obfs_padding_min: WgObfsProfile::default().padding_min,
            obfs_padding_max: WgObfsProfile::default().padding_max,
            obfs_handshake_padding: None,
            obfs_response_padding: None,
            obfs_junk_packets: WgObfsProfile::default().junk_packets,
            obfs_jitter_ms: WgObfsProfile::default().jitter_ms,
            bind: "0.0.0.0:0".to_owned(),
            endpoint: String::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            device: "auto".to_owned(),
            tunnel_ip: "10.8.0.2".parse().expect("valid default WG client IP"),
            peer_tunnel_ip: "10.8.0.1".parse().expect("valid default WG peer IP"),
            mtu: DEFAULT_TUNNEL_MTU,
            persistent_keepalive_secs: None,
            dns: None,
            dns_capture: false,
            proxy_ips: Vec::new(),
            direct_ips: Vec::new(),
            domain_rules: RouteRuleConfig::default(),
            adblock: AdblockConfig::default(),
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: false,
            skip_handshake_probe: false,
            tcpdump: false,
            tcpdump_interface: None,
        }
    }
}

pub async fn run(args: WgClientArgs) -> Result<()> {
    let runtime = args.resolve()?;
    let obfs_profile = args.obfs_profile();
    validate_engine_obfs("wg client", args.engine, args.obfs, &obfs_profile)?;
    if args.dns.is_some() && !args.dns_capture {
        warn!(
            "wg DNS capture is disabled; TUI Recent Domains requires --dns-capture or client.wg.dns_capture: true"
        );
    }
    if !args.dry_run {
        check_preflight(
            WgPreflightRole::Client,
            args.dns.is_some() || args.dns_capture,
            false,
        )?;
    }

    if args.print_hooks || args.dry_run {
        let planned_device = select_device_name(&args.device)?;
        let default_plan = plan_client_hooks(&planned_device, &runtime)?;
        let plan = effective_hook_plan(default_plan, &args.up, &args.down);
        let lines = plan_lines(&args, &planned_device, &runtime, &plan);
        if args.print_hooks {
            print_plan(&lines);
        } else {
            log_plan_lines(&lines);
        }
        if args.dry_run {
            return Ok(());
        }
    }

    run_with_recovery(args, runtime, obfs_profile).await
}

async fn run_with_recovery(
    args: WgClientArgs,
    runtime: WgRuntimeConfig,
    obfs_profile: WgObfsProfile,
) -> Result<()> {
    let endpoint = runtime.endpoint.context("wg client endpoint missing")?;
    let mut restart_count = 0u64;
    let mut restart_delay = WG_CLIENT_RECOVERY_INITIAL_DELAY;

    loop {
        let result =
            run_client_session(args.clone(), runtime.clone(), obfs_profile, restart_count).await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) => {
                if let Some(local_path_lost) = error.downcast_ref::<noise::WgNoiseLocalPathLost>() {
                    restart_count += 1;
                    warn!(
                        engine = ?args.engine,
                        endpoint = %endpoint,
                        restart_count,
                        backoff_ms = restart_delay.as_millis(),
                        consecutive_failures = local_path_lost.consecutive_failures,
                        os_error = ?local_path_lost.os_error,
                        os_error_name = local_path_lost.os_error_name,
                        last_error = %local_path_lost.last_error,
                        "wg client local UDP path lost; rebuilding session after backoff"
                    );
                } else if let Some(route_not_ready) = error.downcast_ref::<EgressRouteNotReady>() {
                    restart_count += 1;
                    warn!(
                        engine = ?args.engine,
                        endpoint = %endpoint,
                        route_target = route_not_ready.target(),
                        route_detail = route_not_ready.detail(),
                        route_output = ?route_not_ready.route_output_for_log(),
                        restart_count,
                        backoff_ms = restart_delay.as_millis(),
                        "wg client egress route not ready; retrying session after backoff"
                    );
                } else if let Some(network_not_ready) =
                    error.downcast_ref::<WgClientNetworkNotReady>()
                {
                    restart_count += 1;
                    warn!(
                        engine = ?args.engine,
                        endpoint = %endpoint,
                        operation = network_not_ready.operation,
                        probe_endpoint = %network_not_ready.endpoint,
                        os_error = ?network_not_ready.os_error,
                        os_error_name = network_not_ready.os_error_name,
                        last_error = %network_not_ready.last_error,
                        restart_count,
                        backoff_ms = restart_delay.as_millis(),
                        "wg client network not ready; retrying session after backoff"
                    );
                } else {
                    return Err(error);
                }

                tokio::select! {
                    _ = tokio::time::sleep(restart_delay) => {}
                    signal = wait_for_shutdown_signal() => return signal,
                }

                info!(
                    engine = ?args.engine,
                    endpoint = %endpoint,
                    restart_count,
                    "wg client rebuilding session after recoverable network change"
                );
                restart_delay = next_recovery_delay(restart_delay);
            }
        }
    }
}

async fn run_client_session(
    args: WgClientArgs,
    runtime: WgRuntimeConfig,
    obfs_profile: WgObfsProfile,
    restart_count: u64,
) -> Result<()> {
    if !args.skip_handshake_probe {
        probe_server_handshake(&runtime, args.obfs, obfs_profile, HANDSHAKE_PROBE_TIMEOUT).await?;
    }

    if args.engine == WgEngine::Noise {
        let endpoint = runtime.endpoint.context("wg client endpoint missing")?;
        return noise::run_client_session(args, runtime, endpoint, restart_count).await;
    }

    run_device_client_session(args, runtime, restart_count).await
}

async fn run_device_client_session(
    args: WgClientArgs,
    runtime: WgRuntimeConfig,
    restart_count: u64,
) -> Result<()> {
    let endpoint = runtime.endpoint.context("wg client endpoint missing")?;
    let (_device_handle, actual_device) = create_device_handle(&args.device)?;
    let socket_path = control_socket_path(&actual_device);
    apply_device_config(&socket_path, &runtime)?;
    start_stats_poller("wg-client", socket_path.clone());
    let _tcpdump = args.tcpdump.then(|| {
        tcpdump::start(
            "wg-client",
            args.tcpdump_interface.as_deref(),
            TcpdumpFilter::Client { endpoint },
        )
    });
    let adblock = Adblocker::from_config(&args.adblock).await?;
    let plan = effective_hook_plan(
        plan_client_hooks(&actual_device, &runtime)?,
        &args.up,
        &args.down,
    );
    let domain_route_manager = if domain_rules_need_dns_capture(&args.domain_rules) {
        Some(Arc::new(DynamicRouteManager::for_client(&runtime)?))
    } else {
        None
    };
    let domain_rules = domain_route_manager
        .as_ref()
        .map(|manager| {
            DomainRuleEngine::new(
                args.domain_rules.clone(),
                Some(Arc::clone(manager)),
                adblock.clone(),
            )
        })
        .or_else(|| {
            adblock
                .as_ref()
                .map(|_| DomainRuleEngine::new(args.domain_rules.clone(), None, adblock.clone()))
        });
    run_hooks(&plan.up)?;

    // Keep the device alive until we receive a shutdown signal. The guard is declared
    // after the handle so cleanup hooks run before the device file descriptor closes.
    let route_switch = SwitchableHookGuard::new("wg-client", plan);
    let dns_capture = match (args.dns_capture, args.dns) {
        (true, Some(dns)) => Some(start_dns_capture(dns, domain_rules).await?),
        (true, None) => bail!("wg client --dns-capture requires --dns as the upstream resolver"),
        (false, _) => None,
    };
    let dns_capture_control = dns_capture.as_ref().map(|capture| capture.controller());
    let dns_guard = match (args.dns, args.dns_capture) {
        (Some(_), true) => system_proxy::maybe_activate_tun_dns(&["127.0.0.1".to_owned()])?,
        (Some(dns), false) => system_proxy::maybe_activate_tun_dns(&[dns.to_string()])?,
        (None, _) => None,
    };
    let bypass_dns = dns_guard
        .as_ref()
        .and_then(system_proxy::SystemDnsGuard::direct_dns_upstream);
    let traffic_switch = Arc::new(Mutex::new(WgTrafficSwitch::new(
        route_switch,
        domain_route_manager.clone(),
        dns_guard,
        dns_capture_control,
        args.dns.filter(|_| args.dns_capture),
        bypass_dns,
    )));
    telemetry::set_traffic_state(telemetry::TrafficState::Proxying);
    let traffic_switch_task = tokio::spawn(run_wg_traffic_switch_control(
        telemetry::init_control_channel(),
        Arc::clone(&traffic_switch),
    ));

    info!(
        device = %actual_device,
        endpoint = %endpoint,
        tunnel_ip = %runtime.tunnel_ip,
        peer_tunnel_ip = %runtime.peer_tunnel_ip,
        dns = ?args.dns,
        dns_capture = args.dns_capture,
        mtu = runtime.mtu,
        restart_count,
        uapi_socket = %socket_path.display(),
        "wg client started"
    );

    let result = wait_for_shutdown_signal().await;
    traffic_switch_task.abort();
    let _ = traffic_switch_task.await;
    result
}

struct WgTrafficSwitch {
    state: telemetry::TrafficState,
    routes: SwitchableHookGuard,
    _domain_routes: Option<Arc<DynamicRouteManager>>,
    dns_guard: Option<system_proxy::SystemDnsGuard>,
    dns_capture: Option<DnsCaptureController>,
    proxy_dns: Option<IpAddr>,
    bypass_dns: Option<IpAddr>,
}

impl WgTrafficSwitch {
    fn new(
        routes: SwitchableHookGuard,
        domain_routes: Option<Arc<DynamicRouteManager>>,
        dns_guard: Option<system_proxy::SystemDnsGuard>,
        dns_capture: Option<DnsCaptureController>,
        proxy_dns: Option<IpAddr>,
        bypass_dns: Option<IpAddr>,
    ) -> Self {
        Self {
            state: telemetry::TrafficState::Proxying,
            routes,
            _domain_routes: domain_routes,
            dns_guard,
            dns_capture,
            proxy_dns,
            bypass_dns,
        }
    }

    fn switch(&mut self, target: telemetry::TrafficSwitchTarget) -> telemetry::ControlResponse {
        let previous_state = self.state;
        match self.try_switch(target) {
            Ok(state) => telemetry::ControlResponse::ok(previous_state, state),
            Err(err) => telemetry::ControlResponse::error(format!("{err:#}")),
        }
    }

    fn try_switch(
        &mut self,
        target: telemetry::TrafficSwitchTarget,
    ) -> Result<telemetry::TrafficState> {
        let next = target.resolve(self.state);
        if next == self.state {
            return Ok(self.state);
        }

        match next {
            telemetry::TrafficState::Proxying => {
                self.routes.proxying()?;
                if let (Some(dns_capture), Some(proxy_dns)) = (&self.dns_capture, self.proxy_dns) {
                    dns_capture.set_upstream(proxy_dns);
                }
                if let Some(dns_guard) = &self.dns_guard {
                    dns_guard.apply_override()?;
                }
            }
            telemetry::TrafficState::Bypass => {
                self.routes.bypass()?;
                match (&self.dns_capture, self.bypass_dns) {
                    (Some(dns_capture), Some(bypass_dns)) => {
                        dns_capture.set_upstream(bypass_dns);
                        if let Some(dns_guard) = &self.dns_guard {
                            dns_guard.apply_override()?;
                        }
                    }
                    _ => {
                        if let Some(dns_guard) = &self.dns_guard {
                            dns_guard.restore_original()?;
                        }
                    }
                }
            }
        }

        self.state = next;
        telemetry::set_traffic_state(next);
        emit_traffic_switch(next);
        Ok(next)
    }
}

async fn run_wg_traffic_switch_control(
    mut receiver: tokio::sync::mpsc::Receiver<telemetry::ControlEnvelope>,
    traffic_switch: Arc<Mutex<WgTrafficSwitch>>,
) {
    while let Some(envelope) = receiver.recv().await {
        let response = match envelope.request.command {
            telemetry::ControlCommand::Switch { target } => {
                traffic_switch.lock().await.switch(target)
            }
        };
        envelope.respond(response);
    }
}

fn emit_traffic_switch(state: telemetry::TrafficState) {
    let mut fields = BTreeMap::new();
    fields.insert("state".to_owned(), state.as_str().to_owned());
    fields.insert("mode".to_owned(), "wg".to_owned());
    telemetry::emit("INFO", "traffic switch", fields);
}

fn next_recovery_delay(delay: Duration) -> Duration {
    delay.saturating_mul(2).min(WG_CLIENT_RECOVERY_MAX_DELAY)
}

async fn probe_server_handshake(
    runtime: &WgRuntimeConfig,
    obfs: WgObfsMode,
    obfs_profile: WgObfsProfile,
    timeout_duration: Duration,
) -> Result<()> {
    let endpoint = runtime.endpoint.context("wg client endpoint missing")?;
    let socket = UdpSocket::bind(probe_bind_addr(runtime.bind, endpoint))
        .await
        .with_context(|| {
            format!(
                "failed to bind wg client handshake probe socket for {}",
                runtime.bind
            )
        })?;
    let mut tunnel = runtime.new_tunnel(1);
    let codec = noise::NoisePacketCodec::new(obfs, obfs_profile, runtime);
    let mut send_buf = [0u8; super::HANDSHAKE_BUFFER_SIZE];
    let packet = match tunnel.format_handshake_initiation(&mut send_buf, false) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        TunnResult::Done => return Ok(()),
        TunnResult::Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to build WG handshake probe packet: {err:?}"
            ));
        }
        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
            bail!("WG handshake probe unexpectedly produced a tunnel packet");
        }
    };
    let mut encoded_buf = vec![0u8; noise::MAX_NOISE_UDP_PACKET_SIZE];
    let encoded_len = codec.encode(&packet, &mut encoded_buf)?;

    send_probe_udp_packet(
        &socket,
        &encoded_buf[..encoded_len],
        endpoint,
        "sending WG handshake probe",
    )
    .await?;

    let mut recv_buf = vec![0u8; noise::MAX_NOISE_UDP_PACKET_SIZE];
    let mut decoded_buf = [0u8; super::HANDSHAKE_BUFFER_SIZE];
    let mut decap_buf = [0u8; super::HANDSHAKE_BUFFER_SIZE];
    let probe = async {
        loop {
            let (len, addr) = socket.recv_from(&mut recv_buf).await?;
            if addr != endpoint {
                continue;
            }
            let Some(decoded_len) = codec.decode(&recv_buf[..len], &mut decoded_buf)? else {
                continue;
            };
            match tunnel.decapsulate(
                Some(endpoint.ip()),
                &decoded_buf[..decoded_len],
                &mut decap_buf,
            ) {
                TunnResult::WriteToNetwork(packet) => {
                    let encoded_len = codec.encode(packet, &mut encoded_buf)?;
                    send_probe_udp_packet(
                        &socket,
                        &encoded_buf[..encoded_len],
                        endpoint,
                        "sending WG handshake probe keepalive",
                    )
                    .await?;
                    return Ok(());
                }
                TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                    return Ok(());
                }
                TunnResult::Done | TunnResult::Err(_) => continue,
            }
        }
    };

    match timeout(timeout_duration, probe).await {
        Ok(result) => result,
        Err(_) => bail!(
            "wg client handshake probe timed out after {}s; endpoint may be unreachable or WG keys may not match. Pass --skip-handshake-probe or set client.wg.skip_handshake_probe: true to start without probing.",
            timeout_duration.as_secs()
        ),
    }
}

async fn send_probe_udp_packet(
    socket: &UdpSocket,
    packet: &[u8],
    endpoint: SocketAddr,
    operation: &'static str,
) -> Result<usize> {
    match socket.send_to(packet, endpoint).await {
        Ok(sent) => Ok(sent),
        Err(error) if is_recoverable_udp_path_error(&error) => {
            Err(WgClientNetworkNotReady::from_udp_error(operation, endpoint, &error).into())
        }
        Err(error) => {
            Err(error).with_context(|| format!("failed to send WG handshake probe to {endpoint}"))
        }
    }
}

fn is_recoverable_udp_path_error(error: &io::Error) -> bool {
    error.raw_os_error().and_then(udp_os_error_name).is_some()
}

fn udp_os_error_name(code: i32) -> Option<&'static str> {
    match code {
        libc::EADDRNOTAVAIL => Some("EADDRNOTAVAIL"),
        libc::ENETDOWN => Some("ENETDOWN"),
        libc::ENETUNREACH => Some("ENETUNREACH"),
        libc::EHOSTUNREACH => Some("EHOSTUNREACH"),
        _ => None,
    }
}

fn probe_bind_addr(bind: SocketAddr, endpoint: SocketAddr) -> SocketAddr {
    let port = bind.port();
    match endpoint {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], port)),
        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port)),
    }
}

fn plan_lines(
    args: &WgClientArgs,
    device: &str,
    runtime: &WgRuntimeConfig,
    plan: &super::hooks::HookPlan,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("runnel wg-client plan".to_owned());
    lines.push(format!("  engine: {}", args.engine));
    lines.push(format!("  obfs: {}", args.obfs));
    if args.obfs != WgObfsMode::Off {
        lines.push(format!("  obfs_padding: {}", args.obfs_profile()));
    }
    if super::is_auto_device(&args.device) {
        lines.push(format!("  device: {device} (auto)"));
    } else {
        lines.push(format!("  device: {device}"));
    }
    lines.push(format!("  bind: {}", runtime.bind));
    lines.push(format!(
        "  endpoint: {}",
        runtime
            .endpoint
            .map(|endpoint| endpoint.to_string())
            .unwrap_or_else(|| "-".to_owned())
    ));
    lines.push(format!("  tunnel_ip: {}", runtime.tunnel_ip));
    lines.push(format!("  peer_tunnel_ip: {}", runtime.peer_tunnel_ip));
    lines.push(format!(
        "  tunnel_routes: {}",
        runtime.peer_allowed_ips.join(", ")
    ));
    lines.push(format!(
        "  ip_rules.direct: {}",
        if runtime.excluded_ips.is_empty() {
            "-".to_owned()
        } else {
            runtime.excluded_ips.join(", ")
        }
    ));
    lines.push(format!(
        "  dns: {}",
        args.dns
            .map(|dns| dns.to_string())
            .unwrap_or_else(|| "-".to_owned())
    ));
    lines.push(format!("  dns_capture: {}", args.dns_capture));
    lines.push(format!(
        "  domain_rules: {}",
        if domain_rules_need_dns_capture(&args.domain_rules) {
            "dns-capture"
        } else {
            "disabled"
        }
    ));
    lines.push(format!(
        "  handshake_probe: {}",
        if args.skip_handshake_probe {
            "disabled"
        } else {
            "enabled"
        }
    ));
    lines.push(format!(
        "  tcpdump: {}",
        if args.tcpdump {
            args.tcpdump_interface.as_deref().unwrap_or("auto")
        } else {
            "disabled"
        }
    ));
    lines.push("  up hooks:".to_owned());
    if plan.up.is_empty() {
        lines.push("    - (none)".to_owned());
    } else {
        for hook in &plan.up {
            lines.push(format!("    - {hook}"));
        }
    }
    lines.push("  down hooks:".to_owned());
    if plan.down.is_empty() {
        lines.push("    - (none)".to_owned());
    } else {
        for hook in &plan.down {
            lines.push(format!("    - {hook}"));
        }
    }
    lines
}

fn validate_engine_obfs(
    role: &str,
    engine: WgEngine,
    obfs: WgObfsMode,
    profile: &WgObfsProfile,
) -> Result<()> {
    if obfs != WgObfsMode::Off && engine != WgEngine::Noise {
        bail!("{role} --obfs requires --engine noise");
    }
    if obfs == WgObfsMode::Off && *profile != WgObfsProfile::default() {
        bail!("{role} --obfs-* options require --obfs mask");
    }
    profile.validate(role)?;
    Ok(())
}

impl WgClientArgs {
    pub fn validate_required(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            bail!("wg client endpoint is required; pass --endpoint or set it in --config");
        }
        if self.private_key.trim().is_empty() {
            bail!(
                "wg client private_key is required; pass --private-key, set RUNNEL_WG_PRIVATE_KEY, or set it in --config"
            );
        }
        if self.peer_public_key.trim().is_empty() {
            bail!(
                "wg client peer_public_key is required; pass --peer-public-key or set it in --config"
            );
        }
        if self.dns_capture && self.dns.is_none() {
            bail!("wg client --dns-capture requires --dns as the upstream resolver");
        }
        if domain_rules_need_dns_capture(&self.domain_rules) {
            if self.dns.is_none() {
                bail!(
                    "wg client domain_rules require client.wg.dns because WG domain routing is driven by DNS capture"
                );
            }
            if !self.dns_capture {
                bail!(
                    "wg client domain_rules require client.wg.dns_capture: true because WG cannot route by domain without DNS capture"
                );
            }
        }
        if self.adblock.is_active() {
            if self.dns.is_none() {
                bail!(
                    "wg client adblock requires client.wg.dns because WG adblock is driven by DNS capture"
                );
            }
            if !self.dns_capture {
                bail!(
                    "wg client adblock requires client.wg.dns_capture: true because WG cannot block by domain without DNS capture"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn resolve(&self) -> Result<WgRuntimeConfig> {
        self.validate_required()?;
        let runtime = WgRuntimeConfig {
            bind: parse_socket_addr("wg client bind", &self.bind)?,
            endpoint: Some(parse_socket_addr("wg client endpoint", &self.endpoint)?),
            tunnel_ip: self.tunnel_ip,
            peer_tunnel_ip: self.peer_tunnel_ip,
            mtu: self.mtu,
            persistent_keepalive_secs: self.persistent_keepalive_secs,
            private_key: parse_key("wg client private_key", &self.private_key)?,
            peer_public_key: parse_key("wg client peer_public_key", &self.peer_public_key)?,
            peer_allowed_ips: normalize_allowed_ips(
                "wg client",
                &self.proxy_ips,
                &default_client_allowed_ips_for(self.tunnel_ip),
            )?,
            excluded_ips: self.normalized_direct_ips()?,
        };
        runtime.validate("wg client")?;

        // Surface key/engine issues early without touching the real device lifecycle.
        let mut tunnel = runtime.new_tunnel(1);
        let mut buffer = [0u8; super::HANDSHAKE_BUFFER_SIZE];
        match tunnel.format_handshake_initiation(&mut buffer, false) {
            TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
            TunnResult::Err(err) => {
                return Err(anyhow::anyhow!(
                    "failed to bootstrap boringtun handshake for wg client: {err:?}"
                ));
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("wg client handshake bootstrap returned an unexpected tunnel packet");
            }
        }

        Ok(runtime)
    }

    fn normalized_direct_ips(&self) -> Result<Vec<String>> {
        let mut direct = normalize_allowed_ips("wg client direct", &self.direct_ips, &[])?;
        direct.sort();
        direct.dedup();
        Ok(direct)
    }

    pub(crate) fn obfs_profile(&self) -> WgObfsProfile {
        WgObfsProfile {
            padding_min: self.obfs_padding_min,
            padding_max: self.obfs_padding_max,
            handshake_padding: self.obfs_handshake_padding,
            response_padding: self.obfs_response_padding,
            junk_packets: self.obfs_junk_packets,
            jitter_ms: self.obfs_jitter_ms,
        }
    }
}

fn domain_rules_need_dns_capture(domain_rules: &RouteRuleConfig) -> bool {
    !domain_rules.direct.is_empty() || !domain_rules.block.is_empty()
}

#[cfg(test)]
mod tests {
    use super::{
        WG_CLIENT_RECOVERY_INITIAL_DELAY, WgClientArgs, WgClientNetworkNotReady,
        is_recoverable_udp_path_error, next_recovery_delay, plan_lines, probe_server_handshake,
        udp_os_error_name,
    };
    use crate::proxy::route::RouteRuleConfig;
    use crate::wg::{
        HANDSHAKE_BUFFER_SIZE, WgEngine, WgObfsMode, WgObfsProfile, WgRuntimeConfig,
        default_client_allowed_ips, default_server_allowed_ips, hooks::HookPlan, noise,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boringtun::{
        noise::TunnResult,
        x25519::{PublicKey, StaticSecret},
    };
    use std::{
        io,
        net::{IpAddr, Ipv4Addr, SocketAddr},
        time::Duration,
    };
    use tokio::{net::UdpSocket, task::JoinHandle};

    #[test]
    fn client_args_resolve_runtime() {
        let args = WgClientArgs {
            engine: WgEngine::Device,
            obfs: WgObfsMode::Off,
            obfs_padding_min: 0,
            obfs_padding_max: 128,
            obfs_handshake_padding: None,
            obfs_response_padding: None,
            obfs_junk_packets: 0,
            obfs_jitter_ms: 0,
            bind: "0.0.0.0:0".to_owned(),
            endpoint: "198.51.100.10:51820".to_owned(),
            private_key: STANDARD.encode([1u8; 32]),
            peer_public_key: STANDARD.encode([2u8; 32]),
            device: "auto".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            dns: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            dns_capture: false,
            proxy_ips: Vec::new(),
            direct_ips: Vec::new(),
            domain_rules: RouteRuleConfig::default(),
            adblock: Default::default(),
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
            skip_handshake_probe: false,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let runtime = args.resolve().unwrap();
        assert_eq!(runtime.bind, SocketAddr::from(([0, 0, 0, 0], 0)));
        assert_eq!(
            runtime.endpoint,
            Some(SocketAddr::from(([198, 51, 100, 10], 51820)))
        );
        assert_eq!(runtime.tunnel_ip, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(runtime.peer_allowed_ips, vec!["0.0.0.0/0"]);
    }

    #[test]
    fn recovery_backoff_caps_at_ten_seconds() {
        let mut delay = WG_CLIENT_RECOVERY_INITIAL_DELAY;
        let mut observed = Vec::new();
        for _ in 0..6 {
            observed.push(delay);
            delay = next_recovery_delay(delay);
        }

        assert_eq!(
            observed,
            vec![
                Duration::from_secs(1),
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(10),
                Duration::from_secs(10),
            ]
        );
    }

    #[test]
    fn handshake_probe_send_errors_mark_local_network_not_ready() {
        for code in [
            libc::EADDRNOTAVAIL,
            libc::ENETDOWN,
            libc::ENETUNREACH,
            libc::EHOSTUNREACH,
        ] {
            assert!(is_recoverable_udp_path_error(
                &io::Error::from_raw_os_error(code)
            ));
        }
        assert!(!is_recoverable_udp_path_error(
            &io::Error::from_raw_os_error(libc::ECONNREFUSED)
        ));

        let endpoint = SocketAddr::from(([198, 51, 100, 10], 51820));
        let error = io::Error::from_raw_os_error(libc::ENETUNREACH);
        let network_not_ready =
            WgClientNetworkNotReady::from_udp_error("sending WG handshake probe", endpoint, &error);
        assert_eq!(network_not_ready.endpoint, endpoint);
        assert_eq!(network_not_ready.os_error, Some(libc::ENETUNREACH));
        assert_eq!(network_not_ready.os_error_name, "ENETUNREACH");
        assert_eq!(udp_os_error_name(libc::ENETUNREACH), Some("ENETUNREACH"));
    }

    #[test]
    fn client_args_preserve_custom_proxy_ips() {
        let args = WgClientArgs {
            engine: WgEngine::Device,
            obfs: WgObfsMode::Off,
            obfs_padding_min: 0,
            obfs_padding_max: 128,
            obfs_handshake_padding: None,
            obfs_response_padding: None,
            obfs_junk_packets: 0,
            obfs_jitter_ms: 0,
            bind: "0.0.0.0:0".to_owned(),
            endpoint: "198.51.100.10:51820".to_owned(),
            private_key: STANDARD.encode([1u8; 32]),
            peer_public_key: STANDARD.encode([2u8; 32]),
            device: "auto".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            dns: None,
            dns_capture: false,
            proxy_ips: vec!["203.0.113.0/24".to_owned()],
            direct_ips: Vec::new(),
            domain_rules: RouteRuleConfig::default(),
            adblock: Default::default(),
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
            skip_handshake_probe: false,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let runtime = args.resolve().unwrap();
        assert_eq!(runtime.peer_allowed_ips, vec!["203.0.113.0/24"]);
    }

    #[test]
    fn client_args_collect_direct_ips() {
        let args = WgClientArgs {
            engine: WgEngine::Device,
            obfs: WgObfsMode::Off,
            obfs_padding_min: 0,
            obfs_padding_max: 128,
            obfs_handshake_padding: None,
            obfs_response_padding: None,
            obfs_junk_packets: 0,
            obfs_jitter_ms: 0,
            bind: "0.0.0.0:0".to_owned(),
            endpoint: "198.51.100.10:51820".to_owned(),
            private_key: STANDARD.encode([1u8; 32]),
            peer_public_key: STANDARD.encode([2u8; 32]),
            device: "auto".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            dns: None,
            dns_capture: false,
            proxy_ips: Vec::new(),
            direct_ips: vec!["100.64.0.0/10".to_owned()],
            domain_rules: RouteRuleConfig::default(),
            adblock: Default::default(),
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
            skip_handshake_probe: false,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let runtime = args.resolve().unwrap();
        assert!(runtime.excluded_ips.contains(&"100.64.0.0/10".to_owned()));
    }

    #[test]
    fn client_args_reject_dns_capture_without_dns_upstream() {
        let args = WgClientArgs {
            engine: WgEngine::Device,
            obfs: WgObfsMode::Off,
            obfs_padding_min: 0,
            obfs_padding_max: 128,
            obfs_handshake_padding: None,
            obfs_response_padding: None,
            obfs_junk_packets: 0,
            obfs_jitter_ms: 0,
            bind: "0.0.0.0:0".to_owned(),
            endpoint: "198.51.100.10:51820".to_owned(),
            private_key: STANDARD.encode([1u8; 32]),
            peer_public_key: STANDARD.encode([2u8; 32]),
            device: "auto".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            dns: None,
            dns_capture: true,
            proxy_ips: Vec::new(),
            direct_ips: Vec::new(),
            domain_rules: RouteRuleConfig::default(),
            adblock: Default::default(),
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
            skip_handshake_probe: false,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let err = args.resolve().unwrap_err().to_string();
        assert!(err.contains("dns-capture"), "{err}");
    }

    #[test]
    fn client_plan_mentions_dns_and_hooks() {
        let args = WgClientArgs {
            engine: WgEngine::Device,
            obfs: WgObfsMode::Off,
            obfs_padding_min: 0,
            obfs_padding_max: 128,
            obfs_handshake_padding: None,
            obfs_response_padding: None,
            obfs_junk_packets: 0,
            obfs_jitter_ms: 0,
            bind: "0.0.0.0:0".to_owned(),
            endpoint: "198.51.100.10:51820".to_owned(),
            private_key: STANDARD.encode([1u8; 32]),
            peer_public_key: STANDARD.encode([2u8; 32]),
            device: "runnelwg0".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            dns: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            dns_capture: true,
            proxy_ips: vec!["203.0.113.0/24".to_owned()],
            direct_ips: Vec::new(),
            domain_rules: RouteRuleConfig::default(),
            adblock: Default::default(),
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: true,
            dry_run: true,
            skip_handshake_probe: false,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let runtime = args.resolve().unwrap();
        let lines = plan_lines(
            &args,
            "runnelwg0",
            &runtime,
            &HookPlan {
                up: vec!["ip route replace 203.0.113.0/24 dev runnelwg0".to_owned()],
                down: vec!["ip route del 203.0.113.0/24 dev runnelwg0".to_owned()],
            },
        );

        assert!(lines.iter().any(|line| line == "  dns: 1.1.1.1"));
        assert!(lines.iter().any(|line| line == "  dns_capture: true"));
        assert!(
            lines
                .iter()
                .any(|line| line == "    - ip route replace 203.0.113.0/24 dev runnelwg0")
        );
    }

    #[tokio::test]
    async fn handshake_probe_succeeds_when_keys_match() {
        let client_private = [0x11u8; 32];
        let server_private = [0x22u8; 32];
        let client_public = public_key(client_private);
        let server_public = public_key(server_private);
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = server_socket.local_addr().unwrap();
        let server_task = spawn_handshake_responder(
            server_socket,
            server_runtime(endpoint.port(), server_private, client_public),
            WgObfsMode::Off,
        );

        let client_runtime = client_runtime(endpoint, client_private, server_public);

        probe_server_handshake(
            &client_runtime,
            WgObfsMode::Off,
            WgObfsProfile::default(),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_probe_reports_friendly_error_when_wg_keys_do_not_match() {
        let client_private = [0x11u8; 32];
        let server_private = [0x22u8; 32];
        let wrong_server_private = [0x33u8; 32];
        let client_public = public_key(client_private);
        let wrong_server_public = public_key(wrong_server_private);
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = server_socket.local_addr().unwrap();
        let server_task = spawn_handshake_responder(
            server_socket,
            server_runtime(endpoint.port(), server_private, client_public),
            WgObfsMode::Off,
        );

        let client_runtime = client_runtime(endpoint, client_private, wrong_server_public);
        let err = probe_server_handshake(
            &client_runtime,
            WgObfsMode::Off,
            WgObfsProfile::default(),
            Duration::from_millis(100),
        )
        .await
        .expect_err("mismatched WG keys should fail the startup probe")
        .to_string();

        assert!(err.contains("WG keys may not match"), "{err}");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn handshake_probe_succeeds_with_mask_obfs() {
        let client_private = [0x11u8; 32];
        let server_private = [0x22u8; 32];
        let client_public = public_key(client_private);
        let server_public = public_key(server_private);
        let server_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let endpoint = server_socket.local_addr().unwrap();
        let server_task = spawn_handshake_responder(
            server_socket,
            server_runtime(endpoint.port(), server_private, client_public),
            WgObfsMode::Mask,
        );

        let client_runtime = client_runtime(endpoint, client_private, server_public);

        probe_server_handshake(
            &client_runtime,
            WgObfsMode::Mask,
            WgObfsProfile {
                padding_min: 4,
                padding_max: 4,
                handshake_padding: Some(32),
                response_padding: Some(24),
                junk_packets: 0,
                jitter_ms: 0,
            },
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    fn spawn_handshake_responder(
        socket: UdpSocket,
        runtime: WgRuntimeConfig,
        obfs: WgObfsMode,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tunnel = runtime.new_tunnel(2);
            let codec = noise::NoisePacketCodec::new(obfs, WgObfsProfile::default(), &runtime);
            let mut recv_buf = vec![0u8; noise::MAX_NOISE_UDP_PACKET_SIZE];
            let mut decoded_buf = [0u8; HANDSHAKE_BUFFER_SIZE];
            let mut send_buf = [0u8; HANDSHAKE_BUFFER_SIZE];
            let mut encoded_buf = vec![0u8; noise::MAX_NOISE_UDP_PACKET_SIZE];
            let Ok((len, addr)) = socket.recv_from(&mut recv_buf).await else {
                return;
            };
            let Ok(Some(decoded_len)) = codec.decode(&recv_buf[..len], &mut decoded_buf) else {
                return;
            };
            if let TunnResult::WriteToNetwork(packet) =
                tunnel.decapsulate(Some(addr.ip()), &decoded_buf[..decoded_len], &mut send_buf)
            {
                let Ok(encoded_len) = codec.encode(packet, &mut encoded_buf) else {
                    return;
                };
                let _ = socket.send_to(&encoded_buf[..encoded_len], addr).await;
            }
        })
    }

    fn client_runtime(
        endpoint: SocketAddr,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
    ) -> WgRuntimeConfig {
        WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            endpoint: Some(endpoint),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            private_key,
            peer_public_key,
            peer_allowed_ips: default_client_allowed_ips(),
            excluded_ips: Vec::new(),
        }
    }

    fn server_runtime(
        listen_port: u16,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
    ) -> WgRuntimeConfig {
        WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], listen_port)),
            endpoint: None,
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            mtu: 1420,
            persistent_keepalive_secs: None,
            private_key,
            peer_public_key,
            peer_allowed_ips: default_server_allowed_ips(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            excluded_ips: Vec::new(),
        }
    }

    fn public_key(private_key: [u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(private_key)).as_bytes()
    }
}
