use super::{
    DEFAULT_TUNNEL_MTU, HookGuard, WgPreflightRole, WgRuntimeConfig, apply_device_config,
    control_socket_path, create_device_handle, default_client_allowed_ips_for,
    default_client_excluded_lan_ips, effective_hook_plan, log_plan_lines, normalize_allowed_ips,
    parse_key, parse_socket_addr, plan_client_hooks, print_plan, select_device_name,
    start_dns_capture, start_stats_poller, wait_for_shutdown_signal,
};
use anyhow::{Context, Result, bail};
use boringtun::noise::TunnResult;
use clap::Args;
use std::net::IpAddr;
use tracing::{info, warn};

use crate::system_proxy;

#[derive(Clone, Debug, Args)]
pub struct WgClientArgs {
    #[arg(long, default_value = "0.0.0.0:0")]
    pub bind: String,
    #[arg(long)]
    #[arg(default_value = "")]
    pub endpoint: String,
    #[arg(long, env = "PIPIT_WG_PRIVATE_KEY")]
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
    #[arg(long = "allowed-ip")]
    pub allowed_ips: Vec<String>,
    #[arg(long = "exclude-ip")]
    pub excluded_ips: Vec<String>,
    #[arg(long)]
    pub exclude_lan: bool,
    #[arg(long)]
    pub up: Vec<String>,
    #[arg(long)]
    pub down: Vec<String>,
    #[arg(long)]
    pub print_hooks: bool,
    #[arg(long)]
    pub dry_run: bool,
}

impl Default for WgClientArgs {
    fn default() -> Self {
        Self {
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
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: false,
        }
    }
}

pub async fn run(args: WgClientArgs) -> Result<()> {
    let runtime = args.resolve()?;
    if args.dns.is_some() && !args.dns_capture {
        warn!(
            "wg DNS capture is disabled; TUI Recent Domains requires --dns-capture or client.wg.dns_capture: true"
        );
    }
    if !args.dry_run {
        super::check_preflight(
            WgPreflightRole::Client,
            args.dns.is_some() || args.dns_capture,
            false,
        )?;
    }
    let planned_device = select_device_name(&args.device)?;
    let default_plan = plan_client_hooks(&planned_device, &runtime)?;
    let plan = effective_hook_plan(default_plan, &args.up, &args.down);

    if args.print_hooks || args.dry_run {
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

    let (_device_handle, actual_device) = create_device_handle(&args.device)?;
    let socket_path = control_socket_path(&actual_device);
    apply_device_config(&socket_path, &runtime)?;
    start_stats_poller("wg-client", socket_path.clone());
    let plan = effective_hook_plan(
        plan_client_hooks(&actual_device, &runtime)?,
        &args.up,
        &args.down,
    );
    super::run_hooks(&plan.up)?;

    // Keep the device alive until we receive a shutdown signal. The guard is declared
    // after the handle so cleanup hooks run before the device file descriptor closes.
    let _cleanup = HookGuard::new("wg-client", plan.down);
    let _dns_capture = match (args.dns_capture, args.dns) {
        (true, Some(dns)) => Some(start_dns_capture(dns).await?),
        (true, None) => bail!("wg client --dns-capture requires --dns as the upstream resolver"),
        (false, _) => None,
    };
    let _dns_guard = match (args.dns, args.dns_capture) {
        (Some(_), true) => system_proxy::maybe_activate_tun_dns(&["127.0.0.1".to_owned()])?,
        (Some(dns), false) => system_proxy::maybe_activate_tun_dns(&[dns.to_string()])?,
        (None, _) => None,
    };

    info!(
        device = %actual_device,
        endpoint = %runtime.endpoint.context("wg client endpoint missing")?,
        tunnel_ip = %runtime.tunnel_ip,
        peer_tunnel_ip = %runtime.peer_tunnel_ip,
        dns = ?args.dns,
        dns_capture = args.dns_capture,
        mtu = runtime.mtu,
        uapi_socket = %socket_path.display(),
        "wg client started"
    );

    wait_for_shutdown_signal().await
}

fn plan_lines(
    args: &WgClientArgs,
    device: &str,
    runtime: &WgRuntimeConfig,
    plan: &super::hooks::HookPlan,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("pipit wg-client plan".to_owned());
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
        "  allowed_ips: {}",
        runtime.peer_allowed_ips.join(", ")
    ));
    lines.push(format!(
        "  excluded_ips: {}",
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

impl WgClientArgs {
    pub fn validate_required(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            bail!("wg client endpoint is required; pass --endpoint or set it in --config");
        }
        if self.private_key.trim().is_empty() {
            bail!(
                "wg client private_key is required; pass --private-key, set PIPIT_WG_PRIVATE_KEY, or set it in --config"
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
                &self.allowed_ips,
                &default_client_allowed_ips_for(self.tunnel_ip),
            )?,
            excluded_ips: self.normalized_excluded_ips()?,
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

    fn normalized_excluded_ips(&self) -> Result<Vec<String>> {
        let mut excluded = normalize_allowed_ips("wg client exclude", &self.excluded_ips, &[])?;
        if self.exclude_lan {
            excluded.extend(default_client_excluded_lan_ips());
        }
        excluded.sort();
        excluded.dedup();
        Ok(excluded)
    }
}

#[cfg(test)]
mod tests {
    use super::{WgClientArgs, plan_lines};
    use crate::wg::hooks::HookPlan;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn client_args_resolve_runtime() {
        let args = WgClientArgs {
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
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
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
    fn client_args_preserve_custom_allowed_ips() {
        let args = WgClientArgs {
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
            allowed_ips: vec!["203.0.113.0/24".to_owned()],
            excluded_ips: Vec::new(),
            exclude_lan: false,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
        };

        let runtime = args.resolve().unwrap();
        assert_eq!(runtime.peer_allowed_ips, vec!["203.0.113.0/24"]);
    }

    #[test]
    fn client_args_collect_excluded_ips_and_lan_excludes() {
        let args = WgClientArgs {
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
            allowed_ips: Vec::new(),
            excluded_ips: vec!["100.64.0.0/10".to_owned()],
            exclude_lan: true,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
        };

        let runtime = args.resolve().unwrap();
        assert!(runtime.excluded_ips.contains(&"100.64.0.0/10".to_owned()));
        assert!(runtime.excluded_ips.contains(&"192.168.0.0/16".to_owned()));
    }

    #[test]
    fn client_args_reject_dns_capture_without_dns_upstream() {
        let args = WgClientArgs {
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
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
        };

        let err = args.resolve().unwrap_err().to_string();
        assert!(err.contains("dns-capture"), "{err}");
    }

    #[test]
    fn client_plan_mentions_dns_and_hooks() {
        let args = WgClientArgs {
            bind: "0.0.0.0:0".to_owned(),
            endpoint: "198.51.100.10:51820".to_owned(),
            private_key: STANDARD.encode([1u8; 32]),
            peer_public_key: STANDARD.encode([2u8; 32]),
            device: "pipitwg0".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            dns: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            dns_capture: true,
            allowed_ips: vec!["203.0.113.0/24".to_owned()],
            excluded_ips: Vec::new(),
            exclude_lan: false,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: true,
            dry_run: true,
        };

        let runtime = args.resolve().unwrap();
        let lines = plan_lines(
            &args,
            "pipitwg0",
            &runtime,
            &HookPlan {
                up: vec!["ip route replace 203.0.113.0/24 dev pipitwg0".to_owned()],
                down: vec!["ip route del 203.0.113.0/24 dev pipitwg0".to_owned()],
            },
        );

        assert!(lines.iter().any(|line| line == "  dns: 1.1.1.1"));
        assert!(lines.iter().any(|line| line == "  dns_capture: true"));
        assert!(
            lines
                .iter()
                .any(|line| line == "    - ip route replace 203.0.113.0/24 dev pipitwg0")
        );
    }
}
