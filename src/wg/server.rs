use super::{
    DEFAULT_TUNNEL_MTU, WgRuntimeConfig, create_device_handle, default_server_allowed_ips,
    hooks::{
        HookGuard, effective_hook_plan, log_plan_lines, plan_server_hooks, print_plan, run_hooks,
    },
    normalize_allowed_ips, parse_key, parse_socket_addr,
    preflight::{WgPreflightRole, check as check_preflight},
    select_device_name,
    stats::{start_stats_poller, start_unhandshaken_peer_refresher},
    tcpdump::{self, TcpdumpFilter},
    uapi::{apply_device_config, control_socket_path},
    wait_for_shutdown_signal,
};
use anyhow::{Result, bail};
use clap::Args;
use std::{net::IpAddr, time::Duration};
use tracing::info;

const UNHANDSHAKEN_PEER_REFRESH_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Args)]
pub struct WgServerArgs {
    #[arg(long, default_value = "0.0.0.0:51820")]
    pub listen: String,
    #[arg(long, env = "RUNNEL_WG_PRIVATE_KEY")]
    #[arg(default_value = "")]
    pub private_key: String,
    #[arg(long)]
    #[arg(default_value = "")]
    pub peer_public_key: String,
    #[arg(long, default_value = "auto")]
    pub device: String,
    #[arg(long, default_value = "10.8.0.1")]
    pub tunnel_ip: IpAddr,
    #[arg(long, default_value = "10.8.0.2")]
    pub peer_tunnel_ip: IpAddr,
    #[arg(long = "peer-allowed-ip")]
    pub peer_allowed_ips: Vec<String>,
    #[arg(long)]
    pub nat_out_interface: Option<String>,
    #[arg(long, default_value_t = DEFAULT_TUNNEL_MTU)]
    pub mtu: u16,
    #[arg(long)]
    pub up: Vec<String>,
    #[arg(long)]
    pub down: Vec<String>,
    #[arg(long)]
    pub print_hooks: bool,
    #[arg(long)]
    pub dry_run: bool,
    #[arg(long)]
    pub tcpdump: bool,
    #[arg(long)]
    pub tcpdump_interface: Option<String>,
}

impl Default for WgServerArgs {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:51820".to_owned(),
            private_key: String::new(),
            peer_public_key: String::new(),
            device: "auto".to_owned(),
            tunnel_ip: "10.8.0.1".parse().expect("valid default WG server IP"),
            peer_tunnel_ip: "10.8.0.2".parse().expect("valid default WG peer IP"),
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            mtu: DEFAULT_TUNNEL_MTU,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: false,
            tcpdump: false,
            tcpdump_interface: None,
        }
    }
}

pub async fn run(args: WgServerArgs) -> Result<()> {
    let runtime = args.resolve()?;
    if !args.dry_run {
        check_preflight(
            WgPreflightRole::Server,
            false,
            args.nat_out_interface.is_some(),
        )?;
    }
    let planned_device = select_device_name(&args.device)?;
    let default_plan =
        plan_server_hooks(&planned_device, &runtime, args.nat_out_interface.as_deref())?;
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
    start_stats_poller("wg-server", socket_path.clone());
    let _tcpdump = args.tcpdump.then(|| {
        tcpdump::start(
            "wg-server",
            args.tcpdump_interface.as_deref(),
            TcpdumpFilter::Server {
                listen: runtime.bind,
            },
        )
    });
    start_unhandshaken_peer_refresher(
        "wg-server",
        socket_path.clone(),
        runtime.clone(),
        UNHANDSHAKEN_PEER_REFRESH_INTERVAL,
    );
    let plan = effective_hook_plan(
        plan_server_hooks(&actual_device, &runtime, args.nat_out_interface.as_deref())?,
        &args.up,
        &args.down,
    );
    run_hooks(&plan.up)?;

    // Keep the device alive until shutdown; cleanup hooks run first on drop.
    let _cleanup = HookGuard::new("wg-server", plan.down);

    info!(
        device = %actual_device,
        listen = %runtime.bind,
        tunnel_ip = %runtime.tunnel_ip,
        peer_tunnel_ip = %runtime.peer_tunnel_ip,
        mtu = runtime.mtu,
        nat_out_interface = ?args.nat_out_interface,
        uapi_socket = %socket_path.display(),
        "wg server started"
    );

    wait_for_shutdown_signal().await
}

fn plan_lines(
    args: &WgServerArgs,
    device: &str,
    runtime: &WgRuntimeConfig,
    plan: &super::hooks::HookPlan,
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("runnel wg-server plan".to_owned());
    if super::is_auto_device(&args.device) {
        lines.push(format!("  device: {device} (auto)"));
    } else {
        lines.push(format!("  device: {device}"));
    }
    lines.push(format!("  listen: {}", runtime.bind));
    lines.push(format!("  tunnel_ip: {}", runtime.tunnel_ip));
    lines.push(format!("  peer_tunnel_ip: {}", runtime.peer_tunnel_ip));
    lines.push(format!(
        "  peer_allowed_ips: {}",
        runtime.peer_allowed_ips.join(", ")
    ));
    lines.push(format!(
        "  nat_out_interface: {}",
        args.nat_out_interface.as_deref().unwrap_or("-")
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

impl WgServerArgs {
    pub fn validate_required(&self) -> Result<()> {
        if self.private_key.trim().is_empty() {
            bail!(
                "wg server private_key is required; pass --private-key, set RUNNEL_WG_PRIVATE_KEY, or set it in --config"
            );
        }
        if self.peer_public_key.trim().is_empty() {
            bail!(
                "wg server peer_public_key is required; pass --peer-public-key or set it in --config"
            );
        }
        Ok(())
    }

    pub(crate) fn resolve(&self) -> Result<WgRuntimeConfig> {
        self.validate_required()?;
        let runtime = WgRuntimeConfig {
            bind: parse_socket_addr("wg server listen", &self.listen)?,
            endpoint: None,
            tunnel_ip: self.tunnel_ip,
            peer_tunnel_ip: self.peer_tunnel_ip,
            mtu: self.mtu,
            persistent_keepalive_secs: None,
            private_key: parse_key("wg server private_key", &self.private_key)?,
            peer_public_key: parse_key("wg server peer_public_key", &self.peer_public_key)?,
            peer_allowed_ips: normalize_allowed_ips(
                "wg server",
                &self.peer_allowed_ips,
                &default_server_allowed_ips(self.peer_tunnel_ip),
            )?,
            excluded_ips: Vec::new(),
        };
        runtime.validate("wg server")?;
        Ok(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::WgServerArgs;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn server_args_resolve_runtime() {
        let args = WgServerArgs {
            listen: "0.0.0.0:51820".to_owned(),
            private_key: STANDARD.encode([3u8; 32]),
            peer_public_key: STANDARD.encode([4u8; 32]),
            device: "auto".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_allowed_ips: Vec::new(),
            nat_out_interface: Some("en0".to_owned()),
            mtu: 1420,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let runtime = args.resolve().unwrap();
        assert_eq!(runtime.bind, SocketAddr::from(([0, 0, 0, 0], 51820)));
        assert_eq!(runtime.endpoint, None);
        assert_eq!(runtime.tunnel_ip, IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)));
        assert_eq!(runtime.peer_allowed_ips, vec!["10.8.0.2/32"]);
    }

    #[test]
    fn server_args_preserve_custom_peer_allowed_ips() {
        let args = WgServerArgs {
            listen: "0.0.0.0:51820".to_owned(),
            private_key: STANDARD.encode([3u8; 32]),
            peer_public_key: STANDARD.encode([4u8; 32]),
            device: "auto".to_owned(),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_allowed_ips: vec!["10.9.0.0/24".to_owned()],
            nat_out_interface: None,
            mtu: 1420,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: false,
            dry_run: true,
            tcpdump: false,
            tcpdump_interface: None,
        };

        let runtime = args.resolve().unwrap();
        assert_eq!(runtime.peer_allowed_ips, vec!["10.9.0.0/24"]);
    }
}
