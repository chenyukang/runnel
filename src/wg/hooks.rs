use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
    process::Command,
};
use tracing::{info, warn};

use super::WgRuntimeConfig;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RouteInfo {
    pub interface: Option<String>,
    pub gateway: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct HookPlan {
    pub up: Vec<String>,
    pub down: Vec<String>,
}

pub(crate) struct HookGuard {
    label: &'static str,
    hooks: Vec<String>,
}

impl HookGuard {
    pub(crate) fn new(label: &'static str, hooks: Vec<String>) -> Self {
        Self { label, hooks }
    }
}

impl Drop for HookGuard {
    fn drop(&mut self) {
        if self.hooks.is_empty() {
            return;
        }
        if let Err(err) = run_hooks(&self.hooks) {
            warn!(label = self.label, error = %err, "wg cleanup hooks failed");
        }
    }
}

pub(crate) fn run_hooks(hooks: &[String]) -> Result<()> {
    for hook in hooks {
        info!(hook = %hook, "running wg hook");
        let status = Command::new("/bin/sh")
            .arg("-lc")
            .arg(hook)
            .status()
            .with_context(|| format!("failed to spawn wg hook: {hook}"))?;
        if !status.success() {
            bail!("wg hook failed with status {status}: {hook}");
        }
    }
    Ok(())
}

pub(crate) fn effective_hook_plan(
    default: HookPlan,
    up_override: &[String],
    down_override: &[String],
) -> HookPlan {
    HookPlan {
        up: if up_override.is_empty() {
            default.up
        } else {
            up_override.to_vec()
        },
        down: if down_override.is_empty() {
            default.down
        } else {
            down_override.to_vec()
        },
    }
}

pub(crate) fn print_plan(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

pub(crate) fn log_plan_lines(lines: &[String]) {
    for line in lines {
        info!("{line}");
    }
}

pub(crate) fn plan_client_hooks(device: &str, runtime: &WgRuntimeConfig) -> Result<HookPlan> {
    let endpoint_ip = runtime
        .endpoint_ip()
        .context("wg client endpoint is required to build default hooks")?;
    let route = detect_egress_route(endpoint_ip)?;
    build_client_hook_plan(device, endpoint_ip, runtime, &route)
}

pub(crate) fn plan_server_hooks(
    device: &str,
    runtime: &WgRuntimeConfig,
    nat_out_interface: Option<&str>,
) -> Result<HookPlan> {
    build_server_hook_plan(device, runtime, nat_out_interface)
}

pub(crate) fn build_client_hook_plan(
    device: &str,
    endpoint_ip: IpAddr,
    runtime: &WgRuntimeConfig,
    route: &RouteInfo,
) -> Result<HookPlan> {
    let local = ensure_ipv4(runtime.tunnel_ip, "wg client tunnel_ip")?;
    let peer = ensure_ipv4(runtime.peer_tunnel_ip, "wg client peer_tunnel_ip")?;
    let endpoint = ensure_ipv4(endpoint_ip, "wg client endpoint ip")?;
    let routes = allowed_ipv4_routes("wg client", &runtime.peer_allowed_ips)?;

    #[cfg(target_os = "macos")]
    {
        if route.interface.is_none() {
            bail!(
                "failed to determine macOS outbound interface for {}; explicit hooks are required",
                endpoint
            );
        }

        let mut up = vec![format!("ifconfig {device} inet {local} {peer} up")];
        up.push(default_macos_bypass_route(endpoint, route));
        up.extend(
            routes
                .iter()
                .map(|route| macos_add_route_command(*route, peer)),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| macos_delete_route_command(*route))
            .collect::<Vec<_>>();
        down.push(format!(
            "route -q -n delete -host {endpoint} >/dev/null 2>&1 || true"
        ));
        down.push(format!("ifconfig {device} down >/dev/null 2>&1 || true"));
        return Ok(HookPlan { up, down });
    }

    #[cfg(target_os = "linux")]
    {
        if route.interface.is_none() {
            bail!(
                "failed to determine linux outbound interface for {}; explicit hooks are required",
                endpoint
            );
        }

        let bypass = match route.gateway.as_deref() {
            Some(gateway) if !gateway.is_empty() => {
                format!(
                    "ip route replace {endpoint}/32 via {gateway} dev {}",
                    route.interface.as_deref().unwrap()
                )
            }
            _ => format!(
                "ip route replace {endpoint}/32 dev {}",
                route.interface.as_deref().unwrap()
            ),
        };

        let mut up = vec![
            format!("ip address add {local} peer {peer} dev {device}"),
            format!("ip link set mtu {} up dev {device}", runtime.mtu),
            bypass,
        ];
        up.extend(
            routes
                .iter()
                .map(|route| format!("ip route replace {route} dev {device}")),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| format!("ip route del {route} dev {device} >/dev/null 2>&1 || true"))
            .collect::<Vec<_>>();
        down.push(format!(
            "ip route del {endpoint}/32 >/dev/null 2>&1 || true"
        ));
        down.push(format!(
            "ip address del {local} peer {peer} dev {device} >/dev/null 2>&1 || true"
        ));
        down.push(format!(
            "ip link set dev {device} down >/dev/null 2>&1 || true"
        ));
        return Ok(HookPlan { up, down });
    }

    #[allow(unreachable_code)]
    Ok(HookPlan::default())
}

pub(crate) fn build_server_hook_plan(
    device: &str,
    runtime: &WgRuntimeConfig,
    nat_out_interface: Option<&str>,
) -> Result<HookPlan> {
    let local = ensure_ipv4(runtime.tunnel_ip, "wg server tunnel_ip")?;
    let peer = ensure_ipv4(runtime.peer_tunnel_ip, "wg server peer_tunnel_ip")?;
    let peer_host_route = Ipv4Net::new(peer, 32).expect("valid /32 peer route");
    let routes = allowed_ipv4_routes("wg server", &runtime.peer_allowed_ips)?
        .into_iter()
        .filter(|route| route != &peer_host_route)
        .collect::<Vec<_>>();

    #[cfg(target_os = "macos")]
    {
        let mut up = vec![format!("ifconfig {device} inet {local} {peer} up")];
        up.extend(
            routes
                .iter()
                .map(|route| macos_add_route_command(*route, peer)),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| macos_delete_route_command(*route))
            .collect::<Vec<_>>();
        down.push(format!("ifconfig {device} down >/dev/null 2>&1 || true"));

        if nat_out_interface.is_some() {
            warn!("wg server nat_out_interface is currently ignored on macOS");
        }

        return Ok(HookPlan { up, down });
    }

    #[cfg(target_os = "linux")]
    {
        let mut up = vec![
            format!("ip address add {local} peer {peer} dev {device}"),
            format!("ip link set mtu {} up dev {device}", runtime.mtu),
        ];
        up.extend(
            routes
                .iter()
                .map(|route| format!("ip route replace {route} dev {device}")),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| format!("ip route del {route} dev {device} >/dev/null 2>&1 || true"))
            .collect::<Vec<_>>();
        down.push(format!(
            "ip address del {local} peer {peer} dev {device} >/dev/null 2>&1 || true"
        ));
        down.push(format!(
            "ip link set dev {device} down >/dev/null 2>&1 || true"
        ));

        if let Some(nat_if) = nat_out_interface {
            up.push("sysctl -w net.ipv4.ip_forward=1 >/dev/null".to_owned());
            up.push(format!("iptables -A FORWARD -i {device} -j ACCEPT"));
            up.push(format!(
                "iptables -A FORWARD -o {device} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
            ));
            up.push(format!(
                "iptables -t nat -A POSTROUTING -o {nat_if} -j MASQUERADE"
            ));

            down.insert(
                0,
                format!(
                    "iptables -t nat -D POSTROUTING -o {nat_if} -j MASQUERADE >/dev/null 2>&1 || true"
                ),
            );
            down.insert(
                0,
                format!(
                    "iptables -D FORWARD -o {device} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 || true"
                ),
            );
            down.insert(
                0,
                format!("iptables -D FORWARD -i {device} -j ACCEPT >/dev/null 2>&1 || true"),
            );
        }

        return Ok(HookPlan { up, down });
    }

    #[allow(unreachable_code)]
    Ok(HookPlan::default())
}

fn allowed_ipv4_routes(role: &str, allowed_ips: &[String]) -> Result<Vec<Ipv4Net>> {
    let mut routes = BTreeSet::new();
    for allowed_ip in allowed_ips {
        let net = allowed_ip
            .parse::<IpNet>()
            .with_context(|| format!("{role} allowed_ip must be CIDR, got {allowed_ip}"))?;
        match net {
            IpNet::V4(net) if net.prefix_len() == 0 => {
                routes.extend(split_default_ipv4_routes());
            }
            IpNet::V4(net) => {
                routes.insert(net.trunc());
            }
            IpNet::V6(_) => {
                bail!(
                    "{role} automatic hooks currently only support IPv4 allowed_ips; got {allowed_ip}"
                );
            }
        }
    }
    Ok(routes.into_iter().collect())
}

fn split_default_ipv4_routes() -> [Ipv4Net; 2] {
    [
        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 1).expect("valid split default route"),
        Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).expect("valid split default route"),
    ]
}

#[cfg(target_os = "macos")]
fn macos_add_route_command(route: Ipv4Net, gateway: Ipv4Addr) -> String {
    let rendered = route.to_string();
    if route.prefix_len() == 32 {
        let host = rendered.trim_end_matches("/32");
        format!(
            "route -q -n add -host {host} {gateway} >/dev/null 2>&1 || route -q -n change -host {host} {gateway}"
        )
    } else {
        format!(
            "route -q -n add -net {rendered} {gateway} >/dev/null 2>&1 || route -q -n change -net {rendered} {gateway}"
        )
    }
}

#[cfg(target_os = "macos")]
fn macos_delete_route_command(route: Ipv4Net) -> String {
    let rendered = route.to_string();
    if route.prefix_len() == 32 {
        let host = rendered.trim_end_matches("/32");
        format!("route -q -n delete -host {host} >/dev/null 2>&1 || true")
    } else {
        format!("route -q -n delete -net {rendered} >/dev/null 2>&1 || true")
    }
}

fn ensure_ipv4(ip: IpAddr, label: &str) -> Result<Ipv4Addr> {
    match ip {
        IpAddr::V4(ip) => Ok(ip),
        IpAddr::V6(_) => bail!("{label} currently only supports IPv4 automatic hooks"),
    }
}

#[cfg(target_os = "macos")]
fn default_macos_bypass_route(endpoint: Ipv4Addr, route: &RouteInfo) -> String {
    match route.gateway.as_deref() {
        Some(gateway) if !gateway.is_empty() => format!(
            "route -q -n add -host {endpoint} {gateway} >/dev/null 2>&1 || route -q -n change -host {endpoint} {gateway}"
        ),
        _ => format!(
            "route -q -n add -host {endpoint} -interface {} >/dev/null 2>&1 || route -q -n change -host {endpoint} -interface {}",
            route.interface.as_deref().unwrap_or(""),
            route.interface.as_deref().unwrap_or("")
        ),
    }
}

fn detect_egress_route(target: IpAddr) -> Result<RouteInfo> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args(["-n", "get", &target.to_string()])
            .output()
            .with_context(|| format!("failed to inspect route to {target}"))?;
        if !output.status.success() {
            bail!(
                "failed to inspect route to {target}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        return parse_macos_route_get(&String::from_utf8_lossy(&output.stdout));
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "get", &target.to_string()])
            .output()
            .with_context(|| format!("failed to inspect route to {target}"))?;
        if !output.status.success() {
            bail!(
                "failed to inspect route to {target}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        return parse_linux_route_get(&String::from_utf8_lossy(&output.stdout));
    }

    #[allow(unreachable_code)]
    Ok(RouteInfo {
        interface: None,
        gateway: None,
    })
}

#[cfg(target_os = "macos")]
fn parse_macos_route_get(output: &str) -> Result<RouteInfo> {
    let mut interface = None;
    let mut gateway = None;
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("interface:") {
            interface = Some(value.trim().to_owned());
        } else if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = Some(value.trim().to_owned());
        }
    }

    if interface.is_none() {
        bail!("route output did not include an interface");
    }

    Ok(RouteInfo { interface, gateway })
}

#[cfg(target_os = "linux")]
fn parse_linux_route_get(output: &str) -> Result<RouteInfo> {
    let tokens = output.split_whitespace().collect::<Vec<_>>();
    let mut interface = None;
    let mut gateway = None;
    for window in tokens.windows(2) {
        match window {
            ["dev", value] => interface = Some((*value).to_owned()),
            ["via", value] => gateway = Some((*value).to_owned()),
            _ => {}
        }
    }

    if interface.is_none() {
        bail!("linux route output did not include an interface");
    }

    Ok(RouteInfo { interface, gateway })
}

#[cfg(test)]
mod tests {
    use super::{RouteInfo, build_client_hook_plan};
    use crate::wg::{WgRuntimeConfig, default_client_allowed_ips};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn client_runtime() -> WgRuntimeConfig {
        WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            endpoint: Some(SocketAddr::from(([198, 51, 100, 10], 51820))),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            private_key: [1u8; 32],
            peer_public_key: [2u8; 32],
            peer_allowed_ips: default_client_allowed_ips(),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_client_hook_plan_installs_split_default_routes() {
        let plan = build_client_hook_plan(
            "utun123",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            &client_runtime(),
            &RouteInfo {
                interface: Some("en0".to_owned()),
                gateway: Some("192.168.3.1".to_owned()),
            },
        )
        .unwrap();

        assert_eq!(
            plan.up.first().map(String::as_str),
            Some("ifconfig utun123 inet 10.8.0.2 10.8.0.1 up")
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("route -q -n add -host 198.51.100.10 192.168.3.1"))
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("route -q -n add -net 0.0.0.0/1 10.8.0.1"))
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("route -q -n add -net 128.0.0.0/1 10.8.0.1"))
        );
        assert!(
            plan.down
                .iter()
                .any(|hook| hook.contains("ifconfig utun123 down"))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_client_hook_plan_uses_custom_allowed_routes() {
        let mut runtime = client_runtime();
        runtime.peer_allowed_ips = vec!["203.0.113.0/24".to_owned(), "198.18.0.2/32".to_owned()];
        let plan = build_client_hook_plan(
            "utun123",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            &runtime,
            &RouteInfo {
                interface: Some("en0".to_owned()),
                gateway: Some("192.168.3.1".to_owned()),
            },
        )
        .unwrap();

        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("add -net 203.0.113.0/24 10.8.0.1"))
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("add -host 198.18.0.2 10.8.0.1"))
        );
        assert!(!plan.up.iter().any(|hook| hook.contains("0.0.0.0/1")));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_client_hook_plan_installs_split_default_routes() {
        let plan = build_client_hook_plan(
            "pipitwg0",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            &client_runtime(),
            &RouteInfo {
                interface: Some("eth0".to_owned()),
                gateway: Some("192.168.1.1".to_owned()),
            },
        )
        .unwrap();

        assert_eq!(
            plan.up.first().map(String::as_str),
            Some("ip address add 10.8.0.2 peer 10.8.0.1 dev pipitwg0")
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook == "ip route replace 0.0.0.0/1 dev pipitwg0")
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook == "ip route replace 128.0.0.0/1 dev pipitwg0")
        );
        assert!(
            plan.down
                .iter()
                .any(|hook| hook.contains("ip link set dev pipitwg0 down"))
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_client_hook_plan_uses_custom_allowed_routes() {
        let mut runtime = client_runtime();
        runtime.peer_allowed_ips = vec!["203.0.113.0/24".to_owned(), "198.18.0.2/32".to_owned()];
        let plan = build_client_hook_plan(
            "pipitwg0",
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            &runtime,
            &RouteInfo {
                interface: Some("eth0".to_owned()),
                gateway: Some("192.168.1.1".to_owned()),
            },
        )
        .unwrap();

        assert!(
            plan.up
                .iter()
                .any(|hook| hook == "ip route replace 203.0.113.0/24 dev pipitwg0")
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook == "ip route replace 198.18.0.2/32 dev pipitwg0")
        );
        assert!(
            !plan
                .up
                .iter()
                .any(|hook| hook == "ip route replace 0.0.0.0/1 dev pipitwg0")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_server_hook_plan_adds_nat_rules_and_peer_routes_when_requested() {
        use super::{HookPlan, build_server_hook_plan};

        let runtime = WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 51820)),
            endpoint: None,
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            mtu: 1420,
            persistent_keepalive_secs: None,
            private_key: [3u8; 32],
            peer_public_key: [4u8; 32],
            peer_allowed_ips: vec!["10.9.0.0/24".to_owned(), "10.8.0.2/32".to_owned()],
        };

        let HookPlan { up, down } =
            build_server_hook_plan("pipitwg0", &runtime, Some("eth0")).unwrap();
        assert!(up.iter().any(|hook| hook.contains("net.ipv4.ip_forward=1")));
        assert!(
            up.iter()
                .any(|hook| hook == "ip route replace 10.9.0.0/24 dev pipitwg0")
        );
        assert!(
            !up.iter()
                .any(|hook| hook == "ip route replace 10.8.0.2/32 dev pipitwg0")
        );
        assert!(
            up.iter()
                .any(|hook| hook.contains("POSTROUTING -o eth0 -j MASQUERADE"))
        );
        assert!(
            down.iter()
                .any(|hook| hook.contains("-D POSTROUTING -o eth0 -j MASQUERADE"))
        );
    }
}
