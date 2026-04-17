use anyhow::{Context, Result, bail};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    process::Command,
    sync::Mutex,
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

pub(crate) struct DynamicRouteManager {
    route: RouteInfo,
    tunnel: TunnelPair,
    direct_hosts: Mutex<BTreeMap<IpAddr, String>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunnelPair {
    V4 { local: Ipv4Addr, peer: Ipv4Addr },
    V6 { local: Ipv6Addr, peer: Ipv6Addr },
}

impl TunnelPair {
    #[cfg(target_os = "macos")]
    fn peer_ip(self) -> IpAddr {
        match self {
            Self::V4 { peer, .. } => IpAddr::V4(peer),
            Self::V6 { peer, .. } => IpAddr::V6(peer),
        }
    }

    fn peer_host_route(self) -> IpNet {
        match self {
            Self::V4 { peer, .. } => IpNet::V4(Ipv4Net::new(peer, 32).expect("valid peer route")),
            Self::V6 { peer, .. } => IpNet::V6(Ipv6Net::new(peer, 128).expect("valid peer route")),
        }
    }

    fn family_label(self) -> &'static str {
        match self {
            Self::V4 { .. } => "IPv4",
            Self::V6 { .. } => "IPv6",
        }
    }

    fn supports_ip(self, ip: IpAddr) -> bool {
        matches!(
            (self, ip),
            (Self::V4 { .. }, IpAddr::V4(_)) | (Self::V6 { .. }, IpAddr::V6(_))
        )
    }
}

impl HookGuard {
    pub(crate) fn new(label: &'static str, hooks: Vec<String>) -> Self {
        Self { label, hooks }
    }
}

impl DynamicRouteManager {
    pub(crate) fn for_client(runtime: &WgRuntimeConfig) -> Result<Self> {
        let endpoint_ip = runtime
            .endpoint_ip()
            .context("wg client endpoint is required to build dynamic domain routes")?;
        let route = detect_egress_route(endpoint_ip)?;
        let tunnel = ensure_tunnel_pair(
            runtime.tunnel_ip,
            runtime.peer_tunnel_ip,
            "wg client tunnel_ip",
            "wg client peer_tunnel_ip",
        )?;
        Ok(Self {
            route,
            tunnel,
            direct_hosts: Mutex::new(BTreeMap::new()),
        })
    }

    pub(crate) fn add_direct_host(&self, domain: &str, ip: IpAddr) -> Result<bool> {
        if !self.tunnel.supports_ip(ip) {
            return Ok(false);
        }
        let mut direct_hosts = self.direct_hosts.lock().expect("dynamic route mutex");
        if direct_hosts.contains_key(&ip) {
            return Ok(false);
        }
        run_domain_route_hook(domain, ip, &direct_host_add_command(ip, &self.route))?;
        direct_hosts.insert(ip, domain.to_owned());
        Ok(true)
    }
}

impl Drop for DynamicRouteManager {
    fn drop(&mut self) {
        let hosts = self
            .direct_hosts
            .get_mut()
            .expect("dynamic route mutex")
            .iter()
            .map(|(ip, domain)| (*ip, domain.clone()))
            .collect::<Vec<_>>();
        for (ip, domain) in hosts.into_iter().rev() {
            if let Err(err) = run_domain_route_hook(&domain, ip, &direct_host_delete_command(ip)) {
                warn!(host = %ip, error = %err, "wg dynamic direct route cleanup failed");
            }
        }
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
        run_hook(hook, None, None)?;
    }
    Ok(())
}

fn run_domain_route_hook(domain: &str, ip: IpAddr, hook: &str) -> Result<()> {
    run_hook(hook, Some(domain), Some(ip))
}

fn run_hook(hook: &str, domain: Option<&str>, ip: Option<IpAddr>) -> Result<()> {
    match (domain, ip) {
        (Some(domain), Some(ip)) => {
            info!(hook = %hook, domain = %domain, ip = %ip, "running wg hook")
        }
        (Some(domain), None) => info!(hook = %hook, domain = %domain, "running wg hook"),
        (None, Some(ip)) => info!(hook = %hook, ip = %ip, "running wg hook"),
        (None, None) => info!(hook = %hook, "running wg hook"),
    }
    let status = Command::new("/bin/sh")
        .arg("-lc")
        .arg(hook)
        .status()
        .with_context(|| format!("failed to spawn wg hook: {hook}"))?;
    if !status.success() {
        bail!("wg hook failed with status {status}: {hook}");
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
    let tunnel = ensure_tunnel_pair(
        runtime.tunnel_ip,
        runtime.peer_tunnel_ip,
        "wg client tunnel_ip",
        "wg client peer_tunnel_ip",
    )?;
    let routes = allowed_routes("wg client", &runtime.peer_allowed_ips, tunnel)?;
    let excluded_routes = excluded_routes("wg client exclude", &runtime.excluded_ips, tunnel)?;
    let routes = exclude_routes(routes, &excluded_routes);

    #[cfg(target_os = "macos")]
    {
        if route.interface.is_none() {
            bail!(
                "failed to determine macOS outbound interface for {}; explicit hooks are required",
                endpoint_ip
            );
        }

        let mut up = vec![macos_ifconfig_command(device, tunnel, runtime.mtu)];
        up.push(macos_bypass_route(endpoint_ip, route));
        up.extend(
            routes
                .iter()
                .map(|route| macos_add_route_command(*route, tunnel.peer_ip())),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| macos_delete_route_command(*route))
            .collect::<Vec<_>>();
        down.push(macos_delete_host_route_command(endpoint_ip));
        down.push(format!("ifconfig {device} down >/dev/null 2>&1 || true"));
        return Ok(HookPlan { up, down });
    }

    #[cfg(target_os = "linux")]
    {
        if route.interface.is_none() {
            bail!(
                "failed to determine linux outbound interface for {}; explicit hooks are required",
                endpoint_ip
            );
        }

        let mut up = vec![
            linux_address_add_command(device, tunnel),
            format!("ip link set mtu {} up dev {device}", runtime.mtu),
            linux_bypass_route(endpoint_ip, route),
        ];
        up.extend(
            routes
                .iter()
                .map(|route| linux_add_route_command(*route, device)),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| linux_delete_route_command(*route, device))
            .collect::<Vec<_>>();
        down.push(linux_delete_host_route_command(endpoint_ip));
        down.push(linux_address_del_command(device, tunnel));
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
    let tunnel = ensure_tunnel_pair(
        runtime.tunnel_ip,
        runtime.peer_tunnel_ip,
        "wg server tunnel_ip",
        "wg server peer_tunnel_ip",
    )?;
    let peer_host_route = tunnel.peer_host_route();
    let routes = allowed_routes("wg server", &runtime.peer_allowed_ips, tunnel)?
        .into_iter()
        .filter(|route| route != &peer_host_route)
        .collect::<Vec<_>>();

    #[cfg(target_os = "macos")]
    {
        let mut up = vec![macos_ifconfig_command(device, tunnel, runtime.mtu)];
        up.extend(
            routes
                .iter()
                .map(|route| macos_add_route_command(*route, tunnel.peer_ip())),
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
            linux_address_add_command(device, tunnel),
            format!("ip link set mtu {} up dev {device}", runtime.mtu),
        ];
        up.extend(
            routes
                .iter()
                .map(|route| linux_add_route_command(*route, device)),
        );

        let mut down = routes
            .iter()
            .rev()
            .map(|route| linux_delete_route_command(*route, device))
            .collect::<Vec<_>>();
        down.push(linux_address_del_command(device, tunnel));
        down.push(format!(
            "ip link set dev {device} down >/dev/null 2>&1 || true"
        ));

        if let Some(nat_if) = nat_out_interface {
            if matches!(tunnel, TunnelPair::V6 { .. }) {
                bail!(
                    "wg server nat_out_interface automatic hooks currently only support IPv4 tunnels; use explicit --up/--down hooks for IPv6 routing/NAT"
                );
            }
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

fn allowed_routes(role: &str, allowed_ips: &[String], tunnel: TunnelPair) -> Result<Vec<IpNet>> {
    let mut result = BTreeSet::new();
    for allowed_ip in allowed_ips {
        let net = allowed_ip
            .parse::<IpNet>()
            .with_context(|| format!("{role} allowed_ip must be CIDR, got {allowed_ip}"))?;
        match (net, tunnel) {
            (IpNet::V4(net), TunnelPair::V4 { .. }) if net.prefix_len() == 0 => {
                result.extend(split_default_ipv4_routes().map(IpNet::V4));
            }
            (IpNet::V6(net), TunnelPair::V6 { .. }) if net.prefix_len() == 0 => {
                result.extend(split_default_ipv6_routes().map(IpNet::V6));
            }
            (IpNet::V4(net), TunnelPair::V4 { .. }) => {
                result.insert(IpNet::V4(net.trunc()));
            }
            (IpNet::V6(net), TunnelPair::V6 { .. }) => {
                result.insert(IpNet::V6(net.trunc()));
            }
            (net, tunnel) => {
                bail!(
                    "{role} automatic hooks use {} tunnel addresses but got mismatched allowed_ip {net}; use matching tunnel addresses or explicit --up/--down hooks",
                    tunnel.family_label()
                );
            }
        }
    }
    Ok(result.into_iter().collect())
}

fn excluded_routes(role: &str, excluded_ips: &[String], tunnel: TunnelPair) -> Result<Vec<IpNet>> {
    let mut result = BTreeSet::new();
    for excluded_ip in excluded_ips {
        let net = excluded_ip
            .parse::<IpNet>()
            .with_context(|| format!("{role} exclude_ip must be CIDR, got {excluded_ip}"))?;
        match (net, tunnel) {
            (IpNet::V4(net), TunnelPair::V4 { .. }) => {
                result.insert(IpNet::V4(net.trunc()));
            }
            (IpNet::V6(net), TunnelPair::V6 { .. }) => {
                result.insert(IpNet::V6(net.trunc()));
            }
            _ => {}
        }
    }
    Ok(result.into_iter().collect())
}

fn exclude_routes(routes: Vec<IpNet>, excluded_routes: &[IpNet]) -> Vec<IpNet> {
    let mut result = BTreeSet::new();
    for route in routes {
        let mut remaining = vec![route];
        for excluded in excluded_routes {
            remaining = remaining
                .into_iter()
                .flat_map(|candidate| subtract_route(candidate, *excluded))
                .collect();
        }
        result.extend(remaining);
    }
    result.into_iter().collect()
}

fn subtract_route(route: IpNet, excluded: IpNet) -> Vec<IpNet> {
    match (route, excluded) {
        (IpNet::V4(route), IpNet::V4(excluded)) => subtract_ipv4_route(route, excluded)
            .into_iter()
            .map(IpNet::V4)
            .collect(),
        (IpNet::V6(route), IpNet::V6(excluded)) => subtract_ipv6_route(route, excluded)
            .into_iter()
            .map(IpNet::V6)
            .collect(),
        _ => vec![route],
    }
}

fn subtract_ipv4_route(route: Ipv4Net, excluded: Ipv4Net) -> Vec<Ipv4Net> {
    if !ipv4_routes_overlap(route, excluded) {
        return vec![route];
    }
    if excluded.contains(&route) {
        return Vec::new();
    }
    if route.prefix_len() == 32 {
        return Vec::new();
    }

    route
        .subnets(route.prefix_len() + 1)
        .expect("splitting a non-/32 IPv4 route is valid")
        .flat_map(|subnet| subtract_ipv4_route(subnet, excluded))
        .collect()
}

fn ipv4_routes_overlap(left: Ipv4Net, right: Ipv4Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn subtract_ipv6_route(route: Ipv6Net, excluded: Ipv6Net) -> Vec<Ipv6Net> {
    if !ipv6_routes_overlap(route, excluded) {
        return vec![route];
    }
    if excluded.contains(&route) {
        return Vec::new();
    }
    if route.prefix_len() == 128 {
        return Vec::new();
    }

    route
        .subnets(route.prefix_len() + 1)
        .expect("splitting a non-/128 IPv6 route is valid")
        .flat_map(|subnet| subtract_ipv6_route(subnet, excluded))
        .collect()
}

fn ipv6_routes_overlap(left: Ipv6Net, right: Ipv6Net) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

fn split_default_ipv4_routes() -> [Ipv4Net; 2] {
    [
        Ipv4Net::new(Ipv4Addr::UNSPECIFIED, 1).expect("valid split default route"),
        Ipv4Net::new(Ipv4Addr::new(128, 0, 0, 0), 1).expect("valid split default route"),
    ]
}

fn split_default_ipv6_routes() -> [Ipv6Net; 2] {
    [
        Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 1).expect("valid split default route"),
        Ipv6Net::new(
            Ipv6Addr::from(0x8000_0000_0000_0000_0000_0000_0000_0000u128),
            1,
        )
        .expect("valid split default route"),
    ]
}

#[cfg(target_os = "macos")]
fn macos_ifconfig_command(device: &str, tunnel: TunnelPair, mtu: u16) -> String {
    match tunnel {
        TunnelPair::V4 { local, peer } => {
            format!("ifconfig {device} inet {local} {peer} mtu {mtu} up")
        }
        TunnelPair::V6 { local, peer } => {
            format!("ifconfig {device} inet6 {local} {peer} prefixlen 128 mtu {mtu} up")
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_add_route_command(route: IpNet, gateway: IpAddr) -> String {
    let rendered = route.to_string();
    match route {
        IpNet::V4(route) if route.prefix_len() == 32 => {
            let host = rendered.trim_end_matches("/32");
            format!(
                "route -q -n add -host {host} {gateway} >/dev/null 2>&1 || route -q -n change -host {host} {gateway}"
            )
        }
        IpNet::V4(_) => {
            format!(
                "route -q -n add -net {rendered} {gateway} >/dev/null 2>&1 || route -q -n change -net {rendered} {gateway}"
            )
        }
        IpNet::V6(route) if route.prefix_len() == 128 => {
            let host = rendered.trim_end_matches("/128");
            format!(
                "route -q -n add -inet6 -host {host} {gateway} >/dev/null 2>&1 || route -q -n change -inet6 -host {host} {gateway}"
            )
        }
        IpNet::V6(_) => {
            format!(
                "route -q -n add -inet6 -net {rendered} {gateway} >/dev/null 2>&1 || route -q -n change -inet6 -net {rendered} {gateway}"
            )
        }
    }
}

#[cfg(target_os = "macos")]
fn macos_delete_route_command(route: IpNet) -> String {
    let rendered = route.to_string();
    match route {
        IpNet::V4(route) if route.prefix_len() == 32 => {
            let host = rendered.trim_end_matches("/32");
            format!("route -q -n delete -host {host} >/dev/null 2>&1 || true")
        }
        IpNet::V4(_) => {
            format!("route -q -n delete -net {rendered} >/dev/null 2>&1 || true")
        }
        IpNet::V6(route) if route.prefix_len() == 128 => {
            let host = rendered.trim_end_matches("/128");
            format!("route -q -n delete -inet6 -host {host} >/dev/null 2>&1 || true")
        }
        IpNet::V6(_) => {
            format!("route -q -n delete -inet6 -net {rendered} >/dev/null 2>&1 || true")
        }
    }
}

fn ensure_tunnel_pair(
    local: IpAddr,
    peer: IpAddr,
    local_label: &str,
    peer_label: &str,
) -> Result<TunnelPair> {
    match (local, peer) {
        (IpAddr::V4(local), IpAddr::V4(peer)) => Ok(TunnelPair::V4 { local, peer }),
        (IpAddr::V6(local), IpAddr::V6(peer)) => Ok(TunnelPair::V6 { local, peer }),
        _ => bail!("{local_label} and {peer_label} must use the same IP version"),
    }
}

#[cfg(target_os = "macos")]
fn macos_bypass_route(endpoint: IpAddr, route: &RouteInfo) -> String {
    match route.gateway.as_deref() {
        Some(gateway) if !gateway.is_empty() && endpoint.is_ipv6() => {
            format!(
                "route -q -n add -inet6 -host {endpoint} {gateway} >/dev/null 2>&1 || route -q -n change -inet6 -host {endpoint} {gateway}"
            )
        }
        Some(gateway) if !gateway.is_empty() => {
            format!(
                "route -q -n add -host {endpoint} {gateway} >/dev/null 2>&1 || route -q -n change -host {endpoint} {gateway}"
            )
        }
        _ if endpoint.is_ipv6() => format!(
            "route -q -n add -inet6 -host {endpoint} -interface {} >/dev/null 2>&1 || route -q -n change -inet6 -host {endpoint} -interface {}",
            route.interface.as_deref().unwrap_or(""),
            route.interface.as_deref().unwrap_or("")
        ),
        _ => format!(
            "route -q -n add -host {endpoint} -interface {} >/dev/null 2>&1 || route -q -n change -host {endpoint} -interface {}",
            route.interface.as_deref().unwrap_or(""),
            route.interface.as_deref().unwrap_or("")
        ),
    }
}

#[cfg(target_os = "macos")]
fn macos_delete_host_route_command(endpoint: IpAddr) -> String {
    if endpoint.is_ipv6() {
        format!("route -q -n delete -inet6 -host {endpoint} >/dev/null 2>&1 || true")
    } else {
        format!("route -q -n delete -host {endpoint} >/dev/null 2>&1 || true")
    }
}

#[cfg(target_os = "macos")]
fn direct_host_add_command(ip: IpAddr, route: &RouteInfo) -> String {
    macos_bypass_route(ip, route)
}

#[cfg(target_os = "macos")]
fn direct_host_delete_command(ip: IpAddr) -> String {
    macos_delete_host_route_command(ip)
}

#[cfg(target_os = "linux")]
fn linux_address_add_command(device: &str, tunnel: TunnelPair) -> String {
    match tunnel {
        TunnelPair::V4 { local, peer } => {
            format!("ip address add {local} peer {peer} dev {device}")
        }
        TunnelPair::V6 { local, .. } => format!("ip -6 address add {local}/128 dev {device}"),
    }
}

#[cfg(target_os = "linux")]
fn linux_address_del_command(device: &str, tunnel: TunnelPair) -> String {
    match tunnel {
        TunnelPair::V4 { local, peer } => {
            format!("ip address del {local} peer {peer} dev {device} >/dev/null 2>&1 || true")
        }
        TunnelPair::V6 { local, .. } => {
            format!("ip -6 address del {local}/128 dev {device} >/dev/null 2>&1 || true")
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_add_route_command(route: IpNet, device: &str) -> String {
    match route {
        IpNet::V4(_) => format!("ip route replace {route} dev {device}"),
        IpNet::V6(_) => format!("ip -6 route replace {route} dev {device}"),
    }
}

#[cfg(target_os = "linux")]
fn linux_delete_route_command(route: IpNet, device: &str) -> String {
    match route {
        IpNet::V4(_) => format!("ip route del {route} dev {device} >/dev/null 2>&1 || true"),
        IpNet::V6(_) => format!("ip -6 route del {route} dev {device} >/dev/null 2>&1 || true"),
    }
}

#[cfg(target_os = "linux")]
fn linux_bypass_route(endpoint: IpAddr, route: &RouteInfo) -> String {
    let command = if endpoint.is_ipv6() {
        "ip -6 route replace"
    } else {
        "ip route replace"
    };
    let prefix = if endpoint.is_ipv6() { 128 } else { 32 };
    match route.gateway.as_deref() {
        Some(gateway) if !gateway.is_empty() => {
            format!(
                "{command} {endpoint}/{prefix} via {gateway} dev {}",
                route.interface.as_deref().unwrap()
            )
        }
        _ => format!(
            "{command} {endpoint}/{prefix} dev {}",
            route.interface.as_deref().unwrap()
        ),
    }
}

#[cfg(target_os = "linux")]
fn linux_delete_host_route_command(endpoint: IpAddr) -> String {
    if endpoint.is_ipv6() {
        format!("ip -6 route del {endpoint}/128 >/dev/null 2>&1 || true")
    } else {
        format!("ip route del {endpoint}/32 >/dev/null 2>&1 || true")
    }
}

#[cfg(target_os = "linux")]
fn direct_host_add_command(ip: IpAddr, route: &RouteInfo) -> String {
    linux_bypass_route(ip, route)
}

#[cfg(target_os = "linux")]
fn direct_host_delete_command(ip: IpAddr) -> String {
    linux_delete_host_route_command(ip)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn direct_host_add_command(ip: IpAddr, _route: &RouteInfo) -> String {
    format!("true # dynamic direct route for {ip} is unsupported on this OS")
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn direct_host_delete_command(ip: IpAddr) -> String {
    format!("true # dynamic direct route cleanup for {ip} is unsupported on this OS")
}

fn detect_egress_route(target: IpAddr) -> Result<RouteInfo> {
    #[cfg(target_os = "macos")]
    {
        let target = target.to_string();
        let args = if target.contains(':') {
            vec!["-n", "get", "-inet6", target.as_str()]
        } else {
            vec!["-n", "get", target.as_str()]
        };
        let output = Command::new("route")
            .args(args)
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
        let target = target.to_string();
        let args = if target.contains(':') {
            vec!["-6", "route", "get", target.as_str()]
        } else {
            vec!["route", "get", target.as_str()]
        };
        let output = Command::new("ip")
            .args(args)
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
    use super::{RouteInfo, build_client_hook_plan, exclude_routes};
    use crate::wg::{WgRuntimeConfig, default_client_allowed_ips};
    use ipnet::IpNet;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

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
            excluded_ips: Vec::new(),
        }
    }

    fn client_runtime_v6() -> WgRuntimeConfig {
        WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            endpoint: Some("[2001:db8::10]:51820".parse().unwrap()),
            tunnel_ip: IpAddr::V6("fd00:8::2".parse().unwrap()),
            peer_tunnel_ip: IpAddr::V6("fd00:8::1".parse().unwrap()),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            private_key: [1u8; 32],
            peer_public_key: [2u8; 32],
            peer_allowed_ips: vec!["::/0".to_owned()],
            excluded_ips: vec!["fc00::/7".to_owned(), "10.0.0.0/8".to_owned()],
        }
    }

    #[test]
    fn excluded_ipv4_route_removes_subnet_from_default_halves() {
        let routes = vec![
            "0.0.0.0/1".parse::<IpNet>().unwrap(),
            "128.0.0.0/1".parse::<IpNet>().unwrap(),
        ];
        let excluded = vec!["192.168.0.0/16".parse::<IpNet>().unwrap()];

        let result = exclude_routes(routes, &excluded);

        assert!(!result.contains(&"192.168.0.0/16".parse::<IpNet>().unwrap()));
        assert!(
            result
                .iter()
                .any(|route| route.contains(&IpAddr::V4(Ipv4Addr::new(192, 167, 255, 255))))
        );
        assert!(
            result
                .iter()
                .any(|route| route.contains(&IpAddr::V4(Ipv4Addr::new(192, 169, 0, 1))))
        );
        assert!(
            !result
                .iter()
                .any(|route| route.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))))
        );
    }

    #[test]
    fn excluded_ipv6_route_removes_subnet_from_default_halves() {
        let routes = vec![
            "::/1".parse::<IpNet>().unwrap(),
            "8000::/1".parse().unwrap(),
        ];
        let excluded = vec!["fc00::/7".parse::<IpNet>().unwrap()];

        let result = exclude_routes(routes, &excluded);

        assert!(!result.contains(&"fc00::/7".parse::<IpNet>().unwrap()));
        assert!(
            result
                .iter()
                .any(|route| route.contains(&IpAddr::V6("fbff::1".parse::<Ipv6Addr>().unwrap())))
        );
        assert!(
            result
                .iter()
                .any(|route| route.contains(&IpAddr::V6("fe00::1".parse::<Ipv6Addr>().unwrap())))
        );
        assert!(
            !result
                .iter()
                .any(|route| route.contains(&IpAddr::V6("fc00::1".parse::<Ipv6Addr>().unwrap())))
        );
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
            Some("ifconfig utun123 inet 10.8.0.2 10.8.0.1 mtu 1420 up")
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

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_client_hook_plan_supports_ipv6_tunnel_and_endpoint() {
        let plan = build_client_hook_plan(
            "utun123",
            IpAddr::V6("2001:db8::10".parse().unwrap()),
            &client_runtime_v6(),
            &RouteInfo {
                interface: Some("en0".to_owned()),
                gateway: Some("fe80::1".to_owned()),
            },
        )
        .unwrap();

        assert_eq!(
            plan.up.first().map(String::as_str),
            Some("ifconfig utun123 inet6 fd00:8::2 fd00:8::1 prefixlen 128 mtu 1420 up")
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("route -q -n add -inet6 -host 2001:db8::10 fe80::1"))
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("route -q -n add -inet6 -net ::/1 fd00:8::1"))
        );
        assert!(
            plan.up
                .iter()
                .any(|hook| hook.contains("route -q -n add -inet6 -net fe00::/7 fd00:8::1"))
        );
        assert!(
            !plan
                .up
                .iter()
                .any(|hook| hook.contains("route -q -n add -net 10.0.0.0/8"))
        );
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
            excluded_ips: Vec::new(),
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
