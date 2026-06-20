#[cfg(any(target_os = "macos", test))]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(any(target_os = "macos", test))]
use std::net::IpAddr;
#[cfg(target_os = "macos")]
use tracing::{info, warn};

use crate::client::ClientArgs;
#[cfg(target_os = "macos")]
use crate::proxy::tls;

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceProxySnapshot {
    name: String,
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
    authenticated: bool,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceDnsSnapshot {
    name: String,
    servers: Vec<String>,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct SystemProxyGuard {
    snapshots: Vec<ServiceProxySnapshot>,
    host: String,
    port: u16,
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
pub struct SystemProxyGuard;

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct SystemDnsGuard {
    snapshots: Vec<ServiceDnsSnapshot>,
    servers: Vec<String>,
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
pub struct SystemDnsGuard;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SystemDnsMonitorCheck {
    pub ok: bool,
    pub detail: String,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug)]
pub struct SystemDnsMonitor {
    services: Vec<String>,
    servers: Vec<String>,
}

#[cfg(not(target_os = "macos"))]
#[derive(Clone, Debug)]
pub struct SystemDnsMonitor;

pub fn maybe_activate(args: &ClientArgs) -> Result<Option<SystemProxyGuard>> {
    if !args.system_proxy {
        return Ok(None);
    }

    #[cfg(target_os = "macos")]
    {
        SystemProxyGuard::activate(args).map(Some)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        bail!("--system-proxy is only supported on macOS");
    }
}

pub fn maybe_activate_tun_dns(servers: &[String]) -> Result<Option<SystemDnsGuard>> {
    if servers.is_empty() {
        return Ok(None);
    }

    #[cfg(target_os = "macos")]
    {
        SystemDnsGuard::activate(servers).map(Some)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = servers;
        Ok(None)
    }
}

#[cfg(target_os = "macos")]
impl SystemProxyGuard {
    fn activate(args: &ClientArgs) -> Result<Self> {
        let (host, port) = proxy_target_from_listen(&args.listen)?;
        let services = determine_services(&args.system_proxy_services)?;
        if services.is_empty() {
            bail!("no macOS network services are available for --system-proxy");
        }

        let snapshots = services
            .iter()
            .map(|service| read_service_snapshot(service))
            .collect::<Result<Vec<_>>>()?;

        for snapshot in &snapshots {
            if snapshot.authenticated {
                bail!(
                    "cannot override authenticated SOCKS proxy on macOS service {} safely",
                    snapshot.name
                );
            }
            if snapshot.enabled && (snapshot.server.is_none() || snapshot.port.is_none()) {
                bail!(
                    "cannot restore existing SOCKS proxy on macOS service {} because its current server or port is missing",
                    snapshot.name
                );
            }
        }

        let mut applied = Vec::with_capacity(snapshots.len());
        for snapshot in &snapshots {
            if let Err(err) = set_service_proxy(&snapshot.name, &host, port) {
                restore_many(applied.iter().rev());
                return Err(err);
            }
            info!(
                service = %snapshot.name,
                host = %host,
                port,
                "enabled macOS SOCKS system proxy"
            );
            applied.push(snapshot.clone());
        }

        Ok(Self {
            snapshots,
            host,
            port,
        })
    }

    pub fn apply_proxy(&self) -> Result<()> {
        for snapshot in &self.snapshots {
            set_service_proxy(&snapshot.name, &self.host, self.port)?;
            info!(
                service = %snapshot.name,
                host = %self.host,
                port = self.port,
                "enabled macOS SOCKS system proxy"
            );
        }
        Ok(())
    }

    pub fn restore_original(&self) -> Result<()> {
        restore_many(self.snapshots.iter().rev());
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl SystemDnsGuard {
    fn activate(servers: &[String]) -> Result<Self> {
        let services = determine_services(&[])?;
        if services.is_empty() {
            bail!("no macOS network services are available for tun DNS override");
        }

        let snapshots = services
            .iter()
            .map(|service| {
                let snapshot = read_service_dns_snapshot(service)?;
                let (snapshot, sanitized) = sanitize_dns_snapshot_for_override(snapshot, servers);
                if sanitized {
                    warn!(
                        service = %snapshot.name,
                        servers = ?servers,
                        "ignored stale macOS DNS snapshot matching loopback tunnel override"
                    );
                }
                Ok(snapshot)
            })
            .collect::<Result<Vec<_>>>()?;

        let mut applied = Vec::with_capacity(snapshots.len());
        for snapshot in &snapshots {
            if let Err(err) = set_service_dns_servers(&snapshot.name, servers) {
                restore_dns_many(applied.iter().rev());
                return Err(err);
            }
            info!(
                service = %snapshot.name,
                servers = ?servers,
                "overrode macOS DNS servers for tun session"
            );
            applied.push(snapshot.clone());
        }

        Ok(Self {
            snapshots,
            servers: servers.to_vec(),
        })
    }

    pub fn apply_override(&self) -> Result<()> {
        for snapshot in &self.snapshots {
            set_service_dns_servers(&snapshot.name, &self.servers)?;
            info!(
                service = %snapshot.name,
                servers = ?self.servers,
                "overrode macOS DNS servers for tunnel session"
            );
        }
        Ok(())
    }

    pub fn restore_original(&self) -> Result<()> {
        restore_dns_many(self.snapshots.iter().rev());
        Ok(())
    }

    pub fn direct_dns_upstream(&self) -> Option<IpAddr> {
        self.snapshots
            .iter()
            .flat_map(|snapshot| snapshot.servers.iter())
            .filter_map(|server| parse_direct_dns_ip(server))
            .next()
            .or_else(|| {
                self.snapshots.iter().find_map(|snapshot| {
                    read_service_router(&snapshot.name)
                        .ok()
                        .flatten()
                        .filter(|ip| is_direct_dns_ip(*ip))
                })
            })
    }

    pub fn monitor(&self) -> SystemDnsMonitor {
        SystemDnsMonitor {
            services: self
                .snapshots
                .iter()
                .map(|snapshot| snapshot.name.clone())
                .collect(),
            servers: self.servers.clone(),
        }
    }
}

#[cfg(not(target_os = "macos"))]
impl SystemProxyGuard {
    pub fn apply_proxy(&self) -> Result<()> {
        Ok(())
    }

    pub fn restore_original(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(not(target_os = "macos"))]
impl SystemDnsGuard {
    pub fn apply_override(&self) -> Result<()> {
        Ok(())
    }

    pub fn restore_original(&self) -> Result<()> {
        Ok(())
    }

    pub fn direct_dns_upstream(&self) -> Option<std::net::IpAddr> {
        None
    }

    pub fn monitor(&self) -> SystemDnsMonitor {
        SystemDnsMonitor
    }
}

#[cfg(target_os = "macos")]
impl SystemDnsMonitor {
    pub fn check(&self) -> Result<SystemDnsMonitorCheck> {
        for service in &self.services {
            let current = read_service_dns_snapshot(service)?;
            if !dns_server_lists_match(&current.servers, &self.servers) {
                return Ok(SystemDnsMonitorCheck {
                    ok: false,
                    detail: format!(
                        "{service} DNS is {:?}, expected {:?}",
                        current.servers, self.servers
                    ),
                });
            }
        }

        Ok(SystemDnsMonitorCheck {
            ok: true,
            detail: format!("system DNS matches {:?}", self.servers),
        })
    }
}

#[cfg(not(target_os = "macos"))]
impl SystemDnsMonitor {
    pub fn check(&self) -> Result<SystemDnsMonitorCheck> {
        Ok(SystemDnsMonitorCheck {
            ok: true,
            detail: "system DNS monitor is not required on this platform".to_owned(),
        })
    }
}

#[cfg(target_os = "macos")]
impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        restore_many(self.snapshots.iter().rev());
    }
}

#[cfg(target_os = "macos")]
impl Drop for SystemDnsGuard {
    fn drop(&mut self) {
        restore_dns_many(self.snapshots.iter().rev());
    }
}

#[cfg(target_os = "macos")]
fn restore_many<'a>(snapshots: impl IntoIterator<Item = &'a ServiceProxySnapshot>) {
    for snapshot in snapshots {
        match restore_service(snapshot) {
            Ok(()) => {
                info!(service = %snapshot.name, "restored macOS SOCKS system proxy");
            }
            Err(err) => {
                warn!(
                    service = %snapshot.name,
                    error = %err,
                    "failed to restore macOS SOCKS system proxy"
                );
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn restore_dns_many<'a>(snapshots: impl IntoIterator<Item = &'a ServiceDnsSnapshot>) {
    for snapshot in snapshots {
        match restore_service_dns(snapshot) {
            Ok(()) => {
                info!(
                    service = %snapshot.name,
                    servers = ?snapshot.servers,
                    "restored macOS DNS servers"
                );
            }
            Err(err) => {
                warn!(
                    service = %snapshot.name,
                    error = %err,
                    "failed to restore macOS DNS servers"
                );
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn determine_services(explicit: &[String]) -> Result<Vec<String>> {
    if !explicit.is_empty() {
        return Ok(explicit.to_vec());
    }

    let services = list_enabled_services()?;
    if services.is_empty() {
        bail!("networksetup returned no enabled macOS network services");
    }

    let active = services
        .iter()
        .filter_map(|service| match service_is_active(service) {
            Ok(true) => Some(Ok(service.clone())),
            Ok(false) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>>>()?;

    if active.is_empty() {
        Ok(services)
    } else {
        Ok(active)
    }
}

#[cfg(target_os = "macos")]
fn list_enabled_services() -> Result<Vec<String>> {
    let output = run_networksetup(["-listallnetworkservices"])?;
    Ok(parse_network_services(&output))
}

#[cfg(target_os = "macos")]
fn service_is_active(service: &str) -> Result<bool> {
    let output = run_networksetup(["-getinfo", service])?;
    Ok(parse_service_has_ip_address(&output))
}

#[cfg(target_os = "macos")]
fn read_service_snapshot(service: &str) -> Result<ServiceProxySnapshot> {
    let output = run_networksetup(["-getsocksfirewallproxy", service])?;
    parse_socks_proxy(service, &output)
}

#[cfg(target_os = "macos")]
fn read_service_dns_snapshot(service: &str) -> Result<ServiceDnsSnapshot> {
    let output = run_networksetup(["-getdnsservers", service])?;
    Ok(ServiceDnsSnapshot {
        name: service.to_owned(),
        servers: parse_dns_servers(&output),
    })
}

#[cfg(target_os = "macos")]
fn read_service_router(service: &str) -> Result<Option<IpAddr>> {
    let output = run_networksetup(["-getinfo", service])?;
    Ok(parse_service_router(&output))
}

#[cfg(target_os = "macos")]
fn set_service_proxy(service: &str, host: &str, port: u16) -> Result<()> {
    let port = port.to_string();
    run_networksetup_no_output(["-setsocksfirewallproxy", service, host, &port])?;
    run_networksetup_no_output(["-setsocksfirewallproxystate", service, "on"])?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn set_service_dns_servers(service: &str, servers: &[String]) -> Result<()> {
    if servers.is_empty() {
        bail!("at least one DNS server is required");
    }
    let mut args = Vec::with_capacity(2 + servers.len());
    args.push("-setdnsservers");
    args.push(service);
    args.extend(servers.iter().map(String::as_str));
    run_networksetup_dynamic(&args)?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_service(snapshot: &ServiceProxySnapshot) -> Result<()> {
    if let (Some(server), Some(port)) = (&snapshot.server, snapshot.port) {
        let port = port.to_string();
        run_networksetup_no_output(["-setsocksfirewallproxy", &snapshot.name, server, &port])?;
    }

    let state = if snapshot.enabled { "on" } else { "off" };
    run_networksetup_no_output(["-setsocksfirewallproxystate", &snapshot.name, state])?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_service_dns(snapshot: &ServiceDnsSnapshot) -> Result<()> {
    if snapshot.servers.is_empty() {
        run_networksetup_dynamic(&["-setdnsservers", &snapshot.name, "Empty"])?;
    } else {
        let mut args = Vec::with_capacity(2 + snapshot.servers.len());
        args.push("-setdnsservers");
        args.push(snapshot.name.as_str());
        args.extend(snapshot.servers.iter().map(String::as_str));
        run_networksetup_dynamic(&args)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn run_networksetup<const N: usize>(args: [&str; N]) -> Result<String> {
    run_networksetup_dynamic(&args)
}

#[cfg(target_os = "macos")]
fn run_networksetup_dynamic(args: &[&str]) -> Result<String> {
    let output = std::process::Command::new("networksetup")
        .args(args)
        .output()
        .context("failed to execute networksetup")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "networksetup {:?} failed: {}{}",
            args,
            stderr.trim(),
            if stdout.trim().is_empty() {
                String::new()
            } else if stderr.trim().is_empty() {
                stdout.trim().to_owned()
            } else {
                format!("; {}", stdout.trim())
            }
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

#[cfg(target_os = "macos")]
fn run_networksetup_no_output<const N: usize>(args: [&str; N]) -> Result<()> {
    let _ = run_networksetup(args)?;
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn parse_network_services(output: &str) -> Vec<String> {
    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("An asterisk"))
        .filter(|line| !line.starts_with('*'))
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn parse_dns_servers(output: &str) -> Vec<String> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed.starts_with("There aren't any DNS Servers set on ") {
        return Vec::new();
    }

    output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(any(target_os = "macos", test))]
fn parse_service_router(output: &str) -> Option<IpAddr> {
    output.lines().find_map(|line| {
        let value = line.trim().strip_prefix("Router:")?.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("none") {
            return None;
        }
        value
            .parse::<IpAddr>()
            .ok()
            .filter(|ip| is_direct_dns_ip(*ip))
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_direct_dns_ip(value: &str) -> Option<IpAddr> {
    value
        .parse::<IpAddr>()
        .ok()
        .filter(|ip| is_direct_dns_ip(*ip))
}

#[cfg(any(target_os = "macos", test))]
fn sanitize_dns_snapshot_for_override(
    mut snapshot: ServiceDnsSnapshot,
    override_servers: &[String],
) -> (ServiceDnsSnapshot, bool) {
    if is_loopback_dns_override(override_servers)
        && dns_server_lists_match(&snapshot.servers, override_servers)
    {
        snapshot.servers.clear();
        return (snapshot, true);
    }
    (snapshot, false)
}

#[cfg(any(target_os = "macos", test))]
fn is_loopback_dns_override(servers: &[String]) -> bool {
    !servers.is_empty()
        && servers.iter().all(|server| {
            server.parse::<IpAddr>().is_ok_and(|ip| match ip {
                IpAddr::V4(ip) => ip.is_loopback(),
                IpAddr::V6(ip) => ip.is_loopback(),
            })
        })
}

#[cfg(any(target_os = "macos", test))]
fn dns_server_lists_match(left: &[String], right: &[String]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.trim().eq_ignore_ascii_case(right.trim()))
}

#[cfg(any(target_os = "macos", test))]
fn is_direct_dns_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => !ip.is_loopback() && !ip.is_unspecified(),
        IpAddr::V6(ip) => !ip.is_loopback() && !ip.is_unspecified(),
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse_service_has_ip_address(output: &str) -> bool {
    output.lines().any(|line| {
        let Some(value) = line.trim().strip_prefix("IP address:") else {
            return false;
        };
        let value = value.trim();
        !value.is_empty() && !value.eq_ignore_ascii_case("none")
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_socks_proxy(service: &str, output: &str) -> Result<ServiceProxySnapshot> {
    let mut enabled = None;
    let mut server = None;
    let mut port = None;
    let mut authenticated = false;

    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Enabled:") {
            enabled = Some(parse_yes_no(value.trim()).context("invalid Enabled field")?);
        } else if let Some(value) = line.strip_prefix("Server:") {
            let value = value.trim();
            if !value.is_empty() && !value.eq_ignore_ascii_case("(null)") {
                server = Some(value.to_owned());
            }
        } else if let Some(value) = line.strip_prefix("Port:") {
            let value = value.trim();
            if !value.is_empty() && !value.eq_ignore_ascii_case("(null)") {
                port = Some(value.parse::<u16>().context("invalid Port field")?);
            }
        } else if let Some(value) = line.strip_prefix("Authenticated Proxy Enabled:") {
            authenticated = matches!(value.trim(), "1" | "yes" | "Yes");
        }
    }

    Ok(ServiceProxySnapshot {
        name: service.to_owned(),
        enabled: enabled.context("missing Enabled field")?,
        server,
        port,
        authenticated,
    })
}

#[cfg(any(target_os = "macos", test))]
fn parse_yes_no(value: &str) -> Result<bool> {
    match value {
        "Yes" | "yes" | "on" | "On" | "true" | "True" => Ok(true),
        "No" | "no" | "off" | "Off" | "false" | "False" => Ok(false),
        _ => bail!("expected Yes/No value, got {value}"),
    }
}

#[cfg(target_os = "macos")]
fn proxy_target_from_listen(listen: &str) -> Result<(String, u16)> {
    let (host, port) = tls::split_host_port(listen)
        .with_context(|| format!("failed to parse client listen address {listen}"))?;
    Ok((normalize_proxy_host(&host), port))
}

#[cfg(any(target_os = "macos", test))]
fn normalize_proxy_host(host: &str) -> String {
    match host {
        "0.0.0.0" => "127.0.0.1".to_owned(),
        "::" => "::1".to_owned(),
        _ => host.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ServiceDnsSnapshot, ServiceProxySnapshot, normalize_proxy_host, parse_direct_dns_ip,
        parse_dns_servers, parse_network_services, parse_service_has_ip_address,
        parse_service_router, parse_socks_proxy, sanitize_dns_snapshot_for_override,
    };

    #[test]
    fn parses_enabled_network_services() {
        let raw = "\
An asterisk (*) denotes that a network service is disabled.\n\
USB 10/100/1000 LAN\n\
Thunderbolt Bridge\n\
Wi-Fi\n\
*Disabled Service\n";
        assert_eq!(
            parse_network_services(raw),
            vec![
                "USB 10/100/1000 LAN".to_owned(),
                "Thunderbolt Bridge".to_owned(),
                "Wi-Fi".to_owned()
            ]
        );
    }

    #[test]
    fn detects_active_service_from_ip_address() {
        let active = "\
DHCP Configuration\n\
IP address: 192.168.3.46\n\
Router: 192.168.3.1\n";
        let inactive = "\
DHCP Configuration\n\
IP address: none\n";
        assert!(parse_service_has_ip_address(active));
        assert!(!parse_service_has_ip_address(inactive));
    }

    #[test]
    fn parses_router_from_service_info() {
        let raw = "\
DHCP Configuration\n\
IP address: 192.168.3.46\n\
Router: 192.168.3.1\n";
        assert_eq!(
            parse_service_router(raw),
            Some("192.168.3.1".parse().unwrap())
        );
    }

    #[test]
    fn ignores_loopback_as_direct_dns_upstream() {
        assert_eq!(parse_direct_dns_ip("127.0.0.1"), None);
        assert_eq!(
            parse_direct_dns_ip("223.5.5.5"),
            Some("223.5.5.5".parse().unwrap())
        );
    }

    #[test]
    fn parses_socks_proxy_snapshot() {
        let raw = "\
Enabled: Yes\n\
Server: 127.0.0.1\n\
Port: 1080\n\
Authenticated Proxy Enabled: 0\n";
        assert_eq!(
            parse_socks_proxy("Wi-Fi", raw).unwrap(),
            ServiceProxySnapshot {
                name: "Wi-Fi".to_owned(),
                enabled: true,
                server: Some("127.0.0.1".to_owned()),
                port: Some(1080),
                authenticated: false,
            }
        );
    }

    #[test]
    fn normalizes_wildcard_listen_address() {
        assert_eq!(normalize_proxy_host("0.0.0.0"), "127.0.0.1");
        assert_eq!(normalize_proxy_host("::"), "::1");
        assert_eq!(normalize_proxy_host("127.0.0.1"), "127.0.0.1");
    }

    #[test]
    fn parses_dns_server_list() {
        let raw = "\
1.1.1.1\n\
1.0.0.1\n";
        assert_eq!(
            parse_dns_servers(raw),
            vec!["1.1.1.1".to_owned(), "1.0.0.1".to_owned()]
        );
    }

    #[test]
    fn parses_empty_dns_server_list() {
        let raw = "There aren't any DNS Servers set on Wi-Fi.\n";
        assert!(parse_dns_servers(raw).is_empty());
    }

    #[test]
    fn sanitizes_loopback_dns_snapshot_matching_tunnel_override() {
        let snapshot = ServiceDnsSnapshot {
            name: "Wi-Fi".to_owned(),
            servers: vec!["127.0.0.1".to_owned()],
        };
        let override_servers = vec!["127.0.0.1".to_owned()];

        let (snapshot, sanitized) = sanitize_dns_snapshot_for_override(snapshot, &override_servers);

        assert!(sanitized);
        assert!(snapshot.servers.is_empty());
    }

    #[test]
    fn preserves_non_loopback_dns_snapshot() {
        let snapshot = ServiceDnsSnapshot {
            name: "Wi-Fi".to_owned(),
            servers: vec!["223.5.5.5".to_owned()],
        };
        let override_servers = vec!["127.0.0.1".to_owned()];

        let (snapshot, sanitized) = sanitize_dns_snapshot_for_override(snapshot, &override_servers);

        assert!(!sanitized);
        assert_eq!(snapshot.servers, vec!["223.5.5.5".to_owned()]);
    }
}
