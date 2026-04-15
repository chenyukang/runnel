#[cfg(any(target_os = "macos", test))]
use anyhow::Context;
use anyhow::{Result, bail};
#[cfg(target_os = "macos")]
use tracing::{info, warn};

use crate::client::ClientArgs;
#[cfg(target_os = "macos")]
use crate::tls;

#[cfg(any(target_os = "macos", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceProxySnapshot {
    name: String,
    enabled: bool,
    server: Option<String>,
    port: Option<u16>,
    authenticated: bool,
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct SystemProxyGuard {
    snapshots: Vec<ServiceProxySnapshot>,
}

#[cfg(not(target_os = "macos"))]
#[derive(Debug)]
pub struct SystemProxyGuard;

pub fn maybe_activate(args: &ClientArgs) -> Result<Option<SystemProxyGuard>> {
    if !args.system_proxy {
        return Ok(None);
    }

    #[cfg(target_os = "macos")]
    {
        return SystemProxyGuard::activate(args).map(Some);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = args;
        bail!("--system-proxy is only supported on macOS");
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

        Ok(Self { snapshots })
    }
}

#[cfg(target_os = "macos")]
impl Drop for SystemProxyGuard {
    fn drop(&mut self) {
        restore_many(self.snapshots.iter().rev());
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
fn set_service_proxy(service: &str, host: &str, port: u16) -> Result<()> {
    let port = port.to_string();
    run_networksetup_no_output(["-setsocksfirewallproxy", service, host, &port])?;
    run_networksetup_no_output(["-setsocksfirewallproxystate", service, "on"])?;
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
fn run_networksetup<const N: usize>(args: [&str; N]) -> Result<String> {
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
        ServiceProxySnapshot, normalize_proxy_host, parse_network_services,
        parse_service_has_ip_address, parse_socks_proxy,
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
}
