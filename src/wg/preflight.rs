use anyhow::{Result, bail};
use std::{env, path::PathBuf};
#[cfg(target_os = "linux")]
use std::{fs::OpenOptions, path::Path};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WgPreflightRole {
    Client,
    Server,
}

pub(crate) fn check(role: WgPreflightRole, dns_enabled: bool, nat_enabled: bool) -> Result<()> {
    let mut issues = Vec::new();

    check_privileges(&mut issues);
    check_platform_requirements(role, dns_enabled, nat_enabled, &mut issues);

    if issues.is_empty() {
        return Ok(());
    }

    bail!("wg preflight failed:\n  - {}", issues.join("\n  - "))
}

#[cfg(target_os = "linux")]
fn check_platform_requirements(
    _role: WgPreflightRole,
    _dns_enabled: bool,
    nat_enabled: bool,
    issues: &mut Vec<String>,
) {
    check_tun_device(issues);
    require_command("ip", issues);

    if nat_enabled {
        require_command("sysctl", issues);
        if !command_exists("iptables") {
            if command_exists("nft") {
                issues.push(
                    "nft was found but iptables was not; current default WG NAT hooks still use iptables, so pass custom --up/--down hooks or install iptables".to_owned(),
                );
            } else {
                issues.push("iptables was not found in PATH; nft was not found either".to_owned());
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn check_platform_requirements(
    _role: WgPreflightRole,
    dns_enabled: bool,
    _nat_enabled: bool,
    issues: &mut Vec<String>,
) {
    require_command("ifconfig", issues);
    require_command("route", issues);

    if dns_enabled {
        require_command("networksetup", issues);
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn check_platform_requirements(
    _role: WgPreflightRole,
    _dns_enabled: bool,
    _nat_enabled: bool,
    issues: &mut Vec<String>,
) {
    issues.push("wg mode preflight is only implemented for Linux and macOS".to_owned());
}

#[cfg(target_os = "linux")]
fn check_tun_device(issues: &mut Vec<String>) {
    let path = Path::new("/dev/net/tun");
    if !path.exists() {
        issues.push(
            "/dev/net/tun does not exist; load the tun module or enable TUN support".to_owned(),
        );
        return;
    }

    if let Err(err) = OpenOptions::new().read(true).write(true).open(path) {
        issues.push(format!(
            "failed to open /dev/net/tun for read/write: {err}; run as root or grant CAP_NET_ADMIN"
        ));
    }
}

fn require_command(command: &str, issues: &mut Vec<String>) {
    if !command_exists(command) {
        issues.push(format!("{command} was not found in PATH"));
    }
}

fn command_exists(command: &str) -> bool {
    command_path(command).is_some()
}

fn command_path(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        let path = PathBuf::from(command);
        return path.is_file().then_some(path);
    }

    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|dir| dir.join(command))
        .find(|path| path.is_file())
}

fn check_privileges(issues: &mut Vec<String>) {
    if is_effectively_privileged() {
        return;
    }

    #[cfg(target_os = "linux")]
    issues.push("wg mode needs root or CAP_NET_ADMIN to create/configure TUN devices, routes, forwarding, and firewall rules".to_owned());

    #[cfg(target_os = "macos")]
    issues.push(
        "wg mode needs root on macOS to create/configure utun devices, routes, and DNS settings"
            .to_owned(),
    );

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    issues.push("wg mode needs elevated network privileges on this platform".to_owned());
}

fn is_effectively_privileged() -> bool {
    effective_uid() == 0 || has_effective_linux_capability(CAP_NET_ADMIN)
}

fn effective_uid() -> u32 {
    unsafe { libc::geteuid() as u32 }
}

const CAP_NET_ADMIN: u8 = 12;

#[cfg(target_os = "linux")]
fn has_effective_linux_capability(capability: u8) -> bool {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return false;
    };
    let Some(hex) = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
    else {
        return false;
    };
    cap_eff_contains(hex, capability)
}

#[cfg(not(target_os = "linux"))]
fn has_effective_linux_capability(_capability: u8) -> bool {
    false
}

#[cfg(any(target_os = "linux", test))]
fn cap_eff_contains(hex: &str, capability: u8) -> bool {
    let Ok(value) = u64::from_str_radix(hex.trim(), 16) else {
        return false;
    };
    value & (1u64 << capability) != 0
}

#[cfg(test)]
mod tests {
    use super::cap_eff_contains;

    #[test]
    fn cap_eff_contains_detects_net_admin_bit() {
        assert!(cap_eff_contains("0000000000001000", 12));
        assert!(!cap_eff_contains("0000000000000000", 12));
    }

    #[test]
    fn cap_eff_contains_rejects_invalid_hex() {
        assert!(!cap_eff_contains("not-hex", 12));
    }
}
