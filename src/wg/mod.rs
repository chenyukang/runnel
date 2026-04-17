pub mod client;
pub mod configgen;
mod dns;
mod hooks;
pub mod keys;
mod preflight;
pub mod server;
mod stats;
mod uapi;

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::{
    device::{DeviceConfig, DeviceHandle},
    noise::Tunn,
    x25519::{PublicKey, StaticSecret},
};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};

pub(crate) const AUTO_WG_DEVICE: &str = "auto";
pub(crate) const DEFAULT_TUNNEL_MTU: u16 = 1420;
pub(crate) const HANDSHAKE_BUFFER_SIZE: usize = 2048;
const WG_KEY_LEN: usize = 32;
#[cfg(target_os = "macos")]
const MACOS_AUTO_WG_START_INDEX: u16 = 233;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WgRuntimeConfig {
    pub bind: SocketAddr,
    pub endpoint: Option<SocketAddr>,
    pub tunnel_ip: IpAddr,
    pub peer_tunnel_ip: IpAddr,
    pub mtu: u16,
    pub persistent_keepalive_secs: Option<u16>,
    pub private_key: [u8; WG_KEY_LEN],
    pub peer_public_key: [u8; WG_KEY_LEN],
    pub peer_allowed_ips: Vec<String>,
    pub excluded_ips: Vec<String>,
}

impl WgRuntimeConfig {
    pub(crate) fn validate(&self, role: &str) -> Result<()> {
        if self.mtu < 1280 {
            bail!("{role} mtu must be at least 1280, got {}", self.mtu);
        }
        if self.persistent_keepalive_secs == Some(0) {
            bail!("{role} persistent_keepalive_secs must be greater than 0");
        }
        if self.tunnel_ip == self.peer_tunnel_ip {
            bail!("{role} tunnel_ip and peer_tunnel_ip must differ");
        }
        if self.tunnel_ip.is_ipv4() != self.peer_tunnel_ip.is_ipv4() {
            bail!("{role} tunnel_ip and peer_tunnel_ip must use the same IP version");
        }
        if !self.bind.ip().is_unspecified() {
            bail!(
                "{role} currently requires an unspecified listen address because boringtun device mode binds UDP on all interfaces"
            );
        }
        if let Some(endpoint) = self.endpoint
            && !endpoint.ip().is_ipv4()
            && !endpoint.ip().is_ipv6()
        {
            bail!("{role} endpoint must resolve to an IP literal");
        }
        if self.peer_allowed_ips.is_empty() {
            bail!("{role} peer allowed IPs cannot be empty");
        }
        for allowed_ip in &self.peer_allowed_ips {
            allowed_ip.parse::<IpNet>().with_context(|| {
                format!("{role} allowed_ip must be a CIDR literal, got {allowed_ip}")
            })?;
        }
        for excluded_ip in &self.excluded_ips {
            excluded_ip.parse::<IpNet>().with_context(|| {
                format!("{role} exclude_ip must be a CIDR literal, got {excluded_ip}")
            })?;
        }
        Ok(())
    }

    pub(crate) fn new_tunnel(&self, index: u32) -> Tunn {
        Tunn::new(
            StaticSecret::from(self.private_key),
            PublicKey::from(self.peer_public_key),
            None,
            self.persistent_keepalive_secs,
            index,
            None,
        )
    }

    pub(crate) fn listen_port(&self) -> Option<u16> {
        (self.bind.port() != 0).then_some(self.bind.port())
    }

    pub(crate) fn endpoint_ip(&self) -> Option<IpAddr> {
        self.endpoint.map(|endpoint| endpoint.ip())
    }
}

pub(crate) fn parse_socket_addr(label: &str, value: &str) -> Result<SocketAddr> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} cannot be empty");
    }
    trimmed
        .parse()
        .with_context(|| format!("failed to parse {label} as host:port: {trimmed}"))
}

pub(crate) fn parse_key(label: &str, value: &str) -> Result<[u8; WG_KEY_LEN]> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!("{label} cannot be empty");
    }

    let raw = STANDARD
        .decode(trimmed)
        .with_context(|| format!("failed to decode {label} as base64"))?;
    if raw.len() != WG_KEY_LEN {
        bail!(
            "{label} must decode to exactly {WG_KEY_LEN} bytes, got {} bytes",
            raw.len()
        );
    }

    let mut out = [0u8; WG_KEY_LEN];
    out.copy_from_slice(&raw);
    Ok(out)
}

pub(crate) fn normalize_allowed_ips(
    role: &str,
    configured: &[String],
    defaults: &[String],
) -> Result<Vec<String>> {
    let values = if configured.is_empty() {
        defaults.to_vec()
    } else {
        configured.to_vec()
    };
    for value in &values {
        value
            .parse::<IpNet>()
            .with_context(|| format!("{role} allowed_ip must be CIDR, got {value}"))?;
    }
    Ok(values)
}

#[cfg(test)]
pub(crate) fn default_client_allowed_ips() -> Vec<String> {
    default_client_allowed_ips_for(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
}

pub(crate) fn default_client_allowed_ips_for(tunnel_ip: IpAddr) -> Vec<String> {
    vec![match tunnel_ip {
        IpAddr::V4(_) => "0.0.0.0/0".to_owned(),
        IpAddr::V6(_) => "::/0".to_owned(),
    }]
}

pub(crate) fn default_client_excluded_lan_ips() -> Vec<String> {
    vec![
        "10.0.0.0/8".to_owned(),
        "172.16.0.0/12".to_owned(),
        "192.168.0.0/16".to_owned(),
        "169.254.0.0/16".to_owned(),
        "fc00::/7".to_owned(),
        "fe80::/10".to_owned(),
        "ff00::/8".to_owned(),
    ]
}

pub(crate) fn default_server_allowed_ips(peer_tunnel_ip: IpAddr) -> Vec<String> {
    vec![match peer_tunnel_ip {
        IpAddr::V4(ip) => format!("{ip}/32"),
        IpAddr::V6(ip) => format!("{ip}/128"),
    }]
}

pub(crate) fn is_auto_device(device: &str) -> bool {
    let trimmed = device.trim();
    trimmed.is_empty() || trimmed.eq_ignore_ascii_case(AUTO_WG_DEVICE)
}

pub(crate) fn default_device_name() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "utun"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "pipitwg0"
    }
}

pub(crate) fn resolve_requested_device(device: &str) -> String {
    if is_auto_device(device) {
        default_device_name().to_owned()
    } else {
        device.trim().to_owned()
    }
}

pub(crate) fn select_device_name(requested_device: &str) -> Result<String> {
    #[cfg(target_os = "macos")]
    {
        if is_auto_device(requested_device) {
            return pick_available_macos_utun();
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = requested_device;
    }

    Ok(resolve_requested_device(requested_device))
}

pub(crate) fn create_device_handle(requested_device: &str) -> Result<(DeviceHandle, String)> {
    let requested_device = select_device_name(requested_device)?;
    #[cfg(not(target_os = "macos"))]
    let requested_device = requested_device;
    #[cfg(target_os = "macos")]
    let requested_device = requested_device;
    let config = DeviceConfig::default();

    let handle = DeviceHandle::new(&requested_device, config)
        .with_context(|| format!("failed to create boringtun device for {requested_device}"))?;
    Ok((handle, requested_device))
}

#[cfg(target_os = "macos")]
fn pick_available_macos_utun() -> Result<String> {
    let output = std::process::Command::new("ifconfig")
        .arg("-l")
        .output()
        .context("failed to list network interfaces for automatic WG device selection")?;
    if !output.status.success() {
        bail!(
            "failed to list network interfaces for automatic WG device selection: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let interfaces = String::from_utf8_lossy(&output.stdout);
    let in_use: std::collections::HashSet<&str> = interfaces.split_whitespace().collect();
    for index in MACOS_AUTO_WG_START_INDEX..u16::MAX {
        let candidate = format!("utun{index}");
        if !in_use.contains(candidate.as_str()) {
            return Ok(candidate);
        }
    }

    bail!(
        "failed to find a free utun device starting at utun{}",
        MACOS_AUTO_WG_START_INDEX
    )
}

pub(crate) async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .context("failed to register SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to wait for Ctrl-C")?;
            }
            _ = terminate.recv() => {}
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to wait for Ctrl-C")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTO_WG_DEVICE, HANDSHAKE_BUFFER_SIZE, WgRuntimeConfig, default_client_allowed_ips,
        default_server_allowed_ips, is_auto_device, normalize_allowed_ips, parse_key,
        resolve_requested_device,
    };
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boringtun::{
        noise::TunnResult,
        x25519::{PublicKey, StaticSecret},
    };
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn parse_key_rejects_non_32_byte_payloads() {
        let encoded = STANDARD.encode([0u8; 16]);
        let err = parse_key("test key", &encoded).unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "{err}");
    }

    #[test]
    fn runtime_config_bootstraps_boringtun_handshake() {
        let config = WgRuntimeConfig {
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
        };

        config.validate("wg test").unwrap();
        let mut tunnel = config.new_tunnel(7);
        let mut buffer = [0u8; HANDSHAKE_BUFFER_SIZE];
        let packet_len = match tunnel.format_handshake_initiation(&mut buffer, false) {
            TunnResult::WriteToNetwork(packet) => packet.len(),
            other => panic!("expected handshake packet, got {other:?}"),
        };
        assert_eq!(packet_len, 148);
    }

    #[test]
    fn paired_tunnels_complete_handshake_and_exchange_ipv4_packets() {
        let client_private = [0x11u8; 32];
        let server_private = [0x22u8; 32];
        let client_public = *PublicKey::from(&StaticSecret::from(client_private)).as_bytes();
        let server_public = *PublicKey::from(&StaticSecret::from(server_private)).as_bytes();

        let client_runtime = WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            endpoint: Some(SocketAddr::from(([198, 51, 100, 10], 51820))),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            private_key: client_private,
            peer_public_key: server_public,
            peer_allowed_ips: default_client_allowed_ips(),
            excluded_ips: Vec::new(),
        };
        let server_runtime = WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 51820)),
            endpoint: None,
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            mtu: 1420,
            persistent_keepalive_secs: None,
            private_key: server_private,
            peer_public_key: client_public,
            peer_allowed_ips: default_server_allowed_ips(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            excluded_ips: Vec::new(),
        };

        let mut client = client_runtime.new_tunnel(1);
        let mut server = server_runtime.new_tunnel(2);
        let client_remote_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let server_remote_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));

        let outbound = ipv4_packet(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(1, 1, 1, 1), 6);
        let mut client_buf = [0u8; HANDSHAKE_BUFFER_SIZE];
        let mut server_buf = [0u8; HANDSHAKE_BUFFER_SIZE];

        let handshake_init = network_packet(client.encapsulate(&outbound, &mut client_buf));
        let handshake_response = network_packet(server.decapsulate(
            Some(client_remote_ip),
            &handshake_init,
            &mut server_buf,
        ));
        let keepalive = network_packet(client.decapsulate(
            Some(server_remote_ip),
            &handshake_response,
            &mut client_buf,
        ));
        assert!(matches!(
            server.decapsulate(Some(client_remote_ip), &keepalive, &mut server_buf),
            TunnResult::Done
        ));

        let outbound_ciphertext =
            network_packet(client.decapsulate(Some(server_remote_ip), &[], &mut client_buf));
        expect_tunnel_ipv4(
            server.decapsulate(
                Some(client_remote_ip),
                &outbound_ciphertext,
                &mut server_buf,
            ),
            &outbound,
            Ipv4Addr::new(10, 8, 0, 2),
        );

        let inbound = ipv4_packet(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(10, 8, 0, 2), 17);
        let inbound_ciphertext = network_packet(server.encapsulate(&inbound, &mut server_buf));
        expect_tunnel_ipv4(
            client.decapsulate(Some(server_remote_ip), &inbound_ciphertext, &mut client_buf),
            &inbound,
            Ipv4Addr::new(1, 1, 1, 1),
        );
    }

    #[test]
    fn normalize_allowed_ips_uses_defaults_for_empty_input() {
        let defaults = default_client_allowed_ips();
        let result = normalize_allowed_ips("wg test", &[], &defaults).unwrap();
        assert_eq!(result, defaults);
    }

    #[test]
    fn default_server_allowed_ip_matches_peer_tunnel_ip() {
        assert_eq!(
            default_server_allowed_ips(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            vec!["10.8.0.2/32".to_owned()]
        );
    }

    #[test]
    fn auto_device_detection_handles_empty_and_keyword() {
        assert!(is_auto_device(AUTO_WG_DEVICE));
        assert!(is_auto_device(""));
        assert!(!is_auto_device("utun233"));
    }

    #[test]
    fn resolve_requested_device_uses_platform_default_for_auto() {
        assert_eq!(
            resolve_requested_device(AUTO_WG_DEVICE),
            super::default_device_name()
        );
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn select_device_name_uses_platform_default_for_auto() {
        assert_eq!(
            super::select_device_name(AUTO_WG_DEVICE).unwrap(),
            super::default_device_name()
        );
    }

    fn network_packet(result: TunnResult<'_>) -> Vec<u8> {
        match result {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected network packet, got {other:?}"),
        }
    }

    fn expect_tunnel_ipv4(result: TunnResult<'_>, expected: &[u8], expected_src: Ipv4Addr) {
        match result {
            TunnResult::WriteToTunnelV4(packet, src) => {
                assert_eq!(packet, expected);
                assert_eq!(src, expected_src);
            }
            other => panic!("expected IPv4 tunnel packet, got {other:?}"),
        }
    }

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x12, 0x34, 0x00, 0x00, 64, protocol, 0x00, 0x00,
        ];
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet
    }
}
