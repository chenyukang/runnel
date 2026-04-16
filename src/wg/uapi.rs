use anyhow::{Context, Result, bail};
use hex::encode as hex_encode;
use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    thread::sleep,
    time::Duration,
};

use super::WgRuntimeConfig;

pub(crate) fn control_socket_path(device_name: &str) -> PathBuf {
    Path::new("/var/run/wireguard").join(format!("{device_name}.sock"))
}

pub(crate) fn build_set_request(runtime: &WgRuntimeConfig) -> String {
    let mut lines = vec![format!("private_key={}", hex_encode(runtime.private_key))];
    if let Some(listen_port) = runtime.listen_port() {
        lines.push(format!("listen_port={listen_port}"));
    }
    lines.push("replace_peers=true".to_owned());
    lines.push(format!(
        "public_key={}",
        hex_encode(runtime.peer_public_key)
    ));
    if let Some(endpoint) = runtime.endpoint {
        lines.push(format!("endpoint={endpoint}"));
    }
    if let Some(keepalive) = runtime.persistent_keepalive_secs {
        lines.push(format!("persistent_keepalive_interval={keepalive}"));
    }
    lines.extend(
        runtime
            .peer_allowed_ips
            .iter()
            .map(|allowed_ip| format!("allowed_ip={allowed_ip}")),
    );
    lines.join("\n")
}

pub(crate) fn apply_device_config(socket_path: &Path, runtime: &WgRuntimeConfig) -> Result<()> {
    let request = build_set_request(runtime);
    send_set_request(socket_path, &request)
}

fn send_set_request(socket_path: &Path, body: &str) -> Result<()> {
    let mut last_error = None;
    for _ in 0..20 {
        match try_send_set_request(socket_path, body) {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_error = Some(err);
                sleep(Duration::from_millis(50));
            }
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("failed to configure boringtun UAPI socket")))
}

fn try_send_set_request(socket_path: &Path, body: &str) -> Result<()> {
    let mut socket = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "failed to connect boringtun UAPI socket {}",
            socket_path.display()
        )
    })?;
    write!(socket, "set=1\n{body}\n\n").with_context(|| {
        format!(
            "failed to write boringtun UAPI socket {}",
            socket_path.display()
        )
    })?;
    let mut response = String::new();
    socket.read_to_string(&mut response).with_context(|| {
        format!(
            "failed to read boringtun UAPI socket {}",
            socket_path.display()
        )
    })?;
    parse_errno(&response)
}

fn parse_errno(response: &str) -> Result<()> {
    let errno = response
        .lines()
        .find_map(|line| line.strip_prefix("errno="))
        .context("boringtun UAPI response did not include errno")?;
    let errno: i32 = errno
        .parse()
        .with_context(|| format!("invalid boringtun errno field: {errno}"))?;
    if errno == 0 {
        return Ok(());
    }
    bail!("boringtun UAPI returned errno={errno}: {response}");
}

#[cfg(test)]
mod tests {
    use super::{build_set_request, control_socket_path};
    use crate::wg::{WgRuntimeConfig, default_client_allowed_ips, default_server_allowed_ips};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn control_socket_path_uses_wireguard_run_dir() {
        assert_eq!(
            control_socket_path("utun123"),
            std::path::Path::new("/var/run/wireguard/utun123.sock")
        );
    }

    #[test]
    fn client_set_request_contains_endpoint_keepalive_and_ipv4_full_tunnel_allowed_ips() {
        let runtime = WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 51820)),
            endpoint: Some(SocketAddr::from(([198, 51, 100, 10], 51820))),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            private_key: [0x11; 32],
            peer_public_key: [0x22; 32],
            peer_allowed_ips: default_client_allowed_ips(),
        };

        let request = build_set_request(&runtime);
        assert!(request.contains(
            "private_key=1111111111111111111111111111111111111111111111111111111111111111"
        ));
        assert!(request.contains("listen_port=51820"));
        assert!(request.contains("endpoint=198.51.100.10:51820"));
        assert!(request.contains("persistent_keepalive_interval=25"));
        assert!(request.contains("allowed_ip=0.0.0.0/0"));
        assert!(!request.contains("allowed_ip=::/0"));
    }

    #[test]
    fn server_set_request_defaults_to_host_route_for_peer_tunnel_ip() {
        let runtime = WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 51820)),
            endpoint: None,
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            mtu: 1420,
            persistent_keepalive_secs: None,
            private_key: [0x33; 32],
            peer_public_key: [0x44; 32],
            peer_allowed_ips: default_server_allowed_ips(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
        };

        let request = build_set_request(&runtime);
        assert!(request.contains("replace_peers=true"));
        assert!(request.contains(
            "public_key=4444444444444444444444444444444444444444444444444444444444444444"
        ));
        assert!(request.contains("allowed_ip=10.8.0.2/32"));
        assert!(!request.contains("endpoint="));
        assert!(!request.contains("persistent_keepalive_interval="));
    }
}
