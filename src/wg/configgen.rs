use anyhow::{Result, bail};
use clap::Args;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

use super::{
    DEFAULT_TUNNEL_MTU, default_client_allowed_ips_for, default_server_allowed_ips,
    keys::generate_key_material, normalize_allowed_ips, parse_socket_addr,
};

#[derive(Clone, Debug, Args)]
pub struct WgConfigArgs {
    #[arg(long)]
    pub server_endpoint: String,
    #[arg(long, default_value = "10.8.0.2")]
    pub client_tunnel_ip: IpAddr,
    #[arg(long, default_value = "10.8.0.1")]
    pub server_tunnel_ip: IpAddr,
    #[arg(long, default_value_t = DEFAULT_TUNNEL_MTU)]
    pub mtu: u16,
    #[arg(long, default_value_t = 25)]
    pub persistent_keepalive_secs: u16,
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
    #[arg(long = "peer-allowed-ip")]
    pub peer_allowed_ips: Vec<String>,
    #[arg(long)]
    pub nat_out_interface: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GeneratedWgConfig {
    wg_client: GeneratedWgClientConfig,
    wg_server: GeneratedWgServerConfig,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GeneratedWgClientConfig {
    endpoint: String,
    private_key: String,
    peer_public_key: String,
    tunnel_ip: IpAddr,
    peer_tunnel_ip: IpAddr,
    mtu: u16,
    persistent_keepalive_secs: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    dns: Option<IpAddr>,
    #[serde(skip_serializing_if = "is_false")]
    dns_capture: bool,
    allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    excluded_ips: Vec<String>,
    #[serde(skip_serializing_if = "is_false")]
    exclude_lan: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GeneratedWgServerConfig {
    listen: String,
    private_key: String,
    peer_public_key: String,
    tunnel_ip: IpAddr,
    peer_tunnel_ip: IpAddr,
    mtu: u16,
    peer_allowed_ips: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nat_out_interface: Option<String>,
}

pub fn run_config(args: WgConfigArgs) -> Result<()> {
    let config = generate_config(&args)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&config)?);
    } else {
        println!("{}", serde_yaml::to_string(&config)?);
    }
    Ok(())
}

fn generate_config(args: &WgConfigArgs) -> Result<GeneratedWgConfig> {
    if args.persistent_keepalive_secs == 0 {
        bail!("wg config persistent_keepalive_secs must be greater than 0");
    }
    if args.client_tunnel_ip == args.server_tunnel_ip {
        bail!("wg config client_tunnel_ip and server_tunnel_ip must differ");
    }
    if args.dns_capture && args.dns.is_none() {
        bail!("wg config dns_capture requires --dns as the upstream resolver");
    }
    let server_endpoint = parse_socket_addr("wg config server_endpoint", &args.server_endpoint)?;
    let client_keys = generate_key_material();
    let server_keys = generate_key_material();
    let allowed_ips = normalize_allowed_ips(
        "wg config client",
        &args.allowed_ips,
        &default_client_allowed_ips_for(args.client_tunnel_ip),
    )?;
    let peer_allowed_ips = normalize_allowed_ips(
        "wg config server",
        &args.peer_allowed_ips,
        &default_server_allowed_ips(args.client_tunnel_ip),
    )?;
    let listen = server_listen_from_endpoint(server_endpoint);

    Ok(GeneratedWgConfig {
        wg_client: GeneratedWgClientConfig {
            endpoint: server_endpoint.to_string(),
            private_key: client_keys.private_key,
            peer_public_key: server_keys.public_key,
            tunnel_ip: args.client_tunnel_ip,
            peer_tunnel_ip: args.server_tunnel_ip,
            mtu: args.mtu,
            persistent_keepalive_secs: args.persistent_keepalive_secs,
            dns: args.dns,
            dns_capture: args.dns_capture,
            allowed_ips,
            excluded_ips: normalize_allowed_ips(
                "wg config client exclude",
                &args.excluded_ips,
                &[],
            )?,
            exclude_lan: args.exclude_lan,
        },
        wg_server: GeneratedWgServerConfig {
            listen,
            private_key: server_keys.private_key,
            peer_public_key: client_keys.public_key,
            tunnel_ip: args.server_tunnel_ip,
            peer_tunnel_ip: args.client_tunnel_ip,
            mtu: args.mtu,
            peer_allowed_ips,
            nat_out_interface: args.nat_out_interface.clone(),
        },
    })
}

fn is_false(value: &bool) -> bool {
    !*value
}

fn server_listen_from_endpoint(endpoint: SocketAddr) -> String {
    if endpoint.is_ipv6() {
        format!("[::]:{}", endpoint.port())
    } else {
        format!("0.0.0.0:{}", endpoint.port())
    }
}

#[cfg(test)]
mod tests {
    use super::{WgConfigArgs, generate_config};
    use crate::config::FileConfig;
    use crate::wg::keys::public_key_from_private_key;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn config_generator_outputs_crossed_key_pairs_and_parseable_yaml() {
        let args = WgConfigArgs {
            server_endpoint: "198.51.100.10:51820".to_owned(),
            client_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            server_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: 25,
            dns: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            dns_capture: false,
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            peer_allowed_ips: Vec::new(),
            nat_out_interface: Some("eth0".to_owned()),
            json: false,
        };

        let generated = generate_config(&args).unwrap();
        assert_eq!(generated.wg_client.endpoint, "198.51.100.10:51820");
        assert_eq!(generated.wg_server.listen, "0.0.0.0:51820");
        assert_eq!(generated.wg_client.allowed_ips, vec!["0.0.0.0/0"]);
        assert_eq!(generated.wg_server.peer_allowed_ips, vec!["10.8.0.2/32"]);
        assert_eq!(
            generated.wg_client.peer_public_key,
            public_key_from_private_key(&generated.wg_server.private_key).unwrap()
        );
        assert_eq!(
            generated.wg_server.peer_public_key,
            public_key_from_private_key(&generated.wg_client.private_key).unwrap()
        );

        let yaml = serde_yaml::to_string(&generated).unwrap();
        let parsed: FileConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            parsed
                .wg_client
                .as_ref()
                .and_then(|cfg| cfg.endpoint.as_deref()),
            Some("198.51.100.10:51820")
        );
        assert_eq!(
            parsed
                .wg_server
                .as_ref()
                .and_then(|cfg| cfg.nat_out_interface.as_deref()),
            Some("eth0")
        );
    }

    #[test]
    fn config_generator_preserves_custom_allowed_ips() {
        let args = WgConfigArgs {
            server_endpoint: "198.51.100.10:51820".to_owned(),
            client_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            server_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1280,
            persistent_keepalive_secs: 30,
            dns: None,
            dns_capture: false,
            allowed_ips: vec!["203.0.113.0/24".to_owned()],
            excluded_ips: vec!["192.168.0.0/16".to_owned()],
            exclude_lan: true,
            peer_allowed_ips: vec!["10.9.0.0/24".to_owned()],
            nat_out_interface: None,
            json: true,
        };

        let generated = generate_config(&args).unwrap();
        assert_eq!(generated.wg_client.allowed_ips, vec!["203.0.113.0/24"]);
        assert_eq!(generated.wg_client.excluded_ips, vec!["192.168.0.0/16"]);
        assert!(generated.wg_client.exclude_lan);
        assert_eq!(generated.wg_server.peer_allowed_ips, vec!["10.9.0.0/24"]);
        assert_eq!(generated.wg_client.mtu, 1280);
        assert_eq!(generated.wg_client.persistent_keepalive_secs, 30);
    }

    #[test]
    fn config_generator_defaults_to_ipv6_allowed_ip_for_ipv6_tunnel() {
        let args = WgConfigArgs {
            server_endpoint: "[2001:db8::10]:51820".to_owned(),
            client_tunnel_ip: IpAddr::V6("fd00:8::2".parse().unwrap()),
            server_tunnel_ip: IpAddr::V6("fd00:8::1".parse().unwrap()),
            mtu: 1420,
            persistent_keepalive_secs: 25,
            dns: Some(IpAddr::V6("2606:4700:4700::1111".parse().unwrap())),
            dns_capture: false,
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            json: false,
        };

        let generated = generate_config(&args).unwrap();
        assert_eq!(generated.wg_client.allowed_ips, vec!["::/0"]);
        assert_eq!(generated.wg_server.listen, "[::]:51820");
        assert_eq!(generated.wg_server.peer_allowed_ips, vec!["fd00:8::2/128"]);
    }

    #[test]
    fn config_generator_rejects_invalid_inputs() {
        let args = WgConfigArgs {
            server_endpoint: "198.51.100.10:51820".to_owned(),
            client_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            server_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            mtu: 1420,
            persistent_keepalive_secs: 0,
            dns: None,
            dns_capture: false,
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            json: false,
        };

        let err = generate_config(&args).unwrap_err().to_string();
        assert!(err.contains("persistent_keepalive_secs"), "{err}");
    }
}
