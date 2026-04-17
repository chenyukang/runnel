use anyhow::{Result, bail};
use clap::Args;
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};

use crate::proxy::route::{self, RouteRuleConfig};

use super::{
    DEFAULT_TUNNEL_MTU, default_server_allowed_ips, keys::generate_key_material,
    normalize_allowed_ips, parse_socket_addr,
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
    #[arg(long = "direct-ip")]
    pub direct_ips: Vec<String>,
    #[arg(long = "peer-allowed-ip")]
    pub peer_allowed_ips: Vec<String>,
    #[arg(long)]
    pub nat_out_interface: Option<String>,
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GeneratedWgConfig {
    client: GeneratedWgClientSection,
    server: GeneratedWgServerSection,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GeneratedWgClientSection {
    mode: &'static str,
    #[serde(skip_serializing_if = "RouteRuleConfig::is_empty")]
    ip_rules: RouteRuleConfig,
    wg: GeneratedWgClientConfig,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct GeneratedWgServerSection {
    mode: &'static str,
    wg: GeneratedWgServerConfig,
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
    validate_ip_rules("wg config client direct", &args.direct_ips)?;
    let peer_allowed_ips = normalize_allowed_ips(
        "wg config server",
        &args.peer_allowed_ips,
        &default_server_allowed_ips(args.client_tunnel_ip),
    )?;
    let listen = server_listen_from_endpoint(server_endpoint);

    Ok(GeneratedWgConfig {
        client: GeneratedWgClientSection {
            mode: "wg",
            ip_rules: RouteRuleConfig {
                direct: args.direct_ips.clone(),
                proxy: Vec::new(),
                block: Vec::new(),
            },
            wg: GeneratedWgClientConfig {
                endpoint: server_endpoint.to_string(),
                private_key: client_keys.private_key,
                peer_public_key: server_keys.public_key,
                tunnel_ip: args.client_tunnel_ip,
                peer_tunnel_ip: args.server_tunnel_ip,
                mtu: args.mtu,
                persistent_keepalive_secs: args.persistent_keepalive_secs,
                dns: args.dns,
                dns_capture: args.dns_capture,
            },
        },
        server: GeneratedWgServerSection {
            mode: "wg",
            wg: GeneratedWgServerConfig {
                listen,
                private_key: server_keys.private_key,
                peer_public_key: client_keys.public_key,
                tunnel_ip: args.server_tunnel_ip,
                peer_tunnel_ip: args.client_tunnel_ip,
                mtu: args.mtu,
                peer_allowed_ips,
                nat_out_interface: args.nat_out_interface.clone(),
            },
        },
    })
}

fn validate_ip_rules(label: &str, rules: &[String]) -> Result<()> {
    route::parse_ip_rule_entries(label, rules)?;
    Ok(())
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
            direct_ips: Vec::new(),
            peer_allowed_ips: Vec::new(),
            nat_out_interface: Some("eth0".to_owned()),
            json: false,
        };

        let generated = generate_config(&args).unwrap();
        assert_eq!(generated.client.mode, "wg");
        assert_eq!(generated.server.mode, "wg");
        assert_eq!(generated.client.wg.endpoint, "198.51.100.10:51820");
        assert_eq!(generated.server.wg.listen, "0.0.0.0:51820");
        assert!(generated.client.ip_rules.is_empty());
        assert_eq!(generated.server.wg.peer_allowed_ips, vec!["10.8.0.2/32"]);
        assert_eq!(
            generated.client.wg.peer_public_key,
            public_key_from_private_key(&generated.server.wg.private_key).unwrap()
        );
        assert_eq!(
            generated.server.wg.peer_public_key,
            public_key_from_private_key(&generated.client.wg.private_key).unwrap()
        );

        let yaml = serde_yaml::to_string(&generated).unwrap();
        assert!(!yaml.contains("proxy:"), "{yaml}");
        let parsed: FileConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.endpoint.as_deref()),
            Some("198.51.100.10:51820")
        );
        assert_eq!(
            parsed
                .server
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.nat_out_interface.as_deref()),
            Some("eth0")
        );
    }

    #[test]
    fn config_generator_preserves_custom_ip_rules() {
        let args = WgConfigArgs {
            server_endpoint: "198.51.100.10:51820".to_owned(),
            client_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            server_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1280,
            persistent_keepalive_secs: 30,
            dns: None,
            dns_capture: false,
            direct_ips: vec!["192.168.*".to_owned()],
            peer_allowed_ips: vec!["10.9.0.0/24".to_owned()],
            nat_out_interface: None,
            json: true,
        };

        let generated = generate_config(&args).unwrap();
        assert!(generated.client.ip_rules.proxy.is_empty());
        assert_eq!(
            generated.client.ip_rules.direct,
            vec!["192.168.*".to_owned()]
        );
        assert_eq!(generated.server.wg.peer_allowed_ips, vec!["10.9.0.0/24"]);
        assert_eq!(generated.client.wg.mtu, 1280);
        assert_eq!(generated.client.wg.persistent_keepalive_secs, 30);

        let yaml = serde_yaml::to_string(&generated).unwrap();
        assert!(yaml.contains("direct:"), "{yaml}");
        assert!(!yaml.contains("proxy:"), "{yaml}");
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
            direct_ips: Vec::new(),
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            json: false,
        };

        let generated = generate_config(&args).unwrap();
        assert!(generated.client.ip_rules.is_empty());
        assert_eq!(generated.server.wg.listen, "[::]:51820");
        assert_eq!(generated.server.wg.peer_allowed_ips, vec!["fd00:8::2/128"]);
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
            direct_ips: Vec::new(),
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            json: false,
        };

        let err = generate_config(&args).unwrap_err().to_string();
        assert!(err.contains("persistent_keepalive_secs"), "{err}");
    }
}
