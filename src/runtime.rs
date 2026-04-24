use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    time::Duration,
};

use crate::{
    client::ClientArgs,
    proxy::{
        adblock::AdblockConfig,
        route::{FilterMode, RouteRuleConfig},
        socks5,
    },
    server::ServerArgs,
};

const TUN_DNS_PORT: u16 = 53;

#[derive(Clone, Debug)]
pub(crate) struct ClientRuntime {
    pub listen: String,
    pub server: String,
    pub server_name: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub password: String,
    pub path: String,
    pub mux_path: String,
    pub filter: FilterMode,
    pub rule_file: Option<PathBuf>,
    pub cidr_file: Option<PathBuf>,
    pub domain_rules: RouteRuleConfig,
    pub ip_rules: RouteRuleConfig,
    pub adblock: AdblockConfig,
    pub user_agent: String,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_header_size: usize,
    pub tun_dns_redirect_ip: Option<IpAddr>,
    pub tun_dns_upstream: Option<SocketAddr>,
}

impl ClientRuntime {
    pub(crate) fn from_args(args: &ClientArgs) -> Self {
        Self {
            listen: args.listen.clone(),
            server: args.server.clone(),
            server_name: args.server_name.clone(),
            ca_cert: args.ca_cert.clone(),
            password: args.password.clone(),
            path: args.path.clone(),
            mux_path: args.mux_path.clone(),
            filter: args.filter,
            rule_file: args.rule_file.clone(),
            cidr_file: args.cidr_file.clone(),
            domain_rules: args.domain_rules.clone(),
            ip_rules: args.ip_rules.clone(),
            adblock: args.adblock.clone(),
            user_agent: args.user_agent.clone(),
            handshake_timeout: Duration::from_secs(args.handshake_timeout_secs),
            connect_timeout: Duration::from_secs(args.connect_timeout_secs),
            max_header_size: args.max_header_size,
            tun_dns_redirect_ip: args.tun_dns_redirect_ip,
            tun_dns_upstream: args.tun_dns_upstream,
        }
    }

    pub(crate) fn tun_dns_tcp_upstream(&self, target: &socks5::TargetAddr) -> Option<SocketAddr> {
        let redirect_ip = self.tun_dns_redirect_ip?;
        let upstream = self.tun_dns_upstream?;
        match target {
            socks5::TargetAddr::Ip(ip, port) if *ip == redirect_ip && *port == TUN_DNS_PORT => {
                Some(upstream)
            }
            _ => None,
        }
    }

    pub(crate) fn tun_dns_udp_upstream(
        &self,
        target: &socks5::TargetAddr,
    ) -> Option<socks5::TargetAddr> {
        let upstream = self.tun_dns_upstream?;
        match target {
            socks5::TargetAddr::Ip(ip, port)
                if (*port == TUN_DNS_PORT || *port == upstream.port())
                    && (self.tun_dns_redirect_ip == Some(*ip) || *ip == upstream.ip()) =>
            {
                Some(socks5::TargetAddr::Ip(upstream.ip(), upstream.port()))
            }
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ServerRuntime {
    pub listen: String,
    pub password: String,
    pub mux_path: String,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    pub max_header_size: usize,
    pub max_tunnel_body_size: usize,
    pub allow_private_targets: bool,
    pub fallback_url: String,
    pub fallback_timeout: Duration,
    pub max_fallback_body_size: usize,
}

impl ServerRuntime {
    pub(crate) fn from_args(args: &ServerArgs) -> Self {
        Self {
            listen: args.listen.clone(),
            password: args.password.clone(),
            mux_path: args.mux_path.clone(),
            handshake_timeout: Duration::from_secs(args.handshake_timeout_secs),
            connect_timeout: Duration::from_secs(args.connect_timeout_secs),
            max_header_size: args.max_header_size,
            max_tunnel_body_size: args.max_tunnel_body_size,
            allow_private_targets: args.allow_private_targets,
            fallback_url: args.fallback_url.clone(),
            fallback_timeout: Duration::from_secs(args.fallback_timeout_secs),
            max_fallback_body_size: args.max_fallback_body_size,
        }
    }
}
