use crate::{client::ClientArgs, socks5, socks5::TargetAddr};
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpStream, lookup_host},
    sync::Mutex,
    time::timeout,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum FilterMode {
    Proxy,
    Direct,
    Rule,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RouteDecision {
    Direct,
    Remote,
    Block,
}

#[derive(Default)]
struct RuleTable {
    direct_globs: Vec<String>,
    remote_globs: Vec<String>,
    block_globs: Vec<String>,
    direct_cidrs: Vec<ipnet::IpNet>,
    remote_cidrs: Vec<ipnet::IpNet>,
    block_cidrs: Vec<ipnet::IpNet>,
}

pub struct Router {
    mode: FilterMode,
    table: RuleTable,
    cache: Mutex<HashMap<String, RouteDecision>>,
}

impl Router {
    pub fn from_args(args: &ClientArgs) -> Result<Arc<Self>> {
        let mut table = if matches!(args.filter, FilterMode::Rule) {
            RuleTable::load(
                args.rule_file.as_deref(),
                args.cidr_file.as_deref(),
            )?
        } else {
            RuleTable::default()
        };
        if matches!(args.filter, FilterMode::Rule) {
            table.direct_cidrs.extend(reserved_ip_nets());
        }

        Ok(Arc::new(Self {
            mode: args.filter,
            table,
            cache: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn decide(&self, target: &TargetAddr) -> Result<RouteDecision> {
        match self.mode {
            FilterMode::Proxy => Ok(RouteDecision::Remote),
            FilterMode::Direct => Ok(RouteDecision::Direct),
            FilterMode::Rule => self.decide_by_rule(target).await,
        }
    }

    async fn decide_by_rule(&self, target: &TargetAddr) -> Result<RouteDecision> {
        let host = target.host_string();
        if let Some(cached) = self.cache.lock().await.get(&host).copied() {
            return Ok(cached);
        }

        let decision = self.table.decide(target).await?;
        self.cache.lock().await.insert(host, decision);
        Ok(decision)
    }
}

impl RuleTable {
    fn load(rule_file: Option<&Path>, cidr_file: Option<&Path>) -> Result<Self> {
        let mut table = Self::default();
        if let Some(path) = rule_file {
            table.load_rule_file(path)?;
        }
        if let Some(path) = cidr_file {
            table.load_cidr_file(path)?;
        }
        Ok(table)
    }

    fn load_rule_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read rule file {}", path.display()))?;
        for (index, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 2 {
                continue;
            }
            match parts[0] {
                "L" => self
                    .direct_globs
                    .extend(parts[1..].iter().map(|s| (*s).to_owned())),
                "R" => self
                    .remote_globs
                    .extend(parts[1..].iter().map(|s| (*s).to_owned())),
                "B" => self
                    .block_globs
                    .extend(parts[1..].iter().map(|s| (*s).to_owned())),
                other => bail!(
                    "invalid rule mode '{}' at {}:{}",
                    other,
                    path.display(),
                    index + 1
                ),
            }
        }
        Ok(())
    }

    fn load_cidr_file(&mut self, path: &Path) -> Result<()> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read CIDR file {}", path.display()))?;
        for (index, line) in content.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 2 {
                continue;
            }
            let cidr = parts[1].parse::<ipnet::IpNet>().with_context(|| {
                format!("invalid CIDR '{}' at {}:{}", parts[1], path.display(), index + 1)
            })?;
            match parts[0] {
                "L" => self.direct_cidrs.push(cidr),
                "R" => self.remote_cidrs.push(cidr),
                "B" => self.block_cidrs.push(cidr),
                other => bail!(
                    "invalid CIDR mode '{}' at {}:{}",
                    other,
                    path.display(),
                    index + 1
                ),
            }
        }
        Ok(())
    }

    async fn decide(&self, target: &TargetAddr) -> Result<RouteDecision> {
        let host = target.host_string();
        if matches_any(&self.direct_globs, &host)? {
            return Ok(RouteDecision::Direct);
        }
        if matches_any(&self.remote_globs, &host)? {
            return Ok(RouteDecision::Remote);
        }
        if matches_any(&self.block_globs, &host)? {
            return Ok(RouteDecision::Block);
        }

        let addrs = resolve_target_ips(target).await?;
        if contains_any(&self.direct_cidrs, &addrs) {
            return Ok(RouteDecision::Direct);
        }
        if contains_any(&self.remote_cidrs, &addrs) {
            return Ok(RouteDecision::Remote);
        }
        if contains_any(&self.block_cidrs, &addrs) {
            return Ok(RouteDecision::Block);
        }

        Ok(RouteDecision::Remote)
    }
}

pub async fn relay_direct_socks(
    mut inbound: TcpStream,
    target: &TargetAddr,
    connect_timeout: Duration,
) -> Result<(u64, u64)> {
    let target_string = target.to_string();
    let mut outbound = timeout(connect_timeout, TcpStream::connect(&target_string))
        .await
        .context("direct connect timed out")??;
    outbound.set_nodelay(true)?;
    socks5::send_success(&mut inbound)
        .await
        .context("failed to send SOCKS success reply")?;
    copy_bidirectional(&mut inbound, &mut outbound)
        .await
        .context("direct relay failed")
}

fn matches_any(patterns: &[String], host: &str) -> Result<bool> {
    for pattern in patterns {
        if glob::Pattern::new(pattern)
            .with_context(|| format!("invalid glob pattern '{pattern}'"))?
            .matches(host)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn contains_any(cidrs: &[ipnet::IpNet], addrs: &[IpAddr]) -> bool {
    addrs.iter()
        .any(|addr| cidrs.iter().any(|cidr| cidr.contains(addr)))
}

async fn resolve_target_ips(target: &TargetAddr) -> Result<Vec<IpAddr>> {
    match target {
        TargetAddr::Ip(addr, _) => Ok(vec![*addr]),
        TargetAddr::Domain(host, port) => {
            let resolved = lookup_host((host.as_str(), *port))
                .await
                .with_context(|| format!("failed to resolve {host}"))?;
            let mut addrs = Vec::new();
            for addr in resolved {
                let ip = addr.ip();
                if !addrs.contains(&ip) {
                    addrs.push(ip);
                }
            }
            Ok(addrs)
        }
    }
}

pub fn reserved_ip_nets() -> Vec<ipnet::IpNet> {
    [
        IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)),
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(198, 18, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0)),
        IpAddr::V4(Ipv4Addr::new(224, 0, 0, 0)),
        IpAddr::V4(Ipv4Addr::new(240, 0, 0, 0)),
        IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ]
    .into_iter()
    .zip([
        8_u8, 8, 10, 8, 16, 12, 24, 24, 16, 15, 24, 24, 4, 4, 128, 128,
    ])
    .map(|(ip, prefix)| ipnet::IpNet::new(ip, prefix).expect("valid reserved CIDR"))
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rule_table_prefers_glob_before_default_remote() {
        let table = RuleTable {
            direct_globs: vec!["*.local".to_owned()],
            remote_globs: vec![],
            block_globs: vec!["blocked.example".to_owned()],
            direct_cidrs: vec![],
            remote_cidrs: vec![],
            block_cidrs: vec![],
        };

        assert_eq!(
            table
                .decide(&TargetAddr::Domain("printer.local".to_owned(), 80))
                .await
                .expect("rule decision"),
            RouteDecision::Direct
        );
        assert_eq!(
            table
                .decide(&TargetAddr::Domain("blocked.example".to_owned(), 80))
                .await
                .expect("rule decision"),
            RouteDecision::Block
        );
        assert_eq!(
            table
                .decide(&TargetAddr::Domain("example.com".to_owned(), 80))
                .await
                .expect("rule decision"),
            RouteDecision::Remote
        );
    }

    #[test]
    fn reserved_nets_contains_loopback() {
        let nets = reserved_ip_nets();
        assert!(contains_any(&nets, &[IpAddr::V4(Ipv4Addr::LOCALHOST)]));
        assert!(contains_any(&nets, &[IpAddr::V6(Ipv6Addr::LOCALHOST)]));
    }
}
