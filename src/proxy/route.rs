use super::{adblock::Adblocker, socks5, socks5::TargetAddr, traffic};
use crate::client::ClientArgs;
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::{TcpStream, lookup_host},
    sync::Mutex,
    time::timeout,
};

const IPV4_WILDCARD_EXPANSION_LIMIT: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Deserialize)]
#[serde(rename_all = "kebab-case")]
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

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteRuleConfig {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub direct: Vec<String>,
    #[serde(alias = "remote")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub proxy: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub block: Vec<String>,
}

impl RouteRuleConfig {
    pub fn is_empty(&self) -> bool {
        self.direct.is_empty() && self.proxy.is_empty() && self.block.is_empty()
    }
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
    adblock: Option<Arc<Adblocker>>,
    cache: Mutex<HashMap<String, RouteDecision>>,
}

impl Router {
    pub async fn from_args(args: &ClientArgs) -> Result<Arc<Self>> {
        let should_load_inline_rules = !args.domain_rules.is_empty() || !args.ip_rules.is_empty();
        let mut table = if matches!(args.filter, FilterMode::Rule) || should_load_inline_rules {
            RuleTable::load(
                matches!(args.filter, FilterMode::Rule)
                    .then_some(args.rule_file.as_deref())
                    .flatten(),
                matches!(args.filter, FilterMode::Rule)
                    .then_some(args.cidr_file.as_deref())
                    .flatten(),
                &args.domain_rules,
                &args.ip_rules,
            )?
        } else {
            RuleTable::default()
        };
        if matches!(args.filter, FilterMode::Rule) {
            table.direct_cidrs.extend(reserved_ip_nets());
        }
        let adblock = Adblocker::from_config(&args.adblock).await?;

        Ok(Arc::new(Self {
            mode: args.filter,
            table,
            adblock,
            cache: Mutex::new(HashMap::new()),
        }))
    }

    pub async fn decide(&self, target: &TargetAddr) -> Result<RouteDecision> {
        if let Some(cached) = self.cache.lock().await.get(&cache_key(target)).copied() {
            return Ok(cached);
        }

        let decision = self.decide_uncached(target).await?;
        self.cache.lock().await.insert(cache_key(target), decision);
        Ok(decision)
    }

    async fn decide_uncached(&self, target: &TargetAddr) -> Result<RouteDecision> {
        if let Some(decision) = self.table.decide_block_only(target).await? {
            return Ok(decision);
        }
        if let Some(adblock) = &self.adblock
            && adblock.blocks_target(target).await
        {
            return Ok(RouteDecision::Block);
        }

        match self.mode {
            FilterMode::Proxy => Ok(RouteDecision::Remote),
            FilterMode::Direct => Ok(RouteDecision::Direct),
            FilterMode::Rule => self.table.decide_route_only(target).await,
        }
    }
}

impl RuleTable {
    fn load(
        rule_file: Option<&Path>,
        cidr_file: Option<&Path>,
        domain_rules: &RouteRuleConfig,
        ip_rules: &RouteRuleConfig,
    ) -> Result<Self> {
        let mut table = Self::default();
        if let Some(path) = rule_file {
            table.load_rule_file(path)?;
        }
        if let Some(path) = cidr_file {
            table.load_cidr_file(path)?;
        }
        table.load_domain_rules(domain_rules)?;
        table.load_ip_rules(ip_rules)?;
        Ok(table)
    }

    fn load_domain_rules(&mut self, rules: &RouteRuleConfig) -> Result<()> {
        validate_domain_patterns("client.domain_rules.direct", &rules.direct)?;
        validate_domain_patterns("client.domain_rules.proxy", &rules.proxy)?;
        validate_domain_patterns("client.domain_rules.block", &rules.block)?;
        self.direct_globs.extend(rules.direct.iter().cloned());
        self.remote_globs.extend(rules.proxy.iter().cloned());
        self.block_globs.extend(rules.block.iter().cloned());
        Ok(())
    }

    fn load_ip_rules(&mut self, rules: &RouteRuleConfig) -> Result<()> {
        self.direct_cidrs.extend(parse_ip_rule_entries(
            "client.ip_rules.direct",
            &rules.direct,
        )?);
        self.remote_cidrs.extend(parse_ip_rule_entries(
            "client.ip_rules.proxy",
            &rules.proxy,
        )?);
        self.block_cidrs.extend(parse_ip_rule_entries(
            "client.ip_rules.block",
            &rules.block,
        )?);
        Ok(())
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
            let cidrs = parse_ip_rule_entry(parts[1]).with_context(|| {
                format!(
                    "invalid CIDR '{}' at {}:{}",
                    parts[1],
                    path.display(),
                    index + 1
                )
            })?;
            match parts[0] {
                "L" => self.direct_cidrs.extend(cidrs),
                "R" => self.remote_cidrs.extend(cidrs),
                "B" => self.block_cidrs.extend(cidrs),
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

    #[cfg(test)]
    async fn decide(&self, target: &TargetAddr) -> Result<RouteDecision> {
        let host = target.host_string();
        if matches_any(&self.block_globs, &host)? {
            return Ok(RouteDecision::Block);
        }

        if !self.block_cidrs.is_empty() {
            let addrs = resolve_target_ips(target).await?;
            if contains_any(&self.block_cidrs, &addrs) {
                return Ok(RouteDecision::Block);
            }
            return self
                .decide_route_only_with_addrs(target, Some(&addrs))
                .await;
        }

        self.decide_route_only(target).await
    }

    async fn decide_route_only(&self, target: &TargetAddr) -> Result<RouteDecision> {
        self.decide_route_only_with_addrs(target, None).await
    }

    async fn decide_route_only_with_addrs(
        &self,
        target: &TargetAddr,
        known_addrs: Option<&[IpAddr]>,
    ) -> Result<RouteDecision> {
        let host = target.host_string();
        if matches_any(&self.direct_globs, &host)? {
            return Ok(RouteDecision::Direct);
        }
        if matches_any(&self.remote_globs, &host)? {
            return Ok(RouteDecision::Remote);
        }

        let addrs;
        let addrs = if let Some(addrs) = known_addrs {
            addrs
        } else {
            addrs = resolve_target_ips(target).await?;
            &addrs
        };
        if contains_any(&self.direct_cidrs, addrs) {
            return Ok(RouteDecision::Direct);
        }
        if contains_any(&self.remote_cidrs, addrs) {
            return Ok(RouteDecision::Remote);
        }

        Ok(RouteDecision::Remote)
    }

    async fn decide_block_only(&self, target: &TargetAddr) -> Result<Option<RouteDecision>> {
        let host = target.host_string();
        if matches_any(&self.block_globs, &host)? {
            return Ok(Some(RouteDecision::Block));
        }
        if self.block_cidrs.is_empty() {
            return Ok(None);
        }
        let addrs = resolve_target_ips(target).await?;
        if contains_any(&self.block_cidrs, &addrs) {
            return Ok(Some(RouteDecision::Block));
        }
        Ok(None)
    }
}

fn cache_key(target: &TargetAddr) -> String {
    target.to_string()
}

pub async fn relay_direct_socks(
    mut inbound: TcpStream,
    target: &TargetAddr,
    connect_timeout: Duration,
    mode: Option<&str>,
) -> Result<traffic::RelayStats> {
    let target_string = target.to_string();
    let outbound = timeout(connect_timeout, TcpStream::connect(&target_string))
        .await
        .context("direct connect timed out")??;
    outbound.set_nodelay(true)?;
    socks5::send_success(&mut inbound)
        .await
        .context("failed to send SOCKS success reply")?;
    traffic::relay_with_telemetry(
        inbound,
        outbound,
        traffic::RelayLabels {
            target: target_string,
            route: Some("direct".to_owned()),
            mode: mode.map(str::to_owned),
        },
    )
    .await
    .context("direct relay failed")
}

fn matches_any(patterns: &[String], host: &str) -> Result<bool> {
    let host = normalize_domain(host);
    for pattern in patterns {
        let pattern = normalize_domain(pattern);
        if let Some(suffix) = pattern.strip_prefix("*.")
            && (host == suffix || host.ends_with(&format!(".{suffix}")))
        {
            return Ok(true);
        }
        if glob::Pattern::new(&pattern)
            .with_context(|| format!("invalid glob pattern '{pattern}'"))?
            .matches(&host)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn matches_domain_rules(patterns: &[String], host: &str) -> Result<bool> {
    matches_any(patterns, host)
}

pub(crate) fn validate_domain_rule_entries(label: &str, patterns: &[String]) -> Result<()> {
    validate_domain_patterns(label, patterns)
}

fn normalize_domain(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

fn validate_domain_patterns(label: &str, patterns: &[String]) -> Result<()> {
    for pattern in patterns {
        glob::Pattern::new(&normalize_domain(pattern))
            .with_context(|| format!("invalid glob pattern in {label}: '{pattern}'"))?;
    }
    Ok(())
}

fn contains_any(cidrs: &[ipnet::IpNet], addrs: &[IpAddr]) -> bool {
    addrs
        .iter()
        .any(|addr| cidrs.iter().any(|cidr| cidr.contains(addr)))
}

pub fn parse_ip_rule_entries(label: &str, entries: &[String]) -> Result<Vec<ipnet::IpNet>> {
    let mut cidrs = Vec::new();
    for entry in entries {
        cidrs.extend(
            parse_ip_rule_entry(entry)
                .with_context(|| format!("invalid IP rule in {label}: '{entry}'"))?,
        );
    }
    Ok(cidrs)
}

fn parse_ip_rule_entry(entry: &str) -> Result<Vec<ipnet::IpNet>> {
    let entry = entry.trim();
    if entry.is_empty() {
        bail!("IP rule cannot be empty");
    }
    if entry.contains('*') {
        return parse_ipv4_wildcard_rule(entry);
    }
    if let Ok(ip) = entry.parse::<IpAddr>() {
        let prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        return Ok(vec![
            ipnet::IpNet::new(ip, prefix).expect("host route prefix is valid"),
        ]);
    }
    let net = entry
        .parse::<ipnet::IpNet>()
        .with_context(|| format!("expected CIDR, IP literal, or IPv4 wildcard, got {entry}"))?;
    Ok(vec![truncate_net(net)])
}

fn parse_ipv4_wildcard_rule(entry: &str) -> Result<Vec<ipnet::IpNet>> {
    if entry.contains('/') || entry.contains(':') {
        bail!("IPv4 wildcard rules cannot contain CIDR prefixes or IPv6 separators");
    }

    let parts = entry.split('.').collect::<Vec<_>>();
    if parts.is_empty() || parts.len() > 4 {
        bail!("IPv4 wildcard must contain between 1 and 4 octets");
    }

    let mut pattern = [None; 4];
    let mut has_concrete_after_wildcard = false;
    let mut saw_wildcard = false;
    for (index, part) in parts.iter().enumerate() {
        if part.is_empty() {
            bail!("IPv4 wildcard contains an empty octet");
        }
        if *part == "*" {
            saw_wildcard = true;
            continue;
        }
        if saw_wildcard {
            has_concrete_after_wildcard = true;
        }
        pattern[index] = Some(
            part.parse::<u8>()
                .with_context(|| format!("IPv4 wildcard octet '{part}' is not in 0..=255"))?,
        );
    }

    if has_concrete_after_wildcard && parts.len() != 4 {
        bail!("non-suffix IPv4 wildcards must contain exactly 4 octets");
    }

    if is_suffix_wildcard(&pattern) {
        let concrete = pattern.iter().filter(|part| part.is_some()).count();
        let mut octets = [0u8; 4];
        for (index, part) in pattern.iter().enumerate() {
            if let Some(part) = part {
                octets[index] = *part;
            }
        }
        let prefix = u8::try_from(concrete * 8).expect("prefix is at most 32");
        let net = ipnet::Ipv4Net::new(Ipv4Addr::from(octets), prefix)
            .with_context(|| format!("invalid IPv4 wildcard rule {entry}"))?;
        return Ok(vec![ipnet::IpNet::V4(net.trunc())]);
    }

    let wildcard_count = pattern.iter().filter(|part| part.is_none()).count();
    let expansion_count = 256usize
        .checked_pow(u32::try_from(wildcard_count).expect("wildcard count fits"))
        .context("IPv4 wildcard expansion overflowed")?;
    if expansion_count > IPV4_WILDCARD_EXPANSION_LIMIT {
        bail!(
            "IPv4 wildcard expands to {expansion_count} host routes, above limit {IPV4_WILDCARD_EXPANSION_LIMIT}"
        );
    }

    let mut routes = Vec::with_capacity(expansion_count);
    expand_ipv4_wildcard(&pattern, 0, [0u8; 4], &mut routes);
    Ok(routes)
}

fn is_suffix_wildcard(pattern: &[Option<u8>; 4]) -> bool {
    let Some(first_wildcard) = pattern.iter().position(Option::is_none) else {
        return false;
    };
    pattern[first_wildcard..].iter().all(Option::is_none)
}

fn expand_ipv4_wildcard(
    pattern: &[Option<u8>; 4],
    index: usize,
    mut octets: [u8; 4],
    routes: &mut Vec<ipnet::IpNet>,
) {
    if index == octets.len() {
        routes.push(ipnet::IpNet::V4(
            ipnet::Ipv4Net::new(Ipv4Addr::from(octets), 32).expect("host IPv4 route is valid"),
        ));
        return;
    }

    match pattern[index] {
        Some(octet) => {
            octets[index] = octet;
            expand_ipv4_wildcard(pattern, index + 1, octets, routes);
        }
        None => {
            for octet in 0..=u8::MAX {
                octets[index] = octet;
                expand_ipv4_wildcard(pattern, index + 1, octets, routes);
            }
        }
    }
}

fn truncate_net(net: ipnet::IpNet) -> ipnet::IpNet {
    match net {
        ipnet::IpNet::V4(net) => ipnet::IpNet::V4(net.trunc()),
        ipnet::IpNet::V6(net) => ipnet::IpNet::V6(net.trunc()),
    }
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

    #[tokio::test]
    async fn inline_rules_support_domain_and_ip_rules() {
        let domain_rules = RouteRuleConfig {
            direct: vec!["*.qq.com".to_owned()],
            proxy: Vec::new(),
            block: vec!["*.xxx.com".to_owned()],
        };
        let ip_rules = RouteRuleConfig {
            direct: vec!["128.33.*".to_owned()],
            proxy: Vec::new(),
            block: vec!["12.9.*.0".to_owned()],
        };
        let table = RuleTable::load(None, None, &domain_rules, &ip_rules).unwrap();

        assert_eq!(
            table
                .decide(&TargetAddr::Domain("qq.com".to_owned(), 80))
                .await
                .expect("apex wildcard decision"),
            RouteDecision::Direct
        );
        assert_eq!(
            table
                .decide(&TargetAddr::Domain("img.qq.com".to_owned(), 80))
                .await
                .expect("subdomain wildcard decision"),
            RouteDecision::Direct
        );
        assert_eq!(
            table
                .decide(&TargetAddr::Domain("ads.xxx.com".to_owned(), 80))
                .await
                .expect("block decision"),
            RouteDecision::Block
        );
        assert_eq!(
            table
                .decide(&TargetAddr::Ip(Ipv4Addr::new(128, 33, 42, 7).into(), 443))
                .await
                .expect("wildcard IP decision"),
            RouteDecision::Direct
        );
        assert_eq!(
            table
                .decide(&TargetAddr::Ip(Ipv4Addr::new(12, 9, 42, 0).into(), 443))
                .await
                .expect("block IP decision"),
            RouteDecision::Block
        );
    }

    #[tokio::test]
    async fn proxy_filter_still_honors_block_rules() {
        let table = RuleTable::load(
            None,
            None,
            &RouteRuleConfig {
                direct: vec!["*.qq.com".to_owned()],
                proxy: Vec::new(),
                block: vec!["*.xxx.com".to_owned()],
            },
            &RouteRuleConfig::default(),
        )
        .unwrap();
        let router = Router {
            mode: FilterMode::Proxy,
            table,
            adblock: None,
            cache: Mutex::new(HashMap::new()),
        };

        assert_eq!(
            router
                .decide(&TargetAddr::Domain("img.qq.com".to_owned(), 80))
                .await
                .expect("direct rule is ignored in proxy mode"),
            RouteDecision::Remote
        );
        assert_eq!(
            router
                .decide(&TargetAddr::Domain("ads.xxx.com".to_owned(), 80))
                .await
                .expect("block rule is honored in proxy mode"),
            RouteDecision::Block
        );
    }

    #[tokio::test]
    async fn user_block_rules_beat_direct_rules() {
        let table = RuleTable::load(
            None,
            None,
            &RouteRuleConfig {
                direct: vec!["*.example".to_owned()],
                proxy: Vec::new(),
                block: vec!["ads.example".to_owned()],
            },
            &RouteRuleConfig::default(),
        )
        .unwrap();

        assert_eq!(
            table
                .decide(&TargetAddr::Domain("ads.example".to_owned(), 443))
                .await
                .expect("block wins over direct"),
            RouteDecision::Block
        );
    }

    #[tokio::test]
    async fn adblock_rules_beat_user_direct_rules() {
        let table = RuleTable::load(
            None,
            None,
            &RouteRuleConfig {
                direct: vec!["*.qq.com".to_owned()],
                proxy: Vec::new(),
                block: Vec::new(),
            },
            &RouteRuleConfig::default(),
        )
        .unwrap();
        let router = Router {
            mode: FilterMode::Rule,
            table,
            adblock: Some(Adblocker::from_rules_for_test(&["||ads.qq.com^"])),
            cache: Mutex::new(HashMap::new()),
        };

        assert_eq!(
            router
                .decide(&TargetAddr::Domain("ads.qq.com".to_owned(), 443))
                .await
                .expect("adblock wins over direct"),
            RouteDecision::Block
        );
        assert_eq!(
            router
                .decide(&TargetAddr::Domain("img.qq.com".to_owned(), 443))
                .await
                .expect("direct still applies after adblock miss"),
            RouteDecision::Direct
        );
    }

    #[test]
    fn ip_rule_wildcard_expands_to_cidr() {
        assert_eq!(
            parse_ip_rule_entry("128.33.*").unwrap(),
            vec!["128.33.0.0/16".parse::<ipnet::IpNet>().unwrap()]
        );
        assert_eq!(
            parse_ip_rule_entry("128.33.2.*").unwrap(),
            vec!["128.33.2.0/24".parse::<ipnet::IpNet>().unwrap()]
        );
        let expanded = parse_ip_rule_entry("12.9.*.0").unwrap();
        assert_eq!(expanded.len(), 256);
        assert_eq!(
            expanded.first(),
            Some(&"12.9.0.0/32".parse::<ipnet::IpNet>().unwrap())
        );
        assert_eq!(
            expanded.last(),
            Some(&"12.9.255.0/32".parse::<ipnet::IpNet>().unwrap())
        );
        assert_eq!(
            parse_ip_rule_entry("0.3.0.2/16").unwrap(),
            vec!["0.3.0.0/16".parse::<ipnet::IpNet>().unwrap()]
        );
    }

    #[test]
    fn ip_rule_wildcard_rejects_invalid_octet() {
        let err = parse_ip_rule_entry("128.332.*").unwrap_err().to_string();
        assert!(err.contains("0..=255"), "{err}");
    }

    #[test]
    fn reserved_nets_contains_loopback() {
        let nets = reserved_ip_nets();
        assert!(contains_any(&nets, &[IpAddr::V4(Ipv4Addr::LOCALHOST)]));
        assert!(contains_any(&nets, &[IpAddr::V6(Ipv6Addr::LOCALHOST)]));
    }
}
