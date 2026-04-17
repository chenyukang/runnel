use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{ArgMatches, parser::ValueSource};
use serde::Deserialize;
use serde_yaml::Value;
use tracing::warn;

use crate::{
    cert::CertArgs,
    client::ClientArgs,
    mode::ProxyMode,
    proxy::route::{self, FilterMode, RouteRuleConfig},
    server::ServerArgs,
    tun::TunArgs,
    wg::{client::WgClientArgs, keys::public_key_from_private_key, server::WgServerArgs},
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub log: Option<String>,
    pub log_file: Option<PathBuf>,
    pub telemetry_sock: Option<PathBuf>,
    pub pid_file: Option<PathBuf>,
    pub tui: Option<bool>,
    pub daemon: Option<bool>,
    pub domain_rules: Option<RouteRuleConfig>,
    pub ip_rules: Option<RouteRuleConfig>,
    pub client: Option<ClientConfig>,
    pub server: Option<ServerConfig>,
    pub tun: Option<TunConfig>,
    pub cert: Option<CertConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub listen: Option<String>,
    pub server: Option<String>,
    pub server_name: Option<String>,
    pub ca_cert: Option<PathBuf>,
    pub mode: Option<ProxyMode>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub mux_path: Option<String>,
    pub mux: Option<bool>,
    pub filter: Option<FilterMode>,
    pub rule_file: Option<PathBuf>,
    pub cidr_file: Option<PathBuf>,
    pub domain_rules: Option<RouteRuleConfig>,
    pub ip_rules: Option<RouteRuleConfig>,
    pub user_agent: Option<String>,
    pub handshake_timeout_secs: Option<u64>,
    pub connect_timeout_secs: Option<u64>,
    pub max_header_size: Option<usize>,
    pub system_proxy: Option<bool>,
    pub system_proxy_services: Option<Vec<String>>,
    pub wg: Option<WgClientConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub listen: Option<String>,
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub mode: Option<ProxyMode>,
    pub password: Option<String>,
    pub path: Option<String>,
    pub mux_path: Option<String>,
    pub auth_window_secs: Option<u64>,
    pub handshake_timeout_secs: Option<u64>,
    pub connect_timeout_secs: Option<u64>,
    pub max_header_size: Option<usize>,
    pub max_tunnel_body_size: Option<usize>,
    pub allow_private_targets: Option<bool>,
    pub fallback_url: Option<String>,
    pub fallback_timeout_secs: Option<u64>,
    pub max_fallback_body_size: Option<usize>,
    pub wg: Option<WgServerConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    pub device: Option<String>,
    pub shell: Option<String>,
    pub helper_cmd: Option<String>,
    pub dns_upstream: Option<String>,
    pub helper_ready_delay_ms: Option<u64>,
    pub up: Option<Vec<String>>,
    pub down: Option<Vec<String>>,
    pub print_hooks: Option<bool>,
    pub dry_run: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgClientConfig {
    pub bind: Option<String>,
    pub endpoint: Option<String>,
    pub private_key: Option<String>,
    pub peer_public_key: Option<String>,
    pub device: Option<String>,
    pub tunnel_ip: Option<std::net::IpAddr>,
    pub peer_tunnel_ip: Option<std::net::IpAddr>,
    pub mtu: Option<u16>,
    pub persistent_keepalive_secs: Option<u16>,
    pub dns: Option<std::net::IpAddr>,
    pub dns_capture: Option<bool>,
    pub up: Option<Vec<String>>,
    pub down: Option<Vec<String>>,
    pub print_hooks: Option<bool>,
    pub dry_run: Option<bool>,
    pub skip_handshake_probe: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgServerConfig {
    pub listen: Option<String>,
    pub private_key: Option<String>,
    pub peer_public_key: Option<String>,
    pub device: Option<String>,
    pub tunnel_ip: Option<std::net::IpAddr>,
    pub peer_tunnel_ip: Option<std::net::IpAddr>,
    pub peer_allowed_ips: Option<Vec<String>>,
    pub nat_out_interface: Option<String>,
    pub mtu: Option<u16>,
    pub up: Option<Vec<String>>,
    pub down: Option<Vec<String>>,
    pub print_hooks: Option<bool>,
    pub dry_run: Option<bool>,
    pub handshake_watchdog_secs: Option<u64>,
}

pub fn load(path: &Path) -> Result<(FileConfig, PathBuf)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed to read current directory")?
            .join(path)
    };
    let contents = std::fs::read_to_string(&absolute)
        .with_context(|| format!("failed to read {}", absolute.display()))?;
    let raw_config: Value = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse {}", absolute.display()))?;
    reject_deprecated_wg_sections(&raw_config, &absolute)?;
    let config: FileConfig = serde_yaml::from_value(raw_config)
        .with_context(|| format!("failed to parse {}", absolute.display()))?;
    let base_dir = absolute
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((config, base_dir))
}

fn reject_deprecated_wg_sections(config: &Value, path: &Path) -> Result<()> {
    let Value::Mapping(mapping) = config else {
        return Ok(());
    };

    for (key, target) in [
        ("wg_client", "client.wg with client.mode: wg"),
        ("wg_server", "server.wg with server.mode: wg"),
    ] {
        if mapping.contains_key(&Value::String(key.to_owned())) {
            bail!(
                "{} uses deprecated top-level `{}`; move it under `{}`",
                path.display(),
                key,
                target
            );
        }
    }

    Ok(())
}

pub fn apply_globals(
    log: &mut String,
    log_file: &mut PathBuf,
    telemetry_sock: &mut Option<PathBuf>,
    pid_file: &mut Option<PathBuf>,
    tui: &mut bool,
    daemon: &mut bool,
    config: &FileConfig,
    matches: &ArgMatches,
    base_dir: &Path,
) {
    maybe_assign(log, &config.log, should_override(matches, "log"));
    if should_override(matches, "log_file") {
        if let Some(path) = &config.log_file {
            *log_file = resolve_path(base_dir, path);
        }
    }
    if should_override(matches, "telemetry_sock") {
        if let Some(path) = &config.telemetry_sock {
            *telemetry_sock = Some(resolve_path(base_dir, path));
        }
    }
    if should_override(matches, "pid_file") {
        if let Some(path) = &config.pid_file {
            *pid_file = Some(resolve_path(base_dir, path));
        }
    }
    maybe_assign(tui, &config.tui, should_override(matches, "tui"));
    maybe_assign(daemon, &config.daemon, should_override(matches, "daemon"));
}

pub fn apply_client(
    args: &mut ClientArgs,
    config: &FileConfig,
    matches: &ArgMatches,
    base_dir: &Path,
) -> Result<()> {
    let Some(client) = &config.client else {
        return Ok(());
    };

    maybe_assign(
        &mut args.listen,
        &client.listen,
        should_override(matches, "listen"),
    );
    maybe_assign(
        &mut args.server,
        &client.server,
        should_override(matches, "server"),
    );
    maybe_assign_optional(
        &mut args.server_name,
        &client.server_name,
        should_override(matches, "server_name"),
    );
    maybe_assign_path(
        &mut args.ca_cert,
        &client.ca_cert,
        should_override(matches, "ca_cert"),
        base_dir,
    );
    maybe_assign(
        &mut args.mode,
        &client.mode,
        should_override(matches, "mode"),
    );
    maybe_assign(
        &mut args.password,
        &client.password,
        should_override(matches, "password"),
    );
    maybe_assign(
        &mut args.path,
        &client.path,
        should_override(matches, "path"),
    );
    maybe_assign(
        &mut args.mux_path,
        &client.mux_path,
        should_override(matches, "mux_path"),
    );
    maybe_assign(&mut args.mux, &client.mux, should_override(matches, "mux"));
    maybe_assign(
        &mut args.filter,
        &client.filter,
        should_override(matches, "filter"),
    );
    maybe_assign_path(
        &mut args.rule_file,
        &client.rule_file,
        should_override(matches, "rule_file"),
        base_dir,
    );
    maybe_assign_path(
        &mut args.cidr_file,
        &client.cidr_file,
        should_override(matches, "cidr_file"),
        base_dir,
    );
    let domain_rules = merged_route_rules(&config.domain_rules, &client.domain_rules);
    let ip_rules = merged_route_rules(&config.ip_rules, &client.ip_rules);
    args.domain_rules = domain_rules.clone();
    args.ip_rules = ip_rules.clone();
    if should_enable_rule_mode_for_inline_rules(args, client, matches, &domain_rules, &ip_rules) {
        args.filter = FilterMode::Rule;
    }
    maybe_assign(
        &mut args.user_agent,
        &client.user_agent,
        should_override(matches, "user_agent"),
    );
    maybe_assign(
        &mut args.handshake_timeout_secs,
        &client.handshake_timeout_secs,
        should_override(matches, "handshake_timeout_secs"),
    );
    maybe_assign(
        &mut args.connect_timeout_secs,
        &client.connect_timeout_secs,
        should_override(matches, "connect_timeout_secs"),
    );
    maybe_assign(
        &mut args.max_header_size,
        &client.max_header_size,
        should_override(matches, "max_header_size"),
    );
    maybe_assign(
        &mut args.system_proxy,
        &client.system_proxy,
        should_override(matches, "system_proxy"),
    );
    maybe_assign(
        &mut args.system_proxy_services,
        &client.system_proxy_services,
        should_override(matches, "system_proxy_services"),
    );
    if let Some(wg) = &client.wg {
        apply_wg_client_config(&mut args.wg, wg, |_| true);
    }
    if matches!(args.effective_mode()?, ProxyMode::Wg) {
        apply_common_route_rules_to_wg(&mut args.wg, &domain_rules, &ip_rules)?;
    }
    validate_active_client_credentials(args, config)
}

pub fn apply_server(
    args: &mut ServerArgs,
    config: &FileConfig,
    matches: &ArgMatches,
    base_dir: &Path,
) -> Result<()> {
    let Some(server) = &config.server else {
        return Ok(());
    };

    maybe_assign(
        &mut args.listen,
        &server.listen,
        should_override(matches, "listen"),
    );
    maybe_assign_path(
        &mut args.cert,
        &server.cert,
        should_override(matches, "cert"),
        base_dir,
    );
    maybe_assign_path(
        &mut args.key,
        &server.key,
        should_override(matches, "key"),
        base_dir,
    );
    maybe_assign(
        &mut args.mode,
        &server.mode,
        should_override(matches, "mode"),
    );
    maybe_assign(
        &mut args.password,
        &server.password,
        should_override(matches, "password"),
    );
    maybe_assign(
        &mut args.path,
        &server.path,
        should_override(matches, "path"),
    );
    maybe_assign(
        &mut args.mux_path,
        &server.mux_path,
        should_override(matches, "mux_path"),
    );
    maybe_assign(
        &mut args.auth_window_secs,
        &server.auth_window_secs,
        should_override(matches, "auth_window_secs"),
    );
    maybe_assign(
        &mut args.handshake_timeout_secs,
        &server.handshake_timeout_secs,
        should_override(matches, "handshake_timeout_secs"),
    );
    maybe_assign(
        &mut args.connect_timeout_secs,
        &server.connect_timeout_secs,
        should_override(matches, "connect_timeout_secs"),
    );
    maybe_assign(
        &mut args.max_header_size,
        &server.max_header_size,
        should_override(matches, "max_header_size"),
    );
    maybe_assign(
        &mut args.max_tunnel_body_size,
        &server.max_tunnel_body_size,
        should_override(matches, "max_tunnel_body_size"),
    );
    maybe_assign(
        &mut args.allow_private_targets,
        &server.allow_private_targets,
        should_override(matches, "allow_private_targets"),
    );
    maybe_assign(
        &mut args.fallback_url,
        &server.fallback_url,
        should_override(matches, "fallback_url"),
    );
    maybe_assign(
        &mut args.fallback_timeout_secs,
        &server.fallback_timeout_secs,
        should_override(matches, "fallback_timeout_secs"),
    );
    maybe_assign(
        &mut args.max_fallback_body_size,
        &server.max_fallback_body_size,
        should_override(matches, "max_fallback_body_size"),
    );
    if let Some(wg) = &server.wg {
        apply_wg_server_config(&mut args.wg, wg, |_| true);
    }
    validate_active_server_credentials(args, config)
}

pub fn apply_tun(
    args: &mut TunArgs,
    config: &FileConfig,
    matches: &ArgMatches,
    base_dir: &Path,
) -> Result<()> {
    apply_client(&mut args.client, config, matches, base_dir)?;

    let Some(tun) = &config.tun else {
        return Ok(());
    };

    maybe_assign(
        &mut args.device,
        &tun.device,
        should_override(matches, "device"),
    );
    maybe_assign(
        &mut args.shell,
        &tun.shell,
        should_override(matches, "shell"),
    );
    maybe_assign(
        &mut args.helper_cmd,
        &tun.helper_cmd,
        should_override(matches, "helper_cmd"),
    );
    maybe_assign_optional(
        &mut args.dns_upstream,
        &tun.dns_upstream,
        should_override(matches, "dns_upstream"),
    );
    maybe_assign(
        &mut args.helper_ready_delay_ms,
        &tun.helper_ready_delay_ms,
        should_override(matches, "helper_ready_delay_ms"),
    );
    maybe_assign(&mut args.up, &tun.up, should_override(matches, "up"));
    maybe_assign(&mut args.down, &tun.down, should_override(matches, "down"));
    maybe_assign(
        &mut args.print_hooks,
        &tun.print_hooks,
        should_override(matches, "print_hooks"),
    );
    maybe_assign(
        &mut args.dry_run,
        &tun.dry_run,
        should_override(matches, "dry_run"),
    );
    Ok(())
}

pub fn apply_wg_client(
    args: &mut WgClientArgs,
    config: &FileConfig,
    _matches: &ArgMatches,
    _base_dir: &Path,
) -> Result<()> {
    let Some(client) = &config.client else {
        return Ok(());
    };
    let Some(wg_client) = &client.wg else {
        return Ok(());
    };

    apply_wg_client_config(args, wg_client, |id| should_override(_matches, id));
    let domain_rules = merged_route_rules(&config.domain_rules, &client.domain_rules);
    let ip_rules = merged_route_rules(&config.ip_rules, &client.ip_rules);
    apply_common_route_rules_to_wg(args, &domain_rules, &ip_rules)?;
    validate_wg_client_pair(args, config.server.as_ref())
}

pub fn apply_wg_server(
    args: &mut WgServerArgs,
    config: &FileConfig,
    _matches: &ArgMatches,
    _base_dir: &Path,
) -> Result<()> {
    let Some(server) = &config.server else {
        return Ok(());
    };
    let Some(wg_server) = &server.wg else {
        return Ok(());
    };

    apply_wg_server_config(args, wg_server, |id| should_override(_matches, id));
    validate_wg_server_pair(args, config.client.as_ref())
}

fn apply_wg_client_config(
    args: &mut WgClientArgs,
    wg_client: &WgClientConfig,
    should_apply: impl Fn(&str) -> bool,
) {
    maybe_assign(&mut args.bind, &wg_client.bind, should_apply("bind"));
    maybe_assign(
        &mut args.endpoint,
        &wg_client.endpoint,
        should_apply("endpoint"),
    );
    maybe_assign(
        &mut args.private_key,
        &wg_client.private_key,
        should_apply("private_key"),
    );
    maybe_assign(
        &mut args.peer_public_key,
        &wg_client.peer_public_key,
        should_apply("peer_public_key"),
    );
    maybe_assign(&mut args.device, &wg_client.device, should_apply("device"));
    if should_apply("tunnel_ip")
        && let Some(tunnel_ip) = wg_client.tunnel_ip
    {
        args.tunnel_ip = tunnel_ip;
    }
    if should_apply("peer_tunnel_ip")
        && let Some(peer_tunnel_ip) = wg_client.peer_tunnel_ip
    {
        args.peer_tunnel_ip = peer_tunnel_ip;
    }
    maybe_assign(&mut args.mtu, &wg_client.mtu, should_apply("mtu"));
    maybe_assign_optional(
        &mut args.persistent_keepalive_secs,
        &wg_client.persistent_keepalive_secs,
        should_apply("persistent_keepalive_secs"),
    );
    if should_apply("dns")
        && let Some(dns) = wg_client.dns
    {
        args.dns = Some(dns);
    }
    maybe_assign(
        &mut args.dns_capture,
        &wg_client.dns_capture,
        should_apply("dns_capture"),
    );
    maybe_assign(&mut args.up, &wg_client.up, should_apply("up"));
    maybe_assign(&mut args.down, &wg_client.down, should_apply("down"));
    maybe_assign(
        &mut args.print_hooks,
        &wg_client.print_hooks,
        should_apply("print_hooks"),
    );
    maybe_assign(
        &mut args.dry_run,
        &wg_client.dry_run,
        should_apply("dry_run"),
    );
    maybe_assign(
        &mut args.skip_handshake_probe,
        &wg_client.skip_handshake_probe,
        should_apply("skip_handshake_probe"),
    );
}

fn apply_wg_server_config(
    args: &mut WgServerArgs,
    wg_server: &WgServerConfig,
    should_apply: impl Fn(&str) -> bool,
) {
    maybe_assign(&mut args.listen, &wg_server.listen, should_apply("listen"));
    maybe_assign(
        &mut args.private_key,
        &wg_server.private_key,
        should_apply("private_key"),
    );
    maybe_assign(
        &mut args.peer_public_key,
        &wg_server.peer_public_key,
        should_apply("peer_public_key"),
    );
    maybe_assign(&mut args.device, &wg_server.device, should_apply("device"));
    if should_apply("tunnel_ip")
        && let Some(tunnel_ip) = wg_server.tunnel_ip
    {
        args.tunnel_ip = tunnel_ip;
    }
    if should_apply("peer_tunnel_ip")
        && let Some(peer_tunnel_ip) = wg_server.peer_tunnel_ip
    {
        args.peer_tunnel_ip = peer_tunnel_ip;
    }
    maybe_assign(
        &mut args.peer_allowed_ips,
        &wg_server.peer_allowed_ips,
        should_apply("peer_allowed_ips"),
    );
    maybe_assign(&mut args.mtu, &wg_server.mtu, should_apply("mtu"));
    maybe_assign_optional(
        &mut args.nat_out_interface,
        &wg_server.nat_out_interface,
        should_apply("nat_out_interface"),
    );
    maybe_assign(&mut args.up, &wg_server.up, should_apply("up"));
    maybe_assign(&mut args.down, &wg_server.down, should_apply("down"));
    maybe_assign(
        &mut args.print_hooks,
        &wg_server.print_hooks,
        should_apply("print_hooks"),
    );
    maybe_assign(
        &mut args.dry_run,
        &wg_server.dry_run,
        should_apply("dry_run"),
    );
    maybe_assign(
        &mut args.handshake_watchdog_secs,
        &wg_server.handshake_watchdog_secs,
        should_apply("handshake_watchdog_secs"),
    );
}

fn should_enable_rule_mode_for_inline_rules(
    args: &ClientArgs,
    client: &ClientConfig,
    matches: &ArgMatches,
    domain_rules: &RouteRuleConfig,
    ip_rules: &RouteRuleConfig,
) -> bool {
    if !matches!(args.filter, FilterMode::Proxy) || client.filter.is_some() {
        return false;
    }
    if !should_override(matches, "filter") {
        return false;
    }
    !domain_rules.is_empty() || !ip_rules.is_empty()
}

fn apply_common_route_rules_to_wg(
    args: &mut WgClientArgs,
    domain_rules: &RouteRuleConfig,
    ip_rules: &RouteRuleConfig,
) -> Result<()> {
    if !ip_rules.is_empty() {
        let direct = route::parse_ip_rule_entries("client.ip_rules.direct", &ip_rules.direct)?;
        append_unique(
            &mut args.direct_ips,
            direct.into_iter().map(|rule| rule.to_string()),
        );

        let proxy = route::parse_ip_rule_entries("client.ip_rules.proxy", &ip_rules.proxy)?;
        append_unique(
            &mut args.proxy_ips,
            proxy.into_iter().map(|rule| rule.to_string()),
        );

        if !ip_rules.block.is_empty() {
            warn!(
                "client.ip_rules.block is not enforced by wg mode yet; use SOCKS modes for rule-level blocking"
            );
        }
    }

    if !domain_rules.is_empty() {
        route::validate_domain_rule_entries("client.domain_rules.direct", &domain_rules.direct)?;
        route::validate_domain_rule_entries("client.domain_rules.proxy", &domain_rules.proxy)?;
        route::validate_domain_rule_entries("client.domain_rules.block", &domain_rules.block)?;
        args.domain_rules
            .direct
            .extend(domain_rules.direct.iter().cloned());
        args.domain_rules
            .proxy
            .extend(domain_rules.proxy.iter().cloned());
        args.domain_rules
            .block
            .extend(domain_rules.block.iter().cloned());

        if wg_domain_rules_need_dns_capture(domain_rules) && args.dns.is_none() {
            bail!(
                "client.domain_rules require client.wg.dns in wg mode because domain routing is driven by DNS capture"
            );
        }
        if wg_domain_rules_need_dns_capture(domain_rules) && !args.dns_capture {
            warn!(
                "enabling client.wg.dns_capture because client.domain_rules are configured for wg mode"
            );
            args.dns_capture = true;
        }
    }

    Ok(())
}

fn wg_domain_rules_need_dns_capture(domain_rules: &RouteRuleConfig) -> bool {
    !domain_rules.direct.is_empty() || !domain_rules.block.is_empty()
}

fn merged_route_rules(
    global: &Option<RouteRuleConfig>,
    local: &Option<RouteRuleConfig>,
) -> RouteRuleConfig {
    let mut merged = global.clone().unwrap_or_default();
    if let Some(local) = local {
        merged.direct.extend(local.direct.iter().cloned());
        merged.proxy.extend(local.proxy.iter().cloned());
        merged.block.extend(local.block.iter().cloned());
    }
    merged
}

fn append_unique(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn validate_active_client_credentials(args: &ClientArgs, config: &FileConfig) -> Result<()> {
    if matches!(args.effective_mode()?, ProxyMode::Wg) {
        return validate_wg_client_pair(&args.wg, config.server.as_ref());
    }

    let Some(server) = &config.server else {
        return Ok(());
    };
    if matches!(server.mode.unwrap_or(ProxyMode::NativeHttp), ProxyMode::Wg) {
        return Ok(());
    }
    validate_password_pair(
        "client password",
        &args.password,
        "server.password",
        server.password.as_deref(),
    )
}

fn validate_active_server_credentials(args: &ServerArgs, config: &FileConfig) -> Result<()> {
    if matches!(args.mode, ProxyMode::Wg) {
        return validate_wg_server_pair(&args.wg, config.client.as_ref());
    }

    let Some(client) = &config.client else {
        return Ok(());
    };
    if matches!(client.mode.unwrap_or(ProxyMode::NativeHttp), ProxyMode::Wg) {
        return Ok(());
    }
    validate_password_pair(
        "server password",
        &args.password,
        "client.password",
        client.password.as_deref(),
    )
}

fn validate_password_pair(
    active_label: &str,
    active_password: &str,
    peer_label: &str,
    peer_password: Option<&str>,
) -> Result<()> {
    let Some(peer_password) = peer_password else {
        return Ok(());
    };
    if active_password.trim().is_empty() || peer_password.trim().is_empty() {
        return Ok(());
    }
    if active_password != peer_password {
        bail!(
            "{active_label} does not match {peer_label} in the same config; use matching passwords or update one side"
        );
    }
    Ok(())
}

fn validate_wg_client_pair(args: &WgClientArgs, server: Option<&ServerConfig>) -> Result<()> {
    let Some(server_wg) = server.and_then(|server| server.wg.as_ref()) else {
        return Ok(());
    };

    validate_wg_peer_public_key(
        "client.wg.peer_public_key",
        Some(args.peer_public_key.as_str()),
        "server.wg.private_key",
        server_wg.private_key.as_deref(),
    )?;
    validate_wg_peer_public_key(
        "server.wg.peer_public_key",
        server_wg.peer_public_key.as_deref(),
        "client.wg.private_key",
        Some(&args.private_key),
    )
}

fn validate_wg_server_pair(args: &WgServerArgs, client: Option<&ClientConfig>) -> Result<()> {
    let Some(client_wg) = client.and_then(|client| client.wg.as_ref()) else {
        return Ok(());
    };

    validate_wg_peer_public_key(
        "server.wg.peer_public_key",
        Some(args.peer_public_key.as_str()),
        "client.wg.private_key",
        client_wg.private_key.as_deref(),
    )?;
    validate_wg_peer_public_key(
        "client.wg.peer_public_key",
        client_wg.peer_public_key.as_deref(),
        "server.wg.private_key",
        Some(&args.private_key),
    )
}

fn validate_wg_peer_public_key(
    peer_public_label: &str,
    peer_public_key: Option<&str>,
    private_label: &str,
    private_key: Option<&str>,
) -> Result<()> {
    let Some(peer_public_key) = peer_public_key.map(str::trim).filter(|key| !key.is_empty()) else {
        return Ok(());
    };
    let Some(private_key) = private_key.map(str::trim).filter(|key| !key.is_empty()) else {
        return Ok(());
    };
    let expected = public_key_from_private_key(private_key)
        .with_context(|| format!("failed to verify {peer_public_label} against {private_label}"))?;
    if peer_public_key != expected {
        bail!(
            "{peer_public_label} does not match {private_label} in the same config; regenerate the WG config or set matching keys"
        );
    }
    Ok(())
}

pub fn apply_cert(args: &mut CertArgs, config: &FileConfig, matches: &ArgMatches, base_dir: &Path) {
    let Some(cert) = &config.cert else {
        return;
    };

    if should_override(matches, "cert") {
        if let Some(path) = &cert.cert {
            args.cert = resolve_path(base_dir, path);
        }
    }
    if should_override(matches, "key") {
        if let Some(path) = &cert.key {
            args.key = resolve_path(base_dir, path);
        }
    }
    maybe_assign(
        &mut args.names,
        &cert.names,
        should_override(matches, "names"),
    );
}

fn should_override(matches: &ArgMatches, id: &str) -> bool {
    !matches
        .value_source(id)
        .is_some_and(|source| matches!(source, ValueSource::CommandLine | ValueSource::EnvVariable))
}

fn maybe_assign<T: Clone>(slot: &mut T, config: &Option<T>, allowed: bool) {
    if allowed {
        if let Some(value) = config {
            *slot = value.clone();
        }
    }
}

fn maybe_assign_optional<T: Clone>(slot: &mut Option<T>, config: &Option<T>, allowed: bool) {
    if allowed {
        if let Some(value) = config {
            *slot = Some(value.clone());
        }
    }
}

fn maybe_assign_path(
    slot: &mut Option<PathBuf>,
    config: &Option<PathBuf>,
    allowed: bool,
    base_dir: &Path,
) {
    if allowed {
        if let Some(path) = config {
            *slot = Some(resolve_path(base_dir, path));
        }
    }
}

fn resolve_path(base_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientConfig, FileConfig, ServerConfig, WgServerConfig, apply_common_route_rules_to_wg,
        load, maybe_assign_optional, resolve_path, validate_active_client_credentials,
        validate_active_server_credentials, validate_wg_client_pair,
    };
    use crate::{
        client::ClientArgs,
        mode::ProxyMode,
        proxy::route::{FilterMode, RouteRuleConfig},
        server::ServerArgs,
        wg::{client::WgClientArgs, keys::public_key_from_private_key, server::WgServerArgs},
    };
    use std::fs;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn yaml_parse_smoke() {
        let raw = r#"
log: debug
telemetry_sock: run/pipit.sock
pid_file: run/pipit.pid
tui: true
daemon: true
domain_rules:
  block:
    - "*.global.test"
ip_rules:
  direct:
    - "10.*"
client:
  server: 127.0.0.1:1443
  mode: native-mux
  rule_file: rules/rule.ls
  domain_rules:
    direct:
      - "*.qq.com"
      - "*.cn"
    block:
      - "*.xxx.com"
  ip_rules:
    direct:
      - "128.33.*"
      - "0.3.0.2/16"
    block:
      - "12.9.*.0"
  system_proxy: true
  system_proxy_services:
    - Wi-Fi
  wg:
    endpoint: 198.51.100.10:51820
    tunnel_ip: 10.8.0.2
    peer_tunnel_ip: 10.8.0.1
    dns: 1.1.1.1
    dns_capture: true
    up:
      - ip route replace 203.0.113.0/24 dev pipitwg0
    print_hooks: true
    dry_run: true
    skip_handshake_probe: true
tun:
  device: auto
  helper_cmd: tun2proxy-bin --tun {device} --proxy socks5://{socks}
  dns_upstream: 1.1.1.1:53
  print_hooks: true
  dry_run: true
server:
  listen: 0.0.0.0:1443
  wg:
    listen: 0.0.0.0:51820
    tunnel_ip: 10.8.0.1
    peer_tunnel_ip: 10.8.0.2
    nat_out_interface: en0
    down:
      - ip link set dev pipitwg0 down || true
    dry_run: true
    handshake_watchdog_secs: 0
"#;
        let parsed: FileConfig = serde_yaml::from_str(raw).unwrap();
        assert_eq!(parsed.log.as_deref(), Some("debug"));
        assert_eq!(
            parsed.telemetry_sock.as_deref(),
            Some(Path::new("run/pipit.sock"))
        );
        assert_eq!(parsed.pid_file.as_deref(), Some(Path::new("run/pipit.pid")));
        assert_eq!(parsed.tui, Some(true));
        assert_eq!(parsed.daemon, Some(true));
        assert_eq!(
            parsed
                .domain_rules
                .as_ref()
                .map(|rules| rules.block.clone()),
            Some(vec!["*.global.test".to_owned()])
        );
        assert_eq!(
            parsed.ip_rules.as_ref().map(|rules| rules.direct.clone()),
            Some(vec!["10.*".to_owned()])
        );
        assert_eq!(
            parsed.client.as_ref().and_then(|cfg| cfg.server.as_deref()),
            Some("127.0.0.1:1443")
        );
        assert_eq!(
            parsed.client.as_ref().and_then(|cfg| cfg.system_proxy),
            Some(true)
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.domain_rules.as_ref())
                .map(|rules| rules.direct.clone()),
            Some(vec!["*.qq.com".to_owned(), "*.cn".to_owned()])
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.ip_rules.as_ref())
                .map(|rules| rules.direct.clone()),
            Some(vec!["128.33.*".to_owned(), "0.3.0.2/16".to_owned()])
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.system_proxy_services.as_ref())
                .map(|items| items.len()),
            Some(1)
        );
        assert_eq!(
            parsed.server.as_ref().and_then(|cfg| cfg.listen.as_deref()),
            Some("0.0.0.0:1443")
        );
        assert_eq!(
            parsed.tun.as_ref().and_then(|cfg| cfg.device.as_deref()),
            Some("auto")
        );
        assert_eq!(
            parsed.tun.as_ref().and_then(|cfg| cfg.print_hooks),
            Some(true)
        );
        assert_eq!(
            parsed
                .tun
                .as_ref()
                .and_then(|cfg| cfg.dns_upstream.as_deref()),
            Some("1.1.1.1:53")
        );
        assert_eq!(parsed.tun.as_ref().and_then(|cfg| cfg.dry_run), Some(true));
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
                .client
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.dns),
            Some("1.1.1.1".parse().unwrap())
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.dns_capture),
            Some(true)
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.print_hooks),
            Some(true)
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.skip_handshake_probe),
            Some(true)
        );
        assert_eq!(
            parsed
                .client
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.up.as_ref())
                .map(|items| items.len()),
            Some(1)
        );
        assert_eq!(
            parsed
                .server
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.nat_out_interface.as_deref()),
            Some("en0")
        );
        assert_eq!(
            parsed
                .server
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.down.as_ref())
                .map(|items| items.len()),
            Some(1)
        );
        assert_eq!(
            parsed
                .server
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.dry_run),
            Some(true)
        );
        assert_eq!(
            parsed
                .server
                .as_ref()
                .and_then(|cfg| cfg.wg.as_ref())
                .and_then(|cfg| cfg.handshake_watchdog_secs),
            Some(0)
        );
    }

    #[test]
    fn yaml_parse_rejects_unknown_fields() {
        let nested_raw = r#"
client:
  mode: wg
  telemetry-sock: /tmp/pipit.sock
  wg:
    endpoint: 198.51.100.10:51820
"#;

        let err = serde_yaml::from_str::<FileConfig>(nested_raw)
            .expect_err("unknown client field should fail");
        let message = err.to_string();
        assert!(
            message.contains("unknown field `telemetry-sock`"),
            "{message}"
        );
        assert!(message.contains("client:"), "{message}");

        let top_level_raw = r#"
telemetry-sock: /tmp/pipit.sock
"#;

        let err = serde_yaml::from_str::<FileConfig>(top_level_raw)
            .expect_err("unknown top-level field should fail");
        let message = err.to_string();
        assert!(
            message.contains("unknown field `telemetry-sock`"),
            "{message}"
        );
        assert!(message.contains("telemetry_sock"), "{message}");
    }

    #[test]
    fn relative_path_uses_config_directory() {
        let base = Path::new("/tmp/pipit");
        let resolved = resolve_path(base, Path::new("rules/rule.ls"));
        assert_eq!(resolved, PathBuf::from("/tmp/pipit/rules/rule.ls"));
    }

    #[test]
    fn optional_values_fill_empty_slots() {
        let mut slot = None;
        let config = Some("example.com".to_owned());
        maybe_assign_optional(&mut slot, &config, true);
        assert_eq!(slot.as_deref(), Some("example.com"));
    }

    #[test]
    fn active_client_password_mismatch_reports_startup_error() {
        let args = client_args("client-secret", ProxyMode::NativeHttp);
        let config = FileConfig {
            server: Some(ServerConfig {
                password: Some("server-secret".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_active_client_credentials(&args, &config)
            .expect_err("password mismatch should fail before network startup")
            .to_string();
        assert!(err.contains("client password"), "{err}");
        assert!(err.contains("server.password"), "{err}");
        assert!(err.contains("same config"), "{err}");
    }

    #[test]
    fn active_server_password_mismatch_reports_startup_error() {
        let args = server_args("server-secret", ProxyMode::DazeBaboon);
        let config = FileConfig {
            client: Some(ClientConfig {
                mode: Some(ProxyMode::DazeBaboon),
                password: Some("client-secret".to_owned()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_active_server_credentials(&args, &config)
            .expect_err("password mismatch should fail before network startup")
            .to_string();
        assert!(err.contains("server password"), "{err}");
        assert!(err.contains("client.password"), "{err}");
        assert!(err.contains("same config"), "{err}");
    }

    #[test]
    fn common_ip_rules_map_to_wg_route_fields() {
        let mut args = WgClientArgs::default();
        let domain_rules = RouteRuleConfig::default();
        let ip_rules = RouteRuleConfig {
            direct: vec!["128.33.*".to_owned()],
            proxy: vec!["203.0.113.0/24".to_owned()],
            block: Vec::new(),
        };

        apply_common_route_rules_to_wg(&mut args, &domain_rules, &ip_rules).unwrap();

        assert_eq!(args.direct_ips, vec!["128.33.0.0/16"]);
        assert_eq!(args.proxy_ips, vec!["203.0.113.0/24"]);
    }

    #[test]
    fn common_domain_rules_enable_wg_dns_capture() {
        let mut args = WgClientArgs {
            dns: Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
            dns_capture: false,
            ..Default::default()
        };
        let domain_rules = RouteRuleConfig {
            direct: vec!["*.qq.com".to_owned()],
            proxy: Vec::new(),
            block: vec!["*.xxx.com".to_owned()],
        };
        let ip_rules = RouteRuleConfig::default();

        apply_common_route_rules_to_wg(&mut args, &domain_rules, &ip_rules).unwrap();

        assert!(args.dns_capture);
        assert_eq!(args.domain_rules.direct, vec!["*.qq.com"]);
        assert_eq!(args.domain_rules.block, vec!["*.xxx.com"]);
    }

    #[test]
    fn common_domain_rules_require_wg_dns_upstream() {
        let mut args = WgClientArgs::default();
        let domain_rules = RouteRuleConfig {
            direct: vec!["*.qq.com".to_owned()],
            proxy: Vec::new(),
            block: Vec::new(),
        };
        let ip_rules = RouteRuleConfig::default();

        let err = apply_common_route_rules_to_wg(&mut args, &domain_rules, &ip_rules)
            .unwrap_err()
            .to_string();
        assert!(err.contains("client.wg.dns"), "{err}");
    }

    #[test]
    fn common_proxy_only_domain_rules_do_not_require_wg_dns_capture() {
        let mut args = WgClientArgs::default();
        let domain_rules = RouteRuleConfig {
            direct: Vec::new(),
            proxy: vec!["*.example.com".to_owned()],
            block: Vec::new(),
        };
        let ip_rules = RouteRuleConfig::default();

        apply_common_route_rules_to_wg(&mut args, &domain_rules, &ip_rules).unwrap();

        assert!(!args.dns_capture);
        assert_eq!(args.domain_rules.proxy, vec!["*.example.com"]);
    }

    #[test]
    fn wg_peer_public_key_mismatch_reports_startup_error() {
        let client_private = key([0x11; 32]);
        let server_private = key([0x22; 32]);
        let client_public = public_key_from_private_key(&client_private).unwrap();
        let wrong_server_public = public_key_from_private_key(&key([0x33; 32])).unwrap();

        let args = WgClientArgs {
            private_key: client_private,
            peer_public_key: wrong_server_public,
            ..Default::default()
        };
        let config = FileConfig {
            server: Some(ServerConfig {
                mode: Some(ProxyMode::Wg),
                wg: Some(WgServerConfig {
                    private_key: Some(server_private),
                    peer_public_key: Some(client_public),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let err = validate_wg_client_pair(&args, config.server.as_ref())
            .expect_err("WG peer key mismatch should fail before network startup")
            .to_string();
        assert!(err.contains("client.wg.peer_public_key"), "{err}");
        assert!(err.contains("server.wg.private_key"), "{err}");
        assert!(err.contains("regenerate the WG config"), "{err}");
    }

    #[test]
    fn load_rejects_deprecated_top_level_wg_sections() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pipit-deprecated-wg-config-{}-{suffix}.yaml",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"
wg_client:
  endpoint: 198.51.100.10:51820
"#,
        )
        .unwrap();

        let err = load(&path).expect_err("deprecated top-level wg_client should fail");
        let _ = fs::remove_file(&path);

        let message = err.to_string();
        assert!(
            message.contains("deprecated top-level `wg_client`"),
            "{message}"
        );
        assert!(message.contains("client.wg"), "{message}");
    }

    fn client_args(password: &str, mode: ProxyMode) -> ClientArgs {
        ClientArgs {
            listen: "127.0.0.1:1080".to_owned(),
            server: "127.0.0.1:1443".to_owned(),
            server_name: None,
            ca_cert: None,
            mode,
            password: password.to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            mux: false,
            filter: FilterMode::Proxy,
            rule_file: None,
            cidr_file: None,
            domain_rules: Default::default(),
            ip_rules: Default::default(),
            user_agent: "Mozilla/5.0".to_owned(),
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 8 * 1024,
            system_proxy: false,
            system_proxy_services: Vec::new(),
            tun_dns_redirect_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            tun_dns_upstream: None,
            wg: WgClientArgs::default(),
        }
    }

    fn server_args(password: &str, mode: ProxyMode) -> ServerArgs {
        ServerArgs {
            listen: "0.0.0.0:1443".to_owned(),
            cert: None,
            key: None,
            mode,
            password: password.to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            auth_window_secs: 120,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 16 * 1024,
            max_tunnel_body_size: 8 * 1024,
            allow_private_targets: false,
            fallback_url: "https://www.qq.com".to_owned(),
            fallback_timeout_secs: 15,
            max_fallback_body_size: 1024 * 1024,
            wg: WgServerArgs::default(),
        }
    }

    fn key(bytes: [u8; 32]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }
}
