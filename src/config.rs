use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{ArgMatches, parser::ValueSource};
use serde::Deserialize;

use crate::{
    cert::CertArgs, client::ClientArgs, mode::ProxyMode, route::FilterMode, server::ServerArgs,
    tun::TunArgs,
};

#[derive(Debug, Default, Deserialize)]
pub struct FileConfig {
    pub log: Option<String>,
    pub log_file: Option<PathBuf>,
    pub telemetry_sock: Option<PathBuf>,
    pub pid_file: Option<PathBuf>,
    pub tui: Option<bool>,
    pub daemon: Option<bool>,
    pub client: Option<ClientConfig>,
    pub server: Option<ServerConfig>,
    pub tun: Option<TunConfig>,
    pub cert: Option<CertConfig>,
}

#[derive(Debug, Default, Deserialize)]
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
    pub user_agent: Option<String>,
    pub handshake_timeout_secs: Option<u64>,
    pub connect_timeout_secs: Option<u64>,
    pub max_header_size: Option<usize>,
    pub system_proxy: Option<bool>,
    pub system_proxy_services: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
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
}

#[derive(Debug, Default, Deserialize)]
pub struct CertConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    pub names: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
pub struct TunConfig {
    pub device: Option<String>,
    pub shell: Option<String>,
    pub helper_cmd: Option<String>,
    pub helper_ready_delay_ms: Option<u64>,
    pub up: Option<Vec<String>>,
    pub down: Option<Vec<String>>,
    pub print_hooks: Option<bool>,
    pub dry_run: Option<bool>,
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
    let config: FileConfig = serde_yaml::from_str(&contents)
        .with_context(|| format!("failed to parse {}", absolute.display()))?;
    let base_dir = absolute
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((config, base_dir))
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
) {
    let Some(client) = &config.client else {
        return;
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
}

pub fn apply_server(
    args: &mut ServerArgs,
    config: &FileConfig,
    matches: &ArgMatches,
    base_dir: &Path,
) {
    let Some(server) = &config.server else {
        return;
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
}

pub fn apply_tun(args: &mut TunArgs, config: &FileConfig, matches: &ArgMatches, base_dir: &Path) {
    apply_client(&mut args.client, config, matches, base_dir);

    let Some(tun) = &config.tun else {
        return;
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
    use super::{FileConfig, maybe_assign_optional, resolve_path};
    use std::path::{Path, PathBuf};

    #[test]
    fn yaml_parse_smoke() {
        let raw = r#"
log: debug
telemetry_sock: run/pipit.sock
pid_file: run/pipit.pid
tui: true
daemon: true
client:
  server: 127.0.0.1:1443
  mode: native-mux
  rule_file: rules/rule.ls
  system_proxy: true
  system_proxy_services:
    - Wi-Fi
tun:
  device: auto
  helper_cmd: tun2socks --device {device} --proxy socks5://{socks}
  print_hooks: true
  dry_run: true
server:
  listen: 0.0.0.0:1443
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
        assert_eq!(parsed.tun.as_ref().and_then(|cfg| cfg.dry_run), Some(true));
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
}
