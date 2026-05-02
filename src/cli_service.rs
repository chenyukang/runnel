use anyhow::{Context, Result};
use runnel::{telemetry, tui};
use std::path::{Path, PathBuf};

use super::{Cli, Commands, DEFAULT_CURRENT_DIR, DEFAULT_LOG_DIR, DEFAULT_RUN_LOG_FILE};

pub(super) const SERVICE_ROLES: &[&str] = &["client", "server", "tun"];

#[derive(Clone, Debug)]
struct ServiceDescriptor {
    command_label: String,
    mode_label: String,
    listen: Option<String>,
    upstream: Option<String>,
    path: Option<String>,
}

fn service_descriptor(command: &Commands) -> Option<ServiceDescriptor> {
    match command {
        Commands::Client(args) => {
            let mode = args.effective_mode().ok();
            Some(ServiceDescriptor {
                command_label: "client".to_owned(),
                mode_label: mode
                    .map(|mode| mode.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                listen: Some(if matches!(mode, Some(runnel::mode::ProxyMode::Wg)) {
                    args.wg.bind.clone()
                } else {
                    args.listen.clone()
                }),
                upstream: Some(if matches!(mode, Some(runnel::mode::ProxyMode::Wg)) {
                    args.wg.endpoint.clone()
                } else {
                    args.server.clone()
                }),
                path: Some(match mode {
                    Some(runnel::mode::ProxyMode::NativeMux) => args.mux_path.clone(),
                    Some(runnel::mode::ProxyMode::Wg) => args.wg.device.clone(),
                    _ => args.path.clone(),
                }),
            })
        }
        Commands::Server(args) => Some(ServiceDescriptor {
            command_label: "server".to_owned(),
            mode_label: args.mode.to_string(),
            listen: Some(if matches!(args.mode, runnel::mode::ProxyMode::Wg) {
                args.wg.listen.clone()
            } else {
                args.listen.clone()
            }),
            upstream: Some(if matches!(args.mode, runnel::mode::ProxyMode::Wg) {
                args.wg.peer_tunnel_ip.to_string()
            } else {
                args.fallback_url.clone()
            }),
            path: Some(match args.mode {
                runnel::mode::ProxyMode::NativeMux => args.mux_path.clone(),
                runnel::mode::ProxyMode::Wg => args.wg.device.clone(),
                _ => args.path.clone(),
            }),
        }),
        Commands::Tun(args) => Some(ServiceDescriptor {
            command_label: "tun".to_owned(),
            mode_label: args
                .client
                .effective_mode()
                .ok()
                .map(|mode| mode.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            listen: Some(args.client.listen.clone()),
            upstream: Some(args.client.server.clone()),
            path: Some(args.device.clone()),
        }),
        Commands::WgClient(args) => Some(ServiceDescriptor {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: Some(args.bind.clone()),
            upstream: Some(args.endpoint.clone()),
            path: Some(args.device.clone()),
        }),
        Commands::WgServer(args) => Some(ServiceDescriptor {
            command_label: "wg-server".to_owned(),
            mode_label: "wg".to_owned(),
            listen: Some(args.listen.clone()),
            upstream: Some(args.peer_tunnel_ip.to_string()),
            path: Some(args.device.clone()),
        }),
        Commands::WgConfig(_)
        | Commands::WgKeygen(_)
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Reload(_)
        | Commands::Status(_) => None,
    }
}

pub(super) fn dashboard_context(
    cli: &Cli,
    log_file: PathBuf,
    log_timezone_offset_secs: i32,
) -> Option<tui::DashboardContext> {
    if !cli.tui {
        return None;
    }

    let descriptor = service_descriptor(&cli.command)?;
    Some(tui::DashboardContext {
        command_label: descriptor.command_label,
        mode_label: descriptor.mode_label,
        listen: descriptor.listen,
        upstream: descriptor.upstream,
        path: descriptor.path,
        log_file,
        log_filter: cli.log.clone(),
        log_timezone_offset_secs,
    })
}

pub(super) fn monitor_context(
    cli: &Cli,
    log_file: PathBuf,
    log_timezone_offset_secs: i32,
) -> Option<telemetry::MonitorContext> {
    let descriptor = service_descriptor(&cli.command)?;
    Some(telemetry::MonitorContext {
        command_label: descriptor.command_label,
        mode_label: descriptor.mode_label,
        listen: descriptor.listen,
        upstream: descriptor.upstream,
        path: descriptor.path,
        log_file,
        log_filter: cli.log.clone(),
        log_timezone_offset_secs,
        pid: std::process::id(),
    })
}

pub(super) fn resolve_socket_for_service(cli: &Cli, log_file: &Path) -> Result<PathBuf> {
    if let Some(path) = &cli.telemetry_sock {
        return absolute_path(path);
    }

    let role = command_role(&cli.command).context("telemetry socket is not supported")?;
    default_socket_path(log_file, role)
}

pub(super) fn resolve_attach_socket(
    log_file: &Path,
    global_socket: Option<PathBuf>,
    attach: Option<PathBuf>,
) -> Result<PathBuf> {
    if let Some(path) = attach.or(global_socket) {
        return absolute_path(&path);
    }

    let client = default_socket_path(log_file, "client")?;
    let server = default_socket_path(log_file, "server")?;
    let tun = default_socket_path(log_file, "tun")?;
    let wg_client = default_socket_path(log_file, "wg-client")?;
    let wg_server = default_socket_path(log_file, "wg-server")?;

    let mut found = Vec::new();
    if client.exists() {
        found.push(client);
    }
    if server.exists() {
        found.push(server);
    }
    if tun.exists() {
        found.push(tun);
    }
    if wg_client.exists() {
        found.push(wg_client);
    }
    if wg_server.exists() {
        found.push(wg_server);
    }

    match found.len() {
        0 => default_socket_path(log_file, "client"),
        1 => Ok(found.remove(0)),
        _ => anyhow::bail!("multiple telemetry sockets exist; pass --attach explicitly"),
    }
}

pub(super) fn default_socket_path(log_file: &Path, role: &str) -> Result<PathBuf> {
    default_sidecar_path(log_file, role, "sock")
}

pub(super) fn default_pid_path(log_file: &Path, role: &str) -> Result<PathBuf> {
    default_sidecar_path(log_file, role, "pid")
}

pub(super) fn default_sidecar_path(_log_file: &Path, role: &str, ext: &str) -> Result<PathBuf> {
    Ok(absolute_path(Path::new(DEFAULT_CURRENT_DIR))?.join(format!("{role}.{ext}")))
}

pub(super) fn default_log_file_for_command(command: &Commands) -> PathBuf {
    if let Some(role) = command_role(command) {
        return default_log_file_for_role(role);
    }

    match command {
        Commands::Stop(args) => args
            .role
            .map(|role| default_log_file_for_role(role.as_str()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_RUN_LOG_FILE)),
        Commands::Reload(args) => args
            .role
            .map(|role| default_log_file_for_role(role.as_str()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_RUN_LOG_FILE)),
        Commands::Status(args) => args
            .role
            .map(|role| default_log_file_for_role(role.as_str()))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_RUN_LOG_FILE)),
        Commands::WgConfig(_) | Commands::WgKeygen(_) | Commands::Cert(_) | Commands::Tui(_) => {
            PathBuf::from(DEFAULT_RUN_LOG_FILE)
        }
        Commands::Client(_)
        | Commands::Server(_)
        | Commands::Tun(_)
        | Commands::WgClient(_)
        | Commands::WgServer(_) => unreachable!("service commands are handled by command_role"),
    }
}

pub(super) fn default_log_file_for_role(role: &str) -> PathBuf {
    Path::new(DEFAULT_LOG_DIR).join(format!("{role}.log"))
}

pub(super) fn absolute_path(path: &Path) -> Result<PathBuf> {
    if let Some(expanded) = expand_home(path) {
        return Ok(expanded);
    }
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()
        .context("failed to read current directory")?
        .join(path))
}

fn expand_home(path: &Path) -> Option<PathBuf> {
    let raw = path.to_string_lossy();
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    if raw == "~" {
        return Some(home);
    }
    raw.strip_prefix("~/").map(|rest| home.join(rest))
}

pub(super) fn command_role(command: &Commands) -> Option<&'static str> {
    match command {
        Commands::Client(_) => Some("client"),
        Commands::Server(_) => Some("server"),
        Commands::Tun(_) => Some("tun"),
        Commands::WgClient(_) => Some("wg-client"),
        Commands::WgServer(_) => Some("wg-server"),
        Commands::WgConfig(_)
        | Commands::WgKeygen(_)
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Reload(_)
        | Commands::Status(_) => None,
    }
}
