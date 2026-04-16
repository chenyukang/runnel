use anyhow::{Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use pipit::{cert, client, config, server, telemetry, tui, tun, wg};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::Duration,
};
use tokio::time::sleep;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

const DAEMON_ENV: &str = "PIPIT_DAEMONIZED";

#[derive(Debug, Parser)]
#[command(
    name = "pipit",
    version,
    about = "A compact and durable Rust tunnel proxy"
)]
struct Cli {
    #[arg(long, global = true, env = "PIPIT_LOG", default_value = "info")]
    log: String,
    #[arg(long, global = true, default_value = "proxy.log")]
    log_file: PathBuf,
    #[arg(long, global = true)]
    telemetry_sock: Option<PathBuf>,
    #[arg(long, global = true)]
    pid_file: Option<PathBuf>,
    #[arg(long, global = true)]
    tui: bool,
    #[arg(long, global = true)]
    daemon: bool,
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Server(server::ServerArgs),
    Client(client::ClientArgs),
    Tun(tun::TunArgs),
    #[command(hide = true)]
    WgClient(wg::WgClientArgs),
    #[command(hide = true)]
    WgServer(wg::WgServerArgs),
    WgConfig(wg::WgConfigArgs),
    WgKeygen(wg::WgKeygenArgs),
    WgPubkey(wg::WgPubkeyArgs),
    Cert(cert::CertArgs),
    Tui(TuiArgs),
    Stop(StopArgs),
    Status(StatusArgs),
}

#[derive(Debug, Clone, Args)]
struct TuiArgs {
    #[arg(long)]
    attach: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ServiceRole {
    Client,
    Server,
    Tun,
    WgClient,
    WgServer,
}

impl ServiceRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Tun => "tun",
            Self::WgClient => "wg-client",
            Self::WgServer => "wg-server",
        }
    }
}

#[derive(Debug, Clone, Args)]
struct StopArgs {
    #[arg(value_enum)]
    role: Option<ServiceRole>,
    #[arg(long, default_value_t = 10)]
    wait_secs: u64,
}

#[derive(Debug, Clone, Args)]
struct StatusArgs {
    #[arg(value_enum)]
    role: Option<ServiceRole>,
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).context("failed to parse CLI arguments")?;
    if let Some(config_path) = &cli.config {
        let (file_config, base_dir) = config::load(config_path)?;
        config::apply_globals(
            &mut cli.log,
            &mut cli.log_file,
            &mut cli.telemetry_sock,
            &mut cli.pid_file,
            &mut cli.tui,
            &mut cli.daemon,
            &file_config,
            &matches,
            &base_dir,
        );
        if let Some((name, sub_matches)) = matches.subcommand() {
            match (&mut cli.command, name) {
                (Commands::Client(args), "client") => {
                    config::apply_client(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::Server(args), "server") => {
                    config::apply_server(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::Tun(args), "tun") => {
                    config::apply_tun(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::WgClient(args), "wg-client") => {
                    config::apply_wg_client(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::WgServer(args), "wg-server") => {
                    config::apply_wg_server(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::WgConfig(_), "wg-config")
                | (Commands::WgKeygen(_), "wg-keygen")
                | (Commands::WgPubkey(_), "wg-pubkey") => {}
                (Commands::Cert(args), "cert") => {
                    config::apply_cert(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::Tui(args), "tui") => {
                    if should_override(sub_matches, "attach") && args.attach.is_none() {
                        args.attach = cli.telemetry_sock.clone();
                    }
                }
                (Commands::Stop(_), "stop") | (Commands::Status(_), "status") => {}
                _ => {}
            }
        }
    }
    normalize_cli_modes(&mut cli);
    validate_daemon_mode(&cli)?;
    if should_spawn_daemon(&cli) {
        spawn_daemon_process(&cli)?;
        return Ok(());
    }
    if let Commands::Stop(args) = &cli.command {
        stop_daemon_process(&cli.log_file, cli.pid_file.clone(), args.clone()).await?;
        return Ok(());
    }
    if let Commands::Status(args) = &cli.command {
        status_daemon_processes(
            &cli.log_file,
            cli.pid_file.clone(),
            cli.telemetry_sock.clone(),
            args.clone(),
        )
        .await?;
        return Ok(());
    }
    if let Commands::Tui(args) = cli.command {
        let socket = resolve_attach_socket(&cli.log_file, cli.telemetry_sock, args.attach)?;
        return tui::run_attached(socket).await;
    }
    if let Some(result) = run_utility_command(&cli.command) {
        return result;
    }
    telemetry::init_channel(2048);
    let observability = init_tracing(&cli.log, &cli.log_file, !cli.tui && !cli.daemon)?;
    tun::set_embedded_tui(cli.tui);
    let _pid_file = maybe_create_pid_file(&cli, &observability.log_file)?;
    if let Some(context) = monitor_context(&cli, observability.log_file.clone()) {
        telemetry::set_context(context);
        if cli.daemon || cli.telemetry_sock.is_some() {
            let socket = resolve_socket_for_service(&cli, &observability.log_file)?;
            telemetry::start_socket_server(socket).await?;
        }
    }
    let dashboard_context = dashboard_context(&cli, observability.log_file.clone());

    let command = async move {
        match cli.command {
            Commands::Server(args) => server::run(args).await,
            Commands::Client(args) => client::run(args).await,
            Commands::Tun(args) => tun::run(args).await,
            Commands::WgClient(args) => wg::run_client(args).await,
            Commands::WgServer(args) => wg::run_server(args).await,
            Commands::WgConfig(args) => wg::run_config(args),
            Commands::WgKeygen(args) => wg::run_keygen(args),
            Commands::WgPubkey(args) => wg::run_pubkey(args),
            Commands::Cert(args) => cert::run(args),
            Commands::Tui(_) => Ok(()),
            Commands::Stop(_) => Ok(()),
            Commands::Status(_) => Ok(()),
        }
    };

    if let Some(context) = dashboard_context {
        let receiver = telemetry::subscribe().context("telemetry channel is not initialized")?;
        tokio::select! {
            result = command => result,
            result = tui::run(context, receiver) => result,
            signal = tokio::signal::ctrl_c() => {
                signal?;
                Ok(())
            }
        }
    } else {
        command.await
    }
}

fn normalize_cli_modes(cli: &mut Cli) {
    if matches!(
        cli.command,
        Commands::Tui(_) | Commands::Stop(_) | Commands::Status(_)
    ) {
        cli.tui = false;
        cli.daemon = false;
        return;
    }

    if cli.daemon && cli.tui {
        eprintln!("pipit: disabling TUI because daemon mode runs in the background");
        cli.tui = false;
    }
}

fn validate_daemon_mode(cli: &Cli) -> Result<()> {
    if !cli.daemon {
        return Ok(());
    }

    match cli.command {
        Commands::Client(_)
        | Commands::Server(_)
        | Commands::Tun(_)
        | Commands::WgClient(_)
        | Commands::WgServer(_) => Ok(()),
        Commands::WgConfig(_)
        | Commands::WgKeygen(_)
        | Commands::WgPubkey(_)
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Status(_) => {
            anyhow::bail!(
                "--daemon is only supported for client, server, tun, wg-client, and wg-server"
            )
        }
    }
}

fn should_spawn_daemon(cli: &Cli) -> bool {
    cli.daemon && std::env::var_os(DAEMON_ENV).is_none()
}

fn spawn_daemon_process(cli: &Cli) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate current executable")?;
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let mut command = Command::new(executable);
    command
        .args(args)
        .env(DAEMON_ENV, "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    #[cfg(unix)]
    {
        use std::{io, os::unix::process::CommandExt};

        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    let child = command
        .spawn()
        .context("failed to start daemon process in background")?;
    if let Some(role) = command_role(&cli.command) {
        let pid_file = resolve_pid_file_for_role(&cli.log_file, cli.pid_file.clone(), role).ok();
        if let Some(pid_file) = pid_file {
            println!(
                "pipit daemon started pid={} pid_file={}",
                child.id(),
                pid_file.display()
            );
        } else {
            println!("pipit daemon started pid={}", child.id());
        }
    } else {
        println!("pipit daemon started pid={}", child.id());
    }
    Ok(())
}

struct ObservabilityGuard {
    _file_guard: tracing_appender::non_blocking::WorkerGuard,
    log_file: PathBuf,
}

fn init_tracing(
    default_filter: &str,
    log_file: &Path,
    mirror_to_stderr: bool,
) -> Result<ObservabilityGuard> {
    let log_file = absolute_path(log_file)?;
    if let Some(parent) = log_file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let filter_directives =
        std::env::var(EnvFilter::DEFAULT_ENV).unwrap_or_else(|_| default_filter.to_owned());
    let filter_for_telemetry = EnvFilter::new(filter_directives.clone());
    let filter_for_file = EnvFilter::new(filter_directives.clone());
    let filter_for_stderr = EnvFilter::new(filter_directives);

    let directory = log_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = log_file
        .file_name()
        .and_then(|name| name.to_str())
        .context("log file path must end with a file name")?;
    let file_appender = tracing_appender::rolling::never(directory, file_name);
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);

    let file_layer = fmt::layer()
        .with_target(false)
        .with_ansi(false)
        .compact()
        .with_writer(file_writer)
        .with_filter(filter_for_file);
    let stderr_layer = mirror_to_stderr.then(|| {
        fmt::layer()
            .with_target(false)
            .compact()
            .with_writer(std::io::stderr)
            .with_filter(filter_for_stderr)
    });

    tracing_subscriber::registry()
        .with(telemetry::layer().with_filter(filter_for_telemetry))
        .with(file_layer)
        .with(stderr_layer)
        .try_init()
        .context("failed to initialize tracing")?;

    Ok(ObservabilityGuard {
        _file_guard: file_guard,
        log_file,
    })
}

fn dashboard_context(cli: &Cli, log_file: PathBuf) -> Option<tui::DashboardContext> {
    if !cli.tui {
        return None;
    }

    let context = match &cli.command {
        Commands::Client(args) => {
            let mode = args.effective_mode().ok();
            tui::DashboardContext {
                command_label: "client".to_owned(),
                mode_label: mode
                    .map(|mode| mode.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                listen: Some(if matches!(mode, Some(pipit::mode::ProxyMode::Wg)) {
                    args.wg.bind.clone()
                } else {
                    args.listen.clone()
                }),
                upstream: Some(if matches!(mode, Some(pipit::mode::ProxyMode::Wg)) {
                    args.wg.endpoint.clone()
                } else {
                    args.server.clone()
                }),
                path: Some(match mode {
                    Some(pipit::mode::ProxyMode::NativeMux) => args.mux_path.clone(),
                    Some(pipit::mode::ProxyMode::Wg) => args.wg.device.clone(),
                    _ => args.path.clone(),
                }),
                log_file,
                log_filter: cli.log.clone(),
            }
        }
        Commands::Server(args) => tui::DashboardContext {
            command_label: "server".to_owned(),
            mode_label: args.mode.to_string(),
            listen: Some(if matches!(args.mode, pipit::mode::ProxyMode::Wg) {
                args.wg.listen.clone()
            } else {
                args.listen.clone()
            }),
            upstream: Some(if matches!(args.mode, pipit::mode::ProxyMode::Wg) {
                args.wg.peer_tunnel_ip.to_string()
            } else {
                args.fallback_url.clone()
            }),
            path: Some(match args.mode {
                pipit::mode::ProxyMode::NativeMux => args.mux_path.clone(),
                pipit::mode::ProxyMode::Wg => args.wg.device.clone(),
                _ => args.path.clone(),
            }),
            log_file,
            log_filter: cli.log.clone(),
        },
        Commands::Tun(args) => tui::DashboardContext {
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
            log_file,
            log_filter: cli.log.clone(),
        },
        Commands::WgClient(args) => tui::DashboardContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: Some(args.bind.clone()),
            upstream: Some(args.endpoint.clone()),
            path: Some(args.device.clone()),
            log_file,
            log_filter: cli.log.clone(),
        },
        Commands::WgServer(args) => tui::DashboardContext {
            command_label: "wg-server".to_owned(),
            mode_label: "wg".to_owned(),
            listen: Some(args.listen.clone()),
            upstream: Some(args.peer_tunnel_ip.to_string()),
            path: Some(args.device.clone()),
            log_file,
            log_filter: cli.log.clone(),
        },
        Commands::WgConfig(_)
        | Commands::WgKeygen(_)
        | Commands::WgPubkey(_)
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Status(_) => {
            return None;
        }
    };

    Some(context)
}

fn monitor_context(cli: &Cli, log_file: PathBuf) -> Option<telemetry::MonitorContext> {
    let pid = std::process::id();
    let context = match &cli.command {
        Commands::Client(args) => {
            let mode = args.effective_mode().ok();
            telemetry::MonitorContext {
                command_label: "client".to_owned(),
                mode_label: mode
                    .map(|mode| mode.to_string())
                    .unwrap_or_else(|| "-".to_owned()),
                listen: Some(if matches!(mode, Some(pipit::mode::ProxyMode::Wg)) {
                    args.wg.bind.clone()
                } else {
                    args.listen.clone()
                }),
                upstream: Some(if matches!(mode, Some(pipit::mode::ProxyMode::Wg)) {
                    args.wg.endpoint.clone()
                } else {
                    args.server.clone()
                }),
                path: Some(match mode {
                    Some(pipit::mode::ProxyMode::NativeMux) => args.mux_path.clone(),
                    Some(pipit::mode::ProxyMode::Wg) => args.wg.device.clone(),
                    _ => args.path.clone(),
                }),
                log_file,
                log_filter: cli.log.clone(),
                pid,
            }
        }
        Commands::Server(args) => telemetry::MonitorContext {
            command_label: "server".to_owned(),
            mode_label: args.mode.to_string(),
            listen: Some(if matches!(args.mode, pipit::mode::ProxyMode::Wg) {
                args.wg.listen.clone()
            } else {
                args.listen.clone()
            }),
            upstream: Some(if matches!(args.mode, pipit::mode::ProxyMode::Wg) {
                args.wg.peer_tunnel_ip.to_string()
            } else {
                args.fallback_url.clone()
            }),
            path: Some(match args.mode {
                pipit::mode::ProxyMode::NativeMux => args.mux_path.clone(),
                pipit::mode::ProxyMode::Wg => args.wg.device.clone(),
                _ => args.path.clone(),
            }),
            log_file,
            log_filter: cli.log.clone(),
            pid,
        },
        Commands::Tun(args) => telemetry::MonitorContext {
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
            log_file,
            log_filter: cli.log.clone(),
            pid,
        },
        Commands::WgClient(args) => telemetry::MonitorContext {
            command_label: "wg-client".to_owned(),
            mode_label: "wg".to_owned(),
            listen: Some(args.bind.clone()),
            upstream: Some(args.endpoint.clone()),
            path: Some(args.device.clone()),
            log_file,
            log_filter: cli.log.clone(),
            pid,
        },
        Commands::WgServer(args) => telemetry::MonitorContext {
            command_label: "wg-server".to_owned(),
            mode_label: "wg".to_owned(),
            listen: Some(args.listen.clone()),
            upstream: Some(args.peer_tunnel_ip.to_string()),
            path: Some(args.device.clone()),
            log_file,
            log_filter: cli.log.clone(),
            pid,
        },
        Commands::WgConfig(_)
        | Commands::WgKeygen(_)
        | Commands::WgPubkey(_)
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Status(_) => {
            return None;
        }
    };

    Some(context)
}

fn resolve_socket_for_service(cli: &Cli, log_file: &Path) -> Result<PathBuf> {
    if let Some(path) = &cli.telemetry_sock {
        return absolute_path(path);
    }

    let role = command_role(&cli.command).context("telemetry socket is not supported")?;
    default_socket_path(log_file, role)
}

fn resolve_attach_socket(
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

fn default_socket_path(log_file: &Path, role: &str) -> Result<PathBuf> {
    default_sidecar_path(log_file, role, "sock")
}

fn default_pid_path(log_file: &Path, role: &str) -> Result<PathBuf> {
    default_sidecar_path(log_file, role, "pid")
}

fn default_sidecar_path(log_file: &Path, role: &str, ext: &str) -> Result<PathBuf> {
    let log_file = absolute_path(log_file)?;
    let parent = log_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = log_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("pipit");
    Ok(parent.join(format!("{stem}.{role}.{ext}")))
}

fn should_override(matches: &clap::ArgMatches, id: &str) -> bool {
    !matches.value_source(id).is_some_and(|source| {
        matches!(
            source,
            clap::parser::ValueSource::CommandLine | clap::parser::ValueSource::EnvVariable
        )
    })
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()
        .context("failed to read current directory")?
        .join(path))
}

fn command_role(command: &Commands) -> Option<&'static str> {
    match command {
        Commands::Client(_) => Some("client"),
        Commands::Server(_) => Some("server"),
        Commands::Tun(_) => Some("tun"),
        Commands::WgClient(_) => Some("wg-client"),
        Commands::WgServer(_) => Some("wg-server"),
        Commands::WgConfig(_)
        | Commands::WgKeygen(_)
        | Commands::WgPubkey(_)
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Status(_) => None,
    }
}

fn run_utility_command(command: &Commands) -> Option<Result<()>> {
    match command {
        Commands::WgConfig(args) => Some(wg::run_config(args.clone())),
        Commands::WgKeygen(args) => Some(wg::run_keygen(args.clone())),
        Commands::WgPubkey(args) => Some(wg::run_pubkey(args.clone())),
        Commands::Cert(args) => Some(cert::run(args.clone())),
        _ => None,
    }
}

#[derive(Debug, Clone)]
struct StatusTarget {
    label: String,
    pid_file: Option<PathBuf>,
    telemetry_socket: Option<PathBuf>,
}

#[derive(Debug, Serialize)]
struct StatusReport {
    services: Vec<ServiceStatus>,
}

#[derive(Debug, Serialize)]
struct ServiceStatus {
    role: String,
    state: String,
    pid_file: Option<PathBuf>,
    telemetry_sock: Option<PathBuf>,
    pid_from_file: Option<u32>,
    runtime: Option<RuntimeStatus>,
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct RuntimeStatus {
    command: String,
    mode: String,
    pid: u32,
    listen: Option<String>,
    upstream: Option<String>,
    path: Option<String>,
    log_file: PathBuf,
    log_filter: String,
    uptime_secs: u64,
    total_relays: u64,
    total_errors: u64,
    total_warnings: u64,
    total_uploaded: u64,
    total_downloaded: u64,
    last_event_age_ms: Option<u64>,
    last_warning_age_ms: Option<u64>,
    last_traffic_age_ms: Option<u64>,
}

impl From<telemetry::DashboardSnapshot> for RuntimeStatus {
    fn from(snapshot: telemetry::DashboardSnapshot) -> Self {
        Self {
            command: snapshot.context.command_label,
            mode: snapshot.context.mode_label,
            pid: snapshot.context.pid,
            listen: snapshot.context.listen,
            upstream: snapshot.context.upstream,
            path: snapshot.context.path,
            log_file: snapshot.context.log_file,
            log_filter: snapshot.context.log_filter,
            uptime_secs: snapshot.uptime_secs,
            total_relays: snapshot.total_relays,
            total_errors: snapshot.total_errors,
            total_warnings: snapshot.total_warnings,
            total_uploaded: snapshot.total_uploaded,
            total_downloaded: snapshot.total_downloaded,
            last_event_age_ms: snapshot.last_event_age_ms,
            last_warning_age_ms: snapshot.last_warning_age_ms,
            last_traffic_age_ms: snapshot.last_traffic_age_ms,
        }
    }
}

async fn status_daemon_processes(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    configured_socket: Option<PathBuf>,
    args: StatusArgs,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (log_file, configured_pid_file, configured_socket, args);
        anyhow::bail!("pipit status is only supported on unix platforms");
    }

    #[cfg(unix)]
    {
        let targets =
            resolve_status_targets(log_file, configured_pid_file, configured_socket, args.role)?;
        let mut services = Vec::with_capacity(targets.len());
        for target in targets {
            services.push(inspect_status_target(target).await?);
        }
        let report = StatusReport { services };
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&report).context("failed to encode status JSON")?
            );
        } else {
            print_status_report(&report);
        }
        Ok(())
    }
}

fn resolve_status_targets(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    configured_socket: Option<PathBuf>,
    role: Option<ServiceRole>,
) -> Result<Vec<StatusTarget>> {
    if let Some(role) = role {
        return Ok(vec![StatusTarget {
            label: role.as_str().to_owned(),
            pid_file: Some(match configured_pid_file {
                Some(path) => absolute_path(&path)?,
                None => default_pid_path(log_file, role.as_str())?,
            }),
            telemetry_socket: Some(match configured_socket {
                Some(path) => absolute_path(&path)?,
                None => default_socket_path(log_file, role.as_str())?,
            }),
        }]);
    }

    if configured_pid_file.is_some() || configured_socket.is_some() {
        return Ok(vec![StatusTarget {
            label: "service".to_owned(),
            pid_file: configured_pid_file
                .as_deref()
                .map(absolute_path)
                .transpose()?,
            telemetry_socket: configured_socket
                .as_deref()
                .map(absolute_path)
                .transpose()?,
        }]);
    }

    Ok(["client", "server", "tun", "wg-client", "wg-server"]
        .into_iter()
        .map(|role| {
            Ok(StatusTarget {
                label: role.to_owned(),
                pid_file: Some(default_pid_path(log_file, role)?),
                telemetry_socket: Some(default_socket_path(log_file, role)?),
            })
        })
        .collect::<Result<Vec<_>>>()?)
}

#[cfg(unix)]
async fn inspect_status_target(target: StatusTarget) -> Result<ServiceStatus> {
    let mut notes = Vec::new();

    let pid_file_exists = target.pid_file.as_ref().is_some_and(|path| path.exists());
    let (pid_from_file, pid_alive) = match &target.pid_file {
        Some(path) if path.exists() => match read_pid_file(path) {
            Ok(pid) => {
                let alive = process_exists(pid)?;
                if !alive {
                    notes.push(format!("stale pid file {}", path.display()));
                }
                (Some(pid), Some(alive))
            }
            Err(err) => {
                notes.push(format!("{err:#}"));
                (None, None)
            }
        },
        Some(path) => {
            notes.push(format!("pid file not found: {}", path.display()));
            (None, None)
        }
        None => (None, None),
    };

    let runtime = match &target.telemetry_socket {
        Some(path) if path.exists() => match telemetry::attach_socket(path).await {
            Ok((snapshot, _receiver)) => Some(RuntimeStatus::from(snapshot)),
            Err(err) => {
                notes.push(format!(
                    "failed to query telemetry socket {}: {err:#}",
                    path.display()
                ));
                None
            }
        },
        Some(path) => {
            notes.push(format!("telemetry socket not found: {}", path.display()));
            None
        }
        None => None,
    };

    if let (Some(pid), Some(runtime)) = (pid_from_file, runtime.as_ref())
        && pid != runtime.pid
    {
        notes.push(format!(
            "pid file reports {}, telemetry reports {}",
            pid, runtime.pid
        ));
    }

    let role = runtime
        .as_ref()
        .map(|runtime| runtime.command.clone())
        .unwrap_or_else(|| target.label.clone());
    let state = classify_service_state(
        target.pid_file.is_some(),
        pid_file_exists,
        pid_from_file,
        pid_alive,
        runtime.as_ref(),
    );

    Ok(ServiceStatus {
        role,
        state: state.to_owned(),
        pid_file: target.pid_file,
        telemetry_sock: target.telemetry_socket,
        pid_from_file,
        runtime,
        detail: (!notes.is_empty()).then(|| notes.join("; ")),
    })
}

fn classify_service_state(
    expects_pid_file: bool,
    pid_file_exists: bool,
    pid_from_file: Option<u32>,
    pid_alive: Option<bool>,
    runtime: Option<&RuntimeStatus>,
) -> &'static str {
    if let Some(runtime) = runtime {
        if expects_pid_file {
            return match (pid_from_file, pid_alive) {
                (Some(pid), Some(true)) if pid == runtime.pid => "running",
                _ => "degraded",
            };
        }
        return "running";
    }

    if matches!(pid_alive, Some(true)) {
        return "degraded";
    }

    if expects_pid_file && (pid_file_exists || pid_from_file.is_some()) {
        return "stale";
    }

    "not-running"
}

fn print_status_report(report: &StatusReport) {
    for (index, service) in report.services.iter().enumerate() {
        if index > 0 {
            println!();
        }

        println!("{}: {}", service.role, service.state);
        if let Some(pid) = service
            .runtime
            .as_ref()
            .map(|runtime| runtime.pid)
            .or(service.pid_from_file)
        {
            println!("  pid: {pid}");
        }
        if let Some(runtime) = &service.runtime {
            println!("  mode: {}", runtime.mode);
            if let Some(listen) = &runtime.listen {
                println!("  listen: {listen}");
            }
            if let Some(upstream) = &runtime.upstream {
                println!("  upstream: {upstream}");
            }
            if let Some(path) = &runtime.path {
                println!("  path: {path}");
            }
            println!("  uptime: {}", format_duration(runtime.uptime_secs));
            println!(
                "  traffic: up {} down {}",
                format_bytes(runtime.total_uploaded),
                format_bytes(runtime.total_downloaded)
            );
            println!(
                "  health: relays {} warnings {} errors {}",
                runtime.total_relays, runtime.total_warnings, runtime.total_errors
            );
            println!(
                "  log: {} ({})",
                runtime.log_file.display(),
                runtime.log_filter
            );
        }
        if let Some(pid_file) = &service.pid_file {
            println!("  pid_file: {}", pid_file.display());
        }
        if let Some(telemetry_sock) = &service.telemetry_sock {
            println!("  telemetry_sock: {}", telemetry_sock.display());
        }
        if let Some(detail) = &service.detail {
            println!("  detail: {detail}");
        }
    }
}

fn format_duration(total_secs: u64) -> String {
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;
    if hours > 0 {
        format!("{hours}h{minutes:02}m{seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m{seconds:02}s")
    } else {
        format!("{seconds}s")
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn resolve_pid_file_for_role(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: &str,
) -> Result<PathBuf> {
    if let Some(path) = configured_pid_file {
        return absolute_path(&path);
    }
    default_pid_path(log_file, role)
}

fn maybe_create_pid_file(cli: &Cli, log_file: &Path) -> Result<Option<PidFileGuard>> {
    let Some(role) = command_role(&cli.command) else {
        return Ok(None);
    };
    if !cli.daemon && cli.pid_file.is_none() {
        return Ok(None);
    }

    let path = resolve_pid_file_for_role(log_file, cli.pid_file.clone(), role)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if path.exists() {
        match read_pid_file(&path) {
            Ok(pid) if process_exists(pid)? => {
                anyhow::bail!(
                    "another {} daemon is already running with pid {} (pid file: {})",
                    role,
                    pid,
                    path.display()
                );
            }
            Ok(_) | Err(_) => {
                let _ = fs::remove_file(&path);
            }
        }
    }

    fs::write(&path, format!("{}\n", std::process::id()))
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(PidFileGuard { path }))
}

async fn stop_daemon_process(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    args: StopArgs,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (log_file, configured_pid_file, args);
        anyhow::bail!("pipit stop is only supported on unix platforms");
    }

    #[cfg(unix)]
    {
        let pid_file = resolve_stop_pid_file(log_file, configured_pid_file, args.role)?;
        let pid = read_pid_file(&pid_file)?;
        if !process_exists(pid)? {
            let _ = fs::remove_file(&pid_file);
            println!(
                "pipit daemon is not running (removed stale pid file {})",
                pid_file.display()
            );
            return Ok(());
        }

        send_sigterm(pid)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(args.wait_secs);
        loop {
            if !process_exists(pid)? {
                let _ = fs::remove_file(&pid_file);
                println!(
                    "pipit daemon stopped pid={} pid_file={}",
                    pid,
                    pid_file.display()
                );
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                anyhow::bail!(
                    "timed out waiting {}s for pid {} to exit; try again or stop it manually",
                    args.wait_secs,
                    pid
                );
            }
            sleep(Duration::from_millis(100)).await;
        }
    }
}

fn resolve_stop_pid_file(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: Option<ServiceRole>,
) -> Result<PathBuf> {
    if let Some(path) = configured_pid_file {
        return absolute_path(&path);
    }
    if let Some(role) = role {
        return default_pid_path(log_file, role.as_str());
    }

    let client = default_pid_path(log_file, "client")?;
    let server = default_pid_path(log_file, "server")?;
    let tun = default_pid_path(log_file, "tun")?;
    let wg_client = default_pid_path(log_file, "wg-client")?;
    let wg_server = default_pid_path(log_file, "wg-server")?;
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
        0 => anyhow::bail!(
            "no pid file found; pass `stop client`, `stop server`, `stop tun`, `stop wg-client`, `stop wg-server`, or `--pid-file`"
        ),
        1 => Ok(found.remove(0)),
        _ => anyhow::bail!(
            "multiple pid files exist; pass `stop client`, `stop server`, `stop tun`, `stop wg-client`, `stop wg-server`, or `--pid-file`"
        ),
    }
}

fn read_pid_file(path: &Path) -> Result<u32> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read pid file {}", path.display()))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("invalid pid in {}", path.display()))
}

#[cfg(unix)]
fn process_exists(pid: u32) -> Result<bool> {
    let pid = pid as i32;
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == libc::ESRCH => Ok(false),
        Some(code) if code == libc::EPERM => Ok(true),
        _ => Err(err).with_context(|| format!("failed to inspect process {}", pid)),
    }
}

#[cfg(unix)]
fn send_sigterm(pid: u32) -> Result<()> {
    let pid = pid as i32;
    let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
    if rc == 0 {
        return Ok(());
    }
    Err(std::io::Error::last_os_error())
        .with_context(|| format!("failed to send SIGTERM to {}", pid))
}

struct PidFileGuard {
    path: PathBuf,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Commands, RuntimeStatus, ServiceRole, classify_service_state, command_role,
        resolve_status_targets, run_utility_command,
    };
    use pipit::wg;
    use std::path::Path;

    #[test]
    fn status_targets_default_to_all_roles() {
        let targets = resolve_status_targets(Path::new("proxy.log"), None, None, None).unwrap();
        let labels = targets
            .iter()
            .map(|target| target.label.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            labels,
            vec!["client", "server", "tun", "wg-client", "wg-server"]
        );
        assert!(targets.iter().all(|target| target.pid_file.is_some()));
        assert!(
            targets
                .iter()
                .all(|target| target.telemetry_socket.is_some())
        );
    }

    #[test]
    fn status_target_uses_role_specific_overrides() {
        let targets = resolve_status_targets(
            Path::new("proxy.log"),
            Some(Path::new("custom.pid").to_path_buf()),
            Some(Path::new("custom.sock").to_path_buf()),
            Some(ServiceRole::Tun),
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].label, "tun");
        assert!(
            targets[0]
                .pid_file
                .as_ref()
                .is_some_and(|path| path.ends_with("custom.pid"))
        );
        assert!(
            targets[0]
                .telemetry_socket
                .as_ref()
                .is_some_and(|path| path.ends_with("custom.sock"))
        );
    }

    #[test]
    fn wg_utility_commands_are_not_treated_as_services() {
        let config = Commands::WgConfig(wg::WgConfigArgs {
            server_endpoint: "198.51.100.10:51820".to_owned(),
            client_tunnel_ip: "10.8.0.2".parse().unwrap(),
            server_tunnel_ip: "10.8.0.1".parse().unwrap(),
            mtu: 1420,
            persistent_keepalive_secs: 25,
            dns: None,
            dns_capture: false,
            allowed_ips: Vec::new(),
            excluded_ips: Vec::new(),
            exclude_lan: false,
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            json: false,
        });
        assert!(command_role(&config).is_none());
        assert!(run_utility_command(&config).is_some_and(|result| result.is_ok()));

        let keygen = Commands::WgKeygen(wg::WgKeygenArgs { json: false });
        assert!(command_role(&keygen).is_none());
        assert!(run_utility_command(&keygen).is_some());

        let pubkey = Commands::WgPubkey(wg::WgPubkeyArgs {
            private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=".to_owned(),
            json: false,
        });
        assert!(command_role(&pubkey).is_none());
        assert!(run_utility_command(&pubkey).is_some_and(|result| result.is_ok()));
    }

    #[test]
    fn status_state_is_running_when_pid_and_runtime_match() {
        let runtime = RuntimeStatus {
            command: "client".to_owned(),
            mode: "native-http".to_owned(),
            pid: 42,
            listen: None,
            upstream: None,
            path: None,
            log_file: Path::new("proxy.log").to_path_buf(),
            log_filter: "info".to_owned(),
            uptime_secs: 0,
            total_relays: 0,
            total_errors: 0,
            total_warnings: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            last_event_age_ms: None,
            last_warning_age_ms: None,
            last_traffic_age_ms: None,
        };
        assert_eq!(
            classify_service_state(true, true, Some(42), Some(true), Some(&runtime)),
            "running"
        );
    }

    #[test]
    fn status_state_is_degraded_when_runtime_disagrees_with_pid_file() {
        let runtime = RuntimeStatus {
            command: "tun".to_owned(),
            mode: "native-http".to_owned(),
            pid: 77,
            listen: None,
            upstream: None,
            path: None,
            log_file: Path::new("proxy.log").to_path_buf(),
            log_filter: "info".to_owned(),
            uptime_secs: 0,
            total_relays: 0,
            total_errors: 0,
            total_warnings: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            last_event_age_ms: None,
            last_warning_age_ms: None,
            last_traffic_age_ms: None,
        };
        assert_eq!(
            classify_service_state(true, true, Some(42), Some(true), Some(&runtime)),
            "degraded"
        );
    }

    #[test]
    fn status_state_is_stale_when_only_pid_file_remains() {
        assert_eq!(
            classify_service_state(true, true, Some(42), Some(false), None),
            "stale"
        );
    }
}
