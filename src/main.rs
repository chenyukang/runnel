use anyhow::{Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use pipit::{cert, client, config, server, telemetry, tui, tun};
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
    Cert(cert::CertArgs),
    Tui(TuiArgs),
    Stop(StopArgs),
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
}

impl ServiceRole {
    fn as_str(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Server => "server",
            Self::Tun => "tun",
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
                (Commands::Cert(args), "cert") => {
                    config::apply_cert(args, &file_config, sub_matches, &base_dir);
                }
                (Commands::Tui(args), "tui") => {
                    if should_override(sub_matches, "attach") && args.attach.is_none() {
                        args.attach = cli.telemetry_sock.clone();
                    }
                }
                (Commands::Stop(_), "stop") => {}
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
    if let Commands::Tui(args) = cli.command {
        let socket = resolve_attach_socket(&cli.log_file, cli.telemetry_sock, args.attach)?;
        return tui::run_attached(socket).await;
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
            Commands::Cert(args) => cert::run(args),
            Commands::Tui(_) => Ok(()),
            Commands::Stop(_) => Ok(()),
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
    if matches!(cli.command, Commands::Tui(_) | Commands::Stop(_)) {
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
        Commands::Client(_) | Commands::Server(_) | Commands::Tun(_) => Ok(()),
        Commands::Cert(_) | Commands::Tui(_) | Commands::Stop(_) => {
            anyhow::bail!("--daemon is only supported for client, server, and tun")
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
        .with(telemetry::layer())
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
        Commands::Client(args) => tui::DashboardContext {
            command_label: "client".to_owned(),
            mode_label: args
                .effective_mode()
                .ok()
                .map(|mode| mode.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            listen: Some(args.listen.clone()),
            upstream: Some(args.server.clone()),
            path: Some(
                args.effective_mode()
                    .ok()
                    .filter(|mode| matches!(mode, pipit::mode::ProxyMode::NativeMux))
                    .map(|_| args.mux_path.clone())
                    .unwrap_or_else(|| args.path.clone()),
            ),
            log_file,
            log_filter: cli.log.clone(),
        },
        Commands::Server(args) => tui::DashboardContext {
            command_label: "server".to_owned(),
            mode_label: args.mode.to_string(),
            listen: Some(args.listen.clone()),
            upstream: Some(args.fallback_url.clone()),
            path: Some(match args.mode {
                pipit::mode::ProxyMode::NativeMux => args.mux_path.clone(),
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
        Commands::Cert(_) | Commands::Tui(_) | Commands::Stop(_) => return None,
    };

    Some(context)
}

fn monitor_context(cli: &Cli, log_file: PathBuf) -> Option<telemetry::MonitorContext> {
    let pid = std::process::id();
    let context = match &cli.command {
        Commands::Client(args) => telemetry::MonitorContext {
            command_label: "client".to_owned(),
            mode_label: args
                .effective_mode()
                .ok()
                .map(|mode| mode.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            listen: Some(args.listen.clone()),
            upstream: Some(args.server.clone()),
            path: Some(
                args.effective_mode()
                    .ok()
                    .filter(|mode| matches!(mode, pipit::mode::ProxyMode::NativeMux))
                    .map(|_| args.mux_path.clone())
                    .unwrap_or_else(|| args.path.clone()),
            ),
            log_file,
            log_filter: cli.log.clone(),
            pid,
        },
        Commands::Server(args) => telemetry::MonitorContext {
            command_label: "server".to_owned(),
            mode_label: args.mode.to_string(),
            listen: Some(args.listen.clone()),
            upstream: Some(args.fallback_url.clone()),
            path: Some(match args.mode {
                pipit::mode::ProxyMode::NativeMux => args.mux_path.clone(),
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
        Commands::Cert(_) | Commands::Tui(_) | Commands::Stop(_) => return None,
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
        Commands::Cert(_) | Commands::Tui(_) | Commands::Stop(_) => None,
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

    match found.len() {
        0 => anyhow::bail!(
            "no pid file found; pass `stop client`, `stop server`, `stop tun`, or `--pid-file`"
        ),
        1 => Ok(found.remove(0)),
        _ => anyhow::bail!(
            "multiple pid files exist; pass `stop client`, `stop server`, `stop tun`, or `--pid-file`"
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
