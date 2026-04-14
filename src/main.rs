use anyhow::{Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use pipit::{cert, client, config, server, telemetry, tui, tun};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
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
}

#[derive(Debug, Clone, Args)]
struct TuiArgs {
    #[arg(long)]
    attach: Option<PathBuf>,
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
                _ => {}
            }
        }
    }
    normalize_cli_modes(&mut cli);
    validate_daemon_mode(&cli)?;
    if should_spawn_daemon(&cli) {
        spawn_daemon_process()?;
        return Ok(());
    }
    if let Commands::Tui(args) = cli.command {
        let socket = resolve_attach_socket(&cli.log_file, cli.telemetry_sock, args.attach)?;
        return tui::run_attached(socket).await;
    }
    telemetry::init_channel(2048);
    let observability = init_tracing(&cli.log, &cli.log_file, !cli.tui && !cli.daemon)?;
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
    if matches!(cli.command, Commands::Tui(_)) {
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
        Commands::Cert(_) | Commands::Tui(_) => {
            anyhow::bail!("--daemon is only supported for client, server, and tun")
        }
    }
}

fn should_spawn_daemon(cli: &Cli) -> bool {
    cli.daemon && std::env::var_os(DAEMON_ENV).is_none()
}

fn spawn_daemon_process() -> Result<()> {
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
    println!("pipit daemon started pid={}", child.id());
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
        Commands::Cert(_) => return None,
        Commands::Tui(_) => return None,
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
        Commands::Cert(_) | Commands::Tui(_) => return None,
    };

    Some(context)
}

fn resolve_socket_for_service(cli: &Cli, log_file: &Path) -> Result<PathBuf> {
    if let Some(path) = &cli.telemetry_sock {
        return absolute_path(path);
    }

    let role = match cli.command {
        Commands::Client(_) => "client",
        Commands::Server(_) => "server",
        Commands::Tun(_) => "tun",
        Commands::Cert(_) | Commands::Tui(_) => anyhow::bail!("telemetry socket is not supported"),
    };
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
    let log_file = absolute_path(log_file)?;
    let parent = log_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let stem = log_file
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("pipit");
    Ok(parent.join(format!("{stem}.{role}.sock")))
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
