use anyhow::{Context, Result};
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use pipit::{cert, client, config, server, telemetry, tui};
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
    Cert(cert::CertArgs),
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
                (Commands::Cert(args), "cert") => {
                    config::apply_cert(args, &file_config, sub_matches, &base_dir);
                }
                _ => {}
            }
        }
    }
    normalize_daemon_mode(&mut cli);
    validate_daemon_mode(&cli)?;
    if should_spawn_daemon(&cli) {
        spawn_daemon_process()?;
        return Ok(());
    }
    telemetry::init_channel(2048);
    let observability = init_tracing(&cli.log, &cli.log_file, !cli.tui && !cli.daemon)?;
    let dashboard_context = dashboard_context(&cli, observability.log_file.clone());

    let command = async move {
        match cli.command {
            Commands::Server(args) => server::run(args).await,
            Commands::Client(args) => client::run(args).await,
            Commands::Cert(args) => cert::run(args),
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

fn normalize_daemon_mode(cli: &mut Cli) {
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
        Commands::Client(_) | Commands::Server(_) => Ok(()),
        Commands::Cert(_) => anyhow::bail!("--daemon is only supported for client and server"),
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
        Commands::Cert(_) => return None,
    };

    Some(context)
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    Ok(std::env::current_dir()
        .context("failed to read current directory")?
        .join(path))
}
