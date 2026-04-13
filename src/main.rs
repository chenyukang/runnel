use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pipit::{cert, client, server, telemetry, tui};
use std::path::{Path, PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

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
    let cli = Cli::parse();
    telemetry::init_channel(2048);
    let observability = init_tracing(&cli.log, &cli.log_file, !cli.tui)?;
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
