mod cli_daemon;
mod cli_service;

use anyhow::{Context, Result};
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use cli_daemon::{
    maybe_create_pid_file, reload_daemon_process, resolve_pid_file_for_role,
    status_daemon_processes, stop_daemon_process, switch_daemon_process,
};
use cli_service::{
    absolute_path, command_role, dashboard_context, default_log_file_for_command, monitor_context,
    resolve_attach_socket, resolve_socket_for_service,
};
use runnel::{cert, client, config, server, telemetry, tui, tun, wg};
use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};
use tracing::error;
use tracing_subscriber::{EnvFilter, fmt, fmt::time::FormatTime, prelude::*};

const DAEMON_ENV: &str = "RUNNEL_DAEMONIZED";
const DAEMON_STARTUP_CHECK: Duration = Duration::from_millis(1200);
const DAEMON_STARTUP_POLL: Duration = Duration::from_millis(100);
const DEFAULT_CURRENT_DIR: &str = "~/.runnel/current";
const DEFAULT_LOG_DIR: &str = "~/.runnel/logs";
const DEFAULT_RUN_LOG_FILE: &str = "~/.runnel/logs/run.log";

#[derive(Debug, Parser)]
#[command(
    name = "runnel",
    version,
    about = "A compact and durable Rust tunnel proxy"
)]
struct Cli {
    #[arg(long, global = true, env = "RUNNEL_LOG", default_value = "info")]
    log: String,
    #[arg(
        long,
        global = true,
        default_value = DEFAULT_RUN_LOG_FILE,
        hide_default_value = true,
        help = "Write logs to this file; service commands default to ~/.runnel/logs/<role>.log"
    )]
    log_file: PathBuf,
    #[arg(
        long,
        global = true,
        env = "RUNNEL_LOG_TIMEZONE",
        default_value = "local",
        help = "Timezone for log timestamps: utc, local, +08:00, or Asia/Shanghai"
    )]
    log_timezone: String,
    #[arg(long, global = true)]
    telemetry_sock: Option<PathBuf>,
    #[arg(long, global = true)]
    pid_file: Option<PathBuf>,
    #[arg(long, global = true)]
    tui: bool,
    #[arg(long, global = true)]
    daemon: bool,
    #[arg(long, global = true, hide = true)]
    check_config_only: bool,
    #[arg(long, global = true, env = "RUNNEL_CONFIG")]
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
    WgClient(wg::client::WgClientArgs),
    #[command(hide = true)]
    WgServer(wg::server::WgServerArgs),
    WgConfig(wg::configgen::WgConfigArgs),
    WgKeygen(wg::keys::WgKeygenArgs),
    Cert(cert::CertArgs),
    Tui(TuiArgs),
    Stop(StopArgs),
    Reload(ReloadArgs),
    Switch(SwitchArgs),
    Status(StatusArgs),
}

#[derive(Debug, Clone, Args)]
struct TuiArgs {
    #[arg(long)]
    attach: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
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

#[derive(Debug, Clone, Copy, Eq, PartialEq, ValueEnum)]
enum SwitchRole {
    Client,
    Tun,
    WgClient,
}

impl SwitchRole {
    fn service_role(self) -> ServiceRole {
        match self {
            Self::Client => ServiceRole::Client,
            Self::Tun => ServiceRole::Tun,
            Self::WgClient => ServiceRole::WgClient,
        }
    }

    fn as_str(self) -> &'static str {
        self.service_role().as_str()
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
struct ReloadArgs {
    #[arg(value_enum)]
    role: Option<ServiceRole>,
    #[arg(long, default_value_t = 10)]
    wait_secs: u64,
}

#[derive(Debug, Clone, Args)]
struct SwitchArgs {
    #[arg(value_enum)]
    role: Option<SwitchRole>,
    #[arg(long, conflicts_with = "proxy", help = "Force bypass mode")]
    bypass: bool,
    #[arg(long, help = "Force normal proxying mode")]
    proxy: bool,
}

impl SwitchArgs {
    fn target(&self) -> telemetry::TrafficSwitchTarget {
        if self.bypass {
            telemetry::TrafficSwitchTarget::Bypass
        } else if self.proxy {
            telemetry::TrafficSwitchTarget::Proxying
        } else {
            telemetry::TrafficSwitchTarget::Toggle
        }
    }
}

#[derive(Debug, Clone, Args)]
struct StatusArgs {
    #[arg(value_enum)]
    role: Option<ServiceRole>,
    #[arg(long)]
    json: bool,
}

fn discover_default_config_path() -> Option<PathBuf> {
    first_existing_config_path(default_config_paths())
}

fn first_existing_config_path(paths: impl IntoIterator<Item = PathBuf>) -> Option<PathBuf> {
    paths.into_iter().find(|path| path.is_file())
}

fn default_config_paths() -> Vec<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let xdg_config_home = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from);
    let sudo_home = sudo_user_home_dir();
    default_config_paths_for(
        home.as_deref(),
        xdg_config_home.as_deref(),
        sudo_home.as_deref(),
    )
}

fn default_config_paths_for(
    home: Option<&Path>,
    xdg_config_home: Option<&Path>,
    sudo_home: Option<&Path>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut seen = BTreeSet::new();

    if let Some(home) = home {
        push_legacy_home_config_paths(&mut paths, &mut seen, home);
    }
    if let Some(xdg_config_home) = xdg_config_home {
        push_config_file_variants(&mut paths, &mut seen, &xdg_config_home.join("runnel"));
    }
    if let Some(home) = home {
        push_modern_home_config_paths(&mut paths, &mut seen, home);
    }
    if let Some(sudo_home) = sudo_home {
        push_legacy_home_config_paths(&mut paths, &mut seen, sudo_home);
        push_modern_home_config_paths(&mut paths, &mut seen, sudo_home);
    }

    #[cfg(unix)]
    push_config_file_variants(&mut paths, &mut seen, Path::new("/etc/runnel"));

    paths
}

fn push_legacy_home_config_paths(
    paths: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
    home: &Path,
) {
    push_config_file_variants(paths, seen, &home.join(".runnel"));
}

fn push_modern_home_config_paths(
    paths: &mut Vec<PathBuf>,
    seen: &mut BTreeSet<PathBuf>,
    home: &Path,
) {
    push_config_file_variants(paths, seen, &home.join(".config").join("runnel"));

    #[cfg(target_os = "macos")]
    push_config_file_variants(
        paths,
        seen,
        &home
            .join("Library")
            .join("Application Support")
            .join("runnel"),
    );
}

fn push_config_file_variants(paths: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>, dir: &Path) {
    push_config_path(paths, seen, dir.join("config.yaml"));
    push_config_path(paths, seen, dir.join("config.yml"));
}

fn push_config_path(paths: &mut Vec<PathBuf>, seen: &mut BTreeSet<PathBuf>, path: PathBuf) {
    if seen.insert(path.clone()) {
        paths.push(path);
    }
}

#[cfg(unix)]
fn sudo_user_home_dir() -> Option<PathBuf> {
    use std::{
        ffi::{CStr, CString},
        mem::MaybeUninit,
        os::unix::ffi::OsStrExt,
        ptr,
    };

    let sudo_user = std::env::var_os("SUDO_USER")?;
    if sudo_user.as_os_str() == "root" {
        return None;
    }
    let sudo_user = CString::new(sudo_user.as_os_str().as_bytes()).ok()?;

    let initial_size = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let initial_size = if initial_size > 0 {
        initial_size as usize
    } else {
        16 * 1024
    };
    let mut buffer = vec![0u8; initial_size];

    loop {
        let mut passwd = MaybeUninit::<libc::passwd>::uninit();
        let mut result = ptr::null_mut();
        let rc = unsafe {
            libc::getpwnam_r(
                sudo_user.as_ptr(),
                passwd.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };

        if rc == libc::ERANGE {
            buffer.resize(buffer.len().saturating_mul(2), 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }

        let passwd = unsafe { passwd.assume_init() };
        if passwd.pw_dir.is_null() {
            return None;
        }

        return Some(PathBuf::from(
            unsafe { CStr::from_ptr(passwd.pw_dir) }
                .to_string_lossy()
                .into_owned(),
        ));
    }
}

#[cfg(not(unix))]
fn sudo_user_home_dir() -> Option<PathBuf> {
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).context("failed to parse CLI arguments")?;
    let log_file_from_cli_or_env = value_from_command_or_env(&matches, "log_file");
    let mut log_file_from_config = false;
    let config_path = cli.config.clone().or_else(discover_default_config_path);
    if let Some(config_path) = &config_path {
        if command_requires_strict_config(&cli.command) {
            let (file_config, base_dir) = config::load(config_path)?;
            log_file_from_config = !log_file_from_cli_or_env && file_config.log_file.is_some();
            config::apply_globals(
                &mut cli.log,
                &mut cli.log_file,
                &mut cli.log_timezone,
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
                        config::apply_client(args, &file_config, sub_matches, &base_dir)?;
                    }
                    (Commands::Server(args), "server") => {
                        config::apply_server(args, &file_config, sub_matches, &base_dir)?;
                    }
                    (Commands::Tun(args), "tun") => {
                        config::apply_tun(args, &file_config, sub_matches, &base_dir)?;
                    }
                    (Commands::WgClient(args), "wg-client") => {
                        config::apply_wg_client(args, &file_config, sub_matches, &base_dir)?;
                    }
                    (Commands::WgServer(args), "wg-server") => {
                        config::apply_wg_server(args, &file_config, sub_matches, &base_dir)?;
                    }
                    (Commands::Cert(args), "cert") => {
                        config::apply_cert(args, &file_config, sub_matches, &base_dir);
                    }
                    _ => {}
                }
            }
        } else {
            let (global_config, base_dir) = config::load_globals(config_path)?;
            log_file_from_config = !log_file_from_cli_or_env && global_config.log_file.is_some();
            config::apply_global_config(
                &mut cli.log,
                &mut cli.log_file,
                &mut cli.log_timezone,
                &mut cli.telemetry_sock,
                &mut cli.pid_file,
                &mut cli.tui,
                &mut cli.daemon,
                &global_config,
                &matches,
                &base_dir,
            );
            if let Some(("tui", sub_matches)) = matches.subcommand()
                && let Commands::Tui(args) = &mut cli.command
                && should_override(sub_matches, "attach")
                && args.attach.is_none()
            {
                args.attach = cli.telemetry_sock.clone();
            }
        }
    }
    normalize_cli_modes(&mut cli);
    let log_file_is_default = !log_file_from_cli_or_env && !log_file_from_config;
    if log_file_is_default {
        cli.log_file = default_log_file_for_command(&cli.command);
    }
    validate_daemon_mode(&cli)?;
    if cli.check_config_only {
        return Ok(());
    }
    if should_spawn_daemon(&cli) {
        spawn_daemon_process(&cli)?;
        return Ok(());
    }
    if let Commands::Stop(args) = &cli.command {
        stop_daemon_process(
            &cli.log_file,
            cli.pid_file.clone(),
            args.clone(),
            log_file_is_default,
        )
        .await?;
        return Ok(());
    }
    if let Commands::Reload(args) = &cli.command {
        reload_daemon_process(&cli, config_path, args.clone(), log_file_is_default).await?;
        return Ok(());
    }
    if let Commands::Switch(args) = &cli.command {
        switch_daemon_process(&cli, args.clone(), log_file_is_default).await?;
        return Ok(());
    }
    if let Commands::Status(args) = &cli.command {
        status_daemon_processes(
            &cli.log_file,
            cli.pid_file.clone(),
            cli.telemetry_sock.clone(),
            args.clone(),
            log_file_is_default,
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
    let observability = init_tracing(
        &cli.log,
        &cli.log_file,
        &cli.log_timezone,
        !cli.tui && !cli.daemon,
    )?;
    tun::set_embedded_tui(cli.tui);
    let _pid_file = maybe_create_pid_file(&cli, &observability.log_file)?;
    if let Some(context) = monitor_context(
        &cli,
        observability.log_file.clone(),
        observability.log_timezone_offset_secs,
    ) {
        telemetry::set_context(context);
        if cli.daemon || cli.telemetry_sock.is_some() {
            let socket = resolve_socket_for_service(&cli, &observability.log_file)?;
            telemetry::start_socket_server(socket).await?;
        }
    }
    let dashboard_context = dashboard_context(
        &cli,
        observability.log_file.clone(),
        observability.log_timezone_offset_secs,
    );

    let command = async move {
        match cli.command {
            Commands::Server(args) => server::run(args).await,
            Commands::Client(args) => client::run(args).await,
            Commands::Tun(args) => tun::run(args).await,
            Commands::WgClient(args) => wg::client::run(args).await,
            Commands::WgServer(args) => wg::server::run(args).await,
            Commands::WgConfig(args) => wg::configgen::run_config(args),
            Commands::WgKeygen(args) => wg::keys::run_keygen(args),
            Commands::Cert(args) => cert::run(args),
            Commands::Tui(_) => Ok(()),
            Commands::Stop(_) => Ok(()),
            Commands::Reload(_) => Ok(()),
            Commands::Switch(_) => Ok(()),
            Commands::Status(_) => Ok(()),
        }
    };
    let command = async move {
        let result = command.await;
        if let Err(error) = &result {
            error!(error = %format!("{error:#}"), "runnel command exited with error");
        }
        result
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
        Commands::Tui(_)
            | Commands::Stop(_)
            | Commands::Reload(_)
            | Commands::Switch(_)
            | Commands::Status(_)
    ) {
        cli.tui = false;
        cli.daemon = false;
        return;
    }

    if cli.daemon && cli.tui {
        eprintln!("runnel: disabling TUI because daemon mode runs in the background");
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
        | Commands::Cert(_)
        | Commands::Tui(_)
        | Commands::Stop(_)
        | Commands::Reload(_)
        | Commands::Switch(_)
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

    let mut child = command
        .spawn()
        .context("failed to start daemon process in background")?;
    if let Some(status) = wait_for_daemon_startup(&mut child)? {
        let mut message = format!("runnel daemon exited during startup with {status}");
        if let Ok(log_file) = absolute_path(&cli.log_file) {
            if log_file.exists() {
                message.push_str(&format!("\nlog: {}", log_file.display()));
                if let Ok(tail) = read_file_tail(&log_file, 20)
                    && !tail.trim().is_empty()
                {
                    message.push_str("\nrecent log lines:\n");
                    message.push_str(&tail);
                }
            } else {
                message.push_str(&format!(
                    "\nlog file was not created: {}",
                    log_file.display()
                ));
            }
        }
        anyhow::bail!("{message}");
    }
    if let Some(role) = command_role(&cli.command) {
        let pid_file = resolve_pid_file_for_role(&cli.log_file, cli.pid_file.clone(), role).ok();
        if let Some(pid_file) = pid_file {
            println!(
                "runnel daemon started pid={} pid_file={}",
                child.id(),
                pid_file.display()
            );
        } else {
            println!("runnel daemon started pid={}", child.id());
        }
    } else {
        println!("runnel daemon started pid={}", child.id());
    }
    Ok(())
}

fn wait_for_daemon_startup(
    child: &mut std::process::Child,
) -> Result<Option<std::process::ExitStatus>> {
    let deadline = Instant::now() + DAEMON_STARTUP_CHECK;
    loop {
        if let Some(status) = child
            .try_wait()
            .context("failed to inspect daemon startup status")?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(DAEMON_STARTUP_POLL);
    }
}

fn read_file_tail(path: &Path, max_lines: usize) -> Result<String> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut lines = contents.lines().rev().take(max_lines).collect::<Vec<_>>();
    lines.reverse();
    Ok(lines.join("\n"))
}

struct ObservabilityGuard {
    _file_guard: tracing_appender::non_blocking::WorkerGuard,
    log_file: PathBuf,
    log_timezone_offset_secs: i32,
}

#[derive(Debug, Clone, Copy)]
struct LogTimer {
    offset: UtcOffset,
}

impl FormatTime for LogTimer {
    fn format_time(&self, writer: &mut fmt::format::Writer<'_>) -> std::fmt::Result {
        let now = OffsetDateTime::now_utc().to_offset(self.offset);
        let formatted = now.format(&Rfc3339).map_err(|_| std::fmt::Error)?;
        writer.write_str(&formatted)
    }
}

fn log_timer(timezone: &str) -> Result<LogTimer> {
    Ok(LogTimer {
        offset: parse_log_timezone(timezone)?,
    })
}

fn parse_log_timezone(timezone: &str) -> Result<UtcOffset> {
    let value = timezone.trim();
    if value.is_empty() {
        anyhow::bail!("log timezone cannot be empty");
    }

    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "utc" | "z" | "gmt" => return Ok(UtcOffset::UTC),
        "local" => {
            return UtcOffset::current_local_offset().context(
                "failed to determine local timezone offset; use a fixed offset like +08:00",
            );
        }
        "asia/shanghai" | "shanghai" => return east_8_offset(),
        _ => {}
    }

    let fixed = lower
        .strip_prefix("utc")
        .or_else(|| lower.strip_prefix("gmt"))
        .unwrap_or(value);
    parse_fixed_log_offset(fixed)
}

fn east_8_offset() -> Result<UtcOffset> {
    UtcOffset::from_hms(8, 0, 0).context("failed to build +08:00 log timezone offset")
}

fn parse_fixed_log_offset(value: &str) -> Result<UtcOffset> {
    let (sign, digits) = match value.as_bytes().first() {
        Some(b'+') => (1_i8, &value[1..]),
        Some(b'-') => (-1_i8, &value[1..]),
        _ => anyhow::bail!(
            "unsupported log timezone `{value}`; expected utc, local, +08:00, or Asia/Shanghai"
        ),
    };

    let (hours, minutes, seconds) = if digits.contains(':') {
        parse_colon_log_offset(digits, value)?
    } else {
        parse_compact_log_offset(digits, value)?
    };

    if hours > 23 || minutes > 59 || seconds > 59 {
        anyhow::bail!("invalid log timezone `{value}`; offset must be within +/-23:59:59");
    }

    UtcOffset::from_hms(
        sign * hours as i8,
        sign * minutes as i8,
        sign * seconds as i8,
    )
    .with_context(|| format!("invalid log timezone offset `{value}`"))
}

fn parse_colon_log_offset(value: &str, original: &str) -> Result<(u8, u8, u8)> {
    let parts = value.split(':').collect::<Vec<_>>();
    match parts.as_slice() {
        [hours, minutes] => Ok((
            parse_log_offset_component(hours, "hours", original)?,
            parse_log_offset_component(minutes, "minutes", original)?,
            0,
        )),
        [hours, minutes, seconds] => Ok((
            parse_log_offset_component(hours, "hours", original)?,
            parse_log_offset_component(minutes, "minutes", original)?,
            parse_log_offset_component(seconds, "seconds", original)?,
        )),
        _ => anyhow::bail!("invalid log timezone `{original}`; expected +HH:MM or +HH:MM:SS"),
    }
}

fn parse_compact_log_offset(value: &str, original: &str) -> Result<(u8, u8, u8)> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("invalid log timezone `{original}`; expected +HH, +HHMM, or +HHMMSS");
    }

    match value.len() {
        1 | 2 => Ok((parse_log_offset_component(value, "hours", original)?, 0, 0)),
        4 => Ok((
            parse_log_offset_component(&value[..2], "hours", original)?,
            parse_log_offset_component(&value[2..], "minutes", original)?,
            0,
        )),
        6 => Ok((
            parse_log_offset_component(&value[..2], "hours", original)?,
            parse_log_offset_component(&value[2..4], "minutes", original)?,
            parse_log_offset_component(&value[4..], "seconds", original)?,
        )),
        _ => anyhow::bail!("invalid log timezone `{original}`; expected +HH, +HHMM, or +HHMMSS"),
    }
}

fn parse_log_offset_component(value: &str, label: &str, original: &str) -> Result<u8> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        anyhow::bail!("invalid {label} in log timezone `{original}`");
    }
    value
        .parse::<u8>()
        .with_context(|| format!("invalid {label} in log timezone `{original}`"))
}

fn init_tracing(
    default_filter: &str,
    log_file: &Path,
    log_timezone: &str,
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

    let file_appender = build_log_file_appender(&log_file)?;
    let (file_writer, file_guard) = tracing_appender::non_blocking(file_appender);
    let timer = log_timer(log_timezone)?;
    let log_timezone_offset_secs = timer.offset.whole_seconds();

    let file_layer = fmt::layer()
        .with_timer(timer)
        .with_target(false)
        .with_ansi(false)
        .compact()
        .with_writer(file_writer)
        .with_filter(filter_for_file);
    let stderr_layer = mirror_to_stderr.then(|| {
        fmt::layer()
            .with_timer(timer)
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
        log_timezone_offset_secs,
    })
}

fn build_log_file_appender(
    log_file: &Path,
) -> Result<tracing_appender::rolling::RollingFileAppender> {
    let directory = log_file
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let file_name = log_file
        .file_name()
        .and_then(|name| name.to_str())
        .context("log file path must end with a file name")?;

    tracing_appender::rolling::RollingFileAppender::builder()
        .rotation(tracing_appender::rolling::Rotation::NEVER)
        .filename_prefix(file_name)
        .build(&directory)
        .with_context(|| {
            format!(
                "failed to open log file {}; run with sudo or set --log-file to a writable path",
                log_file.display()
            )
        })
}

fn should_override(matches: &clap::ArgMatches, id: &str) -> bool {
    !matches.value_source(id).is_some_and(|source| {
        matches!(
            source,
            clap::parser::ValueSource::CommandLine | clap::parser::ValueSource::EnvVariable
        )
    })
}

fn value_from_command_or_env(matches: &clap::ArgMatches, id: &str) -> bool {
    matches.value_source(id).is_some_and(|source| {
        matches!(
            source,
            clap::parser::ValueSource::CommandLine | clap::parser::ValueSource::EnvVariable
        )
    })
}

fn run_utility_command(command: &Commands) -> Option<Result<()>> {
    match command {
        Commands::WgConfig(args) => Some(wg::configgen::run_config(args.clone())),
        Commands::WgKeygen(args) => Some(wg::keys::run_keygen(args.clone())),
        Commands::Cert(args) => Some(cert::run(args.clone())),
        _ => None,
    }
}

fn command_requires_strict_config(command: &Commands) -> bool {
    matches!(
        command,
        Commands::Server(_)
            | Commands::Client(_)
            | Commands::Tun(_)
            | Commands::WgClient(_)
            | Commands::WgServer(_)
            | Commands::Cert(_)
    )
}

#[cfg(test)]
mod tests {
    use super::{
        Cli, Commands, ReloadArgs, ServiceRole, StatusArgs, StopArgs, SwitchArgs, SwitchRole,
        build_log_file_appender, cli_daemon, cli_service, command_requires_strict_config,
        default_config_paths_for, first_existing_config_path, parse_log_timezone, read_file_tail,
        run_utility_command, wait_for_daemon_startup,
    };
    use clap::CommandFactory;
    use runnel::wg;
    use std::{
        ffi::OsString,
        fs,
        path::{Path, PathBuf},
        process::Command as ProcessCommand,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn default_config_paths_prefer_user_home_then_xdg_then_system() {
        let paths = default_config_paths_for(
            Some(Path::new("/home/alice")),
            Some(Path::new("/xdg")),
            Some(Path::new("/home/alice")),
        );

        assert_eq!(paths[0], PathBuf::from("/home/alice/.runnel/config.yaml"));
        assert_eq!(paths[1], PathBuf::from("/home/alice/.runnel/config.yml"));
        assert_eq!(paths[2], PathBuf::from("/xdg/runnel/config.yaml"));
        assert_eq!(paths[3], PathBuf::from("/xdg/runnel/config.yml"));
        assert!(paths.contains(&PathBuf::from("/home/alice/.config/runnel/config.yaml")));
        assert!(paths.contains(&PathBuf::from("/home/alice/.config/runnel/config.yml")));
        assert_eq!(
            paths
                .iter()
                .filter(|path| *path == &PathBuf::from("/home/alice/.runnel/config.yaml"))
                .count(),
            1
        );
        assert_eq!(
            paths
                .iter()
                .filter(|path| *path == &PathBuf::from("/home/alice/.runnel/config.yml"))
                .count(),
            1
        );
        #[cfg(unix)]
        assert!(paths.ends_with(&[
            PathBuf::from("/etc/runnel/config.yaml"),
            PathBuf::from("/etc/runnel/config.yml")
        ]));
    }

    #[test]
    fn first_existing_config_path_uses_first_existing_candidate() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "runnel-config-discovery-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.yaml");
        let first = dir.join("first.yaml");
        let second = dir.join("second.yaml");
        fs::write(&first, "log: debug\n").unwrap();
        fs::write(&second, "log: info\n").unwrap();

        assert_eq!(
            first_existing_config_path([missing, first.clone(), second]),
            Some(first)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn wait_for_daemon_startup_reports_early_exit() {
        let mut child = ProcessCommand::new("sh")
            .arg("-c")
            .arg("exit 7")
            .spawn()
            .unwrap();
        let status = wait_for_daemon_startup(&mut child)
            .unwrap()
            .expect("child should exit during startup check");
        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn read_file_tail_returns_last_lines() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "runnel-log-tail-{}-{suffix}.log",
            std::process::id()
        ));
        fs::write(&path, "one\ntwo\nthree\nfour\n").unwrap();

        assert_eq!(read_file_tail(&path, 2).unwrap(), "three\nfour");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn log_file_appender_reports_open_errors() {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "runnel-log-open-error-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();

        let error = build_log_file_appender(&path).unwrap_err();

        assert!(format!("{error:#}").contains("failed to open log file"));
        let _ = fs::remove_dir_all(path);
    }

    #[test]
    fn status_targets_default_to_all_roles() {
        let targets =
            cli_daemon::resolve_status_targets(Path::new("proxy.log"), None, None, None, false)
                .unwrap();
        let labels = targets
            .iter()
            .map(|target| target.label.as_str())
            .collect::<Vec<_>>();
        assert!(labels.contains(&"client"));
        assert!(labels.contains(&"server"));
        assert!(labels.contains(&"tun"));
        assert!(!labels.contains(&"wg-client"));
        assert!(!labels.contains(&"wg-server"));
    }

    #[test]
    fn service_commands_default_to_role_log_files() {
        assert_eq!(
            cli_service::default_log_file_for_role("client"),
            PathBuf::from("~/.runnel/logs/client.log")
        );
        assert_eq!(
            cli_service::default_log_file_for_role("server"),
            PathBuf::from("~/.runnel/logs/server.log")
        );
        assert_eq!(
            cli_service::default_log_file_for_command(&Commands::Status(StatusArgs {
                role: Some(ServiceRole::Client),
                json: false,
            })),
            PathBuf::from("~/.runnel/logs/client.log")
        );
    }

    #[test]
    fn log_timezone_defaults_to_local() {
        let command = Cli::command();
        let log_timezone = command
            .get_arguments()
            .find(|arg| arg.get_id() == "log_timezone")
            .expect("log timezone argument");
        let defaults = log_timezone
            .get_default_values()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(defaults, vec!["local"]);
    }

    #[test]
    fn log_timezone_accepts_common_values() {
        assert_eq!(parse_log_timezone("utc").unwrap(), time::UtcOffset::UTC);
        assert_eq!(
            parse_log_timezone("Asia/Shanghai").unwrap(),
            time::UtcOffset::from_hms(8, 0, 0).unwrap()
        );
        assert_eq!(
            parse_log_timezone("+08:00").unwrap(),
            time::UtcOffset::from_hms(8, 0, 0).unwrap()
        );
        assert_eq!(
            parse_log_timezone("UTC-0530").unwrap(),
            time::UtcOffset::from_hms(-5, -30, 0).unwrap()
        );
    }

    #[test]
    fn status_defaults_can_use_role_log_files() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };
        let server_pid_file = home.join(".runnel/current/server.pid");
        let server_socket = home.join(".runnel/current/server.sock");
        let targets =
            cli_daemon::resolve_status_targets(Path::new("ignored.log"), None, None, None, true)
                .unwrap();
        let server = targets
            .iter()
            .find(|target| target.label == "server")
            .expect("server target");

        assert!(
            server
                .pid_file
                .as_ref()
                .is_some_and(|path| path == &server_pid_file)
        );
        assert!(
            server
                .telemetry_socket
                .as_ref()
                .is_some_and(|path| path == &server_socket)
        );
    }

    #[test]
    fn default_pid_and_socket_paths_use_current_dir() {
        let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
            return;
        };

        assert_eq!(
            cli_service::default_pid_path(Path::new("/var/log/runnel/client.log"), "client")
                .unwrap(),
            home.join(".runnel/current/client.pid")
        );
        assert_eq!(
            cli_service::default_socket_path(Path::new("/var/log/runnel/client.log"), "client")
                .unwrap(),
            home.join(".runnel/current/client.sock")
        );
    }

    #[test]
    fn status_hides_not_running_services_by_default() {
        assert!(!cli_daemon::should_show_status_state("not-running", false));
        assert!(cli_daemon::should_show_status_state("running", false));
        assert!(cli_daemon::should_show_status_state("degraded", false));
        assert!(cli_daemon::should_show_status_state("stale", false));
        assert!(cli_daemon::should_show_status_state("not-running", true));
    }

    #[test]
    fn management_commands_use_lenient_global_config() {
        assert!(!command_requires_strict_config(&Commands::Stop(StopArgs {
            role: None,
            wait_secs: 10,
        })));
        assert!(!command_requires_strict_config(&Commands::Status(
            StatusArgs {
                role: None,
                json: false,
            }
        )));
        assert!(!command_requires_strict_config(&Commands::Reload(
            ReloadArgs {
                role: Some(ServiceRole::Client),
                wait_secs: 10,
            }
        )));
        assert!(!command_requires_strict_config(&Commands::Switch(
            SwitchArgs {
                role: Some(SwitchRole::Client),
                bypass: false,
                proxy: false,
            }
        )));
    }

    #[test]
    fn status_target_uses_role_specific_overrides() {
        let targets = cli_daemon::resolve_status_targets(
            Path::new("proxy.log"),
            Some(Path::new("custom.pid").to_path_buf()),
            Some(Path::new("custom.sock").to_path_buf()),
            Some(ServiceRole::Tun),
            false,
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
        let config = Commands::WgConfig(wg::configgen::WgConfigArgs {
            server_endpoint: "198.51.100.10:51820".to_owned(),
            client_tunnel_ip: "10.8.0.2".parse().unwrap(),
            server_tunnel_ip: "10.8.0.1".parse().unwrap(),
            mtu: 1420,
            persistent_keepalive_secs: 25,
            dns: None,
            dns_capture: false,
            direct_ips: Vec::new(),
            peer_allowed_ips: Vec::new(),
            nat_out_interface: None,
            json: false,
        });
        assert!(cli_service::command_role(&config).is_none());
        assert!(run_utility_command(&config).is_some_and(|result| result.is_ok()));

        let keygen = Commands::WgKeygen(wg::keys::WgKeygenArgs { json: false });
        assert!(cli_service::command_role(&keygen).is_none());
        assert!(run_utility_command(&keygen).is_some());
    }

    #[test]
    fn reload_start_args_restarts_selected_role_as_daemon() {
        let cli = Cli {
            log: "debug".to_owned(),
            log_file: PathBuf::from("runnel.log"),
            log_timezone: "Asia/Shanghai".to_owned(),
            telemetry_sock: Some(PathBuf::from("runnel.sock")),
            pid_file: Some(PathBuf::from("runnel.pid")),
            tui: false,
            daemon: false,
            check_config_only: false,
            config: Some(PathBuf::from("config.yaml")),
            command: Commands::Reload(ReloadArgs {
                role: Some(ServiceRole::WgClient),
                wait_secs: 10,
            }),
        };

        assert_eq!(
            cli_daemon::reload_start_args(
                &cli,
                Some(Path::new("config.yaml")),
                ServiceRole::WgClient,
                Path::new("runnel.log"),
            ),
            vec![
                OsString::from("--log"),
                OsString::from("debug"),
                OsString::from("--log-file"),
                OsString::from("runnel.log"),
                OsString::from("--log-timezone"),
                OsString::from("Asia/Shanghai"),
                OsString::from("--telemetry-sock"),
                OsString::from("runnel.sock"),
                OsString::from("--pid-file"),
                OsString::from("runnel.pid"),
                OsString::from("--config"),
                OsString::from("config.yaml"),
                OsString::from("--daemon"),
                OsString::from("wg-client"),
            ]
        );
    }

    #[test]
    fn reload_role_can_be_inferred_from_wg_pid_file() {
        assert_eq!(
            cli_daemon::role_from_pid_file(Path::new("server.pid")),
            Some(ServiceRole::Server)
        );
        assert_eq!(
            cli_daemon::role_from_pid_file(Path::new("proxy.wg-client.pid")),
            Some(ServiceRole::WgClient)
        );
        assert_eq!(
            cli_daemon::role_from_pid_file(Path::new("proxy.wg-server.pid")),
            Some(ServiceRole::WgServer)
        );
    }

    #[test]
    fn reload_requires_role_with_custom_pid_file() {
        let error = cli_daemon::resolve_reload_role(
            Path::new("proxy.log"),
            Some(PathBuf::from("custom.pid")),
            None,
            false,
        )
        .expect_err("custom pid reload needs explicit role");

        assert!(format!("{error:#}").contains("requires a role"));
    }

    #[test]
    fn reload_command_is_not_a_service_role() {
        let command = Commands::Reload(ReloadArgs {
            role: Some(ServiceRole::Client),
            wait_secs: 10,
        });

        assert!(cli_service::command_role(&command).is_none());
        assert!(run_utility_command(&command).is_none());
    }

    #[test]
    fn switch_command_is_not_a_service_role() {
        let args = SwitchArgs {
            role: Some(SwitchRole::Client),
            bypass: true,
            proxy: false,
        };
        assert_eq!(
            args.target(),
            runnel::telemetry::TrafficSwitchTarget::Bypass
        );

        let command = Commands::Switch(args);
        assert!(cli_service::command_role(&command).is_none());
        assert!(run_utility_command(&command).is_none());
    }

    #[test]
    fn status_state_is_running_when_pid_and_runtime_match() {
        let runtime = cli_daemon::RuntimeStatus {
            command: "client".to_owned(),
            mode: "native-http".to_owned(),
            traffic_state: runnel::telemetry::TrafficState::Proxying,
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
            cli_daemon::classify_service_state(true, true, Some(42), Some(true), Some(&runtime)),
            "running"
        );
    }

    #[test]
    fn status_state_is_degraded_when_runtime_disagrees_with_pid_file() {
        let runtime = cli_daemon::RuntimeStatus {
            command: "tun".to_owned(),
            mode: "native-http".to_owned(),
            traffic_state: runnel::telemetry::TrafficState::Proxying,
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
            cli_daemon::classify_service_state(true, true, Some(42), Some(true), Some(&runtime)),
            "degraded"
        );
    }

    #[test]
    fn status_state_is_stale_when_only_pid_file_remains() {
        assert_eq!(
            cli_daemon::classify_service_state(true, true, Some(42), Some(false), None),
            "stale"
        );
    }
}
