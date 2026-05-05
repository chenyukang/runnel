use anyhow::{Context, Result};
use runnel::telemetry;
use serde::Serialize;
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};
use tokio::time::sleep;

use super::{
    Cli, ReloadArgs, ServiceRole, StatusArgs, StopArgs, SwitchArgs,
    cli_service::{
        SERVICE_ROLES, absolute_path, command_role, default_log_file_for_role, default_pid_path,
        default_socket_path,
    },
};

#[derive(Debug, Clone)]
pub(super) struct StatusTarget {
    pub(super) label: String,
    pub(super) pid_file: Option<PathBuf>,
    pub(super) telemetry_socket: Option<PathBuf>,
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
pub(super) struct RuntimeStatus {
    pub(super) command: String,
    pub(super) mode: String,
    pub(super) traffic_state: telemetry::TrafficState,
    pub(super) pid: u32,
    pub(super) listen: Option<String>,
    pub(super) upstream: Option<String>,
    pub(super) path: Option<String>,
    pub(super) log_file: PathBuf,
    pub(super) log_filter: String,
    pub(super) uptime_secs: u64,
    pub(super) total_relays: u64,
    pub(super) total_errors: u64,
    pub(super) total_warnings: u64,
    pub(super) total_uploaded: u64,
    pub(super) total_downloaded: u64,
    pub(super) last_event_age_ms: Option<u64>,
    pub(super) last_warning_age_ms: Option<u64>,
    pub(super) last_traffic_age_ms: Option<u64>,
}

impl From<telemetry::DashboardSnapshot> for RuntimeStatus {
    fn from(snapshot: telemetry::DashboardSnapshot) -> Self {
        Self {
            command: snapshot.context.command_label,
            mode: snapshot.context.mode_label,
            traffic_state: snapshot.context.traffic_state,
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

pub(super) async fn status_daemon_processes(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    configured_socket: Option<PathBuf>,
    args: StatusArgs,
    use_role_default_log_files: bool,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (
            log_file,
            configured_pid_file,
            configured_socket,
            args,
            use_role_default_log_files,
        );
        anyhow::bail!("runnel status is only supported on unix platforms");
    }

    #[cfg(unix)]
    {
        let include_not_running =
            args.role.is_some() || configured_pid_file.is_some() || configured_socket.is_some();
        let targets = resolve_status_targets(
            log_file,
            configured_pid_file,
            configured_socket,
            args.role,
            use_role_default_log_files,
        )?;
        let mut services = Vec::with_capacity(targets.len());
        for target in targets {
            let service = inspect_status_target(target).await?;
            if should_show_status_state(&service.state, include_not_running) {
                services.push(service);
            }
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

pub(super) fn resolve_status_targets(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    configured_socket: Option<PathBuf>,
    role: Option<ServiceRole>,
    use_role_default_log_files: bool,
) -> Result<Vec<StatusTarget>> {
    if let Some(role) = role {
        let log_file = if use_role_default_log_files
            && configured_pid_file.is_none()
            && configured_socket.is_none()
        {
            default_log_file_for_role(role.as_str())
        } else {
            log_file.to_path_buf()
        };
        return Ok(vec![StatusTarget {
            label: role.as_str().to_owned(),
            pid_file: Some(match configured_pid_file {
                Some(path) => absolute_path(&path)?,
                None => default_pid_path(&log_file, role.as_str())?,
            }),
            telemetry_socket: Some(match configured_socket {
                Some(path) => absolute_path(&path)?,
                None => default_socket_path(&log_file, role.as_str())?,
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

    let defaults = SERVICE_ROLES
        .iter()
        .map(|role| {
            if use_role_default_log_files {
                default_status_target(&default_log_file_for_role(role), role)
            } else {
                default_status_target(log_file, role)
            }
        })
        .collect::<Result<Vec<_>>>()?;
    let discovered = discover_status_targets()?;
    Ok(merge_status_targets(defaults, discovered))
}

fn default_status_target(log_file: &Path, role: &str) -> Result<StatusTarget> {
    Ok(StatusTarget {
        label: role.to_owned(),
        pid_file: Some(default_pid_path(log_file, role)?),
        telemetry_socket: Some(default_socket_path(log_file, role)?),
    })
}

fn merge_status_targets(
    defaults: Vec<StatusTarget>,
    discovered: Vec<StatusTarget>,
) -> Vec<StatusTarget> {
    let active_discovered = discovered
        .into_iter()
        .filter(status_target_is_active)
        .collect::<Vec<_>>();

    let mut seen = BTreeSet::new();
    let mut merged = Vec::new();
    for default in defaults {
        let mut found_active = false;
        for target in active_discovered
            .iter()
            .filter(|target| target.label == default.label)
        {
            found_active = true;
            push_status_target_once(&mut merged, &mut seen, target.clone());
        }
        if !found_active {
            push_status_target_once(&mut merged, &mut seen, default);
        }
    }
    for target in active_discovered {
        push_status_target_once(&mut merged, &mut seen, target);
    }

    merged
}

fn push_status_target_once(
    targets: &mut Vec<StatusTarget>,
    seen: &mut BTreeSet<(String, Option<PathBuf>, Option<PathBuf>)>,
    target: StatusTarget,
) {
    let key = status_target_key(&target);
    if seen.insert(key) {
        targets.push(target);
    }
}

fn status_target_is_active(target: &StatusTarget) -> bool {
    status_target_has_live_pid(target) || status_target_has_connectable_socket(target)
}

fn status_target_has_live_pid(target: &StatusTarget) -> bool {
    let Some(path) = &target.pid_file else {
        return false;
    };
    let Ok(pid) = read_pid_file(path) else {
        return false;
    };
    process_exists(pid).unwrap_or(false)
}

#[cfg(unix)]
fn status_target_has_connectable_socket(target: &StatusTarget) -> bool {
    let Some(path) = &target.telemetry_socket else {
        return false;
    };
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn status_target_has_connectable_socket(_target: &StatusTarget) -> bool {
    false
}

fn status_target_key(target: &StatusTarget) -> (String, Option<PathBuf>, Option<PathBuf>) {
    (
        target.label.clone(),
        target.pid_file.clone(),
        target.telemetry_socket.clone(),
    )
}

fn discover_status_targets() -> Result<Vec<StatusTarget>> {
    let mut dirs = vec![
        std::env::current_dir().context("failed to read current directory")?,
        std::env::temp_dir(),
    ];
    #[cfg(unix)]
    dirs.push(PathBuf::from("/tmp"));

    let mut seen_dirs = BTreeSet::new();
    let mut seen_targets = BTreeSet::new();
    let mut targets = Vec::new();
    for dir in dirs {
        let dir = dir.canonicalize().unwrap_or(dir);
        if seen_dirs.insert(dir.clone()) {
            discover_status_targets_in_dir(&dir, &mut seen_targets, &mut targets)?;
        }
    }
    Ok(targets)
}

fn discover_status_targets_in_dir(
    dir: &Path,
    seen_targets: &mut BTreeSet<(String, PathBuf)>,
    targets: &mut Vec<StatusTarget>,
) -> Result<()> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(());
    };

    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read {}", dir.display()))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Some((stem, role, compact)) = parse_sidecar_file_name(file_name) else {
            continue;
        };
        let key = (role.to_owned(), dir.join(stem));
        if !seen_targets.insert(key) {
            continue;
        }

        let (pid_file, telemetry_socket) = if compact {
            (
                dir.join(format!("{stem}.pid")),
                dir.join(format!("{stem}.sock")),
            )
        } else {
            (
                dir.join(format!("{stem}.{role}.pid")),
                dir.join(format!("{stem}.{role}.sock")),
            )
        };
        targets.push(StatusTarget {
            label: role.to_owned(),
            pid_file: pid_file.exists().then_some(pid_file),
            telemetry_socket: telemetry_socket.exists().then_some(telemetry_socket),
        });
    }

    Ok(())
}

fn parse_sidecar_file_name(file_name: &str) -> Option<(&str, &'static str, bool)> {
    for role in SERVICE_ROLES {
        for ext in ["pid", "sock"] {
            let compact = format!("{role}.{ext}");
            if file_name == compact {
                return Some((role, *role, true));
            }

            let suffix = format!(".{role}.{ext}");
            if let Some(stem) = file_name.strip_suffix(&suffix) {
                return Some((stem, *role, false));
            }
        }
    }
    None
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

pub(super) fn classify_service_state(
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

pub(super) fn should_show_status_state(state: &str, include_not_running: bool) -> bool {
    include_not_running || state != "not-running"
}

fn print_status_report(report: &StatusReport) {
    if report.services.is_empty() {
        println!("no running services");
        return;
    }

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
            println!("  traffic_state: {}", runtime.traffic_state);
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

pub(super) fn resolve_pid_file_for_role(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: &str,
) -> Result<PathBuf> {
    if let Some(path) = configured_pid_file {
        return absolute_path(&path);
    }
    default_pid_path(log_file, role)
}

pub(super) fn maybe_create_pid_file(cli: &Cli, log_file: &Path) -> Result<Option<PidFileGuard>> {
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

    write_pid_file_exclusive(&path, std::process::id())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(Some(PidFileGuard { path }))
}

pub(super) async fn stop_daemon_process(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    args: StopArgs,
    use_role_default_log_files: bool,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (
            log_file,
            configured_pid_file,
            args,
            use_role_default_log_files,
        );
        anyhow::bail!("runnel stop is only supported on unix platforms");
    }

    #[cfg(unix)]
    {
        let pid_file = resolve_stop_pid_file(
            log_file,
            configured_pid_file,
            args.role,
            use_role_default_log_files,
        )?;
        let pid = read_pid_file(&pid_file)?;
        if !process_exists(pid)? {
            let _ = fs::remove_file(&pid_file);
            println!(
                "runnel daemon is not running (removed stale pid file {})",
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
                    "runnel daemon stopped pid={} pid_file={}",
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

pub(super) async fn reload_daemon_process(
    cli: &Cli,
    config_path: Option<PathBuf>,
    args: ReloadArgs,
    use_role_default_log_files: bool,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (cli, config_path, args, use_role_default_log_files);
        anyhow::bail!("runnel reload is only supported on unix platforms");
    }

    #[cfg(unix)]
    {
        let role = resolve_reload_role(
            &cli.log_file,
            cli.pid_file.clone(),
            args.role,
            use_role_default_log_files,
        )?;
        let log_file = if use_role_default_log_files && cli.pid_file.is_none() {
            default_log_file_for_role(role.as_str())
        } else {
            cli.log_file.clone()
        };
        check_reloaded_daemon_config(cli, config_path.as_deref(), role, &log_file)?;
        stop_daemon_process(
            &log_file,
            cli.pid_file.clone(),
            StopArgs {
                role: Some(role),
                wait_secs: args.wait_secs,
            },
            use_role_default_log_files,
        )
        .await?;
        start_reloaded_daemon(cli, config_path.as_deref(), role, &log_file)?;
        println!("runnel daemon reloaded role={}", role.as_str());
        Ok(())
    }
}

pub(super) async fn switch_daemon_process(
    cli: &Cli,
    args: SwitchArgs,
    use_role_default_log_files: bool,
) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = (cli, args, use_role_default_log_files);
        anyhow::bail!("runnel switch is only supported on unix platforms");
    }

    #[cfg(unix)]
    {
        let role = resolve_control_role(
            "switch",
            &cli.log_file,
            cli.pid_file.clone(),
            args.role.map(|role| role.service_role()),
            use_role_default_log_files,
        )?;
        let log_file = if use_role_default_log_files && cli.pid_file.is_none() {
            default_log_file_for_role(role.as_str())
        } else {
            cli.log_file.clone()
        };
        let socket = match &cli.telemetry_sock {
            Some(socket) => absolute_path(socket)?,
            None => default_socket_path(&log_file, role.as_str())?,
        };
        let response = telemetry::switch_socket(&socket, args.target()).await?;
        if !response.ok {
            anyhow::bail!("{}", response.message);
        }
        let previous_state = response
            .previous_state
            .map(|state| state.as_str())
            .unwrap_or("unknown");
        let state = response
            .state
            .map(|state| state.as_str())
            .unwrap_or("unknown");
        println!(
            "runnel traffic switched role={} {} -> {}",
            role.as_str(),
            previous_state,
            state
        );
        Ok(())
    }
}

pub(super) fn resolve_reload_role(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: Option<ServiceRole>,
    use_role_default_log_files: bool,
) -> Result<ServiceRole> {
    resolve_control_role(
        "reload",
        log_file,
        configured_pid_file,
        role,
        use_role_default_log_files,
    )
}

fn resolve_control_role(
    command: &str,
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: Option<ServiceRole>,
    use_role_default_log_files: bool,
) -> Result<ServiceRole> {
    if let Some(role) = role {
        return Ok(role);
    }

    if configured_pid_file.is_some() {
        anyhow::bail!("{command} requires a role when --pid-file is set");
    }

    let pid_file =
        resolve_pid_file_for_control(command, log_file, None, None, use_role_default_log_files)?;
    role_from_pid_file(&pid_file).with_context(|| {
        format!(
            "failed to infer daemon role from pid file {}; pass `{command} client`, `{command} server`, `{command} tun`, `{command} wg-client`, or `{command} wg-server`",
            pid_file.display()
        )
    })
}

fn start_reloaded_daemon(
    cli: &Cli,
    config_path: Option<&Path>,
    role: ServiceRole,
    log_file: &Path,
) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate current executable")?;
    let args = reload_start_args(cli, config_path, role, log_file);
    let status = Command::new(executable)
        .args(&args)
        .status()
        .context("failed to start reloaded daemon process")?;
    if !status.success() {
        anyhow::bail!("reloaded daemon startup command exited with {status}");
    }
    Ok(())
}

fn check_reloaded_daemon_config(
    cli: &Cli,
    config_path: Option<&Path>,
    role: ServiceRole,
    log_file: &Path,
) -> Result<()> {
    let executable = std::env::current_exe().context("failed to locate current executable")?;
    let args = reload_check_args(cli, config_path, role, log_file);
    let status = Command::new(executable)
        .args(&args)
        .status()
        .context("failed to check reloaded daemon configuration")?;
    if !status.success() {
        anyhow::bail!(
            "reloaded daemon configuration check exited with {status}; old daemon was not stopped"
        );
    }
    Ok(())
}

pub(super) fn reload_start_args(
    cli: &Cli,
    config_path: Option<&Path>,
    role: ServiceRole,
    log_file: &Path,
) -> Vec<OsString> {
    let mut args = reload_base_args(cli, config_path, log_file);
    args.push("--daemon".into());
    args.push(role.as_str().into());
    args
}

fn reload_check_args(
    cli: &Cli,
    config_path: Option<&Path>,
    role: ServiceRole,
    log_file: &Path,
) -> Vec<OsString> {
    let mut args = reload_base_args(cli, config_path, log_file);
    args.push("--check-config-only".into());
    args.push(role.as_str().into());
    args
}

fn reload_base_args(cli: &Cli, config_path: Option<&Path>, log_file: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec![
        "--log".into(),
        cli.log.clone().into(),
        "--log-file".into(),
        log_file.as_os_str().to_owned(),
        "--log-timezone".into(),
        cli.log_timezone.clone().into(),
    ];
    if let Some(path) = &cli.telemetry_sock {
        args.push("--telemetry-sock".into());
        args.push(path.as_os_str().to_owned());
    }
    if let Some(path) = &cli.pid_file {
        args.push("--pid-file".into());
        args.push(path.as_os_str().to_owned());
    }
    if let Some(path) = config_path {
        args.push("--config".into());
        args.push(path.as_os_str().to_owned());
    }
    args
}

pub(super) fn role_from_pid_file(path: &Path) -> Option<ServiceRole> {
    let file_name = path.file_name()?.to_str()?;
    for role in [
        ServiceRole::Client,
        ServiceRole::Server,
        ServiceRole::Tun,
        ServiceRole::WgClient,
        ServiceRole::WgServer,
    ] {
        if file_name == format!("{}.pid", role.as_str())
            || file_name.ends_with(&format!(".{}.pid", role.as_str()))
        {
            return Some(role);
        }
    }
    None
}

fn resolve_stop_pid_file(
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: Option<ServiceRole>,
    use_role_default_log_files: bool,
) -> Result<PathBuf> {
    resolve_pid_file_for_control(
        "stop",
        log_file,
        configured_pid_file,
        role,
        use_role_default_log_files,
    )
}

fn resolve_pid_file_for_control(
    command: &str,
    log_file: &Path,
    configured_pid_file: Option<PathBuf>,
    role: Option<ServiceRole>,
    use_role_default_log_files: bool,
) -> Result<PathBuf> {
    if let Some(path) = configured_pid_file {
        return absolute_path(&path);
    }
    if let Some(role) = role {
        let log_file = if use_role_default_log_files {
            default_log_file_for_role(role.as_str())
        } else {
            log_file.to_path_buf()
        };
        return default_pid_path(&log_file, role.as_str());
    }

    let client =
        default_pid_path_for_role_or_log_file(log_file, "client", use_role_default_log_files)?;
    let server =
        default_pid_path_for_role_or_log_file(log_file, "server", use_role_default_log_files)?;
    let tun = default_pid_path_for_role_or_log_file(log_file, "tun", use_role_default_log_files)?;
    let wg_client =
        default_pid_path_for_role_or_log_file(log_file, "wg-client", use_role_default_log_files)?;
    let wg_server =
        default_pid_path_for_role_or_log_file(log_file, "wg-server", use_role_default_log_files)?;
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
            "no pid file found; pass `{command} client`, `{command} server`, `{command} tun`, `{command} wg-client`, `{command} wg-server`, or `--pid-file`"
        ),
        1 => Ok(found.remove(0)),
        _ => anyhow::bail!(
            "multiple pid files exist; pass `{command} client`, `{command} server`, `{command} tun`, `{command} wg-client`, `{command} wg-server`, or `--pid-file`"
        ),
    }
}

fn default_pid_path_for_role_or_log_file(
    log_file: &Path,
    role: &str,
    use_role_default_log_files: bool,
) -> Result<PathBuf> {
    if use_role_default_log_files {
        default_pid_path(&default_log_file_for_role(role), role)
    } else {
        default_pid_path(log_file, role)
    }
}

fn read_pid_file(path: &Path) -> Result<u32> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read pid file {}", path.display()))?;
    raw.trim()
        .parse::<u32>()
        .with_context(|| format!("invalid pid in {}", path.display()))
}

fn write_pid_file_exclusive(path: &Path, pid: u32) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("failed to create pid file {}", path.display()))?;
    file.write_all(format!("{pid}\n").as_bytes())
        .with_context(|| format!("failed to write pid file {}", path.display()))?;
    file.flush()
        .with_context(|| format!("failed to flush pid file {}", path.display()))?;
    Ok(())
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

pub(super) struct PidFileGuard {
    path: PathBuf,
}

impl Drop for PidFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "runnel-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    #[test]
    fn pid_file_is_created_exclusively() {
        let dir = temp_dir("pid-exclusive");
        let path = dir.join("runnel.pid");

        write_pid_file_exclusive(&path, 1234).expect("pid file should be created");
        assert_eq!(read_pid_file(&path).unwrap(), 1234);
        assert!(
            write_pid_file_exclusive(&path, 5678).is_err(),
            "existing pid file must not be truncated"
        );
        assert_eq!(read_pid_file(&path).unwrap(), 1234);

        let _ = fs::remove_file(&path);
        let _ = fs::remove_dir(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn pid_file_creation_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let dir = temp_dir("pid-symlink");
        let target = dir.join("target.txt");
        let path = dir.join("runnel.pid");
        fs::write(&target, "keep me\n").expect("target file");
        symlink(&target, &path).expect("pid symlink");

        assert!(
            write_pid_file_exclusive(&path, 1234).is_err(),
            "pid file creation must not follow symlinks"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "keep me\n");

        let _ = fs::remove_file(&path);
        let _ = fs::remove_file(&target);
        let _ = fs::remove_dir(&dir);
    }
}
