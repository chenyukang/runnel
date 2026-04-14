use std::{
    collections::BTreeMap,
    fs,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{TcpStream, lookup_host},
    process::{Child, Command},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{debug, error, info, warn};

use crate::{
    client::{self, ClientArgs},
    route::FilterMode,
    tls,
};

#[cfg(test)]
const TEST_SERVER_ENDPOINT: &str = "198.51.100.10:1443";
#[cfg(test)]
const TEST_SERVER_HOST: &str = "198.51.100.10";
#[cfg(test)]
const TEST_SERVER_IP: &str = "198.51.100.10";

const MACOS_TUN_GATEWAY_V4: &str = "198.18.0.1";
const AUTO_TUN_DEVICE: &str = "auto";
static EMBEDDED_TUI_ACTIVE: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "macos")]
const MACOS_AUTO_TUN_START_INDEX: u16 = 233;
#[cfg(not(target_os = "macos"))]
const DEFAULT_AUTO_TUN_DEVICE: &str = "tun0";
const MACOS_TUN_ROUTE_SET: &[&str] = &[
    "1.0.0.0/8",
    "2.0.0.0/7",
    "4.0.0.0/6",
    "8.0.0.0/5",
    "16.0.0.0/4",
    "32.0.0.0/3",
    "64.0.0.0/2",
    "128.0.0.0/1",
    "198.18.0.0/15",
];

#[derive(Clone, Debug, Args)]
pub struct TunArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[arg(long, default_value = AUTO_TUN_DEVICE)]
    pub device: String,
    #[arg(long, default_value = "/bin/sh")]
    pub shell: String,
    #[arg(long, default_value = "")]
    pub helper_cmd: String,
    #[arg(long, default_value_t = 800)]
    pub helper_ready_delay_ms: u64,
    #[arg(long)]
    pub up: Vec<String>,
    #[arg(long)]
    pub down: Vec<String>,
    #[arg(long)]
    pub print_hooks: bool,
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Deserialize)]
struct HelperLogLine {
    level: Option<String>,
    caller: Option<String>,
    msg: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct TunState {
    pid: u32,
    helper_pid: Option<u32>,
    shell: String,
    down_hooks: Vec<String>,
}

struct TunStateGuard {
    path: PathBuf,
    state: TunState,
}

#[derive(Clone, Debug)]
enum TunHelperConfig {
    EmbeddedTun2Proxy,
    ExternalCommand(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TunHelperFlavor {
    Tun2Proxy,
    Tun2Socks,
}

#[derive(Clone, Debug)]
struct TunHelperBinary {
    path: PathBuf,
    flavor: TunHelperFlavor,
}

enum RunningTunHelper {
    Embedded {
        task: JoinHandle<Result<()>>,
        shutdown_token: tun2proxy::CancellationToken,
    },
    External(Child),
}

pub fn set_embedded_tui(active: bool) {
    EMBEDDED_TUI_ACTIVE.store(active, Ordering::Relaxed);
}

impl TunHelperConfig {
    fn describe(&self, context: &CommandContext) -> String {
        match self {
            Self::EmbeddedTun2Proxy => format!(
                "embedded tun2proxy crate --tun {} --proxy socks5://{} --dns direct --verbosity warn --exit-on-fatal-error",
                context.device, context.socks_listen
            ),
            Self::ExternalCommand(template) => context.expand(template),
        }
    }
}

impl TunHelperBinary {
    fn default_command(&self, context: &CommandContext) -> String {
        match self.flavor {
            TunHelperFlavor::Tun2Proxy => format!(
                "{} --tun {{device}} --proxy socks5://{{socks}} --dns direct --verbosity warn --exit-on-fatal-error",
                shell_quote_path(&self.path)
            ),
            TunHelperFlavor::Tun2Socks => {
                let mut command = format!(
                    "{} -device {{device}} -proxy socks5://{{socks}} -loglevel info -tcp-auto-tuning",
                    shell_quote_path(&self.path)
                );
                if let Some(interface) = &context.egress_interface {
                    command.push_str(&format!(" -interface {interface}"));
                }
                command
            }
        }
    }
}

impl RunningTunHelper {
    fn id(&self) -> Option<u32> {
        match self {
            Self::Embedded { .. } => None,
            Self::External(child) => child.id(),
        }
    }
}

impl TunStateGuard {
    async fn acquire(shell: &str, context: &CommandContext, down_hooks: &[String]) -> Result<Self> {
        let path = resolve_tun_state_path(context)?;
        let guard = Self {
            path,
            state: TunState {
                pid: std::process::id(),
                helper_pid: None,
                shell: shell.to_owned(),
                down_hooks: down_hooks.iter().map(|hook| context.expand(hook)).collect(),
            },
        };

        for _ in 0..2 {
            match guard.persist(true) {
                Ok(()) => return Ok(guard),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    match load_tun_state(&guard.path)? {
                        Some(existing) if process_alive(existing.pid) => {
                            bail!(
                                "another pipit tun is already running (pid {}); stop it before starting a new tun session",
                                existing.pid
                            );
                        }
                        Some(existing) => {
                            cleanup_stale_tun_state(&guard.path, &existing).await?;
                        }
                        None => {
                            warn!(
                                path = %guard.path.display(),
                                "found an unreadable tun state file; removing it before retrying"
                            );
                        }
                    }
                    let _ = fs::remove_file(&guard.path);
                }
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("failed to create tun state {}", guard.path.display())
                    });
                }
            }
        }

        guard
            .persist(true)
            .with_context(|| format!("failed to create tun state {}", guard.path.display()))?;
        Ok(guard)
    }

    fn update_helper_pid(&mut self, helper_pid: Option<u32>) -> Result<()> {
        self.state.helper_pid = helper_pid;
        self.persist(false)
            .with_context(|| format!("failed to update tun state {}", self.path.display()))?;
        Ok(())
    }

    fn clear(&self) {
        let _ = fs::remove_file(&self.path);
    }

    fn persist(&self, create_new: bool) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).truncate(true);
        if create_new {
            options.create_new(true);
        } else {
            options.create(true);
        }
        let mut file = options.open(&self.path)?;
        serde_json::to_writer_pretty(&mut file, &self.state).map_err(std::io::Error::other)?;
        file.write_all(b"\n")?;
        file.flush()?;
        Ok(())
    }
}

impl Drop for TunStateGuard {
    fn drop(&mut self) {
        self.clear();
    }
}

pub async fn run(mut args: TunArgs) -> Result<()> {
    normalize_client_args_for_tun(&mut args.client);
    args.validate_required()?;
    let context = CommandContext::from_args(&args).await?;
    let helper = effective_helper(&args, &context)?;
    let up_hooks = effective_up_hooks(&args, &context)?;
    let down_hooks = effective_down_hooks(&args, &context)?;
    if args.print_hooks || args.dry_run {
        let plan_lines = plan_lines(&args, &context, &helper, &up_hooks, &down_hooks);
        if EMBEDDED_TUI_ACTIVE.load(Ordering::Relaxed) {
            log_plan_lines(&plan_lines);
        } else {
            print_plan(&plan_lines);
        }
    }
    if args.dry_run {
        info!("tun dry-run completed without changing network settings");
        return Ok(());
    }
    let mut tun_state = TunStateGuard::acquire(&args.shell, &context, &down_hooks).await?;
    let mut client_task = tokio::spawn(client::run_embedded(args.client.clone()));
    wait_for_listener(&args.client.listen, Duration::from_secs(5)).await?;
    ensure_device_available(&context.device).await?;

    let mut helper_handle = spawn_tun_helper(&args.shell, &helper, &context)?;
    tun_state.update_helper_pid(helper_handle.id())?;
    info!(
        device = %context.device,
        socks = %args.client.listen,
        server = %args.client.server,
        server_ip = %context.server_ip,
        egress_interface = context.egress_interface.as_deref().unwrap_or("-"),
        egress_gateway = context.egress_gateway.as_deref().unwrap_or("-"),
        helper = %helper.describe(&context),
        "tun helper started"
    );

    sleep(Duration::from_millis(args.helper_ready_delay_ms)).await;
    if let Err(err) =
        ensure_helper_alive(&mut helper_handle, &context.device, "before up hooks").await
    {
        abort_client_task(&mut client_task).await;
        tun_state.clear();
        return Err(err);
    }
    if let Err(err) = run_hooks("up hook", &args.shell, &up_hooks, &context).await {
        shutdown(
            &args.shell,
            &down_hooks,
            &context,
            &mut helper_handle,
            &mut client_task,
        )
        .await;
        tun_state.clear();
        return Err(err);
    }
    if let Err(err) =
        ensure_helper_alive(&mut helper_handle, &context.device, "after up hooks").await
    {
        shutdown(
            &args.shell,
            &down_hooks,
            &context,
            &mut helper_handle,
            &mut client_task,
        )
        .await;
        tun_state.clear();
        return Err(err);
    }

    let result = tokio::select! {
        result = &mut client_task => join_client(result),
        helper_result = wait_for_tun_helper(&mut helper_handle) => helper_result,
        signal = wait_for_shutdown_signal() => {
            signal?;
            Ok(())
        }
    };

    match &result {
        Ok(()) => info!("tun session ending"),
        Err(err) => warn!(error = %err, "tun session ending with error"),
    }

    shutdown(
        &args.shell,
        &down_hooks,
        &context,
        &mut helper_handle,
        &mut client_task,
    )
    .await;
    tun_state.clear();
    result
}

fn normalize_client_args_for_tun(args: &mut ClientArgs) {
    if !matches!(args.filter, FilterMode::Proxy) {
        warn!(
            requested_filter = ?args.filter,
            "tun mode currently forces client filter=proxy; direct/rule routing can loop traffic back into the TUN device"
        );
        args.filter = FilterMode::Proxy;
        args.rule_file = None;
        args.cidr_file = None;
    }
}

impl TunArgs {
    pub fn validate_required(&self) -> Result<()> {
        self.client.validate_required()?;
        Ok(())
    }
}

#[derive(Clone)]
struct CommandContext {
    device: String,
    socks_listen: String,
    server: String,
    server_host: String,
    server_port: u16,
    server_ip: String,
    egress_interface: Option<String>,
    egress_gateway: Option<String>,
    log_file: Option<String>,
}

impl CommandContext {
    async fn from_args(args: &TunArgs) -> Result<Self> {
        let (server_host, server_port) = tls::split_host_port(&args.client.server)?;
        let device = resolve_device_name(&args.device).await?;
        let server_ip = resolve_server_ip(&server_host, server_port).await?;
        let needs_egress_metadata = needs_egress_metadata(args);
        let (egress_interface, egress_gateway) = if needs_egress_metadata {
            detect_egress_route(&server_ip).await?
        } else {
            (None, None)
        };

        Ok(Self {
            device,
            socks_listen: args.client.listen.clone(),
            server: args.client.server.clone(),
            server_host,
            server_port,
            server_ip,
            egress_interface,
            egress_gateway,
            log_file: std::env::var("PIPIT_LOG_FILE").ok(),
        })
    }

    fn expand(&self, template: &str) -> String {
        template
            .replace("{device}", &self.device)
            .replace("{socks}", &self.socks_listen)
            .replace("{socks_listen}", &self.socks_listen)
            .replace("{server}", &self.server)
            .replace("{server_host}", &self.server_host)
            .replace("{server_port}", &self.server_port.to_string())
            .replace("{server_ip}", &self.server_ip)
            .replace(
                "{egress_interface}",
                self.egress_interface.as_deref().unwrap_or(""),
            )
            .replace(
                "{egress_gateway}",
                self.egress_gateway.as_deref().unwrap_or(""),
            )
            .replace(
                "{log_file}",
                self.log_file.as_deref().unwrap_or("proxy.log"),
            )
    }

    fn apply_envs(&self, command: &mut Command) {
        command.env("PIPIT_TUN_DEVICE", &self.device);
        command.env("PIPIT_SOCKS_LISTEN", &self.socks_listen);
        command.env("PIPIT_SERVER", &self.server);
        command.env("PIPIT_SERVER_HOST", &self.server_host);
        command.env("PIPIT_SERVER_PORT", self.server_port.to_string());
        command.env("PIPIT_SERVER_IP", &self.server_ip);
        if let Some(interface) = &self.egress_interface {
            command.env("PIPIT_EGRESS_INTERFACE", interface);
        }
        if let Some(gateway) = &self.egress_gateway {
            command.env("PIPIT_EGRESS_GATEWAY", gateway);
        }
        if let Some(log_file) = &self.log_file {
            command.env("PIPIT_LOG_FILE", log_file);
        }
    }
}

fn needs_egress_metadata(args: &TunArgs) -> bool {
    let helper_override =
        !args.helper_cmd.trim().is_empty() || std::env::var_os("PIPIT_TUN_HELPER").is_some();
    (helper_override
        && (args.helper_cmd.trim().is_empty() || needs_placeholder(&args.helper_cmd, "{egress_")))
        || args
            .up
            .iter()
            .any(|hook| needs_placeholder(hook, "{egress_"))
        || args
            .down
            .iter()
            .any(|hook| needs_placeholder(hook, "{egress_"))
        || cfg!(target_os = "macos") && (args.up.is_empty() || args.down.is_empty())
}

fn needs_placeholder(template: &str, prefix: &str) -> bool {
    template.contains(prefix)
}

fn effective_helper(args: &TunArgs, context: &CommandContext) -> Result<TunHelperConfig> {
    if !args.helper_cmd.trim().is_empty() {
        return Ok(TunHelperConfig::ExternalCommand(args.helper_cmd.clone()));
    }

    default_helper(context)
}

fn effective_up_hooks(args: &TunArgs, context: &CommandContext) -> Result<Vec<String>> {
    if !args.up.is_empty() {
        return Ok(args.up.clone());
    }

    default_up_hooks(context)
}

fn effective_down_hooks(args: &TunArgs, context: &CommandContext) -> Result<Vec<String>> {
    if !args.down.is_empty() {
        return Ok(args.down.clone());
    }

    default_down_hooks(context)
}

fn default_helper(context: &CommandContext) -> Result<TunHelperConfig> {
    if let Some(helper) = detect_helper_override() {
        return Ok(TunHelperConfig::ExternalCommand(
            helper.default_command(context),
        ));
    }

    Ok(TunHelperConfig::EmbeddedTun2Proxy)
}

fn default_up_hooks(context: &CommandContext) -> Result<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        ensure_default_macos_server_route(context)?;
        let mut hooks = vec![format!(
            "ifconfig {{device}} inet {gateway} {gateway} up",
            gateway = MACOS_TUN_GATEWAY_V4
        )];
        hooks.push(default_server_bypass_route(context));
        hooks.extend(
            MACOS_TUN_ROUTE_SET
                .iter()
                .map(|cidr| {
                    format!(
                        "route -q -n add -net {cidr} {MACOS_TUN_GATEWAY_V4} >/dev/null 2>&1 || route -q -n change -net {cidr} {MACOS_TUN_GATEWAY_V4}"
                    )
                }),
        );
        return Ok(hooks);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = context;
        Ok(Vec::new())
    }
}

fn default_down_hooks(context: &CommandContext) -> Result<Vec<String>> {
    #[cfg(target_os = "macos")]
    {
        ensure_default_macos_server_route(context)?;
        let mut hooks: Vec<String> = MACOS_TUN_ROUTE_SET
            .iter()
            .rev()
            .map(|cidr| format!("route -q -n delete -net {cidr} >/dev/null 2>&1 || true"))
            .collect();
        hooks.push("route -q -n delete -host {server_ip} >/dev/null 2>&1 || true".to_owned());
        hooks.push("ifconfig {device} down >/dev/null 2>&1 || true".to_owned());
        return Ok(hooks);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = context;
        Ok(Vec::new())
    }
}

#[cfg(target_os = "macos")]
fn ensure_default_macos_server_route(context: &CommandContext) -> Result<()> {
    if context
        .server_ip
        .parse::<IpAddr>()
        .is_ok_and(|ip| ip.is_ipv6())
    {
        bail!(
            "default macOS tun hooks currently support IPv4 server endpoints only; set tun.up/down explicitly for IPv6 upstreams"
        );
    }
    if context.egress_interface.is_none() {
        bail!(
            "failed to determine the outbound interface for {}; set tun.helper_cmd and tun.up/down explicitly",
            context.server_ip
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn default_server_bypass_route(context: &CommandContext) -> String {
    match &context.egress_gateway {
        Some(gateway) if !gateway.is_empty() => format!(
            "route -q -n add -host {{server_ip}} {gateway} >/dev/null 2>&1 || route -q -n change -host {{server_ip}} {gateway}"
        ),
        _ => "route -q -n add -host {server_ip} -interface {egress_interface} >/dev/null 2>&1 || route -q -n change -host {server_ip} -interface {egress_interface}".to_owned(),
    }
}

#[cfg(not(target_os = "macos"))]
fn ensure_default_macos_server_route(_context: &CommandContext) -> Result<()> {
    Ok(())
}

fn detect_helper_override() -> Option<TunHelperBinary> {
    if let Some(path) = std::env::var_os("PIPIT_TUN_HELPER") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(TunHelperBinary {
                flavor: detect_tun_helper_flavor(&candidate),
                path: candidate,
            });
        }
    }

    None
}

fn detect_tun_helper_flavor(path: &Path) -> TunHelperFlavor {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("tun2socks") {
        TunHelperFlavor::Tun2Socks
    } else {
        TunHelperFlavor::Tun2Proxy
    }
}

fn resolve_tun_state_path(context: &CommandContext) -> Result<PathBuf> {
    let log_file = context.log_file.as_deref().unwrap_or("proxy.log");
    let log_path = PathBuf::from(log_file);
    let absolute = if log_path.is_absolute() {
        log_path
    } else {
        std::env::current_dir()
            .context("failed to read current directory for tun state path")?
            .join(log_path)
    };
    let parent = absolute
        .parent()
        .context("log file path did not have a parent directory")?;
    let stem = absolute
        .file_stem()
        .and_then(|value| value.to_str())
        .context("log file path did not have a valid stem")?;
    Ok(parent.join(format!("{stem}.tun.state.json")))
}

fn load_tun_state(path: &Path) -> Result<Option<TunState>> {
    match fs::read_to_string(path) {
        Ok(contents) => serde_json::from_str(&contents)
            .map(Some)
            .with_context(|| format!("failed to parse tun state {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("failed to read tun state {}", path.display()))
        }
    }
}

async fn cleanup_stale_tun_state(path: &Path, state: &TunState) -> Result<()> {
    info!(
        path = %path.display(),
        pid = state.pid,
        helper_pid = state.helper_pid.unwrap_or_default(),
        "detected stale tun state; attempting cleanup before startup"
    );
    if let Some(helper_pid) = state.helper_pid {
        terminate_process_group(helper_pid, "stale tun helper").await;
    }
    run_expanded_hooks("stale down hook", &state.shell, &state.down_hooks).await?;
    Ok(())
}

async fn run_expanded_hooks(label: &str, shell: &str, hooks: &[String]) -> Result<()> {
    for hook in hooks {
        info!(hook = %hook, "{label} starting");
        let status = Command::new(shell)
            .arg("-lc")
            .arg(hook)
            .status()
            .await
            .with_context(|| format!("failed to run {label}: {hook}"))?;
        if !status.success() {
            bail!("{label} failed with status {status}: {hook}");
        }
    }
    Ok(())
}

#[cfg(unix)]
fn process_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as i32, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(not(unix))]
fn process_alive(_pid: u32) -> bool {
    false
}

#[cfg(unix)]
async fn terminate_process_group(pgid: u32, label: &str) {
    let target = -(pgid as i32);
    let rc = unsafe { libc::kill(target, 0) };
    if rc != 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
        return;
    }

    info!(pgid, "{label} stopping");
    let _ = unsafe { libc::kill(target, libc::SIGTERM) };
    sleep(Duration::from_millis(300)).await;

    let rc = unsafe { libc::kill(target, 0) };
    if rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) {
        warn!(pgid, "{label} did not exit after SIGTERM; sending SIGKILL");
        let _ = unsafe { libc::kill(target, libc::SIGKILL) };
        sleep(Duration::from_millis(150)).await;
    }
}

#[cfg(not(unix))]
async fn terminate_process_group(_pgid: u32, _label: &str) {}

fn is_auto_device(device: &str) -> bool {
    let requested = device.trim();
    requested.is_empty() || requested.eq_ignore_ascii_case(AUTO_TUN_DEVICE)
}

async fn resolve_device_name(requested: &str) -> Result<String> {
    if !is_auto_device(requested) {
        return Ok(requested.trim().to_owned());
    }

    #[cfg(target_os = "macos")]
    {
        return pick_available_macos_utun().await;
    }

    #[cfg(not(target_os = "macos"))]
    {
        Ok(DEFAULT_AUTO_TUN_DEVICE.to_owned())
    }
}

#[cfg(target_os = "macos")]
async fn pick_available_macos_utun() -> Result<String> {
    let output = Command::new("ifconfig")
        .arg("-l")
        .output()
        .await
        .context("failed to list network interfaces for automatic TUN selection")?;
    if !output.status.success() {
        bail!(
            "failed to list network interfaces for automatic TUN selection: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let interfaces = String::from_utf8_lossy(&output.stdout);
    let in_use: std::collections::HashSet<&str> = interfaces.split_whitespace().collect();
    for index in MACOS_AUTO_TUN_START_INDEX..u16::MAX {
        let candidate = format!("utun{index}");
        if !in_use.contains(candidate.as_str()) {
            return Ok(candidate);
        }
    }

    bail!(
        "failed to find a free utun device starting at utun{}",
        MACOS_AUTO_TUN_START_INDEX
    );
}

async fn ensure_device_available(device: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        let status = Command::new("ifconfig")
            .arg(device)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .with_context(|| format!("failed to inspect TUN device {device}"))?;
        if status.success() {
            bail!(
                "TUN device {device} is already in use; choose a different --device or stop the other VPN/tun helper first"
            );
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = device;
    }

    Ok(())
}

fn shell_quote_path(path: &Path) -> String {
    shell_quote(&path.to_string_lossy())
}

fn shell_quote(input: &str) -> String {
    format!("'{}'", input.replace('\'', "'\\''"))
}

async fn resolve_server_ip(host: &str, port: u16) -> Result<String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }

    let resolved: Vec<_> = lookup_host((host, port))
        .await
        .with_context(|| format!("failed to resolve {host}:{port} for tun mode"))?
        .collect();
    let chosen = resolved
        .iter()
        .find(|addr| addr.is_ipv4())
        .or_else(|| resolved.first())
        .context("tun mode resolved no usable server addresses")?;
    Ok(chosen.ip().to_string())
}

async fn detect_egress_route(server_ip: &str) -> Result<(Option<String>, Option<String>)> {
    #[cfg(target_os = "macos")]
    {
        let route = detect_macos_route(server_ip).await?;
        if should_fallback_to_default_egress(&route) {
            let default_route = detect_macos_route("default").await?;
            if default_route
                .0
                .as_deref()
                .is_some_and(|interface| !interface.starts_with("utun"))
            {
                warn!(
                    server_ip,
                    route_interface = route.0.as_deref().unwrap_or("-"),
                    route_gateway = route.1.as_deref().unwrap_or("-"),
                    default_interface = default_route.0.as_deref().unwrap_or("-"),
                    default_gateway = default_route.1.as_deref().unwrap_or("-"),
                    "route to upstream currently points at a utun interface; falling back to the default egress route",
                );
                return Ok(default_route);
            }
        }
        return Ok(route);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = server_ip;
        Ok((None, None))
    }
}

#[cfg(target_os = "macos")]
async fn detect_macos_route(target: &str) -> Result<(Option<String>, Option<String>)> {
    let output = Command::new("route")
        .arg("-n")
        .arg("get")
        .arg(target)
        .output()
        .await
        .with_context(|| format!("failed to inspect route to {target}"))?;
    if !output.status.success() {
        bail!(
            "failed to inspect route to {target}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_macos_route_get(&stdout)
}

#[cfg(target_os = "macos")]
fn should_fallback_to_default_egress(route: &(Option<String>, Option<String>)) -> bool {
    route
        .0
        .as_deref()
        .is_some_and(|interface| interface.starts_with("utun"))
        || route.1.as_deref() == Some(MACOS_TUN_GATEWAY_V4)
}

#[cfg(target_os = "macos")]
fn parse_macos_route_get(output: &str) -> Result<(Option<String>, Option<String>)> {
    let mut interface = None;
    let mut gateway = None;

    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("interface:") {
            interface = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("gateway:") {
            gateway = Some(value.trim().to_owned());
        }
    }

    if interface.is_none() {
        bail!("route output did not include an interface");
    }

    Ok((interface, gateway))
}

#[cfg(not(target_os = "macos"))]
fn parse_macos_route_get(_output: &str) -> Result<(Option<String>, Option<String>)> {
    Ok((None, None))
}

fn spawn_shell_command(
    label: &str,
    shell: &str,
    template: &str,
    context: &CommandContext,
    quiet: bool,
    isolated_process_group: bool,
) -> Result<Child> {
    let expanded = context.expand(template);
    let mut command = Command::new(shell);
    command.arg("-lc").arg(&expanded);
    context.apply_envs(&mut command);
    command.kill_on_drop(true);
    #[cfg(unix)]
    if isolated_process_group {
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    if quiet {
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
    } else {
        command.stdout(std::process::Stdio::piped());
        command.stderr(std::process::Stdio::piped());
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to start {label}: {expanded}"))?;
    if !quiet {
        attach_child_logs(label, &mut child);
    }
    Ok(child)
}

fn spawn_tun_helper(
    shell: &str,
    helper: &TunHelperConfig,
    context: &CommandContext,
) -> Result<RunningTunHelper> {
    match helper {
        TunHelperConfig::EmbeddedTun2Proxy => {
            let helper_context = context.clone();
            let shutdown_token = tun2proxy::CancellationToken::new();
            let task_shutdown = shutdown_token.clone();
            let task =
                tokio::spawn(
                    async move { run_embedded_tun2proxy(helper_context, task_shutdown).await },
                );
            Ok(RunningTunHelper::Embedded {
                task,
                shutdown_token,
            })
        }
        TunHelperConfig::ExternalCommand(template) => Ok(RunningTunHelper::External(
            spawn_shell_command("tun helper", shell, template, context, false, true)?,
        )),
    }
}

async fn run_embedded_tun2proxy(
    context: CommandContext,
    shutdown_token: tun2proxy::CancellationToken,
) -> Result<()> {
    let proxy_url = format!("socks5://{}", context.socks_listen);
    let proxy = tun2proxy::ArgProxy::try_from(proxy_url.as_str())
        .map_err(|err| anyhow::anyhow!("invalid tun2proxy proxy URL {proxy_url}: {err}"))?;
    let mut args = tun2proxy::Args::default();
    args.proxy(proxy)
        .tun(context.device.clone())
        .dns(tun2proxy::ArgDns::Direct)
        .verbosity(tun2proxy::ArgVerbosity::Warn)
        .setup(false);
    args.exit_on_fatal_error = true;
    tun2proxy::general_run_async(
        args,
        tun2proxy::DEFAULT_MTU,
        cfg!(target_os = "macos"),
        shutdown_token,
    )
    .await
    .context("embedded tun2proxy failed")?;
    Ok(())
}

fn attach_child_logs(label: &str, child: &mut Child) {
    if let Some(stdout) = child.stdout.take() {
        let label = label.to_owned();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_child_line(&label, false, &line);
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let label = label.to_owned();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log_child_line(&label, true, &line);
            }
        });
    }
}

fn log_child_line(label: &str, stderr: bool, line: &str) {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return;
    }

    if let Ok(parsed) = serde_json::from_str::<HelperLogLine>(trimmed) {
        let message = parsed.msg.unwrap_or_else(|| trimmed.to_owned());
        let caller = parsed.caller.unwrap_or_default();
        match parsed
            .level
            .as_deref()
            .map(|value| value.to_ascii_lowercase())
        {
            Some(level) if level == "debug" => {
                debug!(caller = %caller, "{} {}", label, message);
            }
            Some(level) if level == "warn" || level == "warning" => {
                warn!(caller = %caller, "{} {}", label, message);
            }
            Some(level) if level == "error" || level == "fatal" => {
                error!(caller = %caller, "{} {}", label, message);
            }
            _ => {
                info!(caller = %caller, "{} {}", label, message);
            }
        }
        return;
    }

    if stderr {
        warn!("{} {}", label, trimmed);
    } else {
        info!("{} {}", label, trimmed);
    }
}

async fn run_hooks(
    label: &str,
    shell: &str,
    hooks: &[String],
    context: &CommandContext,
) -> Result<()> {
    for hook in hooks {
        let expanded = context.expand(hook);
        info!(hook = %expanded, "{label} starting");
        let status = Command::new(shell)
            .arg("-lc")
            .arg(&expanded)
            .envs(shell_envs(context))
            .status()
            .await
            .with_context(|| format!("failed to run {label}: {expanded}"))?;
        if !status.success() {
            bail!("{label} failed with status {status}: {expanded}");
        }
    }
    Ok(())
}

async fn shutdown(
    shell: &str,
    down_hooks: &[String],
    context: &CommandContext,
    helper: &mut RunningTunHelper,
    client_task: &mut JoinHandle<Result<()>>,
) {
    if let Err(err) = run_hooks("down hook", shell, down_hooks, context).await {
        warn!(error = %err, "tun down hook failed");
    }

    shutdown_tun_helper(helper).await;
    client_task.abort();
    let _ = client_task.await;
}

async fn abort_client_task(client_task: &mut JoinHandle<Result<()>>) {
    client_task.abort();
    let _ = client_task.await;
}

async fn shutdown_tun_helper(helper: &mut RunningTunHelper) {
    match helper {
        RunningTunHelper::Embedded {
            task,
            shutdown_token,
        } => {
            info!("stopping embedded tun2proxy");
            shutdown_token.cancel();
            if timeout(Duration::from_secs(2), &mut *task).await.is_err() {
                warn!("embedded tun2proxy did not exit in time; aborting task");
                task.abort();
                let _ = task.await;
            }
        }
        RunningTunHelper::External(child) => {
            if let Some(pid) = child.id() {
                terminate_process_group(pid, "tun helper").await;
            }
            let _ = timeout(Duration::from_secs(2), child.wait()).await;
        }
    }
}

async fn ensure_helper_alive(
    helper: &mut RunningTunHelper,
    device: &str,
    stage: &str,
) -> Result<()> {
    match helper {
        RunningTunHelper::Embedded { task, .. } => {
            if task.is_finished() {
                return match task.await {
                    Ok(Ok(())) => Err(anyhow::anyhow!(
                        "embedded tun2proxy exited {stage} unexpectedly"
                    )),
                    Ok(Err(err)) => {
                        Err(err).with_context(|| format!("embedded tun2proxy exited {stage}"))
                    }
                    Err(err) if err.is_cancelled() => {
                        Err(anyhow::anyhow!("embedded tun2proxy was cancelled {stage}"))
                    }
                    Err(err) => {
                        Err(err).with_context(|| format!("embedded tun2proxy task failed {stage}"))
                    }
                };
            }
            Ok(())
        }
        RunningTunHelper::External(child) => {
            if let Some(status) = child
                .try_wait()
                .with_context(|| format!("failed to inspect tun helper status {stage}"))?
            {
                bail!(
                    "tun helper exited {stage} with status {status}; if the helper logged `create tun: resource busy`, `{device}` was already in use"
                );
            }
            Ok(())
        }
    }
}

async fn wait_for_tun_helper(helper: &mut RunningTunHelper) -> Result<()> {
    match helper {
        RunningTunHelper::Embedded { task, .. } => match task.await {
            Ok(Ok(())) => bail!("embedded tun2proxy exited unexpectedly"),
            Ok(Err(err)) => Err(err).context("embedded tun2proxy exited"),
            Err(err) if err.is_cancelled() => Ok(()),
            Err(err) => Err(err).context("embedded tun2proxy task failed"),
        },
        RunningTunHelper::External(child) => {
            let status = child
                .wait()
                .await
                .context("failed to wait for tun helper")?;
            if status.success() {
                bail!("tun helper exited unexpectedly")
            } else {
                bail!("tun helper exited with status {status}")
            }
        }
    }
}

async fn wait_for_listener(listen: &str, timeout_window: Duration) -> Result<()> {
    let started = tokio::time::Instant::now();
    loop {
        if TcpStream::connect(listen).await.is_ok() {
            return Ok(());
        }
        if started.elapsed() >= timeout_window {
            bail!("timed out waiting for local SOCKS listener at {listen}");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn join_client(result: Result<Result<()>, tokio::task::JoinError>) -> Result<()> {
    match result {
        Ok(inner) => inner.context("embedded client exited"),
        Err(err) if err.is_cancelled() => Ok(()),
        Err(err) => Err(err).context("embedded client task failed"),
    }
}

async fn wait_for_shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate =
            signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.context("failed to wait for Ctrl-C")?;
            }
            _ = terminate.recv() => {}
        }
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .context("failed to wait for Ctrl-C")?;
        Ok(())
    }
}

fn shell_envs(context: &CommandContext) -> BTreeMap<&'static str, String> {
    let mut envs = BTreeMap::new();
    envs.insert("PIPIT_TUN_DEVICE", context.device.clone());
    envs.insert("PIPIT_SOCKS_LISTEN", context.socks_listen.clone());
    envs.insert("PIPIT_SERVER", context.server.clone());
    envs.insert("PIPIT_SERVER_HOST", context.server_host.clone());
    envs.insert("PIPIT_SERVER_PORT", context.server_port.to_string());
    envs.insert("PIPIT_SERVER_IP", context.server_ip.clone());
    if let Some(interface) = &context.egress_interface {
        envs.insert("PIPIT_EGRESS_INTERFACE", interface.clone());
    }
    if let Some(gateway) = &context.egress_gateway {
        envs.insert("PIPIT_EGRESS_GATEWAY", gateway.clone());
    }
    if let Some(log_file) = &context.log_file {
        envs.insert("PIPIT_LOG_FILE", log_file.clone());
    }
    envs
}

fn plan_lines(
    args: &TunArgs,
    context: &CommandContext,
    helper: &TunHelperConfig,
    up_hooks: &[String],
    down_hooks: &[String],
) -> Vec<String> {
    let mut lines = Vec::new();
    lines.push("pipit tun plan".to_owned());
    if is_auto_device(&args.device) {
        lines.push(format!("  device: {} (auto)", context.device));
    } else {
        lines.push(format!("  device: {}", context.device));
    }
    lines.push(format!("  socks: {}", args.client.listen));
    lines.push(format!("  server: {}", args.client.server));
    lines.push(format!("  server_ip: {}", context.server_ip));
    lines.push(format!(
        "  egress_interface: {}",
        context.egress_interface.as_deref().unwrap_or("-")
    ));
    lines.push(format!(
        "  egress_gateway: {}",
        context.egress_gateway.as_deref().unwrap_or("-")
    ));
    lines.push(format!("  helper: {}", helper.describe(context)));
    lines.push("  up hooks:".to_owned());
    if up_hooks.is_empty() {
        lines.push("    - (none)".to_owned());
    } else {
        for hook in up_hooks {
            lines.push(format!("    - {}", context.expand(hook)));
        }
    }
    lines.push("  down hooks:".to_owned());
    if down_hooks.is_empty() {
        lines.push("    - (none)".to_owned());
    } else {
        for hook in down_hooks {
            lines.push(format!("    - {}", context.expand(hook)));
        }
    }
    lines
}

fn print_plan(lines: &[String]) {
    for line in lines {
        println!("{line}");
    }
}

fn log_plan_lines(lines: &[String]) {
    for line in lines {
        info!("{}", line);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AUTO_TUN_DEVICE, CommandContext, MACOS_TUN_GATEWAY_V4, TEST_SERVER_ENDPOINT,
        TEST_SERVER_HOST, TEST_SERVER_IP, TunArgs, TunHelperBinary, TunHelperConfig,
        TunHelperFlavor, default_down_hooks, default_server_bypass_route, default_up_hooks,
        detect_tun_helper_flavor, is_auto_device, parse_macos_route_get, plan_lines, print_plan,
        shell_envs,
    };
    use crate::{client::ClientArgs, mode::ProxyMode, route::FilterMode};
    use std::path::PathBuf;

    #[test]
    fn placeholders_expand_into_shell_commands() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let expanded = context.expand(
            "tun2proxy-bin --tun {device} --proxy socks5://{socks} --server {server} --iface {egress_interface} --host {server_host} --ip {server_ip}",
        );
        assert_eq!(
            expanded,
            "tun2proxy-bin --tun utun233 --proxy socks5://127.0.0.1:1080 --server 198.51.100.10:1443 --iface en0 --host 198.51.100.10 --ip 198.51.100.10"
        );
    }

    #[test]
    fn helper_flavor_detection_prefers_tun2proxy_for_unknown_names() {
        assert_eq!(
            detect_tun_helper_flavor(std::path::Path::new("/usr/local/bin/tun2proxy-bin")),
            TunHelperFlavor::Tun2Proxy
        );
        assert_eq!(
            detect_tun_helper_flavor(std::path::Path::new("/usr/local/bin/custom-helper")),
            TunHelperFlavor::Tun2Proxy
        );
        assert_eq!(
            detect_tun_helper_flavor(std::path::Path::new("/usr/local/bin/tun2socks")),
            TunHelperFlavor::Tun2Socks
        );
    }

    #[test]
    fn tun2proxy_default_helper_command_uses_new_cli_flags() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let helper = TunHelperBinary {
            path: PathBuf::from("/usr/local/bin/tun2proxy-bin"),
            flavor: TunHelperFlavor::Tun2Proxy,
        };
        assert_eq!(
            helper.default_command(&context),
            "'/usr/local/bin/tun2proxy-bin' --tun {device} --proxy socks5://{socks} --dns direct --verbosity warn --exit-on-fatal-error"
        );
    }

    #[test]
    fn tun2socks_default_helper_command_keeps_legacy_interface_flag() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let helper = TunHelperBinary {
            path: PathBuf::from("/usr/local/bin/tun2socks"),
            flavor: TunHelperFlavor::Tun2Socks,
        };
        assert_eq!(
            helper.default_command(&context),
            "'/usr/local/bin/tun2socks' -device {device} -proxy socks5://{socks} -loglevel info -tcp-auto-tuning -interface en0"
        );
    }

    #[test]
    fn embedded_tun2proxy_helper_description_is_human_readable() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        assert_eq!(
            TunHelperConfig::EmbeddedTun2Proxy.describe(&context),
            "embedded tun2proxy crate --tun utun233 --proxy socks5://127.0.0.1:1080 --dns direct --verbosity warn --exit-on-fatal-error"
        );
    }

    #[test]
    fn shell_envs_include_runtime_values() {
        let context = CommandContext {
            device: "utun9".to_owned(),
            socks_listen: "127.0.0.1:19080".to_owned(),
            server: "example.com:443".to_owned(),
            server_host: "example.com".to_owned(),
            server_port: 443,
            server_ip: "93.184.216.34".to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let envs = shell_envs(&context);
        assert_eq!(
            envs.get("PIPIT_TUN_DEVICE").map(String::as_str),
            Some("utun9")
        );
        assert_eq!(
            envs.get("PIPIT_SOCKS_LISTEN").map(String::as_str),
            Some("127.0.0.1:19080")
        );
        assert_eq!(
            envs.get("PIPIT_SERVER_IP").map(String::as_str),
            Some("93.184.216.34")
        );
        assert_eq!(
            envs.get("PIPIT_EGRESS_INTERFACE").map(String::as_str),
            Some("en0")
        );
    }

    #[test]
    fn auto_device_flag_is_detected() {
        assert!(is_auto_device(AUTO_TUN_DEVICE));
        assert!(is_auto_device("AUTO"));
        assert!(is_auto_device(""));
        assert!(!is_auto_device("utun233"));
    }

    #[test]
    fn tun_state_path_follows_log_stem() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("/tmp/proxy.log".to_owned()),
        };
        let path = super::resolve_tun_state_path(&context).expect("state path resolves");
        assert_eq!(path, PathBuf::from("/tmp/proxy.tun.state.json"));
    }

    #[test]
    fn tun_mode_forces_proxy_filter_to_avoid_loops() {
        let mut args = ClientArgs {
            listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_name: Some("example.com".to_owned()),
            ca_cert: None,
            mode: ProxyMode::NativeHttp,
            password: "secret".to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            mux: false,
            filter: FilterMode::Rule,
            rule_file: Some(PathBuf::from("rule.ls")),
            cidr_file: Some(PathBuf::from("rule.cidr")),
            user_agent: "Mozilla/5.0".to_owned(),
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 8 * 1024,
            system_proxy: false,
            system_proxy_services: Vec::new(),
        };

        super::normalize_client_args_for_tun(&mut args);

        assert_eq!(args.filter, FilterMode::Proxy);
        assert!(args.rule_file.is_none());
        assert!(args.cidr_file.is_none());
    }

    #[test]
    fn print_plan_expands_helper_and_hooks() {
        let args = TunArgs {
            client: ClientArgs {
                listen: "127.0.0.1:1080".to_owned(),
                server: TEST_SERVER_ENDPOINT.to_owned(),
                server_name: Some("example.com".to_owned()),
                ca_cert: None,
                mode: ProxyMode::NativeHttp,
                password: "hello-world".to_owned(),
                path: "/connect".to_owned(),
                mux_path: "/mux".to_owned(),
                mux: false,
                filter: FilterMode::Proxy,
                rule_file: None,
                cidr_file: None,
                user_agent: "pipit-test".to_owned(),
                handshake_timeout_secs: 10,
                connect_timeout_secs: 10,
                max_header_size: 8192,
                system_proxy: false,
                system_proxy_services: Vec::new(),
            },
            device: "utun233".to_owned(),
            shell: "/bin/sh".to_owned(),
            helper_cmd: String::new(),
            helper_ready_delay_ms: 800,
            up: Vec::new(),
            down: Vec::new(),
            print_hooks: true,
            dry_run: false,
        };
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let lines = plan_lines(
            &args,
            &context,
            &TunHelperConfig::EmbeddedTun2Proxy,
            &["ifconfig {device} inet 198.18.0.1 198.18.0.1 up".to_owned()],
            &["ifconfig {device} down >/dev/null 2>&1 || true".to_owned()],
        );
        print_plan(&lines);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_route_output_is_parsed() {
        let output = r#"
   route to: 198.51.100.10
destination: 198.51.100.10
    gateway: 192.168.3.1
  interface: en0
"#;
        let (interface, gateway) = parse_macos_route_get(output).expect("route output parses");
        assert_eq!(interface.as_deref(), Some("en0"));
        assert_eq!(gateway.as_deref(), Some("192.168.3.1"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn utun_routes_trigger_default_egress_fallback() {
        assert!(super::should_fallback_to_default_egress(&(
            Some("utun4".to_owned()),
            Some("198.18.0.1".to_owned())
        )));
        assert!(super::should_fallback_to_default_egress(&(
            Some("utun4".to_owned()),
            Some("192.168.3.1".to_owned())
        )));
        assert!(!super::should_fallback_to_default_egress(&(
            Some("en0".to_owned()),
            Some("192.168.3.1".to_owned())
        )));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_macos_up_hooks_assign_interface_and_split_routes() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let hooks = default_up_hooks(&context).expect("macOS hooks are generated");
        assert_eq!(
            hooks.first().map(String::as_str),
            Some("ifconfig {device} inet 198.18.0.1 198.18.0.1 up")
        );
        assert!(
            hooks
                .iter()
                .any(|hook| hook == "route -q -n add -net 1.0.0.0/8 198.18.0.1 >/dev/null 2>&1 || route -q -n change -net 1.0.0.0/8 198.18.0.1")
        );
        assert!(
            hooks
                .iter()
                .any(|hook| hook == "route -q -n add -net 128.0.0.0/1 198.18.0.1 >/dev/null 2>&1 || route -q -n change -net 128.0.0.0/1 198.18.0.1")
        );
        assert!(
            hooks
                .iter()
                .any(|hook| hook.contains("route -q -n add -host {server_ip} 192.168.3.1"))
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn default_macos_bypass_route_prefers_gateway() {
        let context = CommandContext {
            device: "utun233".to_owned(),
            socks_listen: "127.0.0.1:1080".to_owned(),
            server: TEST_SERVER_ENDPOINT.to_owned(),
            server_host: TEST_SERVER_HOST.to_owned(),
            server_port: 1443,
            server_ip: TEST_SERVER_IP.to_owned(),
            egress_interface: Some("en0".to_owned()),
            egress_gateway: Some("192.168.3.1".to_owned()),
            log_file: Some("proxy.log".to_owned()),
        };
        let route = default_server_bypass_route(&context);
        assert!(route.contains("192.168.3.1"));
        assert!(!route.contains("-interface {egress_interface}"));
        let down = default_down_hooks(&context).expect("down hooks are generated");
        assert_eq!(
            down.last().map(String::as_str),
            Some("ifconfig {device} down >/dev/null 2>&1 || true")
        );
        assert!(
            down.iter()
                .any(|hook| hook.contains("delete -net 198.18.0.0/15"))
        );
        assert_eq!(MACOS_TUN_GATEWAY_V4, "198.18.0.1");
    }
}
