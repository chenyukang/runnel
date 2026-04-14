use std::{
    collections::BTreeMap,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use clap::Args;
use tokio::{
    net::{TcpStream, lookup_host},
    process::{Child, Command},
    task::JoinHandle,
    time::{sleep, timeout},
};
use tracing::{info, warn};

use crate::{
    client::{self, ClientArgs},
    tls,
};

#[cfg(test)]
const TEST_SERVER_ENDPOINT: &str = "198.51.100.10:1443";
#[cfg(test)]
const TEST_SERVER_HOST: &str = "198.51.100.10";
#[cfg(test)]
const TEST_SERVER_IP: &str = "198.51.100.10";

const MACOS_TUN_GATEWAY_V4: &str = "198.18.0.1";
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
    #[arg(long, default_value = "utun233")]
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
}

pub async fn run(args: TunArgs) -> Result<()> {
    args.validate_required()?;
    let context = CommandContext::from_args(&args).await?;
    let helper_cmd = effective_helper_cmd(&args, &context)?;
    let up_hooks = effective_up_hooks(&args, &context)?;
    let down_hooks = effective_down_hooks(&args, &context)?;
    let mut client_task = tokio::spawn(client::run(args.client.clone()));
    wait_for_listener(&args.client.listen, Duration::from_secs(5)).await?;

    let mut helper = spawn_shell_command("tun helper", &args.shell, &helper_cmd, &context, false)?;
    info!(
        device = %args.device,
        socks = %args.client.listen,
        server = %args.client.server,
        server_ip = %context.server_ip,
        egress_interface = context.egress_interface.as_deref().unwrap_or("-"),
        egress_gateway = context.egress_gateway.as_deref().unwrap_or("-"),
        "tun helper started"
    );

    sleep(Duration::from_millis(args.helper_ready_delay_ms)).await;
    if let Err(err) = run_hooks("up hook", &args.shell, &up_hooks, &context).await {
        shutdown(
            &args.shell,
            &down_hooks,
            &context,
            &mut helper,
            &mut client_task,
        )
        .await;
        return Err(err);
    }

    let result = tokio::select! {
        result = &mut client_task => join_client(result),
        status = helper.wait() => {
            let status = status.context("failed to wait for tun helper")?;
            if status.success() {
                bail!("tun helper exited unexpectedly")
            } else {
                bail!("tun helper exited with status {status}")
            }
        }
        signal = tokio::signal::ctrl_c() => {
            signal?;
            Ok(())
        }
    };

    shutdown(
        &args.shell,
        &down_hooks,
        &context,
        &mut helper,
        &mut client_task,
    )
    .await;
    result
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
        let server_ip = resolve_server_ip(&server_host, server_port).await?;
        let needs_egress_metadata = needs_egress_metadata(args);
        let (egress_interface, egress_gateway) = if needs_egress_metadata {
            detect_egress_route(&server_ip).await?
        } else {
            (None, None)
        };

        Ok(Self {
            device: args.device.clone(),
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
    args.helper_cmd.trim().is_empty()
        || needs_placeholder(&args.helper_cmd, "{egress_")
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

fn effective_helper_cmd(args: &TunArgs, context: &CommandContext) -> Result<String> {
    if !args.helper_cmd.trim().is_empty() {
        return Ok(args.helper_cmd.clone());
    }

    default_helper_cmd(context)
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

fn default_helper_cmd(context: &CommandContext) -> Result<String> {
    let helper = detect_tun_helper().context(
        "no standalone tun helper found; install tun2socks in PATH, set PIPIT_TUN_HELPER, or set tun.helper_cmd",
    )?;
    let mut command = format!(
        "{} -device {{device}} -proxy socks5://{{socks}} -loglevel info -tcp-auto-tuning",
        shell_quote_path(&helper)
    );
    if let Some(interface) = &context.egress_interface {
        command.push_str(&format!(" -interface {interface}"));
    }
    Ok(command)
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
                .map(|cidr| format!("route -q -n add -net {cidr} {MACOS_TUN_GATEWAY_V4}")),
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

fn detect_tun_helper() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("PIPIT_TUN_HELPER") {
        let candidate = PathBuf::from(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    find_in_path("tun2socks")
}

fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for entry in std::env::split_paths(&path) {
        let candidate = entry.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
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
        let output = Command::new("route")
            .arg("-n")
            .arg("get")
            .arg(server_ip)
            .output()
            .await
            .with_context(|| format!("failed to inspect route to {server_ip}"))?;
        if !output.status.success() {
            bail!(
                "failed to inspect route to {server_ip}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        return parse_macos_route_get(&stdout);
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = server_ip;
        Ok((None, None))
    }
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
) -> Result<Child> {
    let expanded = context.expand(template);
    let mut command = Command::new(shell);
    command.arg("-lc").arg(&expanded);
    context.apply_envs(&mut command);
    if quiet {
        command.stdout(std::process::Stdio::null());
        command.stderr(std::process::Stdio::null());
    }
    let child = command
        .spawn()
        .with_context(|| format!("failed to start {label}: {expanded}"))?;
    Ok(child)
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
    helper: &mut Child,
    client_task: &mut JoinHandle<Result<()>>,
) {
    if let Err(err) = run_hooks("down hook", shell, down_hooks, context).await {
        warn!(error = %err, "tun down hook failed");
    }

    if let Some(pid) = helper.id() {
        info!(pid, "stopping tun helper");
    }
    let _ = helper.start_kill();
    let _ = timeout(Duration::from_secs(2), helper.wait()).await;
    client_task.abort();
    let _ = client_task.await;
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

#[cfg(test)]
mod tests {
    use super::{
        CommandContext, MACOS_TUN_GATEWAY_V4, TEST_SERVER_ENDPOINT, TEST_SERVER_HOST,
        TEST_SERVER_IP, default_down_hooks, default_server_bypass_route, default_up_hooks,
        parse_macos_route_get, shell_envs,
    };

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
            "tun2socks --device {device} --proxy socks5://{socks} --server {server} --iface {egress_interface} --host {server_host} --ip {server_ip}",
        );
        assert_eq!(
            expanded,
            "tun2socks --device utun233 --proxy socks5://127.0.0.1:1080 --server 198.51.100.10:1443 --iface en0 --host 198.51.100.10 --ip 198.51.100.10"
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
                .any(|hook| hook == "route -q -n add -net 1.0.0.0/8 198.18.0.1")
        );
        assert!(
            hooks
                .iter()
                .any(|hook| hook == "route -q -n add -net 128.0.0.0/1 198.18.0.1")
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
