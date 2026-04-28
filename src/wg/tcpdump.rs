use std::{collections::BTreeMap, net::SocketAddr, process::Stdio};

use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
    task::JoinHandle,
};
use tracing::{debug, info, warn};

use crate::telemetry;

pub(crate) struct TcpdumpGuard {
    handle: JoinHandle<()>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PacketLine {
    src: String,
    dst: String,
    length: u64,
    direction: Option<&'static str>,
}

#[derive(Clone, Debug)]
pub(crate) enum TcpdumpFilter {
    Client { endpoint: SocketAddr },
    Server { listen: SocketAddr },
}

impl Drop for TcpdumpGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub(crate) fn start(
    role: &'static str,
    interface: Option<&str>,
    filter: TcpdumpFilter,
) -> TcpdumpGuard {
    let interface = interface
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(default_interface())
        .to_owned();
    let handle = tokio::spawn(run_tcpdump(role, interface, filter));
    TcpdumpGuard { handle }
}

async fn run_tcpdump(role: &'static str, interface: String, filter: TcpdumpFilter) {
    let args = tcpdump_args(&interface, &filter);
    info!(
        role,
        interface = %interface,
        filter = %args[4..].join(" "),
        "starting wg tcpdump monitor"
    );

    let mut command = Command::new("tcpdump");
    command.args(&args);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.kill_on_drop(true);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            warn!(
                role,
                interface = %interface,
                error = %error,
                "failed to start wg tcpdump monitor"
            );
            return;
        }
    };

    let stdout_task = child.stdout.take().map(|stdout| {
        tokio::spawn(read_tcpdump_stdout(
            role,
            interface.clone(),
            filter.clone(),
            stdout,
        ))
    });
    let stderr_task = child
        .stderr
        .take()
        .map(|stderr| tokio::spawn(read_tcpdump_stderr(role, interface.clone(), stderr)));

    match child.wait().await {
        Ok(status) if status.success() => {
            debug!(role, interface = %interface, "wg tcpdump monitor exited");
        }
        Ok(status) => {
            warn!(
                role,
                interface = %interface,
                status = %status,
                "wg tcpdump monitor exited"
            );
        }
        Err(error) => {
            warn!(
                role,
                interface = %interface,
                error = %error,
                "failed to wait for wg tcpdump monitor"
            );
        }
    }

    if let Some(task) = stdout_task {
        task.abort();
    }
    if let Some(task) = stderr_task {
        task.abort();
    }
}

async fn read_tcpdump_stdout(
    role: &'static str,
    interface: String,
    filter: TcpdumpFilter,
    stdout: tokio::process::ChildStdout,
) {
    let mut lines = BufReader::new(stdout).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if let Some(packet) = parse_packet_line(&line) {
            emit_packet(role, &interface, &filter, packet);
        }
    }
}

async fn read_tcpdump_stderr(
    role: &'static str,
    interface: String,
    stderr: tokio::process::ChildStderr,
) {
    let mut lines = BufReader::new(stderr).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("listening on ") || line.starts_with("tcpdump: verbose output") {
            debug!(role, interface = %interface, message = %line, "wg tcpdump monitor");
        } else {
            warn!(role, interface = %interface, message = %line, "wg tcpdump monitor");
        }
    }
}

fn tcpdump_args(interface: &str, filter: &TcpdumpFilter) -> Vec<String> {
    let mut args = vec![
        "-l".to_owned(),
        "-n".to_owned(),
        "-tt".to_owned(),
        "-i".to_owned(),
        interface.to_owned(),
        "udp".to_owned(),
        "and".to_owned(),
    ];
    match filter {
        TcpdumpFilter::Client { endpoint } => {
            args.extend([
                "host".to_owned(),
                endpoint.ip().to_string(),
                "and".to_owned(),
                "port".to_owned(),
                endpoint.port().to_string(),
            ]);
        }
        TcpdumpFilter::Server { listen } => {
            args.extend(["port".to_owned(), listen.port().to_string()]);
        }
    }
    args
}

fn emit_packet(role: &'static str, interface: &str, filter: &TcpdumpFilter, packet: PacketLine) {
    let mut fields = BTreeMap::new();
    fields.insert("mode".to_owned(), "wg".to_owned());
    fields.insert("role".to_owned(), role.to_owned());
    fields.insert("interface".to_owned(), interface.to_owned());
    fields.insert("src".to_owned(), packet.src.clone());
    fields.insert("dst".to_owned(), packet.dst.clone());
    fields.insert("length".to_owned(), packet.length.to_string());
    fields.insert("packet".to_owned(), packet_kind(packet.length).to_owned());
    fields.insert(
        "target".to_owned(),
        format!("{} > {}", packet.src, packet.dst),
    );
    fields.insert(
        "detail".to_owned(),
        format!("{} bytes {}", packet.length, packet_kind(packet.length)),
    );
    if let Some(direction) = packet
        .direction
        .or_else(|| infer_direction(filter, &packet.src, &packet.dst))
    {
        fields.insert("direction".to_owned(), direction.to_owned());
    }
    telemetry::emit("INFO", "wg tcpdump packet", fields);
}

fn parse_packet_line(line: &str) -> Option<PacketLine> {
    let length = parse_udp_length(line)?;
    let tokens = line.split_whitespace().collect::<Vec<_>>();
    let arrow = tokens.iter().position(|token| *token == ">")?;
    let src = tokens.get(arrow.checked_sub(1)?)?.trim_end_matches(':');
    let dst = tokens.get(arrow + 1)?.trim_end_matches(':');
    Some(PacketLine {
        src: src.to_owned(),
        dst: dst.to_owned(),
        length,
        direction: parse_direction(&tokens),
    })
}

fn parse_udp_length(line: &str) -> Option<u64> {
    let marker = " UDP, length ";
    let value = line.split_once(marker)?.1;
    value
        .split(|ch: char| !ch.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

fn parse_direction(tokens: &[&str]) -> Option<&'static str> {
    if tokens.contains(&"In") {
        return Some("in");
    }
    if tokens.contains(&"Out") {
        return Some("out");
    }
    None
}

fn infer_direction(filter: &TcpdumpFilter, src: &str, dst: &str) -> Option<&'static str> {
    match filter {
        TcpdumpFilter::Client { endpoint } => {
            let endpoint = tcpdump_addr(*endpoint);
            if dst == endpoint {
                Some("out")
            } else if src == endpoint {
                Some("in")
            } else {
                None
            }
        }
        TcpdumpFilter::Server { listen } => {
            let port_suffix = format!(".{}", listen.port());
            if dst.ends_with(&port_suffix) {
                Some("in")
            } else if src.ends_with(&port_suffix) {
                Some("out")
            } else {
                None
            }
        }
    }
}

fn tcpdump_addr(addr: SocketAddr) -> String {
    format!("{}.{}", addr.ip(), addr.port())
}

fn packet_kind(length: u64) -> &'static str {
    match length {
        148 => "handshake-init",
        92 => "handshake-response",
        64 => "cookie-reply",
        32 => "keepalive",
        _ => "data",
    }
}

fn default_interface() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "any"
    }
    #[cfg(target_os = "macos")]
    {
        "any"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        "any"
    }
}

#[cfg(test)]
mod tests {
    use super::{PacketLine, TcpdumpFilter, infer_direction, parse_packet_line, tcpdump_args};
    use std::net::SocketAddr;

    #[test]
    fn parses_tcpdump_packet_line() {
        let line =
            "1713430000.158956 IP 192.168.3.72.64306 > 172.235.244.118.1443: UDP, length 148";
        assert_eq!(
            parse_packet_line(line),
            Some(PacketLine {
                src: "192.168.3.72.64306".to_owned(),
                dst: "172.235.244.118.1443".to_owned(),
                length: 148,
                direction: None,
            })
        );
    }

    #[test]
    fn parses_linux_any_direction() {
        let line = "1713430000.899841 eth0 In IP 120.231.241.251.3480 > 172.235.244.118.1443: UDP, length 148";
        assert_eq!(parse_packet_line(line).unwrap().direction, Some("in"));
    }

    #[test]
    fn infers_client_direction_from_endpoint() {
        let filter = TcpdumpFilter::Client {
            endpoint: "172.235.244.118:1443".parse::<SocketAddr>().unwrap(),
        };
        assert_eq!(
            infer_direction(&filter, "192.168.3.72.64306", "172.235.244.118.1443"),
            Some("out")
        );
        assert_eq!(
            infer_direction(&filter, "172.235.244.118.1443", "192.168.3.72.64306"),
            Some("in")
        );
    }

    #[test]
    fn builds_client_tcpdump_filter() {
        let args = tcpdump_args(
            "any",
            &TcpdumpFilter::Client {
                endpoint: "172.235.244.118:1443".parse::<SocketAddr>().unwrap(),
            },
        );
        assert_eq!(
            args,
            [
                "-l",
                "-n",
                "-tt",
                "-i",
                "any",
                "udp",
                "and",
                "host",
                "172.235.244.118",
                "and",
                "port",
                "1443"
            ]
        );
    }
}
