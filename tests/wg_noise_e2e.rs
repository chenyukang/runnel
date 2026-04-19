mod support;

fn obfs_profile_args() -> [&'static str; 12] {
    [
        "--obfs-padding-min",
        "8",
        "--obfs-padding-max",
        "64",
        "--obfs-handshake-padding",
        "96",
        "--obfs-response-padding",
        "80",
        "--obfs-junk-packets",
        "1",
        "--obfs-jitter-ms",
        "0",
    ]
}

mod linux {
    use anyhow::{Context, Result, bail, ensure};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boringtun::x25519::{PublicKey, StaticSecret};
    use std::{
        ffi::{OsStr, OsString},
        fs,
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    use super::{obfs_profile_args, support::TempDir};

    const SERVER_UNDERLAY: &str = "192.0.2.1";
    const CLIENT_UNDERLAY: &str = "192.0.2.2";
    const WG_SERVER_IP: &str = "10.88.0.1";
    const WG_CLIENT_IP: &str = "10.88.0.2";
    const WG_PORT: &str = "1443";
    const WG_DEVICE: &str = "rwg0";

    #[test]
    #[ignore = "requires Linux root privileges, network namespaces, /dev/net/tun, ip, and ping"]
    fn wg_noise_engine_connects_two_linux_namespaces() -> Result<()> {
        ensure!(
            cfg!(target_os = "linux"),
            "wg noise e2e only runs on Linux because it uses network namespaces"
        );
        #[cfg(unix)]
        let is_root = unsafe { libc::geteuid() == 0 };
        #[cfg(not(unix))]
        let is_root = false;
        ensure!(
            is_root,
            "wg noise e2e requires root; run: sudo cargo test --test wg_noise_e2e -- --ignored --nocapture"
        );
        require_command("ip")?;
        require_command("ping")?;
        run(["ip", "netns", "list"])?;

        let temp_dir = TempDir::new("runnel-wg-noise-e2e")?;
        let empty_config = temp_dir.join("empty-config.yaml");
        fs::write(&empty_config, "{}\n")
            .with_context(|| format!("failed to write {}", empty_config.display()))?;
        let server_log = temp_dir.join("server.log");
        let client_log = temp_dir.join("client.log");
        let id = unique_id();
        let server_ns = format!("rn-s-{id}");
        let client_ns = format!("rn-c-{id}");
        let server_veth = format!("rns{id}s");
        let client_veth = format!("rns{id}c");
        let _netns = NetnsGuard::new([server_ns.clone(), client_ns.clone()]);

        run(["ip", "netns", "add", &server_ns])?;
        run(["ip", "netns", "add", &client_ns])?;
        run([
            "ip",
            "link",
            "add",
            &server_veth,
            "type",
            "veth",
            "peer",
            "name",
            &client_veth,
        ])?;
        run(["ip", "link", "set", &server_veth, "netns", &server_ns])?;
        run(["ip", "link", "set", &client_veth, "netns", &client_ns])?;
        run([
            "ip",
            "-n",
            &server_ns,
            "addr",
            "add",
            &format!("{SERVER_UNDERLAY}/24"),
            "dev",
            &server_veth,
        ])?;
        run([
            "ip",
            "-n",
            &client_ns,
            "addr",
            "add",
            &format!("{CLIENT_UNDERLAY}/24"),
            "dev",
            &client_veth,
        ])?;
        run(["ip", "-n", &server_ns, "link", "set", "lo", "up"])?;
        run(["ip", "-n", &client_ns, "link", "set", "lo", "up"])?;
        run(["ip", "-n", &server_ns, "link", "set", &server_veth, "up"])?;
        run(["ip", "-n", &client_ns, "link", "set", &client_veth, "up"])?;

        let client_private = STANDARD.encode([0x11_u8; 32]);
        let server_private = STANDARD.encode([0x22_u8; 32]);
        let client_public = public_key([0x11_u8; 32]);
        let server_public = public_key([0x22_u8; 32]);
        let bin = runnel_bin()?;

        let mut server = ChildGuard::spawn(
            "wg-noise-server",
            &server_log,
            Command::new("ip")
                .arg("netns")
                .arg("exec")
                .arg(&server_ns)
                .arg(&bin)
                .arg("--config")
                .arg(&empty_config)
                .arg("--log-file")
                .arg(&server_log)
                .arg("wg-server")
                .arg("--engine")
                .arg("noise")
                .arg("--obfs")
                .arg("mask")
                .args(obfs_profile_args())
                .arg("--listen")
                .arg(format!("0.0.0.0:{WG_PORT}"))
                .arg("--private-key")
                .arg(&server_private)
                .arg("--peer-public-key")
                .arg(&client_public)
                .arg("--device")
                .arg(WG_DEVICE)
                .arg("--tunnel-ip")
                .arg(WG_SERVER_IP)
                .arg("--peer-tunnel-ip")
                .arg(WG_CLIENT_IP)
                .arg("--peer-allowed-ip")
                .arg(format!("{WG_CLIENT_IP}/32"))
                .arg("--mtu")
                .arg("1420"),
        )?;
        wait_for_log(&server_log, "wg server started", &mut server)?;

        let mut client = ChildGuard::spawn(
            "wg-noise-client",
            &client_log,
            Command::new("ip")
                .arg("netns")
                .arg("exec")
                .arg(&client_ns)
                .arg(&bin)
                .arg("--config")
                .arg(&empty_config)
                .arg("--log-file")
                .arg(&client_log)
                .arg("wg-client")
                .arg("--engine")
                .arg("noise")
                .arg("--obfs")
                .arg("mask")
                .args(obfs_profile_args())
                .arg("--bind")
                .arg("0.0.0.0:0")
                .arg("--endpoint")
                .arg(format!("{SERVER_UNDERLAY}:{WG_PORT}"))
                .arg("--private-key")
                .arg(&client_private)
                .arg("--peer-public-key")
                .arg(&server_public)
                .arg("--device")
                .arg(WG_DEVICE)
                .arg("--tunnel-ip")
                .arg(WG_CLIENT_IP)
                .arg("--peer-tunnel-ip")
                .arg(WG_SERVER_IP)
                .arg("--persistent-keepalive-secs")
                .arg("1")
                .arg("--mtu")
                .arg("1420"),
        )?;
        wait_for_log(&client_log, "wg client started", &mut client)?;

        wait_for_ping(&client_ns, WG_SERVER_IP, &mut server, &mut client)
            .with_context(|| e2e_debug(&server_ns, &client_ns, &server_log, &client_log))?;

        Ok(())
    }

    fn wait_for_ping(
        client_ns: &str,
        target: &str,
        server: &mut ChildGuard,
        client: &mut ChildGuard,
    ) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(8) {
            server.ensure_running()?;
            client.ensure_running()?;
            let output = Command::new("ip")
                .args([
                    "netns", "exec", client_ns, "ping", "-c", "1", "-W", "1", target,
                ])
                .output()
                .context("failed to run ping inside client netns")?;
            if output.status.success() {
                return Ok(());
            }
            last = format_output("ping", &output);
            thread::sleep(Duration::from_millis(250));
        }
        bail!("timed out waiting for WG noise ping to {target}\n{last}");
    }

    fn wait_for_log(path: &Path, needle: &str, child: &mut ChildGuard) -> Result<()> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            child.ensure_running()?;
            if fs::read_to_string(path)
                .unwrap_or_default()
                .contains(needle)
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "timed out waiting for log line `{needle}` in {}",
            path.display()
        );
    }

    fn require_command(command: &str) -> Result<()> {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {command} >/dev/null 2>&1"))
            .status()
            .with_context(|| format!("failed to check for command {command}"))?;
        ensure!(
            status.success(),
            "wg noise e2e requires `{command}` to be installed"
        );
        Ok(())
    }

    fn run<I, S>(args: I) -> Result<()>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect::<Vec<_>>();
        let Some((program, rest)) = args.split_first() else {
            bail!("empty command");
        };
        let output = Command::new(program)
            .args(rest)
            .output()
            .with_context(|| format!("failed to run {}", command_line(program, rest)))?;
        ensure!(
            output.status.success(),
            "{}",
            format_output(&command_line(program, rest), &output)
        );
        Ok(())
    }

    fn command_line(program: &OsStr, args: &[OsString]) -> String {
        std::iter::once(program.to_string_lossy().into_owned())
            .chain(args.iter().map(|arg| arg.to_string_lossy().into_owned()))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn format_output(label: &str, output: &std::process::Output) -> String {
        format!(
            "{label} exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn e2e_debug(server_ns: &str, client_ns: &str, server_log: &Path, client_log: &Path) -> String {
        format!(
            "server log:\n{}\nclient log:\n{}\nserver addr:\n{}\nclient addr:\n{}\nclient route:\n{}",
            fs::read_to_string(server_log).unwrap_or_default(),
            fs::read_to_string(client_log).unwrap_or_default(),
            command_stdout(["ip", "-n", server_ns, "addr"]),
            command_stdout(["ip", "-n", client_ns, "addr"]),
            command_stdout(["ip", "-n", client_ns, "route"]),
        )
    }

    fn command_stdout<I, S>(args: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let args = args
            .into_iter()
            .map(|arg| arg.as_ref().to_os_string())
            .collect::<Vec<_>>();
        let Some((program, rest)) = args.split_first() else {
            return String::new();
        };
        Command::new(program)
            .args(rest)
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default()
    }

    fn runnel_bin() -> Result<String> {
        std::env::var("CARGO_BIN_EXE_runnel").context("cargo did not provide CARGO_BIN_EXE_runnel")
    }

    fn unique_id() -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            % 100_000;
        format!("{}{}", std::process::id() % 10_000, millis)
    }

    fn public_key(private_key: [u8; 32]) -> String {
        STANDARD.encode(PublicKey::from(&StaticSecret::from(private_key)).as_bytes())
    }

    struct NetnsGuard {
        names: Vec<String>,
    }

    impl NetnsGuard {
        fn new(names: impl IntoIterator<Item = String>) -> Self {
            Self {
                names: names.into_iter().collect(),
            }
        }
    }

    impl Drop for NetnsGuard {
        fn drop(&mut self) {
            for name in self.names.iter().rev() {
                let _ = Command::new("ip").args(["netns", "del", name]).status();
            }
        }
    }

    struct ChildGuard {
        label: &'static str,
        child: Child,
        log_path: PathBuf,
    }

    impl ChildGuard {
        fn spawn(label: &'static str, log_path: &Path, command: &mut Command) -> Result<Self> {
            let child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .with_context(|| format!("failed to spawn {label}"))?;
            Ok(Self {
                label,
                child,
                log_path: log_path.to_path_buf(),
            })
        }

        fn ensure_running(&mut self) -> Result<()> {
            if let Some(status) = self
                .child
                .try_wait()
                .with_context(|| format!("failed to inspect {}", self.label))?
            {
                bail!(
                    "{} exited early with {status}\nlog:\n{}",
                    self.label,
                    fs::read_to_string(&self.log_path).unwrap_or_default()
                );
            }
            Ok(())
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

mod macos {
    use anyhow::{Context, Result, bail, ensure};
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use boringtun::x25519::{PublicKey, StaticSecret};
    use std::{
        collections::HashSet,
        fs,
        net::{Ipv4Addr, SocketAddr, UdpSocket},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    use super::{obfs_profile_args, support::TempDir};

    const WG_SERVER_IP: &str = "10.89.0.1";
    const WG_CLIENT_IP: &str = "10.89.0.2";

    #[test]
    #[ignore = "requires macOS root privileges, utun support, ifconfig, route, and ping"]
    fn wg_noise_engine_connects_two_macos_utuns() -> Result<()> {
        ensure!(
            cfg!(target_os = "macos"),
            "wg noise macOS e2e only runs on macOS"
        );
        #[cfg(unix)]
        let is_root = unsafe { libc::geteuid() == 0 };
        #[cfg(not(unix))]
        let is_root = false;
        ensure!(
            is_root,
            "wg noise macOS e2e requires root; run: sudo cargo test --test wg_noise_e2e -- --ignored --nocapture"
        );
        require_command("ifconfig")?;
        require_command("route")?;
        require_command("ping")?;

        let temp_dir = TempDir::new("runnel-wg-noise-macos-e2e")?;
        let empty_config = temp_dir.join("empty-config.yaml");
        fs::write(&empty_config, "{}\n")
            .with_context(|| format!("failed to write {}", empty_config.display()))?;
        let server_log = temp_dir.join("macos-server.log");
        let client_log = temp_dir.join("macos-client.log");
        let port = free_udp_port()?;
        let devices = pick_available_utuns(2)?;
        let server_device = devices[0].clone();
        let client_device = devices[1].clone();
        let _cleanup = MacosCleanup::new(vec![server_device.clone(), client_device.clone()]);

        let client_private = STANDARD.encode([0x11_u8; 32]);
        let server_private = STANDARD.encode([0x22_u8; 32]);
        let client_public = public_key([0x11_u8; 32]);
        let server_public = public_key([0x22_u8; 32]);
        let bin = runnel_bin()?;

        let mut server = ChildGuard::spawn(
            "wg-noise-macos-server",
            &server_log,
            Command::new(&bin)
                .arg("--log")
                .arg("debug")
                .arg("--config")
                .arg(&empty_config)
                .arg("--log-file")
                .arg(&server_log)
                .arg("wg-server")
                .arg("--engine")
                .arg("noise")
                .arg("--obfs")
                .arg("mask")
                .args(obfs_profile_args())
                .arg("--listen")
                .arg(format!("0.0.0.0:{port}"))
                .arg("--private-key")
                .arg(&server_private)
                .arg("--peer-public-key")
                .arg(&client_public)
                .arg("--device")
                .arg(&server_device)
                .arg("--tunnel-ip")
                .arg(WG_SERVER_IP)
                .arg("--peer-tunnel-ip")
                .arg(WG_CLIENT_IP)
                .arg("--peer-allowed-ip")
                .arg(format!("{WG_CLIENT_IP}/32"))
                .arg("--mtu")
                .arg("1420")
                .arg("--up")
                .arg(macos_ifconfig_up(
                    &server_device,
                    WG_SERVER_IP,
                    WG_CLIENT_IP,
                ))
                .arg("--down")
                .arg(macos_ifconfig_down(&server_device, WG_CLIENT_IP)),
        )?;
        wait_for_log(&server_log, "wg server started", &mut server)?;

        let mut client = ChildGuard::spawn(
            "wg-noise-macos-client",
            &client_log,
            Command::new(&bin)
                .arg("--log")
                .arg("debug")
                .arg("--config")
                .arg(&empty_config)
                .arg("--log-file")
                .arg(&client_log)
                .arg("wg-client")
                .arg("--engine")
                .arg("noise")
                .arg("--obfs")
                .arg("mask")
                .args(obfs_profile_args())
                .arg("--bind")
                .arg("0.0.0.0:0")
                .arg("--endpoint")
                .arg(format!("127.0.0.1:{port}"))
                .arg("--private-key")
                .arg(&client_private)
                .arg("--peer-public-key")
                .arg(&server_public)
                .arg("--device")
                .arg(&client_device)
                .arg("--tunnel-ip")
                .arg(WG_CLIENT_IP)
                .arg("--peer-tunnel-ip")
                .arg(WG_SERVER_IP)
                .arg("--persistent-keepalive-secs")
                .arg("1")
                .arg("--mtu")
                .arg("1420")
                .arg("--up")
                .arg(macos_ifconfig_up(
                    &client_device,
                    WG_CLIENT_IP,
                    WG_SERVER_IP,
                ))
                .arg("--down")
                .arg(macos_ifconfig_down(&client_device, WG_SERVER_IP)),
        )?;
        wait_for_log(&client_log, "wg client started", &mut client)?;

        wait_for_ping(WG_CLIENT_IP, WG_SERVER_IP, &mut server, &mut client)
            .with_context(|| e2e_debug(&server_device, &client_device, &server_log, &client_log))?;

        Ok(())
    }

    fn wait_for_ping(
        source: &str,
        target: &str,
        server: &mut ChildGuard,
        client: &mut ChildGuard,
    ) -> Result<()> {
        let started = Instant::now();
        let mut last = String::new();
        while started.elapsed() < Duration::from_secs(8) {
            server.ensure_running()?;
            client.ensure_running()?;
            let output = Command::new("ping")
                .args(["-c", "1", "-S", source, "-W", "1000", target])
                .output()
                .context("failed to run macOS ping")?;
            if output.status.success() {
                return Ok(());
            }
            last = format_output("ping", &output);
            thread::sleep(Duration::from_millis(250));
        }
        bail!("timed out waiting for WG noise macOS ping to {target}\n{last}");
    }

    fn wait_for_log(path: &Path, needle: &str, child: &mut ChildGuard) -> Result<()> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            child.ensure_running()?;
            if fs::read_to_string(path)
                .unwrap_or_default()
                .contains(needle)
            {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(100));
        }
        bail!(
            "timed out waiting for log line `{needle}` in {}",
            path.display()
        );
    }

    fn macos_ifconfig_up(device: &str, local: &str, peer: &str) -> String {
        format!(
            "ifconfig {device} inet {local} {peer} mtu 1420 up && (route -q -n add -host {peer} -interface {device} >/dev/null 2>&1 || true)"
        )
    }

    fn macos_ifconfig_down(device: &str, peer: &str) -> String {
        format!(
            "route -q -n delete -host {peer} >/dev/null 2>&1 || true; ifconfig {device} down >/dev/null 2>&1 || true"
        )
    }

    fn pick_available_utuns(count: usize) -> Result<Vec<String>> {
        let output = Command::new("ifconfig")
            .arg("-l")
            .output()
            .context("failed to list macOS interfaces")?;
        ensure!(
            output.status.success(),
            "{}",
            format_output("ifconfig -l", &output)
        );
        let interfaces = String::from_utf8_lossy(&output.stdout);
        let in_use = interfaces.split_whitespace().collect::<HashSet<_>>();
        let mut selected = Vec::with_capacity(count);
        for index in 4..256 {
            let candidate = format!("utun{index}");
            if !in_use.contains(candidate.as_str()) {
                selected.push(candidate);
                if selected.len() == count {
                    return Ok(selected);
                }
            }
        }
        bail!("failed to find {count} free utun devices")
    }

    fn free_udp_port() -> Result<u16> {
        let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .context("failed to allocate loopback UDP port")?;
        Ok(socket.local_addr()?.port())
    }

    fn require_command(command: &str) -> Result<()> {
        let status = Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {command} >/dev/null 2>&1"))
            .status()
            .with_context(|| format!("failed to check for command {command}"))?;
        ensure!(
            status.success(),
            "wg noise macOS e2e requires `{command}` to be installed"
        );
        Ok(())
    }

    fn e2e_debug(
        server_device: &str,
        client_device: &str,
        server_log: &Path,
        client_log: &Path,
    ) -> String {
        format!(
            "server log:\n{}\nclient log:\n{}\nserver ifconfig:\n{}\nclient ifconfig:\n{}\nroute to server tunnel ip:\n{}",
            fs::read_to_string(server_log).unwrap_or_default(),
            fs::read_to_string(client_log).unwrap_or_default(),
            command_stdout(["ifconfig", server_device]),
            command_stdout(["ifconfig", client_device]),
            command_stdout(["route", "-n", "get", WG_SERVER_IP]),
        )
    }

    fn command_stdout<const N: usize>(args: [&str; N]) -> String {
        let Some((program, rest)) = args.split_first() else {
            return String::new();
        };
        Command::new(program)
            .args(rest)
            .output()
            .map(|output| {
                format!(
                    "stdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            })
            .unwrap_or_default()
    }

    fn format_output(label: &str, output: &std::process::Output) -> String {
        format!(
            "{label} exited with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    }

    fn runnel_bin() -> Result<String> {
        std::env::var("CARGO_BIN_EXE_runnel").context("cargo did not provide CARGO_BIN_EXE_runnel")
    }

    fn public_key(private_key: [u8; 32]) -> String {
        STANDARD.encode(PublicKey::from(&StaticSecret::from(private_key)).as_bytes())
    }

    struct MacosCleanup {
        devices: Vec<String>,
    }

    impl MacosCleanup {
        fn new(devices: Vec<String>) -> Self {
            Self { devices }
        }
    }

    impl Drop for MacosCleanup {
        fn drop(&mut self) {
            for peer in [WG_SERVER_IP, WG_CLIENT_IP] {
                let _ = Command::new("route")
                    .args(["-q", "-n", "delete", "-host", peer])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            for device in &self.devices {
                let _ = Command::new("ifconfig")
                    .args([device, "down"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }

    struct ChildGuard {
        label: &'static str,
        child: Child,
        log_path: PathBuf,
        stdout_path: PathBuf,
        stderr_path: PathBuf,
    }

    impl ChildGuard {
        fn spawn(label: &'static str, log_path: &Path, command: &mut Command) -> Result<Self> {
            let stdout_path = log_path.with_extension("stdout.log");
            let stderr_path = log_path.with_extension("stderr.log");
            let stdout = fs::File::create(&stdout_path)
                .with_context(|| format!("failed to create {}", stdout_path.display()))?;
            let stderr = fs::File::create(&stderr_path)
                .with_context(|| format!("failed to create {}", stderr_path.display()))?;
            let child = command
                .stdin(Stdio::null())
                .stdout(stdout)
                .stderr(stderr)
                .spawn()
                .with_context(|| format!("failed to spawn {label}"))?;
            Ok(Self {
                label,
                child,
                log_path: log_path.to_path_buf(),
                stdout_path,
                stderr_path,
            })
        }

        fn ensure_running(&mut self) -> Result<()> {
            if let Some(status) = self
                .child
                .try_wait()
                .with_context(|| format!("failed to inspect {}", self.label))?
            {
                bail!(
                    "{} exited early with {status}\nlog:\n{}\nstdout:\n{}\nstderr:\n{}",
                    self.label,
                    fs::read_to_string(&self.log_path).unwrap_or_default(),
                    fs::read_to_string(&self.stdout_path).unwrap_or_default(),
                    fs::read_to_string(&self.stderr_path).unwrap_or_default()
                );
            }
            Ok(())
        }
    }

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            terminate_child(&mut self.child);
        }
    }

    #[cfg(unix)]
    fn terminate_child(child: &mut Child) {
        let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(2) {
            if child.try_wait().ok().flatten().is_some() {
                return;
            }
            thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
    }

    #[cfg(not(unix))]
    fn terminate_child(child: &mut Child) {
        let _ = child.kill();
        let _ = child.wait();
    }
}
