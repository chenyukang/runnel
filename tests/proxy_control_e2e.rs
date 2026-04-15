mod support;

use anyhow::Result;
use pipit::{
    client::{self, ClientArgs},
    mode::ProxyMode,
    route::FilterMode,
};
use std::{fs, path::PathBuf, sync::OnceLock, time::Duration};
use support::{
    TempDir, fetch_via_socks_ip_path, free_port, init_test_tracing, socks_connect_domain_reply,
    spawn_http_target, wait_for_tcp_listener,
};
use tokio::{sync::Mutex, task::JoinHandle, time::sleep};

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ClientEnv {
    _target_handle: Option<JoinHandle<()>>,
    _client_handle: JoinHandle<()>,
    _temp_dir: Option<TempDir>,
    _rule_file: Option<PathBuf>,
}

impl Drop for ClientEnv {
    fn drop(&mut self) {
        self._client_handle.abort();
        if let Some(handle) = &self._target_handle {
            handle.abort();
        }
        if let Some(path) = &self._rule_file {
            let _ = fs::remove_file(path);
        }
    }
}

#[tokio::test]
async fn direct_filter_bypasses_unreachable_server() -> Result<()> {
    let _guard = test_lock().lock().await;
    init_test_tracing();

    let target_port = free_port()?;
    let server_port = free_port()?;
    let socks_port = free_port()?;
    let target_handle = spawn_http_target(target_port, |_path, _request| b"direct-ok".to_vec());

    let _env = start_client(
        socks_port,
        server_port,
        FilterMode::Direct,
        None,
        Some(target_handle),
    )
    .await?;

    let body = fetch_via_socks_ip_path(socks_port, target_port, "/").await?;
    assert!(
        body.ends_with(b"direct-ok"),
        "unexpected direct response body: {:?}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

#[tokio::test]
async fn rule_filter_uses_reserved_ip_direct_path_when_server_is_down() -> Result<()> {
    let _guard = test_lock().lock().await;
    init_test_tracing();

    let target_port = free_port()?;
    let server_port = free_port()?;
    let socks_port = free_port()?;
    let target_handle = spawn_http_target(target_port, |_path, _request| {
        b"reserved-direct-ok".to_vec()
    });

    let _env = start_client(
        socks_port,
        server_port,
        FilterMode::Rule,
        None,
        Some(target_handle),
    )
    .await?;

    let body = fetch_via_socks_ip_path(socks_port, target_port, "/").await?;
    assert!(
        body.ends_with(b"reserved-direct-ok"),
        "unexpected rule-direct response body: {:?}",
        String::from_utf8_lossy(&body)
    );
    Ok(())
}

#[tokio::test]
async fn rule_filter_blocks_matching_domain_before_dns_resolution() -> Result<()> {
    let _guard = test_lock().lock().await;
    init_test_tracing();

    let temp_dir = TempDir::new("pipit-rule-e2e")?;
    let rule_file = temp_dir.join("rules.ls");
    fs::write(&rule_file, "B blocked.invalid\n")?;

    let server_port = free_port()?;
    let socks_port = free_port()?;
    let _env = start_client(
        socks_port,
        server_port,
        FilterMode::Rule,
        Some(rule_file.clone()),
        None,
    )
    .await?
    .with_temp_dir(temp_dir, rule_file);

    let reply = socks_connect_domain_reply(socks_port, "blocked.invalid", 80).await?;
    assert_eq!(reply, 0x01, "expected general failure for blocked target");
    Ok(())
}

impl ClientEnv {
    fn with_temp_dir(mut self, temp_dir: TempDir, rule_file: PathBuf) -> Self {
        self._temp_dir = Some(temp_dir);
        self._rule_file = Some(rule_file);
        self
    }
}

async fn start_client(
    socks_port: u16,
    server_port: u16,
    filter: FilterMode,
    rule_file: Option<PathBuf>,
    target_handle: Option<JoinHandle<()>>,
) -> Result<ClientEnv> {
    let client_args = ClientArgs {
        listen: format!("127.0.0.1:{socks_port}"),
        server: format!("127.0.0.1:{server_port}"),
        server_name: None,
        ca_cert: None,
        mode: ProxyMode::DazeAshe,
        password: "hello-world".to_owned(),
        path: "/connect".to_owned(),
        mux_path: "/mux".to_owned(),
        mux: false,
        filter,
        rule_file,
        cidr_file: None,
        user_agent: "pipit-test".to_owned(),
        handshake_timeout_secs: 10,
        connect_timeout_secs: 1,
        max_header_size: 16 * 1024,
        system_proxy: false,
        system_proxy_services: Vec::new(),
    };

    let client_handle = tokio::spawn(async move {
        let _ = client::run(client_args).await;
    });
    wait_for_tcp_listener(socks_port).await?;
    sleep(Duration::from_millis(50)).await;

    Ok(ClientEnv {
        _target_handle: target_handle,
        _client_handle: client_handle,
        _temp_dir: None,
        _rule_file: None,
    })
}

fn test_lock() -> &'static Mutex<()> {
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}
