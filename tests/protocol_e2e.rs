mod support;

use anyhow::{Context, Result};
use pipit::{
    client::{self, ClientArgs},
    mode::ProxyMode,
    route::FilterMode,
    server::{self, ServerArgs},
};
use std::{fs, path::PathBuf, sync::OnceLock, time::Duration};
use support::{
    fetch_plain_http, fetch_tls_http_path, free_port, init_test_tracing, socks_connect_ip_reply,
    spawn_http_target, wait_for_tcp_listener, write_temp_cert_pair,
};
use tokio::{sync::Mutex, task::JoinHandle, time::sleep};

static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ProtocolEnv {
    fallback_handle: Option<JoinHandle<()>>,
    server_handle: JoinHandle<()>,
    client_handle: Option<JoinHandle<()>>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
}

impl Drop for ProtocolEnv {
    fn drop(&mut self) {
        self.server_handle.abort();
        if let Some(handle) = &self.fallback_handle {
            handle.abort();
        }
        if let Some(handle) = &self.client_handle {
            handle.abort();
        }
        if let Some(path) = &self.cert_path {
            let _ = fs::remove_file(path);
        }
        if let Some(path) = &self.key_path {
            let _ = fs::remove_file(path);
        }
    }
}

#[tokio::test]
async fn native_http_server_fallback_serves_plain_tls_requests() -> Result<()> {
    let _guard = test_lock().lock().await;
    init_test_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let fallback_port = free_port()?;
    let server_port = free_port()?;
    let fallback_handle = spawn_http_target(fallback_port, |_path, _request| {
        b"native-fallback-ok".to_vec()
    });
    let (cert_path, key_path) = write_temp_cert_pair("pipit-native-fallback")?;

    let _env = start_server(
        ServerArgs {
            listen: format!("127.0.0.1:{server_port}"),
            cert: Some(cert_path.clone()),
            key: Some(key_path.clone()),
            mode: ProxyMode::NativeHttp,
            password: "hello-world".to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            auth_window_secs: 120,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 16 * 1024,
            max_tunnel_body_size: 8 * 1024,
            allow_private_targets: false,
            fallback_url: format!("http://127.0.0.1:{fallback_port}"),
            fallback_timeout_secs: 5,
            max_fallback_body_size: 1024 * 1024,
            wg: Default::default(),
        },
        Some(fallback_handle),
        None,
        Some(cert_path.clone()),
        Some(key_path.clone()),
    )
    .await?;

    let response = fetch_tls_http_path(
        &format!("127.0.0.1:{server_port}"),
        "example.com",
        "/public",
        &cert_path,
    )
    .await?;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "unexpected TLS fallback response: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response.ends_with(b"native-fallback-ok"),
        "unexpected TLS fallback body: {:?}",
        String::from_utf8_lossy(&response)
    );
    Ok(())
}

#[tokio::test]
async fn daze_baboon_server_fallback_serves_plain_http_requests() -> Result<()> {
    let _guard = test_lock().lock().await;
    init_test_tracing();

    let fallback_port = free_port()?;
    let server_port = free_port()?;
    let fallback_handle = spawn_http_target(fallback_port, |_path, _request| {
        b"baboon-fallback-ok".to_vec()
    });

    let _env = start_server(
        ServerArgs {
            listen: format!("127.0.0.1:{server_port}"),
            cert: None,
            key: None,
            mode: ProxyMode::DazeBaboon,
            password: "hello-world".to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            auth_window_secs: 120,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 16 * 1024,
            max_tunnel_body_size: 8 * 1024,
            allow_private_targets: false,
            fallback_url: format!("http://127.0.0.1:{fallback_port}"),
            fallback_timeout_secs: 5,
            max_fallback_body_size: 1024 * 1024,
            wg: Default::default(),
        },
        Some(fallback_handle),
        None,
        None,
        None,
    )
    .await?;

    let response = fetch_plain_http(&format!("127.0.0.1:{server_port}"), "/public").await?;
    assert!(
        response.starts_with(b"HTTP/1.1 200 OK"),
        "unexpected baboon fallback response: {:?}",
        String::from_utf8_lossy(&response)
    );
    assert!(
        response.ends_with(b"baboon-fallback-ok"),
        "unexpected baboon fallback body: {:?}",
        String::from_utf8_lossy(&response)
    );
    Ok(())
}

#[tokio::test]
async fn native_http_mode_rejects_private_literal_targets_by_default() -> Result<()> {
    let _guard = test_lock().lock().await;
    init_test_tracing();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let server_port = free_port()?;
    let socks_port = free_port()?;
    let target_port = free_port()?;
    let (cert_path, key_path) = write_temp_cert_pair("pipit-private-target")?;

    let client_args = ClientArgs {
        listen: format!("127.0.0.1:{socks_port}"),
        server: format!("127.0.0.1:{server_port}"),
        server_name: Some("example.com".to_owned()),
        ca_cert: Some(cert_path.clone()),
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
        max_header_size: 16 * 1024,
        system_proxy: false,
        system_proxy_services: Vec::new(),
        tun_dns_redirect_ip: None,
        tun_dns_upstream: None,
        wg: Default::default(),
    };

    let _env = start_server(
        ServerArgs {
            listen: format!("127.0.0.1:{server_port}"),
            cert: Some(cert_path.clone()),
            key: Some(key_path.clone()),
            mode: ProxyMode::NativeHttp,
            password: "hello-world".to_owned(),
            path: "/connect".to_owned(),
            mux_path: "/mux".to_owned(),
            auth_window_secs: 120,
            handshake_timeout_secs: 10,
            connect_timeout_secs: 10,
            max_header_size: 16 * 1024,
            max_tunnel_body_size: 8 * 1024,
            allow_private_targets: false,
            fallback_url: "http://127.0.0.1:1".to_owned(),
            fallback_timeout_secs: 1,
            max_fallback_body_size: 1024,
            wg: Default::default(),
        },
        None,
        Some(client_args),
        Some(cert_path.clone()),
        Some(key_path.clone()),
    )
    .await?;

    let reply = socks_connect_ip_reply(socks_port, target_port).await?;
    assert_eq!(
        reply, 0x01,
        "expected general failure for private literal target"
    );
    Ok(())
}

async fn start_server(
    server_args: ServerArgs,
    fallback_handle: Option<JoinHandle<()>>,
    client_args: Option<ClientArgs>,
    cert_path: Option<PathBuf>,
    key_path: Option<PathBuf>,
) -> Result<ProtocolEnv> {
    let server_port = pipit::tls::split_host_port(&server_args.listen)?.1;
    let server_handle = tokio::spawn(async move {
        let _ = server::run(server_args).await;
    });
    wait_for_tcp_listener(server_port).await?;
    sleep(Duration::from_millis(50)).await;

    let mut client_handle = None;
    if let Some(client_args) = client_args {
        let socks_port = pipit::tls::split_host_port(&client_args.listen)
            .context("failed to parse client listen address")?
            .1;
        let handle = tokio::spawn(async move {
            let _ = client::run(client_args).await;
        });
        wait_for_tcp_listener(socks_port).await?;
        client_handle = Some(handle);
    }

    Ok(ProtocolEnv {
        fallback_handle,
        server_handle,
        client_handle,
        cert_path,
        key_path,
    })
}

fn test_lock() -> &'static Mutex<()> {
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}
