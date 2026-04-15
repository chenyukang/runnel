mod support;

use anyhow::{Context, Result};
use std::{fs, process::Command};
use support::TempDir;

#[test]
fn tun_dry_run_from_config_prints_helper_and_hooks() -> Result<()> {
    let temp_dir = TempDir::new("pipit-tun-cli")?;
    let config_path = temp_dir.join("pipit.yaml");
    let log_path = temp_dir.join("proxy.log");
    fs::write(
        &config_path,
        r#"
client:
  server: 127.0.0.1:9
  password: hello-world
tun:
  device: testtun0
  helper_cmd: echo helper {device} {socks}
  up:
    - echo up {device}
  down:
    - echo down {device}
  dry_run: true
"#,
    )?;

    let output = Command::new(pipit_bin()?)
        .current_dir(temp_dir.path())
        .args([
            "--log-file",
            log_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "tun",
        ])
        .output()
        .context("failed to run pipit tun dry-run")?;
    assert!(
        output.status.success(),
        "tun dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("pipit tun plan"));
    assert!(stdout.contains("helper: echo helper testtun0 127.0.0.1:1080"));
    assert!(stdout.contains("echo up testtun0"));
    assert!(stdout.contains("echo down testtun0"));
    Ok(())
}

#[test]
fn tun_dry_run_uses_env_helper_as_tun2proxy_command() -> Result<()> {
    let temp_dir = TempDir::new("pipit-tun-helper-env")?;
    let helper_path = temp_dir.join("tun2socks");
    let config_path = temp_dir.join("pipit.yaml");
    let log_path = temp_dir.join("proxy.log");
    fs::write(&helper_path, "#!/bin/sh\nexit 0\n")?;
    fs::write(
        &config_path,
        r#"
client:
  server: 127.0.0.1:9
  password: hello-world
tun:
  device: testtun1
  up:
    - echo up {device}
  down:
    - echo down {device}
  dry_run: true
"#,
    )?;

    let output = Command::new(pipit_bin()?)
        .current_dir(temp_dir.path())
        .args([
            "--log-file",
            log_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "tun",
        ])
        .env("PIPIT_TUN_HELPER", &helper_path)
        .output()
        .context("failed to run pipit tun with env helper")?;
    assert!(
        output.status.success(),
        "tun dry-run with env helper failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!(
        "helper: '{}' --tun testtun1 --proxy socks5://127.0.0.1:1080 --dns direct --verbosity warn --exit-on-fatal-error",
        helper_path.display()
    );
    assert!(stdout.contains(&expected), "unexpected stdout: {stdout}");
    assert!(
        !stdout.contains("-device testtun1"),
        "unexpected legacy helper args: {stdout}"
    );
    Ok(())
}

#[test]
fn tun_cli_flag_overrides_configured_helper_command() -> Result<()> {
    let temp_dir = TempDir::new("pipit-tun-helper-override")?;
    let config_path = temp_dir.join("pipit.yaml");
    let log_path = temp_dir.join("proxy.log");
    fs::write(
        &config_path,
        r#"
client:
  server: 127.0.0.1:9
  password: hello-world
tun:
  device: testtun2
  helper_cmd: echo config {device}
  up:
    - echo up {device}
  down:
    - echo down {device}
  dry_run: true
"#,
    )?;

    let output = Command::new(pipit_bin()?)
        .current_dir(temp_dir.path())
        .args([
            "--log-file",
            log_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "tun",
            "--helper-cmd",
            "echo cli {device}",
        ])
        .output()
        .context("failed to run pipit tun with CLI helper override")?;
    assert!(
        output.status.success(),
        "tun dry-run with helper override failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("helper: echo cli testtun2"),
        "unexpected stdout: {stdout}"
    );
    assert!(
        !stdout.contains("helper: echo config testtun2"),
        "config helper should have been overridden: {stdout}"
    );
    Ok(())
}

#[test]
fn tun_dry_run_rejects_inherited_daze_mode_from_client_config() -> Result<()> {
    let temp_dir = TempDir::new("pipit-tun-mode-reject")?;
    let config_path = temp_dir.join("pipit.client.yaml");
    let log_path = temp_dir.join("proxy.log");
    fs::write(
        &config_path,
        r#"
client:
  server: 127.0.0.1:9
  password: hello-world
  mode: daze-ashe
  system_proxy: true
tun:
  dry_run: true
"#,
    )?;

    let output = Command::new(pipit_bin()?)
        .current_dir(temp_dir.path())
        .args([
            "--log-file",
            log_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "tun",
        ])
        .output()
        .context("failed to run pipit tun with inherited daze mode")?;
    assert!(
        !output.status.success(),
        "tun should reject daze mode: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("client mode=native-http"),
        "unexpected stderr: {stderr}"
    );
    assert!(stderr.contains("daze-ashe"), "unexpected stderr: {stderr}");
    Ok(())
}

#[test]
fn tun_dry_run_rejects_legacy_mux_flag() -> Result<()> {
    let temp_dir = TempDir::new("pipit-tun-mux-reject")?;
    let config_path = temp_dir.join("pipit.yaml");
    let log_path = temp_dir.join("proxy.log");
    fs::write(
        &config_path,
        r#"
client:
  server: 127.0.0.1:9
  password: hello-world
tun:
  dry_run: true
"#,
    )?;

    let output = Command::new(pipit_bin()?)
        .current_dir(temp_dir.path())
        .args([
            "--log-file",
            log_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
            "tun",
            "--mux",
        ])
        .output()
        .context("failed to run pipit tun with legacy mux flag")?;
    assert!(
        !output.status.success(),
        "tun should reject native-mux: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("client mode=native-http"),
        "unexpected stderr: {stderr}"
    );
    assert!(stderr.contains("native-mux"), "unexpected stderr: {stderr}");
    Ok(())
}

fn pipit_bin() -> Result<String> {
    std::env::var("CARGO_BIN_EXE_pipit").context("cargo did not provide CARGO_BIN_EXE_pipit")
}
