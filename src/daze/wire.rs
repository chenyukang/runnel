use crate::{
    proxy::{auth::AUTH_FAILURE_HINT, traffic},
    runtime::ServerRuntime,
    telemetry,
};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::Arc,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::{MissedTickBehavior, interval, timeout},
};

const ASHE_LIFE_EXPIRED_SECS: u64 = 120;
const ASHE_NET_TCP: u8 = 0x01;

pub(crate) async fn client_establish_ashe<S>(
    stream: &mut S,
    password: &str,
    target: &str,
) -> Result<(Rc4State, Rc4State)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let password = salt(password);
    let mut random = [0_u8; 32];
    fill_random(&mut random);
    stream.write_all(&random).await?;

    let session_key = xor_key(&random, &password);
    let mut dec = Rc4State::new(&session_key);
    let mut enc = Rc4State::new(&session_key);

    let timestamp = unix_timestamp()?;
    let mut ts = timestamp.to_be_bytes();
    enc.apply_keystream(&mut ts);
    stream.write_all(&ts).await?;

    let mut open = Vec::with_capacity(2 + target.len());
    open.push(ASHE_NET_TCP);
    open.push(target.len() as u8);
    open.extend_from_slice(target.as_bytes());
    enc.apply_keystream(&mut open);
    stream.write_all(&open).await?;

    let mut code = [0_u8; 1];
    stream
        .read_exact(&mut code)
        .await
        .with_context(|| format!("daze-ashe response read failed; {AUTH_FAILURE_HINT}"))?;
    dec.apply_keystream(&mut code);
    if code[0] != 0 {
        bail!("daze-ashe server refused target");
    }

    Ok((enc, dec))
}

pub(crate) async fn server_accept_ashe<S>(
    stream: &mut S,
    runtime: &ServerRuntime,
) -> Result<(Rc4State, Rc4State, String)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut random = [0_u8; 32];
    timeout(runtime.handshake_timeout, stream.read_exact(&mut random))
        .await
        .context("daze-ashe salt read timed out")??;

    let password = salt(&runtime.password);
    let session_key = xor_key(&random, &password);
    let mut dec = Rc4State::new(&session_key);
    let enc = Rc4State::new(&session_key);

    let mut ts = [0_u8; 8];
    timeout(runtime.handshake_timeout, stream.read_exact(&mut ts))
        .await
        .context("daze-ashe timestamp read timed out")??;
    dec.apply_keystream(&mut ts);
    let timestamp = u64::from_be_bytes(ts) as i64;
    validate_timestamp(timestamp)
        .with_context(|| format!("daze-ashe authentication failed; {AUTH_FAILURE_HINT}"))?;

    let mut open_head = [0_u8; 2];
    timeout(runtime.handshake_timeout, stream.read_exact(&mut open_head))
        .await
        .context("daze-ashe request read timed out")??;
    dec.apply_keystream(&mut open_head);
    if open_head[0] != ASHE_NET_TCP {
        bail!("daze-ashe authentication failed or unsupported request type; {AUTH_FAILURE_HINT}");
    }

    let addr_len = open_head[1] as usize;
    let mut address = vec![0_u8; addr_len];
    timeout(runtime.handshake_timeout, stream.read_exact(&mut address))
        .await
        .context("daze-ashe address read timed out")??;
    dec.apply_keystream(&mut address);
    let target = String::from_utf8(address)
        .with_context(|| format!("daze-ashe address decode failed; {AUTH_FAILURE_HINT}"))?;

    Ok((dec, enc, target))
}

pub(crate) async fn relay_rc4<A, B>(
    inbound: A,
    outbound: B,
    mut upload_cipher: Rc4State,
    mut download_cipher: Rc4State,
    labels: traffic::RelayLabels,
) -> Result<traffic::RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(inbound);
    let (mut outbound_reader, mut outbound_writer) = tokio::io::split(outbound);
    let uploaded = Arc::new(AtomicU64::new(0));
    let downloaded = Arc::new(AtomicU64::new(0));
    let sampled = Arc::new(AtomicBool::new(false));
    let sampler = if telemetry::has_live_subscribers() {
        let (stop_tx, stop_rx) = watch::channel(false);
        let task = tokio::spawn(sample_rc4_traffic(
            labels.clone(),
            uploaded.clone(),
            downloaded.clone(),
            sampled.clone(),
            stop_rx,
        ));
        Some((stop_tx, task))
    } else {
        None
    };

    let uplink = async {
        let mut buf = vec![0_u8; 32 * 1024];
        loop {
            let n = inbound_reader.read(&mut buf).await?;
            if n == 0 {
                let _ = outbound_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }

            let mut chunk = buf[..n].to_vec();
            upload_cipher.apply_keystream(&mut chunk);
            outbound_writer.write_all(&chunk).await?;
            uploaded.fetch_add(n as u64, Ordering::Relaxed);
        }
    };

    let downlink = async {
        let mut buf = vec![0_u8; 32 * 1024];
        loop {
            let n = outbound_reader.read(&mut buf).await?;
            if n == 0 {
                let _ = inbound_writer.shutdown().await;
                return Ok::<(), anyhow::Error>(());
            }

            let mut chunk = buf[..n].to_vec();
            download_cipher.apply_keystream(&mut chunk);
            inbound_writer.write_all(&chunk).await?;
            downloaded.fetch_add(n as u64, Ordering::Relaxed);
        }
    };

    let relay = tokio::select! {
        res = uplink => res,
        res = downlink => res,
    };

    if let Some((stop_tx, task)) = sampler {
        let _ = stop_tx.send(true);
        let _ = task.await;
    }

    relay?;

    Ok(traffic::RelayStats {
        uploaded: uploaded.load(Ordering::Relaxed),
        downloaded: downloaded.load(Ordering::Relaxed),
        sampled: sampled.load(Ordering::Relaxed),
        display_target: labels.target,
    })
}

async fn sample_rc4_traffic(
    labels: traffic::RelayLabels,
    uploaded: Arc<AtomicU64>,
    downloaded: Arc<AtomicU64>,
    sampled: Arc<AtomicBool>,
    mut stop_rx: watch::Receiver<bool>,
) {
    let mut last_uploaded = 0_u64;
    let mut last_downloaded = 0_u64;
    let mut ticker = interval(Duration::from_secs(1));
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                emit_rc4_delta(
                    &labels,
                    &uploaded,
                    &downloaded,
                    &sampled,
                    &mut last_uploaded,
                    &mut last_downloaded,
                );
            }
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    emit_rc4_delta(
                        &labels,
                        &uploaded,
                        &downloaded,
                        &sampled,
                        &mut last_uploaded,
                        &mut last_downloaded,
                    );
                    return;
                }
            }
        }
    }
}

fn emit_rc4_delta(
    labels: &traffic::RelayLabels,
    uploaded: &AtomicU64,
    downloaded: &AtomicU64,
    sampled: &AtomicBool,
    last_uploaded: &mut u64,
    last_downloaded: &mut u64,
) {
    let current_uploaded = uploaded.load(Ordering::Relaxed);
    let current_downloaded = downloaded.load(Ordering::Relaxed);
    let delta_uploaded = current_uploaded.saturating_sub(*last_uploaded);
    let delta_downloaded = current_downloaded.saturating_sub(*last_downloaded);

    *last_uploaded = current_uploaded;
    *last_downloaded = current_downloaded;

    if (delta_uploaded == 0 && delta_downloaded == 0) || !telemetry::has_live_subscribers() {
        return;
    }

    sampled.store(true, Ordering::Relaxed);
    let mut fields = BTreeMap::new();
    fields.insert("target".to_owned(), labels.target.clone());
    fields.insert("uploaded".to_owned(), delta_uploaded.to_string());
    fields.insert("downloaded".to_owned(), delta_downloaded.to_string());
    if let Some(route) = &labels.route {
        fields.insert("route".to_owned(), route.clone());
    }
    if let Some(mode) = &labels.mode {
        fields.insert("mode".to_owned(), mode.clone());
    }
    telemetry::emit("INFO", "traffic sample", fields);
}

pub(super) fn salt(password: &str) -> [u8; 32] {
    Sha256::digest(password.as_bytes()).into()
}

fn xor_key(random: &[u8; 32], password: &[u8; 32]) -> [u8; 32] {
    let mut key = [0_u8; 32];
    for (idx, byte) in key.iter_mut().enumerate() {
        *byte = random[idx] ^ password[idx];
    }
    key
}

fn validate_timestamp(timestamp: i64) -> Result<()> {
    let now = unix_timestamp()?;
    let skew = now.abs_diff(timestamp);
    if skew > ASHE_LIFE_EXPIRED_SECS {
        bail!("daze-ashe request expired");
    }
    Ok(())
}

fn unix_timestamp() -> Result<i64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock before unix epoch")?;
    Ok(now.as_secs() as i64)
}

pub(super) fn fill_random(buf: &mut [u8]) {
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(buf);
}

#[derive(Clone)]
pub(crate) struct Rc4State {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4State {
    fn new(key: &[u8]) -> Self {
        let mut s = [0_u8; 256];
        for (idx, byte) in s.iter_mut().enumerate() {
            *byte = idx as u8;
        }

        let mut j = 0_u8;
        for i in 0..256 {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    pub(crate) fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let idx = self.s[self.i as usize].wrapping_add(self.s[self.j as usize]);
            *byte ^= self.s[idx as usize];
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::ServerRuntime;
    use tokio::io::duplex;

    #[test]
    fn rc4_round_trip() {
        let key = [7_u8; 32];
        let mut enc = Rc4State::new(&key);
        let mut dec = Rc4State::new(&key);
        let mut data = b"hello world".to_vec();
        enc.apply_keystream(&mut data);
        dec.apply_keystream(&mut data);
        assert_eq!(data, b"hello world");
    }

    #[tokio::test]
    async fn ashe_password_mismatch_reports_auth_hint() {
        let (mut client_io, mut server_io) = duplex(1024);
        let server_runtime = ServerRuntime {
            listen: "127.0.0.1:0".to_owned(),
            password: "server-secret".to_owned(),
            mux_path: "/mux".to_owned(),
            handshake_timeout: Duration::from_secs(1),
            connect_timeout: Duration::from_secs(10),
            max_header_size: 16 * 1024,
            max_tunnel_body_size: 8 * 1024,
            allow_private_targets: true,
            fallback_url: "https://www.qq.com".to_owned(),
            fallback_timeout: Duration::from_secs(15),
            max_fallback_body_size: 1024 * 1024,
        };

        let server_task =
            tokio::spawn(async move { server_accept_ashe(&mut server_io, &server_runtime).await });
        let client_err =
            match client_establish_ashe(&mut client_io, "client-secret", "example.com:80").await {
                Ok(_) => panic!("wrong password should fail client handshake"),
                Err(err) => err.to_string(),
            };
        let server_err = match server_task.await.unwrap() {
            Ok(_) => panic!("wrong password should fail server handshake"),
            Err(err) => err.to_string(),
        };

        assert!(client_err.contains(AUTH_FAILURE_HINT), "{client_err}");
        assert!(server_err.contains(AUTH_FAILURE_HINT), "{server_err}");
    }
}
