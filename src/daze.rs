use crate::{client::ClientArgs, server::ServerArgs, socks5};
use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tracing::{info, warn};

const ASHE_LIFE_EXPIRED_SECS: u64 = 120;
const ASHE_NET_TCP: u8 = 0x01;

pub async fn run_client(args: ClientArgs) -> Result<()> {
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        server = %args.server,
        mode = "daze-ashe",
        "client listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_client_connection(socket, peer, args).await {
                warn!(peer = %peer, error = %err, "daze-ashe client session ended with error");
            }
        });
    }
}

pub async fn run_server(args: ServerArgs) -> Result<()> {
    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;

    info!(
        listen = %args.listen,
        mode = "daze-ashe",
        "server listening"
    );

    loop {
        let (socket, peer) = listener.accept().await?;
        let args = args.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_server_connection(socket, peer, args).await {
                warn!(peer = %peer, error = %err, "daze-ashe server session ended with error");
            }
        });
    }
}

async fn handle_client_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    args: ClientArgs,
) -> Result<()> {
    inbound.set_nodelay(true)?;
    let target = timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        socks5::accept(&mut inbound),
    )
    .await
    .context("SOCKS handshake timed out")??;
    let target_string = target.to_string();

    if target_string.len() > u8::MAX as usize {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("destination address too long");
    }

    let mut upstream = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&args.server),
    )
    .await
    .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let password = salt(&args.password);
    let mut random = [0_u8; 32];
    fill_random(&mut random);
    upstream.write_all(&random).await?;

    let session_key = xor_key(&random, &password);
    let mut dec = Rc4State::new(&session_key);
    let mut enc = Rc4State::new(&session_key);

    let timestamp = unix_timestamp()?;
    let mut ts = timestamp.to_be_bytes();
    enc.apply_keystream(&mut ts);
    upstream.write_all(&ts).await?;

    let mut open = Vec::with_capacity(2 + target_string.len());
    open.push(ASHE_NET_TCP);
    open.push(target_string.len() as u8);
    open.extend_from_slice(target_string.as_bytes());
    enc.apply_keystream(&mut open);
    upstream.write_all(&open).await?;

    let mut code = [0_u8; 1];
    upstream.read_exact(&mut code).await?;
    dec.apply_keystream(&mut code);
    if code[0] != 0 {
        let _ = socks5::send_failure(&mut inbound, socks5::REP_GENERAL_FAILURE).await;
        bail!("daze-ashe server refused target");
    }

    socks5::send_success(&mut inbound).await?;
    relay_rc4(inbound, upstream, enc, dec).await?;

    info!(peer = %peer, target = %target_string, mode = "daze-ashe", "relay completed");
    Ok(())
}

async fn handle_server_connection(
    mut inbound: TcpStream,
    peer: SocketAddr,
    args: ServerArgs,
) -> Result<()> {
    inbound.set_nodelay(true)?;

    let mut random = [0_u8; 32];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        inbound.read_exact(&mut random),
    )
    .await
    .context("daze-ashe salt read timed out")??;

    let password = salt(&args.password);
    let session_key = xor_key(&random, &password);
    let mut dec = Rc4State::new(&session_key);
    let mut enc = Rc4State::new(&session_key);

    let mut ts = [0_u8; 8];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        inbound.read_exact(&mut ts),
    )
    .await
    .context("daze-ashe timestamp read timed out")??;
    dec.apply_keystream(&mut ts);
    let timestamp = u64::from_be_bytes(ts) as i64;
    validate_timestamp(timestamp)?;

    let mut open_head = [0_u8; 2];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        inbound.read_exact(&mut open_head),
    )
    .await
    .context("daze-ashe request read timed out")??;
    dec.apply_keystream(&mut open_head);
    if open_head[0] != ASHE_NET_TCP {
        let mut code = [1_u8];
        enc.apply_keystream(&mut code);
        inbound.write_all(&code).await?;
        bail!("only tcp is supported in daze-ashe mode");
    }

    let addr_len = open_head[1] as usize;
    let mut address = vec![0_u8; addr_len];
    timeout(
        Duration::from_secs(args.handshake_timeout_secs),
        inbound.read_exact(&mut address),
    )
    .await
    .context("daze-ashe address read timed out")??;
    dec.apply_keystream(&mut address);
    let target = String::from_utf8(address).context("daze-ashe address is not valid UTF-8")?;

    if !args.allow_private_targets && is_private_literal_target(&target) {
        let mut code = [1_u8];
        enc.apply_keystream(&mut code);
        inbound.write_all(&code).await?;
        bail!("literal private IP targets are disabled by default");
    }

    let outbound = timeout(
        Duration::from_secs(args.connect_timeout_secs),
        TcpStream::connect(&target),
    )
    .await
    .context("upstream connect timed out")??;
    outbound.set_nodelay(true)?;

    let mut code = [0_u8];
    enc.apply_keystream(&mut code);
    inbound.write_all(&code).await?;

    relay_rc4(inbound, outbound, dec, enc).await?;

    info!(peer = %peer, target = %target, mode = "daze-ashe", "relay completed");
    Ok(())
}

async fn relay_rc4(
    inbound: TcpStream,
    outbound: TcpStream,
    mut upload_cipher: Rc4State,
    mut download_cipher: Rc4State,
) -> Result<()> {
    let (mut inbound_reader, mut inbound_writer) = inbound.into_split();
    let (mut outbound_reader, mut outbound_writer) = outbound.into_split();

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
        }
    };

    tokio::select! {
        res = uplink => res,
        res = downlink => res,
    }
}

fn salt(password: &str) -> [u8; 32] {
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

fn fill_random(buf: &mut [u8]) {
    use rand::RngCore as _;
    rand::rngs::OsRng.fill_bytes(buf);
}

fn is_private_literal_target(target: &str) -> bool {
    match host_from_target(target).and_then(|host| host.parse::<IpAddr>().ok()) {
        Some(IpAddr::V4(ip)) => {
            ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip == Ipv4Addr::BROADCAST
        }
        Some(IpAddr::V6(ip)) => {
            ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local()
        }
        None => false,
    }
}

fn host_from_target(target: &str) -> Option<&str> {
    if let Some(rest) = target.strip_prefix('[') {
        return rest.split_once(']').map(|(host, _)| host);
    }

    target.rsplit_once(':').map(|(host, _)| host)
}

#[derive(Clone)]
struct Rc4State {
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
            j = j
                .wrapping_add(s[i])
                .wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }

        Self { s, i: 0, j: 0 }
    }

    fn apply_keystream(&mut self, buf: &mut [u8]) {
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
}
