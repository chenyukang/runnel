use std::{
    collections::BTreeMap,
    net::IpAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::watch,
    time::{MissedTickBehavior, interval},
};

use crate::telemetry;

#[derive(Clone, Debug, Default)]
pub struct RelayLabels {
    pub target: String,
    pub route: Option<String>,
    pub mode: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RelayStats {
    pub uploaded: u64,
    pub downloaded: u64,
    pub sampled: bool,
    pub display_target: String,
}

pub async fn relay_with_telemetry<A, B>(
    left: A,
    right: B,
    labels: RelayLabels,
) -> io::Result<RelayStats>
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut left_reader, mut left_writer) = tokio::io::split(left);
    let (mut right_reader, mut right_writer) = tokio::io::split(right);
    let display_target = Arc::new(Mutex::new(labels.target.clone()));

    let uploaded = Arc::new(AtomicU64::new(0));
    let downloaded = Arc::new(AtomicU64::new(0));
    let sampled = Arc::new(AtomicBool::new(false));
    let (stop_tx, stop_rx) = watch::channel(false);

    let sampler = tokio::spawn(sample_traffic(
        labels,
        display_target.clone(),
        uploaded.clone(),
        downloaded.clone(),
        sampled.clone(),
        stop_rx,
    ));

    let transfer = tokio::try_join!(
        copy_one_direction(
            &mut left_reader,
            &mut right_writer,
            uploaded.clone(),
            Some(display_target.clone()),
        ),
        copy_one_direction(
            &mut right_reader,
            &mut left_writer,
            downloaded.clone(),
            None
        ),
    );

    let _ = stop_tx.send(true);
    let _ = sampler.await;

    transfer?;

    Ok(RelayStats {
        uploaded: uploaded.load(Ordering::Relaxed),
        downloaded: downloaded.load(Ordering::Relaxed),
        sampled: sampled.load(Ordering::Relaxed),
        display_target: display_target
            .lock()
            .map(|value| value.clone())
            .unwrap_or_else(|_| String::new()),
    })
}

async fn copy_one_direction<R, W>(
    reader: &mut R,
    writer: &mut W,
    total: Arc<AtomicU64>,
    mut display_target: Option<Arc<Mutex<String>>>,
) -> io::Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buf = vec![0_u8; 16 * 1024];
    loop {
        let read = reader.read(&mut buf).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        if let Some(shared) = display_target.take() {
            maybe_update_display_target(&shared, &buf[..read]);
        }
        writer.write_all(&buf[..read]).await?;
        total.fetch_add(read as u64, Ordering::Relaxed);
    }
}

async fn sample_traffic(
    labels: RelayLabels,
    display_target: Arc<Mutex<String>>,
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
                emit_delta(
                    &labels,
                    &display_target,
                    &uploaded,
                    &downloaded,
                    &sampled,
                    &mut last_uploaded,
                    &mut last_downloaded,
                );
            }
            changed = stop_rx.changed() => {
                if changed.is_ok() && *stop_rx.borrow() {
                    emit_delta(
                        &labels,
                        &display_target,
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

fn emit_delta(
    labels: &RelayLabels,
    display_target: &Arc<Mutex<String>>,
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

    if delta_uploaded == 0 && delta_downloaded == 0 {
        return;
    }

    sampled.store(true, Ordering::Relaxed);
    let mut fields = BTreeMap::new();
    let target = display_target
        .lock()
        .map(|value| value.clone())
        .unwrap_or_else(|_| labels.target.clone());
    fields.insert("target".to_owned(), target);
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

fn maybe_update_display_target(shared: &Arc<Mutex<String>>, first_chunk: &[u8]) {
    let current_target = match shared.lock() {
        Ok(value) => value.clone(),
        Err(_) => return,
    };
    let Some(display_target) = infer_display_target(&current_target, first_chunk) else {
        return;
    };
    if let Ok(mut value) = shared.lock() {
        *value = display_target;
    }
}

fn infer_display_target(target: &str, first_chunk: &[u8]) -> Option<String> {
    let (host, port) = split_target(target);
    if host.parse::<IpAddr>().is_err() {
        return None;
    }

    let authority = infer_http_host(first_chunk).or_else(|| infer_tls_sni(first_chunk))?;
    Some(apply_authority_hint(&authority, port))
}

fn infer_http_host(bytes: &[u8]) -> Option<String> {
    let head = std::str::from_utf8(bytes).ok()?;
    let header_end = head.find("\r\n\r\n")?;
    for line in head[..header_end].split("\r\n").skip(1) {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("host") {
            return Some(value.trim().to_owned());
        }
    }
    None
}

fn infer_tls_sni(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 5 || bytes[0] != 22 {
        return None;
    }
    let record_len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
    if bytes.len() < 5 + record_len || record_len < 4 {
        return None;
    }
    let handshake = &bytes[5..5 + record_len];
    if handshake[0] != 1 {
        return None;
    }

    let body_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
    if handshake.len() < 4 + body_len || body_len < 34 {
        return None;
    }
    let mut cursor = 4;

    cursor += 2; // client_version
    cursor += 32; // random

    let session_len = *handshake.get(cursor)? as usize;
    cursor += 1 + session_len;

    let cipher_len =
        u16::from_be_bytes([*handshake.get(cursor)?, *handshake.get(cursor + 1)?]) as usize;
    cursor += 2 + cipher_len;

    let compression_len = *handshake.get(cursor)? as usize;
    cursor += 1 + compression_len;

    let extensions_len =
        u16::from_be_bytes([*handshake.get(cursor)?, *handshake.get(cursor + 1)?]) as usize;
    cursor += 2;
    let extensions_end = cursor.checked_add(extensions_len)?;
    if extensions_end > handshake.len() {
        return None;
    }

    while cursor + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]);
        let ext_len = u16::from_be_bytes([handshake[cursor + 2], handshake[cursor + 3]]) as usize;
        cursor += 4;
        let ext_end = cursor.checked_add(ext_len)?;
        if ext_end > extensions_end {
            return None;
        }

        if ext_type == 0 {
            if cursor + 2 > ext_end {
                return None;
            }
            let list_len = u16::from_be_bytes([handshake[cursor], handshake[cursor + 1]]) as usize;
            let mut list_cursor = cursor + 2;
            let list_end = list_cursor.checked_add(list_len)?;
            if list_end > ext_end {
                return None;
            }

            while list_cursor + 3 <= list_end {
                let name_type = handshake[list_cursor];
                let name_len =
                    u16::from_be_bytes([handshake[list_cursor + 1], handshake[list_cursor + 2]])
                        as usize;
                list_cursor += 3;
                let name_end = list_cursor.checked_add(name_len)?;
                if name_end > list_end {
                    return None;
                }
                if name_type == 0 {
                    return std::str::from_utf8(&handshake[list_cursor..name_end])
                        .ok()
                        .map(str::to_owned);
                }
                list_cursor = name_end;
            }
            return None;
        }

        cursor = ext_end;
    }

    None
}

fn apply_authority_hint(authority: &str, fallback_port: Option<u16>) -> String {
    let authority = authority.trim();
    let (host, port) = split_target(authority);
    format_target(&host, port.or(fallback_port))
}

fn format_target(host: &str, port: Option<u16>) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    match port {
        Some(port) => format!("{host}:{port}"),
        None => host,
    }
}

fn split_target(target: &str) -> (String, Option<u16>) {
    if let Some(rest) = target.strip_prefix('[')
        && let Some((host, suffix)) = rest.split_once(']')
    {
        let port = suffix.strip_prefix(':').and_then(|port| port.parse().ok());
        return (host.to_owned(), port);
    }

    if let Some((host, port)) = target.rsplit_once(':')
        && let Ok(port) = port.parse::<u16>()
    {
        return (host.to_owned(), Some(port));
    }

    (target.to_owned(), None)
}

#[cfg(test)]
mod tests {
    use super::{apply_authority_hint, infer_display_target};

    #[test]
    fn http_host_hint_rewrites_ip_target() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n";
        let inferred = infer_display_target("1.1.1.1:443", request);
        assert_eq!(inferred.as_deref(), Some("example.com:443"));
    }

    #[test]
    fn tls_sni_hint_rewrites_ip_target() {
        let hello = tls_client_hello("example.com");
        let inferred = infer_display_target("1.1.1.1:443", &hello);
        assert_eq!(inferred.as_deref(), Some("example.com:443"));
    }

    #[test]
    fn authority_hint_keeps_explicit_port() {
        assert_eq!(
            apply_authority_hint("example.com:8443", Some(443)),
            "example.com:8443"
        );
    }

    fn tls_client_hello(host: &str) -> Vec<u8> {
        let host = host.as_bytes();
        let mut server_name_entry = Vec::new();
        server_name_entry.push(0);
        server_name_entry.extend_from_slice(&(host.len() as u16).to_be_bytes());
        server_name_entry.extend_from_slice(host);

        let mut server_name = Vec::new();
        server_name.extend_from_slice(&(server_name_entry.len() as u16).to_be_bytes());
        server_name.extend_from_slice(&server_name_entry);

        let mut ext = Vec::new();
        ext.extend_from_slice(&0_u16.to_be_bytes());
        ext.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        ext.extend_from_slice(&server_name);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0_u8; 32]);
        body.push(0);
        body.extend_from_slice(&2_u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(1);
        body.push(0);
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut handshake = Vec::new();
        handshake.push(1);
        let body_len = body.len() as u32;
        handshake.extend_from_slice(&body_len.to_be_bytes()[1..]);
        handshake.extend_from_slice(&body);

        let mut record = Vec::new();
        record.push(22);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }
}
