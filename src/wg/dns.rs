use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tracing::{debug, warn};

use crate::telemetry;

const DNS_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_PACKET: usize = 4096;

pub(crate) struct DnsCaptureGuard {
    handle: JoinHandle<()>,
}

impl Drop for DnsCaptureGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub(crate) async fn start_dns_capture(upstream: IpAddr) -> Result<DnsCaptureGuard> {
    let socket = Arc::new(
        UdpSocket::bind(DNS_LISTEN)
            .await
            .with_context(|| format!("failed to bind WG DNS capture listener on {DNS_LISTEN}"))?,
    );
    let handle = tokio::spawn(run_dns_capture(socket, SocketAddr::new(upstream, 53)));
    Ok(DnsCaptureGuard { handle })
}

async fn run_dns_capture(socket: Arc<UdpSocket>, upstream: SocketAddr) {
    let mut buffer = vec![0u8; MAX_DNS_PACKET];
    loop {
        let Ok((len, client_addr)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let packet = buffer[..len].to_vec();
        if let Some(domain) = parse_dns_query_name(&packet) {
            emit_dns_query(&domain);
        }

        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Err(err) = forward_dns_packet(socket, upstream, client_addr, packet).await {
                debug!(error = %err, "wg dns capture forward failed");
            }
        });
    }
}

async fn forward_dns_packet(
    client_socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    client_addr: SocketAddr,
    packet: Vec<u8>,
) -> Result<()> {
    let bind_addr = if upstream.is_ipv4() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0)
    };
    let upstream_socket = UdpSocket::bind(bind_addr)
        .await
        .context("failed to bind transient WG DNS upstream socket")?;
    upstream_socket
        .send_to(&packet, upstream)
        .await
        .with_context(|| format!("failed to forward WG DNS query to {upstream}"))?;

    let mut response = vec![0u8; MAX_DNS_PACKET];
    let (len, _) = timeout(DNS_TIMEOUT, upstream_socket.recv_from(&mut response))
        .await
        .context("WG DNS upstream response timed out")?
        .context("failed to read WG DNS upstream response")?;
    client_socket
        .send_to(&response[..len], client_addr)
        .await
        .context("failed to return WG DNS response to local client")?;
    Ok(())
}

fn emit_dns_query(domain: &str) {
    let mut fields = BTreeMap::new();
    fields.insert("target".to_owned(), domain.to_owned());
    fields.insert("link".to_owned(), format!("dns://{domain}"));
    fields.insert("route".to_owned(), "wg-dns".to_owned());
    fields.insert("mode".to_owned(), "wg".to_owned());
    telemetry::emit("INFO", "dns query", fields);
}

fn parse_dns_query_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let mut offset = 12usize;
    let mut labels = Vec::new();
    while offset < packet.len() {
        let len = packet[offset];
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0b1100_0000 != 0 {
            warn!("compressed DNS query names are not recorded by WG DNS capture");
            return None;
        }
        let label_len = usize::from(len);
        let end = offset.checked_add(label_len)?;
        if end > packet.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&packet[offset..end]).ok()?.to_owned());
        offset = end;
    }

    (!labels.is_empty()).then(|| labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::parse_dns_query_name;

    #[test]
    fn parses_dns_query_name() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ];

        assert_eq!(
            parse_dns_query_name(&packet),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn rejects_truncated_dns_query_name() {
        let packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
        ];

        assert_eq!(parse_dns_query_name(&packet), None);
    }
}
