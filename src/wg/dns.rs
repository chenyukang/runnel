use anyhow::{Context, Result};
use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tracing::{debug, warn};

use crate::{
    proxy::{
        adblock::Adblocker,
        route::{self, RouteDecision, RouteRuleConfig},
    },
    telemetry,
};

use super::hooks::DynamicRouteManager;

const DNS_LISTEN: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_PACKET: usize = 4096;

pub(crate) struct DnsCaptureGuard {
    handle: JoinHandle<()>,
}

#[derive(Clone)]
pub(crate) struct DomainRuleEngine {
    rules: RouteRuleConfig,
    dynamic_routes: Option<Arc<DynamicRouteManager>>,
    adblock: Option<Arc<Adblocker>>,
}

impl Drop for DnsCaptureGuard {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl DomainRuleEngine {
    pub(crate) fn new(
        rules: RouteRuleConfig,
        dynamic_routes: Option<Arc<DynamicRouteManager>>,
        adblock: Option<Arc<Adblocker>>,
    ) -> Self {
        Self {
            rules,
            dynamic_routes,
            adblock,
        }
    }

    async fn decide(&self, domain: &str) -> Result<RouteDecision> {
        decide_domain_rules(&self.rules, self.adblock.as_deref(), domain).await
    }

    fn apply_response_routes(&self, domain: &str, response: &[u8]) -> Result<()> {
        let Some(dynamic_routes) = &self.dynamic_routes else {
            return Ok(());
        };
        for ip in parse_dns_answer_ips(response) {
            if dynamic_routes.add_direct_host(domain, ip)? {
                debug!(domain = %domain, ip = %ip, "wg domain direct route installed");
            }
        }
        Ok(())
    }
}

async fn decide_domain_rules(
    rules: &RouteRuleConfig,
    adblock: Option<&Adblocker>,
    domain: &str,
) -> Result<RouteDecision> {
    if route::matches_domain_rules(&rules.block, domain)? {
        return Ok(RouteDecision::Block);
    }
    if let Some(adblock) = adblock
        && adblock.blocks_domain(domain).await
    {
        return Ok(RouteDecision::Block);
    }
    if route::matches_domain_rules(&rules.direct, domain)? {
        return Ok(RouteDecision::Direct);
    }
    if route::matches_domain_rules(&rules.proxy, domain)? {
        return Ok(RouteDecision::Remote);
    }
    Ok(RouteDecision::Remote)
}

pub(crate) async fn start_dns_capture(
    upstream: IpAddr,
    domain_rules: Option<DomainRuleEngine>,
) -> Result<DnsCaptureGuard> {
    let socket = Arc::new(
        UdpSocket::bind(DNS_LISTEN)
            .await
            .with_context(|| format!("failed to bind WG DNS capture listener on {DNS_LISTEN}"))?,
    );
    let handle = tokio::spawn(run_dns_capture(
        socket,
        SocketAddr::new(upstream, 53),
        domain_rules,
    ));
    Ok(DnsCaptureGuard { handle })
}

async fn run_dns_capture(
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    domain_rules: Option<DomainRuleEngine>,
) {
    let mut buffer = vec![0u8; MAX_DNS_PACKET];
    loop {
        let Ok((len, client_addr)) = socket.recv_from(&mut buffer).await else {
            continue;
        };
        let packet = buffer[..len].to_vec();
        let domain = parse_dns_query_name(&packet);
        let decision = match (&domain_rules, domain.as_deref()) {
            (Some(rules), Some(domain)) => match rules.decide(domain).await {
                Ok(decision) => decision,
                Err(err) => {
                    warn!(domain = %domain, error = %err, "wg DNS domain rule evaluation failed");
                    RouteDecision::Remote
                }
            },
            _ => RouteDecision::Remote,
        };

        if let Some(domain) = &domain {
            emit_dns_query(domain, decision);
        }

        if matches!(decision, RouteDecision::Block)
            && let Some(response) = nxdomain_response(&packet)
        {
            if let Err(err) = socket.send_to(&response, client_addr).await {
                debug!(error = %err, "wg dns capture block response failed");
            }
            continue;
        }

        let socket = Arc::clone(&socket);
        let domain_rules = domain_rules.clone();
        tokio::spawn(async move {
            if let Err(err) = forward_dns_packet(
                socket,
                upstream,
                client_addr,
                packet,
                domain,
                decision,
                domain_rules,
            )
            .await
            {
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
    domain: Option<String>,
    decision: RouteDecision,
    domain_rules: Option<DomainRuleEngine>,
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
    if matches!(decision, RouteDecision::Direct)
        && let (Some(domain), Some(rules)) = (domain.as_deref(), domain_rules.as_ref())
        && let Err(err) = rules.apply_response_routes(domain, &response[..len])
    {
        warn!(domain = %domain, error = %err, "wg DNS domain direct route failed");
    }
    client_socket
        .send_to(&response[..len], client_addr)
        .await
        .context("failed to return WG DNS response to local client")?;
    Ok(())
}

fn emit_dns_query(domain: &str, decision: RouteDecision) {
    let mut fields = BTreeMap::new();
    fields.insert("target".to_owned(), domain.to_owned());
    fields.insert("link".to_owned(), format!("dns://{domain}"));
    fields.insert(
        "route".to_owned(),
        match decision {
            RouteDecision::Direct => "wg-dns-direct",
            RouteDecision::Remote => "wg-dns",
            RouteDecision::Block => "wg-dns-block",
        }
        .to_owned(),
    );
    fields.insert("mode".to_owned(), "wg".to_owned());
    telemetry::emit("INFO", "dns query", fields);
}

fn parse_dns_query_name(packet: &[u8]) -> Option<String> {
    parse_dns_question(packet).map(|question| question.name)
}

struct DnsQuestion {
    name: String,
    end: usize,
}

fn parse_dns_question(packet: &[u8]) -> Option<DnsQuestion> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }

    let (name, offset) = parse_dns_name(packet, 12)?;
    let end = offset.checked_add(4)?;
    if end > packet.len() {
        return None;
    }

    (!name.is_empty()).then_some(DnsQuestion { name, end })
}

fn parse_dns_answer_ips(packet: &[u8]) -> Vec<IpAddr> {
    let Some(mut question) = parse_dns_question(packet) else {
        return Vec::new();
    };
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    for _ in 1..qdcount {
        let Some((_, offset)) = parse_dns_name(packet, question.end) else {
            return Vec::new();
        };
        let Some(end) = offset.checked_add(4) else {
            return Vec::new();
        };
        if end > packet.len() {
            return Vec::new();
        }
        question.end = end;
    }

    let ancount = u16::from_be_bytes([packet[6], packet[7]]);
    let mut offset = question.end;
    let mut ips = Vec::new();
    for _ in 0..ancount {
        let Some((_, rr_offset)) = parse_dns_name(packet, offset) else {
            return ips;
        };
        let Some(header_end) = rr_offset.checked_add(10) else {
            return ips;
        };
        if header_end > packet.len() {
            return ips;
        }

        let rr_type = u16::from_be_bytes([packet[rr_offset], packet[rr_offset + 1]]);
        let rr_class = u16::from_be_bytes([packet[rr_offset + 2], packet[rr_offset + 3]]);
        let rdlen = usize::from(u16::from_be_bytes([
            packet[rr_offset + 8],
            packet[rr_offset + 9],
        ]));
        let Some(rdata_end) = header_end.checked_add(rdlen) else {
            return ips;
        };
        if rdata_end > packet.len() {
            return ips;
        }

        if rr_class == 1 && rr_type == 1 && rdlen == 4 {
            ips.push(IpAddr::V4(Ipv4Addr::new(
                packet[header_end],
                packet[header_end + 1],
                packet[header_end + 2],
                packet[header_end + 3],
            )));
        } else if rr_class == 1 && rr_type == 28 && rdlen == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&packet[header_end..rdata_end]);
            ips.push(IpAddr::V6(octets.into()));
        }
        offset = rdata_end;
    }
    ips
}

fn parse_dns_name(packet: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut next_offset = offset;
    let mut steps = 0usize;
    loop {
        steps += 1;
        if steps > 128 || offset >= packet.len() {
            return None;
        }
        let len = packet[offset];
        if len & 0b1100_0000 == 0b1100_0000 {
            let pointer_end = offset.checked_add(2)?;
            if pointer_end > packet.len() {
                return None;
            }
            let pointer = (usize::from(len & 0b0011_1111) << 8) | usize::from(packet[offset + 1]);
            if !jumped {
                next_offset = pointer_end;
            }
            offset = pointer;
            jumped = true;
            continue;
        }
        if len & 0b1100_0000 != 0 {
            return None;
        }

        offset += 1;
        if len == 0 {
            if !jumped {
                next_offset = offset;
            }
            break;
        }
        let label_len = usize::from(len);
        let end = offset.checked_add(label_len)?;
        if end > packet.len() {
            return None;
        }
        labels.push(std::str::from_utf8(&packet[offset..end]).ok()?.to_owned());
        offset = end;
        if !jumped {
            next_offset = offset;
        }
    }

    Some((labels.join("."), next_offset))
}

fn nxdomain_response(packet: &[u8]) -> Option<Vec<u8>> {
    let question = parse_dns_question(packet)?;
    let mut response = packet[..question.end].to_vec();
    response[2] = 0x80 | (packet[2] & 0x79);
    response[3] = 0x80 | 0x03;
    response[4] = 0;
    response[5] = 1;
    response[6] = 0;
    response[7] = 0;
    response[8] = 0;
    response[9] = 0;
    response[10] = 0;
    response[11] = 0;
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::{
        decide_domain_rules, nxdomain_response, parse_dns_answer_ips, parse_dns_query_name,
    };
    use crate::proxy::{
        adblock::Adblocker,
        route::{RouteDecision, RouteRuleConfig},
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn query_packet() -> Vec<u8> {
        vec![
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01,
        ]
    }

    #[test]
    fn parses_dns_query_name() {
        let packet = query_packet();

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

    #[test]
    fn parses_dns_answer_ips_from_compressed_response() {
        let mut packet = query_packet();
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[6] = 0x00;
        packet[7] = 0x01;
        packet.extend_from_slice(&[
            0xc0, 0x0c, // answer name pointer to example.com
            0x00, 0x01, // A
            0x00, 0x01, // IN
            0x00, 0x00, 0x00, 0x3c, // TTL
            0x00, 0x04, // RDLENGTH
            93, 184, 216, 34,
        ]);

        assert_eq!(
            parse_dns_answer_ips(&packet),
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }

    #[test]
    fn nxdomain_response_keeps_question_and_clears_answers() {
        let packet = query_packet();
        let response = nxdomain_response(&packet).expect("nxdomain response");

        assert_eq!(&response[..2], &[0x12, 0x34]);
        assert_eq!(response[2] & 0x80, 0x80);
        assert_eq!(response[3] & 0x0f, 0x03);
        assert_eq!(&response[4..6], &[0x00, 0x01]);
        assert_eq!(&response[6..12], &[0, 0, 0, 0, 0, 0]);
        assert_eq!(&response[12..], &packet[12..]);
    }

    #[tokio::test]
    async fn domain_rule_decision_matches_wg_dns_policy() {
        let rules = RouteRuleConfig {
            direct: vec!["*.qq.com".to_owned()],
            proxy: Vec::new(),
            block: vec!["*.xxx.com".to_owned()],
        };

        assert_eq!(
            decide_domain_rules(&rules, None, "img.qq.com")
                .await
                .unwrap(),
            RouteDecision::Direct
        );
        assert_eq!(
            decide_domain_rules(&rules, None, "ads.xxx.com")
                .await
                .unwrap(),
            RouteDecision::Block
        );
        assert_eq!(
            decide_domain_rules(&rules, None, "example.com")
                .await
                .unwrap(),
            RouteDecision::Remote
        );
    }

    #[tokio::test]
    async fn adblock_decision_beats_wg_direct_rule() {
        let rules = RouteRuleConfig {
            direct: vec!["*.qq.com".to_owned()],
            proxy: Vec::new(),
            block: Vec::new(),
        };
        let adblock = Adblocker::from_rules_for_test(&["||ads.qq.com^"]);

        assert_eq!(
            decide_domain_rules(&rules, Some(&adblock), "ads.qq.com")
                .await
                .unwrap(),
            RouteDecision::Block
        );
        assert_eq!(
            decide_domain_rules(&rules, Some(&adblock), "img.qq.com")
                .await
                .unwrap(),
            RouteDecision::Direct
        );
    }
}
