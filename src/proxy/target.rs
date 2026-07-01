use anyhow::{Context, Result, bail};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::{TcpStream, lookup_host};

pub(crate) async fn connect_tcp_target(
    target: &str,
    allow_private_targets: bool,
) -> Result<TcpStream> {
    let addrs = resolve_allowed_target_addrs(target, allow_private_targets).await?;
    let mut last_err = None;

    for addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }

    match last_err {
        Some(err) => Err(err).with_context(|| format!("failed to connect to {target}")),
        None => bail!("target {target} resolved no allowed addresses"),
    }
}

pub(crate) async fn resolve_allowed_target_addrs(
    target: &str,
    allow_private_targets: bool,
) -> Result<Vec<SocketAddr>> {
    let addrs = lookup_host(target)
        .await
        .with_context(|| format!("failed to resolve target {target}"))?
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        bail!("target {target} resolved no addresses");
    }

    if allow_private_targets {
        return Ok(addrs);
    }

    let allowed = addrs
        .into_iter()
        .filter(|addr| !is_restricted_target_ip(addr.ip()))
        .collect::<Vec<_>>();
    if allowed.is_empty() {
        bail!("private IP targets are disabled by default");
    }
    Ok(allowed)
}

pub(crate) fn is_restricted_target_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_restricted_v4(ip),
        IpAddr::V6(ip) => is_restricted_v6(ip),
    }
}

fn is_restricted_v4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _d] = ip.octets();
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || a == 0
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 240
}

fn is_restricted_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_unique_local()
        || ip.is_unicast_link_local()
        || ip.is_multicast()
        || ip.to_ipv4_mapped().is_some_and(is_restricted_v4)
        || (segments[0] == 0x2001 && segments[1] == 0x0db8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_loopback_domain_when_private_targets_disabled() {
        let err = resolve_allowed_target_addrs("localhost:80", false)
            .await
            .expect_err("localhost should be blocked")
            .to_string();
        assert!(err.contains("private IP targets"), "{err}");
    }

    #[tokio::test]
    async fn rejects_loopback_literal_when_private_targets_disabled() {
        let err = resolve_allowed_target_addrs("127.0.0.1:80", false)
            .await
            .expect_err("loopback should be blocked")
            .to_string();
        assert!(err.contains("private IP targets"), "{err}");
    }

    #[tokio::test]
    async fn allows_public_literal_when_private_targets_disabled() {
        let addrs = resolve_allowed_target_addrs("1.1.1.1:53", false)
            .await
            .expect("public literal should be allowed");
        assert_eq!(addrs, vec!["1.1.1.1:53".parse::<SocketAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn allows_loopback_when_private_targets_enabled() {
        let addrs = resolve_allowed_target_addrs("127.0.0.1:80", true)
            .await
            .expect("private target override should allow loopback");
        assert_eq!(addrs, vec!["127.0.0.1:80".parse::<SocketAddr>().unwrap()]);
    }
}
