use super::{
    WgRuntimeConfig,
    client::WgClientArgs,
    dns::{DomainRuleEngine, start_dns_capture},
    hooks::{
        DynamicRouteManager, HookGuard, effective_hook_plan, plan_client_hooks, plan_server_hooks,
        run_hooks,
    },
    select_device_name,
    server::WgServerArgs,
    tcpdump::{self, TcpdumpFilter},
    wait_for_shutdown_signal,
};
use anyhow::{Context, Result, bail};
use boringtun::{
    device::{Error as DeviceError, tun::TunSocket},
    noise::{Tunn, TunnResult},
};
use std::{
    collections::BTreeMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::unix::AsyncFd,
    net::UdpSocket,
    time::{MissedTickBehavior, interval},
};
use tracing::{debug, info, warn};

use crate::{
    proxy::{adblock::Adblocker, route::RouteRuleConfig},
    system_proxy, telemetry,
};

const MAX_IP_PACKET_SIZE: usize = 65_535;
const MAX_WG_PACKET_SIZE: usize = MAX_IP_PACKET_SIZE + 512;
const TIMER_TICK: Duration = Duration::from_millis(250);
const TRAFFIC_SAMPLE_TICK: Duration = Duration::from_secs(1);
const MAX_QUEUE_FLUSH: usize = 256;

pub(crate) async fn run_client(args: WgClientArgs, runtime: WgRuntimeConfig) -> Result<()> {
    let endpoint = runtime.endpoint.context("wg client endpoint missing")?;
    let (tun, actual_device) = open_tun_device(&args.device)?;
    let socket = UdpSocket::bind(bind_addr_for_endpoint(runtime.bind, endpoint))
        .await
        .with_context(|| format!("failed to bind wg noise client UDP socket {}", runtime.bind))?;
    let _tcpdump = args.tcpdump.then(|| {
        tcpdump::start(
            "wg-client",
            args.tcpdump_interface.as_deref(),
            TcpdumpFilter::Client { endpoint },
        )
    });

    let adblock = Adblocker::from_config(&args.adblock).await?;
    let plan = effective_hook_plan(
        plan_client_hooks(&actual_device, &runtime)?,
        &args.up,
        &args.down,
    );
    let domain_route_manager = if domain_rules_need_dns_capture(&args.domain_rules) {
        Some(Arc::new(DynamicRouteManager::for_client(&runtime)?))
    } else {
        None
    };
    let domain_rules = domain_route_manager
        .as_ref()
        .map(|manager| {
            DomainRuleEngine::new(
                args.domain_rules.clone(),
                Some(Arc::clone(manager)),
                adblock.clone(),
            )
        })
        .or_else(|| {
            adblock
                .as_ref()
                .map(|_| DomainRuleEngine::new(args.domain_rules.clone(), None, adblock.clone()))
        });

    run_hooks(&plan.up)?;
    let _cleanup = HookGuard::new("wg-client", plan.down);
    let _dns_capture = match (args.dns_capture, args.dns) {
        (true, Some(dns)) => Some(start_dns_capture(dns, domain_rules).await?),
        (true, None) => bail!("wg client --dns-capture requires --dns as the upstream resolver"),
        (false, _) => None,
    };
    let _domain_route_manager = domain_route_manager;
    let _dns_guard = match (args.dns, args.dns_capture) {
        (Some(_), true) => system_proxy::maybe_activate_tun_dns(&["127.0.0.1".to_owned()])?,
        (Some(dns), false) => system_proxy::maybe_activate_tun_dns(&[dns.to_string()])?,
        (None, _) => None,
    };

    info!(
        device = %actual_device,
        endpoint = %endpoint,
        tunnel_ip = %runtime.tunnel_ip,
        peer_tunnel_ip = %runtime.peer_tunnel_ip,
        dns = ?args.dns,
        dns_capture = args.dns_capture,
        mtu = runtime.mtu,
        engine = "noise",
        "wg client started"
    );

    run_noise_loop("wg-client", tun, socket, runtime, Some(endpoint), false).await
}

pub(crate) async fn run_server(args: WgServerArgs, runtime: WgRuntimeConfig) -> Result<()> {
    let (tun, actual_device) = open_tun_device(&args.device)?;
    let socket = UdpSocket::bind(runtime.bind)
        .await
        .with_context(|| format!("failed to bind wg noise server UDP socket {}", runtime.bind))?;
    let _tcpdump = args.tcpdump.then(|| {
        tcpdump::start(
            "wg-server",
            args.tcpdump_interface.as_deref(),
            TcpdumpFilter::Server {
                listen: runtime.bind,
            },
        )
    });
    let plan = effective_hook_plan(
        plan_server_hooks(&actual_device, &runtime, args.nat_out_interface.as_deref())?,
        &args.up,
        &args.down,
    );
    run_hooks(&plan.up)?;
    let _cleanup = HookGuard::new("wg-server", plan.down);

    info!(
        device = %actual_device,
        listen = %runtime.bind,
        tunnel_ip = %runtime.tunnel_ip,
        peer_tunnel_ip = %runtime.peer_tunnel_ip,
        mtu = runtime.mtu,
        nat_out_interface = ?args.nat_out_interface,
        engine = "noise",
        "wg server started"
    );

    run_noise_loop("wg-server", tun, socket, runtime, None, true).await
}

fn open_tun_device(requested_device: &str) -> Result<(AsyncFd<TunSocket>, String)> {
    let requested_device = select_device_name(requested_device)?;
    let tun = TunSocket::new(&requested_device)
        .with_context(|| format!("failed to create noise engine TUN device {requested_device}"))?
        .set_non_blocking()
        .with_context(|| {
            format!("failed to set noise engine TUN device {requested_device} nonblocking")
        })?;
    let actual_device = tun.name().with_context(|| {
        format!("failed to read noise engine TUN device name {requested_device}")
    })?;
    let tun = AsyncFd::new(tun).context("failed to register noise engine TUN fd")?;
    Ok((tun, actual_device))
}

async fn run_noise_loop(
    role: &'static str,
    tun: AsyncFd<TunSocket>,
    socket: UdpSocket,
    runtime: WgRuntimeConfig,
    initial_endpoint: Option<SocketAddr>,
    learn_endpoint: bool,
) -> Result<()> {
    let mut tunnel = runtime.new_tunnel(1);
    let mut peer = NoisePeerState::new(initial_endpoint, learn_endpoint);
    let mut tun_packet = vec![0u8; MAX_IP_PACKET_SIZE];
    let mut udp_packet = vec![0u8; MAX_WG_PACKET_SIZE];
    let mut out_packet = vec![0u8; MAX_WG_PACKET_SIZE];
    let mut timers = interval(TIMER_TICK);
    timers.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut traffic_timer = interval(TRAFFIC_SAMPLE_TICK);
    traffic_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut traffic = TrafficCounters::default();
    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            result = &mut shutdown => return result,
            packet = read_tun_packet(&tun, &mut tun_packet) => {
                let len = packet?;
                if len == 0 {
                    continue;
                }
                let action = noise_action(tunnel.encapsulate(&tun_packet[..len], &mut out_packet));
                apply_noise_action(role, &tun, &socket, peer.endpoint(), action, &mut traffic).await?;
            }
            received = socket.recv_from(&mut udp_packet) => {
                let (len, source) = received.context("failed to receive wg noise UDP packet")?;
                let action = noise_action(tunnel.decapsulate(Some(source.ip()), &udp_packet[..len], &mut out_packet));
                let response_target = peer.observe_source(role, source, &action);
                apply_noise_action(role, &tun, &socket, response_target, action, &mut traffic).await?;
                flush_queued_packets(role, &mut tunnel, &tun, &socket, peer.endpoint(), &mut out_packet, &mut traffic).await?;
            }
            _ = timers.tick() => {
                let action = noise_action(tunnel.update_timers(&mut out_packet));
                apply_noise_action(role, &tun, &socket, peer.endpoint(), action, &mut traffic).await?;
            }
            _ = traffic_timer.tick() => {
                traffic.emit(role);
            }
        }
    }
}

async fn flush_queued_packets(
    role: &'static str,
    tunnel: &mut Tunn,
    tun: &AsyncFd<TunSocket>,
    socket: &UdpSocket,
    peer_endpoint: Option<SocketAddr>,
    out_packet: &mut [u8],
    traffic: &mut TrafficCounters,
) -> Result<()> {
    for _ in 0..MAX_QUEUE_FLUSH {
        let action = noise_action(tunnel.decapsulate(None, &[], out_packet));
        if matches!(action, NoiseAction::Done) {
            return Ok(());
        }
        let should_continue = matches!(action, NoiseAction::SendNetwork(_));
        apply_noise_action(role, tun, socket, peer_endpoint, action, traffic).await?;
        if !should_continue {
            return Ok(());
        }
    }
    warn!(role, "wg noise queued packet flush hit iteration limit");
    Ok(())
}

async fn read_tun_packet(tun: &AsyncFd<TunSocket>, dst: &mut [u8]) -> Result<usize> {
    loop {
        let mut guard = tun
            .readable()
            .await
            .context("failed to wait for noise engine TUN readability")?;
        match guard.try_io(|inner| match inner.get_ref().read(dst) {
            Ok(packet) => Ok(packet.len()),
            Err(DeviceError::IfaceRead(error)) => Err(error),
            Err(error) => Err(io::Error::other(error)),
        }) {
            Ok(result) => return result.context("failed to read from noise engine TUN device"),
            Err(_would_block) => continue,
        }
    }
}

async fn apply_noise_action(
    role: &'static str,
    tun: &AsyncFd<TunSocket>,
    socket: &UdpSocket,
    peer_endpoint: Option<SocketAddr>,
    action: NoiseAction,
    traffic: &mut TrafficCounters,
) -> Result<()> {
    match action {
        NoiseAction::Done => Ok(()),
        NoiseAction::Error(error) => {
            debug!(role, error = %error, "wg noise packet ignored");
            Ok(())
        }
        NoiseAction::SendNetwork(packet) => {
            let Some(endpoint) = peer_endpoint else {
                debug!(
                    role,
                    "wg noise dropped network packet before peer endpoint was known"
                );
                return Ok(());
            };
            socket
                .send_to(&packet, endpoint)
                .await
                .with_context(|| format!("failed to send wg noise packet to {endpoint}"))?;
            traffic.uploaded += packet.len() as u64;
            Ok(())
        }
        NoiseAction::WriteTunnelV4(packet) => {
            write_tun_packet(role, tun, &packet, false, traffic);
            Ok(())
        }
        NoiseAction::WriteTunnelV6(packet) => {
            write_tun_packet(role, tun, &packet, true, traffic);
            Ok(())
        }
    }
}

fn write_tun_packet(
    role: &'static str,
    tun: &AsyncFd<TunSocket>,
    packet: &[u8],
    ipv6: bool,
    traffic: &mut TrafficCounters,
) {
    let written = if ipv6 {
        tun.get_ref().write6(packet)
    } else {
        tun.get_ref().write4(packet)
    };
    if written == 0 && !packet.is_empty() {
        warn!(
            role,
            bytes = packet.len(),
            "wg noise TUN write returned zero bytes"
        );
        return;
    }
    traffic.downloaded += written as u64;
}

fn noise_action(result: TunnResult<'_>) -> NoiseAction {
    match result {
        TunnResult::Done => NoiseAction::Done,
        TunnResult::Err(error) => NoiseAction::Error(format!("{error:?}")),
        TunnResult::WriteToNetwork(packet) => NoiseAction::SendNetwork(packet.to_vec()),
        TunnResult::WriteToTunnelV4(packet, _) => NoiseAction::WriteTunnelV4(packet.to_vec()),
        TunnResult::WriteToTunnelV6(packet, _) => NoiseAction::WriteTunnelV6(packet.to_vec()),
    }
}

fn bind_addr_for_endpoint(bind: SocketAddr, endpoint: SocketAddr) -> SocketAddr {
    if !bind.ip().is_unspecified() {
        return bind;
    }
    match endpoint {
        SocketAddr::V4(_) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind.port())),
        SocketAddr::V6(_) => {
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, bind.port(), 0, 0))
        }
    }
}

fn domain_rules_need_dns_capture(domain_rules: &RouteRuleConfig) -> bool {
    !domain_rules.direct.is_empty() || !domain_rules.block.is_empty()
}

#[derive(Debug)]
struct NoisePeerState {
    endpoint: Option<SocketAddr>,
    learn_endpoint: bool,
}

impl NoisePeerState {
    fn new(endpoint: Option<SocketAddr>, learn_endpoint: bool) -> Self {
        Self {
            endpoint,
            learn_endpoint,
        }
    }

    fn endpoint(&self) -> Option<SocketAddr> {
        self.endpoint
    }

    fn observe_source(
        &mut self,
        role: &'static str,
        source: SocketAddr,
        action: &NoiseAction,
    ) -> Option<SocketAddr> {
        if !self.learn_endpoint {
            return self.endpoint;
        }

        if action.is_valid_peer_packet() {
            if self.endpoint != Some(source) {
                info!(role, endpoint = %source, "wg noise peer endpoint learned");
            }
            self.endpoint = Some(source);
        }

        Some(source)
    }
}

#[derive(Debug)]
enum NoiseAction {
    Done,
    Error(String),
    SendNetwork(Vec<u8>),
    WriteTunnelV4(Vec<u8>),
    WriteTunnelV6(Vec<u8>),
}

impl NoiseAction {
    fn is_valid_peer_packet(&self) -> bool {
        !matches!(self, Self::Error(_))
    }
}

#[derive(Default)]
struct TrafficCounters {
    uploaded: u64,
    downloaded: u64,
}

impl TrafficCounters {
    fn emit(&mut self, role: &'static str) {
        if self.uploaded == 0 && self.downloaded == 0 {
            return;
        }
        let mut fields = BTreeMap::new();
        fields.insert("target".to_owned(), "wireguard".to_owned());
        fields.insert("link".to_owned(), "wg://wireguard".to_owned());
        fields.insert("route".to_owned(), role.to_owned());
        fields.insert("mode".to_owned(), "wg".to_owned());
        fields.insert("aggregate".to_owned(), "true".to_owned());
        fields.insert("engine".to_owned(), "noise".to_owned());
        fields.insert("uploaded".to_owned(), self.uploaded.to_string());
        fields.insert("downloaded".to_owned(), self.downloaded.to_string());
        telemetry::emit("INFO", "traffic sample", fields);
        self.uploaded = 0;
        self.downloaded = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_WG_PACKET_SIZE, NoiseAction, NoisePeerState, bind_addr_for_endpoint, noise_action,
    };
    use crate::wg::{WgRuntimeConfig, default_client_allowed_ips, default_server_allowed_ips};
    use boringtun::x25519::{PublicKey, StaticSecret};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn bind_addr_for_endpoint_preserves_endpoint_family() {
        assert_eq!(
            bind_addr_for_endpoint(
                SocketAddr::from(([0, 0, 0, 0], 1234)),
                SocketAddr::from(([198, 51, 100, 10], 51820)),
            ),
            SocketAddr::from(([0, 0, 0, 0], 1234))
        );
        assert_eq!(
            bind_addr_for_endpoint(
                SocketAddr::from(([0, 0, 0, 0], 1234)),
                SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 51820)),
            ),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 1234))
        );
    }

    #[test]
    fn peer_state_learns_server_endpoint_only_from_valid_packets() {
        let client_endpoint = SocketAddr::from(([203, 0, 113, 10], 4242));
        let server_endpoint = SocketAddr::from(([198, 51, 100, 10], 1443));
        let spoofed_endpoint = SocketAddr::from(([198, 51, 100, 99], 1443));

        let mut server_peer = NoisePeerState::new(None, true);
        assert_eq!(
            server_peer.observe_source(
                "wg-server",
                client_endpoint,
                &NoiseAction::Error("bad packet".to_owned()),
            ),
            Some(client_endpoint)
        );
        assert_eq!(server_peer.endpoint(), None);

        assert_eq!(
            server_peer.observe_source(
                "wg-server",
                client_endpoint,
                &NoiseAction::SendNetwork(vec![1, 2, 3]),
            ),
            Some(client_endpoint)
        );
        assert_eq!(server_peer.endpoint(), Some(client_endpoint));

        let mut client_peer = NoisePeerState::new(Some(server_endpoint), false);
        assert_eq!(
            client_peer.observe_source(
                "wg-client",
                spoofed_endpoint,
                &NoiseAction::SendNetwork(vec![1, 2, 3]),
            ),
            Some(server_endpoint)
        );
        assert_eq!(client_peer.endpoint(), Some(server_endpoint));
    }

    #[test]
    fn noise_flow_completes_handshake_flushes_queue_and_exchanges_packets() {
        let client_private = [0x11u8; 32];
        let server_private = [0x22u8; 32];
        let client_public = public_key(client_private);
        let server_public = public_key(server_private);
        let client_endpoint = SocketAddr::from(([203, 0, 113, 10], 4242));
        let server_endpoint = SocketAddr::from(([198, 51, 100, 10], 1443));

        let client_runtime = client_runtime(server_endpoint, client_private, server_public);
        let server_runtime = server_runtime(server_private, client_public);
        let mut client = client_runtime.new_tunnel(1);
        let mut server = server_runtime.new_tunnel(2);
        let mut client_peer = NoisePeerState::new(Some(server_endpoint), false);
        let mut server_peer = NoisePeerState::new(None, true);
        let mut client_buf = vec![0u8; MAX_WG_PACKET_SIZE];
        let mut server_buf = vec![0u8; MAX_WG_PACKET_SIZE];

        let outbound = ipv4_packet(Ipv4Addr::new(10, 8, 0, 2), Ipv4Addr::new(1, 1, 1, 1), 6);
        let handshake_init =
            network_packet(noise_action(client.encapsulate(&outbound, &mut client_buf)));
        assert_eq!(handshake_init.len(), 148);
        assert_eq!(client_peer.endpoint(), Some(server_endpoint));

        let server_action = noise_action(server.decapsulate(
            Some(client_endpoint.ip()),
            &handshake_init,
            &mut server_buf,
        ));
        assert_eq!(
            server_peer.observe_source("wg-server", client_endpoint, &server_action),
            Some(client_endpoint)
        );
        assert_eq!(server_peer.endpoint(), Some(client_endpoint));
        let handshake_response = network_packet(server_action);

        let client_action = noise_action(client.decapsulate(
            Some(server_endpoint.ip()),
            &handshake_response,
            &mut client_buf,
        ));
        assert_eq!(
            client_peer.observe_source("wg-client", server_endpoint, &client_action),
            Some(server_endpoint)
        );
        let keepalive = network_packet(client_action);

        let queued_data =
            network_packet(noise_action(client.decapsulate(None, &[], &mut client_buf)));
        assert_ne!(queued_data, keepalive);

        assert_done(noise_action(server.decapsulate(
            Some(client_endpoint.ip()),
            &keepalive,
            &mut server_buf,
        )));
        expect_tunnel_ipv4(
            noise_action(server.decapsulate(
                Some(client_endpoint.ip()),
                &queued_data,
                &mut server_buf,
            )),
            &outbound,
            Ipv4Addr::new(10, 8, 0, 2),
        );

        let inbound = ipv4_packet(Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(10, 8, 0, 2), 17);
        let inbound_ciphertext =
            network_packet(noise_action(server.encapsulate(&inbound, &mut server_buf)));
        expect_tunnel_ipv4(
            noise_action(client.decapsulate(
                Some(server_endpoint.ip()),
                &inbound_ciphertext,
                &mut client_buf,
            )),
            &inbound,
            Ipv4Addr::new(1, 1, 1, 1),
        );
    }

    fn client_runtime(
        endpoint: SocketAddr,
        private_key: [u8; 32],
        peer_public_key: [u8; 32],
    ) -> WgRuntimeConfig {
        WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 0)),
            endpoint: Some(endpoint),
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            mtu: 1420,
            persistent_keepalive_secs: Some(25),
            private_key,
            peer_public_key,
            peer_allowed_ips: default_client_allowed_ips(),
            excluded_ips: Vec::new(),
        }
    }

    fn server_runtime(private_key: [u8; 32], peer_public_key: [u8; 32]) -> WgRuntimeConfig {
        WgRuntimeConfig {
            bind: SocketAddr::from(([0, 0, 0, 0], 1443)),
            endpoint: None,
            tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 1)),
            peer_tunnel_ip: IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2)),
            mtu: 1420,
            persistent_keepalive_secs: None,
            private_key,
            peer_public_key,
            peer_allowed_ips: default_server_allowed_ips(IpAddr::V4(Ipv4Addr::new(10, 8, 0, 2))),
            excluded_ips: Vec::new(),
        }
    }

    fn network_packet(action: NoiseAction) -> Vec<u8> {
        match action {
            NoiseAction::SendNetwork(packet) => packet,
            other => panic!("expected network packet, got {other:?}"),
        }
    }

    fn expect_tunnel_ipv4(action: NoiseAction, expected: &[u8], expected_src: Ipv4Addr) {
        match action {
            NoiseAction::WriteTunnelV4(packet) => assert_eq!(packet, expected),
            other => panic!("expected IPv4 tunnel packet, got {other:?}"),
        }
        assert_eq!(expected_src.octets(), expected[12..16]);
    }

    fn assert_done(action: NoiseAction) {
        assert!(matches!(action, NoiseAction::Done), "{action:?}");
    }

    fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8) -> Vec<u8> {
        let mut packet = vec![
            0x45, 0x00, 0x00, 0x14, 0x12, 0x34, 0x00, 0x00, 64, protocol, 0x00, 0x00,
        ];
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet
    }

    fn public_key(private_key: [u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(private_key)).as_bytes()
    }
}
