use super::{
    WG_OBFS_MAX_PADDING, WgObfsMode, WgObfsProfile, WgRuntimeConfig,
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
    x25519::{PublicKey, StaticSecret},
};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
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
    time::{MissedTickBehavior, interval, sleep},
};
use tracing::{debug, info, warn};

use crate::{
    proxy::{adblock::Adblocker, route::RouteRuleConfig},
    system_proxy, telemetry,
};

const MAX_IP_PACKET_SIZE: usize = 65_535;
const MAX_WG_PACKET_SIZE: usize = MAX_IP_PACKET_SIZE + 512;
pub(crate) const MAX_NOISE_UDP_PACKET_SIZE: usize = MAX_WG_PACKET_SIZE + MASK_FRAME_OVERHEAD;
const TIMER_TICK: Duration = Duration::from_millis(250);
const TRAFFIC_SAMPLE_TICK: Duration = Duration::from_secs(1);
const MAX_QUEUE_FLUSH: usize = 256;
const MASK_NONCE_LEN: usize = 12;
const MASK_LEN_LEN: usize = 4;
const MASK_PAD_LEN: usize = 2;
const MASK_TAG_LEN: usize = 8;
const MASK_HEADER_LEN: usize = MASK_NONCE_LEN + MASK_LEN_LEN + MASK_PAD_LEN;
const MASK_FRAME_OVERHEAD: usize = MASK_HEADER_LEN + MASK_TAG_LEN + WG_OBFS_MAX_PADDING as usize;
type HmacSha256 = Hmac<Sha256>;

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

    run_noise_loop(
        "wg-client",
        tun,
        socket,
        runtime,
        Some(endpoint),
        false,
        args.obfs,
        args.obfs_profile(),
    )
    .await
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

    run_noise_loop(
        "wg-server",
        tun,
        socket,
        runtime,
        None,
        true,
        args.obfs,
        args.obfs_profile(),
    )
    .await
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

#[allow(clippy::too_many_arguments)]
async fn run_noise_loop(
    role: &'static str,
    tun: AsyncFd<TunSocket>,
    socket: UdpSocket,
    runtime: WgRuntimeConfig,
    initial_endpoint: Option<SocketAddr>,
    learn_endpoint: bool,
    obfs: WgObfsMode,
    obfs_profile: WgObfsProfile,
) -> Result<()> {
    let mut tunnel = runtime.new_tunnel(1);
    let codec = NoisePacketCodec::new(obfs, obfs_profile, &runtime);
    let mut peer = NoisePeerState::new(initial_endpoint, learn_endpoint);
    let mut tun_packet = vec![0u8; MAX_IP_PACKET_SIZE];
    let mut udp_packet = vec![0u8; MAX_NOISE_UDP_PACKET_SIZE];
    let mut decoded_packet = vec![0u8; MAX_WG_PACKET_SIZE];
    let mut out_packet = vec![0u8; MAX_WG_PACKET_SIZE];
    let mut encoded_packet = vec![0u8; MAX_NOISE_UDP_PACKET_SIZE];
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
                apply_noise_action(role, &tun, &socket, &codec, &mut encoded_packet, peer.endpoint(), action, &mut traffic).await?;
            }
            received = socket.recv_from(&mut udp_packet) => {
                let (len, source) = received.context("failed to receive wg noise UDP packet")?;
                let Some(decoded_len) = codec.decode(&udp_packet[..len], &mut decoded_packet)? else {
                    debug!(role, source = %source, "wg noise obfs packet ignored");
                    continue;
                };
                let action = noise_action(tunnel.decapsulate(Some(source.ip()), &decoded_packet[..decoded_len], &mut out_packet));
                let response_target = peer.observe_source(role, source, &action);
                apply_noise_action(role, &tun, &socket, &codec, &mut encoded_packet, response_target, action, &mut traffic).await?;
                flush_queued_packets(role, &mut tunnel, &tun, &socket, &codec, peer.endpoint(), &mut out_packet, &mut encoded_packet, &mut traffic).await?;
            }
            _ = timers.tick() => {
                let action = noise_action(tunnel.update_timers(&mut out_packet));
                apply_noise_action(role, &tun, &socket, &codec, &mut encoded_packet, peer.endpoint(), action, &mut traffic).await?;
            }
            _ = traffic_timer.tick() => {
                traffic.emit(role);
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn flush_queued_packets(
    role: &'static str,
    tunnel: &mut Tunn,
    tun: &AsyncFd<TunSocket>,
    socket: &UdpSocket,
    codec: &NoisePacketCodec,
    peer_endpoint: Option<SocketAddr>,
    out_packet: &mut [u8],
    encoded_packet: &mut [u8],
    traffic: &mut TrafficCounters,
) -> Result<()> {
    for _ in 0..MAX_QUEUE_FLUSH {
        let action = noise_action(tunnel.decapsulate(None, &[], out_packet));
        if matches!(action, NoiseAction::Done) {
            return Ok(());
        }
        let should_continue = matches!(action, NoiseAction::SendNetwork(_));
        apply_noise_action(
            role,
            tun,
            socket,
            codec,
            encoded_packet,
            peer_endpoint,
            action,
            traffic,
        )
        .await?;
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

#[allow(clippy::too_many_arguments)]
async fn apply_noise_action(
    role: &'static str,
    tun: &AsyncFd<TunSocket>,
    socket: &UdpSocket,
    codec: &NoisePacketCodec,
    encoded_packet: &mut [u8],
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
            send_network_packet(
                role,
                socket,
                codec,
                encoded_packet,
                endpoint,
                &packet,
                traffic,
            )
            .await?;
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

async fn send_network_packet(
    role: &'static str,
    socket: &UdpSocket,
    codec: &NoisePacketCodec,
    encoded_packet: &mut [u8],
    endpoint: SocketAddr,
    packet: &[u8],
    traffic: &mut TrafficCounters,
) -> Result<()> {
    if codec.has_junk_packets() {
        for _ in 0..codec.profile.junk_packets {
            let encoded_len = codec.encode_junk(encoded_packet)?;
            if encoded_len > 0 {
                maybe_obfs_jitter(codec).await;
                socket
                    .send_to(&encoded_packet[..encoded_len], endpoint)
                    .await
                    .with_context(|| {
                        format!("failed to send wg noise junk packet to {endpoint}")
                    })?;
                traffic.uploaded += encoded_len as u64;
            }
        }
    }

    let encoded_len = codec.encode(packet, encoded_packet)?;
    maybe_obfs_jitter(codec).await;
    socket
        .send_to(&encoded_packet[..encoded_len], endpoint)
        .await
        .with_context(|| format!("failed to send wg noise packet to {endpoint}"))?;
    traffic.uploaded += encoded_len as u64;
    debug!(
        role,
        bytes = encoded_len,
        raw_bytes = packet.len(),
        "wg noise packet sent"
    );
    Ok(())
}

async fn maybe_obfs_jitter(codec: &NoisePacketCodec) {
    let jitter = codec.jitter();
    if !jitter.is_zero() {
        sleep(jitter).await;
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

pub(crate) struct NoisePacketCodec {
    mode: WgObfsMode,
    profile: WgObfsProfile,
    mask_key: Option<[u8; 32]>,
}

impl NoisePacketCodec {
    pub(crate) fn new(mode: WgObfsMode, profile: WgObfsProfile, runtime: &WgRuntimeConfig) -> Self {
        let mask_key = (mode == WgObfsMode::Mask).then(|| derive_mask_key(runtime));
        Self {
            mode,
            profile,
            mask_key,
        }
    }

    pub(crate) fn encode(&self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        match self.mode {
            WgObfsMode::Off => {
                if out.len() < packet.len() {
                    bail!("noise packet encode buffer is too small");
                }
                out[..packet.len()].copy_from_slice(packet);
                Ok(packet.len())
            }
            WgObfsMode::Mask => self.encode_masked(packet, out),
        }
    }

    pub(crate) fn decode(&self, packet: &[u8], out: &mut [u8]) -> Result<Option<usize>> {
        match self.mode {
            WgObfsMode::Off => {
                if out.len() < packet.len() {
                    return Ok(None);
                }
                out[..packet.len()].copy_from_slice(packet);
                Ok(Some(packet.len()))
            }
            WgObfsMode::Mask => self.decode_masked(packet, out),
        }
    }

    fn has_junk_packets(&self) -> bool {
        self.mode == WgObfsMode::Mask && self.profile.junk_packets > 0
    }

    fn jitter(&self) -> Duration {
        if self.profile.jitter_ms == 0 {
            return Duration::ZERO;
        }
        let jitter =
            (rand::rngs::OsRng.next_u32() % (u32::from(self.profile.jitter_ms) + 1)) as u64;
        Duration::from_millis(jitter)
    }

    fn encode_junk(&self, out: &mut [u8]) -> Result<usize> {
        match self.mode {
            WgObfsMode::Off => Ok(0),
            WgObfsMode::Mask => {
                self.encode_masked_body(&[], self.random_padding_len(None, out), out)
            }
        }
    }

    fn encode_masked(&self, packet: &[u8], out: &mut [u8]) -> Result<usize> {
        self.encode_masked_body(packet, self.random_padding_len(Some(packet), out), out)
    }

    fn encode_masked_body(&self, packet: &[u8], pad_len: usize, out: &mut [u8]) -> Result<usize> {
        let key = self.mask_key.expect("mask codec key is present");
        let mut rng = rand::rngs::OsRng;
        let frame_len = MASK_HEADER_LEN + packet.len() + pad_len + MASK_TAG_LEN;
        if out.len() < frame_len {
            bail!("noise mask packet encode buffer is too small");
        }
        if packet.len() > u32::MAX as usize {
            bail!("noise mask packet is too large");
        }

        rng.fill_bytes(&mut out[..MASK_NONCE_LEN]);
        let mut nonce = [0u8; MASK_NONCE_LEN];
        nonce.copy_from_slice(&out[..MASK_NONCE_LEN]);
        let header_mask = mask_header(&key, &nonce);
        let masked_len = (packet.len() as u32) ^ u32::from_be_bytes(header_mask[..4].try_into()?);
        out[MASK_NONCE_LEN..MASK_NONCE_LEN + MASK_LEN_LEN]
            .copy_from_slice(&masked_len.to_be_bytes());
        let masked_pad_len = (pad_len as u16) ^ u16::from_be_bytes(header_mask[4..6].try_into()?);
        out[MASK_NONCE_LEN + MASK_LEN_LEN..MASK_HEADER_LEN]
            .copy_from_slice(&masked_pad_len.to_be_bytes());

        let body_start = MASK_HEADER_LEN;
        let body_end = body_start + packet.len() + pad_len;
        out[body_start..body_start + packet.len()].copy_from_slice(packet);
        if pad_len > 0 {
            rng.fill_bytes(&mut out[body_start + packet.len()..body_end]);
        }
        xor_mask_body(&key, &nonce, &mut out[body_start..body_end]);

        let tag = mask_tag(&key, &out[..body_end]);
        out[body_end..body_end + MASK_TAG_LEN].copy_from_slice(&tag[..MASK_TAG_LEN]);
        Ok(frame_len)
    }

    fn decode_masked(&self, packet: &[u8], out: &mut [u8]) -> Result<Option<usize>> {
        let key = self.mask_key.expect("mask codec key is present");
        if packet.len() < MASK_HEADER_LEN + MASK_TAG_LEN {
            return Ok(None);
        }
        let nonce = nonce_from_frame(packet);
        let header_mask = mask_header(&key, nonce);
        let masked_len =
            u32::from_be_bytes(packet[MASK_NONCE_LEN..MASK_NONCE_LEN + MASK_LEN_LEN].try_into()?);
        let payload_len = (masked_len ^ u32::from_be_bytes(header_mask[..4].try_into()?)) as usize;
        let masked_pad_len =
            u16::from_be_bytes(packet[MASK_NONCE_LEN + MASK_LEN_LEN..MASK_HEADER_LEN].try_into()?);
        let pad_len = (masked_pad_len ^ u16::from_be_bytes(header_mask[4..6].try_into()?)) as usize;
        let body_len = payload_len.saturating_add(pad_len);
        let Some(tag_start) = MASK_HEADER_LEN.checked_add(body_len) else {
            return Ok(None);
        };
        if tag_start + MASK_TAG_LEN != packet.len() || out.len() < payload_len {
            return Ok(None);
        }

        let expected_tag = mask_tag(&key, &packet[..tag_start]);
        if packet[tag_start..] != expected_tag[..MASK_TAG_LEN] {
            return Ok(None);
        }
        if payload_len == 0 {
            return Ok(None);
        }

        xor_mask_body_to_out(
            &key,
            nonce,
            &packet[MASK_HEADER_LEN..MASK_HEADER_LEN + payload_len],
            &mut out[..payload_len],
        );
        Ok(Some(payload_len))
    }

    fn random_padding_len(&self, packet: Option<&[u8]>, out: &[u8]) -> usize {
        let available = out.len().saturating_sub(
            MASK_HEADER_LEN + MASK_TAG_LEN + packet.map_or(0, |packet| packet.len()),
        );
        let configured = packet
            .and_then(|packet| match wireguard_message_type(packet) {
                Some(1) => self.profile.handshake_padding,
                Some(2) => self.profile.response_padding,
                _ => None,
            })
            .map(|padding| padding as usize);
        if let Some(padding) = configured {
            return padding.min(available);
        }
        let min = usize::from(self.profile.padding_min).min(available);
        let max = usize::from(self.profile.padding_max).min(available);
        if max <= min {
            return min;
        }
        min + (rand::rngs::OsRng.next_u32() as usize % (max - min + 1))
    }
}

fn derive_mask_key(runtime: &WgRuntimeConfig) -> [u8; 32] {
    let shared = StaticSecret::from(runtime.private_key)
        .diffie_hellman(&PublicKey::from(runtime.peer_public_key));
    let mut mac = <HmacSha256 as Mac>::new_from_slice(shared.as_bytes())
        .expect("HMAC accepts arbitrary key sizes");
    mac.update(b"runnel wg noise mask v1");
    let digest = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&digest);
    key
}

fn wireguard_message_type(packet: &[u8]) -> Option<u32> {
    let prefix: [u8; 4] = packet.get(..4)?.try_into().ok()?;
    Some(u32::from_le_bytes(prefix))
}

fn nonce_from_frame(frame: &[u8]) -> &[u8] {
    &frame[..MASK_NONCE_LEN]
}

fn mask_header(key: &[u8; 32], nonce: &[u8]) -> [u8; 32] {
    mask_hmac(key, b"header", nonce, 0)
}

fn mask_tag(key: &[u8; 32], authenticated: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(b"tag");
    mac.update(authenticated);
    let digest = mac.finalize().into_bytes();
    let mut tag = [0u8; 32];
    tag.copy_from_slice(&digest);
    tag
}

fn xor_mask_body(key: &[u8; 32], nonce: &[u8], body: &mut [u8]) {
    let mut offset = 0;
    let mut counter = 0u32;
    while offset < body.len() {
        let stream = mask_hmac(key, b"body", nonce, counter);
        let chunk_len = (body.len() - offset).min(stream.len());
        for (byte, mask) in body[offset..offset + chunk_len]
            .iter_mut()
            .zip(stream.iter())
        {
            *byte ^= mask;
        }
        offset += chunk_len;
        counter = counter.wrapping_add(1);
    }
}

fn xor_mask_body_to_out(key: &[u8; 32], nonce: &[u8], input: &[u8], out: &mut [u8]) {
    let mut offset = 0;
    let mut counter = 0u32;
    while offset < input.len() {
        let stream = mask_hmac(key, b"body", nonce, counter);
        let chunk_len = (input.len() - offset).min(stream.len());
        for ((dst, src), mask) in out[offset..offset + chunk_len]
            .iter_mut()
            .zip(input[offset..offset + chunk_len].iter())
            .zip(stream.iter())
        {
            *dst = src ^ mask;
        }
        offset += chunk_len;
        counter = counter.wrapping_add(1);
    }
}

fn mask_hmac(key: &[u8; 32], label: &[u8], nonce: &[u8], counter: u32) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(label);
    mac.update(nonce);
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
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
        MASK_HEADER_LEN, MASK_TAG_LEN, MAX_NOISE_UDP_PACKET_SIZE, MAX_WG_PACKET_SIZE, NoiseAction,
        NoisePacketCodec, NoisePeerState, bind_addr_for_endpoint, noise_action,
    };
    use crate::wg::{
        WgObfsMode, WgObfsProfile, WgRuntimeConfig, default_client_allowed_ips,
        default_server_allowed_ips,
    };
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
    fn packet_codec_off_round_trips_without_changing_bytes() {
        let runtime = client_runtime(
            SocketAddr::from(([198, 51, 100, 10], 1443)),
            [0x11; 32],
            public_key([0x22; 32]),
        );
        let codec = NoisePacketCodec::new(WgObfsMode::Off, WgObfsProfile::default(), &runtime);
        let packet = b"wireguard packet";
        let mut encoded = vec![0u8; MAX_NOISE_UDP_PACKET_SIZE];
        let mut decoded = vec![0u8; MAX_WG_PACKET_SIZE];

        let encoded_len = codec.encode(packet, &mut encoded).unwrap();
        assert_eq!(&encoded[..encoded_len], packet);
        let decoded_len = codec
            .decode(&encoded[..encoded_len], &mut decoded)
            .unwrap()
            .unwrap();
        assert_eq!(&decoded[..decoded_len], packet);
        assert!(
            codec
                .decode(&encoded[..encoded_len], &mut decoded[..4])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn packet_codec_mask_round_trips_with_peer_derived_keys() {
        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_public = public_key(client_private);
        let server_public = public_key(server_private);
        let client_runtime = client_runtime(
            SocketAddr::from(([198, 51, 100, 10], 1443)),
            client_private,
            server_public,
        );
        let server_runtime = server_runtime(server_private, client_public);
        let client_codec =
            NoisePacketCodec::new(WgObfsMode::Mask, WgObfsProfile::default(), &client_runtime);
        let server_codec =
            NoisePacketCodec::new(WgObfsMode::Mask, WgObfsProfile::default(), &server_runtime);
        let packet = b"\x04\x00\x00\x00masked wireguard transport packet";
        let mut encoded = vec![0u8; MAX_NOISE_UDP_PACKET_SIZE];
        let mut decoded = vec![0u8; MAX_WG_PACKET_SIZE];

        let encoded_len = client_codec.encode(packet, &mut encoded).unwrap();
        assert_ne!(&encoded[..encoded_len], packet);
        let decoded_len = server_codec
            .decode(&encoded[..encoded_len], &mut decoded)
            .unwrap()
            .unwrap();
        assert_eq!(&decoded[..decoded_len], packet);
    }

    #[test]
    fn packet_codec_mask_rejects_tampered_packets() {
        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let client_runtime = client_runtime(
            SocketAddr::from(([198, 51, 100, 10], 1443)),
            client_private,
            public_key(server_private),
        );
        let server_runtime = server_runtime(server_private, public_key(client_private));
        let client_codec =
            NoisePacketCodec::new(WgObfsMode::Mask, WgObfsProfile::default(), &client_runtime);
        let server_codec =
            NoisePacketCodec::new(WgObfsMode::Mask, WgObfsProfile::default(), &server_runtime);
        let mut encoded = vec![0u8; MAX_NOISE_UDP_PACKET_SIZE];
        let mut decoded = vec![0u8; MAX_WG_PACKET_SIZE];

        let encoded_len = client_codec.encode(b"packet", &mut encoded).unwrap();
        encoded[MASK_HEADER_LEN] ^= 0x55;

        assert!(
            server_codec
                .decode(&encoded[..encoded_len], &mut decoded)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn packet_codec_mask_uses_profile_padding_and_junk_frames() {
        let client_private = [0x11; 32];
        let server_private = [0x22; 32];
        let profile = WgObfsProfile {
            padding_min: 7,
            padding_max: 7,
            handshake_padding: Some(32),
            response_padding: Some(24),
            junk_packets: 1,
            jitter_ms: 0,
        };
        let client_runtime = client_runtime(
            SocketAddr::from(([198, 51, 100, 10], 1443)),
            client_private,
            public_key(server_private),
        );
        let server_runtime = server_runtime(server_private, public_key(client_private));
        let client_codec = NoisePacketCodec::new(WgObfsMode::Mask, profile, &client_runtime);
        let server_codec = NoisePacketCodec::new(WgObfsMode::Mask, profile, &server_runtime);
        let mut encoded = vec![0u8; MAX_NOISE_UDP_PACKET_SIZE];
        let mut decoded = vec![0u8; MAX_WG_PACKET_SIZE];

        let handshake = wg_packet(1, b"hello");
        let encoded_len = client_codec.encode(&handshake, &mut encoded).unwrap();
        assert_eq!(
            encoded_len,
            MASK_HEADER_LEN + handshake.len() + 32 + MASK_TAG_LEN
        );
        let decoded_len = server_codec
            .decode(&encoded[..encoded_len], &mut decoded)
            .unwrap()
            .unwrap();
        assert_eq!(&decoded[..decoded_len], handshake);

        let response = wg_packet(2, b"world");
        let encoded_len = server_codec.encode(&response, &mut encoded).unwrap();
        assert_eq!(
            encoded_len,
            MASK_HEADER_LEN + response.len() + 24 + MASK_TAG_LEN
        );

        let data = wg_packet(4, b"data");
        let encoded_len = client_codec.encode(&data, &mut encoded).unwrap();
        assert_eq!(encoded_len, MASK_HEADER_LEN + data.len() + 7 + MASK_TAG_LEN);

        let junk_len = client_codec.encode_junk(&mut encoded).unwrap();
        assert_eq!(junk_len, MASK_HEADER_LEN + 7 + MASK_TAG_LEN);
        assert!(
            server_codec
                .decode(&encoded[..junk_len], &mut decoded)
                .unwrap()
                .is_none()
        );
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

    fn wg_packet(message_type: u32, body: &[u8]) -> Vec<u8> {
        let mut packet = message_type.to_le_bytes().to_vec();
        packet.extend_from_slice(body);
        packet
    }

    fn public_key(private_key: [u8; 32]) -> [u8; 32] {
        *PublicKey::from(&StaticSecret::from(private_key)).as_bytes()
    }
}
