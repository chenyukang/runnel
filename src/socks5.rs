use anyhow::{Context, Result, bail};
use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TargetAddr {
    Ip(IpAddr, u16),
    Domain(String, u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Request {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdpPacket {
    pub target: TargetAddr,
    pub payload: Vec<u8>,
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ip(IpAddr::V4(addr), port) => write!(f, "{addr}:{port}"),
            Self::Ip(IpAddr::V6(addr), port) => write!(f, "[{addr}]:{port}"),
            Self::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

impl TargetAddr {
    pub fn host_string(&self) -> String {
        match self {
            Self::Ip(addr, _) => addr.to_string(),
            Self::Domain(host, _) => host.clone(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Self::Ip(_, port) | Self::Domain(_, port) => *port,
        }
    }

    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        Self::Ip(addr.ip(), addr.port())
    }
}

pub async fn accept(stream: &mut TcpStream) -> Result<TargetAddr> {
    match accept_request(stream).await? {
        Request::Connect(target) => Ok(target),
        Request::UdpAssociate(_) => {
            let _ = send_failure(stream, REP_COMMAND_NOT_SUPPORTED).await;
            bail!("UDP ASSOCIATE is not supported yet");
        }
    }
}

pub async fn accept_request(stream: &mut TcpStream) -> Result<Request> {
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        bail!("unsupported SOCKS version {}", greeting[0]);
    }

    let mut methods = vec![0_u8; greeting[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xff]).await?;
        bail!("SOCKS client requires unsupported authentication");
    }

    stream.write_all(&[0x05, 0x00]).await?;

    let mut request = [0_u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != 0x05 {
        bail!("unsupported SOCKS request version {}", request[0]);
    }
    let command = request[1];
    if command != 0x01 && command != 0x03 {
        let _ = send_reply(stream, REP_COMMAND_NOT_SUPPORTED).await;
        bail!("SOCKS command {} is not supported", command);
    }

    let address = match request[3] {
        0x01 => {
            let mut ip = [0_u8; 4];
            stream.read_exact(&mut ip).await?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Ip(IpAddr::from(ip), u16::from_be_bytes(port))
        }
        0x03 => {
            let mut len = [0_u8; 1];
            stream.read_exact(&mut len).await?;
            let mut host = vec![0_u8; len[0] as usize];
            stream.read_exact(&mut host).await?;
            let host = String::from_utf8(host).context("domain target is not valid UTF-8")?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Domain(host, u16::from_be_bytes(port))
        }
        0x04 => {
            let mut ip = [0_u8; 16];
            stream.read_exact(&mut ip).await?;
            let mut port = [0_u8; 2];
            stream.read_exact(&mut port).await?;
            TargetAddr::Ip(IpAddr::from(ip), u16::from_be_bytes(port))
        }
        _ => {
            let _ = send_reply(stream, REP_ADDRESS_NOT_SUPPORTED).await;
            bail!("unsupported SOCKS address type {}", request[3]);
        }
    };

    Ok(match command {
        0x01 => Request::Connect(address),
        0x03 => Request::UdpAssociate(address),
        _ => unreachable!("validated above"),
    })
}

pub async fn send_success(stream: &mut TcpStream) -> std::io::Result<()> {
    send_reply(stream, 0x00).await
}

pub async fn send_success_bound(stream: &mut TcpStream, bound: SocketAddr) -> std::io::Result<()> {
    send_reply_bound(stream, 0x00, &TargetAddr::from_socket_addr(bound)).await
}

pub async fn send_failure(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    send_reply(stream, code).await
}

async fn send_reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    send_reply_bound(stream, code, &TargetAddr::Ip(IpAddr::from([0, 0, 0, 0]), 0)).await
}

async fn send_reply_bound(
    stream: &mut TcpStream,
    code: u8,
    bound: &TargetAddr,
) -> std::io::Result<()> {
    let mut reply = vec![0x05, code, 0x00];
    encode_target(bound, &mut reply);
    stream.write_all(&reply).await
}

pub fn parse_udp_packet(datagram: &[u8]) -> Result<UdpPacket> {
    if datagram.len() < 4 {
        bail!("SOCKS UDP packet is too short");
    }
    if datagram[0] != 0x00 || datagram[1] != 0x00 {
        bail!("SOCKS UDP packet has invalid reserved bytes");
    }
    if datagram[2] != 0x00 {
        bail!("SOCKS UDP fragmentation is not supported");
    }

    let (target, header_len) = decode_target(&datagram[3..])?;
    Ok(UdpPacket {
        target,
        payload: datagram[3 + header_len..].to_vec(),
    })
}

pub fn build_udp_packet(target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x00, 0x00, 0x00];
    encode_target(target, &mut packet);
    packet.extend_from_slice(payload);
    packet
}

fn encode_target(target: &TargetAddr, out: &mut Vec<u8>) {
    match target {
        TargetAddr::Ip(IpAddr::V4(addr), port) => {
            out.push(0x01);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Domain(host, port) => {
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(IpAddr::V6(addr), port) => {
            out.push(0x04);
            out.extend_from_slice(&addr.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
}

fn decode_target(bytes: &[u8]) -> Result<(TargetAddr, usize)> {
    if bytes.is_empty() {
        bail!("SOCKS target is missing address type");
    }

    match bytes[0] {
        0x01 => {
            if bytes.len() < 1 + 4 + 2 {
                bail!("SOCKS IPv4 target is truncated");
            }
            let mut ip = [0_u8; 4];
            ip.copy_from_slice(&bytes[1..5]);
            let mut port = [0_u8; 2];
            port.copy_from_slice(&bytes[5..7]);
            Ok((
                TargetAddr::Ip(IpAddr::from(ip), u16::from_be_bytes(port)),
                7,
            ))
        }
        0x03 => {
            if bytes.len() < 2 {
                bail!("SOCKS domain target is truncated");
            }
            let len = bytes[1] as usize;
            let end = 2 + len;
            if bytes.len() < end + 2 {
                bail!("SOCKS domain target is truncated");
            }
            let host = String::from_utf8(bytes[2..end].to_vec())
                .context("domain target is not valid UTF-8")?;
            let mut port = [0_u8; 2];
            port.copy_from_slice(&bytes[end..end + 2]);
            Ok((TargetAddr::Domain(host, u16::from_be_bytes(port)), end + 2))
        }
        0x04 => {
            if bytes.len() < 1 + 16 + 2 {
                bail!("SOCKS IPv6 target is truncated");
            }
            let mut ip = [0_u8; 16];
            ip.copy_from_slice(&bytes[1..17]);
            let mut port = [0_u8; 2];
            port.copy_from_slice(&bytes[17..19]);
            Ok((
                TargetAddr::Ip(IpAddr::from(ip), u16::from_be_bytes(port)),
                19,
            ))
        }
        atyp => bail!("unsupported SOCKS address type {}", atyp),
    }
}

#[cfg(test)]
mod tests {
    use super::{Request, TargetAddr, build_udp_packet, parse_udp_packet};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn udp_packet_round_trip_ipv4() {
        let target = TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let packet = build_udp_packet(&target, b"hello");
        let parsed = parse_udp_packet(&packet).unwrap();
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.payload, b"hello");
    }

    #[test]
    fn udp_packet_rejects_fragmentation() {
        let err = parse_udp_packet(&[0x00, 0x00, 0x01, 0x01, 1, 1, 1, 1, 0, 53])
            .unwrap_err()
            .to_string();
        assert!(err.contains("fragmentation"));
    }

    #[test]
    fn request_enum_connect_shape_is_stable() {
        let request = Request::Connect(TargetAddr::Domain("example.com".to_owned(), 443));
        match request {
            Request::Connect(TargetAddr::Domain(host, port)) => {
                assert_eq!(host, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("unexpected request shape"),
        }
    }
}
