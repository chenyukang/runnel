use anyhow::{Context, Result, bail};
use std::{fmt, net::IpAddr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_NOT_SUPPORTED: u8 = 0x08;

#[derive(Clone, Debug)]
pub enum TargetAddr {
    Ip(IpAddr, u16),
    Domain(String, u16),
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
}

pub async fn accept(stream: &mut TcpStream) -> Result<TargetAddr> {
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
    if request[1] != 0x01 {
        let _ = send_reply(stream, REP_COMMAND_NOT_SUPPORTED).await;
        bail!("only CONNECT is supported");
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

    Ok(address)
}

pub async fn send_success(stream: &mut TcpStream) -> std::io::Result<()> {
    send_reply(stream, 0x00).await
}

pub async fn send_failure(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    send_reply(stream, code).await
}

async fn send_reply(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    let reply = [0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    stream.write_all(&reply).await
}
