mod ashe;
mod baboon;
mod czar;
mod wire;

use crate::{client::ClientArgs, mode::ProxyMode, server::ServerArgs};
use anyhow::{Result, bail};

pub async fn run_client(args: ClientArgs) -> Result<()> {
    match args.effective_mode()? {
        ProxyMode::DazeAshe => ashe::run_client(args).await,
        ProxyMode::DazeBaboon => baboon::run_client(args).await,
        ProxyMode::DazeCzar => czar::run_client(args).await,
        _ => bail!("unsupported daze client mode"),
    }
}

pub async fn run_server(args: ServerArgs) -> Result<()> {
    match args.mode {
        ProxyMode::DazeAshe => ashe::run_server(args).await,
        ProxyMode::DazeBaboon => baboon::run_server(args).await,
        ProxyMode::DazeCzar => czar::run_server(args).await,
        _ => bail!("unsupported daze server mode"),
    }
}
