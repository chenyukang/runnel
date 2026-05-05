mod ashe;
mod baboon;
mod czar;
mod wire;

use crate::{
    mode::ProxyMode,
    proxy::route,
    runtime::{ClientRuntime, ServerRuntime},
};
use anyhow::{Result, bail};
use std::sync::Arc;

pub(crate) async fn run_client(
    runtime: ClientRuntime,
    mode: ProxyMode,
    router: Arc<route::Router>,
) -> Result<()> {
    match mode {
        ProxyMode::DazeAshe => ashe::run_client(runtime, router).await,
        ProxyMode::DazeBaboon => baboon::run_client(runtime, router).await,
        ProxyMode::DazeCzar => czar::run_client(runtime, router).await,
        _ => bail!("unsupported daze client mode"),
    }
}

pub(crate) async fn run_server(runtime: ServerRuntime, mode: ProxyMode) -> Result<()> {
    match mode {
        ProxyMode::DazeAshe => ashe::run_server(runtime).await,
        ProxyMode::DazeBaboon => baboon::run_server(runtime).await,
        ProxyMode::DazeCzar => czar::run_server(runtime).await,
        _ => bail!("unsupported daze server mode"),
    }
}
