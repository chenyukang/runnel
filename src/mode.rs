use anyhow::{Result, bail};
use clap::ValueEnum;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProxyMode {
    NativeHttp,
    NativeMux,
    DazeAshe,
    DazeBaboon,
    DazeCzar,
}

impl ProxyMode {
    pub fn from_legacy_mux(mux: bool, mode: ProxyMode) -> Result<ProxyMode> {
        if mux {
            match mode {
                ProxyMode::NativeHttp => Ok(ProxyMode::NativeMux),
                ProxyMode::NativeMux => Ok(ProxyMode::NativeMux),
                ProxyMode::DazeAshe | ProxyMode::DazeBaboon | ProxyMode::DazeCzar => {
                    bail!("--mux cannot be combined with a daze mode")
                }
            }
        } else {
            Ok(mode)
        }
    }
}
