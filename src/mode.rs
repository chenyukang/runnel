use anyhow::{Result, bail};
use clap::ValueEnum;
use std::fmt;

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ProxyMode {
    NativeHttp,
    NativeMux,
    DazeAshe,
    DazeBaboon,
    DazeCzar,
}

impl ProxyMode {
    pub fn as_str(self) -> &'static str {
        match self {
            ProxyMode::NativeHttp => "native-http",
            ProxyMode::NativeMux => "native-mux",
            ProxyMode::DazeAshe => "daze-ashe",
            ProxyMode::DazeBaboon => "daze-baboon",
            ProxyMode::DazeCzar => "daze-czar",
        }
    }

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

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str((*self).as_str())
    }
}
