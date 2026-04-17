use anyhow::{Context, Result, bail};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{fs::File, io::BufReader, net::IpAddr, path::Path, sync::Arc};

pub fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>> {
    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to build server TLS config")?;

    Ok(Arc::new(config))
}

pub fn load_client_config(ca_cert: Option<&Path>) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();

    let native = rustls_native_certs::load_native_certs();
    if !native.errors.is_empty() {
        tracing::warn!(
            errors = native.errors.len(),
            "some native root certificates could not be loaded"
        );
    }

    let (added, _ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 && ca_cert.is_none() {
        bail!("failed to load native root certificates and no --ca-cert was provided");
    }

    if let Some(path) = ca_cert {
        let certs = load_certs(path)?;
        let (added, _ignored) = roots.add_parsable_certificates(certs);
        if added == 0 {
            bail!("no usable certificates found in {}", path.display());
        }
    }

    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(Arc::new(config))
}

pub fn split_host_port(endpoint: &str) -> Result<(String, u16)> {
    if let Some(rest) = endpoint.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .context("invalid bracketed IPv6 endpoint")?;
        let port = tail
            .strip_prefix(':')
            .context("missing port after bracketed IPv6 endpoint")?
            .parse::<u16>()
            .context("invalid port number")?;
        return Ok((host.to_owned(), port));
    }

    let (host, port) = endpoint
        .rsplit_once(':')
        .context("endpoint must look like host:port")?;
    Ok((
        host.to_owned(),
        port.parse::<u16>().context("invalid port number")?,
    ))
}

pub fn server_name(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    ServerName::try_from(host.to_owned()).context("invalid TLS server name")
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to parse certificates from {}", path.display()))
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("failed to parse private key from {}", path.display()))?
        .context("no private key found in PEM file")?;
    Ok(key)
}
