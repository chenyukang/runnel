use anyhow::{Context, Result, bail};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::{
    proxy::{auth::AuthProof, http, tls},
    runtime::ClientRuntime,
};

pub(crate) async fn establish_remote_tunnel(
    runtime: &ClientRuntime,
    connector: &TlsConnector,
    host_header: &str,
    server_name: &str,
    target: &str,
    transport: http::TunnelTransport,
) -> Result<TlsStream<TcpStream>> {
    let upstream = timeout(runtime.connect_timeout, TcpStream::connect(&runtime.server))
        .await
        .context("server connect timed out")??;
    upstream.set_nodelay(true)?;

    let server_name = tls::server_name(server_name)?;
    let mut tunnel = match timeout(
        runtime.handshake_timeout,
        connector.connect(server_name, upstream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => return Err(err).context("TLS handshake with server failed"),
        Err(_) => bail!("TLS handshake with server timed out"),
    };

    let proof = AuthProof::sign(&runtime.password, "POST", &runtime.path, target)?;
    let payload = http::TunnelPayload {
        target: target.to_owned(),
        transport,
        timestamp: proof.timestamp,
        nonce: proof.nonce,
        signature: proof.signature,
    };
    let request =
        http::build_tunnel_request(host_header, &runtime.path, &payload, &runtime.user_agent)?;
    tunnel.write_all(&request).await?;

    let response_head = match timeout(
        runtime.handshake_timeout,
        http::read_head(&mut tunnel, runtime.max_header_size),
    )
    .await
    {
        Ok(Ok((head, body_prefix))) => (head, body_prefix),
        Ok(Err(err)) => return Err(err).context("failed to read server response"),
        Err(_) => bail!("server response timed out"),
    };

    let response =
        http::parse_response_head(&response_head.0).context("invalid server response")?;
    if !response.is_http1 {
        bail!("server returned an unsupported HTTP version");
    }
    if response.status != 200 {
        let detail = http::read_response_body_text(
            &mut tunnel,
            &response_head.1,
            response.content_length,
            runtime.max_header_size,
        )
        .await;
        if let Some(detail) = detail {
            bail!(
                "server refused tunnel with status {} {}: {}",
                response.status,
                response.reason,
                detail
            );
        }
        bail!(
            "server refused tunnel with status {} {}",
            response.status,
            response.reason
        );
    }

    Ok(tunnel)
}
