use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug)]
pub struct HttpResponse {
    pub version: String,
    pub status: u16,
    pub reason: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelPayload {
    pub target: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

pub async fn read_head<R>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];

    while buf.len() < max_bytes {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            bail!("connection closed before HTTP head completed");
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(buf);
        }
    }

    bail!("HTTP head exceeded {max_bytes} bytes")
}

pub async fn read_body<R>(reader: &mut R, length: usize, max_bytes: usize) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    if length > max_bytes {
        bail!("HTTP body exceeded {max_bytes} bytes");
    }

    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).await?;
    Ok(body)
}

pub fn parse_request(bytes: &[u8]) -> Result<HttpRequest> {
    let text = std::str::from_utf8(bytes).context("request is not valid UTF-8")?;
    let mut lines = text.split("\r\n");
    let start = lines.next().context("missing request line")?;
    let mut parts = start.split_whitespace();

    let method = parts.next().context("missing request method")?.to_owned();
    let path = parts.next().context("missing request path")?.to_owned();
    let version = parts.next().context("missing request version")?.to_owned();
    if parts.next().is_some() {
        bail!("request line contains too many fields");
    }

    let headers = parse_headers(lines)?;
    Ok(HttpRequest {
        method,
        path,
        version,
        headers,
    })
}

pub fn parse_response(bytes: &[u8]) -> Result<HttpResponse> {
    let text = std::str::from_utf8(bytes).context("response is not valid UTF-8")?;
    let mut lines = text.split("\r\n");
    let start = lines.next().context("missing status line")?;
    let mut parts = start.split_whitespace();

    let version = parts.next().context("missing response version")?.to_owned();
    let status = parts
        .next()
        .context("missing response status")?
        .parse::<u16>()
        .context("invalid response status")?;
    let reason = parts.collect::<Vec<_>>().join(" ");

    let _headers = parse_headers(lines)?;
    Ok(HttpResponse {
        version,
        status,
        reason,
    })
}

pub fn build_tunnel_request(
    host: &str,
    path: &str,
    payload: &TunnelPayload,
    user_agent: &str,
) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(payload).context("failed to serialize tunnel request body")?;
    let head = format!(
        concat!(
            "POST {} HTTP/1.1\r\n",
            "Host: {}\r\n",
            "User-Agent: {}\r\n",
            "Accept: application/json, text/plain, */*\r\n",
            "Content-Type: application/json\r\n",
            "Content-Length: {}\r\n",
            "Connection: keep-alive\r\n",
            "\r\n"
        ),
        path,
        host,
        user_agent,
        body.len()
    );

    let mut request = head.into_bytes();
    request.extend_from_slice(&body);
    Ok(request)
}

pub fn build_tunnel_established() -> Vec<u8> {
    empty_response(200, "Connection Established")
}

pub fn build_error_response(status: u16, reason: &str, body: &str) -> Vec<u8> {
    format!(
        concat!(
            "HTTP/1.1 {} {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Length: {}\r\n",
            "Connection: close\r\n",
            "\r\n",
            "{}"
        ),
        status,
        reason,
        body.len(),
        body
    )
    .into_bytes()
}

pub fn build_response(
    status: u16,
    reason: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Vec<u8> {
    let mut head = format!("HTTP/1.1 {} {}\r\n", status, reason);
    let mut has_content_length = false;
    let mut has_connection = false;

    for (name, value) in headers {
        if name.eq_ignore_ascii_case("content-length") {
            has_content_length = true;
        }
        if name.eq_ignore_ascii_case("connection") {
            has_connection = true;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }

    if !has_content_length {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if !has_connection {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");

    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    response
}

pub fn parse_tunnel_payload(body: &[u8]) -> Result<TunnelPayload> {
    serde_json::from_slice(body).context("invalid tunnel request body")
}

pub fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .get(&name.to_ascii_lowercase())
        .map(std::string::String::as_str)
}

pub fn content_length(headers: &HashMap<String, String>) -> Result<Option<usize>> {
    match header(headers, "content-length") {
        Some(length) => Ok(Some(
            length
                .parse::<usize>()
                .context("invalid content-length header")?,
        )),
        None => Ok(None),
    }
}

pub fn is_chunked(headers: &HashMap<String, String>) -> bool {
    header(headers, "transfer-encoding")
        .map(|value| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"))
        })
        .unwrap_or(false)
}

fn empty_response(status: u16, reason: &str) -> Vec<u8> {
    format!(
        concat!(
            "HTTP/1.1 {} {}\r\n",
            "Content-Length: 0\r\n",
            "Connection: keep-alive\r\n",
            "\r\n"
        ),
        status, reason
    )
    .into_bytes()
}

fn parse_headers<'a, I>(lines: I) -> Result<HashMap<String, String>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut headers = HashMap::new();

    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .context("malformed header line without colon")?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthProof;

    #[test]
    fn parse_built_request() {
        let proof = AuthProof {
            timestamp: 1,
            nonce: "nonce".to_owned(),
            signature: "sig".to_owned(),
        };

        let payload = TunnelPayload {
            target: "example.com:443".to_owned(),
            timestamp: proof.timestamp,
            nonce: proof.nonce.clone(),
            signature: proof.signature.clone(),
        };
        let req =
            build_tunnel_request("demo.example", "/connect", &payload, "Mozilla/5.0").unwrap();
        let header_end = req
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();
        let parsed = parse_request(&req[..header_end + 4]).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/connect");
        assert_eq!(
            header(&parsed.headers, "content-type"),
            Some("application/json")
        );

        let parsed_payload = parse_tunnel_payload(&req[header_end + 4..]).unwrap();
        assert_eq!(parsed_payload.target, "example.com:443");
    }
}
