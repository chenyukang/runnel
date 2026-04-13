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
pub struct TunnelRequestHead {
    pub content_length: Option<usize>,
    pub chunked: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelPayload {
    pub target: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}

const HEADER_END: &[u8] = b"\r\n\r\n";
const HEAD_READ_CHUNK: usize = 1024;

pub async fn read_head<R>(reader: &mut R, max_bytes: usize) -> Result<(Vec<u8>, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(HEAD_READ_CHUNK.min(max_bytes));
    let mut chunk = [0_u8; HEAD_READ_CHUNK];

    while buf.len() < max_bytes {
        let remaining = max_bytes - buf.len();
        let chunk_len = remaining.min(HEAD_READ_CHUNK);
        let n = reader.read(&mut chunk[..chunk_len]).await?;
        if n == 0 {
            bail!("connection closed before HTTP head completed");
        }
        buf.extend_from_slice(&chunk[..n]);

        if let Some(head_end) = find_header_end(&buf) {
            let body = buf.split_off(head_end);
            return Ok((buf, body));
        }
    }

    bail!("HTTP head exceeded {max_bytes} bytes")
}

pub async fn read_body<R>(
    reader: &mut R,
    prefix: &[u8],
    length: usize,
    max_bytes: usize,
) -> Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    if length > max_bytes {
        bail!("HTTP body exceeded {max_bytes} bytes");
    }

    if prefix.len() > length {
        bail!("HTTP body prefix exceeded declared content-length");
    }

    let mut body = vec![0_u8; length];
    body[..prefix.len()].copy_from_slice(prefix);
    reader.read_exact(&mut body[prefix.len()..]).await?;
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

pub fn parse_tunnel_response(bytes: &[u8]) -> Result<(bool, u16, String)> {
    let text = std::str::from_utf8(bytes).context("response is not valid UTF-8")?;
    let start = text
        .split_once("\r\n")
        .map(|(line, _)| line)
        .unwrap_or(text);
    let mut parts = start.split_whitespace();

    let version = parts.next().context("missing response version")?;
    let status = parts
        .next()
        .context("missing response status")?
        .parse::<u16>()
        .context("invalid response status")?;
    let reason = parts.collect::<Vec<_>>().join(" ");
    Ok((version.starts_with("HTTP/1."), status, reason))
}

pub fn parse_tunnel_request_head(bytes: &[u8], path: &str) -> Result<Option<TunnelRequestHead>> {
    let text = std::str::from_utf8(bytes).context("request is not valid UTF-8")?;
    let mut lines = text.split("\r\n");
    let start = lines.next().context("missing request line")?;
    let mut parts = start.split_whitespace();

    let method = parts.next().context("missing request method")?;
    let request_path = parts.next().context("missing request path")?;
    let version = parts.next().context("missing request version")?;
    if parts.next().is_some() {
        bail!("request line contains too many fields");
    }

    if !version.starts_with("HTTP/1.") || method != "POST" || request_path != path {
        return Ok(None);
    }

    let mut content_length = None;
    let mut chunked = false;

    for line in lines {
        if line.is_empty() {
            break;
        }

        let (name, value) = line
            .split_once(':')
            .context("malformed header line without colon")?;
        let value = value.trim();

        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = Some(
                value
                    .parse::<usize>()
                    .context("invalid content-length header")?,
            );
        } else if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            chunked = value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case("chunked"));
        }
    }

    Ok(Some(TunnelRequestHead {
        content_length,
        chunked,
    }))
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

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(HEADER_END.len())
        .position(|window| window == HEADER_END)
        .map(|idx| idx + HEADER_END.len())
}

fn parse_headers<'a, I>(lines: I) -> Result<HashMap<String, String>>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut headers = HashMap::with_capacity(8);

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
    use tokio::io::{AsyncWriteExt, duplex};

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

    #[test]
    fn parse_tunnel_request_head_fast_path() {
        let proof = AuthProof {
            timestamp: 1,
            nonce: "nonce".to_owned(),
            signature: "sig".to_owned(),
        };
        let payload = TunnelPayload {
            target: "example.com:443".to_owned(),
            timestamp: proof.timestamp,
            nonce: proof.nonce,
            signature: proof.signature,
        };
        let req =
            build_tunnel_request("demo.example", "/connect", &payload, "Mozilla/5.0").unwrap();
        let header_end = req
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap();

        let parsed = parse_tunnel_request_head(&req[..header_end + 4], "/connect")
            .unwrap()
            .unwrap();
        assert_eq!(parsed.content_length, Some(req.len() - (header_end + 4)));
        assert!(!parsed.chunked);
    }

    #[tokio::test]
    async fn read_head_preserves_prefetched_body_bytes() {
        let (mut writer, mut reader) = duplex(128);
        let frame = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

        writer.write_all(frame).await.unwrap();
        drop(writer);

        let (head, prefix) = read_head(&mut reader, 64).await.unwrap();
        assert_eq!(
            std::str::from_utf8(&head).unwrap(),
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
        );
        assert_eq!(prefix, b"hello");
        let body = read_body(&mut reader, &prefix, 5, 16).await.unwrap();
        assert_eq!(body, b"hello");
    }
}
