//! Minimal HTTP/HTTPS GET used to load remote providers. The shared TLS
//! connector handles https; chunked responses are decoded inline.

use std::io;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls;
use crate::adapter::BoxedStream;

/// Body cap for normal downloads (subscriptions, providers).
pub const MAX_BODY: usize = 16 * 1024 * 1024;
/// Body cap for large GeoX downloads (a few MB each).
pub const MAX_BODY_LARGE: usize = 64 * 1024 * 1024;
/// A single chunk or WebSocket frame is never allowed above this.
pub const MAX_CHUNK: usize = 1024 * 1024;

pub async fn fetch_url(url: &str) -> io::Result<Vec<u8>> {
    // Hard cap the whole download so a dead upstream cannot stall core startup.
    fetch_url_timeout(url, Duration::from_secs(3), MAX_BODY).await
}

/// Download with a longer deadline, for large GeoX files (a few MB each).
pub async fn fetch_url_large(url: &str) -> io::Result<Vec<u8>> {
    fetch_url_timeout(url, Duration::from_secs(60), MAX_BODY_LARGE).await
}

pub async fn fetch_url_timeout(
    url: &str,
    timeout: Duration,
    max_body: usize,
) -> io::Result<Vec<u8>> {
    match tokio::time::timeout(timeout, fetch_url_inner(url, max_body)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "download timed out")),
    }
}

use std::time::Duration;

async fn fetch_url_inner(url: &str, max_body: usize) -> io::Result<Vec<u8>> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid URL"))?;
    let use_tls = match scheme {
        "http" => false,
        "https" => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported URL scheme")),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{}", path);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad IPv6 URL"))?;
        let host = stripped[..end].to_string();
        let port = stripped[end + 1..]
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(if use_tls { 443 } else { 80 });
        (host, port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), if use_tls { 443 } else { 80 })
    };

    let mut last_error = None;
    let mut tcp = None;
    let addresses = tokio::net::lookup_host((host.as_str(), port)).await?;
    for addr in addresses {
        match crate::net::connect_tcp(addr).await {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))?;
    let mut stream: BoxedStream = if use_tls {
        // Downloads (subscriptions, GeoX, providers) are always verified.
        connect_tls(&host, tcp, true).await?
    } else {
        tcp
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: skyward-core\r\nConnection: close\r\n\r\n",
        path, authority
    );
    stream.write_all(request.as_bytes()).await?;

    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP head too large"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP response"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_text = String::from_utf8_lossy(&head);
    let status = head_text
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if status != 200 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("HTTP {}", status)));
    }
    let chunked = head_text.lines().any(|l| l.to_ascii_lowercase().contains("transfer-encoding: chunked"));

    if chunked {
        let mut body = Vec::new();
        loop {
            let mut size_line = Vec::new();
            loop {
                if stream.read(&mut byte).await? == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "bad chunk"));
                }
                size_line.push(byte[0]);
                if size_line.ends_with(b"\r\n") {
                    break;
                }
            }
            let size_text = String::from_utf8_lossy(&size_line);
            let size = usize::from_str_radix(size_text.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                break;
            }
            // A hostile server can declare an astronomical chunk size; cap it
            // before allocating, and cap the accumulated body as well.
            if size > MAX_CHUNK || size > max_body.saturating_sub(body.len()) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "chunk too large"));
            }
            let mut chunk = vec![0u8; size];
            stream.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await?;
        }
        Ok(body)
    } else {
        // Read at most max_body + 1 bytes; anything more is an error rather
        // than an unbounded allocation from read_to_end.
        let mut body = Vec::new();
        let mut limited = stream.take((max_body as u64) + 1);
        limited.read_to_end(&mut body).await?;
        if body.len() > max_body {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "response body too large"));
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A server that declares a chunk larger than the cap. The client must
    /// reject the size *before* allocating it, rather than OOM-aborting.
    #[tokio::test]
    async fn rejects_oversized_chunk_without_allocating() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req = vec![0u8; 1024];
            let _ = socket.read(&mut req).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFF\r\n")
                .await
                .unwrap();
        });
        let url = format!("http://127.0.0.1:{}/x", port);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            fetch_url_inner(&url, MAX_BODY),
        )
        .await
        .unwrap();
        assert!(result.is_err(), "oversized chunk must be rejected");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        server.abort();
    }

    /// A server that never stops sending bytes must be cut off at max_body.
    #[tokio::test]
    async fn caps_uncapped_response_body() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut req = vec![0u8; 1024];
            let _ = socket.read(&mut req).await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n")
                .await
                .unwrap();
            let block = vec![b'x'; 64 * 1024];
            // More than the 4 KiB cap below, in small writes.
            for _ in 0..8 {
                if socket.write_all(&block).await.is_err() {
                    break;
                }
            }
        });
        let url = format!("http://127.0.0.1:{}/x", port);
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            fetch_url_inner(&url, 4096),
        )
        .await
        .unwrap();
        assert!(result.is_err(), "body over max_body must be rejected");
        server.abort();
    }
}
