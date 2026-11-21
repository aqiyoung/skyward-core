//! Minimal HTTP/HTTPS GET used to load remote providers. The shared TLS
//! connector handles HTTPS; hyper handles HTTP/1 response framing.

use std::io;

use hyper::{Body, Request, Response, Uri};

use crate::adapter::tls::connect_tls_http1;
use crate::adapter::BoxedStream;

pub async fn fetch_url(url: &str) -> io::Result<Vec<u8>> {
    // Hard cap the whole download so a dead upstream cannot stall core startup.
    fetch_url_timeout(url, Duration::from_secs(3)).await
}

/// Download with a longer deadline, for large GeoX files (a few MB each).
pub async fn fetch_url_large(url: &str) -> io::Result<Vec<u8>> {
    fetch_url_timeout(url, Duration::from_secs(60)).await
}

pub async fn fetch_url_timeout(url: &str, timeout: Duration) -> io::Result<Vec<u8>> {
    match tokio::time::timeout(timeout, fetch_url_inner(url)).await {
        Ok(r) => r,
        Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "download timed out")),
    }
}

use std::time::Duration;

async fn fetch_url_inner(url: &str) -> io::Result<Vec<u8>> {
    let mut url = url.to_string();
    for _ in 0..=5 {
        let uri: Uri = url.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let response = fetch_once(&uri).await?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            let location = response.headers().get(hyper::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "redirect without Location"))?;
            url = redirect_url(&uri, location)?;
            continue;
        }
        if response.status() != hyper::StatusCode::OK {
            return Err(io::Error::new(io::ErrorKind::Other, format!("HTTP {}", response.status())));
        }
        return Ok(response.into_body().to_vec());
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "too many redirects"))
}

async fn fetch_once(uri: &Uri) -> io::Result<Response<bytes::Bytes>> {
    let scheme = uri.scheme_str().unwrap_or("");
    let use_tls = match scheme {
        "http" => false,
        "https" => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported URL scheme")),
    };
    let host = uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL without host"))?
        .trim_start_matches('[').trim_end_matches(']');
    let port = uri.port_u16().unwrap_or(if use_tls { 443 } else { 80 });

    let mut last_error = None;
    let mut tcp = None;
    let addresses = crate::dns::resolve_host(host).await?;
    for ip in addresses {
        let addr = std::net::SocketAddr::new(ip, port);
        match crate::net::connect_tcp(addr).await {
            Ok(stream) => {
                tcp = Some(stream);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))?;
    let stream: BoxedStream = if use_tls {
        // Downloads (subscriptions, GeoX, providers) are always verified.
        connect_tls_http1(host, tcp, true).await?
    } else {
        Box::new(tcp)
    };

    request_over_stream(stream, uri).await
}

async fn request_over_stream(stream: BoxedStream, uri: &Uri) -> io::Result<Response<bytes::Bytes>> {
    let request = Request::builder()
        .uri(uri.path_and_query().map(|path| path.as_str()).unwrap_or("/"))
        .header(hyper::header::HOST, uri.authority().unwrap().as_str())
        .header(hyper::header::USER_AGENT, "skyward-core")
        .header(hyper::header::CONNECTION, "close")
        .body(Body::empty())
        .map_err(http_error)?;
    let (mut sender, connection) = hyper::client::conn::handshake(stream).await.map_err(http_error)?;
    let receive = async {
        let response = sender.send_request(request).await.map_err(http_error)?;
        let (parts, body) = response.into_parts();
        let body = if parts.status == hyper::StatusCode::OK {
            // Complete framed bodies do not require a TLS close_notify. A
            // truncated Content-Length/chunk still fails rather than caching it.
            hyper::body::to_bytes(body).await.map_err(http_error)?
        } else {
            bytes::Bytes::new()
        };
        Ok(Response::from_parts(parts, body))
    };
    tokio::pin!(receive, connection);
    tokio::select! {
        biased;
        result = &mut receive => result,
        _ = &mut connection => receive.await,
    }
}

fn http_error(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error)
}

fn redirect_url(base: &Uri, location: &str) -> io::Result<String> {
    let location = location.split('#').next().unwrap_or("");
    let scheme = base.scheme_str().unwrap_or("https");
    let authority = base.authority().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "URL without host"))?;
    let next = if location.starts_with("//") {
        format!("{}:{}", scheme, location)
    } else if location.contains("://") {
        location.to_string()
    } else if location.starts_with('/') {
        format!("{}://{}{}", scheme, authority, location)
    } else if location.starts_with('?') {
        format!("{}://{}{}{}", scheme, authority, base.path(), location)
    } else {
        let parent = base.path().rsplit_once('/').map(|(parent, _)| parent).unwrap_or("");
        format!("{}://{}{}/{}", scheme, authority, parent, location)
    };
    let uri: Uri = next.parse().map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if !matches!(uri.scheme_str(), Some("https" | "http"))
        || (scheme == "https" && uri.scheme_str() != Some("https")) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsafe download redirect"));
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    struct UncleanEof(tokio::io::DuplexStream);

    impl AsyncRead for UncleanEof {
        fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
            let before = buf.filled().len();
            match Pin::new(&mut self.0).poll_read(cx, buf) {
                Poll::Ready(Ok(())) if buf.filled().len() == before =>
                    Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "missing TLS close_notify"))),
                result => result,
            }
        }
    }

    impl AsyncWrite for UncleanEof {
        fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    async fn response_without_close_notify(raw: &'static [u8]) -> io::Result<Response<bytes::Bytes>> {
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                head.push(server.read_u8().await.unwrap());
            }
            assert!(head.starts_with(b"GET /rules?version=1 HTTP/1.1\r\n"));
            server.write_all(raw).await.unwrap();
        });
        let result = tokio::time::timeout(Duration::from_secs(2), request_over_stream(
            Box::new(UncleanEof(client)), &"https://rules.example/rules?version=1".parse().unwrap(),
        )).await.expect("HTTP framing must not wait for transport EOF");
        task.await.unwrap();
        result
    }

    #[tokio::test]
    async fn accepts_complete_content_length_without_tls_close_notify() {
        let response = response_without_close_notify(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nrules").await.unwrap();
        assert_eq!(response.body().as_ref(), b"rules");
    }

    #[tokio::test]
    async fn accepts_complete_chunked_response_without_tls_close_notify() {
        let response = response_without_close_notify(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nrules\r\n0\r\n\r\n").await.unwrap();
        assert_eq!(response.body().as_ref(), b"rules");
    }

    #[tokio::test]
    async fn rejects_truncated_content_length_and_chunked_bodies() {
        assert!(response_without_close_notify(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nrules").await.is_err());
        assert!(response_without_close_notify(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na\r\nrules").await.is_err());
    }

    #[test]
    fn redirects_preserve_https_and_resolve_locations() {
        let base = "https://rules.example/sets/list.yaml".parse().unwrap();
        assert_eq!(redirect_url(&base, "https://cdn.example/file?sig=1").unwrap(), "https://cdn.example/file?sig=1");
        assert_eq!(redirect_url(&base, "/file").unwrap(), "https://rules.example/file");
        assert_eq!(redirect_url(&base, "next.yaml").unwrap(), "https://rules.example/sets/next.yaml");
        assert_eq!(redirect_url(&base, "//cdn.example/file").unwrap(), "https://cdn.example/file");
        assert!(redirect_url(&base, "http://rules.example/file").is_err());
    }

    #[tokio::test]
    async fn follows_http_redirect_to_complete_download() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for (path, response) in [
                ("/start", "HTTP/1.1 302 Found\r\nLocation: /rules\r\nContent-Length: 0\r\n\r\n"),
                ("/rules", "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nrules"),
            ] {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    head.push(stream.read_u8().await.unwrap());
                }
                assert!(String::from_utf8_lossy(&head).starts_with(&format!("GET {} HTTP/1.1\r\n", path)));
                stream.write_all(response.as_bytes()).await.unwrap();
            }
        });
        assert_eq!(fetch_url(&format!("http://{}/start", address)).await.unwrap(), b"rules");
        server.await.unwrap();
    }
}
