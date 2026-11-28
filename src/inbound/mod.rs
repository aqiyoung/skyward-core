//! Inbound listeners: SOCKS5 (RFC 1928), HTTP proxy and Linux transparent proxy.

pub mod transparent;

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::common::TargetAddr;
use crate::AppState;

pub async fn bind(addr: &str) -> io::Result<TcpListener> {
    let normalized = if let Some(rest) = addr.strip_prefix(':') {
        format!("127.0.0.1:{}", rest)
    } else {
        addr.to_string()
    };
    let socket: SocketAddr = normalized.parse().map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("invalid address '{}': {}", addr, e))
    })?;
    TcpListener::bind(socket).await
}

pub async fn serve_socks(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_socks(stream, state).await {
                        tracing::debug!(%peer, "socks5 connection ended: {}", e);
                    }
                });
            }
            Err(e) => tracing::warn!("socks5 accept failed: {}", e),
        }
    }
}

pub async fn serve_http(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_http(stream, state).await {
                        tracing::debug!(%peer, "http connection ended: {}", e);
                    }
                });
            }
            Err(e) => tracing::warn!("http accept failed: {}", e),
        }
    }
}

pub async fn serve_mixed(listener: TcpListener, state: Arc<AppState>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    let mut probe = [0u8; 1];
                    let kind = match stream.peek(&mut probe).await {
                        Ok(0) => return,
                        Ok(_) if probe[0] == 0x05 => "socks5",
                        Ok(_) => "http",
                        Err(e) => {
                            tracing::debug!(%peer, "mixed peek failed: {}", e);
                            return;
                        }
                    };
                    let result = if kind == "socks5" {
                        handle_socks(stream, state).await
                    } else {
                        handle_http(stream, state).await
                    };
                    if let Err(e) = result {
                        tracing::debug!(%peer, "{} connection ended: {}", kind, e);
                    }
                });
            }
            Err(e) => tracing::warn!("mixed accept failed: {}", e),
        }
    }
}

async fn handle_socks(mut stream: TcpStream, state: Arc<AppState>) -> io::Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "not a SOCKS5 greeting"));
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        stream.write_all(&[0x05, 0xff]).await?; // no acceptable method
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "no acceptable auth method"));
    }
    stream.write_all(&[0x05, 0x00]).await?; // no authentication

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 || req[1] != 0x01 {
        stream.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported SOCKS command"));
    }

    let target = match req[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            let port = read_port(&mut stream).await?;
            TargetAddr::Ip(IpAddr::V4(Ipv4Addr::from(octets)), port)
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut raw = vec![0u8; len[0] as usize];
            stream.read_exact(&mut raw).await?;
            let host = String::from_utf8_lossy(&raw).into_owned();
            let port = read_port(&mut stream).await?;
            TargetAddr::Domain(host, port)
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            let port = read_port(&mut stream).await?;
            TargetAddr::Ip(IpAddr::V6(Ipv6Addr::from(octets)), port)
        }
        _ => {
            stream.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
            return Err(io::Error::new(io::ErrorKind::InvalidData, "unsupported address type"));
        }
    };

    // Success reply with an unspecified bound address (mihomo does the same).
    stream.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;

    // The listener was opened with a one-shot AppState snapshot. Always prefer
    // the live global engine so a config switch updates the system proxy too.
    let engine = match crate::runtime_state::engine().await {
        Some(e) => e,
        None => state.engine.read().await.clone(),
    };
    engine.handle(target, stream, &[]).await
}

async fn read_port(stream: &mut TcpStream) -> io::Result<u16> {
    let mut b = [0u8; 2];
    stream.read_exact(&mut b).await?;
    Ok(u16::from_be_bytes(b))
}

async fn handle_http(mut stream: TcpStream, state: Arc<AppState>) -> io::Result<()> {
    // Read the request head, bounded to avoid unbounded memory use.
    let mut head = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];
    loop {
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP head too large"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP request"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }

    let text = String::from_utf8_lossy(&head);
    let request_line = text.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let uri = parts.next().unwrap_or("");

    let target = if method.eq_ignore_ascii_case("CONNECT") {
        parse_authority(uri)?
    } else if uri.starts_with("http://") {
        parse_absolute(uri)?
    } else {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n").await?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "only CONNECT and absolute-form HTTP are supported"));
    };

    let is_connect = method.eq_ignore_ascii_case("CONNECT");
    if is_connect {
        stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
    }

    // Origin servers expect origin-form ("GET /path"), while a proxy receives
    // absolute-form ("GET http://host/path"). Rewrite just the request line.
    let forward = if is_connect {
        Vec::new()
    } else {
        rewrite_request_line(&head, uri)
    };

    let engine = match crate::runtime_state::engine().await {
        Some(e) => e,
        None => state.engine.read().await.clone(),
    };
    engine.handle(target, stream, &forward).await
}

fn rewrite_request_line(head: &[u8], uri: &str) -> Vec<u8> {
    let path = uri.strip_prefix("http://")
        .and_then(|rest| rest.find('/').map(|i| &rest[i..]))
        .unwrap_or("/");
    let line_end = match head.windows(2).position(|w| w == b"\r\n") {
        Some(i) => i,
        None => return head.to_vec(),
    };
    let line = String::from_utf8_lossy(&head[..line_end]);
    let mut parts = line.splitn(3, ' ');
    let method = parts.next().unwrap_or("GET");
    let version = parts.nth(1).unwrap_or("HTTP/1.1");
    let mut out = format!("{} {} {}", method, path, version).into_bytes();
    out.extend_from_slice(&head[line_end..]);
    out
}

fn parse_authority(uri: &str) -> io::Result<TargetAddr> {
    let (host, port) = split_host_port(uri, 443)?;
    Ok(make_target(host, port))
}

fn parse_absolute(uri: &str) -> io::Result<TargetAddr> {
    let rest = uri.strip_prefix("http://").ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "expected http:// URI")
    })?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let (host, port) = split_host_port(authority, 80)?;
    Ok(make_target(host, port))
}

fn split_host_port(authority: &str, default: u16) -> io::Result<(String, u16)> {
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "malformed IPv6 authority")
        })?;
        let host = &stripped[..end];
        let port = stripped[end + 1..].strip_prefix(':')
            .and_then(|p| p.parse().ok()).unwrap_or(default);
        return Ok((host.to_string(), port));
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port.parse().map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid port")
        })?;
        return Ok((host.to_string(), port));
    }
    Ok((authority.to_string(), default))
}

fn make_target(host: String, port: u16) -> TargetAddr {
    match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(ip, port),
        Err(_) => TargetAddr::Domain(host, port),
    }
}
