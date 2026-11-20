//! VLESS outbound: UUID request header, optional TLS, response handshake.
//!
//! Mirrors `transport/vless/conn.go`. TCP and WebSocket (`network: ws`)
//! transports are covered; XTLS / REALITY flows and UDP are not implemented.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::Poll;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adapter::tls::{connect_tls, connect_tls_http1};
use crate::adapter::ws::connect_ws;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;
use crate::config::WsOpts;

const VERSION: u8 = 0x00;
const COMMAND_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

/// Parse the canonical `8-4-4-4-12` UUID (dashes optional) into 16 bytes.
fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).ok()?;
        out[i] = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(out)
}

fn encode_request(uuid: &[u8; 16], target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 16 + 1 + 1 + 2 + 1 + 8);
    out.push(VERSION);
    out.extend_from_slice(uuid);
    out.push(0); // addons length
    out.push(COMMAND_TCP);
    out.extend_from_slice(&target.port().to_be_bytes());

    match target {
        TargetAddr::Ip(IpAddr::V4(ip), _) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip), _) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(host, _) => {
            out.push(ATYP_DOMAIN);
            let bytes = host.as_bytes();
            let len = bytes.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out
}

pub struct VlessOutbound {
    name: String,
    server: TargetAddr,
    uuid: [u8; 16],
    use_tls: bool,
    sni: String,
    verify: bool,
    use_ws: bool,
    ws_path: String,
    ws_host: String,
    ws_headers: Vec<(String, String)>,
    use_grpc: bool,
    grpc_service: String,
    use_xhttp: bool,
    xhttp_path: String,
    xhttp_host: String,
}

impl VlessOutbound {
    async fn dial_server(&self) -> io::Result<tokio::net::TcpStream> {
        let mut last_error = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no VLESS server address")
        }))
    }
}

impl VlessOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        uuid: &str,
        use_tls: bool,
        sni: Option<&str>,
        verify: bool,
        network: Option<&str>,
        ws_opts: Option<&WsOpts>,
        grpc_opts: Option<&crate::config::GrpcOpts>,
        xhttp_opts: Option<&crate::config::XHttpOpts>,
    ) -> Option<Self> {
        let uuid = parse_uuid(uuid)?;
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let use_grpc = network
            .map(|n| n.eq_ignore_ascii_case("grpc"))
            .unwrap_or(false);
        let grpc_service = grpc_opts
            .and_then(|g| g.service_name.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "GunService".to_string());
        let use_xhttp = network
            .map(|n| n.eq_ignore_ascii_case("xhttp"))
            .unwrap_or(false);
        let xhttp_path = xhttp_opts
            .and_then(|x| x.path.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "/".to_string());
        let xhttp_host = xhttp_opts
            .and_then(|x| x.host.clone())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| sni.clone());
        let server_addr = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        let use_ws = network.map(|n| n.eq_ignore_ascii_case("ws")).unwrap_or(false);
        let (ws_path, ws_host, ws_headers) = if use_ws {
            let path = ws_opts
                .and_then(|w| w.path.clone())
                .unwrap_or_else(|| "/".to_string());
            let headers: Vec<(String, String)> = ws_opts
                .and_then(|w| w.headers.clone())
                .unwrap_or_default()
                .into_iter()
                .collect();
            let host = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| sni.clone());
            (path, host, headers)
        } else {
            (String::new(), String::new(), Vec::new())
        };
        Some(Self {
            name: name.to_string(),
            server: server_addr,
            uuid,
            use_tls,
            sni,
            verify,
            use_ws,
            ws_path,
            ws_host,
            ws_headers,
            use_grpc,
            grpc_service,
            use_xhttp,
            xhttp_path,
            xhttp_host,
        })
    }
}

#[async_trait]
impl Outbound for VlessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "VLESS"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        if self.use_xhttp {
            // XHTTP opens two connections (upload + download); each is a
            // plain TCP stream, wrapped in HTTP/1.1-only TLS when used.
            let outbound = self;
            let dial = move || async move {
                let tcp = outbound.dial_server().await?;
                if outbound.use_tls {
                    connect_tls_http1(&outbound.sni, tcp, outbound.verify).await
                } else {
                    Ok(Box::new(tcp) as BoxedStream)
                }
            };
            let mut stream: BoxedStream = Box::new(
                crate::adapter::xhttp::connect_xhttp(dial, &self.xhttp_host, &self.xhttp_path)
                    .await?,
            );
            stream.write_all(&encode_request(&self.uuid, target)).await?;
            return Ok(Box::new(VlessStream::new(stream)));
        }

        let mut last_error = None;
        let mut tcp = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no VLESS server address"))
        })?;

        let mut stream: BoxedStream = if self.use_tls {
            // Name the server name and verification mode: a handshake the server
            // rejects looks identical for a wrong SNI and for a strict verifier.
            static DIAG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            if DIAG.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 20 {
                crate::jni::emit_log_event(&format!(
                    "[rust-core] vless {} -> {}:{} sni={} verify={}",
                    self.name,
                    self.server.address(),
                    self.server.port(),
                    self.sni,
                    self.verify
                ));
            }
            // A WebSocket upgrade is HTTP/1.1; offering h2 in ALPN could make
            // the server negotiate HTTP/2 and reject the upgrade outright.
            if self.use_ws {
                connect_tls_http1(&self.sni, tcp, self.verify).await?
            } else {
                connect_tls(&self.sni, tcp, self.verify).await?
            }
        } else {
            Box::new(tcp)
        };

        if self.use_ws {
            stream = Box::new(
                connect_ws(stream, &self.ws_host, &self.ws_path, &self.ws_headers).await?,
            );
        }

        if self.use_grpc {
            stream = Box::new(
                crate::adapter::grpc::connect_grpc(stream, &self.sni, &self.grpc_service)
                    .await?,
            );
        }

        stream.write_all(&encode_request(&self.uuid, target)).await?;

        // The server replies with [version, addons_len, addons...] before any
        // payload — but only together with the first payload bytes: servers
        // (xray, sing-box) attach the response header to the first response
        // chunk instead of sending it as soon as the request lands. Reading
        // it eagerly here would deadlock: the caller writes its request only
        // after connect() returns, and the target answers only after that.
        // mihomo consumes the header lazily on first read; do the same.
        Ok(Box::new(VlessStream::new(stream)))
    }
}

/// Byte stream that strips the VLESS response header on its first read.
struct VlessStream<S> {
    inner: S,
    header: [u8; 258],
    header_filled: usize,
    /// Bytes to consume: 2 for [version, addons_len], then 2 + addons_len.
    header_needed: usize,
    header_done: bool,
}

impl<S> VlessStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0u8; 258],
            header_filled: 0,
            header_needed: 2,
            header_done: false,
        }
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> VlessStream<S> {
    fn poll_consume_header(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.header_done {
            while this.header_filled < this.header_needed {
                let start = this.header_filled;
                let end = this.header_needed;
                let mut buf = tokio::io::ReadBuf::new(&mut this.header[start..end]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        if buf.filled().is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "vless: closed before response header",
                            )));
                        }
                        this.header_filled += buf.filled().len();
                    }
                }
            }
            if this.header_needed == 2 {
                if this.header[0] != VERSION {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unexpected VLESS response version",
                    )));
                }
                let addons = this.header[1] as usize;
                if addons == 0 {
                    this.header_done = true;
                } else {
                    this.header_needed = 2 + addons;
                }
            } else {
                this.header_done = true;
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> tokio::io::AsyncRead
    for VlessStream<S>
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.as_mut().poll_consume_header(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
    for VlessStream<S>
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uuid_with_and_without_dashes() {
        let a = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let b = parse_uuid("b831381d63244d53ad4f8cda48b30811").unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0], 0xb8);
        assert_eq!(a[15], 0x11);
        assert!(parse_uuid("not-a-uuid").is_none());
    }

    #[test]
    fn request_header_layout() {
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let header = encode_request(&uuid, &TargetAddr::Ip(ip, 443));
        assert_eq!(header[0], 0);
        assert_eq!(&header[1..17], &uuid[..]);
        assert_eq!(header[17], 0); // no addons
        assert_eq!(header[18], COMMAND_TCP);
        assert_eq!(&header[19..21], &443u16.to_be_bytes());
        assert_eq!(header[21], ATYP_IPV4);
        assert_eq!(&header[22..], &[1, 2, 3, 4]);

        let domain = encode_request(&uuid, &TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(&domain[19..21], &80u16.to_be_bytes()); // port precedes the address
        assert_eq!(domain[21], ATYP_DOMAIN);
        assert_eq!(domain[22], 11);
        assert_eq!(&domain[23..34], b"example.com");
        assert_eq!(domain.len(), 34);

        let v6: IpAddr = "2001:db8::1".parse().unwrap();
        let header6 = encode_request(&uuid, &TargetAddr::Ip(v6, 80));
        assert_eq!(header6[21], ATYP_IPV6);
        assert_eq!(header6.len(), 22 + 16);
    }

    #[test]
    fn tls_and_sni_defaults() {
        let plain = VlessOutbound::try_new("v", "example.com", 443, "b831381d-6324-4d53-ad4f-8cda48b30811", false, None, true, None, None, None, None).unwrap();
        assert!(!plain.use_tls);
        assert!(!plain.use_ws);
        assert_eq!(plain.sni, "example.com");
        let secured = VlessOutbound::try_new("v", "example.com", 443, "b831381d63244d53ad4f8cda48b30811", true, Some("cdn.example.com"), true, None, None, None, None).unwrap();
        assert!(secured.use_tls);
        assert_eq!(secured.sni, "cdn.example.com");
        assert!(VlessOutbound::try_new("v", "h", 443, "bad", true, None, true, None, None, None, None).is_none());
        // WS transport picks up the path and the Host header from ws-opts.
        let ws_opts = WsOpts {
            path: Some("/ray".into()),
            headers: Some(
                [("Host".to_string(), "cdn.example.com".to_string())]
                    .into_iter()
                    .collect(),
            ),
            ..Default::default()
        };
        let ws = VlessOutbound::try_new(
            "v",
            "example.com",
            443,
            "b831381d-6324-4d53-ad4f-8cda48b30811",
            true,
            None,
            true,
            Some("ws"),
            Some(&ws_opts),
            None,
            None,
        )
        .unwrap();
        assert!(ws.use_ws);
        assert_eq!(ws.ws_path, "/ray");
        assert_eq!(ws.ws_host, "cdn.example.com");
    }
}
