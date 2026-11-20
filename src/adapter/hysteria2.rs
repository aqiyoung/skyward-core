//! Hysteria2 outbound (UDP-based, QUIC + HTTP/3 authentication).
//!
//! Wire protocol (verified against apernet/hysteria and
//! sagernet/sing-quic): after the QUIC handshake (ALPN `h3`), the
//! client authenticates with an HTTP/3 POST to `https://hysteria/auth`
//! carrying `Hysteria-Auth` and `Hysteria-CC-RX` headers; status 233
//! means success and the response's `Hysteria-UDP` header says whether
//! UDP relay is enabled. TCP runs over bidirectional QUIC streams
//! framed as [varint 0x401][varint addr len][addr][padding], answered
//! by [status byte][message][padding]. UDP runs over QUIC datagrams:
//! [session id u32 BE][packet id u16 BE][frag id][frag count]
//! [varint addr][payload].
//!
//! One QUIC connection per outbound, established lazily and shared by
//! all streams and UDP sessions; it is re-established when it dies.
//! Congestion control is quinn's default — the reference client's
//! Brutal controller (used when the server dictates a rate) is not
//! replicated, which servers tolerate (they fall back to standard CC).
//! Obfuscation modes (salamander/gecko) and port hopping are not
//! supported; nodes using them fail honestly at build time.
//!
//! NOT locally verifiable: this sandbox blocks all UDP sends, so the
//! first real interop check is a device test.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};

use crate::adapter::h3::{put_varint, read_varint, H3Session};
use crate::adapter::{BoxedStream, Outbound, PacketConn};
use crate::common::TargetAddr;

const AUTH_STATUS_OK: u16 = 233;

fn random_padding(min: usize, max: usize) -> Vec<u8> {
    let span = (max - min).max(1);
    let len = min + (rand::random::<u32>() as usize % span);
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    (0..len)
        .map(|_| CHARS[(rand::random::<u32>() as usize) % CHARS.len()])
        .collect()
}

/// Parse a mihomo bandwidth string ("100 Mbps", "1 Gbps", "512 Kbps",
/// or a bare number meaning Mbps) into bits per second.
pub fn parse_bandwidth(value: &str) -> Option<u64> {
    let text = value.trim().to_ascii_lowercase();
    let digits: String = text
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let amount: f64 = digits.parse().ok()?;
    let bps = if text.contains("gbps") {
        amount * 1_000_000_000.0
    } else if text.contains("kbps") {
        amount * 1_000.0
    } else {
        amount * 1_000_000.0
    };
    Some(bps as u64)
}

struct Hy2Session {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    udp_enabled: bool,
}

pub struct Hysteria2Outbound {
    name: String,
    server: TargetAddr,
    password: String,
    sni: String,
    verify: bool,
    rx_bps: u64,
    session: Mutex<Option<Arc<Hy2Session>>>,
}

impl Hysteria2Outbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        verify: bool,
        up: Option<&str>,
        down: Option<&str>,
    ) -> Option<Self> {
        let server = match server.parse::<std::net::IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        // The auth request advertises our receive rate (the node's
        // `down`); `up` is what the server tells us on its side.
        let _ = up;
        Some(Hysteria2Outbound {
            name: name.to_string(),
            password: password.to_string(),
            sni: sni.map(|s| s.to_string()).unwrap_or_else(|| server.host()),
            verify,
            rx_bps: down.and_then(parse_bandwidth).unwrap_or(0),
            server,
            session: Mutex::new(None),
        })
    }

    async fn establish(&self) -> io::Result<Arc<Hy2Session>> {
        let addrs = self.server.resolve_all().await?;
        let mut last_err: Option<io::Error> = None;
        for addr in addrs {
            match self.dial(addr).await {
                Ok(session) => return Ok(session),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "hysteria2: no server address")
        }))
    }

    async fn dial(&self, addr: SocketAddr) -> io::Result<Arc<Hy2Session>> {
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = std::net::UdpSocket::bind(bind)?;
        #[cfg(unix)]
        crate::jni::protect_fd(std::os::fd::AsRawFd::as_raw_fd(&socket));
        socket.set_nonblocking(true)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;

        let mut transport = quinn::TransportConfig::default();
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(30)
                .try_into()
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
        ));
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
        transport.datagram_receive_buffer_size(Some(4 * 1024 * 1024));
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(
                crate::adapter::tls::quic_client_config(self.verify),
            )
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?,
        ));
        client_config.transport_config(Arc::new(transport));

        let conn = endpoint
            .connect_with(client_config, addr, &self.sni)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("hysteria2 connect: {}", e)))?
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("hysteria2 handshake: {}", e)))?;

        let h3 = H3Session::new(conn.clone()).await?;
        let headers = vec![
            ("Hysteria-Auth".to_string(), self.password.clone()),
            ("Hysteria-CC-RX".to_string(), self.rx_bps.to_string()),
            (
                "Hysteria-Padding".to_string(),
                String::from_utf8_lossy(&random_padding(256, 2048)).into_owned(),
            ),
        ];
        let (status, response_headers) = h3.post("hysteria", "/auth", &headers).await?;
        if status != AUTH_STATUS_OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("hysteria2: authentication failed, status {}", status),
            ));
        }
        let udp_enabled = response_headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("hysteria-udp"))
            .map(|(_, value)| value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        Ok(Arc::new(Hy2Session { _endpoint: endpoint, conn, udp_enabled }))
    }

    async fn session(&self) -> io::Result<Arc<Hy2Session>> {
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_ref() {
            if session.conn.close_reason().is_none() {
                return Ok(session.clone());
            }
        }
        let session = self.establish().await?;
        *guard = Some(session.clone());
        Ok(session)
    }

    async fn open_tcp(
        session: &Hy2Session,
        target: &TargetAddr,
    ) -> io::Result<(quinn::SendStream, quinn::RecvStream)> {
        let (mut send, mut recv) = session
            .conn
            .open_bi()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("hysteria2 open stream: {}", e)))?;
        let addr = target.address();
        let padding = random_padding(64, 512);
        let mut request = Vec::new();
        put_varint(&mut request, 0x401);
        put_varint(&mut request, addr.len() as u64);
        request.extend_from_slice(addr.as_bytes());
        put_varint(&mut request, padding.len() as u64);
        request.extend_from_slice(&padding);
        send.write_all(&request)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("hysteria2 write request: {}", e)))?;

        let mut status = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut status).await?;
        let msg_len = read_varint(&mut recv).await? as usize;
        if msg_len > 2048 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "hysteria2: message too long"));
        }
        let mut msg = vec![0u8; msg_len];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut msg).await?;
        let pad_len = read_varint(&mut recv).await? as usize;
        if pad_len > 4096 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "hysteria2: padding too long"));
        }
        let mut pad = vec![0u8; pad_len];
        tokio::io::AsyncReadExt::read_exact(&mut recv, &mut pad).await?;
        if status[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("hysteria2: {}", String::from_utf8_lossy(&msg)),
            ));
        }
        Ok((send, recv))
    }
}

/// One proxied TCP stream over a QUIC bidirectional stream.
struct Hy2Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl AsyncRead for Hy2Stream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for Hy2Stream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // Fully qualified: SendStream's inherent poll_write shadows
        // the tokio trait method and returns quinn's WriteError.
        tokio::io::AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }
}

#[async_trait]
impl Outbound for Hysteria2Outbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "hysteria2"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let session = self.session().await?;
        match Self::open_tcp(&session, target).await {
            Ok((send, recv)) => Ok(Box::new(Hy2Stream { send, recv })),
            Err(e) => {
                // A cached session may have died between the liveness
                // check and the stream open; retry once on a fresh one.
                if session.conn.close_reason().is_some() {
                    let fresh = {
                        let mut guard = self.session.lock().await;
                        let fresh = self.establish().await?;
                        *guard = Some(fresh.clone());
                        fresh
                    };
                    let (send, recv) = Self::open_tcp(&fresh, target).await?;
                    Ok(Box::new(Hy2Stream { send, recv }))
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn connect_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let session = self.session().await?;
        if !session.udp_enabled {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "hysteria2: server has UDP relay disabled",
            ));
        }
        let session_id = loop {
            let id = rand::random::<u32>();
            if id != 0 {
                break id;
            }
        };
        let (tx, rx) = mpsc::channel::<Bytes>(64);
        let conn = session.conn.clone();
        let pump_conn = conn.clone();
        tokio::spawn(async move {
            let mut fragments: HashMap<u16, (u8, Vec<Option<Bytes>>)> = HashMap::new();
            while let Ok(datagram) = pump_conn.read_datagram().await {
                if datagram.len() < 8 {
                    continue;
                }
                let sid = u32::from_be_bytes(datagram[0..4].try_into().unwrap());
                if sid != session_id {
                    continue;
                }
                let packet_id = u16::from_be_bytes(datagram[4..6].try_into().unwrap());
                let frag_id = datagram[6];
                let frag_count = datagram[7];
                let Some((_, addr_used)) = crate::adapter::h3::parse_varint(&datagram[8..]) else {
                    continue;
                };
                let payload_start = 8 + addr_used;
                if payload_start > datagram.len() {
                    continue;
                }
                let payload = datagram.slice(payload_start..);
                if frag_count <= 1 {
                    if tx.send(payload).await.is_err() {
                        return;
                    }
                    continue;
                }
                if frag_id >= frag_count {
                    continue;
                }
                let entry = fragments
                    .entry(packet_id)
                    .or_insert_with(|| (frag_count, vec![None; frag_count as usize]));
                if entry.0 != frag_count {
                    continue;
                }
                entry.1[frag_id as usize] = Some(payload);
                if entry.1.iter().all(|part| part.is_some()) {
                    let (_, parts) = fragments.remove(&packet_id).unwrap();
                    let mut whole = BytesMut::new();
                    for part in parts {
                        whole.extend_from_slice(&part.unwrap());
                    }
                    if tx.send(whole.freeze()).await.is_err() {
                        return;
                    }
                }
                if fragments.len() > 64 {
                    fragments.clear();
                }
            }
        });
        Ok(Box::new(Hy2PacketConn {
            conn,
            session_id,
            addr: target.address(),
            packet_id: AtomicU16::new(0),
            rx: Mutex::new(Hy2PacketRx { channel: rx, current: BytesMut::new() }),
        }))
    }
}

struct Hy2PacketRx {
    channel: mpsc::Receiver<Bytes>,
    current: BytesMut,
}

struct Hy2PacketConn {
    conn: quinn::Connection,
    session_id: u32,
    addr: String,
    packet_id: AtomicU16,
    rx: Mutex<Hy2PacketRx>,
}

#[async_trait]
impl PacketConn for Hy2PacketConn {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        let max = self
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "hysteria2: datagrams unavailable"))?;
        let mut probe = Vec::new();
        put_varint(&mut probe, self.addr.len() as u64);
        let header_len = 8 + probe.len() + self.addr.len();
        let chunk = max.saturating_sub(header_len);
        if chunk == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "hysteria2: datagram too small"));
        }
        let frag_count = (data.len() + chunk - 1) / chunk.max(1);
        if frag_count > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "hysteria2: packet too large"));
        }
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        for (index, piece) in data.chunks(chunk.max(1)).enumerate() {
            let mut datagram = Vec::with_capacity(header_len + piece.len());
            datagram.extend_from_slice(&self.session_id.to_be_bytes());
            datagram.extend_from_slice(&packet_id.to_be_bytes());
            datagram.push(index as u8);
            datagram.push(frag_count as u8);
            put_varint(&mut datagram, self.addr.len() as u64);
            datagram.extend_from_slice(self.addr.as_bytes());
            datagram.extend_from_slice(piece);
            self.conn
                .send_datagram(Bytes::from(datagram))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("hysteria2 udp send: {}", e)))?;
        }
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().await;
        if rx.current.is_empty() {
            match rx.channel.recv().await {
                Some(packet) => rx.current = BytesMut::from(&packet[..]),
                None => return Ok(0),
            }
        }
        let n = rx.current.len().min(buf.len());
        buf[..n].copy_from_slice(&rx.current[..n]);
        rx.current.advance(n);
        Ok(n)
    }
}
