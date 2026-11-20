//! TUIC v5 outbound (UDP-based, QUIC transport).
//!
//! Wire protocol (verified against sagernet/sing-quic's tuic
//! package): after the QUIC handshake (ALPN `h3` by default), the
//! client opens a unidirectional stream and sends
//! [version=5][command=0 Authenticate][uuid 16][token 32], where the
//! token is TLS keying material exported with the UUID bytes as the
//! label and the password as the context. TCP uses bidirectional
//! streams headed by [5][1 Connect][address]. UDP sessions use
//! [5][2 Packet] messages — over QUIC datagrams in `native` relay
//! mode, or over one bidirectional stream per session in `quic`
//! mode — framed as [session id u16][packet id u16][frag total]
//! [frag id][size u16][address][payload], and are closed with a
//! [5][3 Dissociate] uni stream. A [5][4 Heartbeat] datagram goes
//! out every 10 seconds.
//!
//! One QUIC connection per outbound, established lazily and shared;
//! congestion control is quinn's default (cubic), which the protocol
//! explicitly allows. 0-RTT (`reduce-rtt`) is not used.
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
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};

use crate::adapter::hysteria2::Hy2Stream;
use crate::adapter::{BoxedStream, Outbound, PacketConn};
use crate::common::TargetAddr;

const VERSION: u8 = 5;
const CMD_AUTHENTICATE: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_PACKET: u8 = 2;
const CMD_DISSOCIATE: u8 = 3;
const CMD_HEARTBEAT: u8 = 4;

/// TUIC address: [type][address][port u16 BE]; types 0x00 domain
/// (length-prefixed), 0x01 IPv4, 0x02 IPv6, 0xff empty.
fn encode_addr(target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        TargetAddr::Domain(host, port) => {
            out.push(0x00);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V4(ip), port) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(std::net::IpAddr::V6(ip), port) => {
            out.push(0x02);
            out.extend_from_slice(&ip.octets());
            out.extend_from_slice(&port.to_be_bytes());
        }
    }
    out
}

/// Length of a serialized TUIC address at the start of `data`.
fn addr_len(data: &[u8]) -> Option<usize> {
    match *data.first()? {
        0x00 => {
            let len = *data.get(1)? as usize;
            Some(2 + len + 2)
        }
        0x01 => Some(1 + 4 + 2),
        0x02 => Some(1 + 16 + 2),
        0xff => Some(1),
        _ => None,
    }
}

pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

struct TuicSession {
    _endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    udp_sessions: Arc<Mutex<HashMap<u16, mpsc::Sender<Bytes>>>>,
    next_session_id: AtomicU16,
}

pub struct TuicOutbound {
    name: String,
    server: TargetAddr,
    uuid: [u8; 16],
    password: String,
    sni: String,
    verify: bool,
    udp_stream: bool,
    session: Mutex<Option<Arc<TuicSession>>>,
}

impl TuicOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        uuid: &str,
        password: &str,
        sni: Option<&str>,
        verify: bool,
        udp_stream: bool,
    ) -> Option<Self> {
        let server = match server.parse::<std::net::IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(TuicOutbound {
            name: name.to_string(),
            uuid: parse_uuid(uuid)?,
            password: password.to_string(),
            sni: sni.map(|s| s.to_string()).unwrap_or_else(|| server.host()),
            verify,
            udp_stream,
            server,
            session: Mutex::new(None),
        })
    }

    async fn establish(&self) -> io::Result<Arc<TuicSession>> {
        let addrs = self.server.resolve_all().await?;
        let mut last_err: Option<io::Error> = None;
        for addr in addrs {
            match self.dial(addr).await {
                Ok(session) => return Ok(session),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "tuic: no server address")
        }))
    }

    async fn dial(&self, addr: SocketAddr) -> io::Result<Arc<TuicSession>> {
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
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic connect: {}", e)))?
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic handshake: {}", e)))?;

        // Authenticate on a fresh unidirectional stream.
        let mut token = [0u8; 32];
        conn.export_keying_material(&mut token, &self.uuid, self.password.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic token: {:?}", e)))?;
        let mut auth = Vec::with_capacity(50);
        auth.push(VERSION);
        auth.push(CMD_AUTHENTICATE);
        auth.extend_from_slice(&self.uuid);
        auth.extend_from_slice(&token);
        let mut auth_stream = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic auth stream: {}", e)))?;
        auth_stream
            .write_all(&auth)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic auth write: {}", e)))?;
        let _ = auth_stream.finish();

        let session = Arc::new(TuicSession {
            _endpoint: endpoint,
            conn: conn.clone(),
            udp_sessions: Arc::new(Mutex::new(HashMap::new())),
            next_session_id: AtomicU16::new(1),
        });

        // Datagram pump: heartbeats in, UDP packets out to sessions.
        let pump_conn = conn.clone();
        let pump_session = session.clone();
        tokio::spawn(async move {
            let mut fragments: HashMap<(u16, u16), (u8, Vec<Option<Bytes>>)> = HashMap::new();
            while let Ok(datagram) = pump_conn.read_datagram().await {
                if datagram.len() < 2 || datagram[0] != VERSION {
                    continue;
                }
                match datagram[1] {
                    CMD_PACKET => {
                        let Some(payload) =
                            parse_packet(&datagram[2..], &mut fragments)
                        else {
                            continue;
                        };
                        let (session_id, payload) = payload;
                        let sender = {
                            let map = pump_session.udp_sessions.lock().await;
                            map.get(&session_id).cloned()
                        };
                        if let Some(sender) = sender {
                            let _ = sender.send(payload).await;
                        }
                    }
                    _ => {}
                }
            }
        });

        // Heartbeat task.
        let heartbeat_conn = conn.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(10));
            ticker.tick().await;
            loop {
                ticker.tick().await;
                if heartbeat_conn
                    .send_datagram(Bytes::from_static(&[VERSION, CMD_HEARTBEAT]))
                    .is_err()
                {
                    return;
                }
            }
        });

        Ok(session)
    }

    async fn session(&self) -> io::Result<Arc<TuicSession>> {
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
}

/// Parse one Packet message body (after version+command): returns the
/// session id and the reassembled payload when a packet completes.
fn parse_packet(
    data: &[u8],
    fragments: &mut HashMap<(u16, u16), (u8, Vec<Option<Bytes>>)>,
) -> Option<(u16, Bytes)> {
    if data.len() < 8 {
        return None;
    }
    let session_id = u16::from_be_bytes(data[0..2].try_into().ok()?);
    let packet_id = u16::from_be_bytes(data[2..4].try_into().ok()?);
    let frag_total = data[4];
    let frag_id = data[5];
    let size = u16::from_be_bytes(data[6..8].try_into().ok()?) as usize;
    let addr_used = addr_len(&data[8..])?;
    let start = 8 + addr_used;
    let end = start + size;
    let payload = data.get(start..end)?.to_vec();
    if frag_total <= 1 {
        return Some((session_id, Bytes::from(payload)));
    }
    if frag_id >= frag_total {
        return None;
    }
    let entry = fragments
        .entry((session_id, packet_id))
        .or_insert_with(|| (frag_total, vec![None; frag_total as usize]));
    if entry.0 != frag_total {
        return None;
    }
    entry.1[frag_id as usize] = Some(Bytes::from(payload));
    if entry.1.iter().all(|part| part.is_some()) {
        let (_, parts) = fragments.remove(&(session_id, packet_id))?;
        let mut whole = BytesMut::new();
        for part in parts {
            whole.extend_from_slice(&part?);
        }
        return Some((session_id, whole.freeze()));
    }
    if fragments.len() > 64 {
        fragments.clear();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn uuid_parse() {
        let uuid = parse_uuid("11111111-2222-3333-4444-555555555555").unwrap();
        assert_eq!(uuid[0], 0x11);
        assert_eq!(uuid[15], 0x55);
        assert!(parse_uuid("not-a-uuid").is_none());
    }

    #[test]
    fn addr_encoding() {
        let domain = encode_addr(&TargetAddr::Domain("example.com".into(), 443));
        assert_eq!(domain[0], 0x00);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[domain.len() - 2..], &443u16.to_be_bytes());
        let ip = encode_addr(&TargetAddr::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 53));
        assert_eq!(ip, vec![0x01, 1, 2, 3, 4, 0, 53]);
        assert_eq!(addr_len(&domain), Some(domain.len()));
        assert_eq!(addr_len(&ip), Some(ip.len()));
    }

    #[test]
    fn packet_round_trip() {
        let target = TargetAddr::Domain("dns.example".into(), 53);
        let frame = packet_frame(7, 9, 1, 0, &target, b"hello");
        let mut fragments = HashMap::new();
        let (session, payload) = parse_packet(&frame[2..], &mut fragments).unwrap();
        assert_eq!(session, 7);
        assert_eq!(&payload[..], b"hello");
        // Fragmented: two parts complete only together.
        let f0 = packet_frame(7, 10, 2, 0, &target, b"ab");
        let f1 = packet_frame(7, 10, 2, 1, &target, b"cd");
        assert!(parse_packet(&f0[2..], &mut fragments).is_none());
        let (_, payload) = parse_packet(&f1[2..], &mut fragments).unwrap();
        assert_eq!(&payload[..], b"abcd");
    }
}

fn packet_frame(session_id: u16, packet_id: u16, frag_total: u8, frag_id: u8, target: &TargetAddr, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(10 + payload.len() + 24);
    out.push(VERSION);
    out.push(CMD_PACKET);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.extend_from_slice(&packet_id.to_be_bytes());
    out.push(frag_total);
    out.push(frag_id);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&encode_addr(target));
    out.extend_from_slice(payload);
    out
}

#[async_trait]
impl Outbound for TuicOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "tuic"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        async fn open_tcp(session: &TuicSession, target: &TargetAddr) -> io::Result<Hy2Stream> {
            let (mut send, recv) = session
                .conn
                .open_bi()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic open stream: {}", e)))?;
            let mut header = vec![VERSION, CMD_CONNECT];
            header.extend_from_slice(&encode_addr(target));
            send.write_all(&header)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic write header: {}", e)))?;
            Ok(Hy2Stream::new(send, recv))
        }
        let session = self.session().await?;
        match open_tcp(&session, target).await {
            Ok(stream) => Ok(Box::new(stream)),
            Err(e) => {
                if session.conn.close_reason().is_some() {
                    let fresh = {
                        let mut guard = self.session.lock().await;
                        let fresh = self.establish().await?;
                        *guard = Some(fresh.clone());
                        fresh
                    };
                    Ok(Box::new(open_tcp(&fresh, target).await?))
                } else {
                    Err(e)
                }
            }
        }
    }

    async fn connect_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let session = self.session().await?;
        let session_id = session.next_session_id.fetch_add(1, Ordering::Relaxed);
        if self.udp_stream {
            // `quic` relay mode: one bidirectional stream per session,
            // carrying the same Packet frames both ways.
            let (mut send, mut recv) = session
                .conn
                .open_bi()
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic udp stream: {}", e)))?;
            let (tx, rx) = mpsc::channel::<Bytes>(64);
            tokio::spawn(async move {
                let mut fragments: HashMap<(u16, u16), (u8, Vec<Option<Bytes>>)> = HashMap::new();
                let mut buf = vec![0u8; 65536];
                let mut pending = BytesMut::new();
                loop {
                    // Parse complete frames out of the pending buffer.
                    loop {
                        if pending.len() < 2 {
                            break;
                        }
                        if pending[0] != VERSION || pending[1] != CMD_PACKET {
                            return;
                        }
                        if pending.len() < 10 {
                            break;
                        }
                        let size = u16::from_be_bytes(pending[8..10].try_into().unwrap()) as usize;
                        let Some(alen) = addr_len(&pending[10..]) else { return };
                        let total = 10 + alen + size;
                        if pending.len() < total {
                            break;
                        }
                        let frame = pending.split_to(total);
                        if let Some((_, payload)) = parse_packet(&frame[2..], &mut fragments) {
                            if tx.send(payload).await.is_err() {
                                return;
                            }
                        }
                    }
                    match tokio::io::AsyncReadExt::read(&mut recv, &mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                    }
                }
            });
            return Ok(Box::new(TuicPacketConn {
                session: session.clone(),
                session_id,
                target: target.clone(),
                packet_id: AtomicU16::new(0),
                rx: Mutex::new(PacketRx { channel: rx, current: BytesMut::new() }),
                stream_send: Some(Mutex::new(send)),
            }));
        }
        // `native` relay mode: QUIC datagrams via the session pump.
        let (tx, rx) = mpsc::channel::<Bytes>(64);
        session.udp_sessions.lock().await.insert(session_id, tx);
        Ok(Box::new(TuicPacketConn {
            session: session.clone(),
            session_id,
            target: target.clone(),
            packet_id: AtomicU16::new(0),
            rx: Mutex::new(PacketRx { channel: rx, current: BytesMut::new() }),
            stream_send: None,
        }))
    }
}

struct PacketRx {
    channel: mpsc::Receiver<Bytes>,
    current: BytesMut,
}

struct TuicPacketConn {
    session: Arc<TuicSession>,
    session_id: u16,
    target: TargetAddr,
    packet_id: AtomicU16,
    rx: Mutex<PacketRx>,
    stream_send: Option<Mutex<quinn::SendStream>>,
}

impl Drop for TuicPacketConn {
    fn drop(&mut self) {
        let conn = self.session.conn.clone();
        let session_id = self.session_id;
        let sessions = self.session.udp_sessions.clone();
        tokio::spawn(async move {
            let mut map = sessions.lock().await;
            map.remove(&session_id);
            drop(map);
            if let Ok(mut stream) = conn.open_uni().await {
                let mut msg = vec![VERSION, CMD_DISSOCIATE];
                msg.extend_from_slice(&session_id.to_be_bytes());
                let _ = stream.write_all(&msg).await;
                let _ = stream.finish();
            }
        });
    }
}

#[async_trait]
impl PacketConn for TuicPacketConn {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        let packet_id = self.packet_id.fetch_add(1, Ordering::Relaxed);
        if let Some(send) = &self.stream_send {
            let frame = packet_frame(self.session_id, packet_id, 1, 0, &self.target, data);
            let mut send = send.lock().await;
            send.write_all(&frame)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic udp write: {}", e)))?;
            return Ok(());
        }
        let max = self
            .session
            .conn
            .max_datagram_size()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "tuic: datagrams unavailable"))?;
        // Frame overhead: 10 fixed + address; payload size field is per
        // fragment, so chunk by what fits one datagram.
        let overhead = 10 + encode_addr(&self.target).len();
        let chunk = max.saturating_sub(overhead);
        if chunk == 0 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tuic: datagram too small"));
        }
        let frag_total = (data.len() + chunk - 1) / chunk.max(1);
        if frag_total > u8::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "tuic: packet too large"));
        }
        for (index, piece) in data.chunks(chunk.max(1)).enumerate() {
            let frame = packet_frame(
                self.session_id,
                packet_id,
                frag_total as u8,
                index as u8,
                &self.target,
                piece,
            );
            self.session
                .conn
                .send_datagram(Bytes::from(frame))
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("tuic udp send: {}", e)))?;
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
