//! WireGuard outbound (UDP-based Noise_IKpsk2 tunnel).
//!
//! Implements the WireGuard handshake and transport from the
//! protocol whitepaper: BLAKE2s hashing, HMAC-BLAKE2s key chain,
//! X25519 DH, ChaCha20-Poly1305 AEAD. One peer per outbound (the
//! classic single-peer form and the first entry of mihomo's `peers`
//! list are both honoured).
//!
//! Scope of this first implementation: UDP relay. The PacketConn
//! wraps payloads in real IP/UDP packets from the interface address
//! (the node's `ip` / `ipv6`), so DNS and QUIC traffic work through
//! the TUN UDP manager. TCP (`connect`) is honestly refused: carrying
//! TCP over a packet tunnel needs a client-side TCP/IP stack, which
//! is a separate piece of work. Handshakes re-run when the session
//! ages past 150 s; an empty keepalive packet goes out after 20 s of
//! send silence.
//!
//! NOT locally verifiable: this sandbox blocks all UDP sends, so the
//! first real interop check is a device test.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use blake2::digest::{Digest, KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac};
use bytes::{Buf, Bytes, BytesMut};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, Key as ChaChaKey, Nonce as ChaChaNonce};
use blake2::digest::typenum::U16;
use tokio::sync::{mpsc, Mutex, Notify};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use crate::adapter::{BoxedStream, Outbound, PacketConn};
use crate::common::TargetAddr;

const CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
const LABEL_MAC1: &[u8] = b"mac1----";
const REKEY_AFTER: Duration = Duration::from_secs(150);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(4);

fn wg_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn wg_hash2(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

fn wg_hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC over BLAKE2s-256, written out by hand: the `hmac` crate's
    // trait bounds reject blake2's variable-core wrapper, and the
    // construction is three hashes.
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&wg_hash(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Blake2s256::new();
    inner.update(key_block.iter().map(|b| b ^ 0x36).collect::<Vec<u8>>());
    inner.update(data);
    let inner_hash = inner.finalize();
    let mut outer = Blake2s256::new();
    outer.update(key_block.iter().map(|b| b ^ 0x5c).collect::<Vec<u8>>());
    outer.update(inner_hash);
    outer.finalize().into()
}

fn kdf1(ck: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let temp = wg_hmac(ck, input);
    wg_hmac(&temp, &[0x01])
}

fn kdf2(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = wg_hmac(ck, input);
    let out1 = wg_hmac(&temp, &[0x01]);
    let mut buf = out1.to_vec();
    buf.push(0x02);
    let out2 = wg_hmac(&temp, &buf);
    (out1, out2)
}

fn kdf3(ck: &[u8; 32], input: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let temp = wg_hmac(ck, input);
    let out1 = wg_hmac(&temp, &[0x01]);
    let mut buf = out1.to_vec();
    buf.push(0x02);
    let out2 = wg_hmac(&temp, &buf);
    let mut buf = out1.to_vec();
    buf.extend_from_slice(&out2);
    buf.push(0x03);
    let out3 = wg_hmac(&temp, &buf);
    (out1, out2, out3)
}

fn aead_encrypt(key: &[u8; 32], counter: u64, plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    cipher
        .encrypt(
            ChaChaNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload { msg: plaintext, aad: ad },
        )
        .expect("aead encrypt")
}

fn aead_decrypt(key: &[u8; 32], counter: u64, ciphertext: &[u8], ad: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(ChaChaKey::from_slice(key));
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    cipher
        .decrypt(
            ChaChaNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload { msg: ciphertext, aad: ad },
        )
        .ok()
}

fn mac1(peer_public: &[u8; 32], packet: &[u8]) -> [u8; 16] {
    let key = wg_hash2(LABEL_MAC1, peer_public);
    let mut mac = <Blake2sMac<U16> as Mac>::new_from_slice(&key).expect("mac key");
    mac.update(packet);
    mac.finalize().into_bytes().into()
}

fn tai64n_now() -> [u8; 12] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let tai64 = now.as_secs().wrapping_add(4611686018427387914);
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&tai64.to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

fn decode_key(text: &str) -> Option<[u8; 32]> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(text.trim()).ok()?;
    bytes.try_into().ok()
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

struct Session {
    send_key: [u8; 32],
    recv_key: [u8; 32],
    remote_index: u32,
    local_index: u32,
    send_counter: u64,
    highest_recv: u64,
    created: Instant,
}

struct PendingHandshake {
    chain_key: [u8; 32],
    hash: [u8; 32],
    ephemeral: X25519Secret,
    local_index: u32,
}

struct WgState {
    socket: tokio::net::UdpSocket,
    private_key: [u8; 32],
    public_self: [u8; 32],
    peer_public: [u8; 32],
    preshared: [u8; 32],
    session: Mutex<Option<Session>>,
    pending: Mutex<Option<PendingHandshake>>,
    ready: Notify,
    udp_handlers: Mutex<Vec<(u64, mpsc::Sender<Bytes>)>>,
    last_send_ms: AtomicU64,
    next_handler: AtomicU64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Build a handshake initiation and stash the pending state.
fn build_initiation(state: &WgState) -> (Vec<u8>, PendingHandshake) {
    let mut chain_key = wg_hash(CONSTRUCTION);
    let mut hash = wg_hash2(&chain_key, IDENTIFIER);
    hash = wg_hash2(&hash, &state.peer_public);

    let ephemeral = X25519Secret::random_from_rng(rand_core::OsRng);
    let ephemeral_public = X25519Public::from(&ephemeral).to_bytes();
    let local_index = loop {
        let index = rand::random::<u32>();
        if index != 0 {
            break index;
        }
    };

    let mut msg = Vec::with_capacity(148);
    msg.push(1);
    msg.extend_from_slice(&[0, 0, 0]);
    msg.extend_from_slice(&local_index.to_le_bytes());
    msg.extend_from_slice(&ephemeral_public);

    chain_key = kdf1(&chain_key, &ephemeral_public);
    hash = wg_hash2(&hash, &ephemeral_public);

    let peer = X25519Public::from(state.peer_public);
    let (ck, key) = kdf2(&chain_key, ephemeral.diffie_hellman(&peer).as_bytes());
    chain_key = ck;
    let static_enc = aead_encrypt(&key, 0, &state.public_self, &hash);
    msg.extend_from_slice(&static_enc);
    hash = wg_hash2(&hash, &static_enc);

    let secret = X25519Secret::from(state.private_key);
    let (ck, key) = kdf2(&chain_key, secret.diffie_hellman(&peer).as_bytes());
    chain_key = ck;
    let timestamp_enc = aead_encrypt(&key, 0, &tai64n_now(), &hash);
    msg.extend_from_slice(&timestamp_enc);
    hash = wg_hash2(&hash, &timestamp_enc);

    let mac = mac1(&state.peer_public, &msg);
    msg.extend_from_slice(&mac);
    msg.extend_from_slice(&[0u8; 16]);

    let pending = PendingHandshake { chain_key, hash, ephemeral, local_index };
    (msg, pending)
}

/// Process a handshake response against the pending state; on success
/// returns the established session.
fn process_response(state: &WgState, pending: PendingHandshake, packet: &[u8]) -> Option<Session> {
    if packet.len() != 92 || packet[0] != 2 {
        return None;
    }
    let remote_index = u32::from_le_bytes(packet[4..8].try_into().ok()?);
    let receiver = u32::from_le_bytes(packet[8..12].try_into().ok()?);
    if receiver != pending.local_index {
        return None;
    }
    let ephemeral_public: [u8; 32] = packet[12..44].try_into().ok()?;
    let empty_enc = &packet[44..60];

    let mut chain_key = pending.chain_key;
    let mut hash = wg_hash2(&pending.hash, &ephemeral_public);
    let peer_eph = X25519Public::from(ephemeral_public);
    let (ck, _) = kdf2(&chain_key, pending.ephemeral.diffie_hellman(&peer_eph).as_bytes());
    chain_key = ck;
    let secret = X25519Secret::from(state.private_key);
    let (ck, _) = kdf2(&chain_key, secret.diffie_hellman(&peer_eph).as_bytes());
    chain_key = ck;
    let (ck, tau, key) = kdf3(&chain_key, &state.preshared);
    chain_key = ck;
    hash = wg_hash2(&hash, &tau);
    let empty = aead_decrypt(&key, 0, empty_enc, &hash)?;
    if !empty.is_empty() {
        return None;
    }
    let (send_key, recv_key) = kdf2(&chain_key, &[]);
    Some(Session {
        send_key,
        recv_key,
        remote_index,
        local_index: pending.local_index,
        send_counter: 0,
        highest_recv: 0,
        created: Instant::now(),
    })
}

async fn wg_ensure_session(state: &Arc<WgState>) -> io::Result<()> {
    {
        let session = state.session.lock().await;
        if let Some(session) = session.as_ref() {
            if session.created.elapsed() < REKEY_AFTER {
                return Ok(());
            }
        }
    }
    for _ in 0..2 {
        let (msg, pending) = build_initiation(state);
        *state.pending.lock().await = Some(pending);
        state.socket.send(&msg).await?;
        state.last_send_ms.store(now_ms(), Ordering::Relaxed);
        match tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            loop {
                state.ready.notified().await;
                let session = state.session.lock().await;
                if session.is_some() {
                    return;
                }
            }
        })
        .await
        {
            Ok(()) => return Ok(()),
            Err(_) => continue,
        }
    }
    Err(io::Error::new(io::ErrorKind::TimedOut, "wireguard: handshake timed out"))
}

async fn wg_send_transport(state: &WgState, payload: &[u8]) -> io::Result<()> {
    let mut guard = state.session.lock().await;
    let session = guard
        .as_mut()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "wireguard: no session"))?;
    let counter = session.send_counter;
    session.send_counter += 1;
    let ciphertext = aead_encrypt(&session.send_key, counter, payload, &[]);
    let mut packet = Vec::with_capacity(16 + ciphertext.len());
    packet.push(4);
    packet.extend_from_slice(&[0, 0, 0]);
    packet.extend_from_slice(&session.remote_index.to_le_bytes());
    packet.extend_from_slice(&counter.to_le_bytes());
    packet.extend_from_slice(&ciphertext);
    drop(guard);
    state.socket.send(&packet).await?;
    state.last_send_ms.store(now_ms(), Ordering::Relaxed);
    Ok(())
}

pub struct WireguardOutbound {
    name: String,
    endpoint: TargetAddr,
    private_key: [u8; 32],
    public_self: [u8; 32],
    peer_public: [u8; 32],
    preshared: [u8; 32],
    iface_v4: Option<Ipv4Addr>,
    iface_v6: Option<Ipv6Addr>,
    state: Mutex<Option<Arc<WgState>>>,
}

impl WireguardOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        private_key: &str,
        peer_public: &str,
        preshared: Option<&str>,
        ip: Option<&str>,
        ipv6: Option<&str>,
    ) -> Option<Self> {
        let private_key = decode_key(private_key)?;
        let secret = X25519Secret::from(private_key);
        let public_self: [u8; 32] = X25519Public::from(&secret).to_bytes();
        let endpoint = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(WireguardOutbound {
            name: name.to_string(),
            endpoint,
            private_key,
            public_self,
            peer_public: decode_key(peer_public)?,
            preshared: preshared.and_then(decode_key).unwrap_or([0u8; 32]),
            iface_v4: ip.and_then(|text| text.split('/').next()?.parse().ok()),
            iface_v6: ipv6.and_then(|text| text.split('/').next()?.parse().ok()),
            state: Mutex::new(None),
        })
    }

    async fn state(&self) -> io::Result<Arc<WgState>> {
        let mut guard = self.state.lock().await;
        if let Some(state) = guard.as_ref() {
            return Ok(state.clone());
        }
        let addr = *self
            .endpoint
            .resolve_all()
            .await?
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "wireguard: no endpoint"))?;
        let bind: SocketAddr = if addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        #[cfg(unix)]
        crate::jni::protect_fd(std::os::fd::AsRawFd::as_raw_fd(&socket));
        socket.connect(addr).await?;
        let state = Arc::new(WgState {
            socket,
            private_key: self.private_key,
            public_self: self.public_self,
            peer_public: self.peer_public,
            preshared: self.preshared,
            session: Mutex::new(None),
            pending: Mutex::new(None),
            ready: Notify::new(),
            udp_handlers: Mutex::new(Vec::new()),
            last_send_ms: AtomicU64::new(0),
            next_handler: AtomicU64::new(1),
        });

        // Receive pump: completes handshakes and fans decrypted inner
        // IP packets out to the registered UDP sessions.
        let pump = state.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                let n = match pump.socket.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(_) => return,
                };
                let packet = &buf[..n];
                match packet.first() {
                    Some(2) if packet.len() == 92 => {
                        let pending = pump.pending.lock().await.take();
                        if let Some(pending) = pending {
                            if let Some(session) = process_response(&pump, pending, packet) {
                                *pump.session.lock().await = Some(session);
                                pump.ready.notify_waiters();
                            }
                        }
                    }
                    Some(4) if packet.len() >= 16 => {
                        let receiver = u32::from_le_bytes(packet[4..8].try_into().unwrap());
                        let counter = u64::from_le_bytes(packet[8..16].try_into().unwrap());
                        let mut guard = pump.session.lock().await;
                        if let Some(session) = guard.as_mut() {
                            if receiver == session.local_index
                                && counter.saturating_add(2048) > session.highest_recv
                            {
                                if let Some(plain) =
                                    aead_decrypt(&session.recv_key, counter, &packet[16..], &[])
                                {
                                    if counter > session.highest_recv {
                                        session.highest_recv = counter;
                                    }
                                    drop(guard);
                                    if !plain.is_empty() {
                                        let bytes = Bytes::from(plain);
                                        let mut handlers = pump.udp_handlers.lock().await;
                                        handlers.retain(|(_, sender)| {
                                            sender.try_send(bytes.clone()).is_ok()
                                        });
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        // Keepalive: an empty transport packet after 20 s of silence.
        let keepalive = state.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let last = keepalive.last_send_ms.load(Ordering::Relaxed);
                if last != 0 && now_ms().saturating_sub(last) > 20_000 {
                    if keepalive.session.lock().await.is_some() {
                        let _ = wg_send_transport(&keepalive, &[]).await;
                    }
                }
            }
        });

        *guard = Some(state.clone());
        Ok(state)
    }
}

#[async_trait]
impl Outbound for WireguardOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "wireguard"
    }

    async fn connect(&self, _target: &TargetAddr) -> io::Result<BoxedStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "wireguard: TCP over the tunnel is not supported yet (UDP relay only)",
        ))
    }

    async fn connect_udp(&self, target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        let state = self.state().await?;
        let target_addr = *target
            .resolve_all()
            .await?
            .first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "wireguard: target unresolvable"))?;
        let iface = match target_addr.ip() {
            IpAddr::V4(_) => self
                .iface_v4
                .map(IpAddr::V4)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "wireguard: node has no IPv4 interface address"))?,
            IpAddr::V6(_) => self
                .iface_v6
                .map(IpAddr::V6)
                .ok_or_else(|| io::Error::new(io::ErrorKind::Unsupported, "wireguard: node has no IPv6 interface address"))?,
        };
        wg_ensure_session(&state).await?;
        let (tx, rx) = mpsc::channel::<Bytes>(64);
        let handler_id = state.next_handler.fetch_add(1, Ordering::Relaxed);
        state.udp_handlers.lock().await.push((handler_id, tx));
        let source_port = 20000 + (rand::random::<u16>() % 40000);
        Ok(Box::new(WgPacketConn {
            state,
            handler_id,
            target: target_addr,
            iface,
            source_port,
            rx: Mutex::new(WgRx { channel: rx, current: BytesMut::new() }),
        }))
    }
}

struct WgRx {
    channel: mpsc::Receiver<Bytes>,
    current: BytesMut,
}

struct WgPacketConn {
    state: Arc<WgState>,
    handler_id: u64,
    target: SocketAddr,
    iface: IpAddr,
    source_port: u16,
    rx: Mutex<WgRx>,
}

impl Drop for WgPacketConn {
    fn drop(&mut self) {
        let state = self.state.clone();
        let handler_id = self.handler_id;
        tokio::spawn(async move {
            state
                .udp_handlers
                .lock()
                .await
                .retain(|(id, _)| *id != handler_id);
        });
    }
}

impl WgPacketConn {
    fn build_packet(&self, payload: &[u8]) -> Vec<u8> {
        match (self.iface, self.target.ip()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let udp_len = 8 + payload.len();
                let total = 20 + udp_len;
                let mut packet = vec![0u8; total];
                packet[0] = 0x45;
                packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
                packet[4..6].copy_from_slice(&rand::random::<u16>().to_be_bytes());
                packet[8] = 64;
                packet[9] = 17;
                packet[12..16].copy_from_slice(&src.octets());
                packet[16..20].copy_from_slice(&dst.octets());
                let checksum = internet_checksum(&packet[..20]);
                packet[10..12].copy_from_slice(&checksum.to_be_bytes());
                packet[20..22].copy_from_slice(&self.source_port.to_be_bytes());
                packet[22..24].copy_from_slice(&self.target.port().to_be_bytes());
                packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
                packet[28..].copy_from_slice(payload);
                let mut pseudo = Vec::with_capacity(12 + udp_len);
                pseudo.extend_from_slice(&src.octets());
                pseudo.extend_from_slice(&dst.octets());
                pseudo.push(0);
                pseudo.push(17);
                pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
                pseudo.extend_from_slice(&packet[20..]);
                let udp_checksum = internet_checksum(&pseudo);
                packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
                packet
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let udp_len = 8 + payload.len();
                let mut packet = vec![0u8; 40 + udp_len];
                packet[0] = 0x60;
                packet[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
                packet[6] = 17;
                packet[7] = 64;
                packet[8..24].copy_from_slice(&src.octets());
                packet[24..40].copy_from_slice(&dst.octets());
                packet[40..42].copy_from_slice(&self.source_port.to_be_bytes());
                packet[42..44].copy_from_slice(&self.target.port().to_be_bytes());
                packet[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
                packet[48..].copy_from_slice(payload);
                let mut pseudo = Vec::with_capacity(40 + udp_len);
                pseudo.extend_from_slice(&src.octets());
                pseudo.extend_from_slice(&dst.octets());
                pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
                pseudo.extend_from_slice(&[0, 0, 0, 17]);
                pseudo.extend_from_slice(&packet[40..]);
                let udp_checksum = internet_checksum(&pseudo);
                packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
                packet
            }
            _ => Vec::new(),
        }
    }

    /// If `packet` is a UDP reply for this session, returns its payload.
    fn extract_payload(&self, packet: &[u8]) -> Option<Bytes> {
        match (self.iface, self.target.ip()) {
            (IpAddr::V4(iface), IpAddr::V4(target_ip)) => {
                if packet.len() < 28 || packet[0] >> 4 != 4 || packet[9] != 17 {
                    return None;
                }
                let ihl = ((packet[0] & 0x0f) as usize) * 4;
                if packet.len() < ihl + 8 {
                    return None;
                }
                if packet[12..16] != target_ip.octets() || packet[16..20] != iface.octets() {
                    return None;
                }
                let src_port = u16::from_be_bytes(packet[ihl..ihl + 2].try_into().ok()?);
                let dst_port = u16::from_be_bytes(packet[ihl + 2..ihl + 4].try_into().ok()?);
                let udp_len = u16::from_be_bytes(packet[ihl + 4..ihl + 6].try_into().ok()?) as usize;
                if src_port != self.target.port() || dst_port != self.source_port {
                    return None;
                }
                let end = (ihl + udp_len).min(packet.len());
                Some(Bytes::copy_from_slice(&packet[ihl + 8..end]))
            }
            (IpAddr::V6(iface), IpAddr::V6(target_ip)) => {
                if packet.len() < 48 || packet[0] >> 4 != 6 || packet[6] != 17 {
                    return None;
                }
                if packet[8..24] != target_ip.octets() || packet[24..40] != iface.octets() {
                    return None;
                }
                let src_port = u16::from_be_bytes(packet[40..42].try_into().ok()?);
                let dst_port = u16::from_be_bytes(packet[42..44].try_into().ok()?);
                let udp_len = u16::from_be_bytes(packet[44..46].try_into().ok()?) as usize;
                if src_port != self.target.port() || dst_port != self.source_port {
                    return None;
                }
                let end = (40 + udp_len).min(packet.len());
                Some(Bytes::copy_from_slice(&packet[48..end]))
            }
            _ => None,
        }
    }
}

#[async_trait]
impl PacketConn for WgPacketConn {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        let packet = self.build_packet(data);
        if packet.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "wireguard: address family mismatch"));
        }
        wg_ensure_session(&self.state).await?;
        wg_send_transport(&self.state, &packet).await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut rx = self.rx.lock().await;
        loop {
            if !rx.current.is_empty() {
                let n = rx.current.len().min(buf.len());
                buf[..n].copy_from_slice(&rx.current[..n]);
                rx.current.advance(n);
                return Ok(n);
            }
            match rx.channel.recv().await {
                Some(packet) => {
                    if let Some(payload) = self.extract_payload(&packet) {
                        rx.current = BytesMut::from(&payload[..]);
                    }
                }
                None => return Ok(0),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_decode() {
        // Base64 of the 32 bytes 0x00..0x1f.
        let key = decode_key("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
            .unwrap();
        assert_eq!(key.len(), 32);
        assert!(decode_key("short").is_none());
    }

    #[test]
    fn checksum_known_vector() {
        // IPv4 header checksum example (RFC 1071 style).
        let header: [u8; 20] = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet_checksum(&header), 0xb861);
    }

    #[tokio::test]
    async fn handshake_message_sizes() {
        // Initiation must be exactly 148 bytes, with mac1 over the
        // first 116 — a structural check of the Noise construction.
        let state = WgState {
            socket: tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            private_key: [7u8; 32],
            public_self: [8u8; 32],
            peer_public: [9u8; 32],
            preshared: [0u8; 32],
            session: Mutex::new(None),
            pending: Mutex::new(None),
            ready: Notify::new(),
            udp_handlers: Mutex::new(Vec::new()),
            last_send_ms: AtomicU64::new(0),
            next_handler: AtomicU64::new(1),
        };
        let (msg, _pending) = build_initiation(&state);
        assert_eq!(msg.len(), 148);
        assert_eq!(msg[0], 1);
    }
}
