//! Snell outbound (v1/v2/v3, v4 and v6).
//!
//! v1-v3 use the shadowaead chunk framing with an Argon2-derived subkey and
//! a plaintext salt, then a CONNECT header and a one-byte server reply.
//! v4 wraps records in a 7-byte sealed header with injected padding; v6 wraps
//! them in a profile-shaped record layer. Both are ported from the Go
//! reference (Clash.Meta/transport/snell/{v4,v6,v6_profile}.go).

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use blake2::digest::typenum::U32;
use blake2::Digest;
use blake2::Blake2b;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::adapter::tls::connect_tls;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const TAG_LEN: usize = 16;
const MAX_CHUNK: usize = 0x3FFF;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_CONNECT_V2: u8 = 0x05;
const REPLY_TUNNEL: u8 = 0x00;

fn aead_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "snell: AEAD operation failed")
}

fn snell_kdf(psk: &[u8], salt: &[u8]) -> io::Result<[u8; 32]> {
    // argon2.IDKey(psk, salt, 3, 8, 1, 32)
    // Go: argon2.IDKey(psk, salt, time=3, memory=8, threads=1, keyLen=32)
    let params = Params::new(8, 3, 1, Some(32)).map_err(|_| aead_error())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(psk, salt, &mut key).map_err(|_| aead_error())?;
    Ok(key)
}

enum Cipher {
    ChaCha(ChaCha20Poly1305),
    Aes(Aes128Gcm),
}

impl Cipher {
    fn new(version: i32, key: &[u8; 32]) -> io::Result<Self> {
        match version {
            1 => Ok(Self::ChaCha(ChaCha20Poly1305::new_from_slice(key).map_err(|_| aead_error())?)),
            2 | 3 => Ok(Self::Aes(Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| aead_error())?)),
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported Snell version")),
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], msg: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg, aad: &[] };
        match self {
            Self::ChaCha(c) => c.encrypt(ChaChaNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::Aes(c) => c.encrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], msg: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg, aad: &[] };
        match self {
            Self::ChaCha(c) => c.decrypt(ChaChaNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::Aes(c) => c.decrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
        }
    }
}

fn next_nonce(counter: &mut [u8; 12]) -> [u8; 12] {
    let nonce = *counter;
    for i in 0..NONCE_SIZE {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
    nonce
}

fn poll_read_exact(
    inner: &mut BoxedStream,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<()>> {
    while *filled < dst.len() {
        let mut buf = ReadBuf::new(&mut dst[*filled..]);
        match Pin::new(&mut *inner).poll_read(cx, &mut buf) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                if buf.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "snell: closed mid-frame")));
                }
                *filled += buf.filled().len();
            }
        }
    }
    Poll::Ready(Ok(()))
}

struct SnellStream {
    inner: BoxedStream,
    cipher: Cipher,
    write_nonce: [u8; 12],
    read_nonce: [u8; 12],
    pending: Vec<u8>,
    pending_off: usize,
    write_consumed: bool,
    last_n: usize,
    size_buf: [u8; 2],
    size_filled: usize,
    payload: Vec<u8>,
    payload_filled: usize,
    expect_payload: bool,
    plain: Vec<u8>,
    plain_off: usize,
}

impl SnellStream {
    fn new(inner: BoxedStream, cipher: Cipher) -> Self {
        Self {
            inner,
            cipher,
            write_nonce: [0u8; 12],
            read_nonce: [0u8; 12],
            pending: Vec::new(),
            pending_off: 0,
            write_consumed: false,
            last_n: 0,
            size_buf: [0u8; 2],
            size_filled: 0,
            payload: Vec::new(),
            payload_filled: 0,
            expect_payload: false,
            plain: Vec::new(),
            plain_off: 0,
        }
    }

    fn encrypt_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let len_nonce = next_nonce(&mut self.write_nonce);
        let enc_len = self.cipher.encrypt(&len_nonce, &(data.len() as u16).to_be_bytes())?;
        let data_nonce = next_nonce(&mut self.write_nonce);
        let enc_data = self.cipher.encrypt(&data_nonce, data)?;
        let mut out = Vec::with_capacity(enc_len.len() + enc_data.len());
        out.extend_from_slice(&enc_len);
        out.extend_from_slice(&enc_data);
        Ok(out)
    }

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_off < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "snell: write zero"))),
                Poll::Ready(Ok(n)) => self.pending_off += n,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SnellStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.plain_off < this.plain.len() {
                let n = buf.remaining().min(this.plain.len() - this.plain_off);
                buf.put_slice(&this.plain[this.plain_off..this.plain_off + n]);
                this.plain_off += n;
                return Poll::Ready(Ok(()));
            }
            this.plain.clear();
            this.plain_off = 0;

            if !this.expect_payload {
                match poll_read_exact(&mut this.inner, cx, &mut this.size_buf, &mut this.size_filled) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                // Same as Shadowsocks: the encrypted length chunk is 2+TAG.
                let size_nonce = next_nonce(&mut this.read_nonce);
                let len_plain = match this.cipher.decrypt(&size_nonce, &this.size_buf[..2 + TAG_LEN]) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                if len_plain.len() != 2 {
                    return Poll::Ready(Err(aead_error()));
                }
                let size = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize & MAX_CHUNK;
                this.size_filled = 0;
                if size == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.payload = vec![0u8; size + TAG_LEN];
                this.payload_filled = 0;
                this.expect_payload = true;
            }

            match poll_read_exact(&mut this.inner, cx, &mut this.payload, &mut this.payload_filled) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            let data_nonce = next_nonce(&mut this.read_nonce);
            this.plain = match this.cipher.decrypt(&data_nonce, &this.payload) {
                Ok(v) => v,
                Err(e) => return Poll::Ready(Err(e)),
            };
            this.expect_payload = false;
            this.payload_filled = 0;
        }
    }
}

impl AsyncWrite for SnellStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.flush_pending(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if !this.write_consumed {
            let n = buf.len().min(MAX_CHUNK);
            let frame = match this.encrypt_chunk(&buf[..n]) {
                Ok(f) => f,
                Err(e) => return Poll::Ready(Err(e)),
            };
            this.pending = frame;
            this.pending_off = 0;
            this.last_n = n;
            this.write_consumed = true;
        }
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                this.write_consumed = false;
                Poll::Ready(Ok(this.last_n))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_shutdown(cx),
        }
    }
}

pub struct SnellOutbound {
    name: String,
    server: TargetAddr,
    psk: Vec<u8>,
    version: i32,
    use_tls: bool,
    sni: String,
    verify: bool,
}

impl SnellOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        psk: &str,
        version: i32,
        use_tls: bool,
        sni: Option<&str>,
        verify: bool,
    ) -> Option<Self> {
        if psk.is_empty() || !(1..=6).contains(&version) {
            return None;
        }
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self { name: name.to_string(), server, psk: psk.as_bytes().to_vec(), version, use_tls, sni, verify })
    }

    fn header(&self, target: &TargetAddr) -> Vec<u8> {
        let host = target.host();
        let host_bytes = host.as_bytes();
        let len = host_bytes.len().min(255);
        let command = if self.version == 2 { COMMAND_CONNECT_V2 } else { COMMAND_CONNECT };
        let mut out = Vec::with_capacity(4 + len);
        out.push(0x01); // protocol version
        out.push(command);
        out.push(0x00); // client id length
        out.push(len as u8);
        out.extend_from_slice(&host_bytes[..len]);
        out.extend_from_slice(&target.port().to_be_bytes());
        out
    }
}

#[async_trait]
impl Outbound for SnellOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "Snell"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut last_error = None;
        let mut tcp = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(stream) => { tcp = Some(stream); break; }
                Err(e) => last_error = Some(e),
            }
        }
        let tcp = tcp.ok_or_else(|| last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no Snell server address")))?;

        let mut base: BoxedStream = if self.use_tls {
            connect_tls(&self.sni, tcp, self.verify).await?
        } else {
            Box::new(tcp)
        };

        match self.version {
            1 | 2 | 3 => {
                let mut salt = [0u8; SALT_SIZE];
                OsRng.fill_bytes(&mut salt);
                base.write_all(&salt).await?;
                let key = snell_kdf(&self.psk, &salt)?;
                let cipher = Cipher::new(self.version, &key)?;
                let mut stream = SnellStream::new(base, cipher);

                stream.write_all(&self.header(target)).await?;
                let mut reply = [0u8; 1];
                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut reply).await?;
                if reply[0] != REPLY_TUNNEL {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("Snell server error reply {}", reply[0])));
                }
                Ok(Box::new(stream))
            }
            4 => connect_v4(base, &self.psk, target).await,
            6 => connect_v6(base, &self.psk, V6Mode::Shaped, target).await,
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported Snell version")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_config() {
        assert!(SnellOutbound::try_new("s", "h", 443, "", 1, false, None, true).is_none());
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 0, false, None, true).is_none());
        // Snell v4 and v6 are now supported (ported from the Go reference).
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 4, false, None, true).is_some());
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 6, false, None, true).is_some());
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 1, false, None, true).is_some());
    }

    #[test]
    fn header_layout() {
        let outbound = SnellOutbound::try_new("s", "h", 443, "pw", 1, false, None, true).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let header = outbound.header(&TargetAddr::Ip(ip, 443));
        assert_eq!(header[0], 0x01);
        assert_eq!(header[1], COMMAND_CONNECT);
        assert_eq!(header[2], 0); // client id length
        assert_eq!(header[3], 7); // "1.2.3.4"
        assert_eq!(&header[4..11], b"1.2.3.4");
        assert_eq!(&header[11..], &443u16.to_be_bytes());

        let v2 = SnellOutbound::try_new("s", "h", 443, "pw", 2, false, None, true).unwrap();
        assert_eq!(v2.header(&TargetAddr::Domain("x".into(), 80))[1], COMMAND_CONNECT_V2);
    }

    #[test]
    fn kdf_is_stable() {
        let a = snell_kdf(b"password", &[1u8; 16]).unwrap();
        let b = snell_kdf(b"password", &[1u8; 16]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, snell_kdf(b"other", &[1u8; 16]).unwrap());
    }

    #[test]
    fn cipher_roundtrip() {
        let key = [7u8; 32];
        let cipher = Cipher::new(1, &key).unwrap();
        let nonce = [0u8; 12];
        let ct = cipher.encrypt(&nonce, b"hello").unwrap();
        assert_eq!(cipher.decrypt(&nonce, &ct).unwrap(), b"hello");
        let aes = Cipher::new(2, &key).unwrap();
        let ct2 = aes.encrypt(&nonce, b"hello").unwrap();
        assert_eq!(aes.decrypt(&nonce, &ct2).unwrap(), b"hello");
    }
}

// ---------------------------------------------------------------- snell v4

const V4_SALT_SIZE: usize = 16;
const V4_HEADER_PLAIN_SIZE: usize = 7;
const V4_HEADER_CIPHER_SIZE: usize = V4_HEADER_PLAIN_SIZE + TAG_LEN;
const V4_FRAME_SIZE: usize = 1460;
const V4_INITIAL_PADDING_MIN: u16 = 0x100;
const V4_INITIAL_PADDING_SPAN: u16 = 0x100;

fn v4_aead(psk: &[u8], salt: &[u8; V4_SALT_SIZE]) -> io::Result<Aes128Gcm> {
    let key = snell_kdf(psk, salt)?;
    Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| aead_error())
}

fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

fn seal_aead(aead: &Aes128Gcm, nonce: &[u8; NONCE_SIZE], plain: &[u8]) -> io::Result<Vec<u8>> {
    aead.encrypt(AesNonce::from_slice(nonce), plain).map_err(|_| aead_error())
}

/// Shaped-mode write: the padding region is the additional authenticated
/// data (the Go reference passes it to `aead.Seal`).
fn seal_aead_aad(
    aead: &Aes128Gcm,
    nonce: &[u8; NONCE_SIZE],
    plain: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    aead.encrypt(AesNonce::from_slice(nonce), Payload { msg: plain, aad })
        .map_err(|_| aead_error())
}

fn decrypt_aead(aead: &Aes128Gcm, nonce: &[u8; NONCE_SIZE], cipher: &[u8]) -> io::Result<Vec<u8>> {
    aead.decrypt(AesNonce::from_slice(nonce), cipher).map_err(|_| aead_error())
}

/// Shaped-mode read: the padding region is the additional authenticated
/// data (the Go reference passes it to `aead.Open`).
fn decrypt_aead_aad(
    aead: &Aes128Gcm,
    nonce: &[u8; NONCE_SIZE],
    cipher: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    aead.decrypt(AesNonce::from_slice(nonce), Payload { msg: cipher, aad })
        .map_err(|_| aead_error())
}

/// Uniform in [0, max), mirroring the `cryptoRandomInt` rejection sampling
/// used by the Go reference.
fn crypto_random_int(max: u64) -> u64 {
    if max == 0 {
        return 0;
    }
    let threshold = u64::MAX - (u64::MAX % max);
    loop {
        let value = OsRng.next_u64();
        if value < threshold {
            return value % max;
        }
    }
}

fn random_unit_float64() -> f64 {
    (OsRng.next_u64() % (1 << 53)) as f64 / 9007199254740992.0
}

fn make_v4_random_padding(length: usize) -> io::Result<Vec<u8>> {
    let mut padding = vec![0u8; length];
    OsRng.fill_bytes(&mut padding);
    Ok(padding)
}

fn count_v4_payload_ones(payload_cipher: &[u8]) -> u32 {
    // Only the trailing full 32-bit words count, as in the Go reference.
    let limit = payload_cipher.len() & !3;
    let mut ones = 0u32;
    for chunk in &payload_cipher[..limit] {
        ones += chunk.count_ones();
    }
    ones
}

fn make_v4_bit_count_padding(length: usize, one_bits: usize) -> io::Result<Vec<u8>> {
    let total_bits = 8 * length;
    let mut bitset = vec![0u8; total_bits];
    for bit in &mut bitset[..one_bits.min(total_bits)] {
        *bit = 1;
    }
    let mut i = total_bits as i64 - 1;
    while i > 0 {
        let j = crypto_random_int(i as u64 + 1) as usize;
        bitset.swap(i as usize, j);
        i -= 1;
    }
    let mut padding = vec![0u8; length];
    for (index, bit) in bitset.iter().enumerate() {
        if *bit == 1 {
            padding[index / 8] |= 1 << (index % 8);
        }
    }
    Ok(padding)
}

fn make_v4_padding(payload_cipher: &[u8], padding_length: usize) -> io::Result<Vec<u8>> {
    if padding_length == 0 {
        return Ok(Vec::new());
    }
    let payload_ones = count_v4_payload_ones(payload_cipher);
    let payload_zeros = 8 * payload_cipher.len() as u32 - payload_ones;
    if payload_zeros == 0 {
        return make_v4_random_padding(padding_length);
    }
    let ratio = payload_ones as f64 / payload_zeros as f64;
    if !(ratio > 0.5 && ratio < 1.6) {
        return make_v4_random_padding(padding_length);
    }
    let target_ratio_base = if payload_zeros < payload_ones { 0.4 } else { 1.6 };
    let jitter = random_unit_float64();
    let target_ratio = target_ratio_base + jitter / 10.0;
    let total_bits = 8 * (padding_length + payload_cipher.len());
    let target_ones =
        (total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - payload_ones as f64) as i64;
    if target_ones < 0 || target_ones as usize > 8 * padding_length {
        return make_v4_random_padding(padding_length);
    }
    make_v4_bit_count_padding(padding_length, target_ones as usize)
}

fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    for i in (0..limit).step_by(2) {
        let (a, b) = (padding[i], payload_cipher[i]);
        padding[i] = b;
        payload_cipher[i] = a;
    }
}

struct V4Writer {
    aead: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
    salt: [u8; V4_SALT_SIZE],
    salt_sent: bool,
    initial_padding_length: u16,
    payload_limit: u16,
    last_write: Option<Instant>,
}

impl V4Writer {
    fn new(psk: &[u8]) -> io::Result<V4Writer> {
        let mut salt = [0u8; V4_SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let aead = v4_aead(psk, &salt)?;
        let padding_delta = crypto_random_int(V4_INITIAL_PADDING_SPAN as u64);
        let initial_padding_length = V4_INITIAL_PADDING_MIN + padding_delta as u16;
        Ok(V4Writer {
            aead,
            nonce: [0u8; NONCE_SIZE],
            salt,
            salt_sent: false,
            initial_padding_length,
            payload_limit: 0,
            last_write: None,
        })
    }

    /// Port of Go's `v4Writer.nextPayloadLimit`: the first frame carries the
    /// random initial padding, later frames grow the payload limit.
    fn next_payload_limit(&mut self) -> u16 {
        let now = Instant::now();
        let payload_limit: i64 = match self.last_write {
            None => V4_FRAME_SIZE as i64 - 55 - self.initial_padding_length as i64,
            Some(last) if now.duration_since(last) > Duration::from_secs(30) => V4_FRAME_SIZE as i64 - 39,
            Some(_) => self.payload_limit as i64,
        };
        self.last_write = Some(now);
        if payload_limit <= MAX_CHUNK as i64 - 1 {
            let next = payload_limit + V4_FRAME_SIZE as i64 - 39;
            self.payload_limit =
                if next > MAX_CHUNK as i64 { MAX_CHUNK as u16 } else { next as u16 };
        } else {
            self.payload_limit = MAX_CHUNK as u16;
        }
        payload_limit as u16
    }

    fn next_frame_padding_length(&self, payload_length: usize) -> usize {
        if self.salt_sent || payload_length == 0 {
            0
        } else {
            self.initial_padding_length as usize
        }
    }

    /// Port of Go's `v4Writer.writeFrame`: build the sealed record (salt
    /// first, then the sealed header, the interleaved padding and the sealed
    /// payload ciphertext) and return it.
    fn build_frame(&mut self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let padding_length = self.next_frame_padding_length(payload.len());
        if payload.len() > MAX_CHUNK || padding_length > MAX_CHUNK {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "snell v4 frame too large"));
        }
        if payload.is_empty() && padding_length != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 zero chunk with padding",
            ));
        }
        let mut header = [0u8; V4_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut header_cipher = seal_aead(&self.aead, &self.nonce, &header)?;
        increment_nonce(&mut self.nonce);
        let mut payload_cipher = if payload.is_empty() {
            Vec::new()
        } else {
            let sealed = seal_aead(&self.aead, &self.nonce, payload)?;
            increment_nonce(&mut self.nonce);
            sealed
        };
        let mut out = Vec::with_capacity(
            usize::from(self.salt_sent) * V4_SALT_SIZE
                + header_cipher.len()
                + padding_length
                + payload_cipher.len(),
        );
        if !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        out.append(&mut header_cipher);
        if padding_length > 0 {
            let mut padding = make_v4_padding(&payload_cipher, padding_length)?;
            swap_padding(&mut padding, &mut payload_cipher);
            out.append(&mut padding);
        }
        out.append(&mut payload_cipher);
        Ok(out)
    }
}

/// Flush a whole buffer to the underlying stream, returning the number of
/// bytes written (only partial writes are reported).
fn poll_write_all(inner: &mut BoxedStream, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
    let mut written = 0usize;
    while written < buf.len() {
        match Pin::new(&mut **inner).poll_write(cx, &buf[written..]) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "snell v4 write zero")))
            }
            Poll::Ready(Ok(n)) => written += n,
        }
    }
    Poll::Ready(Ok(written))
}

struct V4Reader {
    aead: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
    buf: Vec<u8>,
    buf_off: usize,
}

impl V4Reader {
    /// Port of Go's `v4Conn.initReader`: the server's salt comes first on the
    /// wire; the AEAD is derived from it.
    async fn open(inner: &mut BoxedStream, psk: &[u8]) -> io::Result<V4Reader> {
        let mut salt = [0u8; V4_SALT_SIZE];
        inner.read_exact(&mut salt).await?;
        Ok(V4Reader { aead: v4_aead(psk, &salt)?, nonce: [0u8; NONCE_SIZE], buf: Vec::new(), buf_off: 0 })
    }

    /// Port of Go's `v4Reader.readFrame`: parse one sealed record.
    fn poll_read_frame(
        &mut self,
        inner: &mut BoxedStream,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Vec<u8>>> {
        let mut header_cipher = [0u8; V4_HEADER_CIPHER_SIZE];
        let mut filled = 0usize;
        match poll_read_exact(inner, cx, &mut header_cipher, &mut filled) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let header = match decrypt_aead(&self.aead, &self.nonce, &header_cipher) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        increment_nonce(&mut self.nonce);
        if header.len() != V4_HEADER_PLAIN_SIZE || header[0] != 4 {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "snell v4 invalid frame header")));
        }
        let padding_length = u16::from_be_bytes([header[3], header[4]]) as usize;
        let payload_length = u16::from_be_bytes([header[5], header[6]]) as usize;
        if payload_length == 0 {
            if padding_length != 0 {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "snell v4 zero chunk with padding")));
            }
            return Poll::Ready(Ok(Vec::new())); // zero chunk
        }
        if payload_length > MAX_CHUNK || padding_length > MAX_CHUNK {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "snell v4 frame too large")));
        }
        let payload_cipher_length = payload_length + TAG_LEN;
        let mut frame = vec![0u8; padding_length + payload_cipher_length];
        let mut filled = 0usize;
        match poll_read_exact(inner, cx, &mut frame, &mut filled) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        if padding_length > 0 {
            let (padding_part, payload_part) = frame.split_at_mut(padding_length);
            swap_padding(padding_part, payload_part);
        }
        let payload_cipher = frame[padding_length..].to_vec();
        match decrypt_aead(&self.aead, &self.nonce, &payload_cipher) {
            Ok(payload) => {
                increment_nonce(&mut self.nonce);
                Poll::Ready(Ok(payload))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_read(
        &mut self,
        inner: &mut BoxedStream,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.buf_off < self.buf.len() {
                let n = buf.remaining().min(self.buf.len() - self.buf_off);
                buf.put_slice(&self.buf[self.buf_off..self.buf_off + n]);
                self.buf_off += n;
                if self.buf_off == self.buf.len() {
                    self.buf.clear();
                    self.buf_off = 0;
                }
                return Poll::Ready(Ok(()));
            }
            self.buf.clear();
            self.buf_off = 0;
            match self.poll_read_frame(inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(payload)) => {
                    self.buf = payload;
                    // A zero chunk loops back to read the next record.
                }
            }
        }
    }
}

struct V4Stream {
    inner: BoxedStream,
    writer: V4Writer,
    reader: V4Reader,
    pending: Vec<u8>,
    pending_off: usize,
    writing: bool,
}

impl V4Stream {
    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_off < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "snell v4 write zero")))
                }
                Poll::Ready(Ok(n)) => self.pending_off += n,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for V4Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.reader.poll_read(&mut this.inner, cx, buf)
    }
}

impl AsyncWrite for V4Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.writing {
            let n = buf.len().min(MAX_CHUNK);
            let frame = match this.writer.build_frame(&buf[..n]) {
                Ok(f) => f,
                Err(e) => return Poll::Ready(Err(e)),
            };
            this.pending = frame;
            this.pending_off = 0;
            this.writing = true;
        }
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                this.writing = false;
                Poll::Ready(Ok(buf.len().min(MAX_CHUNK)))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn connect_v4(mut base: BoxedStream, psk: &[u8], target: &TargetAddr) -> io::Result<BoxedStream> {
    let mut writer = V4Writer::new(psk)?;
    let frame = writer.build_frame(&connect_command(target))?;
    base.write_all(&frame).await?;
    let reader = V4Reader::open(&mut base, psk).await?;
    let mut reply = [0u8; 1];
    base.read_exact(&mut reply).await?;
    if reply[0] != REPLY_TUNNEL {
        return Err(io::Error::new(io::ErrorKind::Other, format!("Snell server error reply {}", reply[0])));
    }
    Ok(Box::new(V4Stream {
        inner: base,
        writer,
        reader,
        pending: Vec::new(),
        pending_off: 0,
        writing: false,
    }))
}

/// The Snell v4/v6 CONNECT header: [0x01, command, 0x00, hostlen, host, port].
fn connect_command(target: &TargetAddr) -> Vec<u8> {
    let host = target.host();
    let host_bytes = host.as_bytes();
    let len = host_bytes.len().min(255);
    let mut out = Vec::with_capacity(4 + len);
    out.push(0x01);
    out.push(COMMAND_CONNECT);
    out.push(0x00); // client id length
    out.push(len as u8);
    out.extend_from_slice(&host_bytes[..len]);
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

// ---------------------------------------------------------------- snell v6

const V6_SALT_SIZE: usize = 16;
const V6_HEADER_VERSION: u8 = 4;
const V6_HEADER_PLAIN_SIZE: usize = 7;
const V6_HEADER_CIPHER_SIZE: usize = V6_HEADER_PLAIN_SIZE + TAG_LEN;
const V6_MAX_PAYLOAD: usize = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum V6Mode {
    /// The default: the profile-shaped record layer.
    Shaped,
    Unshaped,
    UnsafeRaw,
}

// Domain separators for the profile PRFs (port of the Go constants).
const V6_GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const V6_HANDSHAKE_DOMAIN: u32 = 0x7053;
const V6_MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const V6_CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;
const V6_NSS_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const V6_NSS_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const V6_NSS_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const V6_NSS_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const V6_NSS_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const V6_NSS_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const V6_NSS_WRITE: u64 = 0x917b_3c48_e6a2_05d4;
const V6_DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const V6_NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const V6_COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const V6_ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const V6_COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const V6_ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;
const V6_SALT_NS_XOR: u64 = 0xdaa6_6d2c_7ddf_743f;
const V6_MAX_EXTRA_PADDING: i64 = 0x02da;

const V6_LABEL_PADDING: u32 = 0;
const V6_LABEL_BIT_PERCENT: u32 = 1;
const V6_LABEL_MOTIF: u32 = 2;
const V6_LABEL_MIX_OFFSET: u32 = 3;
/// The Go reference's `v6LabelSalt` is an alias of the mix-offset label.
const V6_LABEL_SALT: u32 = V6_LABEL_MIX_OFFSET;
const V6_LABEL_PROFILE_ID: u32 = 5;
const V6_LABEL_GENERATOR: u32 = 6;
const V6_LABEL_PAD_MIN: u32 = 7;
const V6_LABEL_PAD_MAX: u32 = 8;
const V6_LABEL_PAD_COUNT: u32 = 9;
const V6_LABEL_PAD_INTERVAL: u32 = 10;
const V6_LABEL_SMALL_LIMIT: u32 = 11;
const V6_LABEL_BIT_MIN: u32 = 12;
const V6_LABEL_BIT_MAX: u32 = 13;
const V6_LABEL_PREFIX_MIN: u32 = 14;
const V6_LABEL_PREFIX_MAX: u32 = 15;
const V6_LABEL_MIX_MODE: u32 = 16;
const V6_LABEL_MIX_ROUNDS: u32 = 17;
const V6_LABEL_MIX_STRIDE: u32 = 18;
const V6_LABEL_MIX_OFFSET_BASE: u32 = 19;
const V6_LABEL_MIX_BLOCK: u32 = 20;
const V6_LABEL_CHUNK_POLICY: u32 = 21;
const V6_LABEL_CHUNK_INITIAL: u32 = 22;
const V6_LABEL_CHUNK_FIRST_CAP: u32 = 22;
const V6_LABEL_CHUNK_MAX: u32 = 23;
const V6_LABEL_CHUNK_STEP: u32 = 24;
const V6_LABEL_CHUNK_JITTER: u32 = 25;
const V6_LABEL_CHUNK_BUCKET: u32 = 26;
const V6_LABEL_IDLE_RESET: u32 = 27;
const V6_LABEL_WRITE_POLICY: u32 = 28;
const V6_LABEL_WRITE_FIRST: u32 = 29;
const V6_LABEL_WRITE_BUCKET: u32 = 30;
const V6_LABEL_WRITE_SEQ: u32 = 31;
const V6_LABEL_WRITE_JITTER: u32 = 32;
const V6_LABEL_RECORD_PREFIX: u32 = 33;
const V6_LABEL_PAYLOAD_PAD: u32 = 34;
const V6_LABEL_WRITE_TARGET: u32 = 35;
const V6_LABEL_WRITE_JITTER_V: u32 = 36;
const V6_LABEL_WRITE_NEXT: u32 = 37;
const V6_LABEL_CHUNK_SIZE: u32 = 38;
const V6_LABEL_CHUNK_JITTER_V: u32 = 39;

const V6_PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94,
    0x33, 0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

const V6_BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06,
    0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24,
    0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19,
    0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0,
    0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63,
    0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78, 0xf0,
    0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6,
    0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f, 0x1f,
    0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9,
    0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb,
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
    0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

fn v6_split_mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^= x >> 31;
    x
}

fn v6_prf32_fold(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let x = namespace
        ^ b.wrapping_mul(V6_COEF_B).wrapping_add(V6_ADD_B)
        ^ (label as u64).wrapping_mul(V6_GOLDEN_GAMMA)
        ^ a.wrapping_mul(V6_COEF_A).wrapping_add(V6_ADD_A);
    let y = v6_split_mix64(x);
    (y ^ (y >> 32)) as u32
}

fn v6_pick(raw: u32, lo: i64, hi: i64) -> i64 {
    debug_assert!(hi >= lo);
    lo + (raw as u64 % (hi - lo + 1) as u64) as i64
}

fn v6_pick_u32(raw: u32, lo: u32, hi: u32) -> u32 {
    debug_assert!(hi >= lo);
    lo + raw % (hi - lo + 1)
}

fn v6_profile_secret(psk: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(V6_PROFILE_SEED.len() + psk.len());
    input.extend_from_slice(&V6_PROFILE_SEED);
    input.extend_from_slice(psk);
    let mut out = [0u8; 32];
    out.copy_from_slice(&Blake2b::<U32>::digest(&input));
    out
}

#[derive(Debug, Clone, Copy)]
struct V6Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

fn v6_derive_namespace(secret: &[u8], label: u32, seed: u64) -> u64 {
    let s0 = u64::from_le_bytes(secret[0..8].try_into().unwrap());
    let s1 = u64::from_le_bytes(secret[8..16].try_into().unwrap());
    let s2 = u64::from_le_bytes(secret[16..24].try_into().unwrap());
    let s3 = u64::from_le_bytes(secret[24..32].try_into().unwrap());
    let mixed = (label as u64).wrapping_mul(V6_DOMAIN_MUL)
        ^ seed.wrapping_add(V6_NAMESPACE_ADD)
        ^ s0
        ^ s1.wrapping_add(V6_GOLDEN_GAMMA)
        ^ s2.rotate_left(17)
        ^ s3.rotate_left(53); // Go: bits.RotateLeft64(s3, -11)
    v6_split_mix64(mixed)
}

impl V6Namespaces {
    fn new(secret: &[u8]) -> Self {
        Self {
            profile: v6_derive_namespace(secret, V6_LABEL_PROFILE_ID, V6_NSS_PROFILE),
            prefix: v6_derive_namespace(secret, V6_LABEL_PADDING, V6_NSS_PREFIX),
            motif: v6_derive_namespace(secret, V6_LABEL_MOTIF, V6_NSS_MOTIF),
            salt: v6_derive_namespace(secret, V6_LABEL_SALT, V6_NSS_SALT),
            mix: v6_derive_namespace(secret, V6_LABEL_MIX_MODE, V6_NSS_MIX),
            chunk: v6_derive_namespace(secret, V6_LABEL_CHUNK_POLICY, V6_NSS_CHUNK),
            write: v6_derive_namespace(secret, V6_LABEL_WRITE_POLICY, V6_NSS_WRITE),
        }
    }

    fn for_label(&self, label: u32) -> u64 {
        match label {
            V6_LABEL_PADDING | V6_LABEL_BIT_PERCENT | V6_LABEL_PREFIX_MIN
            | V6_LABEL_PREFIX_MAX | V6_LABEL_RECORD_PREFIX | V6_LABEL_PAYLOAD_PAD => self.prefix,
            V6_LABEL_MOTIF => self.motif,
            V6_LABEL_MIX_OFFSET | V6_LABEL_MIX_MODE | V6_LABEL_MIX_ROUNDS | V6_LABEL_MIX_STRIDE
            | V6_LABEL_MIX_OFFSET_BASE | V6_LABEL_MIX_BLOCK => self.mix,
            V6_LABEL_CHUNK_POLICY | V6_LABEL_CHUNK_INITIAL | V6_LABEL_CHUNK_MAX
            | V6_LABEL_CHUNK_STEP | V6_LABEL_CHUNK_JITTER | V6_LABEL_CHUNK_BUCKET
            | V6_LABEL_CHUNK_SIZE | V6_LABEL_CHUNK_JITTER_V => self.chunk,
            V6_LABEL_WRITE_POLICY | V6_LABEL_WRITE_FIRST | V6_LABEL_WRITE_BUCKET
            | V6_LABEL_WRITE_SEQ | V6_LABEL_WRITE_JITTER | V6_LABEL_WRITE_TARGET
            | V6_LABEL_WRITE_JITTER_V | V6_LABEL_WRITE_NEXT => self.write,
            _ => self.profile,
        }
    }

    fn prf32(&self, label: u32, a: u32, b: u32) -> u32 {
        v6_prf32_fold(self.for_label(label), label, a as u64, b as u64)
    }

    fn prf_bytes(&self, label: u32, a: u32, output: &mut [u8]) {
        let mut seed = self.for_label(label)
            ^ (a as u64).wrapping_mul(V6_DOMAIN_MUL).wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ (label as u64).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (output.len() as u64).wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        let mut offset = 0;
        while offset < output.len() {
            seed = seed.wrapping_add(V6_GOLDEN_GAMMA);
            let block = v6_split_mix64(seed);
            for shift in (0..64).step_by(8) {
                if offset >= output.len() {
                    break;
                }
                output[offset] = (block >> shift) as u8;
                offset += 1;
            }
        }
    }

    fn prf_static(&self, label: u32, domain: u32) -> u32 {
        v6_prf32_fold(self.for_label(label), label, 0, domain as u64)
    }
}

#[derive(Debug, Clone)]
struct V6Profile {
    namespaces: V6Namespaces,
    generator: u32,
    pad_min: i64,
    pad_max: i64,
    pad_count: u32,
    pad_interval: u32,
    small_limit: i64,
    bit_min: u32,
    bit_max: u32,
    prefix_min_record: i64,
    prefix_max_record: i64,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: i64,
    mix_offset_base: i64,
    mix_block: i64,
    chunk_policy: u32,
    chunk_initial: i64,
    first_record_cap: i64,
    chunk_max: i64,
    chunk_step: i64,
    chunk_jitter: i64,
    idle_reset_sec: i64,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [i64; 8],
    write_buckets: [i64; 8],
    write_seq: [i64; 8],
    write_jitter: i64,
    write_jitter_pct: i64,
    g1: i64,
    g2: i64,
    g3: i64,
    g4: i64,
    g5: i64,
    g6: i64,
    salt_block_len: usize,
    mix_stride_handshake: i64,
    mix_rounds_handshake: u32,
}

impl V6Profile {
    fn new(psk: &[u8]) -> V6Profile {
        let secret = v6_profile_secret(psk);
        let ns = V6Namespaces::new(&secret);

        let pad_min = v6_pick(ns.prf_static(V6_LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max =
            (pad_min + v6_pick(ns.prf_static(V6_LABEL_PAD_MAX, 0), 0xa0, 0x3c0)).min(V6_MAX_EXTRA_PADDING);

        let prefix_min_hs =
            v6_pick(ns.prf_static(V6_LABEL_PREFIX_MIN, V6_HANDSHAKE_DOMAIN), 0x10, 0x60);
        let prefix_max_hs =
            (prefix_min_hs + v6_pick(ns.prf_static(V6_LABEL_PREFIX_MAX, V6_HANDSHAKE_DOMAIN), 0x10, 0xa0)).min(0x80);
        let prefix_min_hs = prefix_min_hs.min(prefix_max_hs);
        let salt_prefix_len =
            v6_pick(ns.prf_static(V6_LABEL_RECORD_PREFIX, V6_HANDSHAKE_DOMAIN), prefix_min_hs, prefix_max_hs);
        let salt_block_len = V6_SALT_SIZE + salt_prefix_len as usize;

        let mix_rounds_handshake =
            v6_pick_u32(ns.prf_static(V6_LABEL_MIX_ROUNDS, V6_MIX_HANDSHAKE_DOMAIN), 1, 4);
        let mix_stride_handshake =
            v6_pick(ns.prf_static(V6_LABEL_MIX_STRIDE, V6_MIX_HANDSHAKE_DOMAIN), 0x11, 0xfb);

        let prefix_min_record =
            v6_pick(ns.prf_static(V6_LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let prefix_max_record =
            (prefix_min_record + v6_pick(ns.prf_static(V6_LABEL_PREFIX_MAX, 0), 0x10, 0xa0)).min(0x80);
        let prefix_min_record = prefix_min_record.min(prefix_max_record);

        let chunk_initial = (0x60i64)
            .max(v6_pick(ns.prf_static(V6_LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4).min(0x05b4));
        let first_record_cap = (0x100i64)
            .max(v6_pick(ns.prf_static(V6_LABEL_CHUNK_FIRST_CAP, V6_CHUNK_INITIAL_DOMAIN), 0x100, 0x300)
                .min(chunk_initial.min(0x300)));
        let chunk_max = v6_pick(ns.prf_static(V6_LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff).max(chunk_initial);

        let profile = V6Profile {
            namespaces: ns,
            generator: ns.prf_static(V6_LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: v6_pick_u32(ns.prf_static(V6_LABEL_PAD_COUNT, 0), 2, 8),
            pad_interval: v6_pick_u32(ns.prf_static(V6_LABEL_PAD_INTERVAL, 0), 2, 0x0b),
            small_limit: v6_pick(ns.prf_static(V6_LABEL_SMALL_LIMIT, 0), 0x60, 0x300),
            bit_min: v6_pick_u32(ns.prf_static(V6_LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: v6_pick_u32(ns.prf_static(V6_LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min_record,
            prefix_max_record,
            mix_mode: ns.prf_static(V6_LABEL_MIX_MODE, 0) % 3,
            mix_rounds: v6_pick_u32(ns.prf_static(V6_LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: v6_pick(ns.prf_static(V6_LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset_base: v6_pick(ns.prf_static(V6_LABEL_MIX_OFFSET_BASE, 0), 0, 15),
            mix_block: v6_pick(ns.prf_static(V6_LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: ns.prf_static(V6_LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: v6_pick(ns.prf_static(V6_LABEL_CHUNK_STEP, 0), 0x400, 0x1000).min(0x0b68),
            chunk_jitter: v6_pick(ns.prf_static(V6_LABEL_CHUNK_JITTER, 0), 0x10, 0xc0).min(0x0b6),
            idle_reset_sec: v6_pick(ns.prf_static(V6_LABEL_IDLE_RESET, 0), 0x0c, 0x5a),
            write_policy: ns.prf_static(V6_LABEL_WRITE_POLICY, 0) % 3,
            write_first: v6_pick_u32(ns.prf_static(V6_LABEL_WRITE_FIRST, 0), 4, 8),
            write_jitter: v6_pick(ns.prf_static(V6_LABEL_WRITE_JITTER, 0), 0x08, 0x60),
            write_jitter_pct: v6_pick(ns.prf_static(V6_LABEL_WRITE_POLICY, 0x504c), 8, 0x30),
            g1: v6_pick(ns.prf_static(V6_LABEL_GENERATOR, 1), 0x18, 0x80),
            g2: v6_pick(ns.prf_static(V6_LABEL_GENERATOR, 2), 0x10, 0x60),
            g3: v6_pick(ns.prf_static(V6_LABEL_GENERATOR, 3), 0x10, 0x60),
            g4: v6_pick(ns.prf_static(V6_LABEL_GENERATOR, 4), 0x00, 0x09),
            g5: v6_pick(ns.prf_static(V6_LABEL_GENERATOR, 5), 0x01, 0x08),
            g6: v6_pick(ns.prf_static(V6_LABEL_GENERATOR, 6), 0x07, 0x17),
            salt_block_len,
            mix_stride_handshake,
            mix_rounds_handshake,
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_seq: [0; 8],
        };

        let mut profile = profile;
        for index in 0..8 {
            profile.chunk_buckets[index] =
                v6_pick(ns.prf_static(V6_LABEL_CHUNK_BUCKET, index as u32), 0x1000, chunk_max);
            profile.write_buckets[index] =
                v6_pick(ns.prf_static(V6_LABEL_WRITE_BUCKET, index as u32), 0x140, 0x05b4);
            profile.write_seq[index] =
                v6_pick(ns.prf_static(V6_LABEL_WRITE_SEQ, index as u32), 0x168, 0x05b4);
        }
        profile
    }

    fn record_prefix_len(&self, seq: u32) -> usize {
        v6_pick(
            self.namespaces.prf32(V6_LABEL_RECORD_PREFIX, seq, 0),
            self.prefix_min_record,
            self.prefix_max_record,
        ) as usize
    }

    fn chunk_payload_limit(&self, seq: u32, chunk_size: usize) -> usize {
        let chunk_size = if chunk_size == 0 { self.chunk_initial } else { chunk_size as i64 };
        let chunk_size = match self.chunk_policy {
            1 => {
                let index =
                    (self.namespaces.prf32(V6_LABEL_CHUNK_SIZE, seq, chunk_size as u32) as usize)
                        % 8;
                self.chunk_buckets[index]
            }
            2 => {
                let raw = self.namespaces.prf32(V6_LABEL_CHUNK_JITTER_V, seq, chunk_size as u32);
                chunk_size + raw as i64 % (2 * self.chunk_jitter + 1) - self.chunk_jitter
            }
            _ => chunk_size,
        };
        chunk_size.clamp(0x40, self.chunk_max) as usize
    }

    fn next_chunk_size(&self, chunk_size: usize) -> usize {
        if chunk_size == 0 {
            self.chunk_initial as usize
        } else {
            (chunk_size as i64 + self.chunk_step).min(self.chunk_max) as usize
        }
    }

    fn padding_len(
        &self,
        seq: u32,
        payload_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        total_len: usize,
    ) -> usize {
        let mut padding_len = 0i64;
        if seq < self.pad_count as u32
            || (payload_len > 0 && payload_len as i64 <= self.small_limit)
            || (self.pad_interval > 0 && seq % self.pad_interval == 0)
        {
            padding_len = v6_pick(
                self.namespaces.prf32(V6_LABEL_PAYLOAD_PAD, seq, payload_len as u32),
                self.pad_min,
                self.pad_max,
            );
        }
        let payload_tag_len = if payload_len > 0 { TAG_LEN as i64 } else { 0 };
        let frame_len =
            total_len as i64 + prefix_len as i64 + V6_HEADER_CIPHER_SIZE as i64 + padding_len + payload_len as i64 + payload_tag_len;
        let target_len = self.write_target(seq, frame_len);
        if target_len > frame_len {
            padding_len += (target_len - frame_len).min(V6_MAX_EXTRA_PADDING);
        }
        if total_len > 0 {
            padding_len =
                self.first_record_padding_len(padding_len, prefix_len, salt_prefix_len, payload_len);
        }
        padding_len.min(0xffff) as usize
    }

    fn write_target(&self, seq: u32, frame_len: i64) -> i64 {
        if frame_len > 0x05b3 {
            return if frame_len <= 0xffff { frame_len } else { 0xffff };
        }
        let mut target_len = if seq < self.write_first {
            self.write_seq[seq as usize]
        } else {
            self.write_buckets
                [(self.namespaces.prf32(V6_LABEL_WRITE_TARGET, seq, frame_len as u32) as usize) % 8]
        };
        if self.write_policy == 2 {
            let raw_jitter = self.namespaces.prf32(V6_LABEL_WRITE_JITTER_V, seq, 0);
            let jitter = raw_jitter as i64 % (2 * self.write_jitter + 1) - self.write_jitter;
            target_len = (target_len + jitter).max(1);
        }
        let spread = (frame_len.max(0) as u64 * self.write_jitter_pct as u64 / 100).min(V6_MAX_EXTRA_PADDING as u64) as i64;
        if self.namespaces.prf32(V6_LABEL_WRITE_TARGET, seq, spread as u32) & 1 == 0 {
            if target_len + spread <= 0xffff {
                target_len += spread;
            } else {
                target_len = 0xffff;
            }
        } else {
            let half_spread = spread >> 1;
            if target_len > half_spread {
                target_len -= half_spread;
            }
        }
        while target_len >= 0 && frame_len > target_len {
            let next_len = self.write_buckets
                [(self.namespaces.prf32(V6_LABEL_WRITE_NEXT, seq, target_len as u32) as usize) % 8];
            if next_len <= target_len {
                target_len += self.pad_max;
                if target_len > 0xffff {
                    return 0xffff;
                }
            } else {
                target_len = next_len;
            }
        }
        target_len
    }

    fn first_record_padding_len(
        &self,
        padding_len: i64,
        prefix_len: usize,
        salt_prefix_len: usize,
        payload_len: usize,
    ) -> i64 {
        let overhead_len = salt_prefix_len as i64 + prefix_len as i64 + padding_len;
        let threshold_input = if payload_len == 0 {
            payload_len as i64 + 0x27
        } else {
            payload_len as i64 + 0x37
        };
        let threshold = ((threshold_input * 25 + 0x4a) / 75).max(0xc0);
        if overhead_len >= threshold {
            return padding_len;
        }
        let target_padding_len = threshold - salt_prefix_len as i64 - prefix_len as i64;
        let max_padding_len = self.pad_max + V6_MAX_EXTRA_PADDING;
        if max_padding_len <= target_padding_len {
            return max_padding_len;
        }
        if target_padding_len > 0xfffe {
            return padding_len;
        }
        target_padding_len
    }

    fn fill_padding(&self, seq: u32, output: &mut [u8]) {
        if output.is_empty() {
            return;
        }
        self.namespaces.prf_bytes(V6_LABEL_PADDING, seq, output);
        match self.generator {
            0 => {
                let bit_count = self.namespaces.prf32(V6_LABEL_BIT_PERCENT, seq, 0);
                let mut rotate = 1usize;
                let scaled = (bit_count as usize) * 8;
                if scaled > 0x31 {
                    rotate = 7;
                    if scaled <= 0x02ed {
                        rotate = (scaled + 0x32) / 100;
                    }
                }
                for (index, value) in output.iter_mut().enumerate() {
                    let original = *value;
                    let raw = original.wrapping_add((index & 0xff) as u8);
                    let table_value =
                        V6_BIT_ROTATE_TABLE[rotate.max(1) * 16 + ((raw ^ original) & 0x0f) as usize];
                    *value = table_value.rotate_left(((raw ^ (original >> 4)) & 7) as u32);
                }
            }
            1 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let original = *value;
                    let bucket = (original as i64) % (self.g1 + self.g2 + self.g3);
                    *value = if bucket < self.g1 {
                        v6_pick((original as i64 + index as i64) as u8 as u32, 0x20, 0x7e) as u8
                    } else if bucket < self.g1 + self.g2 {
                        v6_pick((original as i64 ^ index as i64) as u8 as u32, 0x80, 0xbf) as u8
                    } else {
                        v6_pick((original as i64 + index as i64 * 7) as u8 as u32, 0xc0, 0xff) as u8
                    };
                }
            }
            2 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let low = (original_low_bits(value) + self.g4 + (index & 1) as i64) % 10;
                    let high =
                        ((*value as i64) + (((index & 3) as i64) << 4) + 0x30) & 0xf0;
                    *value = (high | low) as u8;
                }
            }
            3 => {
                let mut motif = [0u8; 32];
                self.namespaces.prf_bytes(V6_LABEL_MOTIF, seq, &mut motif);
                let motif_len = (self.g5 * 4).max(4);
                let period = self.g6.max(5);
                let mut block_offset = 0i64;
                let mut motif_offset = 0usize;
                for (index, value) in output.iter_mut().enumerate() {
                    match () {
                        _ if block_offset < period - 3 => {
                            *value = (((self.g5 + 3) * index as i64) as u8)
                                ^ motif[motif_offset % motif.len()];
                        }
                        _ if block_offset < period - 1 => {
                            *value = (0x30 | ((*value as i64) % 10)) as u8;
                        }
                        _ => {}
                    }
                    block_offset += 1;
                    if block_offset == period {
                        block_offset = 0;
                    }
                    motif_offset += 1;
                    if motif_offset == motif_len as usize {
                        motif_offset = 0;
                    }
                }
            }
            _ => {}
        }
    }

    fn salt_shuffle_prf(ns_salt: u64, domain: u32, index: u32) -> u32 {
        let rdx = index as u64 * V6_COEF_B + V6_ADD_B;
        let rdi = ns_salt ^ V6_SALT_NS_XOR;
        let rsi = domain as u64 * V6_COEF_A + V6_ADD_A;
        let y = v6_split_mix64(rdx ^ rdi ^ rsi);
        (y ^ (y >> 32)) as u32
    }

    fn shuffle_perm(ns_salt: u64, rounds: u8, length: usize) -> Vec<u8> {
        let mut out: Vec<u8> = (0..length as u8).collect();
        if length == 0 {
            return out;
        }
        let rounds = if rounds == 0 { 1 } else { rounds as u32 };
        for round in 0..rounds {
            let domain = V6_MIX_HANDSHAKE_DOMAIN + round;
            for i in 0..length {
                let span = (length - i) as u64;
                let raw = V6Profile::salt_shuffle_prf(ns_salt, domain, i as u32) as u64;
                let j = i + (raw % span) as usize;
                out.swap(i, j);
            }
        }
        out
    }

    fn salt_mask(ns_salt: u64, mix_stride: u8, index: u32) -> u8 {
        let prf = v6_prf32_fold(ns_salt, V6_LABEL_MOTIF, V6_MIX_HANDSHAKE_DOMAIN as u64, index as u64);
        (index as u8).wrapping_mul(mix_stride) ^ prf as u8
    }

    fn extract_salt(&self, block: &[u8]) -> [u8; V6_SALT_SIZE] {
        let perm = V6Profile::shuffle_perm(self.namespaces.salt, self.mix_rounds_handshake as u8, block.len());
        let mut out = [0u8; V6_SALT_SIZE];
        for i in 0..V6_SALT_SIZE {
            out[i] = V6Profile::salt_mask(self.namespaces.salt, self.mix_stride_handshake as u8, i as u32)
                ^ block[perm[i] as usize];
        }
        out
    }

    fn write_salt_block(&self, salt: &[u8], block: &mut [u8]) {
        let perm = V6Profile::shuffle_perm(self.namespaces.salt, self.mix_rounds_handshake as u8, block.len());
        for i in 0..V6_SALT_SIZE {
            block[perm[i] as usize] =
                V6Profile::salt_mask(self.namespaces.salt, self.mix_stride_handshake as u8, i as u32)
                    ^ salt[i];
        }
    }

    fn mix_padding_payload(&self, seq: u32, padding: &mut [u8], payload_cipher: &mut [u8]) {
        let n = padding.len().min(payload_cipher.len());
        if n == 0 {
            return;
        }
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => self.mix_fixed_stride(round, padding, payload_cipher, n),
                1 => self.mix_alternating_block(round, padding, payload_cipher, n),
                2 => self.mix_prf_stride(seq, round, padding, payload_cipher, n),
                _ => {}
            }
        }
    }

    fn mix_fixed_stride(&self, round: u32, padding: &mut [u8], payload_cipher: &mut [u8], n: usize) {
        let stride = (self.mix_stride + i64::from(round % 3)).max(1) as usize;
        if stride == 1 {
            for i in 0..n {
                let (a, b) = (padding[i], payload_cipher[i]);
                padding[i] = b;
                payload_cipher[i] = a;
            }
            return;
        }
        let mut off = (self.mix_offset_base % stride as i64).max(0);
        while off < n as i64 {
            let i = off as usize;
            let (a, b) = (padding[i], payload_cipher[i]);
            padding[i] = b;
            payload_cipher[i] = a;
            off += stride as i64;
        }
    }

    fn mix_alternating_block(&self, round: u32, padding: &mut [u8], payload_cipher: &mut [u8], n: usize) {
        let block = self.mix_block as usize;
        let mut off = i64::from(round & 1) * block as i64;
        while off + block as i64 <= n as i64 {
            for i in off as usize..off as usize + block {
                let (a, b) = (padding[i], payload_cipher[i]);
                padding[i] = b;
                payload_cipher[i] = a;
            }
            off += (block * 2) as i64;
        }
    }

    fn mix_prf_stride(&self, seq: u32, round: u32, padding: &mut [u8], payload_cipher: &mut [u8], n: usize) {
        let stride = (self.mix_stride + i64::from(round % 3)).max(1);
        let off = (self.namespaces.prf32(V6_LABEL_MIX_OFFSET, seq, round) as i64
            + self.mix_offset_base)
            % stride;
        let mut off = off.max(0);
        if stride == 1 {
            for i in 0..n {
                let (a, b) = (padding[i], payload_cipher[i]);
                padding[i] = b;
                payload_cipher[i] = a;
            }
            return;
        }
        while off < n as i64 {
            let i = off as usize;
            let (a, b) = (padding[i], payload_cipher[i]);
            padding[i] = b;
            payload_cipher[i] = a;
            off += stride;
        }
    }
}

fn original_low_bits(value: &u8) -> i64 {
    (*value as i64) & 0x0f
}

fn v6_bad_header_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "snell v6 invalid record header")
}

fn v6_record_padding_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "snell v6 unexpected padding in record")
}

fn v6_put_header(header: &mut [u8], padding_length: usize, payload_length: usize) {
    header[0] = V6_HEADER_VERSION;
    header[1] = 0;
    header[2] = 0;
    header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
    header[5..7].copy_from_slice(&(payload_length as u16).to_be_bytes());
}

/// Port of Go's `v6ParseHeader`; `strict` requires the reserved bytes to be
/// zero (the official server only checks them outside of the default mode).
fn v6_parse_header(header: &[u8], strict: bool) -> io::Result<(usize, usize)> {
    if header[0] != V6_HEADER_VERSION {
        return Err(v6_bad_header_error());
    }
    if strict && (header[1] != 0 || header[2] != 0) {
        return Err(v6_bad_header_error());
    }
    Ok((
        u16::from_be_bytes([header[3], header[4]]) as usize,
        u16::from_be_bytes([header[5], header[6]]) as usize,
    ))
}

fn v6_aead(psk: &[u8], salt: &[u8; V6_SALT_SIZE]) -> io::Result<Aes128Gcm> {
    let key = snell_kdf(psk, salt)?;
    Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| aead_error())
}

fn poll_read_all(inner: &mut BoxedStream, cx: &mut Context<'_>, dst: &mut [u8]) -> Poll<io::Result<()>> {
    let mut filled = 0usize;
    poll_read_exact(inner, cx, dst, &mut filled)
}

/// Read exactly the record stream of the next record (or a zero chunk) and
/// return its payload. Mirrors `V6RecordReader::readRecord` per mode.
trait V6RecordReader: Send {
    fn poll_read_record(
        &mut self,
        inner: &mut BoxedStream,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<Vec<u8>>>;
}

trait V6RecordWriter: Send {
    fn poll_write(
        &mut self,
        inner: &mut BoxedStream,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>;
}

struct V6RawWriter;

impl V6RawWriter {
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; V6_HEADER_PLAIN_SIZE + payload.len()];
        v6_put_header(&mut out[..V6_HEADER_PLAIN_SIZE], 0, payload.len());
        out[V6_HEADER_PLAIN_SIZE..].copy_from_slice(payload);
        out
    }
}

impl V6RecordWriter for V6RawWriter {
    fn poll_write(&mut self, inner: &mut BoxedStream, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let n = buf.len().min(V6_MAX_PAYLOAD);
        let out = V6RawWriter::record(&buf[..n]);
        match poll_write_all(inner, cx, &out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(n)),
        }
    }
}

struct V6RawReader;

impl V6RecordReader for V6RawReader {
    fn poll_read_record(&mut self, inner: &mut BoxedStream, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        let mut header = [0u8; V6_HEADER_PLAIN_SIZE];
        match poll_read_all(inner, cx, &mut header) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let (padding_length, payload_length) = match v6_parse_header(&header, true) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if padding_length != 0 {
            return Poll::Ready(Err(v6_record_padding_error()));
        }
        if payload_length == 0 {
            return Poll::Ready(Ok(Vec::new())); // zero chunk
        }
        let mut payload = vec![0u8; payload_length];
        match poll_read_all(inner, cx, &mut payload) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        Poll::Ready(Ok(payload))
    }
}

struct V6UnshapedWriter {
    aead: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
    salt: Vec<u8>,
    salt_sent: bool,
}

impl V6UnshapedWriter {
    fn new(psk: &[u8]) -> io::Result<V6UnshapedWriter> {
        let mut salt = vec![0u8; V6_SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let aead = v6_aead(psk, &salt.clone().try_into().map_err(|_| aead_error())?)?;
        Ok(V6UnshapedWriter { aead, nonce: [0u8; NONCE_SIZE], salt, salt_sent: false })
    }

    /// Port of Go's `v6UnshapedWriter::appendRecord`.
    fn append_record(&mut self, mut out: Vec<u8>, payload: &[u8]) -> io::Result<Vec<u8>> {
        let start = out.len();
        out.resize(start + V6_HEADER_PLAIN_SIZE, 0);
        v6_put_header(&mut out[start..start + V6_HEADER_PLAIN_SIZE], 0, payload.len());
        let header = out[start..start + V6_HEADER_PLAIN_SIZE].to_vec();
        let sealed = seal_aead(&self.aead, &self.nonce, &header)?;
        increment_nonce(&mut self.nonce);
        out.truncate(start);
        out.extend_from_slice(&sealed);
        if !payload.is_empty() {
            let sealed = seal_aead(&self.aead, &self.nonce, payload)?;
            increment_nonce(&mut self.nonce);
            out.extend_from_slice(&sealed);
        }
        Ok(out)
    }
}

impl V6RecordWriter for V6UnshapedWriter {
    fn poll_write(&mut self, inner: &mut BoxedStream, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut out = Vec::with_capacity(V6_HEADER_CIPHER_SIZE + buf.len() + TAG_LEN);
        if !self.salt_sent {
            out.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        match self.append_record(out, buf) {
            Ok(o) => match poll_write_all(inner, cx, &o) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            },
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

struct V6UnshapedReader {
    psk: Vec<u8>,
    aead: Option<Aes128Gcm>,
    nonce: [u8; NONCE_SIZE],
}

impl V6UnshapedReader {
    fn new(psk: &[u8]) -> V6UnshapedReader {
        V6UnshapedReader { psk: psk.to_vec(), aead: None, nonce: [0u8; NONCE_SIZE] }
    }
}

impl V6RecordReader for V6UnshapedReader {
    fn poll_read_record(&mut self, inner: &mut BoxedStream, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        if self.aead.is_none() {
            let mut salt = [0u8; V6_SALT_SIZE];
            match poll_read_all(inner, cx, &mut salt) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            self.aead = Some(v6_aead(&self.psk, &salt)?);
        }
        let aead = self.aead.as_ref().unwrap();
        let mut header_cipher = vec![0u8; V6_HEADER_CIPHER_SIZE];
        match poll_read_all(inner, cx, &mut header_cipher) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let header = match decrypt_aead(aead, &self.nonce, &header_cipher) {
            Ok(h) => h,
            Err(e) => return Poll::Ready(Err(e)),
        };
        increment_nonce(&mut self.nonce);
        let (padding_length, payload_length) = match v6_parse_header(&header, true) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        if padding_length != 0 {
            return Poll::Ready(Err(v6_record_padding_error()));
        }
        if payload_length == 0 {
            return Poll::Ready(Ok(Vec::new())); // zero chunk
        }
        let mut payload_cipher = vec![0u8; payload_length + TAG_LEN];
        match poll_read_all(inner, cx, &mut payload_cipher) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        match decrypt_aead(aead, &self.nonce, &payload_cipher) {
            Ok(payload) => {
                increment_nonce(&mut self.nonce);
                Poll::Ready(Ok(payload))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

struct V6ShapedWriter {
    profile: V6Profile,
    aead: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
    salt: Vec<u8>,
    salt_sent: bool,
    seq: u32,
    chunk_size: usize,
    last_write_unix: i64,
}

impl V6ShapedWriter {
    fn new(psk: &[u8], profile: V6Profile) -> io::Result<V6ShapedWriter> {
        let mut salt = vec![0u8; V6_SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let aead = v6_aead(psk, &salt.clone().try_into().map_err(|_| aead_error())?)?;
        Ok(V6ShapedWriter {
            profile,
            aead,
            nonce: [0u8; NONCE_SIZE],
            salt,
            salt_sent: false,
            seq: 0,
            chunk_size: 0,
            last_write_unix: 0,
        })
    }

    fn now_unix() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Port of Go's `v6ShapedWriter::payloadLimitFor`.
    fn payload_limit_for(&mut self, now_unix: i64) -> usize {
        if self.last_write_unix == 0
            || now_unix - self.last_write_unix > self.profile.idle_reset_sec
        {
            self.chunk_size = self.profile.chunk_initial as usize;
        }
        if self.chunk_size == 0 {
            self.chunk_size = self.profile.chunk_initial as usize;
        }
        let mut payload_limit = self.profile.chunk_payload_limit(self.seq, self.chunk_size);
        if self.seq == 0 {
            payload_limit = payload_limit.min(self.profile.first_record_cap as usize);
        }
        self.chunk_size = self.profile.next_chunk_size(self.chunk_size);
        self.last_write_unix = now_unix;
        payload_limit.max(1).min(V6_MAX_PAYLOAD)
    }

    /// Port of Go's `v6ShapedWriter::appendRecord`.
    fn append_record(&mut self, mut out: Vec<u8>, payload: &[u8]) -> io::Result<Vec<u8>> {
        let seq = self.seq;
        let prefix_length = self.profile.record_prefix_len(seq);
        let mut salt_block_length = 0usize;
        let mut salt_prefix_length = 0usize;
        if !self.salt_sent {
            salt_block_length = self.profile.salt_block_len;
            salt_prefix_length = salt_block_length - V6_SALT_SIZE;
        }
        let padding_length = self.profile.padding_len(
            seq,
            payload.len(),
            prefix_length,
            salt_prefix_length,
            salt_block_length,
        );
        let payload_cipher_length = if payload.is_empty() { 0 } else { payload.len() + TAG_LEN };
        let total = salt_block_length
            + prefix_length
            + V6_HEADER_CIPHER_SIZE
            + padding_length
            + payload_cipher_length;
        let start = out.len();
        out.resize(start + total, 0);
        let record: &mut [u8] = &mut out[start..];

        if salt_block_length > 0 {
            let block = &mut record[..salt_block_length];
            self.profile.fill_padding(0xffff_ffff, block);
            self.profile.write_salt_block(&self.salt, block);
            self.salt_sent = true;
        }

        let mut offset = salt_block_length;
        let prefix = {
            let mut p = vec![0u8; prefix_length];
            self.profile.fill_padding(seq, &mut p);
            p
        };
        {
            let mut header_plain = [0u8; V6_HEADER_PLAIN_SIZE];
            v6_put_header(&mut header_plain, padding_length, payload.len());
            let sealed = seal_aead_aad(&self.aead, &self.nonce, &header_plain, &prefix)?;
            increment_nonce(&mut self.nonce);
            record[offset..offset + V6_HEADER_CIPHER_SIZE].copy_from_slice(&sealed);
            offset += V6_HEADER_CIPHER_SIZE;
        }
        let padding_start = offset;
        if padding_length > 0 {
            let mut padding = record[padding_start..padding_start + padding_length].to_vec();
            self.profile.fill_padding(seq, &mut padding);
            record[padding_start..padding_start + padding_length].copy_from_slice(&padding);
        }
        offset += padding_length;
        if !payload.is_empty() {
            let payload_start = offset;
            let mut region = record[payload_start..payload_start + payload_cipher_length].to_vec();
            region[..payload.len()].copy_from_slice(payload);
            let sealed =
                seal_aead_aad(&self.aead, &self.nonce, &region[..payload.len()], &record[padding_start..padding_start + padding_length])?;
            increment_nonce(&mut self.nonce);
            record[payload_start..payload_start + payload_cipher_length].copy_from_slice(&sealed);
            let (padding_part, payload_part) = record.split_at_mut(payload_start);
            self.profile.mix_padding_payload(
                seq,
                &mut padding_part[padding_start..padding_start + padding_length],
                &mut payload_part[..payload_cipher_length],
            );
        }
        self.seq += 1;
        Ok(out)
    }
}

fn record_padding(padding: &[u8]) -> &[u8] {
    padding
}

impl V6RecordWriter for V6ShapedWriter {
    fn poll_write(&mut self, inner: &mut BoxedStream, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let now = Self::now_unix();
        let mut out = Vec::new();
        let mut p = buf;
        while !p.is_empty() {
            let n = p.len().min(self.payload_limit_for(now));
            match self.append_record(out, &p[..n]) {
                Ok(o) => out = o,
                Err(e) => return Poll::Ready(Err(e)),
            }
            p = &p[n..];
        }
        match poll_write_all(inner, cx, &out) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
        }
    }
}

struct V6ShapedReader {
    psk: Vec<u8>,
    profile: V6Profile,
    aead: Option<Aes128Gcm>,
    nonce: [u8; NONCE_SIZE],
    seq: u32,
}

impl V6ShapedReader {
    fn new(psk: &[u8], profile: V6Profile) -> V6ShapedReader {
        V6ShapedReader { psk: psk.to_vec(), profile, aead: None, nonce: [0u8; NONCE_SIZE], seq: 0 }
    }
}

impl V6RecordReader for V6ShapedReader {
    fn poll_read_record(&mut self, inner: &mut BoxedStream, cx: &mut Context<'_>) -> Poll<io::Result<Vec<u8>>> {
        if self.aead.is_none() {
            let mut block = vec![0u8; self.profile.salt_block_len];
            match poll_read_all(inner, cx, &mut block) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            let salt = self.profile.extract_salt(&block);
            match v6_aead(&self.psk, &salt) {
                Ok(aead) => self.aead = Some(aead),
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        let aead = self.aead.as_ref().unwrap();
        let prefix_length = self.profile.record_prefix_len(self.seq);
        let mut head = vec![0u8; prefix_length + V6_HEADER_CIPHER_SIZE];
        match poll_read_all(inner, cx, &mut head) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let prefix = head[..prefix_length].to_vec();
        let header = match decrypt_aead(aead, &self.nonce, &head[prefix_length..]) {
            Ok(h) => h,
            Err(e) => return Poll::Ready(Err(e)),
        };
        increment_nonce(&mut self.nonce);
        let (padding_length, payload_length) = match v6_parse_header(&header, false) {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        let seq = self.seq;
        self.seq += 1;
        if payload_length == 0 {
            if padding_length > 0 {
                let mut discard = vec![0u8; padding_length];
                match poll_read_all(inner, cx, &mut discard) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
            }
            return Poll::Ready(Ok(Vec::new())); // zero chunk
        }
        let body_len = padding_length + payload_length + TAG_LEN;
        let mut body = vec![0u8; body_len];
        match poll_read_all(inner, cx, &mut body) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {}
        }
        let (padding_part, payload_part) = body.split_at_mut(padding_length);
        self.profile
            .mix_padding_payload(seq, padding_part, &mut payload_part[..payload_length + TAG_LEN]);
        match decrypt_aead_aad(aead, &self.nonce, &payload_part[..payload_length + TAG_LEN], padding_part) {
            Ok(payload) => {
                increment_nonce(&mut self.nonce);
                Poll::Ready(Ok(payload))
            }
            Err(e) => Poll::Ready(Err(e)),
        }
    }
}

struct V6Stream {
    inner: BoxedStream,
    reader: Box<dyn V6RecordReader>,
    writer: Box<dyn V6RecordWriter>,
    pending: Vec<u8>,
    pending_off: usize,
}

impl AsyncRead for V6Stream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if this.pending_off < this.pending.len() {
                let n = buf.remaining().min(this.pending.len() - this.pending_off);
                buf.put_slice(&this.pending[this.pending_off..this.pending_off + n]);
                this.pending_off += n;
                if this.pending_off == this.pending.len() {
                    this.pending.clear();
                    this.pending_off = 0;
                }
                return Poll::Ready(Ok(()));
            }
            this.pending.clear();
            this.pending_off = 0;
            match this.reader.poll_read_record(&mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(payload)) => {
                    if payload.is_empty() {
                        continue; // zero chunk: keep reading
                    }
                    let n = buf.remaining().min(payload.len());
                    buf.put_slice(&payload[..n]);
                    if n < payload.len() {
                        this.pending = payload[n..].to_vec();
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for V6Stream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.writer.poll_write(&mut this.inner, cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Write the whole connect header through the writer.
async fn v6_write_all(writer: &mut dyn V6RecordWriter, inner: &mut BoxedStream, buf: &[u8]) -> io::Result<()> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let n = std::future::poll_fn(|cx| writer.poll_write(inner, cx, &buf[filled..])).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "snell v6 write zero"));
        }
        filled += n;
    }
    Ok(())
}

/// Read the first non-empty record's first byte — the snell server reply.
async fn read_v6_reply(reader: &mut dyn V6RecordReader, inner: &mut BoxedStream) -> io::Result<u8> {
    loop {
        let byte = std::future::poll_fn(|cx| {
            match reader.poll_read_record(inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(payload)) => {
                    if payload.is_empty() {
                        Poll::Ready(Ok(None)) // zero chunk: keep waiting
                    } else {
                        Poll::Ready(Ok(Some(payload[0])))
                    }
                }
            }
        })
        .await?;
        if let Some(byte) = byte {
            return Ok(byte);
        }
    }
}

async fn connect_v6(mut base: BoxedStream, psk: &[u8], mode: V6Mode, target: &TargetAddr) -> io::Result<BoxedStream> {
    let header = connect_command(target);
    let (mut writer, mut reader): (Box<dyn V6RecordWriter>, Box<dyn V6RecordReader>) = match mode {
        V6Mode::UnsafeRaw => (Box::new(V6RawWriter), Box::new(V6RawReader)),
        V6Mode::Unshaped => {
            let w = V6UnshapedWriter::new(psk)?;
            let r = V6UnshapedReader::new(psk);
            (Box::new(w), Box::new(r))
        }
        V6Mode::Shaped => {
            let profile = V6Profile::new(psk);
            let w = V6ShapedWriter::new(psk, profile.clone())?;
            let r = V6ShapedReader::new(psk, profile);
            (Box::new(w), Box::new(r))
        }
    };
    match mode {
        V6Mode::UnsafeRaw => {
            base.write_all(&V6RawWriter::record(&header)).await?;
        }
        V6Mode::Unshaped | V6Mode::Shaped => {
            v6_write_all(writer.as_mut(), &mut base, &header).await?;
        }
    }
    let reply = match mode {
        V6Mode::UnsafeRaw => {
            let mut record_header = [0u8; V6_HEADER_PLAIN_SIZE];
            base.read_exact(&mut record_header).await?;
            let mut reply = [0u8; 1];
            base.read_exact(&mut reply).await?;
            reply[0]
        }
        V6Mode::Unshaped | V6Mode::Shaped => read_v6_reply(reader.as_mut(), &mut base).await?,
    };
    if reply != REPLY_TUNNEL {
        return Err(io::Error::new(io::ErrorKind::Other, format!("Snell server error reply {}", reply)));
    }
    Ok(Box::new(V6Stream {
        inner: base,
        reader,
        writer,
        pending: Vec::new(),
        pending_off: 0,
    }))
}

#[cfg(test)]
mod v46_tests {
    use super::*;
    use tokio::io::duplex;

    async fn v4_read(
        reader: &mut V4Reader,
        inner: &mut BoxedStream,
        n: usize,
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < n {
            let mut buf = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut buf[..]);
            std::future::poll_fn(|cx| reader.poll_read(inner, cx, &mut rb)).await?;
            if rb.filled().is_empty() {
                break;
            }
            out.extend_from_slice(rb.filled());
        }
        Ok(out)
    }

    async fn read_v6_records(
        reader: &mut dyn V6RecordReader,
        inner: &mut BoxedStream,
        n: usize,
    ) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        while out.len() < n {
            let payload = std::future::poll_fn(|cx| reader.poll_read_record(inner, cx)).await?;
            if payload.is_empty() {
                continue; // zero chunk: nothing to append
            }
            out.extend_from_slice(&payload);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn v4_framing_round_trips() {
        let (a, b) = duplex(1 << 16);
        let mut a_box: BoxedStream = Box::new(a);
        let mut b_box: BoxedStream = Box::new(b);

        let mut writer = V4Writer::new(b"pw").unwrap();
        let frame = writer.build_frame(b"hello v4").unwrap();
        assert_eq!(&frame[..V4_SALT_SIZE], &writer.salt); // salt leads the first frame
        a_box.write_all(&frame).await.unwrap();

        let mut reader = V4Reader::open(&mut b_box, b"pw").await.unwrap();
        let out = v4_read(&mut reader, &mut b_box, b"hello v4".len()).await.unwrap();
        assert_eq!(out, b"hello v4");
    }

    #[tokio::test]
    async fn v6_unshaped_round_trips() {
        let (a, b) = duplex(1 << 16);
        let mut a_box: BoxedStream = Box::new(a);
        let mut b_box: BoxedStream = Box::new(b);

        let mut writer = V6UnshapedWriter::new(b"pw").unwrap();
        let mut reader = V6UnshapedReader::new(b"pw");
        v6_write_all(&mut writer, &mut a_box, b"hello v6 unshaped").await.unwrap();
        let out =
            read_v6_records(&mut reader, &mut b_box, b"hello v6 unshaped".len()).await.unwrap();
        assert_eq!(out, b"hello v6 unshaped");
    }

    #[tokio::test]
    async fn v6_shaped_round_trips() {
        let (a, b) = duplex(1 << 16);
        let mut a_box: BoxedStream = Box::new(a);
        let mut b_box: BoxedStream = Box::new(b);

        let profile = V6Profile::new(b"pw");
        let mut writer = V6ShapedWriter::new(b"pw", profile.clone()).unwrap();
        let mut reader = V6ShapedReader::new(b"pw", profile);
        v6_write_all(&mut writer, &mut a_box, b"hello v6 shaped").await.unwrap();
        let out = read_v6_records(&mut reader, &mut b_box, b"hello v6 shaped".len()).await.unwrap();
        assert_eq!(out, b"hello v6 shaped");
    }

    #[test]
    fn v6_salt_block_round_trip() {
        let profile = V6Profile::new(b"pw");
        let mut block = vec![0u8; profile.salt_block_len];
        profile.fill_padding(0xffff_ffff, &mut block);
        let mut salt = [0u8; V6_SALT_SIZE];
        for (i, byte) in salt.iter_mut().enumerate() {
            *byte = i as u8 + 1;
        }
        profile.write_salt_block(&salt, &mut block);
        assert_eq!(profile.extract_salt(&block), salt);
    }

    #[test]
    fn v6_mix_padding_payload_is_self_inverse() {
        let profile = V6Profile::new(b"pw");
        let mut padding = vec![0xaa; 32];
        let mut payload_cipher = vec![0x55; 48];
        let (p0, c0) = (padding.clone(), payload_cipher.clone());
        profile.mix_padding_payload(7, &mut padding, &mut payload_cipher);
        profile.mix_padding_payload(7, &mut padding, &mut payload_cipher);
        assert_eq!(padding, p0);
        assert_eq!(payload_cipher, c0);
    }

    #[test]
    fn v6_profile_is_deterministic() {
        let profile = V6Profile::new(b"pw");
        let other = V6Profile::new(b"pw");
        assert_eq!(profile.generator, other.generator);
        assert_eq!(profile.salt_block_len, other.salt_block_len);
        assert_eq!(profile.chunk_initial, other.chunk_initial);
        assert!(profile.salt_block_len >= V6_SALT_SIZE);
        assert!(profile.record_prefix_len(0) <= profile.prefix_max_record as usize);
    }
}


