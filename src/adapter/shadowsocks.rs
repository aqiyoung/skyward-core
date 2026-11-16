//! Shadowsocks AEAD outbound (SIP002 stream framing).
//!
//! Ported from the Go kernel's `transport/shadowsocks`:
//!   - PSK  = EVP_BytesToKey(MD5, password, key_len)
//!   - salt = random(salt_len), sent in the clear
//!   - subkey = HKDF-SHA1(PSK, salt, "ss-subkey")
//!   - each chunk = AEAD(length_be16) || AEAD(payload), nonce increments twice
//!   - the first chunk carries the SOCKS5-style target header

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, KeyInit, Nonce as AesNonce};
use async_trait::async_trait;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::rngs::OsRng;
use rand::RngCore;
use sha1::Sha1;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

const MAX_CHUNK: usize = 0x3FFF;
const TAG_LEN: usize = 16;
type HmacSha1 = Hmac<Sha1>;

#[derive(Clone, Copy)]
enum Method {
    Aes128Gcm,
    Aes192Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
}

impl Method {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().replace('_', "-").as_str() {
            "aes-128-gcm" => Some(Self::Aes128Gcm),
            "aes-192-gcm" => Some(Self::Aes192Gcm),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "xchacha20-ietf-poly1305" | "xchacha20-poly1305" => Some(Self::XChaCha20Poly1305),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            _ => 32,
        }
    }

    fn salt_len(self) -> usize {
        let k = self.key_len();
        if k > 16 { k } else { 16 }
    }

    fn nonce_len(self) -> usize {
        if matches!(self, Self::XChaCha20Poly1305) { 24 } else { 12 }
    }
}

/// The original Shadowsocks key derivation (OpenSSL EVP_BytesToKey with MD5).
fn kdf(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut h = Md5::new();
        h.update(&prev);
        h.update(password);
        prev = h.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

fn hkdf_sha1(ikm: &[u8], salt: &[u8], info: &[u8], out_len: usize) -> Vec<u8> {
    let mut extract = HmacSha1::new_from_slice(salt).expect("HMAC accepts any key length");
    extract.update(ikm);
    let prk = extract.finalize().into_bytes();

    let mut out = Vec::with_capacity(out_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < out_len {
        let mut mac = HmacSha1::new_from_slice(&prk).expect("HMAC accepts any key length");
        mac.update(&t);
        mac.update(info);
        mac.update(&[counter]);
        t = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&t);
        counter += 1;
    }
    out.truncate(out_len);
    out
}

enum Cipher {
    Aes128(Aes128Gcm),
    Aes192(Aes192Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
    XChaCha(XChaCha20Poly1305),
}

fn aead_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "shadowsocks: AEAD operation failed")
}

impl Cipher {
    fn new(method: Method, key: &[u8]) -> io::Result<Self> {
        Ok(match method {
            Method::Aes128Gcm => Self::Aes128(Aes128Gcm::new_from_slice(key).map_err(|_| aead_error())?),
            Method::Aes192Gcm => Self::Aes192(Aes192Gcm::new_from_slice(key).map_err(|_| aead_error())?),
            Method::Aes256Gcm => Self::Aes256(Aes256Gcm::new_from_slice(key).map_err(|_| aead_error())?),
            Method::ChaCha20Poly1305 => Self::ChaCha(ChaCha20Poly1305::new_from_slice(key).map_err(|_| aead_error())?),
            Method::XChaCha20Poly1305 => Self::XChaCha(XChaCha20Poly1305::new_from_slice(key).map_err(|_| aead_error())?),
        })
    }

    fn encrypt(&self, nonce: &[u8], msg: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg, aad: &[] };
        match self {
            Self::Aes128(c) => c.encrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::Aes192(c) => c.encrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::Aes256(c) => c.encrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::ChaCha(c) => c.encrypt(ChaChaNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::XChaCha(c) => c.encrypt(XNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
        }
    }

    fn decrypt(&self, nonce: &[u8], msg: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg, aad: &[] };
        match self {
            Self::Aes128(c) => c.decrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::Aes192(c) => c.decrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::Aes256(c) => c.decrypt(AesNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::ChaCha(c) => c.decrypt(ChaChaNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
            Self::XChaCha(c) => c.decrypt(XNonce::from_slice(nonce), payload).map_err(|_| aead_error()),
        }
    }
}

/// Encrypted stream layered over the TCP connection to the SS server.
struct SsStream {
    inner: TcpStream,
    cipher: Cipher,
    nonce_len: usize,
    read_nonce: [u8; 24],
    write_nonce: [u8; 24],

    pending: Vec<u8>,
    pending_off: usize,
    write_consumed: bool,
    last_n: usize,

    header: Vec<u8>,
    header_len: usize,
    payload: Vec<u8>,
    payload_len: usize,
    expect_payload: bool,
    plain: Vec<u8>,
    plain_off: usize,
}

impl SsStream {
    fn new(inner: TcpStream, cipher: Cipher, nonce_len: usize) -> Self {
        Self {
            inner,
            cipher,
            nonce_len,
            read_nonce: [0u8; 24],
            write_nonce: [0u8; 24],
            pending: Vec::new(),
            pending_off: 0,
            write_consumed: false,
            last_n: 0,
            header: vec![0u8; 2 + TAG_LEN],
            header_len: 0,
            payload: Vec::new(),
            payload_len: 0,
            expect_payload: false,
            plain: Vec::new(),
            plain_off: 0,
        }
    }

    fn next_nonce(counter: &mut [u8; 24], len: usize) -> Vec<u8> {
        let nonce = counter[..len].to_vec();
        for i in 0..len {
            counter[i] = counter[i].wrapping_add(1);
            if counter[i] != 0 {
                break;
            }
        }
        nonce
    }

    fn encrypt_chunk(&mut self, data: &[u8]) -> io::Result<Vec<u8>> {
        let len_bytes = (data.len() as u16).to_be_bytes();
        let n1 = Self::next_nonce(&mut self.write_nonce, self.nonce_len);
        let enc_len = self.cipher.encrypt(&n1, &len_bytes)?;
        let n2 = Self::next_nonce(&mut self.write_nonce, self.nonce_len);
        let enc_data = self.cipher.encrypt(&n2, data)?;
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
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "ss: write zero")));
                }
                Poll::Ready(Ok(n)) => self.pending_off += n,
            }
        }
        Poll::Ready(Ok(()))
    }
}

fn poll_read_into(
    inner: &mut TcpStream,
    cx: &mut Context<'_>,
    dst: &mut [u8],
    filled: &mut usize,
) -> Poll<io::Result<()>> {
    while *filled < dst.len() {
        match Pin::new(&mut *inner).poll_read(cx, &mut dst[*filled..]) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "ss: connection closed mid-frame",
                )));
            }
            Poll::Ready(Ok(n)) => *filled += n,
        }
    }
    Poll::Ready(Ok(()))
}

impl AsyncRead for SsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
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
                match poll_read_into(&mut this.inner, cx, &mut this.header, &mut this.header_len) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {}
                }
                let n1 = Self::next_nonce(&mut this.read_nonce, this.nonce_len);
                let len_plain = match this.cipher.decrypt(&n1, &this.header[..2 + TAG_LEN]) {
                    Ok(v) => v,
                    Err(e) => return Poll::Ready(Err(e)),
                };
                if len_plain.len() != 2 {
                    return Poll::Ready(Err(aead_error()));
                }
                let size = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize & MAX_CHUNK;
                this.header_len = 0;
                if size == 0 {
                    return Poll::Ready(Ok(())); // peer closed its write side
                }
                this.payload = vec![0u8; size + TAG_LEN];
                this.payload_len = 0;
                this.expect_payload = true;
            }

            match poll_read_into(&mut this.inner, cx, &mut this.payload, &mut this.payload_len) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            let n2 = Self::next_nonce(&mut this.read_nonce, this.nonce_len);
            this.plain = match this.cipher.decrypt(&n2, &this.payload) {
                Ok(v) => v,
                Err(e) => return Poll::Ready(Err(e)),
            };
            this.expect_payload = false;
            this.payload_len = 0;
        }
    }
}

impl AsyncWrite for SsStream {
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

fn encode_target(target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        TargetAddr::Ip(IpAddr::V4(ip), _) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip), _) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(host, _) => {
            out.push(0x03);
            let bytes = host.as_bytes();
            let len = bytes.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&bytes[..len]);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

pub struct ShadowsocksOutbound {
    name: String,
    server: TargetAddr,
    password: String,
    method: Method,
}

impl ShadowsocksOutbound {
    pub fn try_new(name: &str, server: &str, port: u16, cipher: &str, password: &str) -> Option<Self> {
        let method = Method::parse(cipher)?;
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self {
            name: name.to_string(),
            server,
            password: password.to_string(),
            method,
        })
    }
}

#[async_trait]
impl Outbound for ShadowsocksOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "Shadowsocks"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut last_error = None;
        let mut tcp = None;
        for addr in self.server.resolve_all().await? {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        let mut tcp = tcp.ok_or_else(|| {
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no SS server address"))
        })?;

        let psk = kdf(self.password.as_bytes(), self.method.key_len());
        let mut salt = vec![0u8; self.method.salt_len()];
        OsRng.fill_bytes(&mut salt);
        let subkey = hkdf_sha1(&psk, &salt, b"ss-subkey", self.method.key_len());
        let cipher = Cipher::new(self.method, &subkey)?;

        tcp.write_all(&salt).await?;
        let mut stream = SsStream::new(tcp, cipher, self.method.nonce_len());
        stream.write_all(&encode_target(target)).await?;
        Ok(Box::new(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_extends_by_md5_chain() {
        let key16 = kdf(b"password", 16);
        assert_eq!(key16.len(), 16);
        assert_eq!(key16, Md5::digest(b"password").to_vec());
        let key32 = kdf(b"password", 32);
        assert_eq!(key32.len(), 32);
        assert_eq!(&key32[..16], &key16[..]);
        let mut next = Md5::new();
        next.update(&key16);
        next.update(b"password");
        assert_eq!(&key32[16..], &next.finalize()[..]);
    }

    #[test]
    fn hkdf_matches_expected_lengths() {
        assert_eq!(hkdf_sha1(b"ikm", b"salt", b"ss-subkey", 16).len(), 16);
        assert_eq!(hkdf_sha1(b"ikm", b"salt", b"ss-subkey", 32).len(), 32);
    }

    #[test]
    fn target_header_formats() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(encode_target(&TargetAddr::Ip(ip, 443)), vec![1, 1, 2, 3, 4, 0x01, 0xBB]);
        let domain = encode_target(&TargetAddr::Domain("example.com".into(), 80));
        assert_eq!(domain[0], 3);
        assert_eq!(domain[1], 11);
        assert_eq!(&domain[2..13], b"example.com");
        assert_eq!(&domain[13..], &80u16.to_be_bytes());
    }

    #[test]
    fn method_aliases() {
        assert!(Method::parse("aes-256-gcm").is_some());
        assert!(Method::parse("chacha20-ietf-poly1305").is_some());
        assert!(Method::parse("xchacha20-poly1305").is_some());
        assert!(Method::parse("rc4-md5").is_none());
        assert_eq!(Method::Aes128Gcm.salt_len(), 16);
        assert_eq!(Method::Aes256Gcm.salt_len(), 32);
        assert_eq!(Method::XChaCha20Poly1305.nonce_len(), 24);
    }

    #[test]
    fn aes_gcm_roundtrip() {
        let cipher = Cipher::new(Method::Aes256Gcm, &[7u8; 32]).unwrap();
        let nonce = [0u8; 12];
        let ct = cipher.encrypt(&nonce, b"hello").unwrap();
        assert_ne!(ct[..5], b"hello"[..]);
        assert_eq!(cipher.decrypt(&nonce, &ct).unwrap(), b"hello");
        assert!(cipher.decrypt(&[1u8; 12], &ct).is_err());
    }
}
