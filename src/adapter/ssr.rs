//! ShadowsocksR outbound — stream-cipher subset.
//!
//! Implements the legacy SSR data path: MD5 EVP-BytesToKey key derivation,
//! a stream cipher with a plaintext IV, and a SOCKS5 target header before the
//! payload. Only the `origin` protocol and `plain` obfs are implemented; other
//! auth protocols (auth_sha1_v4, auth_aes128_*, auth_chain_*) and obfs variants
//! (http_simple, tls1.2_ticket_auth) are not supported.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::BlockEncrypt;
use aes_gcm::KeyInit;
use aes::{Aes128, Aes192, Aes256, Block};
use async_trait::async_trait;
use chacha20::cipher::{KeyIvInit, StreamCipher as _};
use chacha20::{ChaCha20, XChaCha20};
use md5::{Digest, Md5};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

/// EVP_BytesToKey with MD5, identical to Shadowsocks legacy KDF.
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum CipherKind {
    Rc4Md5,
    Aes128Cfb,
    Aes192Cfb,
    Aes256Cfb,
    ChaCha20,
    ChaCha20Ietf,
    XChaCha20,
}

impl CipherKind {
    fn parse(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().replace('_', "-").as_str() {
            "rc4-md5" => Some(Self::Rc4Md5),
            "aes-128-cfb" => Some(Self::Aes128Cfb),
            "aes-192-cfb" => Some(Self::Aes192Cfb),
            "aes-256-cfb" => Some(Self::Aes256Cfb),
            "chacha20" => Some(Self::ChaCha20),
            "chacha20-ietf" => Some(Self::ChaCha20Ietf),
            "xchacha20" => Some(Self::XChaCha20),
            _ => None,
        }
    }

    fn key_len(self) -> usize {
        match self {
            Self::Aes128Cfb | Self::Rc4Md5 => 16,
            Self::Aes192Cfb => 24,
            _ => 32,
        }
    }

    fn iv_len(self) -> usize {
        match self {
            Self::XChaCha20 => 24,
            Self::Rc4Md5 => 16,
            _ => 16,
        }
    }
}

/// Minimal RC4 (KSA + PRGA), used by the rc4-md5 cipher.
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0u8; 256];
        for (i, slot) in s.iter_mut().enumerate() {
            *slot = i as u8;
        }
        let mut j = 0u8;
        for i in 0..256usize {
            j = j.wrapping_add(s[i]).wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    fn apply_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize] as usize + self.s[self.j as usize] as usize) & 0xff];
            *byte ^= k;
        }
    }
}

/// Stateful XOR stream cipher for one direction.
enum StreamCipher {
    Rc4(Rc4),
    Cfb128 { block: AesKind, register: [u8; 16], encrypt: bool },
    ChaCha(Box<dyn chacha20::cipher::StreamCipher + Send>),
}

enum AesKind {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl AesKind {
    fn encrypt_block(&self, block: &mut Block) {
        match self {
            Self::Aes128(c) => c.encrypt_block(block),
            Self::Aes192(c) => c.encrypt_block(block),
            Self::Aes256(c) => c.encrypt_block(block),
        }
    }
}

impl StreamCipher {
    fn new(kind: CipherKind, key: &[u8], iv: &[u8], encrypt: bool) -> io::Result<Self> {
        match kind {
            CipherKind::Rc4Md5 => {
                let mut h = Md5::new();
                h.update(key);
                h.update(iv);
                let rc4_key = h.finalize();
                let cipher = Rc4::new(&rc4_key);
                Ok(Self::Rc4(cipher))
            }
            CipherKind::Aes128Cfb | CipherKind::Aes192Cfb | CipherKind::Aes256Cfb => {
                let block = match kind {
                    CipherKind::Aes128Cfb => AesKind::Aes128(
                        Aes128::new_from_slice(key).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad AES key"))?),
                    CipherKind::Aes192Cfb => AesKind::Aes192(
                        Aes192::new_from_slice(key).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad AES key"))?),
                    _ => AesKind::Aes256(
                        Aes256::new_from_slice(key).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad AES key"))?),
                };
                let mut register = [0u8; 16];
                register.copy_from_slice(&iv[..16]);
                Ok(Self::Cfb128 { block, register, encrypt })
            }
            CipherKind::ChaCha20 | CipherKind::ChaCha20Ietf | CipherKind::XChaCha20 => {
                let cipher: Box<dyn chacha20::cipher::StreamCipher + Send> = match kind {
                    CipherKind::XChaCha20 => {
                        let mut key_arr = [0u8; 32];
                        key_arr.copy_from_slice(key);
                        let mut iv_arr = [0u8; 24];
                        iv_arr.copy_from_slice(&iv[..24]);
                        Box::new(XChaCha20::new(&key_arr.into(), &iv_arr.into()))
                    }
                    _ => {
                        let mut key_arr = [0u8; 32];
                        key_arr.copy_from_slice(key);
                        let mut iv_arr = [0u8; 12];
                        if kind == CipherKind::ChaCha20Ietf {
                            iv_arr.copy_from_slice(&iv[..12]);
                            Box::new(ChaCha20::new(&key_arr.into(), &iv_arr.into()))
                        } else {
                            // Original ChaCha20 uses an 8-byte nonce + 4-byte counter;
                            // the first 8 bytes of the IV are the nonce.
                            iv_arr[4..].copy_from_slice(&iv[..8]);
                            Box::new(ChaCha20::new(&key_arr.into(), &iv_arr.into()))
                        }
                    }
                };
                Ok(Self::ChaCha(cipher))
            }
        }
    }

    fn apply(&mut self, buf: &mut [u8]) {
        match self {
            Self::Rc4(c) => c.apply_keystream(buf),
            Self::ChaCha(c) => c.apply_keystream(buf),
            Self::Cfb128 { block, register, encrypt } => {
                // CFB-128: keystream = AES(register); the feedback register is
                // always the ciphertext block. When encrypting the ciphertext
                // is the post-XOR output; when decrypting it is the pre-XOR
                // input.
                for chunk in buf.chunks_mut(16) {
                    let mut stream = Block::default();
                    stream.copy_from_slice(register);
                    block.encrypt_block(&mut stream);
                    let ciphertext: Vec<u8> = if *encrypt {
                        chunk.iter_mut().zip(stream.iter()).map(|(out, &ks)| {
                            *out ^= ks;
                            *out
                        }).collect()
                    } else {
                        let input = chunk.to_vec();
                        for (out, &ks) in chunk.iter_mut().zip(stream.iter()) {
                            *out ^= ks;
                        }
                        input
                    };
                    if ciphertext.len() == 16 {
                        register.copy_from_slice(&ciphertext);
                    }
                }
            }
        }
    }
}

/// A stream-cipher-wrapped TCP stream. The server's IV is read lazily on the
/// first read (the server sends it when it first writes).
struct SsrStream {
    inner: BoxedStream,
    enc: StreamCipher,
    dec: Option<StreamCipher>,
    key: Vec<u8>,
    cipher: CipherKind,
    iv_len: usize,
    read_iv: Vec<u8>,
    read_iv_filled: usize,
    /// An encrypted frame not fully written yet. The cipher keystream is
    /// advanced once when the frame is built, so a partial write must resume
    /// from `pending_off` instead of re-encrypting (which desynchronizes it).
    pending: Vec<u8>,
    pending_off: usize,
    /// True while `pending` still holds the encryption of the current buf, so
    /// a retried poll_write must not encrypt the same bytes a second time.
    write_consumed: bool,
}

impl SsrStream {
    fn new(inner: BoxedStream, enc: StreamCipher, key: Vec<u8>, cipher: CipherKind) -> Self {
        let iv_len = cipher.iv_len();
        Self {
            inner,
            enc,
            dec: None,
            key,
            cipher,
            iv_len,
            read_iv: vec![0u8; iv_len],
            read_iv_filled: 0,
            pending: Vec::new(),
            pending_off: 0,
            write_consumed: false,
        }
    }

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_off < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_off..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ssr: failed to write frame",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pending_off += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending.clear();
        self.pending_off = 0;
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for SsrStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Read the server IV on first use, before any ciphertext.
        while this.dec.is_none() {
            while this.read_iv_filled < this.iv_len {
                // XChaCha20 uses a 24-byte IV; a 16-byte buffer panics when
                // sliced to the remaining IV length.
                let mut tmp = [0u8; 24];
                let mut rb = ReadBuf::new(&mut tmp[..this.iv_len - this.read_iv_filled]);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Ready(Ok(())) => {
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Ok(())); // EOF
                        }
                        this.read_iv[this.read_iv_filled..this.read_iv_filled + n]
                            .copy_from_slice(&rb.filled()[..n]);
                        this.read_iv_filled += n;
                    }
                }
            }
            match StreamCipher::new(this.cipher, &this.key, &this.read_iv, false) {
                Ok(c) => this.dec = Some(c),
                Err(e) => return Poll::Ready(Err(e)),
            }
        }

        // Allocate a temporary buffer, read into it, then decrypt into the
        // caller's ReadBuf. Avoids aliasing between initialize_unfilled and
        // filled_mut.
        let mut scratch = vec![0u8; buf.remaining().max(1)];
        let mut rb = ReadBuf::new(&mut scratch);
        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => {
                let n = rb.filled().len();
                if let Some(dec) = &mut this.dec {
                    dec.apply(&mut scratch[..n]);
                }
                buf.put_slice(&scratch[..n]);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for SsrStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !this.write_consumed {
            let mut encrypted = buf.to_vec();
            this.enc.apply(&mut encrypted);
            this.pending = encrypted;
            this.pending_off = 0;
            this.write_consumed = true;
        }
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => {
                this.write_consumed = false;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.flush_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct SsrOutbound {
    name: String,
    server: TargetAddr,
    key: Vec<u8>,
    cipher: CipherKind,
}

impl SsrOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        cipher: &str,
        protocol: Option<&str>,
        obfs: Option<&str>,
    ) -> Option<Self> {
        // Only the origin protocol and plain obfs are supported.
        if let Some(p) = protocol {
            if !p.eq_ignore_ascii_case("origin") {
                return None;
            }
        }
        if let Some(o) = obfs {
            if !o.eq_ignore_ascii_case("plain") {
                return None;
            }
        }
        let cipher = CipherKind::parse(cipher)?;
        let key = kdf(password.as_bytes(), cipher.key_len());
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self { name: name.to_string(), server, key, cipher })
    }
}

#[async_trait]
impl Outbound for SsrOutbound {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { "ShadowsocksR" }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut last_error = None;
        let mut tcp = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(stream) => { tcp = Some(stream); break; }
                Err(e) => last_error = Some(e),
            }
        }
        let mut tcp = tcp.ok_or_else(|| last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no SSR server address")))?;

        // Write IV, then send the SOCKS5 target header encrypted with the
        // stream cipher (SSR wraps the cipher around the whole data path).
        let mut iv = vec![0u8; self.cipher.iv_len()];
        OsRng.fill_bytes(&mut iv);
        // SSR sends IV then replaces first chunk with encrypted header; we
        // write IV in clear followed by encrypted target, matching the Go
        // shadowstream + origin protocol layering.
        tcp.write_all(&iv).await?;

        let enc = StreamCipher::new(self.cipher, &self.key, &iv, true)?;
        let mut stream = SsrStream::new(tcp, enc, self.key.clone(), self.cipher);

        let header = encode_socks_target(target);
        stream.write_all(&header).await?;
        Ok(Box::new(stream))
    }
}

fn encode_socks_target(target: &TargetAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        TargetAddr::Ip(IpAddr::V4(ip), _) => { out.push(0x01); out.extend_from_slice(&ip.octets()); }
        TargetAddr::Ip(IpAddr::V6(ip), _) => { out.push(0x04); out.extend_from_slice(&ip.octets()); }
        TargetAddr::Domain(host, _) => {
            out.push(0x03);
            let b = host.as_bytes();
            let len = b.len().min(255);
            out.push(len as u8);
            out.extend_from_slice(&b[..len]);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cipher_parse_and_sizes() {
        assert_eq!(CipherKind::parse("aes-256-cfb"), Some(CipherKind::Aes256Cfb));
        assert_eq!(CipherKind::parse("rc4-md5"), Some(CipherKind::Rc4Md5));
        assert_eq!(CipherKind::parse("chacha20-ietf"), Some(CipherKind::ChaCha20Ietf));
        assert_eq!(CipherKind::parse("aes-256-gcm"), None);
        assert_eq!(CipherKind::Aes128Cfb.key_len(), 16);
        assert_eq!(CipherKind::XChaCha20.iv_len(), 24);
    }

    #[test]
    fn only_origin_plain_supported() {
        assert!(SsrOutbound::try_new("s", "h", 443, "pw", "aes-256-cfb", Some("origin"), Some("plain")).is_some());
        assert!(SsrOutbound::try_new("s", "h", 443, "pw", "aes-256-cfb", Some("auth_sha1_v4"), None).is_none());
        assert!(SsrOutbound::try_new("s", "h", 443, "pw", "aes-256-cfb", None, Some("tls1.2_ticket_auth")).is_none());
    }

    #[test]
    fn rc4_md5_roundtrip() {
        let key = kdf(b"password", 16);
        let iv = [3u8; 16];
        let mut a = StreamCipher::new(CipherKind::Rc4Md5, &key, &iv, true).unwrap();
        let mut b = StreamCipher::new(CipherKind::Rc4Md5, &key, &iv, false).unwrap();
        let original = b"hello world";
        let mut buf = original.to_vec();
        a.apply(&mut buf);
        assert_ne!(&buf, original);
        b.apply(&mut buf);
        assert_eq!(&buf, original);
    }

    #[test]
    fn aes_cfb_roundtrip() {
        let key = kdf(b"password", 16);
        let iv = [5u8; 16];
        let mut a = StreamCipher::new(CipherKind::Aes128Cfb, &key, &iv, true).unwrap();
        let mut b = StreamCipher::new(CipherKind::Aes128Cfb, &key, &iv, false).unwrap();
        let mut buf = vec![0x42u8; 100]; // spans multiple 16-byte blocks
        let original = buf.clone();
        a.apply(&mut buf);
        assert_ne!(buf, original);
        b.apply(&mut buf);
        assert_eq!(buf, original);
    }

    #[test]
    fn target_header() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        assert_eq!(encode_socks_target(&TargetAddr::Ip(ip, 443)), vec![1, 1, 2, 3, 4, 0x01, 0xBB]);
    }
}
