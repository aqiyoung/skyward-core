//! Snell outbound (v1/v2/v3). Uses the shadowaead chunk framing with an
//! Argon2-derived subkey and a plaintext salt, then a CONNECT header and a
//! one-byte server reply. v4/v6 record layers are not implemented.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce as AesNonce};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

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
    ) -> Option<Self> {
        if psk.is_empty() || !(1..=3).contains(&version) {
            return None;
        }
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self { name: name.to_string(), server, psk: psk.as_bytes().to_vec(), version, use_tls, sni })
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
            connect_tls(&self.sni, tcp).await?
        } else {
            Box::new(tcp)
        };

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_config() {
        assert!(SnellOutbound::try_new("s", "h", 443, "", 1, false, None).is_none());
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 0, false, None).is_none());
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 4, false, None).is_none());
        assert!(SnellOutbound::try_new("s", "h", 443, "pw", 1, false, None).is_some());
    }

    #[test]
    fn header_layout() {
        let outbound = SnellOutbound::try_new("s", "h", 443, "pw", 1, false, None).unwrap();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let header = outbound.header(&TargetAddr::Ip(ip, 443));
        assert_eq!(header[0], 0x01);
        assert_eq!(header[1], COMMAND_CONNECT);
        assert_eq!(header[2], 0); // client id length
        assert_eq!(header[3], 7); // "1.2.3.4"
        assert_eq!(&header[4..11], b"1.2.3.4");
        assert_eq!(&header[11..], &443u16.to_be_bytes());

        let v2 = SnellOutbound::try_new("s", "h", 443, "pw", 2, false, None).unwrap();
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
