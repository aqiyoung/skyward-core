//! VMess AEAD outbound (security aes-128-gcm / chacha20-poly1305), ported from
//! `transport/vmess`. The legacy (non-AEAD) auth and alter-id rotation are not
//! implemented; UDP and the HTTP/WS/H2 transport wrappers are out of scope.

use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes::cipher::BlockEncrypt;
use aes::{Aes128, Block};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, KeyInit, Nonce as AesNonce};
use async_trait::async_trait;
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hmac::{Hmac, Mac};
use md5::{Digest, Md5};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls;
use crate::adapter::{BoxedStream, Outbound};
use crate::common::TargetAddr;

const VERSION: u8 = 0x01;
const OPTION_CHUNK_STREAM: u8 = 0x01;
const COMMAND_TCP: u8 = 0x01;
const SECURITY_AES_128_GCM: u8 = 0x03;
const SECURITY_CHACHA20_POLY1305: u8 = 0x04;
const CHUNK_SIZE: usize = 1 << 14;
const TAG_LEN: usize = 16;

fn aead_error() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "vmess: AEAD operation failed")
}

/// HMAC-SHA256 with a fixed key (the base hash of the VMess KDF chain).
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Generic HMAC (block size 64, 32-byte digest) where the digest function is
/// itself another VMess hash — this models Go's `hmac.New(parent.Create, key)`.
fn hmac_with_hash<F: Fn(&[u8]) -> Vec<u8>>(hash: &F, key: &[u8], data: &[u8]) -> Vec<u8> {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let derived = hash(key);
        let n = derived.len().min(BLOCK);
        k[..n].copy_from_slice(&derived[..n]);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Vec::with_capacity(BLOCK + data.len());
    inner.extend_from_slice(&ipad);
    inner.extend_from_slice(data);
    let inner_hash = hash(&inner);
    let mut outer = Vec::with_capacity(BLOCK + inner_hash.len());
    outer.extend_from_slice(&opad);
    outer.extend_from_slice(&inner_hash);
    hash(&outer)
}

enum VmessHash<'a> {
    Base { key: &'a [u8] },
    Nested { key: &'a [u8], parent: Box<VmessHash<'a>> },
}

impl VmessHash<'_> {
    fn digest(&self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Base { key } => hmac_sha256(key, data),
            Self::Nested { key, parent } => hmac_with_hash(&|d| parent.digest(d), key, data),
        }
    }
}

/// The nested HMAC chain from `header.go`: kdf(cmdKey, path...).
fn kdf(key: &[u8], path: &[&[u8]]) -> Vec<u8> {
    let mut hash = VmessHash::Base { key: b"VMess AEAD KDF" };
    for &part in path {
        hash = VmessHash::Nested { key: part, parent: Box::new(hash) };
    }
    hash.digest(key)
}

fn fnv1a32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

/// cmdKey = MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
fn cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(uuid);
    h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

fn create_auth_id(key: &[u8; 16], timestamp: i64) -> [u8; 16] {
    let mut buf = Vec::with_capacity(16);
    buf.extend_from_slice(&(timestamp as u64).to_be_bytes());
    let mut random = [0u8; 4];
    OsRng.fill_bytes(&mut random);
    buf.extend_from_slice(&random);
    let checksum = crc32fast::hash(&buf);
    buf.extend_from_slice(&checksum.to_be_bytes());

    let derived = kdf(key, &[b"AES Auth ID Encryption"]);
    let aes = Aes128::new_from_slice(&derived[..16]).expect("16-byte AES key");
    let mut block = Block::default();
    block.copy_from_slice(&buf);
    aes.encrypt_block(&mut block);
    let mut out = [0u8; 16];
    out.copy_from_slice(&block);
    out
}

fn aes_gcm_encrypt(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| aead_error())?;
    cipher
        .encrypt(AesNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| aead_error())
}

fn aes_gcm_decrypt(key: &[u8], nonce: &[u8], msg: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key).map_err(|_| aead_error())?;
    cipher
        .decrypt(AesNonce::from_slice(nonce), Payload { msg, aad })
        .map_err(|_| aead_error())
}

fn seal_vmess_aead_header(key: &[u8; 16], header: &[u8], timestamp: i64) -> Vec<u8> {
    let auth_id = create_auth_id(key, timestamp);
    let mut connection_nonce = [0u8; 8];
    OsRng.fill_bytes(&mut connection_nonce);
    let aad = &auth_id[..];

    let length_key = kdf(key, &[b"VMess Header AEAD Key_Length", &auth_id[..], &connection_nonce[..]]);
    let length_nonce = kdf(key, &[b"VMess Header AEAD Nonce_Length", &auth_id[..], &connection_nonce[..]]);
    let encrypted_length = aes_gcm_encrypt(
        &length_key[..16],
        &length_nonce[..12],
        &(header.len() as u16).to_be_bytes(),
        aad,
    ).expect("AES-GCM key/nonce lengths are valid");

    let payload_key = kdf(key, &[b"VMess Header AEAD Key", &auth_id[..], &connection_nonce[..]]);
    let payload_nonce = kdf(key, &[b"VMess Header AEAD Nonce", &auth_id[..], &connection_nonce[..]]);
    let encrypted_payload = aes_gcm_encrypt(&payload_key[..16], &payload_nonce[..12], header, aad)
        .expect("AES-GCM key/nonce lengths are valid");

    let mut out = Vec::with_capacity(16 + encrypted_length.len() + 8 + encrypted_payload.len());
    out.extend_from_slice(&auth_id);
    out.extend_from_slice(&encrypted_length);
    out.extend_from_slice(&connection_nonce);
    out.extend_from_slice(&encrypted_payload);
    out
}

fn serialize_request(
    iv: &[u8; 16],
    body_key: &[u8; 16],
    resp_v: u8,
    security: u8,
    target: &TargetAddr,
    padding_len: usize,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(VERSION);
    buf.extend_from_slice(iv);
    buf.extend_from_slice(body_key);
    buf.push(resp_v);
    buf.push(OPTION_CHUNK_STREAM);
    buf.push(((padding_len as u8) << 4) | security);
    buf.push(0); // reserve
    buf.push(COMMAND_TCP);
    buf.extend_from_slice(&target.port().to_be_bytes());

    match target {
        TargetAddr::Ip(IpAddr::V4(ip), _) => {
            buf.push(0x01);
            buf.extend_from_slice(&ip.octets());
        }
        TargetAddr::Ip(IpAddr::V6(ip), _) => {
            buf.push(0x03);
            buf.extend_from_slice(&ip.octets());
        }
        TargetAddr::Domain(host, _) => {
            buf.push(0x02);
            let bytes = host.as_bytes();
            let len = bytes.len().min(255);
            buf.push(len as u8);
            buf.extend_from_slice(&bytes[..len]);
        }
    }

    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len];
        OsRng.fill_bytes(&mut padding);
        buf.extend_from_slice(&padding);
    }
    buf.extend_from_slice(&fnv1a32(&buf).to_be_bytes());
    buf
}

/// Body cipher for one direction. Both ciphers use a 12-byte nonce.
enum BodyCipher {
    Aes(Aes128Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl BodyCipher {
    fn new_crypto(security: u8, key: &[u8]) -> io::Result<Self> {
        match security {
            SECURITY_AES_128_GCM => Ok(Self::Aes(Aes128Gcm::new_from_slice(key).map_err(|_| aead_error())?)),
            SECURITY_CHACHA20_POLY1305 => {
                Ok(Self::ChaCha(ChaCha20Poly1305::new_from_slice(key).map_err(|_| aead_error())?))
            }
            _ => Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported VMess security")),
        }
    }

    fn encrypt(&self, nonce: &[u8; 12], msg: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aes(c) => c.encrypt(AesNonce::from_slice(nonce), Payload { msg, aad: &[] }).map_err(|_| aead_error()),
            Self::ChaCha(c) => c.encrypt(ChaChaNonce::from_slice(nonce), Payload { msg, aad: &[] }).map_err(|_| aead_error()),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], msg: &[u8]) -> io::Result<Vec<u8>> {
        match self {
            Self::Aes(c) => c.decrypt(AesNonce::from_slice(nonce), Payload { msg, aad: &[] }).map_err(|_| aead_error()),
            Self::ChaCha(c) => c.decrypt(ChaChaNonce::from_slice(nonce), Payload { msg, aad: &[] }).map_err(|_| aead_error()),
        }
    }
}

fn body_nonce(count: u16, iv: &[u8; 16]) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..2].copy_from_slice(&count.to_be_bytes());
    nonce[2..].copy_from_slice(&iv[2..12]);
    nonce
}

fn chacha_key(req_key_or_resp_key: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    let first = Md5::digest(req_key_or_resp_key);
    key[..16].copy_from_slice(&first);
    let second = Md5::digest(&key[..16]);
    key[16..].copy_from_slice(&second);
    key
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
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "vmess: closed mid-frame")));
                }
                *filled += buf.filled().len();
            }
        }
    }
    Poll::Ready(Ok(()))
}

/// AEAD-framed VMess body stream.
struct AeadStream {
    inner: BoxedStream,
    write_cipher: BodyCipher,
    write_iv: [u8; 16],
    write_count: u16,
    read_cipher: BodyCipher,
    read_iv: [u8; 16],
    read_count: u16,

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

impl AeadStream {
    fn new(
        inner: BoxedStream,
        write_cipher: BodyCipher,
        write_iv: [u8; 16],
        read_cipher: BodyCipher,
        read_iv: [u8; 16],
    ) -> Self {
        Self {
            inner,
            write_cipher,
            write_iv,
            write_count: 0,
            read_cipher,
            read_iv,
            read_count: 0,
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
        let nonce = body_nonce(self.write_count, &self.write_iv);
        self.write_count = self.write_count.wrapping_add(1);
        let ciphertext = self.write_cipher.encrypt(&nonce, data)?;
        let mut out = Vec::with_capacity(2 + ciphertext.len());
        out.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    fn flush_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.pending_off < self.pending.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.pending[self.pending_off..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "vmess: write zero")));
                }
                Poll::Ready(Ok(n)) => self.pending_off += n,
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for AeadStream {
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
                let size = u16::from_be_bytes(this.size_buf) as usize;
                this.size_filled = 0;
                if size == 0 || size > CHUNK_SIZE {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, "vmess: bad chunk size")));
                }
                this.payload = vec![0u8; size];
                this.payload_filled = 0;
                this.expect_payload = true;
            }

            match poll_read_exact(&mut this.inner, cx, &mut this.payload, &mut this.payload_filled) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
            let nonce = body_nonce(this.read_count, &this.read_iv);
            this.read_count = this.read_count.wrapping_add(1);
            this.plain = match this.read_cipher.decrypt(&nonce, &this.payload) {
                Ok(v) => v,
                Err(e) => return Poll::Ready(Err(e)),
            };
            this.expect_payload = false;
            this.payload_filled = 0;
        }
    }
}

impl AsyncWrite for AeadStream {
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
            let n = buf.len().min(CHUNK_SIZE - TAG_LEN);
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

async fn read_response_header(
    tcp: &mut BoxedStream,
    resp_key: &[u8; 16],
    resp_iv: &[u8; 16],
    resp_v: u8,
) -> io::Result<()> {
    let len_key = kdf(resp_key, &[b"AEAD Resp Header Len Key"]);
    let len_iv = kdf(resp_iv, &[b"AEAD Resp Header Len IV"]);
    let mut encrypted_length = [0u8; 18];
    tcp.read_exact(&mut encrypted_length).await?;
    let length_plain = aes_gcm_decrypt(&len_key[..16], &len_iv[..12], &encrypted_length, &[])?;
    if length_plain.len() < 2 {
        return Err(aead_error());
    }
    let length = u16::from_be_bytes([length_plain[0], length_plain[1]]) as usize;

    let key = kdf(resp_key, &[b"AEAD Resp Header Key"]);
    let iv = kdf(resp_iv, &[b"AEAD Resp Header IV"]);
    let mut encrypted = vec![0u8; length + TAG_LEN];
    tcp.read_exact(&mut encrypted).await?;
    let plain = aes_gcm_decrypt(&key[..16], &iv[..12], &encrypted, &[])?;
    if plain.len() < 4 || plain[0] != resp_v || plain[2] != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "unexpected VMess response header"));
    }
    Ok(())
}

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

pub struct VmessOutbound {
    name: String,
    server: TargetAddr,
    uuid: [u8; 16],
    security: u8,
    use_tls: bool,
    sni: String,
}

impl VmessOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        uuid: &str,
        security: &str,
        use_tls: bool,
        sni: Option<&str>,
    ) -> Option<Self> {
        let uuid = parse_uuid(uuid)?;
        let security = match security.to_ascii_lowercase().as_str() {
            "" | "auto" | "aes-128-gcm" => SECURITY_AES_128_GCM,
            "chacha20-poly1305" => SECURITY_CHACHA20_POLY1305,
            _ => return None,
        };
        let sni = sni.filter(|s| !s.is_empty()).unwrap_or(server).to_string();
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        Some(Self { name: name.to_string(), server, uuid, security, use_tls, sni })
    }
}

#[async_trait]
impl Outbound for VmessOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "VMess"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
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
        let mut tcp = tcp.ok_or_else(|| {
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no VMess server address"))
        })?;

        let mut random = [0u8; 33];
        OsRng.fill_bytes(&mut random);
        let mut req_iv = [0u8; 16];
        req_iv.copy_from_slice(&random[..16]);
        let mut req_key = [0u8; 16];
        req_key.copy_from_slice(&random[16..32]);
        let resp_v = random[32];

        let mut resp_key = [0u8; 16];
        resp_key.copy_from_slice(&Sha256::digest(&req_key)[..16]);
        let mut resp_iv = [0u8; 16];
        resp_iv.copy_from_slice(&Sha256::digest(&req_iv)[..16]);

        let padding = (OsRng.next_u32() % 16) as usize;
        let request = serialize_request(&req_iv, &req_key, resp_v, self.security, target, padding);
        let key = cmd_key(&self.uuid);
        let header = seal_vmess_aead_header(&key, &request, std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "system clock before epoch"))?
            .as_secs() as i64);

        let mut stream: BoxedStream = if self.use_tls {
            connect_tls(&self.sni, tcp).await?
        } else {
            Box::new(tcp)
        };
        stream.write_all(&header).await?;
        read_response_header(&mut stream, &resp_key, &resp_iv, resp_v).await?;

        let (write_cipher, read_cipher) = match self.security {
            SECURITY_AES_128_GCM => (
                BodyCipher::new_crypto(self.security, &req_key)?,
                BodyCipher::new_crypto(self.security, &resp_key)?,
            ),
            SECURITY_CHACHA20_POLY1305 => {
                let req_chacha_key = chacha_key(&req_key);
                let resp_chacha_key = chacha_key(&resp_key);
                (
                    BodyCipher::new_crypto(self.security, &req_chacha_key)?,
                    BodyCipher::new_crypto(self.security, &resp_chacha_key)?,
                )
            }
            _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported VMess security")),
        };

        Ok(Box::new(AeadStream::new(
            stream,
            write_cipher,
            req_iv,
            read_cipher,
            resp_iv,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_uuid() {
        let a = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let b = parse_uuid("b831381d63244d53ad4f8cda48b30811").unwrap();
        assert_eq!(a, b);
        assert!(parse_uuid("bad").is_none());
    }

    #[test]
    fn fnv1a_known_value() {
        assert_eq!(fnv1a32(b"hello"), 0x4f9f2cab);
    }

    #[test]
    fn cmd_key_is_md5_of_uuid_and_magic() {
        let uuid = parse_uuid("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap();
        let key = cmd_key(&uuid);
        let mut h = Md5::new();
        h.update(uuid);
        h.update(b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
        assert_eq!(key.as_slice(), &h.finalize()[..]);
    }

    #[test]
    fn request_header_fields() {
        let iv = [1u8; 16];
        let key = [2u8; 16];
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let header = serialize_request(&iv, &key, 0x7f, SECURITY_AES_128_GCM, &TargetAddr::Ip(ip, 443), 0);
        assert_eq!(header[0], VERSION);
        assert_eq!(&header[1..17], &iv);
        assert_eq!(&header[17..33], &key);
        assert_eq!(header[33], 0x7f);
        assert_eq!(header[34], OPTION_CHUNK_STREAM);
        assert_eq!(header[35], SECURITY_AES_128_GCM);
        assert_eq!(header[37], COMMAND_TCP);
        assert_eq!(&header[38..40], &443u16.to_be_bytes());
        assert_eq!(header[40], 0x01);
        assert_eq!(&header[41..45], &[1, 2, 3, 4]);
        let expected_crc = fnv1a32(&header[..45]).to_be_bytes();
        assert_eq!(&header[45..], &expected_crc);
    }

    #[test]
    fn auth_id_is_sixteen_bytes() {
        let key = [9u8; 16];
        assert_eq!(create_auth_id(&key, 1_700_000_000).len(), 16);
    }
}
