//! Hand-rolled TLS 1.3 client.
//!
//! rustls cannot drive REALITY: the protocol hides an AES-GCM-sealed
//! (version, time, short-id) blob in the ClientHello session id, keyed by
//! an X25519 exchange with the server's static public key — the client
//! must control the session id bytes and know its ephemeral private key.
//! This client also emits a browser-shaped hello (GREASE, hybrid
//! X25519MLKEM768 key share), which XTLS-Vision endpoints expect.
//!
//! Scope: TLS 1.3 only, groups X25519MLKEM768 / X25519, suites
//! AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305. In REALITY mode the
//! server is authenticated by the protocol's own proof: the leaf
//! certificate's signature field must equal HMAC-SHA512(AuthKey,
//! leaf Ed25519 public key). In plain mode the server Finished is
//! verified; certificate chain verification is not performed yet
//! (callers pass verify=false semantics from the proxy config).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use bytes::{Buf, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret as X25519Secret};

use super::BoxedStream;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;

pub const GROUP_X25519_MLKEM768: u16 = 0x11ec;
pub const GROUP_X25519: u16 = 0x001d;

const SUITE_AES128_GCM: u16 = 0x1301;
const SUITE_AES256_GCM: u16 = 0x1302;
const SUITE_CHACHA20: u16 = 0x1303;

#[derive(Clone)]
pub struct RealityParams {
    pub public_key: [u8; 32],
    pub short_id: [u8; 8],
}

pub struct Tls13Options {
    pub server_name: String,
    pub alpn: Vec<Vec<u8>>,
    pub reality: Option<RealityParams>,
}

// ---------- HKDF (RFC 5869 + TLS 1.3 labels, RFC 8446 §7.1) ----------

fn hkdf_extract384(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha384::new_from_slice(salt).expect("hmac key");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

fn hkdf_extract256(salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(salt).expect("hmac key");
    mac.update(ikm);
    mac.finalize().into_bytes().to_vec()
}

struct Schedule {
    hash_len: usize,
    sha384: bool,
}

impl Schedule {
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        if self.sha384 {
            Sha384::digest(data).to_vec()
        } else {
            Sha256::digest(data).to_vec()
        }
    }

    fn extract(&self, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
        if self.sha384 {
            hkdf_extract384(salt, ikm)
        } else {
            hkdf_extract256(salt, ikm)
        }
    }

    fn expand(&self, secret: &[u8], info: &[u8], len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        let mut prev: Vec<u8> = Vec::new();
        let mut counter = 1u8;
        while out.len() < len {
            let block = if self.sha384 {
                let mut mac = HmacSha384::new_from_slice(secret).expect("hmac key");
                mac.update(&prev);
                mac.update(info);
                mac.update(&[counter]);
                mac.finalize().into_bytes().to_vec()
            } else {
                let mut mac = HmacSha256::new_from_slice(secret).expect("hmac key");
                mac.update(&prev);
                mac.update(info);
                mac.update(&[counter]);
                mac.finalize().into_bytes().to_vec()
            };
            out.extend_from_slice(&block);
            prev = block;
            counter += 1;
        }
        out.truncate(len);
        out
    }

    fn expand_label(&self, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&(len as u16).to_be_bytes());
        let full_label = format!("tls13 {}", label);
        info.push(full_label.len() as u8);
        info.extend_from_slice(full_label.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        self.expand(secret, &info, len)
    }

    fn derive_secret(&self, secret: &[u8], label: &str, transcript_hash: &[u8]) -> Vec<u8> {
        self.expand_label(secret, label, transcript_hash, self.hash_len)
    }

    fn finished_verify(&self, secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        let key = self.expand_label(secret, "finished", &[], self.hash_len);
        if self.sha384 {
            let mut mac = HmacSha384::new_from_slice(&key).expect("hmac key");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        } else {
            let mut mac = HmacSha256::new_from_slice(&key).expect("hmac key");
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

// ---------- AEAD record protection ----------

enum AeadKind {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

impl AeadKind {
    fn seal(&self, nonce: &[u8], ad: &[u8], plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg: plaintext, aad: ad };
        let err = |_| io::Error::new(io::ErrorKind::Other, "tls13: record seal failed");
        match self {
            AeadKind::Aes128(c) => c.encrypt(Nonce::from_slice(nonce), payload).map_err(err),
            AeadKind::Aes256(c) => c.encrypt(Nonce::from_slice(nonce), payload).map_err(err),
            AeadKind::ChaCha(c) => c
                .encrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(err),
        }
    }

    fn open(&self, nonce: &[u8], ad: &[u8], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
        let payload = Payload { msg: ciphertext, aad: ad };
        let err = |_| io::Error::new(io::ErrorKind::InvalidData, "tls13: record open failed");
        match self {
            AeadKind::Aes128(c) => c.decrypt(Nonce::from_slice(nonce), payload).map_err(err),
            AeadKind::Aes256(c) => c.decrypt(Nonce::from_slice(nonce), payload).map_err(err),
            AeadKind::ChaCha(c) => c
                .decrypt(chacha20poly1305::Nonce::from_slice(nonce), payload)
                .map_err(err),
        }
    }
}

struct TrafficKeys {
    aead: AeadKind,
    iv: [u8; 12],
    secret: Vec<u8>,
    seq: u64,
}

impl TrafficKeys {
    fn nonce(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq_bytes = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq_bytes[i];
        }
        nonce
    }

    fn seal_record(&mut self, inner_type: u8, plaintext: &[u8]) -> io::Result<Vec<u8>> {
        let mut inner = plaintext.to_vec();
        inner.push(inner_type);
        let len = (inner.len() + 16) as u16;
        let mut ad = vec![0x17, 0x03, 0x03];
        ad.extend_from_slice(&len.to_be_bytes());
        let nonce = self.nonce(self.seq);
        let sealed = self.aead.seal(&nonce, &ad, &inner)?;
        self.seq += 1;
        let mut record = ad;
        record.extend_from_slice(&sealed);
        Ok(record)
    }

    /// Decrypt one application-data record body; returns (inner type, payload).
    fn open_record(&mut self, ciphertext: &[u8], header: &[u8; 5]) -> io::Result<(u8, Vec<u8>)> {
        let nonce = self.nonce(self.seq);
        let opened = self.aead.open(&nonce, header, ciphertext)?;
        self.seq += 1;
        // Strip trailing zeros; the last non-zero byte is the content type.
        let mut end = opened.len();
        while end > 0 && opened[end - 1] == 0 {
            end -= 1;
        }
        if end == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls13: empty inner plaintext",
            ));
        }
        let inner_type = opened[end - 1];
        Ok((inner_type, opened[..end - 1].to_vec()))
    }
}

fn traffic_keys(suite: u16, schedule: &Schedule, secret: &[u8]) -> TrafficKeys {
    let (key_len, make): (usize, fn(&[u8]) -> AeadKind) = match suite {
        SUITE_AES128_GCM => (16, |k| AeadKind::Aes128(<Aes128Gcm as aes_gcm::KeyInit>::new_from_slice(k).unwrap())),
        SUITE_AES256_GCM => (32, |k| AeadKind::Aes256(<Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(k).unwrap())),
        _ => (32, |k| AeadKind::ChaCha(<ChaCha20Poly1305 as aes_gcm::KeyInit>::new_from_slice(k).unwrap())),
    };
    let key = schedule.expand_label(secret, "key", &[], key_len);
    let iv_vec = schedule.expand_label(secret, "iv", &[], 12);
    let mut iv = [0u8; 12];
    iv.copy_from_slice(&iv_vec);
    TrafficKeys { aead: make(&key), iv, secret: secret.to_vec(), seq: 0 }
}

// ---------- ClientHello ----------

struct HelloKeys {
    x25519_secret: X25519Secret,
    x25519_public: [u8; 32],
    mlkem_dk: Option<<ml_kem::MlKem768 as ml_kem::KemCore>::DecapsulationKey>,
}

fn grease() -> u16 {
    0x1a1a
}

fn build_client_hello(opts: &Tls13Options) -> (Vec<u8>, HelloKeys, [u8; 32]) {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;

    let x25519_secret = X25519Secret::random_from_rng(&mut rng);
    let x25519_public = X25519Public::from(&x25519_secret);
    let (mlkem_dk, mlkem_ek) = {
        use ml_kem::{EncodedSizeUser, KemCore};
        let (dk, ek) = ml_kem::MlKem768::generate(&mut rng);
        let ek_bytes = ek.as_bytes();
        (Some(dk), ek_bytes.as_slice().to_vec())
    };

    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);

    let mut body = Vec::with_capacity(1600);
    body.extend_from_slice(&[0x03, 0x03]); // legacy version
    body.extend_from_slice(&random);
    body.push(32); // session id length
    let session_id_offset = 4 + body.len(); // within the full handshake message
    body.extend_from_slice(&[0u8; 32]); // session id slot (patched for REALITY)
    // cipher suites: GREASE + the three TLS 1.3 suites
    let suites: [u16; 4] = [grease(), SUITE_AES128_GCM, SUITE_AES256_GCM, SUITE_CHACHA20];
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // compression: null only

    let mut exts = Vec::new();
    let mut ext = |tag: u16, data: &[u8], exts: &mut Vec<u8>| {
        exts.extend_from_slice(&tag.to_be_bytes());
        exts.extend_from_slice(&(data.len() as u16).to_be_bytes());
        exts.extend_from_slice(data);
    };
    // server_name
    {
        let name = opts.server_name.as_bytes();
        let mut data = Vec::new();
        data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);
        ext(0, &data, &mut exts);
    }
    ext(23, &[], &mut exts); // extended_master_secret
    ext(65281, &[0], &mut exts); // renegotiation_info
    // supported_groups: GREASE, hybrid, x25519, p256, p384
    {
        let groups: [u16; 5] = [grease(), GROUP_X25519_MLKEM768, GROUP_X25519, 0x0017, 0x0018];
        let mut data = Vec::new();
        data.extend_from_slice(&((groups.len() * 2) as u16).to_be_bytes());
        for g in groups {
            data.extend_from_slice(&g.to_be_bytes());
        }
        ext(10, &data, &mut exts);
    }
    ext(11, &[3, 0, 1, 2], &mut exts); // ec_point_formats: uncompressed, ansiX962_compressed_prime, char2
    ext(35, &[], &mut exts); // session_ticket
    // ALPN
    {
        let mut data = Vec::new();
        let total: usize = opts.alpn.iter().map(|p| p.len() + 1).sum();
        data.extend_from_slice(&(total as u16).to_be_bytes());
        for p in &opts.alpn {
            data.push(p.len() as u8);
            data.extend_from_slice(p);
        }
        ext(16, &data, &mut exts);
    }
    ext(5, &[1, 0, 0, 0, 0], &mut exts); // status_request (OCSP)
    // signature_algorithms
    {
        let algs: [u16; 10] = [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0807, 0x0201,
        ];
        let mut data = Vec::new();
        data.extend_from_slice(&((algs.len() * 2) as u16).to_be_bytes());
        for a in algs {
            data.extend_from_slice(&a.to_be_bytes());
        }
        ext(13, &data, &mut exts);
    }
    ext(18, &[], &mut exts); // signed_certificate_timestamp
    // key_share: hybrid + x25519
    {
        let mut shares = Vec::new();
        let mut hybrid = Vec::with_capacity(1216);
        hybrid.extend_from_slice(&mlkem_ek);
        hybrid.extend_from_slice(x25519_public.as_bytes());
        shares.extend_from_slice(&GROUP_X25519_MLKEM768.to_be_bytes());
        shares.extend_from_slice(&(hybrid.len() as u16).to_be_bytes());
        shares.extend_from_slice(&hybrid);
        shares.extend_from_slice(&GROUP_X25519.to_be_bytes());
        shares.extend_from_slice(&32u16.to_be_bytes());
        shares.extend_from_slice(x25519_public.as_bytes());
        let mut data = Vec::new();
        data.extend_from_slice(&(shares.len() as u16).to_be_bytes());
        data.extend_from_slice(&shares);
        ext(51, &data, &mut exts);
    }
    ext(45, &[1, 1], &mut exts); // psk_key_exchange_modes: psk_dhe_ke
    ext(43, &[2, 0x03, 0x04], &mut exts); // supported_versions: TLS 1.3

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg = Vec::with_capacity(body.len() + 4);
    msg.push(1); // ClientHello
    let len = body.len() as u32;
    msg.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    msg.extend_from_slice(&body);
    debug_assert_eq!(session_id_offset, 39);
    (
        msg,
        HelloKeys { x25519_secret, x25519_public: *x25519_public.as_bytes(), mlkem_dk },
        random,
    )
}

/// Patch the REALITY session id into a built hello (see module docs).
fn apply_reality(msg: &mut [u8], keys: &HelloKeys, random: &[u8; 32], params: &RealityParams) {
    let shared = keys
        .x25519_secret
        .diffie_hellman(&X25519Public::from(params.public_key));
    let schedule = Schedule { hash_len: 32, sha384: false };
    let auth_key = schedule.extract(&random[..20], shared.as_bytes());
    // HKDF with salt=random[..20] and info "REALITY": hkdf.Key in Go is
    // extract+expand with the info string used raw (NOT a TLS label).
    let auth_key = hkdf_expand_raw(&auth_key, b"REALITY", 32);
    let mut plain = [0u8; 16];
    plain[0] = 25;
    plain[1] = 12;
    plain[2] = 2;
    plain[3] = 0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    plain[4..8].copy_from_slice(&now.to_be_bytes());
    plain[8..16].copy_from_slice(&params.short_id);
    let cipher = <Aes256Gcm as aes_gcm::KeyInit>::new_from_slice(&auth_key).expect("auth key len");
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&random[20..32]),
            Payload { msg: &plain, aad: msg },
        )
        .expect("gcm seal");
    debug_assert_eq!(sealed.len(), 32);
    msg[39..39 + 32].copy_from_slice(&sealed);
    // Stash the auth key for later certificate verification by returning
    // it through the message-independent channel: callers recompute it
    // via reality_auth_key().
}

fn reality_auth_key(keys: &HelloKeys, random: &[u8; 32], params: &RealityParams) -> Vec<u8> {
    let shared = keys
        .x25519_secret
        .diffie_hellman(&X25519Public::from(params.public_key));
    let schedule = Schedule { hash_len: 32, sha384: false };
    let extracted = schedule.extract(&random[..20], shared.as_bytes());
    hkdf_expand_raw(&extracted, b"REALITY", 32)
}

/// HKDF-Expand with a raw info string (Go hkdf.Key semantics).
fn hkdf_expand_raw(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut prev: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut mac = HmacSha256::new_from_slice(prk).expect("hmac key");
        mac.update(&prev);
        mac.update(info);
        mac.update(&[counter]);
        let block = mac.finalize().into_bytes().to_vec();
        out.extend_from_slice(&block);
        prev = block;
        counter += 1;
    }
    out.truncate(len);
    out
}

// ---------- record IO during the handshake ----------

async fn write_record(inner: &mut BoxedStream, record_type: u8, payload: &[u8]) -> io::Result<()> {
    let mut record = vec![record_type, 0x03, 0x01];
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    inner.write_all(&record).await
}

async fn read_record(inner: &mut BoxedStream) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    inner.read_exact(&mut header).await?;
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > 18432 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: record too large"));
    }
    let mut payload = vec![0u8; len];
    inner.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}

// ---------- minimal DER walk for the REALITY certificate proof ----------

fn der_read_tlv(data: &[u8], pos: usize) -> Option<(u8, usize, usize, usize)> {
    if pos + 2 > data.len() {
        return None;
    }
    let tag = data[pos];
    let mut p = pos + 1;
    let first = data[p];
    p += 1;
    let len = if first & 0x80 == 0 {
        first as usize
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 3 || p + n > data.len() {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = (v << 8) | data[p + i] as usize;
        }
        p += n;
        v
    };
    if p + len > data.len() {
        return None;
    }
    Some((tag, p, len, p + len))
}

/// Extract (Ed25519 public key, certificate signature) from a leaf cert.
fn cert_pubkey_and_signature(cert: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (_, content, _, _) = der_read_tlv(cert, 0)?;
    let mut pos = content;
    // tbsCertificate
    let (_, tbs_content, tbs_len, tbs_next) = der_read_tlv(cert, pos)?;
    // signatureValue is the third element of the outer sequence.
    let (_, _, _, after_alg) = der_read_tlv(cert, tbs_next)?;
    let (tag, sig_content, sig_len, _) = der_read_tlv(cert, after_alg)?;
    if tag != 0x03 || sig_len < 2 {
        return None;
    }
    let signature = cert[sig_content + 1..sig_content + sig_len].to_vec();
    // Walk the tbs children up to subjectPublicKeyInfo:
    // [0] version (optional), serial, signature, issuer, validity, subject, spki
    let mut p = tbs_content;
    let end = tbs_content + tbs_len;
    if let Some((ctag, _, _, cnext)) = der_read_tlv(cert, p) {
        if ctag == 0xa0 {
            p = cnext; // skip the version element
        }
    }
    let mut index = 0usize;
    while p < end {
        let (_, _, _, cnext) = der_read_tlv(cert, p)?;
        // child order after the optional version: 0 serial, 1 signature,
        // 2 issuer, 3 validity, 4 subject, 5 spki
        if index == 5 {
            let (_, spki_content, _, _) = der_read_tlv(cert, p)?;
            let (_, _, _, after_spki_alg) = der_read_tlv(cert, spki_content)?;
            let (btag, bcontent, blen, _) = der_read_tlv(cert, after_spki_alg)?;
            if btag != 0x03 || blen < 2 {
                return None;
            }
            let pubkey = cert[bcontent + 1..bcontent + blen].to_vec();
            return Some((pubkey, signature));
        }
        index += 1;
        p = cnext;
    }
    None
}

fn verify_reality_proof(auth_key: &[u8], cert_msg_body: &[u8]) -> io::Result<()> {
    // Certificate message: request context (1 len byte) + list (3-byte len)
    if cert_msg_body.len() < 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: short certificate message"));
    }
    let ctx_len = cert_msg_body[0] as usize;
    let mut pos = 1 + ctx_len;
    if pos + 3 > cert_msg_body.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: short certificate list"));
    }
    pos += 3;
    if pos + 3 > cert_msg_body.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: no leaf certificate"));
    }
    let leaf_len = ((cert_msg_body[pos] as usize) << 16)
        | ((cert_msg_body[pos + 1] as usize) << 8)
        | cert_msg_body[pos + 2] as usize;
    pos += 3;
    if pos + leaf_len > cert_msg_body.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: leaf overruns message"));
    }
    let leaf = &cert_msg_body[pos..pos + leaf_len];
    let (pubkey, signature) = cert_pubkey_and_signature(leaf).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "tls13: cannot parse leaf certificate")
    })?;
    if pubkey.len() != 32 || signature.len() != 64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tls13: REALITY leaf is not an Ed25519 certificate",
        ));
    }
    let mut mac = Hmac::<sha2::Sha512>::new_from_slice(auth_key).expect("hmac key");
    mac.update(&pubkey);
    let expected = mac.finalize().into_bytes();
    if expected.as_slice() != signature.as_slice() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tls13: REALITY certificate proof mismatch (not a REALITY server)",
        ));
    }
    Ok(())
}

// ---------- handshake driver ----------

pub async fn connect_tls13(
    mut inner: BoxedStream,
    opts: &Tls13Options,
) -> io::Result<Tls13Stream> {
    let (mut hello, keys, random) = build_client_hello(opts);
    let auth_key = opts
        .reality
        .as_ref()
        .map(|params| reality_auth_key(&keys, &random, params));
    if let Some(params) = &opts.reality {
        apply_reality(&mut hello, &keys, &random, params);
    }

    let mut transcript: Vec<u8> = Vec::new();
    write_record(&mut inner, 22, &hello).await?;
    transcript.extend_from_slice(&hello);

    // ServerHello arrives as a plaintext record (possibly with others).
    let mut plain_buf: Vec<u8> = Vec::new();
    let server_hello = loop {
        if let Some(msg) = take_handshake_message(&mut plain_buf) {
            break msg;
        }
        let (record_type, payload) = read_record(&mut inner).await?;
        if record_type == 21 {
            return Err(io::Error::new(io::ErrorKind::Other, "tls13: alert before ServerHello"));
        }
        if record_type != 22 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls13: expected handshake record",
            ));
        }
        plain_buf.extend_from_slice(&payload);
    };
    if server_hello.is_empty() || server_hello[0] != 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: not a ServerHello"));
    }
    transcript.extend_from_slice(&server_hello);
    let (suite, group, server_share) = parse_server_hello(&server_hello)?;
    let schedule = Schedule {
        hash_len: if suite == SUITE_AES256_GCM { 48 } else { 32 },
        sha384: suite == SUITE_AES256_GCM,
    };

    let shared = shared_secret(&keys, group, &server_share)?;
    let zeros = vec![0u8; schedule.hash_len];
    let early = schedule.extract(&zeros, &zeros);
    let derived = schedule.derive_secret(&early, "derived", &schedule.hash(&[]));
    let handshake_secret = schedule.extract(&derived, &shared);
    let transcript_hash = schedule.hash(&transcript);
    let c_hs = schedule.derive_secret(&handshake_secret, "c hs traffic", &transcript_hash);
    let s_hs = schedule.derive_secret(&handshake_secret, "s hs traffic", &transcript_hash);
    let mut server_keys = traffic_keys(suite, &schedule, &s_hs);
    let mut client_keys = traffic_keys(suite, &schedule, &c_hs);

    // Encrypted flight: read messages until Finished, verifying as we go.
    let mut cipher_buf: Vec<u8> = Vec::new();
    let mut server_finished_transcript: Option<Vec<u8>> = None;
    loop {
        if let Some(msg) = take_handshake_message(&mut cipher_buf) {
            if msg.is_empty() {
                continue;
            }
            match msg[0] {
                8 => {
                    // EncryptedExtensions: nothing we must act on.
                    transcript.extend_from_slice(&msg);
                }
                11 => {
                    if let Some(auth) = &auth_key {
                        verify_reality_proof(auth, &msg[4..])?;
                    }
                    transcript.extend_from_slice(&msg);
                }
                15 => {
                    // CertificateVerify: in REALITY mode the HMAC proof
                    // above replaces it; plain mode verifies Finished only.
                    transcript.extend_from_slice(&msg);
                }
                20 => {
                    let expected =
                        schedule.finished_verify(&s_hs, &schedule.hash(&transcript));
                    if msg.len() < 4 + expected.len()
                        || &msg[4..4 + expected.len()] != expected.as_slice()
                    {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "tls13: server Finished verification failed",
                        ));
                    }
                    transcript.extend_from_slice(&msg);
                    server_finished_transcript = Some(transcript.clone());
                    break;
                }
                _ => {
                    transcript.extend_from_slice(&msg);
                }
            }
            continue;
        }
        let (record_type, payload) = read_record(&mut inner).await?;
        if record_type == 21 {
            return Err(io::Error::new(io::ErrorKind::Other, "tls13: alert during handshake"));
        }
        if record_type != 23 {
            // ChangeCipherSpec (20) and stray plaintext records are skipped.
            continue;
        }
        let mut header = [0u8; 5];
        header[0] = record_type;
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let (inner_type, opened) = server_keys.open_record(&payload, &header)?;
        if inner_type == 21 {
            return Err(io::Error::new(io::ErrorKind::Other, "tls13: encrypted alert"));
        }
        if inner_type != 22 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "tls13: expected encrypted handshake record",
            ));
        }
        cipher_buf.extend_from_slice(&opened);
    }
    let finished_transcript = server_finished_transcript.unwrap();

    // Client Finished.
    let client_verify =
        schedule.finished_verify(&c_hs, &schedule.hash(&transcript));
    let mut finished = vec![20u8];
    let flen = client_verify.len() as u32;
    finished.extend_from_slice(&[(flen >> 16) as u8, (flen >> 8) as u8, flen as u8]);
    finished.extend_from_slice(&client_verify);
    let record = client_keys.seal_record(22, &finished)?;
    inner.write_all(&record).await?;

    // Application secrets.
    let derived2 = schedule.derive_secret(&handshake_secret, "derived", &schedule.hash(&[]));
    let master = schedule.extract(&derived2, &zeros);
    let final_hash = schedule.hash(&finished_transcript);
    let c_ap = schedule.derive_secret(&master, "c ap traffic", &final_hash);
    let s_ap = schedule.derive_secret(&master, "s ap traffic", &final_hash);
    let client_write = traffic_keys(suite, &schedule, &c_ap);
    let server_write = traffic_keys(suite, &schedule, &s_ap);

    Ok(Tls13Stream {
        inner,
        schedule,
        suite,
        read_keys: server_write,
        write_keys: client_write,
        read_secret: s_ap,
        write_secret: c_ap,
        raw_buf: BytesMut::new(),
        hs_buf: Vec::new(),
        plain_buf: BytesMut::new(),
        read_eof: false,
        write_buf: Vec::new(),
        write_pos: 0,
        shutdown_sent: false,
    })
}

fn take_handshake_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let msg: Vec<u8> = buf.drain(..4 + len).collect();
    Some(msg)
}

fn parse_server_hello(msg: &[u8]) -> io::Result<(u16, u16, Vec<u8>)> {
    // body: version(2) random(32) session echo(1+len) suite(2) compression(1) exts(2+..)
    let body = &msg[4..];
    if body.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: short ServerHello"));
    }
    let hrr_random: [u8; 32] = [
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8,
        0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8,
        0x33, 0x9c,
    ];
    if &body[2..34] == hrr_random.as_slice() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "tls13: HelloRetryRequest not supported (server rejected our key shares)",
        ));
    }
    let mut pos = 34;
    let echo_len = body[pos] as usize;
    pos += 1 + echo_len;
    let suite = u16::from_be_bytes([body[pos], body[pos + 1]]);
    pos += 2;
    pos += 1; // compression
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = (pos + ext_total).min(body.len());
    let mut group = 0u16;
    let mut share: Vec<u8> = Vec::new();
    let mut saw_versions = false;
    while pos + 4 <= ext_end {
        let tag = u16::from_be_bytes([body[pos], body[pos + 1]]);
        let len = u16::from_be_bytes([body[pos + 2], body[pos + 3]]) as usize;
        pos += 4;
        if pos + len > ext_end {
            break;
        }
        let data = &body[pos..pos + len];
        match tag {
            43 => {
                if len == 2 && data[0] == 0x03 && data[1] == 0x04 {
                    saw_versions = true;
                }
            }
            51 => {
                if len >= 4 {
                    group = u16::from_be_bytes([data[0], data[1]]);
                    let share_len = u16::from_be_bytes([data[2], data[3]]) as usize;
                    if 4 + share_len <= len {
                        share = data[4..4 + share_len].to_vec();
                    }
                }
            }
            _ => {}
        }
        pos += len;
    }
    if !saw_versions {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: server did not negotiate 1.3"));
    }
    if group == 0 || share.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: no key share in ServerHello"));
    }
    if !matches!(suite, SUITE_AES128_GCM | SUITE_AES256_GCM | SUITE_CHACHA20) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: unsupported cipher suite"));
    }
    Ok((suite, group, share))
}

fn shared_secret(keys: &HelloKeys, group: u16, server_share: &[u8]) -> io::Result<Vec<u8>> {
    match group {
        GROUP_X25519 => {
            if server_share.len() != 32 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: bad X25519 share"));
            }
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(server_share);
            Ok(keys
                .x25519_secret
                .diffie_hellman(&X25519Public::from(bytes))
                .as_bytes()
                .to_vec())
        }
        GROUP_X25519_MLKEM768 => {
            use ml_kem::kem::Decapsulate;
            // share = ML-KEM ciphertext (1088) || server X25519 public (32)
            if server_share.len() != 1088 + 32 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tls13: bad X25519MLKEM768 share",
                ));
            }
            let dk = keys.mlkem_dk.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Other, "tls13: missing ML-KEM key")
            })?;
            let ct = ml_kem::Ciphertext::<ml_kem::MlKem768>::from_slice(&server_share[..1088]);
            let mlkem_secret = dk.decapsulate(ct).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "tls13: ML-KEM decapsulation failed")
            })?;
            let mut x_pub = [0u8; 32];
            x_pub.copy_from_slice(&server_share[1088..]);
            let x_secret = keys
                .x25519_secret
                .diffie_hellman(&X25519Public::from(x_pub));
            let mut out = Vec::with_capacity(64);
            out.extend_from_slice(mlkem_secret.as_slice());
            out.extend_from_slice(x_secret.as_bytes());
            Ok(out)
        }
        _ => Err(io::Error::new(io::ErrorKind::InvalidData, "tls13: unsupported group")),
    }
}

// ---------- the stream ----------

pub struct Tls13Stream {
    inner: BoxedStream,
    schedule: Schedule,
    suite: u16,
    read_keys: TrafficKeys,
    write_keys: TrafficKeys,
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    raw_buf: BytesMut,
    plain_buf: BytesMut,
    hs_buf: Vec<u8>,
    read_eof: bool,
    write_buf: Vec<u8>,
    write_pos: usize,
    shutdown_sent: bool,
}

impl Tls13Stream {
    /// Consume the stream and return (raw transport, bytes to read first,
    /// sealed bytes still to write). Used by XTLS-Vision's direct mode,
    /// where the TLS layer is dropped and the inner stream continues on
    /// the raw socket: the read leftovers (decrypted bytes not yet
    /// delivered, then raw bytes read but not yet decrypted) are the
    /// inner stream's first bytes, and the pending sealed records must
    /// still go out on the socket before any raw writes.
    pub fn into_raw_parts(mut self) -> (BoxedStream, BytesMut, Vec<u8>) {
        let mut read_first = BytesMut::new();
        read_first.extend_from_slice(&self.plain_buf);
        read_first.extend_from_slice(&self.raw_buf);
        let pending_write = self.write_buf.split_off(self.write_pos);
        (self.inner, read_first, pending_write)
    }

    fn flush_write_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.write_pos < self.write_buf.len() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.write_buf[self.write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "tls13: underlying write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => self.write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.write_buf.clear();
        self.write_pos = 0;
        Poll::Ready(Ok(()))
    }

    fn roll_read_keys(&mut self) {
        let next = self
            .schedule
            .expand_label(&self.read_secret, "traffic upd", &[], self.schedule.hash_len);
        self.read_secret = next;
        self.read_keys = traffic_keys(self.suite, &self.schedule, &self.read_secret);
    }

    fn roll_write_keys(&mut self) {
        let next = self
            .schedule
            .expand_label(&self.write_secret, "traffic upd", &[], self.schedule.hash_len);
        self.write_secret = next;
        self.write_keys = traffic_keys(self.suite, &self.schedule, &self.write_secret);
    }

    /// Process decrypted handshake-type payloads (post-handshake messages).
    fn handle_handshake_payload(&mut self, payload: &[u8]) -> io::Result<()> {
        self.hs_buf.extend_from_slice(payload);
        loop {
            if self.hs_buf.len() < 4 {
                return Ok(());
            }
            let len = ((self.hs_buf[1] as usize) << 16)
                | ((self.hs_buf[2] as usize) << 8)
                | self.hs_buf[3] as usize;
            if self.hs_buf.len() < 4 + len {
                return Ok(());
            }
            let msg: Vec<u8> = self.hs_buf.drain(..4 + len).collect();
            match msg[0] {
                4 => {
                    // NewSessionTicket: not used.
                }
                24 => {
                    // KeyUpdate
                    let requested = if len >= 1 { msg[4] } else { 0 };
                    self.roll_read_keys();
                    if requested == 1 {
                        self.roll_write_keys();
                        let ku = [24u8, 0, 0, 1, 0];
                        let record = self.write_keys.seal_record(22, &ku)?;
                        self.write_buf.extend_from_slice(&record);
                    }
                }
                _ => {}
            }
        }
    }
}

impl AsyncRead for Tls13Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.plain_buf.is_empty() {
                let n = self.plain_buf.len().min(buf.remaining());
                buf.put_slice(&self.plain_buf[..n]);
                self.plain_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.read_eof {
                return Poll::Ready(Ok(()));
            }
            if self.raw_buf.len() >= 5 {
                let record_len =
                    u16::from_be_bytes([self.raw_buf[3], self.raw_buf[4]]) as usize;
                if record_len > 18432 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls13: record too large",
                    )));
                }
                if self.raw_buf.len() >= 5 + record_len {
                    let record_type = self.raw_buf[0];
                    let mut header = [0u8; 5];
                    header.copy_from_slice(&self.raw_buf[..5]);
                    let payload: Vec<u8> = self.raw_buf[5..5 + record_len].to_vec();
                    self.raw_buf.advance(5 + record_len);
                    match record_type {
                        23 => {
                            let (inner_type, opened) =
                                match self.read_keys.open_record(&payload, &header) {
                                    Ok(v) => v,
                                    Err(e) => return Poll::Ready(Err(e)),
                                };
                            match inner_type {
                                23 => {
                                    self.plain_buf.extend_from_slice(&opened);
                                }
                                22 => {
                                    if let Err(e) = self.handle_handshake_payload(&opened) {
                                        return Poll::Ready(Err(e));
                                    }
                                }
                                21 => {
                                    if opened.len() >= 2 && opened[1] == 0 {
                                        self.read_eof = true;
                                    } else {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::Other,
                                            "tls13: fatal alert received",
                                        )));
                                    }
                                }
                                _ => {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::InvalidData,
                                        "tls13: unexpected inner content type",
                                    )));
                                }
                            }
                            continue;
                        }
                        21 => {
                            if payload.len() >= 2 && payload[1] == 0 {
                                self.read_eof = true;
                            } else {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::Other,
                                    "tls13: plaintext alert received",
                                )));
                            }
                            continue;
                        }
                        20 => {
                            continue; // ChangeCipherSpec: ignore
                        }
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "tls13: unexpected record type",
                            )));
                        }
                    }
                }
            }
            let mut tmp = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut tmp);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled();
                    if filled.is_empty() {
                        self.read_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.raw_buf.extend_from_slice(filled);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for Tls13Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_pos < self.write_buf.len() {
            match self.flush_write_buf(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let chunk = &buf[..buf.len().min(16384)];
        let record = match self.write_keys.seal_record(23, chunk) {
            Ok(r) => r,
            Err(e) => return Poll::Ready(Err(e)),
        };
        self.write_buf.extend_from_slice(&record);
        match self.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }
        Poll::Ready(Ok(chunk.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_write_buf(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown_sent {
            self.shutdown_sent = true;
            if let Ok(record) = self.write_keys.seal_record(21, &[1, 0]) {
                self.write_buf.extend_from_slice(&record);
            }
        }
        match self.flush_write_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}
