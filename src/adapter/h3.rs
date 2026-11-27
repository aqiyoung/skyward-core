//! Minimal HTTP/3 client (RFC 9114) with a literal-only QPACK encoder
//! (RFC 9204) — just enough for Hysteria2 authentication.
//!
//! The encoder never uses the dynamic table or Huffman coding (both
//! legal), and advertises a QPACK capacity of 0 so the peer cannot use
//! the dynamic table either. The decoder handles indexed and literal
//! fields against the static table, including Huffman-coded strings,
//! which real servers (quic-go) do emit.

use std::collections::HashMap;
use std::io;
use std::sync::OnceLock;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

/// QPACK static table (RFC 9204 Appendix A): (name, value) by index.
pub static QPACK_STATIC: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html; charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000; includesubdomains"),
    ("strict-transport-security", "max-age=31536000; includesubdomains; preload"),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// HPACK/QPACK Huffman code table (RFC 7541 Appendix B):
/// (code, code length in bits) per symbol; index 256 is EOS.
pub static HUFFMAN: &[(u32, u8)] = &[
    (0x1ff8, 13),
    (0x7fffd8, 23),
    (0xfffffe2, 28),
    (0xfffffe3, 28),
    (0xfffffe4, 28),
    (0xfffffe5, 28),
    (0xfffffe6, 28),
    (0xfffffe7, 28),
    (0xfffffe8, 28),
    (0xffffea, 24),
    (0x3ffffffc, 30),
    (0xfffffe9, 28),
    (0xfffffea, 28),
    (0x3ffffffd, 30),
    (0xfffffeb, 28),
    (0xfffffec, 28),
    (0xfffffed, 28),
    (0xfffffee, 28),
    (0xfffffef, 28),
    (0xffffff0, 28),
    (0xffffff1, 28),
    (0xffffff2, 28),
    (0x3ffffffe, 30),
    (0xffffff3, 28),
    (0xffffff4, 28),
    (0xffffff5, 28),
    (0xffffff6, 28),
    (0xffffff7, 28),
    (0xffffff8, 28),
    (0xffffff9, 28),
    (0xffffffa, 28),
    (0xffffffb, 28),
    (0x14, 6),
    (0x3f8, 10),
    (0x3f9, 10),
    (0xffa, 12),
    (0x1ff9, 13),
    (0x15, 6),
    (0xf8, 8),
    (0x7fa, 11),
    (0x3fa, 10),
    (0x3fb, 10),
    (0xf9, 8),
    (0x7fb, 11),
    (0xfa, 8),
    (0x16, 6),
    (0x17, 6),
    (0x18, 6),
    (0x0, 5),
    (0x1, 5),
    (0x2, 5),
    (0x19, 6),
    (0x1a, 6),
    (0x1b, 6),
    (0x1c, 6),
    (0x1d, 6),
    (0x1e, 6),
    (0x1f, 6),
    (0x5c, 7),
    (0xfb, 8),
    (0x7ffc, 15),
    (0x20, 6),
    (0xffb, 12),
    (0x3fc, 10),
    (0x1ffa, 13),
    (0x21, 6),
    (0x5d, 7),
    (0x5e, 7),
    (0x5f, 7),
    (0x60, 7),
    (0x61, 7),
    (0x62, 7),
    (0x63, 7),
    (0x64, 7),
    (0x65, 7),
    (0x66, 7),
    (0x67, 7),
    (0x68, 7),
    (0x69, 7),
    (0x6a, 7),
    (0x6b, 7),
    (0x6c, 7),
    (0x6d, 7),
    (0x6e, 7),
    (0x6f, 7),
    (0x70, 7),
    (0x71, 7),
    (0x72, 7),
    (0xfc, 8),
    (0x73, 7),
    (0xfd, 8),
    (0x1ffb, 13),
    (0x7fff0, 19),
    (0x1ffc, 13),
    (0x3ffc, 14),
    (0x22, 6),
    (0x7ffd, 15),
    (0x3, 5),
    (0x23, 6),
    (0x4, 5),
    (0x24, 6),
    (0x5, 5),
    (0x25, 6),
    (0x26, 6),
    (0x27, 6),
    (0x6, 5),
    (0x74, 7),
    (0x75, 7),
    (0x28, 6),
    (0x29, 6),
    (0x2a, 6),
    (0x7, 5),
    (0x2b, 6),
    (0x76, 7),
    (0x2c, 6),
    (0x8, 5),
    (0x9, 5),
    (0x2d, 6),
    (0x77, 7),
    (0x78, 7),
    (0x79, 7),
    (0x7a, 7),
    (0x7b, 7),
    (0x7ffe, 15),
    (0x7fc, 11),
    (0x3ffd, 14),
    (0x1ffd, 13),
    (0xffffffc, 28),
    (0xfffe6, 20),
    (0x3fffd2, 22),
    (0xfffe7, 20),
    (0xfffe8, 20),
    (0x3fffd3, 22),
    (0x3fffd4, 22),
    (0x3fffd5, 22),
    (0x7fffd9, 23),
    (0x3fffd6, 22),
    (0x7fffda, 23),
    (0x7fffdb, 23),
    (0x7fffdc, 23),
    (0x7fffdd, 23),
    (0x7fffde, 23),
    (0xffffeb, 24),
    (0x7fffdf, 23),
    (0xffffec, 24),
    (0xffffed, 24),
    (0x3fffd7, 22),
    (0x7fffe0, 23),
    (0xffffee, 24),
    (0x7fffe1, 23),
    (0x7fffe2, 23),
    (0x7fffe3, 23),
    (0x7fffe4, 23),
    (0x1fffdc, 21),
    (0x3fffd8, 22),
    (0x7fffe5, 23),
    (0x3fffd9, 22),
    (0x7fffe6, 23),
    (0x7fffe7, 23),
    (0xffffef, 24),
    (0x3fffda, 22),
    (0x1fffdd, 21),
    (0xfffe9, 20),
    (0x3fffdb, 22),
    (0x3fffdc, 22),
    (0x7fffe8, 23),
    (0x7fffe9, 23),
    (0x1fffde, 21),
    (0x7fffea, 23),
    (0x3fffdd, 22),
    (0x3fffde, 22),
    (0xfffff0, 24),
    (0x1fffdf, 21),
    (0x3fffdf, 22),
    (0x7fffeb, 23),
    (0x7fffec, 23),
    (0x1fffe0, 21),
    (0x1fffe1, 21),
    (0x3fffe0, 22),
    (0x1fffe2, 21),
    (0x7fffed, 23),
    (0x3fffe1, 22),
    (0x7fffee, 23),
    (0x7fffef, 23),
    (0xfffea, 20),
    (0x3fffe2, 22),
    (0x3fffe3, 22),
    (0x3fffe4, 22),
    (0x7ffff0, 23),
    (0x3fffe5, 22),
    (0x3fffe6, 22),
    (0x7ffff1, 23),
    (0x3ffffe0, 26),
    (0x3ffffe1, 26),
    (0xfffeb, 20),
    (0x7fff1, 19),
    (0x3fffe7, 22),
    (0x7ffff2, 23),
    (0x3fffe8, 22),
    (0x1ffffec, 25),
    (0x3ffffe2, 26),
    (0x3ffffe3, 26),
    (0x3ffffe4, 26),
    (0x7ffffde, 27),
    (0x7ffffdf, 27),
    (0x3ffffe5, 26),
    (0xfffff1, 24),
    (0x1ffffed, 25),
    (0x7fff2, 19),
    (0x1fffe3, 21),
    (0x3ffffe6, 26),
    (0x7ffffe0, 27),
    (0x7ffffe1, 27),
    (0x3ffffe7, 26),
    (0x7ffffe2, 27),
    (0xfffff2, 24),
    (0x1fffe4, 21),
    (0x1fffe5, 21),
    (0x3ffffe8, 26),
    (0x3ffffe9, 26),
    (0xffffffd, 28),
    (0x7ffffe3, 27),
    (0x7ffffe4, 27),
    (0x7ffffe5, 27),
    (0xfffec, 20),
    (0xfffff3, 24),
    (0xfffed, 20),
    (0x1fffe6, 21),
    (0x3fffe9, 22),
    (0x1fffe7, 21),
    (0x1fffe8, 21),
    (0x7ffff3, 23),
    (0x3fffea, 22),
    (0x3fffeb, 22),
    (0x1ffffee, 25),
    (0x1ffffef, 25),
    (0xfffff4, 24),
    (0xfffff5, 24),
    (0x3ffffea, 26),
    (0x7ffff4, 23),
    (0x3ffffeb, 26),
    (0x7ffffe6, 27),
    (0x3ffffec, 26),
    (0x3ffffed, 26),
    (0x7ffffe7, 27),
    (0x7ffffe8, 27),
    (0x7ffffe9, 27),
    (0x7ffffea, 27),
    (0x7ffffeb, 27),
    (0xffffffe, 28),
    (0x7ffffec, 27),
    (0x7ffffed, 27),
    (0x7ffffee, 27),
    (0x7ffffef, 27),
    (0x7fffff0, 27),
    (0x3ffffee, 26),
    (0x3fffffff, 30),
];
// ---------------------------------------------------------------------
// QUIC variable-length integers (RFC 9000 §16)

pub fn put_varint(out: &mut Vec<u8>, value: u64) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else if value < 1073741824 {
        out.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

pub fn parse_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return None;
    }
    let mut value = (first & 0x3f) as u64;
    for &byte in &data[1..len] {
        value = (value << 8) | byte as u64;
    }
    Some((value, len))
}

// ---------------------------------------------------------------------
// QPACK integer and string primitives (RFC 9204 §4)

fn put_prefix_int(out: &mut Vec<u8>, first: u8, prefix_bits: u8, value: u64) {
    let mask = (1u16 << prefix_bits) - 1;
    if value < mask as u64 {
        out.push(first | value as u8);
        return;
    }
    out.push(first | mask as u8);
    let mut rest = value - mask as u64;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

fn parse_prefix_int(data: &[u8], prefix_bits: u8) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let mask = (1u64 << prefix_bits) - 1;
    let mut value = (first as u64) & mask;
    if value < mask {
        return Some((value, 1));
    }
    let mut shift = 0u32;
    let mut pos = 1;
    loop {
        let byte = *data.get(pos)?;
        value += ((byte & 0x7f) as u64) << shift;
        shift += 7;
        pos += 1;
        if byte & 0x80 == 0 {
            return Some((value, pos));
        }
        if shift > 56 {
            return None;
        }
    }
}

fn put_string(out: &mut Vec<u8>, value: &str, prefix_bits: u8, first_flags: u8) {
    // No Huffman coding on encode (H bit = 0).
    put_prefix_int(out, first_flags, prefix_bits, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn huffman_decode(data: &[u8]) -> io::Result<Vec<u8>> {
    static DECODE_MAP: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
    let map = DECODE_MAP.get_or_init(|| {
        let mut map = HashMap::new();
        for (symbol, &(code, len)) in HUFFMAN.iter().enumerate() {
            map.insert((len, code), symbol as u16);
        }
        map
    });
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut code: u32 = 0;
    let mut len: u8 = 0;
    for &byte in data {
        for shift in (0..8).rev() {
            code = (code << 1) | ((byte >> shift) & 1) as u32;
            len += 1;
            if let Some(&symbol) = map.get(&(len, code)) {
                if symbol == 256 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "qpack: EOS in string"));
                }
                out.push(symbol as u8);
                code = 0;
                len = 0;
            } else if len >= 30 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "qpack: bad huffman code"));
            }
        }
    }
    // Trailing bits must be all-ones padding (a prefix of the EOS
    // symbol, whose code is all ones), shorter than 8 bits.
    if len > 0 && (len >= 8 || code != (1u32 << len) - 1) {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "qpack: bad huffman padding"));
    }
    Ok(out)
}

fn parse_string(data: &[u8], prefix_bits: u8) -> io::Result<(Vec<u8>, usize)> {
    let first = *data.first().ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "qpack string"))?;
    let huffman = first & (1 << prefix_bits) != 0;
    let (len, used) = parse_prefix_int(data, prefix_bits)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "qpack string length"))?;
    let len = len as usize;
    let start = used;
    let end = start + len;
    let raw = data.get(start..end).ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "qpack string body"))?;
    let value = if huffman { huffman_decode(raw)? } else { raw.to_vec() };
    Ok((value, end))
}

// ---------------------------------------------------------------------
// QPACK header block encode/decode

/// Encode a header block using only literal fields (no dynamic table,
/// no Huffman). Pseudo-headers must already be ordered first by the
/// caller.
pub fn encode_header_block(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    // Required Insert Count = 0 (8-bit prefix), Signed delta base = 0.
    put_prefix_int(&mut out, 0, 8, 0);
    put_prefix_int(&mut out, 0, 7, 0);
    for (name, value) in headers {
        // Literal Header Field Without Indexing — New Name (RFC 9204 §4.5.4):
        // `001 N H | NameLen(3+)`. The name-length prefix is 3 bits; with a
        // 4-bit prefix names >= 8 bytes shift the H flag into the length and
        // Hysteria2 auth headers (Hysteria-Auth etc.) become malformed.
        let mut line = Vec::new();
        put_string(&mut line, name, 3, 0x20);
        // Value: H bit + 7-bit prefix length, then raw bytes.
        put_string(&mut line, value, 7, 0x00);
        out.extend_from_slice(&line);
    }
    out
}

fn static_entry(index: u64) -> io::Result<&'static (&'static str, &'static str)> {
    QPACK_STATIC
        .get(index as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "qpack: static index out of range"))
}

pub fn decode_header_block(data: &[u8]) -> io::Result<Vec<(String, String)>> {
    let mut pos = 0;
    let (ric, used) = parse_prefix_int(&data[pos..], 8)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "qpack: bad RIC"))?;
    pos += used;
    if ric != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "qpack: dynamic table not supported"));
    }
    let (_, used) = parse_prefix_int(&data[pos..], 7)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "qpack: bad base"))?;
    pos += used;
    let mut headers = Vec::new();
    while pos < data.len() {
        let byte = data[pos];
        match byte {
            // Indexed Header Field: 1Txxxxxx
            0x80..=0xff => {
                if byte & 0x40 == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "qpack: dynamic index"));
                }
                let (index, used) = parse_prefix_int(&data[pos..], 6)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "qpack: bad index"))?;
                pos += used;
                let (name, value) = static_entry(index)?;
                headers.push((name.to_string(), value.to_string()));
            }
            // Literal With Name Reference, Without Indexing: 010NTxxx
            0x40..=0x7f => {
                if byte & 0x10 == 0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "qpack: dynamic name ref"));
                }
                let (index, used) = parse_prefix_int(&data[pos..], 4)
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "qpack: bad name index"))?;
                pos += used;
                let (name, _) = static_entry(index)?;
                let (value, used) = parse_string(&data[pos..], 7)?;
                pos += used;
                headers.push((name.to_string(), String::from_utf8_lossy(&value).into_owned()));
            }
            // Literal Without Indexing, New Name: 001 N H | NameLen(3+).
            // The name uses a 3-bit length prefix (RFC 9204 §4.5.4); the H
            // flag is bit 3, which parse_string reads with prefix_bits=3.
            0x20..=0x3f => {
                let (name, used) = parse_string(&data[pos..], 3)?;
                pos += used;
                let (value, used) = parse_string(&data[pos..], 7)?;
                pos += used;
                headers.push((
                    String::from_utf8_lossy(&name).into_owned(),
                    String::from_utf8_lossy(&value).into_owned(),
                ));
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("qpack: unsupported field line {:#x}", byte),
                ));
            }
        }
    }
    Ok(headers)
}

// ---------------------------------------------------------------------
// HTTP/3 framing

pub async fn read_varint<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<u64> {
    let mut first = [0u8; 1];
    reader.read_exact(&mut first).await?;
    let len = 1usize << (first[0] >> 6);
    let mut rest = vec![0u8; len - 1];
    if len > 1 {
        reader.read_exact(&mut rest).await?;
    }
    let mut buf = vec![first[0]];
    buf.extend_from_slice(&rest);
    parse_varint(&buf)
        .map(|(value, _)| value)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "bad varint"))
}

/// A minimal HTTP/3 client session over an established QUIC connection.
pub struct H3Session {
    conn: quinn::Connection,
    _control: quinn::SendStream,
    _qpack_encoder: quinn::SendStream,
    _qpack_decoder: quinn::SendStream,
}

impl H3Session {
    pub async fn new(conn: quinn::Connection) -> io::Result<Self> {
        // Control stream: type 0x00 + SETTINGS frame.
        let mut control = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 control stream: {}", e)))?;
        let mut settings = Vec::new();
        put_varint(&mut settings, 0x04); // frame type SETTINGS
        let mut payload = Vec::new();
        put_varint(&mut payload, 0x01); // QPACK_MAX_TABLE_CAPACITY
        put_varint(&mut payload, 0);
        put_varint(&mut payload, 0x33); // H3_DATAGRAM
        put_varint(&mut payload, 1);
        put_varint(&mut settings, payload.len() as u64);
        settings.extend_from_slice(&payload);
        let mut head = Vec::new();
        put_varint(&mut head, 0x00); // control stream type
        head.extend_from_slice(&settings);
        control
            .write_all(&head)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 settings: {}", e)))?;

        // QPACK encoder/decoder streams: just the type byte, kept open.
        let mut encoder = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 qpack encoder: {}", e)))?;
        encoder.write_all(&[0x02]).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let mut decoder = conn
            .open_uni()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 qpack decoder: {}", e)))?;
        decoder.write_all(&[0x03]).await.map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Drain incoming unidirectional streams (server control stream).
        let drain_conn = conn.clone();
        tokio::spawn(async move {
            while let Ok(mut stream) = drain_conn.accept_uni().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(Some(_)) => {}
                            _ => break,
                        }
                    }
                });
            }
        });

        Ok(H3Session { conn, _control: control, _qpack_encoder: encoder, _qpack_decoder: decoder })
    }

    /// POST with the given headers and no body; returns the response
    /// status code and headers.
    pub async fn post(
        &self,
        authority: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> io::Result<(u16, Vec<(String, String)>)> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 request stream: {}", e)))?;
        let mut fields = vec![
            (":method".to_string(), "POST".to_string()),
            (":scheme".to_string(), "https".to_string()),
            (":path".to_string(), path.to_string()),
            (":authority".to_string(), authority.to_string()),
        ];
        fields.extend(headers.iter().cloned());
        let block = encode_header_block(&fields);
        let mut frame = Vec::new();
        put_varint(&mut frame, 0x01); // HEADERS
        put_varint(&mut frame, block.len() as u64);
        frame.extend_from_slice(&block);
        send.write_all(&frame)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 write headers: {}", e)))?;
        send.finish()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h3 finish: {}", e)))?;

        loop {
            let frame_type = read_varint(&mut recv).await?;
            let frame_len = read_varint(&mut recv).await? as usize;
            if frame_len > 1_000_000 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "h3: frame too large"));
            }
            let mut payload = vec![0u8; frame_len];
            // Fully qualified: quinn's inherent read_exact shadows the
            // tokio trait method and returns a different error type.
            tokio::io::AsyncReadExt::read_exact(&mut recv, &mut payload).await?;
            if frame_type == 0x01 {
                let decoded = decode_header_block(&payload)?;
                let status = decoded
                    .iter()
                    .find(|(name, _)| name == ":status")
                    .and_then(|(_, value)| value.parse::<u16>().ok())
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "h3: no :status"))?;
                return Ok((status, decoded));
            }
            // DATA and other frames before HEADERS are not expected;
            // skip them and keep reading.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_round_trip() {
        for value in [0u64, 63, 64, 16383, 16384, 1073741823, 1073741824, 1 << 40] {
            let mut out = Vec::new();
            put_varint(&mut out, value);
            let (parsed, used) = parse_varint(&out).unwrap();
            assert_eq!(parsed, value);
            assert_eq!(used, out.len());
        }
    }

    #[test]
    fn header_block_round_trip() {
        let headers = vec![
            (":method".to_string(), "POST".to_string()),
            (":path".to_string(), "/auth".to_string()),
            ("hysteria-auth".to_string(), "secret".to_string()),
        ];
        let block = encode_header_block(&headers);
        let decoded = decode_header_block(&block).unwrap();
        assert_eq!(decoded, headers);
    }

    #[test]
    fn decode_indexed_and_name_ref() {
        // RIC=0, base=0, then an indexed field (:status 200, index 25)
        // and a literal name-ref to :status (index 24) with value 233.
        let mut block = vec![0x00, 0x00];
        block.push(0xc0 | 25);
        // Literal name ref without indexing, static: 0101xxxx, index 24
        block.push(0x50 | 8); // prefix int: 24 = 15 + 9 -> first byte 0x5f? compute below instead
        block.truncate(3);
        block.push(0x5f);
        block.push(9);
        // value "233": raw string, len 3
        block.push(0x03);
        block.extend_from_slice(b"233");
        let decoded = decode_header_block(&block).unwrap();
        assert_eq!(decoded[0], (":status".to_string(), "200".to_string()));
        assert_eq!(decoded[1], (":status".to_string(), "233".to_string()));
    }
}
