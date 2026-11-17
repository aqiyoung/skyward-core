//! Minimal RFC 6455 WebSocket server for the `/traffic` stream. Only the
//! server-side handshake and unmasked text frames are needed.

use std::io;

use base64::Engine;
use hyper::upgrade::Upgraded;
use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub struct Websocket {
    inner: Upgraded,
}

impl Websocket {
    /// Perform the upgrade handshake if the request carries a valid key.
    pub fn accept(key: &str) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(WS_GUID);
        let accept = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            accept
        ).into_bytes()
    }

    pub fn new(inner: Upgraded) -> Self {
        Self { inner }
    }

    /// Send one unmasked text frame.
    pub async fn send_text(&mut self, text: &str) -> io::Result<()> {
        let payload = text.as_bytes();
        let mut header = vec![0x81]; // FIN + text opcode
        let len = payload.len();
        if len < 126 {
            header.push(len as u8);
        } else if len <= 0xffff {
            header.push(126);
            header.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            header.push(127);
            header.extend_from_slice(&(len as u64).to_be_bytes());
        }
        self.inner.write_all(&header).await?;
        self.inner.write_all(payload).await?;
        self.inner.flush().await
    }

    /// Read a client frame, detecting a close frame. Client frames are masked.
    pub async fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut head = [0u8; 2];
        self.inner.read_exact(&mut head).await?;
        let opcode = head[0] & 0x0f;
        let mut len = (head[1] & 0x7f) as u64;
        if len == 126 {
            let mut buf = [0u8; 2];
            self.inner.read_exact(&mut buf).await?;
            len = u16::from_be_bytes(buf) as u64;
        } else if len == 127 {
            let mut buf = [0u8; 8];
            self.inner.read_exact(&mut buf).await?;
            len = u64::from_be_bytes(buf);
        }
        if opcode == 0x8 {
            return Ok(None);
        }
        let masked = head[1] & 0x80 != 0;
        let mut mask = [0u8; 4];
        if masked {
            self.inner.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; len as usize];
        self.inner.read_exact(&mut payload).await?;
        if masked {
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
        }
        Ok(Some(payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accept_key_matches_rfc_example() {
        // RFC 6455 §1.3 example: key "dGhlIHNhbXBsZSBub25jZQ==" ->
        // "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        let response = String::from_utf8(Websocket::accept("dGhlIHNhbXBsZSBub25jZQ==")).unwrap();
        assert!(response.contains("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="));
    }
}
