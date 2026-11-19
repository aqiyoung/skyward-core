//! WebSocket client transport (RFC 6455) for `network: ws` outbounds.
//!
//! mihomo carries VLESS/VMess streams over WebSocket for a large share of
//! real-world nodes (most CDN-fronted VLESS+WS+TLS setups). The handshake is
//! a plain HTTP/1.1 Upgrade over the already-connected (and possibly
//! TLS-wrapped) stream; after it, the byte stream is framed as binary
//! messages. This wrapper presents the framed connection as a plain
//! `AsyncRead + AsyncWrite` stream, so the protocol layers above it neither
//! know nor care that WebSocket is involved.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Perform the client handshake over `inner` and return the framed stream.
/// `host` is sent as the `Host` header; `path` is the request path (a leading
/// `/` is added when missing). Extra `headers` from `ws-opts` are sent as-is.
pub async fn connect_ws<S>(
    mut inner: S,
    host: &str,
    path: &str,
    headers: &[(String, String)],
) -> io::Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut key_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
    let key = BASE64.encode(key_bytes);
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    };
    let mut request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\n",
        path, host, key
    );
    for (name, value) in headers {
        // Host is already written from the dedicated argument.
        if name.eq_ignore_ascii_case("host") {
            continue;
        }
        request.push_str(&format!("{}: {}\r\n", name, value));
    }
    request.push_str("\r\n");
    tokio::io::AsyncWriteExt::write_all(&mut inner, request.as_bytes()).await?;

    // Read the response headers one byte at a time so no frame bytes that
    // arrived in the same packet are swallowed.
    let mut response = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        if response.len() > 16 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "ws: handshake response too large"));
        }
        let n = inner.read(&mut byte).await?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ws: handshake closed"));
        }
        response.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&response);
    let status_line = text.lines().next().unwrap_or("");
    if !status_line.contains(" 101") {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("ws: handshake rejected: {}", status_line.trim()),
        ));
    }
    Ok(WsStream::new(inner))
}

const OP_CONT: u8 = 0;
const OP_BINARY: u8 = 2;
const OP_CLOSE: u8 = 8;
const OP_PING: u8 = 9;
const OP_PONG: u8 = 10;

/// A WebSocket connection exposed as a byte stream.
pub struct WsStream<S> {
    inner: S,
    /// Raw bytes read from the wire but not yet parsed into frames.
    raw: Vec<u8>,
    /// Payload of the message currently being reassembled (fragmentation).
    message: Vec<u8>,
    /// Decoded payload ready to hand to the reader.
    ready: VecDeque<u8>,
    /// A client frame built but not yet fully written.
    pending_write: Option<Vec<u8>>,
    closed: bool,
}

impl<S> WsStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            raw: Vec::new(),
            message: Vec::new(),
            ready: VecDeque::new(),
            pending_write: None,
            closed: false,
        }
    }

    /// Push the stashed frame out. Ready(Ok) only when it is fully written.
    fn flush_pending(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let Some(mut frame) = self.pending_write.take() else {
            return Poll::Ready(Ok(()));
        };
        while !frame.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &frame) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ws: failed to write frame",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    frame.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.pending_write = Some(frame);
                    return Poll::Pending;
                }
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Try to decode one frame from `raw`. Returns the (fin, opcode, payload)
    /// and consumes it, or None when more bytes are needed.
    fn next_frame(&mut self) -> Option<(bool, u8, Vec<u8>)> {
        if self.raw.len() < 2 {
            return None;
        }
        let fin = self.raw[0] & 0x80 != 0;
        let opcode = self.raw[0] & 0x0f;
        let masked = self.raw[1] & 0x80 != 0;
        let mut len = (self.raw[1] & 0x7f) as u64;
        let mut pos = 2;
        if len == 126 {
            if self.raw.len() < pos + 2 {
                return None;
            }
            len = u16::from_be_bytes([self.raw[pos], self.raw[pos + 1]]) as u64;
            pos += 2;
        } else if len == 127 {
            if self.raw.len() < pos + 8 {
                return None;
            }
            len = u64::from_be_bytes(self.raw[pos..pos + 8].try_into().unwrap());
            pos += 8;
        }
        let mask = if masked {
            if self.raw.len() < pos + 4 {
                return None;
            }
            let m: [u8; 4] = self.raw[pos..pos + 4].try_into().unwrap();
            pos += 4;
            Some(m)
        } else {
            None
        };
        let len = len as usize;
        if self.raw.len() < pos + len {
            return None;
        }
        let mut payload: Vec<u8> = self.raw.drain(..pos + len).skip(pos).collect();
        if let Some(mask) = mask {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        Some((fin, opcode, payload))
    }

    fn build_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut mask = [0u8; 4];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut mask);
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | opcode);
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | len as u8);
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
        frame
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WsStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.ready.is_empty() {
                let n = self.ready.len().min(buf.remaining());
                let chunk: Vec<u8> = self.ready.drain(..n).collect();
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(()));
            }
            if let Some((fin, opcode, payload)) = self.next_frame() {
                match opcode {
                    OP_CONT | OP_BINARY | 1 => {
                        self.message.extend_from_slice(&payload);
                        if fin {
                            let message = std::mem::take(&mut self.message);
                            self.ready.extend(message);
                        }
                    }
                    OP_CLOSE => {
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    OP_PING => {
                        // Best-effort pong; a busy socket just drops it.
                        let frame = Self::build_frame(OP_PONG, &payload);
                        let mut pinned = Pin::new(&mut self.inner);
                        let _ = pinned.as_mut().poll_write(cx, &frame);
                    }
                    _ => {}
                }
                continue;
            }
            // Need more bytes from the wire.
            let mut chunk = [0u8; 8192];
            let mut read_buf = ReadBuf::new(&mut chunk);
            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let filled = read_buf.filled().len();
                    if filled == 0 {
                        self.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.raw.extend_from_slice(read_buf.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WsStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // A frame stashed by an earlier call must go out before newer data,
        // or the byte stream would reorder.
        if self.pending_write.is_some() {
            match self.as_mut().flush_pending(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // We take a copy of the payload into our own frame buffer, so the
        // caller's bytes count as consumed even if the wire write completes
        // on a later call; the stash keeps ordering intact.
        let mut frame = Self::build_frame(OP_BINARY, buf);
        while !frame.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &frame) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ws: failed to write frame",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    frame.drain(..n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.pending_write = Some(frame);
                    return Poll::Ready(Ok(buf.len()));
                }
            }
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_write.is_some() {
            match self.as_mut().flush_pending(cx) {
                Poll::Ready(Ok(())) => {}
                other => return other,
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_shutdown(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
        // Server frames are unmasked.
        let mut frame = vec![0x80 | opcode];
        if payload.len() < 126 {
            frame.push(payload.len() as u8);
        } else {
            frame.push(126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        }
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test]
    async fn reads_binary_frames_as_stream() {
        let (mut server, client) = tokio::io::duplex(4096);
        let mut ws = WsStream::new(client);
        server.write_all(&server_frame(OP_BINARY, b"hello ")).await.unwrap();
        server.write_all(&server_frame(OP_BINARY, b"world")).await.unwrap();
        let mut out = [0u8; 11];
        ws.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hello world");
    }

    #[tokio::test]
    async fn reassembles_fragmented_messages() {
        let (mut server, client) = tokio::io::duplex(4096);
        let mut ws = WsStream::new(client);
        let mut first = server_frame(OP_BINARY, b"frag");
        first[0] = OP_BINARY; // FIN cleared
        server.write_all(&first).await.unwrap();
        server.write_all(&server_frame(OP_CONT, b"mented")).await.unwrap();
        let mut out = [0u8; 10];
        ws.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"fragmented");
    }

    #[tokio::test]
    async fn writes_masked_binary_frames() {
        let (mut server, client) = tokio::io::duplex(4096);
        let mut ws = WsStream::new(client);
        ws.write_all(b"ping-payload").await.unwrap();
        let mut raw = [0u8; 64];
        let n = server.read(&mut raw).await.unwrap();
        let frame = &raw[..n];
        assert_eq!(frame[0], 0x82);
        assert!(frame[1] & 0x80 != 0, "client frames must be masked");
        let len = (frame[1] & 0x7f) as usize;
        assert_eq!(len, 12);
        let mask: [u8; 4] = frame[2..6].try_into().unwrap();
        let decoded: Vec<u8> = frame[6..6 + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        assert_eq!(decoded, b"ping-payload");
    }

    #[tokio::test]
    async fn handshake_upgrades_and_carries_data() {
        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let server = tokio::spawn(async move {
            // Read the upgrade request.
            let mut req = Vec::new();
            let mut byte = [0u8; 1];
            while !req.ends_with(b"\r\n\r\n") {
                server_io.read_exact(&mut byte).await.unwrap();
                req.push(byte[0]);
            }
            let text = String::from_utf8_lossy(&req).to_string();
            assert!(text.starts_with("GET /ws-path HTTP/1.1"));
            assert!(text.contains("Host: example.com"));
            server_io
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                .await
                .unwrap();
            server_io.write_all(&server_frame(OP_BINARY, b"hi")).await.unwrap();
            text
        });
        let mut ws = connect_ws(client_io, "example.com", "/ws-path", &[]).await.unwrap();
        let mut out = [0u8; 2];
        ws.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"hi");
        server.await.unwrap();
    }
}
