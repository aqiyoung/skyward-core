//! gRPC transport (Xray "gun" mode) for VLESS/VMess.
//!
//! The proxied byte stream is carried as protobuf `Hunk` messages inside a
//! single streaming HTTP/2 RPC: POST /<service>/Tun with content-type
//! application/grpc. Each gRPC message is [compressed-flag][u32be length]
//! [protobuf], and the protobuf Hunk is field 1 (bytes): tag 0x0A, varint
//! length, payload. Writes are framed the same way; the read side strips
//! both layers and yields the raw payload stream, so the VLESS/VMess
//! codecs above see an ordinary byte stream.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use hyper::body::HttpBody;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BoxedStream;

/// Largest payload carried by one Hunk; larger writes are split.
const MAX_HUNK: usize = 16384;

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
    None
}

/// Frame raw bytes as one or more gRPC Hunk messages.
pub(crate) fn frame_hunks(data: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(data.len() + 16);
    for chunk in data.chunks(MAX_HUNK) {
        let mut proto = Vec::with_capacity(chunk.len() + 5);
        proto.push(0x0a); // field 1, length-delimited
        encode_varint(chunk.len() as u64, &mut proto);
        proto.extend_from_slice(chunk);
        out.push(0); // uncompressed
        out.extend_from_slice(&(proto.len() as u32).to_be_bytes());
        out.extend_from_slice(&proto);
    }
    Bytes::from(out)
}

/// Extract Hunk payloads from one gRPC message body (the protobuf layer).
fn hunk_payloads(message: &[u8], out: &mut BytesMut) -> io::Result<()> {
    let mut rest = message;
    while !rest.is_empty() {
        let (tag, n) = decode_varint(rest)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "grpc: bad tag"))?;
        rest = &rest[n..];
        let field = tag >> 3;
        match tag & 0x07 {
            2 => {
                let (len, n) = decode_varint(rest).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "grpc: bad length")
                })?;
                rest = &rest[n..];
                let len = len as usize;
                if rest.len() < len {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "grpc: field overruns message",
                    ));
                }
                if field == 1 {
                    out.extend_from_slice(&rest[..len]);
                }
                rest = &rest[len..];
            }
            0 => {
                let (_, n) = decode_varint(rest).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "grpc: bad varint field")
                })?;
                rest = &rest[n..];
            }
            1 => {
                if rest.len() < 8 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "grpc: short 64-bit field"));
                }
                rest = &rest[8..];
            }
            5 => {
                if rest.len() < 4 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "grpc: short 32-bit field"));
                }
                rest = &rest[4..];
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "grpc: unsupported wire type",
                ))
            }
        }
    }
    Ok(())
}

/// Open the GunService/Tun RPC over an already-connected stream (TLS with
/// h2 ALPN when the node uses TLS, plain TCP for h2c) and return the byte
/// stream the proxy payload rides on.
pub async fn connect_grpc(
    stream: BoxedStream,
    authority: &str,
    service: &str,
) -> io::Result<GrpcStream> {
    let (mut sender, conn) = hyper::client::conn::Builder::new()
        .http2_only(true)
        .handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("grpc h2 handshake: {}", e)))?;
    // The connection driver must be polled for the life of the RPC.
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let (body_tx, body) = hyper::Body::channel();
    let service = if service.trim().is_empty() {
        "GunService"
    } else {
        service.trim()
    };
    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("https://{}/{}/Tun", authority, service))
        .header("content-type", "application/grpc")
        .header("user-agent", "grpc-go/1.48.0")
        .header("te", "trailers")
        .body(body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("grpc request: {}", e)))?;
    // The response head must NOT be awaited here: gRPC servers send it only
    // after the first request message arrives, and the caller writes that
    // message (the proxy header) only after connect() returns — awaiting
    // would deadlock. The send runs in a task and the body is picked up
    // lazily on first read, the same shape as the VLESS header handling.
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = sender.send_request(request).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("grpc send request: {}", e))
        });
        let result = match result {
            Ok(response) if response.status() == hyper::StatusCode::OK => {
                Ok(response.into_body())
            }
            Ok(response) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("grpc: HTTP status {}", response.status()),
            )),
            Err(e) => Err(e),
        };
        let _ = response_tx.send(result);
    });
    Ok(GrpcStream {
        body: None,
        body_rx: Some(response_rx),
        body_tx: Some(body_tx),
        write_fut: None,
        in_buf: BytesMut::new(),
        read_buf: BytesMut::new(),
        eof: false,
    })
}

type SendDataFut = Pin<
    Box<
        dyn Future<Output = (hyper::body::Sender, Result<(), hyper::Error>)> + Send,
    >,
>;

/// An in-flight body send plus the length of the caller's buffer it is
/// carrying. AsyncWrite callers retry with the same buffer until Ready,
/// so completion must report that buffer's length — and must never frame
/// the buffer a second time.

pub struct GrpcStream {
    body: Option<hyper::Body>,
    body_rx: Option<tokio::sync::oneshot::Receiver<io::Result<hyper::Body>>>,
    body_tx: Option<hyper::body::Sender>,
    write_fut: Option<(SendDataFut, usize)>,
    /// Received bytes not yet consumed as whole gRPC messages.
    in_buf: BytesMut,
    /// Hunk payloads ready to be read.
    read_buf: BytesMut,
    eof: bool,
}

impl GrpcStream {
    /// Move every complete gRPC message in `in_buf` into `read_buf`.
    /// Returns true when at least one payload byte was produced.
    fn parse_frames(&mut self) -> io::Result<bool> {
        let mut produced = false;
        loop {
            if self.in_buf.len() < 5 {
                return Ok(produced);
            }
            let flag = self.in_buf[0];
            let len = u32::from_be_bytes([
                self.in_buf[1],
                self.in_buf[2],
                self.in_buf[3],
                self.in_buf[4],
            ]) as usize;
            if self.in_buf.len() < 5 + len {
                return Ok(produced);
            }
            if flag != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "grpc: compressed frames are not supported",
                ));
            }
            let message = self.in_buf.split_to(5 + len);
            hunk_payloads(&message[5..], &mut self.read_buf)?;
            produced = true;
        }
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match self.parse_frames() {
                Ok(true) => continue,
                Ok(false) => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
            if self.body.is_none() {
                let rx = self.body_rx.as_mut().unwrap();
                match Pin::new(rx).poll(cx) {
                    Poll::Ready(Ok(Ok(body))) => {
                        self.body = Some(body);
                        self.body_rx = None;
                    }
                    Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(e)),
                    Poll::Ready(Err(_)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            "grpc: request task ended without a response",
                        )))
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            match Pin::new(self.body.as_mut().unwrap()).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    self.in_buf.extend_from_slice(&data);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("grpc recv: {}", e),
                    )));
                }
                Poll::Ready(None) => {
                    self.eof = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl GrpcStream {
    /// Drive an in-flight body send to completion; on success returns the
    /// length of the caller buffer that send was carrying.
    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if let Some((fut, len)) = self.write_fut.as_mut() {
            match fut.as_mut().poll(cx) {
                Poll::Ready((tx, Ok(()))) => {
                    let len = *len;
                    self.body_tx = Some(tx);
                    self.write_fut = None;
                    Poll::Ready(Ok(len))
                }
                Poll::Ready((_, Err(e))) => {
                    self.write_fut = None;
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("grpc send: {}", e),
                    )))
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(0))
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // A send started by an earlier poll_write carries that call's
        // buffer (the caller retries with the same one); completing it
        // completes THIS write — the buffer must not be framed again.
        if self.write_fut.is_some() {
            return self.poll_pending_write(cx);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut tx = match self.body_tx.take() {
            Some(tx) => tx,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "grpc: request body already closed",
                )))
            }
        };
        let framed = frame_hunks(buf);
        self.write_fut = Some((
            Box::pin(async move {
                let result = tx.send_data(framed).await;
                (tx, result)
            }),
            buf.len(),
        ));
        self.poll_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_pending_write(cx).map(|r| r.map(|_| ()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => {
                // Dropping the sender ends the request body (END_STREAM),
                // which half-closes the RPC the way servers expect.
                self.body_tx = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunk_framing_roundtrip() {
        let data: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
        let framed = frame_hunks(&data);
        // Walk the gRPC message layer back off.
        let mut in_buf = BytesMut::from(&framed[..]);
        let mut out = BytesMut::new();
        while in_buf.len() >= 5 {
            let len = u32::from_be_bytes([in_buf[1], in_buf[2], in_buf[3], in_buf[4]]) as usize;
            assert!(in_buf.len() >= 5 + len);
            let message = in_buf.split_to(5 + len);
            hunk_payloads(&message[5..], &mut out).unwrap();
        }
        assert_eq!(&out[..], &data[..]);
    }

    #[test]
    fn empty_and_small_payloads() {
        assert!(frame_hunks(&[]).is_empty());
        let framed = frame_hunks(b"hi");
        let mut out = BytesMut::new();
        hunk_payloads(&framed[5..], &mut out).unwrap();
        assert_eq!(&out[..], b"hi");
    }
}
