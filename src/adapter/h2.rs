//! Plain HTTP/2 transport (`network: h2`) for VLESS/VMess.
//!
//! One bidirectional HTTP/2 stream carries the proxy payload as raw
//! DATA frames: POST to the configured path, no extra framing (unlike
//! gRPC mode). The response head is picked up lazily on first read for
//! the same reason as in the gRPC transport: servers answer only after
//! the first request bytes arrive.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use hyper::body::HttpBody;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BoxedStream;

pub async fn connect_h2(
    stream: BoxedStream,
    authority: &str,
    path: &str,
) -> io::Result<H2Stream> {
    let (mut sender, conn) = hyper::client::conn::Builder::new()
        .http2_only(true)
        .handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("h2 handshake: {}", e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let (body_tx, body) = hyper::Body::channel();
    let path = if path.trim().is_empty() { "/" } else { path.trim() };
    let request = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(format!("https://{}{}", authority, path))
        .header("content-type", "application/octet-stream")
        .body(body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("h2 request: {}", e)))?;
    let (response_tx, response_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let result = sender.send_request(request).await.map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("h2 send request: {}", e))
        });
        let result = match result {
            Ok(response) if response.status() == hyper::StatusCode::OK => Ok(response.into_body()),
            Ok(response) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("h2: HTTP status {}", response.status()),
            )),
            Err(e) => Err(e),
        };
        let _ = response_tx.send(result);
    });
    Ok(H2Stream {
        body: None,
        body_rx: Some(response_rx),
        body_tx: Some(body_tx),
        write_fut: None,
        read_buf: BytesMut::new(),
        eof: false,
    })
}

type SendDataFut = Pin<Box<dyn Future<Output = (hyper::body::Sender, Result<(), hyper::Error>)> + Send>>;

pub struct H2Stream {
    body: Option<hyper::Body>,
    body_rx: Option<tokio::sync::oneshot::Receiver<io::Result<hyper::Body>>>,
    body_tx: Option<hyper::body::Sender>,
    write_fut: Option<(SendDataFut, usize)>,
    read_buf: BytesMut,
    eof: bool,
}

impl AsyncRead for H2Stream {
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
            if self.body.is_none() {
                if let Some(mut rx) = self.body_rx.take() {
                    match Pin::new(&mut rx).poll(cx) {
                        Poll::Ready(Ok(Ok(body))) => self.body = Some(body),
                        Poll::Ready(Ok(Err(e))) => return Poll::Ready(Err(e)),
                        Poll::Ready(Err(_)) => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "h2: response task dropped",
                            )))
                        }
                        Poll::Pending => {
                            self.body_rx = Some(rx);
                            return Poll::Pending;
                        }
                    }
                } else {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
            }
            let body = self.body.as_mut().expect("body set above");
            match Pin::new(body).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    self.read_buf.extend_from_slice(&chunk);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("h2 read: {}", e),
                    )))
                }
                Poll::Ready(None) => {
                    self.eof = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl H2Stream {
    /// Poll the stored in-flight send to completion (same contract as
    /// the gRPC transport: the stored buffer length is the result).
    fn poll_pending_write(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let (mut fut, len) = self.write_fut.take().expect("pending write present");
        match fut.as_mut().poll(cx) {
            Poll::Ready((sender, Ok(()))) => {
                self.body_tx = Some(sender);
                Poll::Ready(Ok(len))
            }
            Poll::Ready((_, Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("h2 write: {}", e),
            ))),
            Poll::Pending => {
                self.write_fut = Some((fut, len));
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_some() {
            return self.poll_pending_write(cx);
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut sender = match self.body_tx.take() {
            Some(sender) => sender,
            None => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "h2: write side closed",
                )))
            }
        };
        let data = Bytes::copy_from_slice(buf);
        let len = buf.len();
        self.write_fut = Some((
            Box::pin(async move {
                let result = sender.send_data(data).await;
                (sender, result)
            }),
            len,
        ));
        self.poll_pending_write(cx)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Drive an in-flight write; the previous no-op dropped the last chunk.
        self.poll_pending_write(cx).map(|r| r.map(|_| ()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_pending_write(cx) {
            Poll::Ready(Ok(_)) => {
                self.body_tx = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}
