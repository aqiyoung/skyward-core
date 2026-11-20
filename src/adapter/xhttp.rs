//! XHTTP transport (packet-up mode) for VLESS/VMess.
//!
//! One session is two HTTP exchanges over two connections:
//!   download: GET  <path>/<session>           — a long response whose body
//!                                               is the downstream bytes
//!   upload:   POST <path>/<session>/<seq>     — one request per chunk of
//!                                               upstream bytes, in order
//! The proxy codec's header is simply the first bytes of the upload
//! stream, exactly like the other transports. stream-up/stream-one modes
//! are served by the same request shapes on xray servers (the server
//! distinguishes by URL), so packet-up covers `auto` nodes too.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use bytes::{Buf, Bytes, BytesMut};
use hyper::body::HttpBody;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::BoxedStream;

/// Upload queue high-water mark; poll_write stalls beyond this.
const MAX_QUEUED: usize = 256 * 1024;

#[derive(Default)]
struct UploadState {
    queue: VecDeque<Bytes>,
    queued_bytes: usize,
    in_flight: bool,
    closed: bool,
    error: Option<String>,
    waker: Option<Waker>,
}

struct UploadShared {
    state: Mutex<UploadState>,
    notify: tokio::sync::Notify,
}

impl UploadShared {
    fn wake(&self) {
        if let Some(waker) = self.state.lock().unwrap().waker.take() {
            waker.wake();
        }
    }
}

fn random_session() -> String {
    // Xray servers validate the session id as a UUID; a bare hex string
    // gets the download GET rejected with 400.
    let mut b = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut b);
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // variant 1
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13],
        b[14], b[15]
    )
}

/// Join a configured path and a suffix with exactly one slash.
fn join_path(path: &str, suffix: &str) -> String {
    let base = path.trim_end_matches('/');
    if base.is_empty() {
        format!("/{}", suffix)
    } else if base.starts_with('/') {
        format!("{}/{}", base, suffix)
    } else {
        format!("/{}/{}", base, suffix)
    }
}

async fn http1_sender(
    stream: BoxedStream,
) -> io::Result<hyper::client::conn::SendRequest<hyper::Body>> {
    let (sender, conn) = hyper::client::conn::Builder::new()
        .handshake(stream)
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("xhttp h1 handshake: {}", e)))?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    Ok(sender)
}

/// Open an XHTTP session. `dial` is called twice: once for the upload
/// connection, once for the download connection.
pub async fn connect_xhttp<F, Fut>(
    mut dial: F,
    host: &str,
    path: &str,
) -> io::Result<XHttpStream>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<BoxedStream>>,
{
    let session = random_session();
    let down_path = join_path(path, &session);
    // Xray servers reject requests whose x_padding is missing or outside
    // the configured length range (default 100-1000) with 400; carry it in
    // both the URL query and a Referer, like xray's own client does.
    let padding = "X".repeat(100 + (rand::random::<usize>() % 901));
    let query = format!("?x_padding={}", padding);
    let referer = format!("http://{}{}/{}", host, path.trim_end_matches('/'), query);

    // Download connection: the GET goes out first; its response head is
    // resolved lazily on first read (the server may not send it until the
    // first upload lands, and the caller writes only after connect()).
    let down_stream = dial().await?;
    let mut down_sender = http1_sender(down_stream).await?;
    let (body_tx, body_rx) = tokio::sync::oneshot::channel();
    let host_header = host.to_string();
    let down_uri = format!("{}{}", down_path, query);
    let down_referer = referer.clone();
    tokio::spawn(async move {
        let referer = down_referer;
        let request = hyper::Request::builder()
            .method(hyper::Method::GET)
            .uri(down_uri)
            .header("host", host_header)
            .header("referer", referer)
            .body(hyper::Body::empty());
        let result = match request {
            Ok(req) => down_sender
                .send_request(req)
                .await
                .map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("xhttp download: {}", e))
                })
                .and_then(|resp| {
                    if resp.status() == hyper::StatusCode::OK {
                        Ok(resp.into_body())
                    } else {
                        Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("xhttp download: HTTP {}", resp.status()),
                        ))
                    }
                }),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("xhttp download request: {}", e),
            )),
        };
        let _ = body_tx.send(result);
    });

    // Upload connection + pump task.
    let up_stream = dial().await?;
    let up_sender = http1_sender(up_stream).await?;
    let shared = Arc::new(UploadShared {
        state: Mutex::new(UploadState::default()),
        notify: tokio::sync::Notify::new(),
    });
    tokio::spawn(upload_pump(
        up_sender,
        shared.clone(),
        host.to_string(),
        down_path,
        query,
        referer,
    ));

    Ok(XHttpStream {
        body: None,
        body_rx: Some(body_rx),
        read_buf: BytesMut::new(),
        eof: false,
        upload: shared,
    })
}

async fn upload_pump(
    mut sender: hyper::client::conn::SendRequest<hyper::Body>,
    shared: Arc<UploadShared>,
    host: String,
    base_path: String,
    query: String,
    referer: String,
) {
    let mut seq: u64 = 0;
    loop {
        let chunk = {
            let mut state = shared.state.lock().unwrap();
            if let Some(chunk) = state.queue.pop_front() {
                state.queued_bytes -= chunk.len();
                state.in_flight = true;
                Some(chunk)
            } else if state.closed {
                return;
            } else {
                None
            }
        };
        let chunk = match chunk {
            Some(chunk) => chunk,
            None => {
                shared.notify.notified().await;
                continue;
            }
        };
        let uri = format!("{}/{}{}", base_path, seq, query);
        seq += 1;
        let request = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(uri)
            .header("host", &host)
            .header("referer", &referer)
            .header("content-type", "application/octet-stream")
            .body(hyper::Body::from(chunk));
        let outcome = match request {
            Ok(req) => sender.send_request(req).await,
            Err(e) => {
                fail_upload(&shared, format!("xhttp upload request: {}", e));
                return;
            }
        };
        match outcome {
            Ok(mut resp) => {
                if resp.status() != hyper::StatusCode::OK {
                    fail_upload(&shared, format!("xhttp upload: HTTP {}", resp.status()));
                    return;
                }
                // Drain the (normally empty) response body so the
                // connection can be reused for the next POST.
                while let Some(item) = resp.body_mut().data().await {
                    if item.is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                fail_upload(&shared, format!("xhttp upload: {}", e));
                return;
            }
        }
        {
            let mut state = shared.state.lock().unwrap();
            state.in_flight = false;
        }
        shared.wake();
    }
}

fn fail_upload(shared: &Arc<UploadShared>, message: String) {
    {
        let mut state = shared.state.lock().unwrap();
        state.error = Some(message);
        state.in_flight = false;
    }
    shared.wake();
}

pub struct XHttpStream {
    body: Option<hyper::Body>,
    body_rx: Option<tokio::sync::oneshot::Receiver<io::Result<hyper::Body>>>,
    read_buf: BytesMut,
    eof: bool,
    upload: Arc<UploadShared>,
}

impl AsyncRead for XHttpStream {
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
                            "xhttp: download task ended without a response",
                        )))
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            match Pin::new(self.body.as_mut().unwrap()).poll_data(cx) {
                Poll::Ready(Some(Ok(data))) => {
                    self.read_buf.extend_from_slice(&data);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::Other,
                        format!("xhttp download recv: {}", e),
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

impl AsyncWrite for XHttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut state = self.upload.state.lock().unwrap();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, error.clone())));
        }
        if state.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp: upload already shut down",
            )));
        }
        if state.queued_bytes + buf.len() > MAX_QUEUED {
            state.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        state.queue.push_back(Bytes::copy_from_slice(buf));
        state.queued_bytes += buf.len();
        drop(state);
        self.upload.notify.notify_one();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self.upload.state.lock().unwrap();
        if let Some(error) = &state.error {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, error.clone())));
        }
        if state.queue.is_empty() && !state.in_flight {
            Poll::Ready(Ok(()))
        } else {
            state.waker = Some(cx.waker().clone());
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        {
            let mut state = self.upload.state.lock().unwrap();
            state.closed = true;
        }
        self.upload.notify.notify_one();
        self.poll_flush(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_joining() {
        assert_eq!(join_path("/", "abc"), "/abc");
        assert_eq!(join_path("", "abc"), "/abc");
        assert_eq!(join_path("/xhttp", "abc"), "/xhttp/abc");
        assert_eq!(join_path("/xhttp/", "abc"), "/xhttp/abc");
        assert_eq!(join_path("xhttp", "abc"), "/xhttp/abc");
    }
}
