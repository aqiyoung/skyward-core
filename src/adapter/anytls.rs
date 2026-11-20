//! AnyTLS outbound (sing-box / anytls-go protocol, version 2).
//!
//! One TLS connection carries a multiplexed session of framed streams:
//! frame = [cmd u8][stream id u32 BE][length u16 BE][data]. The client
//! prologue is sha256(password) || u16 padding length || zero padding
//! in a single write (servers authenticate from the first read), then
//! a Settings frame (v=2, padding scheme md5). Each stream opens with
//! SYN, carries the target as a socks-format address in its first data
//! frame, then PSH data frames; FIN closes. The first records are
//! shaped with cmdWaste padding per the negotiated padding scheme —
//! cosmetic anti-fingerprinting the reference client performs; the
//! framing itself does not depend on it.
//!
//! This implementation opens one session per connection (stream id 1
//! only) instead of pooling idle sessions like the reference client;
//! that is protocol-legal and keeps the lifecycle simple.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use md5::Digest as _;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{Mutex, Notify};

use super::packet::PacketConn;
use super::tls::connect_tls_http1;
use super::{BoxedStream, Outbound};
use crate::common::TargetAddr;

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const HEADER_LEN: usize = 7;
const MAX_FRAME_DATA: usize = 16384;

const DEFAULT_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

fn frame(cmd: u8, sid: u32, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + data.len());
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// The padding scheme: for each of the first `stop` records, a list of
/// target payload sizes; -1 is the check mark ("only continue padding
/// if payload remains").
#[derive(Clone)]
struct PaddingScheme {
    stop: u32,
    records: HashMap<u32, Vec<i64>>,
    raw: String,
    md5_hex: String,
}

impl PaddingScheme {
    fn parse(raw: &str) -> Option<Self> {
        let mut stop = None;
        let mut records = HashMap::new();
        for line in raw.lines() {
            let (key, value) = line.split_once('=')?;
            if key == "stop" {
                stop = Some(value.parse().ok()?);
                continue;
            }
            if let Ok(pkt) = key.parse::<u32>() {
                let mut sizes = Vec::new();
                for token in value.split(',') {
                    if token == "c" {
                        sizes.push(-1);
                    } else if let Some((lo, hi)) = token.split_once('-') {
                        let lo: i64 = lo.parse().ok()?;
                        let hi: i64 = hi.parse().ok()?;
                        sizes.push(if lo >= 0 && hi >= lo {
                            lo + (rand::random::<u64>() % ((hi - lo + 1) as u64)) as i64
                        } else {
                            lo
                        });
                    }
                }
                records.insert(pkt, sizes);
            }
        }
        Some(PaddingScheme {
            stop: stop?,
            records,
            raw: raw.to_string(),
            md5_hex: format!("{:x}", md5::Md5::digest(raw.as_bytes())),
        })
    }

    fn sizes_for(&self, pkt: u32) -> &[i64] {
        self.records.get(&pkt).map(Vec::as_slice).unwrap_or(&[])
    }
}

impl Default for PaddingScheme {
    fn default() -> Self {
        PaddingScheme::parse(DEFAULT_SCHEME).expect("default scheme parses")
    }
}

/// The write half of a session, with record shaping for the first
/// packets (mirrors anytls-go's writeConn).
struct SessionWriter {
    inner: tokio::io::WriteHalf<BoxedStream>,
    scheme: Arc<StdMutex<PaddingScheme>>,
    pkt: u32,
}

impl SessionWriter {
    /// Write one logical chunk, applying the padding scheme while the
    /// packet counter is below the scheme's stop value.
    async fn write_shaped(&mut self, mut data: &[u8]) -> io::Result<()> {
        let scheme = self.scheme.lock().unwrap().clone();
        if self.pkt >= scheme.stop {
            return self.inner.write_all(data).await;
        }
        let sizes = scheme.sizes_for(self.pkt).to_vec();
        self.pkt += 1;
        if sizes.is_empty() {
            return self.inner.write_all(data).await;
        }
        for &target in &sizes {
            if target < 0 {
                // Check mark: stop padding when nothing remains.
                if data.is_empty() {
                    return Ok(());
                }
                continue;
            }
            let target = target as usize;
            if data.len() > target {
                self.inner.write_all(&data[..target]).await?;
                data = &data[target..];
            } else if !data.is_empty() {
                let padding_len = target as i64 - data.len() as i64 - HEADER_LEN as i64;
                if padding_len > 0 {
                    let mut out = Vec::with_capacity(target);
                    out.extend_from_slice(data);
                    out.extend_from_slice(&frame(CMD_WASTE, 0, &vec![0u8; padding_len as usize]));
                    self.inner.write_all(&out).await?;
                } else {
                    self.inner.write_all(data).await?;
                }
                return Ok(());
            } else {
                let waste = frame(CMD_WASTE, 0, &vec![0u8; target]);
                self.inner.write_all(&waste).await?;
            }
        }
        if !data.is_empty() {
            self.inner.write_all(data).await?;
        }
        Ok(())
    }

    async fn write_frame(&mut self, cmd: u8, sid: u32, data: &[u8]) -> io::Result<()> {
        self.write_shaped(&frame(cmd, sid, data)).await
    }
}

#[derive(Default)]
struct StreamState {
    queue: StdMutex<(std::collections::VecDeque<Bytes>, bool, Option<String>)>,
    notify: Notify,
}

impl StreamState {
    fn push(&self, data: Bytes) {
        self.queue.lock().unwrap().0.push_back(data);
        self.notify.notify_waiters();
    }
    fn close(&self, error: Option<String>) {
        let mut q = self.queue.lock().unwrap();
        q.1 = true;
        if error.is_some() {
            q.2 = error;
        }
        self.notify.notify_waiters();
    }
}

struct Session {
    writer: Mutex<SessionWriter>,
    streams: StdMutex<HashMap<u32, Arc<StreamState>>>,
}

impl Session {
    fn stream_state(&self, sid: u32) -> Option<Arc<StreamState>> {
        self.streams.lock().unwrap().get(&sid).cloned()
    }
}

async fn recv_loop(
    mut read_half: tokio::io::ReadHalf<BoxedStream>,
    session: Arc<Session>,
    scheme: Arc<StdMutex<PaddingScheme>>,
) {
    let mut header = [0u8; HEADER_LEN];
    loop {
        if read_half.read_exact(&mut header).await.is_err() {
            break;
        }
        let cmd = header[0];
        let sid = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0u8; len];
        if len > 0 && read_half.read_exact(&mut data).await.is_err() {
            break;
        }
        match cmd {
            CMD_PSH => {
                if let Some(state) = session.stream_state(sid) {
                    state.push(Bytes::from(data));
                }
            }
            CMD_FIN => {
                if let Some(state) = session.stream_state(sid) {
                    state.close(None);
                }
            }
            CMD_SYNACK => {
                if !data.is_empty() {
                    if let Some(state) = session.stream_state(sid) {
                        state.close(Some(String::from_utf8_lossy(&data).into_owned()));
                    }
                }
            }
            CMD_ALERT => {
                let message = String::from_utf8_lossy(&data).into_owned();
                for state in session.streams.lock().unwrap().values() {
                    state.close(Some(format!("server alert: {}", message)));
                }
                break;
            }
            CMD_UPDATE_PADDING => {
                if let Some(parsed) = PaddingScheme::parse(&String::from_utf8_lossy(&data)) {
                    *scheme.lock().unwrap() = parsed;
                }
            }
            CMD_HEART_REQUEST => {
                let session = session.clone();
                tokio::spawn(async move {
                    let _ = session.writer.lock().await.write_frame(CMD_HEART_RESPONSE, sid, &[]).await;
                });
            }
            CMD_SETTINGS | CMD_SERVER_SETTINGS | CMD_WASTE | CMD_HEART_RESPONSE => {}
            _ => {}
        }
    }
    for state in session.streams.lock().unwrap().values() {
        state.close(None);
    }
}

pub struct AnytlsOutbound {
    name: String,
    server: TargetAddr,
    password_hash: [u8; 32],
    sni: String,
    verify: bool,
}

impl AnytlsOutbound {
    pub fn try_new(
        name: &str,
        server: &str,
        port: u16,
        password: &str,
        sni: Option<&str>,
        verify: bool,
    ) -> Option<Self> {
        let server = match server.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, port),
            Err(_) => TargetAddr::Domain(server.to_string(), port),
        };
        let sni = sni
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| server.host());
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        Some(AnytlsOutbound {
            name: name.to_string(),
            server,
            password_hash: hasher.finalize().into(),
            sni,
            verify,
        })
    }
}

#[async_trait]
impl Outbound for AnytlsOutbound {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &str {
        "AnyTLS"
    }

    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut last_error = None;
        let mut connected = None;
        for addr in self.server.resolve_all().await? {
            match crate::net::connect_tcp(addr).await {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(e) => last_error = Some(e),
            }
        }
        let tcp = connected.ok_or_else(|| {
            last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no server address"))
        })?;
        let tls = connect_tls_http1(&self.sni, tcp, self.verify).await?;

        let scheme = Arc::new(StdMutex::new(PaddingScheme::default()));
        // Prologue (one raw write, before the session starts):
        // sha256(password) || u16 handshake-padding length || zeros.
        // The length comes from record 0 of the padding scheme. The
        // server reads the hash from its first read and then skips the
        // padding, so this must arrive as one write of >= 32 bytes.
        let handshake_padding = scheme
            .lock()
            .unwrap()
            .sizes_for(0)
            .first()
            .copied()
            .unwrap_or(0)
            .max(0) as u16;
        let mut prologue = Vec::with_capacity(32 + 2 + handshake_padding as usize);
        prologue.extend_from_slice(&self.password_hash);
        prologue.extend_from_slice(&handshake_padding.to_be_bytes());
        prologue.extend(std::iter::repeat(0u8).take(handshake_padding as usize));

        let settings = format!(
            "v=2\nclient=skyward-core\npadding-md5={}",
            scheme.lock().unwrap().md5_hex
        );
        // Settings + SYN + the stream's address frame go out as one
        // shaped write, like the reference client's buffering (the
        // address write flushes the buffered control frames). Record
        // shaping counts from packet 1; packet 0 was the prologue.
        let mut opening = Vec::new();
        opening.extend_from_slice(&frame(CMD_SETTINGS, 0, settings.as_bytes()));
        opening.extend_from_slice(&frame(CMD_SYN, 1, &[]));
        let address = super::trojan::encode_socks_target(target);
        opening.extend_from_slice(&frame(CMD_PSH, 1, &address));

        let (read_half, mut write_half) = tokio::io::split(tls);
        write_half.write_all(&prologue).await?;
        let session = Arc::new(Session {
            writer: Mutex::new(SessionWriter {
                inner: write_half,
                scheme: scheme.clone(),
                pkt: 1,
            }),
            streams: StdMutex::new(HashMap::new()),
        });
        let state = Arc::new(StreamState::default());
        session.streams.lock().unwrap().insert(1, state.clone());
        tokio::spawn(recv_loop(read_half, session.clone(), scheme));

        {
            let mut writer = session.writer.lock().await;
            writer.write_shaped(&opening).await?;
        }

        Ok(Box::new(AnytlsStream {
            session,
            state,
            sid: 1,
            read_buf: BytesMut::new(),
            write_fut: None,
            fin_sent: false,
        }))
    }

    async fn connect_udp(&self, _target: &TargetAddr) -> io::Result<Box<dyn PacketConn>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "anytls: UDP relay not supported",
        ))
    }
}

type WriteFut = Pin<Box<dyn Future<Output = io::Result<usize>> + Send>>;

pub struct AnytlsStream {
    session: Arc<Session>,
    state: Arc<StreamState>,
    sid: u32,
    read_buf: BytesMut,
    write_fut: Option<WriteFut>,
    fin_sent: bool,
}

impl AsyncRead for AnytlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let state = self.state.clone();
        loop {
            if !self.read_buf.is_empty() {
                let n = self.read_buf.len().min(buf.remaining());
                buf.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            let notified = state.notify.notified();
            tokio::pin!(notified);
            // Register the waker before checking the queue.
            if notified.as_mut().poll(cx).is_pending() {
                let mut queue = state.queue.lock().unwrap();
                if let Some(chunk) = queue.0.pop_front() {
                    self.read_buf.extend_from_slice(&chunk);
                    continue;
                }
                if queue.1 {
                    if let Some(error) = &queue.2 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("anytls: {}", error),
                        )));
                    }
                    return Poll::Ready(Ok(()));
                }
                return Poll::Pending;
            }
        }
    }
}

impl AsyncWrite for AnytlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_fut.is_none() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            {
                let queue = self.state.queue.lock().unwrap();
                if queue.1 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "anytls: stream closed",
                    )));
                }
            }
            let chunk_len = buf.len().min(MAX_FRAME_DATA);
            let data = Bytes::copy_from_slice(&buf[..chunk_len]);
            let session = self.session.clone();
            let sid = self.sid;
            self.write_fut = Some(Box::pin(async move {
                let mut writer = session.writer.lock().await;
                writer.write_frame(CMD_PSH, sid, &data).await?;
                Ok(data.len())
            }));
        }
        let fut = self.write_fut.as_mut().expect("write future set");
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.write_fut = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(fut) = self.write_fut.as_mut() {
            return match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(_)) => {
                    self.write_fut = None;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => {
                    self.write_fut = None;
                    Poll::Ready(Err(e))
                }
                Poll::Pending => Poll::Pending,
            };
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.fin_sent {
            self.fin_sent = true;
            let session = self.session.clone();
            let sid = self.sid;
            tokio::spawn(async move {
                let _ = session.writer.lock().await.write_frame(CMD_FIN, sid, &[]).await;
            });
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for AnytlsStream {
    fn drop(&mut self) {
        if !self.fin_sent {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                let session = self.session.clone();
                let sid = self.sid;
                handle.spawn(async move {
                    let _ = session.writer.lock().await.write_frame(CMD_FIN, sid, &[]).await;
                });
            }
        }
    }
}
