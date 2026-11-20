//! XTLS-Vision (`xtls-rprx-vision`) stream wrapper.
//!
//! Vision runs inside the TLS (or REALITY) connection and frames the
//! VLESS payload stream (everything after the VLESS request/response
//! headers, which travel outside the framing) as padding blocks:
//! `[uuid(16, first block only)] [command(1)] [contentLen(2)] [padLen(2)]
//! [content] [zero padding]`.
//! Commands: 0 = continue padding, 1 = end padding (raw stream inside
//! the TLS connection after this block), 2 = direct (the TLS layer is
//! dropped entirely and the inner stream continues on the raw socket).
//! The wrapper watches the inner traffic for a TLS handshake to decide
//! when to stop padding, mirroring xray's filter.
//!
//! Direct mode needs the raw socket under the TLS stream, so it is only
//! armed over the hand-rolled TLS 1.3 client (REALITY); over a rustls
//! stream the wrapper uses end-padding instead and treats a received
//! direct command as end (a server only splices after the client does).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::tls13::Tls13Stream;
use super::BoxedStream;

const CMD_CONTINUE: u8 = 0;
const CMD_END: u8 = 1;
const CMD_DIRECT: u8 = 2;

const HEADER_LEN: usize = 5; // command + contentLen + paddingLen
const FIRST_HEADER_LEN: usize = 16 + HEADER_LEN;
const MAX_BLOCK_CONTENT: usize = 8192 - FIRST_HEADER_LEN;
const APP_DATA_START: [u8; 3] = [0x17, 0x03, 0x03];

enum Inner {
    Tls13(Box<Tls13Stream>),
    Boxed(BoxedStream),
    Raw(BoxedStream),
}

impl Inner {
    fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self {
            Inner::Tls13(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Inner::Boxed(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
            Inner::Raw(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }

    fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self {
            Inner::Tls13(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Inner::Boxed(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
            Inner::Raw(s) => Pin::new(s.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Inner::Tls13(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Inner::Boxed(s) => Pin::new(s.as_mut()).poll_flush(cx),
            Inner::Raw(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self {
            Inner::Tls13(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Inner::Boxed(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
            Inner::Raw(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// TLS-traffic filter state shared by both directions (the inner
/// connection's handshake is observed across reads and writes).
#[derive(Default)]
struct TlsFilter {
    packets_left: i32,
    is_tls: bool,
    is_tls12_or_above: bool,
    enable_xtls: bool,
    cipher: u16,
    remaining_server_hello: u32,
}

impl TlsFilter {
    fn new() -> Self {
        TlsFilter { packets_left: 8, ..Default::default() }
    }

    fn observe(&mut self, buffer: &[u8]) {
        if self.packets_left <= 0 {
            return;
        }
        let len_p = buffer.len();
        self.packets_left -= 1;
        let mut index: Option<usize> = None;
        if let Some(i) = find(buffer, &[0x16, 0x03, 0x03]) {
            index = Some(i);
            if len_p > i + 5 && buffer[0] == 22 && buffer[1] == 3 && buffer[2] == 3 && buffer[5] == 2 {
                self.is_tls = true;
                self.remaining_server_hello =
                    u16::from_be_bytes([buffer[i + 3], buffer[i + 4]]) as u32 + 5;
                self.is_tls12_or_above = true;
                if len_p - i >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = buffer[i + 43] as usize;
                    let cipher_offset = i + 43 + session_id_len + 1;
                    if cipher_offset + 2 <= len_p {
                        self.cipher =
                            u16::from_be_bytes([buffer[cipher_offset], buffer[cipher_offset + 1]]);
                    }
                }
            }
        } else if let Some(i) = find(buffer, &[0x16, 0x03]) {
            if len_p > i + 5 && buffer[i + 5] == 1 {
                self.is_tls = true;
            }
        }

        if self.remaining_server_hello > 0 {
            let i = index.unwrap_or(0);
            let mut end = self.remaining_server_hello as usize;
            if i + end > len_p {
                end = len_p;
                self.remaining_server_hello -= (end - i) as u32;
            } else {
                self.remaining_server_hello = 0;
                end += i;
            }
            let window = &buffer[i.min(len_p)..end.min(len_p)];
            if find(window, &[0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]).is_some() {
                // TLS 1.3 supported_versions inside the ServerHello.
                if matches!(self.cipher, 0x1301 | 0x1302 | 0x1303 | 0x1304) {
                    self.enable_xtls = true;
                }
                self.packets_left = 0;
                return;
            } else if self.remaining_server_hello <= 0 {
                self.packets_left = 0;
                return;
            }
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn rfind(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.len() > haystack.len() {
        return None;
    }
    haystack.windows(needle.len()).rposition(|w| w == needle)
}

enum ReadState {
    /// The VLESS response header travels outside the padding framing:
    /// pass bytes through until it is fully forwarded, then blocks begin.
    ResponseHeader,
    Header,
    Content,
    Padding,
    Raw,
}

pub struct VisionStream {
    inner: Inner,
    uuid: [u8; 16],
    filter: TlsFilter,
    can_direct: bool,
    direct_armed: bool,
    // write side
    write_uuid_pending: bool,
    write_padding: bool,
    out_buf: Vec<u8>,
    out_pos: usize,
    pre_write: Vec<u8>,
    pre_write_pos: usize,
    // read side
    read_uuid_pending: bool,
    read_state: ReadState,
    in_buf: BytesMut,
    pre_read: BytesMut,
    content_left: usize,
    padding_left: usize,
    final_block: bool,
    read_eof: bool,
    resp_seen: usize,
    resp_left: usize,
}

impl VisionStream {
    pub fn new(inner: BoxedStream, uuid: [u8; 16]) -> Self {
        Self::wrap(Inner::Boxed(inner), uuid, false)
    }

    pub fn new_tls13(inner: Tls13Stream, uuid: [u8; 16]) -> Self {
        Self::wrap(Inner::Tls13(Box::new(inner)), uuid, true)
    }

    fn wrap(inner: Inner, uuid: [u8; 16], can_direct: bool) -> Self {
        VisionStream {
            inner,
            uuid,
            filter: TlsFilter::new(),
            can_direct,
            direct_armed: false,
            write_uuid_pending: true,
            write_padding: true,
            out_buf: Vec::new(),
            out_pos: 0,
            pre_write: Vec::new(),
            pre_write_pos: 0,
            read_uuid_pending: true,
            read_state: ReadState::ResponseHeader,
            in_buf: BytesMut::new(),
            pre_read: BytesMut::new(),
            content_left: 0,
            padding_left: 0,
            final_block: false,
            read_eof: false,
            resp_seen: 0,
            resp_left: 2,
        }
    }

    /// If direct mode is armed and every TLS-bound byte has been handed
    /// to the TLS stream, drop the TLS layer: its leftover read bytes
    /// become the raw stream's first bytes and its pending sealed
    /// records still go out before any raw writes.
    fn maybe_flip(&mut self) {
        if !self.direct_armed || self.out_pos < self.out_buf.len() {
            return;
        }
        let old = std::mem::replace(&mut self.inner, Inner::Boxed(Box::new(tokio::io::empty())));
        if let Inner::Tls13(tls) = old {
            let (raw, read_first, pending_write) = tls.into_raw_parts();
            self.pre_read.extend_from_slice(&read_first);
            self.pre_write = pending_write;
            self.pre_write_pos = 0;
            self.inner = Inner::Raw(raw);
        } else {
            self.inner = old;
        }
    }

    fn is_raw(&self) -> bool {
        matches!(self.inner, Inner::Raw(_))
    }

    fn flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Pending sealed records captured at the flip go first.
        while self.pre_write_pos < self.pre_write.len() {
            match self.inner.poll_write(cx, &self.pre_write[self.pre_write_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision: underlying write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => self.pre_write_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        while self.out_pos < self.out_buf.len() {
            match self.inner.poll_write(cx, &self.out_buf[self.out_pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision: underlying write returned 0",
                    )))
                }
                Poll::Ready(Ok(n)) => self.out_pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.out_buf.clear();
        self.out_pos = 0;
        self.maybe_flip();
        Poll::Ready(Ok(()))
    }

    fn fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut tmp = [0u8; 8192];
        let mut read_buf = ReadBuf::new(&mut tmp);
        match self.inner.poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                let filled = read_buf.filled();
                if filled.is_empty() {
                    self.read_eof = true;
                } else {
                    self.in_buf.extend_from_slice(filled);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn after_content(&mut self) {
        self.read_state = if self.padding_left > 0 {
            ReadState::Padding
        } else if self.final_block {
            ReadState::Raw
        } else {
            ReadState::Header
        };
    }

    fn after_padding(&mut self) {
        self.read_state = if self.final_block {
            ReadState::Raw
        } else {
            ReadState::Header
        };
    }

    /// Choose the cut point for the next block: at most MAX_BLOCK_CONTENT,
    /// preferring a cut right before an inner ApplicationData record.
    fn block_cut(&self, buf: &[u8]) -> usize {
        if buf.len() <= MAX_BLOCK_CONTENT {
            return buf.len();
        }
        let window = &buf[..MAX_BLOCK_CONTENT];
        if let Some(pos) = rfind(window, &APP_DATA_START) {
            if pos >= FIRST_HEADER_LEN {
                return pos;
            }
        }
        8192 / 2
    }
}

impl AsyncWrite for VisionStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.out_pos < self.out_buf.len() || self.pre_write_pos < self.pre_write.len() {
            match self.flush_out(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if !self.write_padding {
            if self.is_raw() {
                return self.inner.poll_write(cx, buf);
            }
            return self.inner.poll_write(cx, buf);
        }
        self.filter.observe(buf);
        let cut = self.block_cut(buf);
        let chunk = &buf[..cut];
        let mut command = CMD_CONTINUE;
        let mut last = false;
        if self.filter.is_tls && chunk.len() > 6 && chunk[..3] == APP_DATA_START {
            command = if self.filter.enable_xtls && self.can_direct {
                CMD_DIRECT
            } else {
                CMD_END
            };
            last = true;
        } else if !self.filter.is_tls12_or_above && self.filter.packets_left <= 1 {
            command = CMD_END;
            last = true;
        }
        // Long padding hides small payloads (the first inner records)
        // while the filter is still watching.
        let padding_len = if chunk.len() < 900 {
            let target = 900 + (rand::random::<u32>() % 500) as usize;
            target.saturating_sub(chunk.len())
        } else {
            0
        };
        let mut block = Vec::with_capacity(FIRST_HEADER_LEN + chunk.len() + padding_len);
        if self.write_uuid_pending {
            block.extend_from_slice(&self.uuid);
            self.write_uuid_pending = false;
        }
        block.push(command);
        block.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        block.extend_from_slice(&(padding_len as u16).to_be_bytes());
        block.extend_from_slice(chunk);
        block.resize(block.len() + padding_len, 0);
        self.out_buf.extend_from_slice(&block);
        if last {
            self.write_padding = false;
            if command == CMD_DIRECT {
                self.direct_armed = true;
            }
        }
        match self.flush_out(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => {}
        }
        Poll::Ready(Ok(cut))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_out(cx) {
            Poll::Ready(Ok(())) => self.inner.poll_flush(cx),
            other => other,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.flush_out(cx) {
            Poll::Ready(Ok(())) => self.inner.poll_shutdown(cx),
            other => other,
        }
    }
}

impl AsyncRead for VisionStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            match self.read_state {
                ReadState::ResponseHeader => {
                    // Forward at most resp_left bytes; the second byte is
                    // the addons length, which extends the header.
                    if self.in_buf.is_empty() {
                        match self.fill(cx) {
                            Poll::Ready(Ok(())) => {
                                if self.read_eof {
                                    return Poll::Ready(Ok(()));
                                }
                                continue;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let n = self.resp_left.min(self.in_buf.len()).min(buf.remaining());
                    if n == 0 {
                        return Poll::Pending;
                    }
                    let chunk: Vec<u8> = self.in_buf[..n].to_vec();
                    if self.resp_seen < 2 && self.resp_seen + n >= 2 {
                        let addons_len = chunk[1 - self.resp_seen] as usize;
                        self.resp_left += addons_len;
                    }
                    buf.put_slice(&chunk);
                    self.in_buf.advance(n);
                    self.resp_seen += n;
                    self.resp_left -= n;
                    if self.resp_left == 0 {
                        self.read_state = ReadState::Header;
                    }
                    return Poll::Ready(Ok(()));
                }
                ReadState::Raw => {
                    if !self.is_raw() {
                        // Direct was armed but the flip has not happened
                        // yet (write side busy): help flush, then flip.
                        match self.flush_out(cx) {
                            Poll::Ready(Ok(())) => {}
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                        self.maybe_flip();
                    }
                    if !self.in_buf.is_empty() {
                        let n = self.in_buf.len().min(buf.remaining());
                        buf.put_slice(&self.in_buf[..n]);
                        self.in_buf.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    if !self.pre_read.is_empty() {
                        let n = self.pre_read.len().min(buf.remaining());
                        buf.put_slice(&self.pre_read[..n]);
                        self.pre_read.advance(n);
                        return Poll::Ready(Ok(()));
                    }
                    return self.inner.poll_read(cx, buf);
                }
                ReadState::Content => {
                    if self.content_left == 0 {
                        self.after_content();
                        continue;
                    }
                    if self.in_buf.is_empty() {
                        match self.fill(cx) {
                            Poll::Ready(Ok(())) => {
                                if self.read_eof {
                                    return Poll::Ready(Ok(()));
                                }
                                continue;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let n = self.content_left.min(self.in_buf.len()).min(buf.remaining());
                    if n == 0 {
                        return Poll::Pending;
                    }
                    let chunk: Vec<u8> = self.in_buf[..n].to_vec();
                    buf.put_slice(&chunk);
                    self.in_buf.advance(n);
                    self.content_left -= n;
                    self.filter.observe(&chunk);
                    return Poll::Ready(Ok(()));
                }
                ReadState::Padding => {
                    let n = self.padding_left.min(self.in_buf.len());
                    self.in_buf.advance(n);
                    self.padding_left -= n;
                    if self.padding_left == 0 {
                        self.after_padding();
                        continue;
                    }
                    match self.fill(cx) {
                        Poll::Ready(Ok(())) => {
                            if self.read_eof {
                                return Poll::Ready(Ok(()));
                            }
                            continue;
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ReadState::Header => {
                    let need = if self.read_uuid_pending {
                        FIRST_HEADER_LEN
                    } else {
                        HEADER_LEN
                    };
                    if self.in_buf.len() < need {
                        match self.fill(cx) {
                            Poll::Ready(Ok(())) => {
                                if self.read_eof {
                                    return Poll::Ready(Ok(()));
                                }
                                continue;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    let header: Vec<u8> = self.in_buf[..need].to_vec();
                    self.in_buf.advance(need);
                    let fields = if self.read_uuid_pending {
                        self.read_uuid_pending = false;
                        if header[..16] != self.uuid {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "vision: server responded with an unknown UUID",
                            )));
                        }
                        &header[16..]
                    } else {
                        &header[..]
                    };
                    let command = fields[0];
                    self.content_left = u16::from_be_bytes([fields[1], fields[2]]) as usize;
                    self.padding_left = u16::from_be_bytes([fields[3], fields[4]]) as usize;
                    match command {
                        CMD_CONTINUE => {
                            self.read_state = ReadState::Content;
                        }
                        CMD_END | CMD_DIRECT => {
                            // After this block's content (and padding)
                            // drain, the stream turns raw.
                            self.final_block = true;
                            if command == CMD_DIRECT && self.can_direct {
                                self.direct_armed = true;
                            }
                            if self.content_left == 0 {
                                self.after_content();
                            } else {
                                self.read_state = ReadState::Content;
                            }
                        }
                        _ => {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("vision: unknown padding command {}", command),
                            )));
                        }
                    }
                }
            }
        }
    }
}
