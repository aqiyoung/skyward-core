//! UDP packet sessions (`PacketConn`) and the stream-framed variants.
//!
//! A `PacketConn` is bound to one target at dial time — the TUN layer
//! keeps a session per (source, destination) pair, so per-packet
//! addressing is only needed inside the protocol framing itself.

use std::io;

use async_trait::async_trait;
use tokio::sync::Mutex;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};

use super::BoxedStream;
use crate::common::TargetAddr;

#[async_trait]
pub trait PacketConn: Send + Sync {
    async fn send(&self, data: &[u8]) -> io::Result<()>;
    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

/// Packet framing shared by VLESS and VMess UDP sessions: every packet
/// is `[u16 length][payload]` on the (already header-stripped) stream.
pub struct LengthFramedPacketConn {
    read: Mutex<ReadHalf<BoxedStream>>,
    write: Mutex<WriteHalf<BoxedStream>>,
    read_buf: Mutex<BytesMut>,
}

impl LengthFramedPacketConn {
    pub fn new(stream: BoxedStream) -> Self {
        let (read, write) = tokio::io::split(stream);
        LengthFramedPacketConn {
            read: Mutex::new(read),
            write: Mutex::new(write),
            read_buf: Mutex::new(BytesMut::new()),
        }
    }
}

#[async_trait]
impl PacketConn for LengthFramedPacketConn {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "udp packet too large"));
        }
        let mut frame = Vec::with_capacity(2 + data.len());
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(data);
        let mut write = self.write.lock().await;
        write.write_all(&frame).await?;
        write.flush().await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = self.read_buf.lock().await;
        loop {
            if read_buf.len() >= 2 {
                let len = u16::from_be_bytes([read_buf[0], read_buf[1]]) as usize;
                if read_buf.len() >= 2 + len {
                    read_buf.advance(2);
                    let n = len.min(buf.len());
                    buf[..n].copy_from_slice(&read_buf[..n]);
                    read_buf.advance(len);
                    return Ok(n);
                }
            }
            let mut chunk = [0u8; 8192];
            let n = {
                let mut read = self.read.lock().await;
                read.read(&mut chunk).await?
            };
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "udp session stream closed",
                ));
            }
            read_buf.extend_from_slice(&chunk[..n]);
        }
    }
}

/// Trojan UDP framing: every packet on the stream is
/// `[socks5 addr][port][u16 length][CR LF][payload]`.
pub struct TrojanPacketConn {
    read: Mutex<ReadHalf<BoxedStream>>,
    write: Mutex<WriteHalf<BoxedStream>>,
    read_buf: Mutex<BytesMut>,
    target_header: Vec<u8>,
}

impl TrojanPacketConn {
    pub fn new(stream: BoxedStream, target: &TargetAddr) -> Self {
        let (read, write) = tokio::io::split(stream);
        TrojanPacketConn {
            read: Mutex::new(read),
            write: Mutex::new(write),
            read_buf: Mutex::new(BytesMut::new()),
            target_header: super::trojan::encode_socks_target(target),
        }
    }

    async fn fill(&self, read_buf: &mut BytesMut) -> io::Result<()> {
        let mut chunk = [0u8; 8192];
        let n = {
            let mut read = self.read.lock().await;
            read.read(&mut chunk).await?
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "trojan udp session stream closed",
            ));
        }
        read_buf.extend_from_slice(&chunk[..n]);
        Ok(())
    }
}

/// Length of a socks5-style address header at the start of `buf`, or
/// None when more bytes are needed to tell.
pub(crate) fn socks_addr_len(buf: &[u8]) -> Option<usize> {
    match *buf.first()? {
        0x01 => Some(1 + 4 + 2),
        0x04 => Some(1 + 16 + 2),
        0x03 => {
            if buf.len() < 2 {
                return None;
            }
            Some(1 + 1 + buf[1] as usize + 2)
        }
        _ => Some(0),
    }
}

#[async_trait]
impl PacketConn for TrojanPacketConn {
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        if data.len() > u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "udp packet too large"));
        }
        let mut frame = Vec::with_capacity(self.target_header.len() + 4 + data.len());
        frame.extend_from_slice(&self.target_header);
        frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
        frame.extend_from_slice(b"\r\n");
        frame.extend_from_slice(data);
        let mut write = self.write.lock().await;
        write.write_all(&frame).await?;
        write.flush().await
    }

    async fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut read_buf = self.read_buf.lock().await;
        loop {
            if let Some(addr_len) = socks_addr_len(&read_buf) {
                if addr_len == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "trojan udp: bad address type",
                    ));
                }
                let header_len = addr_len + 2 + 2; // addr + length + CRLF
                if read_buf.len() >= header_len {
                    let len =
                        u16::from_be_bytes([read_buf[addr_len], read_buf[addr_len + 1]]) as usize;
                    if read_buf.len() >= header_len + len {
                        read_buf.advance(header_len);
                        let n = len.min(buf.len());
                        buf[..n].copy_from_slice(&read_buf[..n]);
                        read_buf.advance(len);
                        return Ok(n);
                    }
                }
            }
            self.fill(&mut read_buf).await?;
        }
    }
}
