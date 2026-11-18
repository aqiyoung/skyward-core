//! TCP session relay between smoltcp sockets and the kernel's outbound
//! adapters. smoltcp runs a synchronous poll loop; outbounds are async tokio
//! streams. Two byte queues bridged by `Notify` connect the two worlds:
//!
//!   TUN -> socket.recv  -> to_net  -> [tokio task] -> outbound.write
//!   TUN <- socket.send  <- from_net <- [tokio task] <- outbound.read

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpAddress;

use crate::adapter::BoxedStream;
use crate::common::TargetAddr;
use crate::tunnel::Engine;

/// Tracks the outbound relay session attached to each smoltcp TCP socket.
pub struct SessionManager {
    sessions: std::collections::HashMap<SocketHandle, SessionBridges>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self { sessions: std::collections::HashMap::new() }
    }

    /// Advance all TCP sockets one step: dial new connections, shuttle bytes
    /// between established sockets and their outbound relay, and retire closed
    /// ones. Must be called from within a tokio runtime (it spawns relay tasks).
    pub fn pump(&mut self, sockets: &mut SocketSet<'_>, engine: &Arc<Engine>) {
        // Collect handle snapshots first to avoid borrowing sockets twice.
        let handles: Vec<SocketHandle> = sockets.iter().filter_map(|(h, socket)| {
            matches!(socket, smoltcp::socket::Socket::Tcp(_)).then_some(h)
        }).collect();
        for handle in handles {
            let target = {
                let socket = sockets.get::<tcp::Socket>(handle);
                match socket.state() {
                    tcp::State::SynSent | tcp::State::Established => socket
                        .remote_endpoint()
                        .map(endpoint_to_target),
                    tcp::State::Closed => {
                        self.sessions.remove(&handle);
                        continue;
                    }
                    _ => None,
                }
            };

            if let Some(target) = target {
                if !self.sessions.contains_key(&handle) {
                    let bridges = SessionBridges::new();
                    tracing::info!("TUN TCP {} -> {}", handle, target.address());
                    spawn_session(engine.clone(), target, bridges.clone());
                    self.sessions.insert(handle, bridges);
                }
            }

            // Shuttle bytes using a scoped mutable borrow per socket.
            if let Some(bridges) = self.sessions.get(&handle) {
                let socket = sockets.get_mut::<tcp::Socket>(handle);
                if socket.can_send() && socket.state() == tcp::State::Established {
                    let mut buf = [0u8; 8192];
                    let n = bridges.from_net.pop(&mut buf);
                    if n > 0 {
                        let _ = socket.send_slice(&buf[..n]);
                    }
                }
                if socket.may_recv() && socket.state() == tcp::State::Established {
                    let mut buf = [0u8; 8192];
                    match socket.recv_slice(&mut buf) {
                        Ok(n) if n > 0 => bridges.to_net.push(&buf[..n]),
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn shutdown(&mut self) {
        for bridges in self.sessions.values() {
        bridges.cancel.notify_one();
        }
        self.sessions.clear();
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

fn endpoint_to_target(endpoint: smoltcp::wire::IpEndpoint) -> TargetAddr {
    let port = endpoint.port;
    // Only IPv4 is enabled (proto-ipv6 feature is off).
    let IpAddress::Ipv4(v4) = endpoint.addr;
    let mut octets = [0u8; 4];
    octets.copy_from_slice(v4.as_bytes());
    TargetAddr::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::from(octets)), port)
}

/// A byte queue shared between the synchronous poll thread and an async task.
#[derive(Clone)]
pub struct ByteQueue {
    inner: Arc<Mutex<VecDeque<u8>>>,
    ready: Arc<Notify>,
}

impl ByteQueue {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            ready: Arc::new(Notify::new()),
        }
    }

    pub fn push(&self, data: &[u8]) {
        self.inner.lock().unwrap().extend(data.iter().copied());
        self.ready.notify_one();
    }

    /// Pop up to `out.len()` bytes. Returns the number popped.
    pub fn pop(&self, out: &mut [u8]) -> usize {
        let mut queue = self.inner.lock().unwrap();
        let n = out.len().min(queue.len());
        for slot in out.iter_mut().take(n) {
            *slot = queue.pop_front().unwrap();
        }
        n
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub async fn notified(&self) {
        self.ready.notified().await;
    }
}

impl Default for ByteQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// One live TUN TCP session: the two queues the poll loop and tokio task meet at.
#[derive(Clone)]
pub struct SessionBridges {
    pub to_net: ByteQueue,
    pub from_net: ByteQueue,
    cancel: Arc<Notify>,
}

impl SessionBridges {
    pub fn new() -> Self {
        Self {
            to_net: ByteQueue::new(),
            from_net: ByteQueue::new(),
            cancel: Arc::new(Notify::new()),
        }
    }
}

impl Default for SessionBridges {
    fn default() -> Self {
        Self::new()
    }
}

/// Spawn a tokio task that dials `target` through the engine and pumps bytes
/// between the outbound stream and the two queues. The task exits when the
/// outbound closes or errors.
pub fn spawn_session(engine: Arc<Engine>, target: TargetAddr, bridges: SessionBridges) {
    tokio::spawn(async move {
        let mut stream: BoxedStream = match tokio::select! {
            _ = bridges.cancel.notified() => return,
            result = engine.dial(&target) => result,
        } {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("TUN relay dial {} failed: {}", target.address(), e);
                return;
            }
        };
        let mut read_buf = vec![0u8; 16 * 1024];
        loop {
            // Drain bytes destined for the network into the outbound.
            let mut write_buf = vec![0u8; 16 * 1024];
            let n = bridges.to_net.pop(&mut write_buf);
            tokio::select! {
                _ = bridges.cancel.notified() => break,
                _ = bridges.to_net.notified() => {},
                result = async {
                    if n == 0 { std::future::pending().await } else { stream.write_all(&write_buf[..n]).await }
                } => if result.is_err() { break; },
                result = stream.read(&mut read_buf) => match result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => bridges.from_net.push(&read_buf[..n]),
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_queue_fifo() {
        let q = ByteQueue::new();
        q.push(b"hello");
        q.push(b" world");
        let mut out = [0u8; 32];
        let n = q.pop(&mut out);
        assert_eq!(&out[..n], b"hello world");
        assert!(q.is_empty());
    }

    #[test]
    fn byte_queue_partial_pop() {
        let q = ByteQueue::new();
        q.push(b"abcdef");
        let mut out = [0u8; 4];
        assert_eq!(q.pop(&mut out), 4);
        assert_eq!(&out, b"abcd");
        let mut out2 = [0u8; 4];
        assert_eq!(q.pop(&mut out2), 2);
        assert_eq!(&out2[..2], b"ef");
    }

    #[test]
    fn endpoint_converts_to_target() {
        use smoltcp::wire::{IpEndpoint, Ipv4Address};
        let ep = IpEndpoint::new(
            smoltcp::wire::IpAddress::Ipv4(Ipv4Address::new(1, 2, 3, 4)),
            443,
        );
        let target = endpoint_to_target(ep);
        assert_eq!(target.address(), "1.2.3.4:443");
    }

    #[test]
    fn session_manager_starts_empty() {
        let manager = SessionManager::new();
        assert_eq!(manager.session_count(), 0);
    }

    #[tokio::test]
    async fn bridges_are_independent() {
        let bridges = SessionBridges::new();
        bridges.to_net.push(b"out");
        bridges.from_net.push(b"in");
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        assert_eq!(bridges.to_net.pop(&mut a), 3);
        assert_eq!(&a[..3], b"out");
        assert_eq!(bridges.from_net.pop(&mut b), 2);
        assert_eq!(&b[..2], b"in");
    }
}
