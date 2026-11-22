//! Minimal TCP terminator for the TUN interface.
//!
//! A TUN-based proxy must accept connections for *arbitrary* destination
//! addresses and ports. smoltcp's TCP sockets only accept traffic that matches
//! a socket that is already listening on that exact port, so it can never be
//! used to terminate the TUN's connections directly. This module implements
//! just enough TCP to complete the handshake on behalf of the app, relay the
//! byte stream through an outbound, and tear the connection down.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Notify;

use crate::adapter::BoxedStream;
use crate::common::TargetAddr;
use crate::tunnel::Engine;
use crate::tun::relay::ByteQueue;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

const WINDOW: u16 = 65535;

/// Rate-limited diagnostics for flow establishment.
fn flow_diag(message: String) {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) < 1000 {
        crate::jni::emit_log_event(&format!("[rust-core] {}", message));
    }
}

/// Rate-limited diagnostics for the TUN data path, so one log export can show
/// whether packets arrive and whether the outbound dial works.
fn diag(message: String) {
    static COUNT: AtomicUsize = AtomicUsize::new(0);
    if COUNT.fetch_add(1, Ordering::Relaxed) < 1000 {
        crate::jni::emit_log_event(&format!("[rust-core] {}", message));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub target_ip: IpAddr,
    pub target_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SynReceived,
    Established,
}

/// One segment handed to the app but not yet acknowledged. The minimal stack
/// originally fired and forgot; a real stack (mihomo/gVisor) retransmits
/// unacknowledged data, and without it a single packet dropped by the
/// device-side stack stalls the flow forever.
struct Unacked {
    seq: u32,
    data: Vec<u8>,
    sent_at: std::time::Instant,
}

struct Flow {
    key: FlowKey,
    state: State,
    local_isn: u32,
    local_next: u32,
    client_next: u32,
    to_net: Arc<ByteQueue>,
    from_net: Arc<ByteQueue>,
    cancel: Arc<Notify>,
    done: Arc<AtomicBool>,
    /// The app sent FIN: no more uploads; the relay half-closes the outbound
    /// write side once `to_net` drains, but downloads continue.
    upload_closed: Arc<AtomicBool>,
    /// The outbound stream reached EOF (server closed): once `from_net` has
    /// been delivered, the manager answers with FIN.
    remote_eof: Arc<AtomicBool>,
    /// The relay died (dial failure, read/write error): the manager resets
    /// the flow so the app fails fast instead of hanging on a live-looking
    /// connection.
    relay_failed: Arc<AtomicBool>,
    /// Owning Android package, resolved from the raw TUN tuple at SYN time
    /// (before dialling) and reported to the App as metadata.process.
    package: Option<String>,
    /// Segments sent to the app awaiting its ACK, oldest first.
    unacked: std::collections::VecDeque<Unacked>,
    /// The app's latest advertised receive window; caps unacked bytes.
    peer_window: u32,
    fin_sent: bool,
    fin_sent_at: Option<std::time::Instant>,
}

pub struct TcpManager<T> {
    flows: HashMap<FlowKey, Flow>,
    engine: Arc<Engine>,
    io: Arc<Mutex<T>>,
    tasks: Mutex<tokio::task::JoinSet<()>>,
    /// Largest payload one IPv4 packet written back to the TUN may carry: the
    /// interface MTU minus the IPv4+TCP headers. A larger packet is dropped
    /// by the kernel, and this stack keeps no retransmission state, so the
    /// bytes would be lost for good and the flow would stall.
    mtu_payload: usize,
}

impl<T: Read + Write + Send + 'static> TcpManager<T> {
    pub fn new(engine: Arc<Engine>, io: Arc<Mutex<T>>) -> Self {
        Self {
            flows: HashMap::new(),
            engine,
            io,
            tasks: Mutex::new(tokio::task::JoinSet::new()),
            mtu_payload: 1460,
        }
    }

    /// Set the payload cap from the TUN interface MTU.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu_payload = mtu.saturating_sub(40).max(536);
    }

    /// IPv6 carries 20 more bytes of header than IPv4, so the same link MTU
    /// leaves 20 fewer bytes for TCP payload (and for the advertised MSS).
    fn payload_cap(&self, key: &FlowKey) -> usize {
        match key.target_ip {
            IpAddr::V6(_) => self.mtu_payload.saturating_sub(20),
            IpAddr::V4(_) => self.mtu_payload,
        }
    }

    /// Handle one raw IPv4 packet read from the TUN.
    pub fn handle_packet(&mut self, packet: &[u8]) {
        let Some(ip) = parse_ipv4(packet) else { return };
        if ip.proto != 6 {
            return;
        }
        let Some(tcp) = parse_tcp(packet, ip.ihl) else { return };
        self.process_packet(
            packet,
            IpAddr::V4(ip.src),
            IpAddr::V4(ip.dst),
            ip.ihl,
            tcp,
        );
    }

    /// Handle one raw IPv6/TCP packet read from the TUN. The state machine is
    /// shared with IPv4; only the addresses and transport offset differ.
    pub fn handle_packet6(&mut self, packet: &[u8]) {
        let Some(ip) = parse_ipv6(packet) else { return };
        if ip.next_header != 6 {
            return;
        }
        let Some(tcp) = parse_tcp(packet, ip.payload_offset) else { return };
        self.process_packet(
            packet,
            IpAddr::V6(ip.src),
            IpAddr::V6(ip.dst),
            ip.payload_offset,
            tcp,
        );
    }

    fn process_packet(
        &mut self,
        packet: &[u8],
        src: IpAddr,
        dst: IpAddr,
        payload_offset: usize,
        tcp: TcpHeader,
    ) {
        let key = FlowKey {
            client_ip: src,
            client_port: tcp.src_port,
            target_ip: dst,
            target_port: tcp.dst_port,
        };

        if tcp.flags & SYN != 0 && tcp.flags & ACK == 0 {
            if let Some(flow) = self.flows.get(&key) {
                if flow.state == State::SynReceived {
                    // Retransmitted SYN: answer with the same SYN-ACK.
                    let (isn, client_next) = (flow.local_isn, flow.client_next);
                    self.send_syn_ack(key, isn, client_next);
                }
                return;
            }
            // Resolve the owning app from the raw TUN tuple before dialling:
            // afterwards the socket may be gone and getConnectionOwnerUid
            // returns -1. Use the raw addresses, not the fake-ip target.
            let package = crate::jni::resolve_app_package(
                crate::jni::IPPROTO_TCP,
                &format!("{}:{}", key.client_ip, key.client_port),
                &format!("{}:{}", key.target_ip, key.target_port),
            );
            let isn: u32 = rand::random();
            let flow = Flow {
                key,
                package,
                state: State::SynReceived,
                local_isn: isn,
                local_next: isn.wrapping_add(1),
                client_next: tcp.seq.wrapping_add(1),
                to_net: Arc::new(ByteQueue::new()),
                from_net: Arc::new(ByteQueue::new()),
                cancel: Arc::new(Notify::new()),
                done: Arc::new(AtomicBool::new(false)),
                upload_closed: Arc::new(AtomicBool::new(false)),
                remote_eof: Arc::new(AtomicBool::new(false)),
                relay_failed: Arc::new(AtomicBool::new(false)),
                unacked: std::collections::VecDeque::new(),
                peer_window: tcp.window as u32,
                fin_sent: false,
                fin_sent_at: None,
            };
            self.send_syn_ack(key, isn, flow.client_next);
            diag(format!(
                "TCP SYN {}:{} -> {}:{}",
                key.client_ip, key.client_port, key.target_ip, key.target_port
            ));
            self.flows.insert(key, flow);
            self.spawn_flow(key);
            return;
        }

        if tcp.flags & RST != 0 {
            self.remove(&key);
            return;
        }

        // Update the flow inside a scoped borrow so the manager can still send
        // packets (which takes &self) once the mutation is done.
        enum Act {
            None,
            Ack(u32),
            Remove,
            Reset,
        }
        let action = 'act: {
            let Some(flow) = self.flows.get_mut(&key) else {
                // Not ours (or already gone): reject so the client stops retrying.
                self.send(key, tcp.ack, tcp.seq, RST | ACK, &[]);
                return;
            };

            if flow.state == State::SynReceived && tcp.flags & ACK != 0 {
                flow.state = State::Established;
            }
            flow.peer_window = tcp.window as u32;

            // Retire outbound segments the app has acknowledged, and finish
            // the flow once it acknowledges our FIN.
            if tcp.flags & ACK != 0 {
                while let Some(front) = flow.unacked.front() {
                    let end = front.seq.wrapping_add(front.data.len() as u32);
                    if (tcp.ack.wrapping_sub(end) as i32) >= 0 {
                        flow.unacked.pop_front();
                    } else {
                        break;
                    }
                }
                if flow.fin_sent && tcp.ack == flow.local_next {
                    break 'act Act::Remove;
                }
            }

            let payload = tcp.payload(packet, payload_offset);
            let mut act = Act::None;

            if flow.fin_sent {
                // We already closed our side; anything more is answered with
                // a reset so the app stops.
                if !payload.is_empty() || tcp.flags & FIN != 0 {
                    act = Act::Reset;
                }
            } else if !payload.is_empty() {
                let seg_seq = tcp.seq;
                let seg_end = seg_seq.wrapping_add(payload.len() as u32);
                if seg_seq == flow.client_next {
                    flow.client_next = seg_end;
                    self.engine.traffic.add_upload(payload.len() as u64);
                    flow.to_net.push(payload);
                } else if (seg_end.wrapping_sub(flow.client_next) as i32) > 0
                    && (flow.client_next.wrapping_sub(seg_seq) as i32) > 0
                {
                    // Partial overlap (retransmission straddling new data):
                    // keep only the bytes past what we already have.
                    let skip = flow.client_next.wrapping_sub(seg_seq) as usize;
                    let fresh = &payload[skip..];
                    flow.client_next = seg_end;
                    self.engine.traffic.add_upload(fresh.len() as u64);
                    flow.to_net.push(fresh);
                }
                // else: a pure retransmission or an out-of-order segment —
                // drop it; the ACK below tells the app where we stand.
                act = Act::Ack(flow.client_next);
            }

            if tcp.flags & FIN != 0 && !flow.upload_closed.load(Ordering::Relaxed) {
                let fin_seq = tcp.seq.wrapping_add(payload.len() as u32);
                if fin_seq == flow.client_next {
                    flow.client_next = flow.client_next.wrapping_add(1);
                    // Half-close: downloads continue; the relay shuts the
                    // outbound write side once the queue drains.
                    flow.upload_closed.store(true, Ordering::Relaxed);
                    act = Act::Ack(flow.client_next);
                }
            }

            act
        };

        match action {
            Act::Ack(ack) => {
                let seq = self.flows.get(&key).map(|f| f.local_next).unwrap_or(0);
                self.send(key, seq, ack, ACK, &[]);
            }
            Act::Remove => self.remove(&key),
            Act::Reset => self.reset_flow(key),
            Act::None => {}
        }
    }

    /// Send a RST for a live flow and drop it (dial/relay failure, or the app
    /// kept talking after our FIN).
    fn reset_flow(&mut self, key: FlowKey) {
        if let Some(flow) = self.flows.get(&key) {
            let (seq, ack) = (flow.local_next, flow.client_next);
            self.send(key, seq, ack, RST | ACK, &[]);
        }
        self.remove(&key);
    }

    /// SYN-ACK carrying an MSS option, like a real stack sends: without it
    /// peers fall back to a 536-byte default segment size.
    fn send_syn_ack(&self, key: FlowKey, seq: u32, ack: u32) {
        let mss = self.payload_cap(&key).min(u16::MAX as usize) as u16;
        let options = [2u8, 4, (mss >> 8) as u8, (mss & 0xff) as u8];
        let packet = build_packet_opts(
            key.target_ip,
            key.client_ip,
            key.target_port,
            key.client_port,
            seq,
            ack,
            SYN | ACK,
            &options,
            &[],
        );
        let mut io = self.io.lock().unwrap();
        if let Err(e) = io.write_all(&packet) {
            tracing::warn!("TUN write failed: {}", e);
        }
    }

    /// Push bytes received from outbounds back into the TUN, retransmit what
    /// the app never acknowledged, and drive flow teardown (FIN after the
    /// server closes, RST when the relay died).
    pub fn pump(&mut self) {
        let keys: Vec<FlowKey> = self.flows.keys().copied().collect();
        for key in keys {
            // A dead relay (dial failure, stream error) resets the flow so
            // the app fails fast and retries instead of hanging.
            let failed = self
                .flows
                .get(&key)
                .map(|f| f.relay_failed.load(Ordering::Relaxed))
                .unwrap_or(false);
            if failed {
                self.reset_flow(key);
                continue;
            }

            // Retransmit the oldest unacknowledged segment if it has been
            // outstanding too long — the packet we sent was likely dropped
            // by the device-side stack and the app is waiting on exactly
            // these bytes.
            let retransmit = self.flows.get(&key).and_then(|f| {
                f.unacked.front().and_then(|front| {
                    if front.sent_at.elapsed() > std::time::Duration::from_millis(300) {
                        Some((front.seq, front.data.clone(), f.client_next))
                    } else {
                        None
                    }
                })
            });
            if let Some((seq, data, ack)) = retransmit {
                self.send(key, seq, ack, PSH | ACK, &data);
                if let Some(flow) = self.flows.get_mut(&key) {
                    if let Some(front) = flow.unacked.front_mut() {
                        front.sent_at = std::time::Instant::now();
                    }
                }
                continue;
            }

            // Send new data, bounded by the app's advertised window and the
            // interface MTU.
            let Some(from_net) = self.flows.get(&key).map(|f| f.from_net.clone()) else {
                continue;
            };
            let cap_limit = self.payload_cap(&key);
            let mut buf = vec![0u8; cap_limit];
            for _ in 0..256 {
                let (window_left, seq, ack) = {
                    let Some(flow) = self.flows.get(&key) else { break };
                    let inflight: u32 = flow
                        .unacked
                        .iter()
                        .map(|u| u.data.len() as u32)
                        .sum();
                    (
                        flow.peer_window.saturating_sub(inflight),
                        flow.local_next,
                        flow.client_next,
                    )
                };
                if window_left == 0 {
                    break;
                }
                let cap = (window_left as usize).min(cap_limit);
                let n = from_net.pop(&mut buf[..cap]);
                if n == 0 {
                    break;
                }
                // Application bytes arriving from the network into the device.
                self.engine.traffic.add_download(n as u64);
                self.send(key, seq, ack, PSH | ACK, &buf[..n]);
                if let Some(flow) = self.flows.get_mut(&key) {
                    flow.local_next = flow.local_next.wrapping_add(n as u32);
                    flow.unacked.push_back(Unacked {
                        seq,
                        data: buf[..n].to_vec(),
                        sent_at: std::time::Instant::now(),
                    });
                }
                if from_net.is_empty() {
                    break;
                }
            }

            // Server closed and everything has been handed over: answer FIN.
            let send_fin = self.flows.get(&key).map(|f| {
                f.remote_eof.load(Ordering::Relaxed)
                    && f.from_net.is_empty()
                    && !f.fin_sent
            });
            if send_fin == Some(true) {
                let (seq, ack) = {
                    let flow = self.flows.get(&key).unwrap();
                    (flow.local_next, flow.client_next)
                };
                self.send(key, seq, ack, FIN | ACK, &[]);
                if let Some(flow) = self.flows.get_mut(&key) {
                    flow.local_next = flow.local_next.wrapping_add(1);
                    flow.fin_sent = true;
                    flow.fin_sent_at = Some(std::time::Instant::now());
                }
                continue;
            }

            // Teardown backstops: FIN never acknowledged, or the relay ended
            // quietly with nothing left to deliver.
            let drop_flow = self.flows.get(&key).map(|f| {
                (f.fin_sent
                    && f.fin_sent_at
                        .map(|t| t.elapsed() > std::time::Duration::from_secs(10))
                        .unwrap_or(false))
                    || (f.done.load(Ordering::Relaxed)
                        && f.from_net.is_empty()
                        && f.unacked.is_empty()
                        && !f.fin_sent)
            });
            if drop_flow == Some(true) {
                self.remove(&key);
            }
        }
    }

    /// Stop every relay; used when the VPN goes down.
    pub async fn shutdown(&mut self) {
        self.flows.clear();
        self.tasks.get_mut().unwrap().shutdown().await;
    }

    fn remove(&mut self, key: &FlowKey) {
        if let Some(flow) = self.flows.remove(key) {
            flow.cancel.notify_one();
        }
    }

    fn spawn_flow(&self, key: FlowKey) {
        let Some(flow) = self.flows.get(&key) else { return };
        let to_net = flow.to_net.clone();
        let from_net = flow.from_net.clone();
        let cancel = flow.cancel.clone();
        let done = flow.done.clone();
        let upload_closed = flow.upload_closed.clone();
        let remote_eof = flow.remote_eof.clone();
        let relay_failed = flow.relay_failed.clone();
        let package = flow.package.clone();
        let fallback_engine = self.engine.clone();
        let io = self.io.clone();
        // If the destination is a fake-ip we handed out in DNS, recover the
        // original hostname so rules match by domain and proxies receive the
        // real host instead of a synthetic address.
        // Fake IPs only exist for IPv4; a real IPv6 destination is dialed as-is.
        let target = match key.target_ip {
            IpAddr::V4(v4) => match crate::fake_ip::hostname_for(v4) {
                Some(host) => TargetAddr::Domain(host, key.target_port),
                None => key_target_addr(&key),
            },
            IpAddr::V6(_) => key_target_addr(&key),
        };
        // Log the resolved target (domain when known), not the fake IP, so a
        // log export names the site a flow belongs to.
        let addr = target.address();
        let mut tasks = self.tasks.lock().unwrap();
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            // Use the engine that is current NOW, not the one the TUN started
            // with: setupConfig swaps the engine when the profile changes,
            // and the App does not restart the TUN for that. Capturing the
            // start engine would route new flows through the previous
            // profile's nodes indefinitely.
            let engine = crate::runtime_state::engine()
                .await
                .unwrap_or(fallback_engine);
            // Rules and the chain are decided before dialling so the connection
            // the App lists names the same route the packet actually took.
            let rule = engine.decide(&target).await;
            let final_name = engine.outbounds.resolve(&rule).await;
            let mut stream: BoxedStream = tokio::select! {
                _ = cancel.notified() => {
                    relay_failed.store(true, Ordering::Relaxed);
                    done.store(true, Ordering::Relaxed);
                    return;
                }
                _ = engine.close_signal.notified() => {
                    // The engine was swapped (profile switch): exit, and let
                    // the manager reset the flow so the app reconnects under
                    // the new engine instead of ACKing into a dead queue.
                    relay_failed.store(true, Ordering::Relaxed);
                    done.store(true, Ordering::Relaxed);
                    return;
                }
                result = tokio::time::timeout(std::time::Duration::from_secs(10), engine.dial_named(&final_name, &target)) => {
                    match result {
                        Ok(Ok(s)) => {
                            flow_diag(format!("flow {} connected via {}", addr, final_name));
                            s
                        }
                        Ok(Err(e)) => {
                            tracing::warn!("TUN flow {} dial failed: {}", addr, e);
                            diag(format!("flow {} dial failed: {}", addr, e));
                            // The manager resets the flow so the app fails
                            // fast instead of hanging on a dead connection.
                            relay_failed.store(true, Ordering::Relaxed);
                            done.store(true, Ordering::Relaxed);
                            return;
                        }
                        Err(_) => {
                            diag(format!("flow {} dial timed out", addr));
                            relay_failed.store(true, Ordering::Relaxed);
                            done.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            };
            let (connection, up_counter, down_counter) = engine
                .connections
                .add(
                    &target,
                    &rule,
                    "",
                    vec![final_name, rule.clone()],
                    crate::tunnel::connection::Network::Tcp,
                    Some((key.client_ip.to_string(), key.client_port)),
                    package,
                )
                .await;
            let mut read_buf = vec![0u8; 16 * 1024];
            let started = std::time::Instant::now();
            let mut end_reason = "cancelled";
            let mut write_shutdown = false;
            let relay = async { 'relay: loop {
                // App half-closed and its bytes are flushed: close the
                // outbound write side so the server sees EOF, keep reading.
                if !write_shutdown
                    && upload_closed.load(Ordering::Relaxed)
                    && to_net.is_empty()
                {
                    use tokio::io::AsyncWriteExt as _;
                    let _ = stream.shutdown().await;
                    write_shutdown = true;
                }
                let mut write_buf = vec![0u8; 16 * 1024];
                let n = to_net.pop(&mut write_buf);
                if n > 0 {
                    if stream.write_all(&write_buf[..n]).await.is_err() {
                        end_reason = "write_err";
                        relay_failed.store(true, Ordering::Relaxed);
                        break 'relay;
                    }
                    up_counter.fetch_add(n as u64, Ordering::Relaxed);
                    continue;
                }
                // Backpressure: the manager may only hand the app one window
                // of unacknowledged data, so a fast server and a slow app
                // would otherwise pile bytes into from_net without bound.
                // Stop reading until the queue drains below the cap.
                let over_cap = from_net.len() > 256 * 1024;
                tokio::select! {
                    _ = cancel.notified() => { end_reason = "cancel"; break 'relay; }
                    _ = engine.close_signal.notified() => {
                        end_reason = "engine_close";
                        relay_failed.store(true, Ordering::Relaxed);
                        break 'relay;
                    }
                    _ = to_net.notified() => {}
                    _ = tokio::time::sleep(std::time::Duration::from_millis(50)), if over_cap => {}
                    result = stream.read(&mut read_buf), if !over_cap => match result {
                        Ok(0) => {
                            end_reason = "remote_eof";
                            remote_eof.store(true, Ordering::Relaxed);
                            break 'relay;
                        }
                        Err(_) => {
                            end_reason = "read_err";
                            relay_failed.store(true, Ordering::Relaxed);
                            break 'relay;
                        }
                        Ok(n) => {
                            down_counter.fetch_add(n as u64, Ordering::Relaxed);
                            from_net.push(&read_buf[..n]);
                        }
                    }
                }
            }};
            tokio::select! {
                biased;
                _ = connection.closed() => {
                    end_reason = "connection_closed";
                    relay_failed.store(true, Ordering::Relaxed);
                }
                _ = relay => {}
            }
            flow_diag(format!(
                "flow {} done up={} down={} lived={}ms end={}",
                addr,
                up_counter.load(Ordering::Relaxed),
                down_counter.load(Ordering::Relaxed),
                started.elapsed().as_millis(),
                end_reason
            ));
            done.store(true, Ordering::Relaxed);
        });
    }

    fn send(&self, key: FlowKey, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        let packet = build_packet(
            key.target_ip,
            key.client_ip,
            key.target_port,
            key.client_port,
            seq,
            ack,
            flags,
            payload,
        );
        let mut io = self.io.lock().unwrap();
        if let Err(e) = io.write_all(&packet) {
            tracing::warn!("TUN write failed: {}", e);
            diag(format!("TUN write failed: {}", e));
        }
    }
}

/// Build the dial target directly from the parsed flow key. The target IP is
/// already an `IpAddr` from the packet; never round-trip through an
/// `"ip:port"` string parsed as `IpAddr` (that always failed and dropped every
/// TUN connection).
fn key_target_addr(key: &FlowKey) -> TargetAddr {
    TargetAddr::Ip(key.target_ip, key.target_port)
}

pub(crate) struct Ipv4Info {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub proto: u8,
    pub ihl: usize,
}

pub(crate) fn parse_ipv4(packet: &[u8]) -> Option<Ipv4Info> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if packet.len() < ihl {
        return None;
    }
    Some(Ipv4Info {
        src: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        dst: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        proto: packet[9],
        ihl,
    })
}

pub(crate) struct Ipv6Info {
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// Final protocol number after any extension headers (6 = TCP, 17 = UDP).
    pub next_header: u8,
    /// Byte offset at which the transport header starts.
    pub payload_offset: usize,
}

/// Parse the fixed 40-byte IPv6 header, walking the common extension headers
/// so TCP/UDP are read from the real transport header. The walk is bounded to
/// a handful of headers so a malformed chain cannot stall the TUN read loop.
pub(crate) fn parse_ipv6(packet: &[u8]) -> Option<Ipv6Info> {
    if packet.len() < 40 || packet[0] >> 4 != 6 {
        return None;
    }
    let mut next_header = packet[6];
    let mut offset = 40usize;
    for _ in 0..8 {
        let len = match next_header {
            // Hop-by-hop, routing, and destination options: the length field
            // counts 8-byte units after the first one (RFC 8200 §4).
            0 | 43 | 60 => (*packet.get(offset + 1)? as usize + 1) * 8,
            // AH: length is in 32-bit words minus two (RFC 4302 §2).
            51 => (*packet.get(offset + 1)? as usize + 2) * 4,
            _ => break,
        };
        let following = *packet.get(offset)?;
        offset = offset.checked_add(len)?;
        if offset > packet.len() {
            return None;
        }
        next_header = following;
    }
    if next_header == 59 {
        // No next header (RFC 8200 §4.7).
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&packet[8..24]);
    dst.copy_from_slice(&packet[24..40]);
    Some(Ipv6Info {
        src: Ipv6Addr::from(src),
        dst: Ipv6Addr::from(dst),
        next_header,
        payload_offset: offset,
    })
}

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    data_offset: usize,
}

impl TcpHeader {
    fn payload<'a>(&self, packet: &'a [u8], payload_offset: usize) -> &'a [u8] {
        let start = payload_offset + self.data_offset;
        if start >= packet.len() {
            return &[];
        }
        &packet[start..]
    }
}

/// `payload_offset` is the IPv4 IHL (20+), or 40 plus any IPv6 extension
/// headers — the caller knows which family it parsed.
fn parse_tcp(packet: &[u8], payload_offset: usize) -> Option<TcpHeader> {
    let p = packet.get(payload_offset..)?;
    if p.len() < 20 {
        return None;
    }
    Some(TcpHeader {
        src_port: u16::from_be_bytes([p[0], p[1]]),
        dst_port: u16::from_be_bytes([p[2], p[3]]),
        seq: u32::from_be_bytes([p[4], p[5], p[6], p[7]]),
        ack: u32::from_be_bytes([p[8], p[9], p[10], p[11]]),
        data_offset: ((p[12] >> 4) as usize) * 4,
        flags: p[13],
        window: u16::from_be_bytes([p[14], p[15]]),
    })
}

/// Checksum pseudo-header: RFC 791 §3.1 for IPv4, RFC 8200 §8.1 for IPv6.
/// The v6 form is 16-byte src + 16-byte dst + 32-bit length + 3 zero bytes +
/// the next-header number.
fn pseudo_header(src: IpAddr, dst: IpAddr, proto: u8, len: usize) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut pseudo = Vec::with_capacity(12);
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.push(0);
            pseudo.push(proto);
            pseudo.extend_from_slice(&(len as u16).to_be_bytes());
            pseudo
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut pseudo = Vec::with_capacity(40);
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(len as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0]);
            pseudo.push(proto);
            pseudo
        }
        // Both addresses always come from the same parsed packet.
        _ => Vec::new(),
    }
}

/// Build the IP header for an outbound packet. IPv6 has no header checksum;
/// its mandatory transport checksum covers the pseudo-header instead.
fn build_ip_header(src: IpAddr, dst: IpAddr, proto: u8, payload_len: usize) -> Vec<u8> {
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut ip = [0u8; 20];
            ip[0] = 0x45;
            ip[2..4].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
            ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
            ip[8] = 64;
            ip[9] = proto;
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let ip_checksum = checksum(&ip);
            ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());
            ip.to_vec()
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut ip = Vec::with_capacity(40);
            ip.push(0x60);
            ip.extend_from_slice(&[0, 0, 0]); // traffic class + flow label
            ip.extend_from_slice(&(payload_len as u16).to_be_bytes());
            ip.push(proto);
            ip.push(64); // hop limit
            ip.extend_from_slice(&src.octets());
            ip.extend_from_slice(&dst.octets());
            ip
        }
        _ => Vec::new(),
    }
}

/// Build a complete IP/TCP packet with valid checksums, v4 or v6 according to
/// the address family of `src`/`dst`.
fn build_packet(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    build_packet_opts(src, dst, src_port, dst_port, seq, ack, flags, &[], payload)
}

/// Build an IP/TCP packet with TCP options (already padded to a multiple of
/// 4 bytes), e.g. the MSS option on a SYN-ACK.
#[allow(clippy::too_many_arguments)]
fn build_packet_opts(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    options: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let header_len = 20 + options.len();
    let payload_len = header_len + payload.len();
    let mut tcp = vec![0u8; payload_len];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = ((header_len / 4) as u8) << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&WINDOW.to_be_bytes());
    tcp[20..20 + options.len()].copy_from_slice(options);
    tcp[header_len..].copy_from_slice(payload);

    let mut pseudo = pseudo_header(src, dst, 6, tcp.len());
    pseudo.extend_from_slice(&tcp);
    let tcp_checksum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let ip = build_ip_header(src, dst, 6, payload_len);
    let mut out = Vec::with_capacity(ip.len() + tcp.len());
    out.extend_from_slice(&ip);
    out.extend_from_slice(&tcp);
    out
}

/// Build an IP/UDP packet with valid checksums, v4 or v6 according to the
/// address family of `src`/`dst`.
pub(crate) fn build_udp_packet(
    src: IpAddr,
    dst: IpAddr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);

    let mut pseudo = pseudo_header(src, dst, 17, udp.len());
    pseudo.extend_from_slice(&udp);
    let mut udp_checksum = checksum(&pseudo);
    // A computed zero checksum must be sent as all-ones over IPv6
    // (RFC 8200 §8.1); both fold to the same value at the receiver.
    if matches!(src, IpAddr::V6(_)) && udp_checksum == 0 {
        udp_checksum = 0xffff;
    }
    udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());

    let ip = build_ip_header(src, dst, 17, udp_len);
    let mut out = Vec::with_capacity(ip.len() + udp.len());
    out.extend_from_slice(&ip);
    out.extend_from_slice(&udp);
    out
}

/// Build an ICMP destination/port-unreachable packet answering `original`
/// (a full IPv4 packet). Used where a UDP datagram cannot be relayed —
/// refusing it immediately lets QUIC-capable apps fall back to TCP at once
/// instead of waiting out their handshake timeouts on a silently
/// black-holed datagram.
pub(crate) fn build_icmp_port_unreachable(original: &[u8], ihl: usize) -> Option<Vec<u8>> {
    if original.len() < ihl + 8 {
        return None;
    }
    let src = Ipv4Addr::new(original[16], original[17], original[18], original[19]);
    let dst = Ipv4Addr::new(original[12], original[13], original[14], original[15]);
    let quote_len = ihl + 8;
    let icmp_len = 8 + quote_len;
    let total_len = 20 + icmp_len;

    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = 3; // destination unreachable
    icmp[1] = 3; // port unreachable
    icmp[8..8 + quote_len].copy_from_slice(&original[..quote_len]);
    let icmp_checksum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&icmp_checksum.to_be_bytes());

    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 1;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&icmp);
    Some(out)
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::common::TrafficStats;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }

    #[test]
    fn flow_key_builds_a_valid_dial_target() {
        let key = FlowKey {
            client_ip: v4(198, 18, 0, 1),
            client_port: 40000,
            target_ip: v4(91, 108, 56, 150),
            target_port: 443,
        };
        let target = key_target_addr(&key);
        assert_eq!(target.address(), "91.108.56.150:443");
    }

    struct TestIo {
        out: Vec<u8>,
    }

    impl Read for TestIo {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::WouldBlock, "no data"))
        }
    }

    impl Write for TestIo {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn client_packet(
        client: IpAddr,
        target: IpAddr,
        cport: u16,
        tport: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        build_packet(client, target, cport, tport, seq, ack, flags, payload)
    }

    async fn manager() -> (TcpManager<TestIo>, Arc<Mutex<TestIo>>) {
        let engine = Arc::new(
            Engine::new(
                Config::default(),
                Arc::new(TrafficStats::default()),
                std::path::Path::new("."),
            )
            .await,
        );
        let io = Arc::new(Mutex::new(TestIo { out: Vec::new() }));
        (TcpManager::new(engine, io.clone()), io)
    }

    #[tokio::test]
    async fn mtu_cap_subtracts_headers() {
        let (mut tcp, _io) = manager().await;
        assert_eq!(tcp.mtu_payload, 1460);
        tcp.set_mtu(9000);
        assert_eq!(tcp.mtu_payload, 8960);
        tcp.set_mtu(576);
        assert_eq!(tcp.mtu_payload, 536);
    }

    #[tokio::test]
    async fn syn_is_answered_with_syn_ack() {
        let (mut tcp, io) = manager().await;
        let client = v4(198, 18, 0, 1);
        let target = v4(1, 1, 1, 1);
        let syn = client_packet(client, target, 40000, 443, 1000, 0, SYN, &[]);
        tcp.handle_packet(&syn);

        let out = io.lock().unwrap().out.clone();
        assert!(!out.is_empty(), "expected a SYN-ACK");
        let reply = parse_tcp(&out, 20).expect("valid tcp");
        assert_eq!(reply.flags & (SYN | ACK), SYN | ACK);
        assert_eq!(reply.ack, 1001);
        assert_eq!(reply.src_port, 443);
        assert_eq!(reply.dst_port, 40000);
        let ip = parse_ipv4(&out).unwrap();
        assert_eq!(ip.src, target);
        assert_eq!(ip.dst, client);
    }

    #[tokio::test]
    async fn payload_is_acked_and_queued_for_outbound() {
        let (mut tcp, io) = manager().await;
        let client = v4(198, 18, 0, 1);
        let target = v4(127, 0, 0, 1);
        let tport = 1u16;
        let cport = 40000u16;
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1000, 0, SYN, &[]));
        io.lock().unwrap().out.clear();

        // Complete the handshake, then send data.
        tcp.handle_packet(&client_packet(
            client, target, cport, tport, 1001, 1, ACK, &[],
        ));
        tcp.handle_packet(&client_packet(
            client, target, cport, tport, 1001, 1, PSH | ACK, b"hello",
        ));

        let out = io.lock().unwrap().out.clone();
        let ack = parse_tcp(&out, 20).expect("ack packet");
        assert_eq!(ack.flags & ACK, ACK);
        assert_eq!(ack.ack, 1006, "ack should cover the payload");
    }

    #[tokio::test]
    async fn unknown_flow_is_reset() {
        let (mut tcp, io) = manager().await;
        let client = v4(198, 18, 0, 1);
        let target = v4(9, 9, 9, 9);
        let pkt = client_packet(client, target, 40000, 443, 500, 0, ACK, &[]);
        tcp.handle_packet(&pkt);
        let out = io.lock().unwrap().out.clone();
        let reply = parse_tcp(&out, 20).expect("reset packet");
        assert_eq!(reply.flags & RST, RST);
    }

    #[tokio::test]
    async fn e2e_download_reassembles_over_mtu_sized_packets() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        // Local target server: read the request, reply with 30 KB, stay open.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let expected: Vec<u8> = (0..30_000u32).map(|i| (i % 251) as u8).collect();
        let expected_clone = expected.clone();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"GET / HTTP/1.0\r\n\r\n");
            sock.write_all(&expected_clone).await.unwrap();
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        });

        let (mut tcp, io) = manager().await;
        tcp.set_mtu(9000);
        let client = v4(198, 18, 0, 1);
        let target = v4(127, 0, 0, 1);
        let (cport, tport) = (40000u16, port);

        tcp.handle_packet(&client_packet(client, target, cport, tport, 1000, 0, SYN, &[]));
        let out = io.lock().unwrap().out.clone();
        io.lock().unwrap().out.clear();
        let synack = parse_tcp(&out, 20).expect("syn-ack");
        let isn = synack.seq;
        // Handshake completion + request in one go, like a real app.
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1001, isn + 1, ACK, &[]));
        tcp.handle_packet(&client_packet(
            client, target, cport, tport, 1001, isn + 1, PSH | ACK, b"GET / HTTP/1.0\r\n\r\n",
        ));

        // Pump like the runtime loop and collect every packet written back.
        let mut raw: Vec<u8> = Vec::new();
        for _ in 0..100 {
            tcp.pump();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let mut guard = io.lock().unwrap();
            raw.extend_from_slice(&guard.out);
            guard.out.clear();
        }
        server.abort();

        // Split the byte stream back into IP packets and reassemble by seq.
        let mut segments: Vec<(u32, Vec<u8>)> = Vec::new();
        let mut rest = &raw[..];
        while rest.len() >= 20 {
            let total = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            assert!(total >= 40 && total <= 9000, "packet size {} out of bounds", total);
            assert!(rest.len() >= total, "truncated packet in output");
            let pkt = &rest[..total];
            let hdr = parse_tcp(pkt, 20).expect("tcp header");
            let payload = hdr.payload(pkt, 20);
            if !payload.is_empty() {
                segments.push((hdr.seq, payload.to_vec()));
            }
            rest = &rest[total..];
        }
        segments.sort_by_key(|(seq, _)| *seq);
        let mut got: Vec<u8> = Vec::new();
        let mut next = isn + 1;
        for (seq, payload) in &segments {
            // Retransmissions repeat already-covered bytes; skip the overlap.
            if (*seq).wrapping_add(payload.len() as u32).wrapping_sub(next) as i32 <= 0 {
                continue;
            }
            assert_eq!(*seq, next, "sequence gap at {}", seq);
            got.extend_from_slice(payload);
            next = next.wrapping_add(payload.len() as u32);
        }
        assert_eq!(got, expected, "reassembled download differs");
    }

    #[tokio::test]
    async fn fin_half_closes_and_remote_eof_finishes() {
        let (mut tcp, io) = manager().await;
        let client = v4(198, 18, 0, 1);
        let target = v4(127, 0, 0, 1);
        let (cport, tport) = (40000u16, 1u16);
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1000, 0, SYN, &[]));
        let synack = parse_tcp(&io.lock().unwrap().out.clone(), 20).unwrap();
        let isn = synack.seq;
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1001, isn + 1, ACK, &[]));
        io.lock().unwrap().out.clear();
        // App half-closes: the flow must survive for the download direction.
        tcp.handle_packet(&client_packet(
            client, target, cport, tport, 1001, isn + 1, FIN | ACK, &[],
        ));
        assert_eq!(tcp.flows.len(), 1, "FIN must half-close, not kill the flow");
        let key = *tcp.flows.keys().next().unwrap();
        assert!(tcp.flows[&key].upload_closed.load(Ordering::Relaxed));
        // Server closes too: pump answers with FIN, and the flow is dropped
        // once the app acknowledges it.
        tcp.flows[&key].remote_eof.store(true, Ordering::Relaxed);
        io.lock().unwrap().out.clear();
        tcp.pump();
        let out = io.lock().unwrap().out.clone();
        let fin = parse_tcp(&out, 20).expect("fin packet");
        assert_eq!(fin.flags & (FIN | ACK), FIN | ACK);
        tcp.handle_packet(&client_packet(
            client, target, cport, tport, 1002, isn + 2, ACK, &[],
        ));
        assert!(tcp.flows.is_empty(), "flow ends after the FIN is acked");
    }

    #[tokio::test]
    async fn duplicate_segment_is_not_queued_twice() {
        let (mut tcp, io) = manager().await;
        let client = v4(198, 18, 0, 1);
        let target = v4(127, 0, 0, 1);
        let (cport, tport) = (40000u16, 1u16);
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1000, 0, SYN, &[]));
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1001, 1, ACK, &[]));
        let pkt = client_packet(client, target, cport, tport, 1001, 1, PSH | ACK, b"hello");
        tcp.handle_packet(&pkt);
        tcp.handle_packet(&pkt); // retransmission of the same segment
        let key = *tcp.flows.keys().next().unwrap();
        assert_eq!(tcp.flows[&key].to_net.len(), 5, "duplicate bytes must be dropped");
        let _ = io;
    }

    #[tokio::test]
    async fn syn_ack_carries_mss_option() {
        let (mut tcp, io) = manager().await;
        let client = v4(198, 18, 0, 1);
        let target = v4(1, 1, 1, 1);
        tcp.handle_packet(&client_packet(client, target, 40000, 443, 1000, 0, SYN, &[]));
        let out = io.lock().unwrap().out.clone();
        let reply = parse_tcp(&out, 20).expect("valid tcp");
        assert_eq!(reply.data_offset, 24, "SYN-ACK must carry 4 bytes of options");
        assert_eq!(&out[20 + 20..20 + 24], &[2, 4, 0x05, 0xb4], "MSS option = 1460");
    }

    /// Independently recompute a v6 checksum (RFC 8200 pseudo-header) so the
    /// tests do not rely on the same helper the builder uses.
    fn verify_checksum6(src: Ipv6Addr, dst: Ipv6Addr, proto: u8, data: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(40 + data.len());
        pseudo.extend_from_slice(&src.octets());
        pseudo.extend_from_slice(&dst.octets());
        pseudo.extend_from_slice(&(data.len() as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0]);
        pseudo.push(proto);
        pseudo.extend_from_slice(data);
        checksum(&pseudo)
    }

    #[test]
    fn ipv6_build_packet_has_valid_header_and_checksum() {
        let src: IpAddr = "fdfe:dcba:9876::1".parse().unwrap();
        let dst: IpAddr = "2606:4700:3037::2".parse().unwrap();
        let packet = build_packet_opts(src, dst, 40000, 443, 7, 9, ACK, &[], b"hello");
        assert_eq!(packet.len(), 40 + 20 + 5);
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(&packet[4..6], &25u16.to_be_bytes(), "payload length");
        assert_eq!(packet[6], 6, "TCP next header");
        assert_eq!(packet[7], 64, "hop limit");
        let IpAddr::V6(s6) = src else { unreachable!() };
        let IpAddr::V6(d6) = dst else { unreachable!() };
        assert_eq!(&packet[8..24], &s6.octets());
        assert_eq!(&packet[24..40], &d6.octets());
        let tcp = parse_tcp(&packet, 40).expect("tcp header at offset 40");
        assert_eq!((tcp.src_port, tcp.dst_port), (40000, 443));
        assert_eq!(tcp.payload(&packet, 40), b"hello");
        assert_eq!(verify_checksum6(s6, d6, 6, &packet[40..]), 0);
    }

    #[test]
    fn ipv6_build_udp_packet_has_valid_header_and_checksum() {
        let src: IpAddr = "fdfe:dcba:9876::1".parse().unwrap();
        let dst: IpAddr = "2606:4700:3037::2".parse().unwrap();
        let packet = build_udp_packet(src, dst, 53123, 443, b"hello");
        assert_eq!(packet.len(), 40 + 8 + 5);
        assert_eq!(packet[0] >> 4, 6);
        assert_eq!(&packet[4..6], &13u16.to_be_bytes());
        assert_eq!(packet[6], 17, "UDP next header");
        let IpAddr::V6(s6) = src else { unreachable!() };
        let IpAddr::V6(d6) = dst else { unreachable!() };
        assert_eq!(&packet[8..24], &s6.octets());
        assert_eq!(&packet[24..40], &d6.octets());
        assert_eq!(&packet[40..42], &53123u16.to_be_bytes());
        assert_eq!(&packet[42..44], &443u16.to_be_bytes());
        assert_eq!(verify_checksum6(s6, d6, 17, &packet[40..]), 0);
    }

    #[test]
    fn parse_ipv6_walks_extension_headers() {
        let src: Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let dst: Ipv6Addr = "2606:4700::1".parse().unwrap();
        let mut packet = vec![0x60, 0, 0, 0];
        packet.extend_from_slice(&28u16.to_be_bytes()); // 8-byte extension + 20 TCP
        packet.push(0); // hop-by-hop options first
        packet.push(64);
        packet.extend_from_slice(&src.octets());
        packet.extend_from_slice(&dst.octets());
        packet.extend_from_slice(&[6, 0, 0, 0, 0, 0, 0, 0]); // options, next = TCP
        packet.extend_from_slice(&[0u8; 20]);
        let info = parse_ipv6(&packet).unwrap();
        assert_eq!(info.src, src);
        assert_eq!(info.dst, dst);
        assert_eq!(info.next_header, 6);
        assert_eq!(info.payload_offset, 48);
    }

    #[tokio::test]
    async fn ipv6_syn_gets_ipv6_syn_ack() {
        let (mut tcp, io) = manager().await;
        let client: IpAddr = "fdfe:dcba:9876::1".parse().unwrap();
        let target: IpAddr = "2606:4700:3037::2".parse().unwrap();
        let syn = build_packet(client, target, 40000, 443, 1000, 0, SYN, &[]);
        tcp.handle_packet6(&syn);

        let out = io.lock().unwrap().out.clone();
        assert!(!out.is_empty(), "expected a SYN-ACK, not a silent drop");
        assert_eq!(out[0] >> 4, 6, "reply must be IPv6, not an ICMP refusal");
        assert_eq!(out[6], 6, "reply must carry TCP");
        let reply = parse_tcp(&out, 40).expect("tcp header at offset 40");
        assert_eq!(reply.flags & (SYN | ACK), SYN | ACK);
        assert_eq!(reply.ack, 1001);
        assert_eq!((reply.src_port, reply.dst_port), (443, 40000));
        // IPv6 spends 20 more header bytes, so MSS drops from 1460 to 1440.
        assert_eq!(&out[60..64], &[2, 4, 0x05, 0xa0]);
        let IpAddr::V6(s6) = target else {
            unreachable!()
        };
        let IpAddr::V6(d6) = client else {
            unreachable!()
        };
        assert_eq!(verify_checksum6(s6, d6, 6, &out[40..]), 0);
    }

    #[test]
    fn v6_flow_key_targets_ipv6_address() {
        let key = FlowKey {
            client_ip: "fdfe:dcba:9876::1".parse().unwrap(),
            client_port: 40000,
            target_ip: "2606:4700:3037::2".parse().unwrap(),
            target_port: 443,
        };
        assert_eq!(key_target_addr(&key).address(), "[2606:4700:3037::2]:443");
    }
}
