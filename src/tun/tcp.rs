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
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub client_ip: Ipv4Addr,
    pub client_port: u16,
    pub target_ip: Ipv4Addr,
    pub target_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    SynReceived,
    Established,
    Closed,
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
}

pub struct TcpManager<T> {
    flows: HashMap<FlowKey, Flow>,
    engine: Arc<Engine>,
    io: Arc<Mutex<T>>,
}

impl<T: Read + Write + Send + 'static> TcpManager<T> {
    pub fn new(engine: Arc<Engine>, io: Arc<Mutex<T>>) -> Self {
        Self {
            flows: HashMap::new(),
            engine,
            io,
        }
    }

    /// Handle one raw IPv4 packet read from the TUN.
    pub fn handle_packet(&mut self, packet: &[u8]) {
        let Some(ip) = parse_ipv4(packet) else { return };
        if ip.proto != 6 {
            return;
        }
        let Some(tcp) = parse_tcp(packet, ip.ihl) else { return };
        let key = FlowKey {
            client_ip: ip.src,
            client_port: tcp.src_port,
            target_ip: ip.dst,
            target_port: tcp.dst_port,
        };

        if tcp.flags & SYN != 0 && tcp.flags & ACK == 0 {
            if let Some(flow) = self.flows.get(&key) {
                if flow.state == State::SynReceived {
                    // Retransmitted SYN: answer with the same SYN-ACK.
                    let (isn, client_next) = (flow.local_isn, flow.client_next);
                    self.send(key, isn, client_next, SYN | ACK, &[]);
                }
                return;
            }
            let isn: u32 = rand::random();
            let flow = Flow {
                key,
                state: State::SynReceived,
                local_isn: isn,
                local_next: isn.wrapping_add(1),
                client_next: tcp.seq.wrapping_add(1),
                to_net: Arc::new(ByteQueue::new()),
                from_net: Arc::new(ByteQueue::new()),
                cancel: Arc::new(Notify::new()),
                done: Arc::new(AtomicBool::new(false)),
            };
            self.send(key, isn, flow.client_next, SYN | ACK, &[]);
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
        let action = {
            let Some(flow) = self.flows.get_mut(&key) else {
                // Not ours (or already gone): reject so the client stops retrying.
                self.send(key, tcp.ack, tcp.seq, RST | ACK, &[]);
                return;
            };

            if flow.state == State::SynReceived && tcp.flags & ACK != 0 {
                flow.state = State::Established;
            }

            if tcp.flags & FIN != 0 {
                flow.state = State::Closed;
                Some((flow.local_next, tcp.seq.wrapping_add(1), true))
            } else {
                let payload = tcp.payload(packet, ip.ihl);
                if payload.is_empty() {
                    None
                } else {
                    let n = payload.len() as u32;
                    flow.client_next = flow.client_next.wrapping_add(n);
                    flow.to_net.push(payload);
                    Some((flow.local_next, flow.client_next, false))
                }
            }
        };

        if let Some((seq, ack, fin)) = action {
            self.send(key, seq, ack, ACK, &[]);
            if fin {
                self.send(key, seq, ack, FIN | ACK, &[]);
                self.remove(&key);
            }
        }
    }

    /// Push bytes received from outbounds back into the TUN.
    pub fn pump(&mut self) {
        let mut ready = Vec::new();
        for (key, flow) in self.flows.iter() {
            let n = flow.from_net.len();
            if n > 0 {
                ready.push((*key, n));
            }
        }
        for (key, _) in ready {
            let Some(flow) = self.flows.get(&key) else { continue };
            let mut buf = vec![0u8; 16 * 1024];
            let n = flow.from_net.pop(&mut buf);
            if n > 0 {
                let seq = flow.local_next;
                let ack = flow.client_next;
                self.send(key, seq, ack, PSH | ACK, &buf[..n]);
                if let Some(flow) = self.flows.get_mut(&key) {
                    flow.local_next = flow.local_next.wrapping_add(n as u32);
                }
            }
        }
        // Drop flows whose relay task has finished.
        let dead: Vec<FlowKey> = self
            .flows
            .iter()
            .filter(|(_, f)| f.done.load(Ordering::Relaxed) && f.from_net.is_empty())
            .map(|(k, _)| *k)
            .collect();
        for key in dead {
            self.remove(&key);
        }
    }

    /// Stop every relay; used when the VPN goes down.
    pub fn shutdown(&mut self) {
        for flow in self.flows.values() {
            flow.cancel.notify_one();
        }
        self.flows.clear();
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
        let engine = self.engine.clone();
        let io = self.io.clone();
        let addr = format!("{}:{}", key.target_ip, key.target_port);
        let target = match addr.parse::<IpAddr>() {
            Ok(ip) => TargetAddr::Ip(ip, key.target_port),
            Err(_) => return,
        };
        tokio::spawn(async move {
            let mut stream: BoxedStream = match tokio::select! {
                _ = cancel.notified() => return,
                result = engine.dial(&target) => result,
            } {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!("TUN flow {} dial failed: {}", addr, e);
                    return;
                }
            };
            let mut read_buf = vec![0u8; 16 * 1024];
            loop {
                let mut write_buf = vec![0u8; 16 * 1024];
                let n = to_net.pop(&mut write_buf);
                if n > 0 {
                    if stream.write_all(&write_buf[..n]).await.is_err() {
                        break;
                    }
                    continue;
                }
                tokio::select! {
                    _ = cancel.notified() => break,
                    _ = to_net.notified() => {}
                    result = stream.read(&mut read_buf) => match result {
                        Ok(0) | Err(_) => break,
                        Ok(n) => from_net.push(&read_buf[..n]),
                    }
                }
            }
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
        }
    }
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

struct TcpHeader {
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    data_offset: usize,
}

impl TcpHeader {
    fn payload<'a>(&self, packet: &'a [u8], ihl: usize) -> &'a [u8] {
        let start = ihl + self.data_offset;
        if start >= packet.len() {
            return &[];
        }
        &packet[start..]
    }
}

fn parse_tcp(packet: &[u8], ihl: usize) -> Option<TcpHeader> {
    let p = &packet[ihl..];
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
    })
}

/// Build a complete IPv4/TCP packet with valid checksums.
fn build_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut ip = [0u8; 20];
    let total_len = 40 + payload.len();
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF
    ip[8] = 64;
    ip[9] = 6;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut tcp = vec![0u8; 20 + payload.len()];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&seq.to_be_bytes());
    tcp[8..12].copy_from_slice(&ack.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&WINDOW.to_be_bytes());
    tcp[20..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&tcp);
    let tcp_checksum = checksum(&pseudo);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&tcp);
    out
}

/// Build an IPv4/UDP packet with valid checksums.
pub(crate) fn build_udp_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut ip = [0u8; 20];
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_checksum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut udp = vec![0u8; udp_len];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[8..].copy_from_slice(payload);

    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pseudo.extend_from_slice(&udp);
    let udp_checksum = checksum(&pseudo);
    udp[6..8].copy_from_slice(&udp_checksum.to_be_bytes());

    let mut out = Vec::with_capacity(total_len);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&udp);
    out
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
        client: Ipv4Addr,
        target: Ipv4Addr,
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
    async fn syn_is_answered_with_syn_ack() {
        let (mut tcp, io) = manager().await;
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let target = Ipv4Addr::new(1, 1, 1, 1);
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
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let target = Ipv4Addr::new(127, 0, 0, 1);
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
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let target = Ipv4Addr::new(9, 9, 9, 9);
        let pkt = client_packet(client, target, 40000, 443, 500, 0, ACK, &[]);
        tcp.handle_packet(&pkt);
        let out = io.lock().unwrap().out.clone();
        let reply = parse_tcp(&out, 20).expect("reset packet");
        assert_eq!(reply.flags & RST, RST);
    }

    #[tokio::test]
    async fn fin_completes_the_flow() {
        let (mut tcp, io) = manager().await;
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let target = Ipv4Addr::new(127, 0, 0, 1);
        let (cport, tport) = (40000u16, 1u16);
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1000, 0, SYN, &[]));
        tcp.handle_packet(&client_packet(client, target, cport, tport, 1001, 1, ACK, &[]));
        io.lock().unwrap().out.clear();
        tcp.handle_packet(&client_packet(
            client, target, cport, tport, 1001, 1, FIN | ACK, &[],
        ));
        assert!(tcp.flows.is_empty(), "flow should be gone after FIN");
    }
}
