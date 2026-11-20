//! UDP session manager for the TUN stack.
//!
//! Each (source, destination) pair gets a session: an outbound packet
//! connection dialed through the rule pipeline, a pump task in each
//! direction, and an idle timeout. Replies are written back into the
//! TUN device as fresh IPv4/UDP packets. Before this existed, non-DNS
//! UDP was refused with ICMP port-unreachable so apps fell back to
//! TCP; now QUIC, voice, and game traffic can flow for real.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::common::TargetAddr;
use crate::tunnel::Engine;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
}

pub struct UdpManager<T> {
    engine: Arc<Engine>,
    io: Arc<Mutex<T>>,
    sessions: Arc<Mutex<HashMap<SessionKey, mpsc::Sender<Vec<u8>>>>>,
}

impl<T: Read + Write + Send + 'static> UdpManager<T> {
    pub fn new(engine: Arc<Engine>, io: Arc<Mutex<T>>) -> Self {
        UdpManager { engine, io, sessions: Arc::new(Mutex::new(HashMap::new())) }
    }

    /// Forward one outbound UDP payload from the TUN.
    pub fn handle_packet(&self, src: Ipv4Addr, src_port: u16, dst: Ipv4Addr, dst_port: u16, payload: &[u8]) {
        let key = SessionKey { src, src_port, dst, dst_port };
        let sender = {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(sender) = sessions.get(&key) {
                sender.clone()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                sessions.insert(key, tx.clone());
                self.spawn_session(key, rx);
                tx
            }
        };
        // A full queue means the session is wedged; dropping one packet
        // is better than stalling the whole TUN loop.
        let _ = sender.try_send(payload.to_vec());
    }

    fn spawn_session(&self, key: SessionKey, mut rx: mpsc::Receiver<Vec<u8>>) {
        let engine = self.engine.clone();
        let io = self.io.clone();
        let sessions = self.sessions.clone();
        tokio::spawn(async move {
            let target = match crate::fake_ip::hostname_for(key.dst) {
                Some(host) => TargetAddr::Domain(host, key.dst_port),
                None => TargetAddr::Ip(key.dst.into(), key.dst_port),
            };
            let conn = match tokio::time::timeout(DIAL_TIMEOUT, engine.dial_udp(&target)).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    crate::tun::runtime::diag_udp(format!(
                        "udp session {}:{} -> {} failed: {}",
                        key.src, key.src_port, target.address(), e
                    ));
                    sessions.lock().unwrap().remove(&key);
                    return;
                }
                Err(_) => {
                    crate::tun::runtime::diag_udp(format!(
                        "udp session {}:{} -> {} dial timed out",
                        key.src, key.src_port, target.address()
                    ));
                    sessions.lock().unwrap().remove(&key);
                    return;
                }
            };
            crate::tun::runtime::diag_udp(format!(
                "udp session {}:{} -> {} open",
                key.src, key.src_port, target.address()
            ));
            let mut buf = vec![0u8; 65536];
            loop {
                let step = tokio::time::timeout(IDLE_TIMEOUT, async {
                    tokio::select! {
                        outgoing = rx.recv() => {
                            match outgoing {
                                Some(data) => conn.send(&data).await.map(|_| true),
                                None => Ok(false),
                            }
                        }
                        incoming = conn.recv(&mut buf) => {
                            match incoming {
                                Ok(n) => {
                                    let packet = build_udp_reply(
                                        key.dst, key.dst_port, key.src, key.src_port, &buf[..n],
                                    );
                                    let _ = io.lock().unwrap().write_all(&packet);
                                    Ok(true)
                                }
                                Err(e) => Err(e),
                            }
                        }
                    }
                })
                .await;
                match step {
                    Ok(Ok(true)) => {}
                    Ok(Ok(false)) => break, // sender side closed
                    Ok(Err(_)) => break,    // session transport failed
                    Err(_) => break,        // idle timeout
                }
            }
            sessions.lock().unwrap().remove(&key);
        });
    }
}

/// Build a complete IPv4/UDP packet carrying `payload` from
/// (src, src_port) to (dst, dst_port), with both checksums filled in.
pub fn build_udp_reply(
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut packet = vec![0u8; total_len];
    packet[0] = 0x45; // version + IHL
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    packet[4..6].copy_from_slice(&id.to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 17; // UDP
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let ip_sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    packet[20..22].copy_from_slice(&src_port.to_be_bytes());
    packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let udp_sum = checksum_udp(src, dst, &packet[20..]);
    packet[26..28].copy_from_slice(&(if udp_sum == 0 { 0xffff } else { udp_sum }).to_be_bytes());
    packet
}

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let Some(&last) = chunks.remainder().first() {
        sum += (last as u32) << 8;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_udp(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(udp);
    checksum(&pseudo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_reply_checksums_verify() {
        let packet = build_udp_reply(
            "1.2.3.4".parse().unwrap(),
            53,
            "10.0.0.2".parse().unwrap(),
            5353,
            b"hello",
        );
        assert_eq!(packet.len(), 20 + 8 + 5);
        assert_eq!(checksum(&packet[..20]), 0);
        assert_eq!(
            checksum_udp("1.2.3.4".parse().unwrap(), "10.0.0.2".parse().unwrap(), &packet[20..]),
            0
        );
        assert_eq!(&packet[28..], b"hello");
    }
}
