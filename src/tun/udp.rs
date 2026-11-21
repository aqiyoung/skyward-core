//! UDP session manager for the TUN stack.
//!
//! Each (source, destination) pair gets a session: an outbound packet
//! connection dialed through the rule pipeline, a pump task in each
//! direction, and an idle timeout. Replies are written back into the
//! TUN device as fresh IPv4/UDP packets. Before this existed, non-DNS
//! UDP was refused with ICMP port-unreachable so apps fell back to
//! TCP; now QUIC, voice, and game traffic can flow for real. When a
//! session cannot be dialed at all (the chosen outbound cannot carry
//! UDP), the first datagram is still refused with ICMP port-unreachable
//! so the app falls back to TCP immediately instead of retrying its
//! QUIC handshake into a black hole.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::mpsc;

use crate::common::TargetAddr;
use crate::tunnel::Engine;

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const DIAL_TIMEOUT: Duration = Duration::from_secs(10);

/// Fold session bytes into the global totals (and the proxy-only subset when
/// the session left through a real outbound), matching what TCP does at its
/// relay.
fn account(engine: &Engine, final_name: &str, bytes: u64, upload: bool) {
    let proxied = crate::common::is_proxied_outbound(final_name);
    if upload {
        engine.traffic.add_upload(bytes);
        if proxied {
            engine.traffic.add_proxy_upload(bytes);
        }
    } else {
        engine.traffic.add_download(bytes);
        if proxied {
            engine.traffic.add_proxy_download(bytes);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct SessionKey {
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
}

pub struct UdpManager<T> {
    engine: Arc<Engine>,
    io: Arc<Mutex<T>>,
    sessions: Arc<Mutex<HashMap<SessionKey, mpsc::Sender<Vec<u8>>>>>,
    tasks: Mutex<tokio::task::JoinSet<()>>,
}

impl<T: Read + Write + Send + 'static> UdpManager<T> {
    pub fn new(engine: Arc<Engine>, io: Arc<Mutex<T>>) -> Self {
        UdpManager {
            engine, io, sessions: Arc::new(Mutex::new(HashMap::new())),
            tasks: Mutex::new(tokio::task::JoinSet::new()),
        }
    }

    pub async fn shutdown(&mut self) {
        self.tasks.get_mut().unwrap().shutdown().await;
        self.sessions.lock().unwrap().clear();
    }

    /// Forward one outbound UDP payload from the TUN.
    pub fn handle_packet(&self, src: IpAddr, src_port: u16, dst: IpAddr, dst_port: u16, payload: &[u8]) {
        let key = SessionKey { src, src_port, dst, dst_port };
        let sender = {
            let mut sessions = self.sessions.lock().unwrap();
            if let Some(sender) = sessions.get(&key) {
                sender.clone()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(64);
                sessions.insert(key, tx.clone());
                // The first payload travels with the session task: if the
                // dial fails it is the datagram the ICMP refusal answers.
                self.spawn_session(key, rx, payload.to_vec());
                return;
            }
        };
        // A full queue means the session is wedged; dropping one packet
        // is better than stalling the whole TUN loop.
        let _ = sender.try_send(payload.to_vec());
    }

    fn spawn_session(&self, key: SessionKey, mut rx: mpsc::Receiver<Vec<u8>>, first_payload: Vec<u8>) {
        let fallback_engine = self.engine.clone();
        let io = self.io.clone();
        let sessions = self.sessions.clone();
        let mut tasks = self.tasks.lock().unwrap();
        while tasks.try_join_next().is_some() {}
        tasks.spawn(async move {
            let engine = crate::runtime_state::engine().await.unwrap_or(fallback_engine);
            // Fake IPs are IPv4 for now; v6 destinations route by address.
            let target = match key.dst {
                IpAddr::V4(v4) => match crate::fake_ip::hostname_for(v4) {
                    Some(host) => TargetAddr::Domain(host, key.dst_port),
                    None => TargetAddr::Ip(IpAddr::V4(v4), key.dst_port),
                },
                IpAddr::V6(v6) => TargetAddr::Ip(IpAddr::V6(v6), key.dst_port),
            };
            let (conn, route, final_name) = match tokio::time::timeout(DIAL_TIMEOUT, engine.dial_udp(&target)).await {
                Ok(Ok(dialed)) => dialed,
                Ok(Err(e)) => {
                    crate::tun::runtime::diag_udp(format!(
                        "udp session {}:{} -> {} failed: {}",
                        key.src, key.src_port, target.address(), e
                    ));
                    refuse(&io, &key, first_payload.len());
                    sessions.lock().unwrap().remove(&key);
                    return;
                }
                Err(_) => {
                    crate::tun::runtime::diag_udp(format!(
                        "udp session {}:{} -> {} dial timed out",
                        key.src, key.src_port, target.address()
                    ));
                    refuse(&io, &key, first_payload.len());
                    sessions.lock().unwrap().remove(&key);
                    return;
                }
            };
            // Register with the connection tracker like a TCP flow, so UDP
            // sessions show up in the App's connection and request lists.
            let (connection, up_counter, down_counter) = engine
                .connections
                .add(
                    &target,
                    &route.rule,
                    &route.payload,
                    route.chains(&final_name),
                    crate::tunnel::connection::Network::Udp,
                    Some((key.src.to_string(), key.src_port)),
                    Some(key.dst),
                )
                .await;
            let relay = async {
            if let Err(e) = conn.send(&first_payload).await {
                crate::tun::runtime::diag_udp(format!(
                    "udp session {}:{} -> {} first send failed: {}",
                    key.src, key.src_port, target.address(), e
                ));
                return;
            }
            up_counter.fetch_add(first_payload.len() as u64, Ordering::Relaxed);
            account(&engine, &final_name, first_payload.len() as u64, true);
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
                                Some(data) => conn.send(&data).await.map(|_| {
                                    up_counter.fetch_add(data.len() as u64, Ordering::Relaxed);
                                    account(&engine, &final_name, data.len() as u64, true);
                                    true
                                }),
                                None => Ok(false),
                            }
                        }
                        incoming = conn.recv(&mut buf) => {
                            match incoming {
                                Ok(n) => {
                                    down_counter.fetch_add(n as u64, Ordering::Relaxed);
                                    account(&engine, &final_name, n as u64, false);
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
            };
            tokio::select! {
                biased;
                _ = connection.closed() => {}
                _ = relay => {}
            }
            sessions.lock().unwrap().remove(&key);
        });
    }
}

/// Answer a datagram that could not be relayed with an ICMP
/// port-unreachable, rate-limited like the runtime's other refusals, so
/// the sending app gives up on QUIC and falls back to TCP at once.
fn refuse<T: Write>(io: &Arc<Mutex<T>>, key: &SessionKey, payload_len: usize) {
    if !crate::tun::runtime::icmp_budget() {
        return;
    }
    if let Some(packet) = refuse_packet(key, payload_len) {
        if io.lock().unwrap().write_all(&packet).is_ok() {
            crate::tun::runtime::diag_udp(format!(
                "udp refuse {}:{} -> {}:{} (icmp port-unreachable)",
                key.src, key.src_port, key.dst, key.dst_port
            ));
        }
    }
}

/// The refusal quotes a synthetic copy of the triggering datagram; the IP
/// and UDP headers are all the receiving stack matches on.
fn refuse_packet(key: &SessionKey, payload_len: usize) -> Option<Vec<u8>> {
    match (key.src, key.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut original = vec![0u8; 28];
            original[0] = 0x45;
            original[2..4].copy_from_slice(&((28 + payload_len) as u16).to_be_bytes());
            original[8] = 64;
            original[9] = 17;
            original[12..16].copy_from_slice(&src.octets());
            original[16..20].copy_from_slice(&dst.octets());
            original[20..22].copy_from_slice(&key.src_port.to_be_bytes());
            original[22..24].copy_from_slice(&key.dst_port.to_be_bytes());
            original[24..26].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
            crate::tun::tcp::build_icmp_port_unreachable(&original, 20)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut original = vec![0u8; 48];
            original[0] = 0x60;
            original[4..6].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
            original[6] = 17;
            original[7] = 64;
            original[8..24].copy_from_slice(&src.octets());
            original[24..40].copy_from_slice(&dst.octets());
            original[40..42].copy_from_slice(&key.src_port.to_be_bytes());
            original[42..44].copy_from_slice(&key.dst_port.to_be_bytes());
            original[44..46].copy_from_slice(&((8 + payload_len) as u16).to_be_bytes());
            crate::tun::runtime::build_icmp6_unreachable(&original, 4)
        }
        _ => None,
    }
}

/// Build a complete UDP packet carrying `payload` from (src, src_port) to
/// (dst, dst_port) over either address family.
pub fn build_udp_reply(
    src: IpAddr,
    src_port: u16,
    dst: IpAddr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    crate::tun::tcp::build_udp_packet(src, dst, src_port, dst_port, payload)
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

    #[test]
    fn udp_reply_and_refusal_exist_for_both_families() {
        let v6 = build_udp_reply(
            "fd00::1".parse().unwrap(),
            53,
            "2001:db8::1".parse().unwrap(),
            443,
            b"abc",
        );
        assert_eq!(v6[0], 0x60);
        assert_eq!(super::super::tcp::parse_ipv6(&v6).unwrap().proto, 17);

        let key = SessionKey {
            src: "fd00::1".parse().unwrap(),
            src_port: 53210,
            dst: "2001:db8::9".parse().unwrap(),
            dst_port: 443,
        };
        let packet = refuse_packet(&key, 1200).unwrap();
        assert_eq!(packet[0], 0x60);
        assert_eq!(packet[6], 58); // next header: ICMPv6
        assert_eq!(packet[40], 1); // destination unreachable
        assert_eq!(packet[41], 4); // port unreachable
    }

    #[test]
    fn refuse_packet_is_icmp_port_unreachable() {
        let key = SessionKey {
            src: "198.18.0.1".parse().unwrap(),
            src_port: 53210,
            dst: "198.18.0.9".parse().unwrap(),
            dst_port: 443,
        };
        let packet = refuse_packet(&key, 1200).unwrap();
        assert_eq!(packet[0], 0x45);
        assert_eq!(packet[9], 1); // ICMP
        assert_eq!(&packet[12..16], &[198, 18, 0, 9]); // from the target
        assert_eq!(&packet[16..20], &[198, 18, 0, 1]); // to the app
        assert_eq!(packet[20], 3); // destination unreachable
        assert_eq!(packet[21], 3); // port unreachable
        // The quote carries the original UDP header (ports the app matches).
        assert_eq!(&packet[48..50], &53210u16.to_be_bytes());
        assert_eq!(&packet[50..52], &443u16.to_be_bytes());
    }
}
