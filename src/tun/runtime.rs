//! Async runtime loop that owns the TUN device.
//!
//! Incoming IP packets are dispatched by protocol: TCP is terminated by our own
//! minimal state machine (see `tcp`), and DNS queries are answered directly.
//! smoltcp cannot be used for the TUN's TCP because its sockets only accept
//! connections matching a port that is already listening, which a transparent
//! proxy cannot know in advance.

use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use super::tcp::TcpManager;
use super::{TunConfig, TunDevice};
use crate::tunnel::Engine;

/// Drive the TUN device until `cancel` is notified.
pub async fn run<T>(
    device: TunDevice<T>,
    config: TunConfig,
    engine: Arc<Engine>,
    wake: Arc<Notify>,
    cancel: Arc<Notify>,
) where
    T: Read + Write + Send + 'static,
{
    let _ = &config;
    let io = Arc::new(Mutex::new(device.io));
    let mut tcp = TcpManager::new(engine.clone(), io.clone());
    let mut buf = vec![0u8; 65536];

    loop {
        let read = {
            let mut guard = io.lock().unwrap();
            guard.read(&mut buf)
        };
        match read {
            Ok(0) => {}
            Ok(n) => handle_packet(&buf[..n], &mut tcp, &engine, &io),
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(_) => {}
        }

        tcp.pump();

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            _ = wake.notified() => {}
            _ = cancel.notified() => {
                tcp.shutdown();
                return;
            }
        }
    }
}

fn handle_packet<T: Read + Write + Send + 'static>(
    packet: &[u8],
    tcp: &mut TcpManager<T>,
    engine: &Arc<Engine>,
    io: &Arc<Mutex<T>>,
) {
    let Some(ip) = super::tcp::parse_ipv4(packet) else { return };
    match ip.proto {
        6 => tcp.handle_packet(packet),
        17 => handle_dns_packet(packet, &ip, engine, io),
        _ => {}
    }
}

/// Answer a DNS query that arrived on the TUN. Resolution runs on a spawned
/// task because the resolver performs network I/O.
fn handle_dns_packet<T: Read + Write + Send + 'static>(
    packet: &[u8],
    ip: &super::tcp::Ipv4Info,
    engine: &Arc<Engine>,
    io: &Arc<Mutex<T>>,
) {
    let udp = match packet.get(ip.ihl..) {
        Some(u) if u.len() >= 8 => u,
        _ => return,
    };
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let end = udp.len().min(len);
    let payload = &udp[8..end];
    let Some((qname, qtype)) = parse_dns_question(payload) else { return };
    let name = String::from_utf8_lossy(&qname).into_owned();

    let resolver = engine.resolver.clone();
    let io = io.clone();
    let src_ip = ip.src;
    let dst_ip = ip.dst;
    let query = payload.to_vec();
    tokio::spawn(async move {
        let answer_ip = match resolver.resolve(&name).await {
            Ok(addrs) => addrs.into_iter().find(|ip| match qtype {
                28 => ip.is_ipv6(),
                _ => ip.is_ipv4(),
            }),
            Err(_) => None,
        };
        let response = build_dns_response(&query, answer_ip);
        let packet = super::tcp::build_udp_packet(src_ip, dst_ip, 53, src_port, &response);
        let mut io = io.lock().unwrap();
        let _ = io.write_all(&packet);
    });
}

fn parse_dns_question(packet: &[u8]) -> Option<(Vec<u8>, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    while pos < packet.len() {
        let len = packet[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        if pos + len > packet.len() {
            return None;
        }
        // Replace dots embedded in labels to avoid ambiguity when joining.
        for &b in &packet[pos..pos + len] {
            labels.push(if b == b'.' { b'-' } else { b });
        }
        labels.push(b'.');
        pos += len;
    }
    if pos + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    Some((labels, qtype))
}

fn build_dns_response(query: &[u8], answer_ip: Option<std::net::IpAddr>) -> Vec<u8> {
    let mut out = query.to_vec();
    if out.len() < 12 {
        return out;
    }
    // QR=1, AA=1, RD preserved, RA=1.
    out[2] = (out[2] | 0x84) & 0xfb;
    out[3] |= 0x80;
    let answers: u16 = if answer_ip.is_some() { 1 } else { 0 };
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT placeholder
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());

    if let Some(ip) = answer_ip {
        // Find the end of the question section.
        let mut pos = 12;
        while pos < out.len() && out[pos] != 0 {
            pos += 1 + out[pos] as usize;
        }
        pos += 1; // skip root label
        pos += 4; // skip QTYPE + QCLASS
        if pos <= out.len() {
            // Name pointer to the question name at offset 12.
            out.extend_from_slice(&0xc00cu16.to_be_bytes());
            match ip {
                std::net::IpAddr::V4(v4) => {
                    out.extend_from_slice(&1u16.to_be_bytes()); // A
                    out.extend_from_slice(&1u16.to_be_bytes()); // IN
                    out.extend_from_slice(&60u32.to_be_bytes()); // TTL
                    out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                    out.extend_from_slice(&v4.octets());
                }
                std::net::IpAddr::V6(v6) => {
                    out.extend_from_slice(&28u16.to_be_bytes()); // AAAA
                    out.extend_from_slice(&1u16.to_be_bytes());
                    out.extend_from_slice(&60u32.to_be_bytes());
                    out.extend_from_slice(&16u16.to_be_bytes());
                    out.extend_from_slice(&v6.octets());
                }
            }
            out[6..8].copy_from_slice(&answers.to_be_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The loop must stay alive while the device is open and release the
    // descriptor on cancellation.
    #[cfg(unix)]
    #[tokio::test]
    async fn tun_runtime_keeps_descriptor_open_until_cancelled() {
        use std::os::unix::net::UnixStream;

        let (local, mut peer) = UnixStream::pair().unwrap();
        local.set_nonblocking(true).unwrap();
        peer.set_nonblocking(true).unwrap();
        let config = TunConfig::parse(
            "mips", "198.18.0.1/30", "198.18.0.2",
            r#"{"mtu":9000,"congestion-controller":"cubic"}"#,
        ).unwrap();
        let engine = Arc::new(Engine::new(
            crate::config::Config::default(),
            Arc::new(crate::common::TrafficStats::default()),
            std::path::Path::new("."),
        ).await);
        let cancel = Arc::new(Notify::new());
        let mut task = tokio::spawn(run(
            TunDevice::new(local, config.options.mtu), config, engine,
            Arc::new(Notify::new()), cancel.clone(),
        ));
        assert!(tokio::time::timeout(Duration::from_millis(300), &mut task).await.is_err(),
            "TUN loop exited during startup");
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
        cancel.notify_one();
        task.await.unwrap();
        assert_eq!(peer.read(&mut byte).unwrap(), 0, "cancellation must close the device");
    }

    fn dns_query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.').filter(|x| !x.is_empty()) {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    #[test]
    fn parses_question() {
        let q = dns_query("www.example.com", 1);
        let (name, qtype) = parse_dns_question(&q).unwrap();
        assert_eq!(name, b"www.example.com.");
        assert_eq!(qtype, 1);
    }

    #[test]
    fn builds_a_response() {
        let q = dns_query("example.com", 1);
        let resp = build_dns_response(&q, Some("1.2.3.4".parse().unwrap()));
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]) & 0x8000, 0x8000); // QR bit
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // one answer
        assert!(resp.windows(4).any(|w| w == [1, 2, 3, 4]));
    }

    #[test]
    fn nxdomain_has_no_answers() {
        let q = dns_query("nonexistent.invalid", 1);
        let resp = build_dns_response(&q, None);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn ipv4_info_parses_header() {
        let packet = super::tcp::build_udp_packet(
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 18, 0, 2),
            12345,
            53,
            &[0xaa, 0xbb],
        );
        let info = super::tcp::parse_ipv4(&packet).unwrap();
        assert_eq!(info.proto, 17);
        assert_eq!(info.src, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(info.dst, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(info.ihl, 20);
    }
}
