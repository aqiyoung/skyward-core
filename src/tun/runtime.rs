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
    let io = Arc::new(Mutex::new(device.io));
    let mut tcp = TcpManager::new(engine, io.clone());
    tcp.set_mtu(config.options.mtu);
    let mut buf = vec![0u8; 65536];

    loop {
        // Drain every packet the device has queued before sleeping: reading
        // a single packet per cycle and then sleeping 10 ms capped the TUN
        // at ~100 packets/s, which strangles ACK clocking and throughput.
        let mut drained = 0usize;
        loop {
            let read = {
                let mut guard = io.lock().unwrap();
                guard.read(&mut buf)
            };
            match read {
                Ok(n) if n > 0 => {
                    handle_packet(&buf[..n], &mut tcp, &io);
                    drained += 1;
                    if drained >= 512 {
                        break;
                    }
                }
                _ => break,
            }
        }

        tcp.pump();

        if drained > 0 {
            // Busy: loop again immediately, but still honour cancellation.
            tokio::select! {
                _ = std::future::ready(()) => {}
                _ = cancel.notified() => {
                    tcp.shutdown();
                    return;
                }
            }
            continue;
        }

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

/// Rate-limited diagnostics for the DNS path.
fn diag(message: String) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 80 {
        crate::jni::emit_log_event(&format!("[rust-core] {}", message));
    }
}

fn handle_packet<T: Read + Write + Send + 'static>(
    packet: &[u8],
    tcp: &mut TcpManager<T>,
    io: &Arc<Mutex<T>>,
) {
    let Some(ip) = super::tcp::parse_ipv4(packet) else {
        return;
    };
    match ip.proto {
        6 => tcp.handle_packet(packet),
        17 => handle_dns_packet(packet, &ip, io),
        _ => {}
    }
}

/// Answer a DNS query that arrived on the TUN with a fake-ip immediately.
fn handle_dns_packet<T: Read + Write + Send + 'static>(
    packet: &[u8],
    ip: &super::tcp::Ipv4Info,
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
    let Some(payload) = udp.get(8..len) else {
        return;
    };
    let Some((qname, qtype)) = parse_dns_question(payload) else {
        return;
    };
    let name = String::from_utf8_lossy(&qname);
    diag(format!("DNS query {} type {}", name, qtype));

    let answer_ip = match qtype {
        1 => Some(std::net::IpAddr::V4(crate::fake_ip::fake_ip_for(
            name.trim_end_matches('.'),
        ))),
        _ => None,
    };
    let response = build_dns_response(payload, answer_ip);
    let packet = crate::tun::tcp::build_udp_packet(ip.dst, ip.src, 53, src_port, &response);
    if let Err(e) = io.lock().unwrap().write_all(&packet) {
        tracing::debug!("TUN DNS reply write failed: {}", e);
    }
}

fn parse_dns_question(packet: &[u8]) -> Option<(Vec<u8>, u16)> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
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
        if len > 63 || pos + len > packet.len() {
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
    let mut pos = 12;
    while pos < out.len() && out[pos] != 0 {
        pos += 1 + out[pos] as usize;
    }
    pos += 5; // root label, QTYPE and QCLASS
    if pos > out.len() {
        return out;
    }
    // Drop request-only sections (e.g. an EDNS OPT) before appending answers.
    out.truncate(pos);
    // QR=1, AA=1, RD preserved, RA=1.
    out[2] = (out[2] | 0x84) & 0xfb;
    out[3] |= 0x80;
    let answers: u16 = if answer_ip.is_some() { 1 } else { 0 };
    out[6..8].copy_from_slice(&0u16.to_be_bytes()); // ANCOUNT placeholder
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&0u16.to_be_bytes());

    if let Some(ip) = answer_ip {
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
            "mips",
            "198.18.0.1/30",
            "198.18.0.2",
            r#"{"mtu":9000,"congestion-controller":"cubic"}"#,
        )
        .unwrap();
        let engine = Arc::new(
            Engine::new(
                crate::config::Config::default(),
                Arc::new(crate::common::TrafficStats::default()),
                std::path::Path::new("."),
            )
            .await,
        );
        let cancel = Arc::new(Notify::new());
        let mut task = tokio::spawn(run(
            TunDevice::new(local, config.options.mtu),
            config,
            engine,
            Arc::new(Notify::new()),
            cancel.clone(),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut task)
                .await
                .is_err(),
            "TUN loop exited during startup"
        );
        let mut byte = [0];
        assert_eq!(
            peer.read(&mut byte).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        cancel.notify_one();
        task.await.unwrap();
        assert_eq!(
            peer.read(&mut byte).unwrap(),
            0,
            "cancellation must close the device"
        );
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
    fn dns_reply_reverses_endpoints_and_drops_query_opt() {
        let client = Ipv4Addr::new(198, 18, 0, 1);
        let dns = Ipv4Addr::new(198, 18, 0, 2);
        let mut query = dns_query("reply.example", 1);
        let question_end = query.len();
        query[11] = 1;
        query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
        let packet = super::super::tcp::build_udp_packet(client, dns, 12345, 53, &query);
        let header = super::super::tcp::parse_ipv4(&packet).unwrap();
        let io = Arc::new(Mutex::new(std::io::Cursor::new(Vec::new())));
        handle_dns_packet(&packet, &header, &io);
        let io = io.lock().unwrap();
        let reply = io.get_ref();
        let header = super::super::tcp::parse_ipv4(reply).unwrap();
        assert_eq!((header.src, header.dst), (dns, client));
        assert_eq!(&reply[header.ihl..header.ihl + 4], &[0, 53, 0x30, 0x39]);
        let dns_reply = &reply[header.ihl + 8..];
        assert_eq!(dns_reply[11], 0);
        assert_eq!(&dns_reply[question_end..question_end + 2], &[0xc0, 0x0c]);
        let fake_ip = Ipv4Addr::from(<[u8; 4]>::try_from(&dns_reply[question_end + 12..]).unwrap());
        assert_eq!(
            crate::fake_ip::hostname_for(fake_ip).as_deref(),
            Some("reply.example")
        );
    }

    #[test]
    fn nxdomain_has_no_answers() {
        let q = dns_query("nonexistent.invalid", 1);
        let resp = build_dns_response(&q, None);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn ipv4_info_parses_header() {
        let packet = crate::tun::tcp::build_udp_packet(
            Ipv4Addr::new(198, 18, 0, 1),
            Ipv4Addr::new(198, 18, 0, 2),
            12345,
            53,
            &[0xaa, 0xbb],
        );
        let info = crate::tun::tcp::parse_ipv4(&packet).unwrap();
        assert_eq!(info.proto, 17);
        assert_eq!(info.src, Ipv4Addr::new(198, 18, 0, 1));
        assert_eq!(info.dst, Ipv4Addr::new(198, 18, 0, 2));
        assert_eq!(info.ihl, 20);
    }
}
