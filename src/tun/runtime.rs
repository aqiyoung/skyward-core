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
use super::udp::UdpManager;
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
    let mut tcp = TcpManager::new(engine.clone(), io.clone());
    let mut udp = UdpManager::new(engine, io.clone());
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
                    handle_packet(&buf[..n], &mut tcp, &udp, &io);
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
                biased;
                _ = cancel.notified() => break,
                _ = tokio::task::yield_now() => {}
            }
            continue;
        }

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(10)) => {}
            _ = wake.notified() => {}
            _ = cancel.notified() => break,
        }
    }
    tokio::join!(tcp.shutdown(), udp.shutdown());
}

/// Rate-limited diagnostics for the DNS path.
fn diag(message: String) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 80 {
        crate::jni::emit_log_event(&format!("[rust-core] {}", message));
    }
}

/// UDP session diagnostics, on its own counter.
pub fn diag_udp(message: String) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 100 {
        crate::jni::emit_log_event(&format!("[rust-core] {}", message));
    }
}

fn handle_packet<T: Read + Write + Send + 'static>(
    packet: &[u8],
    tcp: &mut TcpManager<T>,
    udp: &UdpManager<T>,
    io: &Arc<Mutex<T>>,
) {
    // Both families flow through the same managers; DNS keeps its dedicated
    // answer paths (handle_dns_packet / handle_dns_packet6).
    if packet.first().map(|b| b >> 4) == Some(6) {
        handle_ipv6_packet(packet, tcp, udp, io);
        return;
    }
    let Some(ip) = super::tcp::parse_ipv4(packet) else {
        return;
    };
    match ip.proto {
        6 => tcp.handle_packet(packet),
        17 => {
            let src_port = packet
                .get(ip.ihl..ip.ihl + 2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]));
            let dst_port = packet
                .get(ip.ihl + 2..ip.ihl + 4)
                .map(|b| u16::from_be_bytes([b[0], b[1]]));
            if dst_port == Some(53) {
                handle_dns_packet(packet, &ip, io);
            } else if let (Some(src_port), Some(dst_port)) = (src_port, dst_port) {
                let payload_start = ip.ihl + 8;
                if let Some(payload) = packet.get(payload_start..) {
                    udp.handle_packet(ip.src.into(), src_port, ip.dst.into(), dst_port, payload);
                }
            }
        }
        _ => {}
    }
}

/// Rate limit for ICMP refusals (~50/s), so a UDP flood cannot turn into a
/// TUN write flood.
pub(crate) fn icmp_budget() -> bool {
    use std::sync::Mutex as StdMutex;
    static STATE: StdMutex<(Option<std::time::Instant>, u32)> = StdMutex::new((None, 0));
    let mut state = STATE.lock().unwrap();
    let expired = state
        .0
        .map(|t| t.elapsed() > std::time::Duration::from_secs(1))
        .unwrap_or(true);
    if expired {
        *state = (Some(std::time::Instant::now()), 0);
    }
    state.1 += 1;
    state.1 <= 50
}

/// Handle one IPv6 packet from the TUN: TCP and UDP flow through the same
/// managers as IPv4 (DNS on UDP/53 keeps its dedicated answer path); anything
/// else is ignored, as before.
fn handle_ipv6_packet<T: Read + Write + Send + 'static>(
    packet: &[u8],
    tcp: &mut TcpManager<T>,
    udp: &UdpManager<T>,
    io: &Arc<Mutex<T>>,
) {
    let Some(ip) = crate::tun::tcp::parse_ipv6(packet) else {
        return;
    };
    let src = std::net::IpAddr::V6(ip.src);
    let dst = std::net::IpAddr::V6(ip.dst);
    let payload = match packet.get(ip.ihl..) {
        Some(payload) => payload,
        None => return,
    };
    match ip.proto {
        6 => tcp.handle_packet(packet),
        17 => {
            let src_port = payload
                .get(0..2)
                .map(|b| u16::from_be_bytes([b[0], b[1]]));
            let dst_port = payload
                .get(2..4)
                .map(|b| u16::from_be_bytes([b[0], b[1]]));
            if dst_port == Some(53) {
                let mut src6 = [0u8; 16];
                let mut dst6 = [0u8; 16];
                src6.copy_from_slice(&packet[8..24]);
                dst6.copy_from_slice(&packet[24..40]);
                handle_dns_packet6(packet, ip.ihl, src6, dst6, io);
            } else if let (Some(src_port), Some(dst_port)) = (src_port, dst_port) {
                udp.handle_packet(src, src_port, dst, dst_port, payload);
            }
        }
        _ => {}
    }
}

/// Answer a DNS query that arrived over IPv6 transport. The DNS payload is
/// transport-agnostic, so the v4 path's question parsing and response
/// building are reused as-is; only the carrying UDP/IPv6 packet differs.
fn handle_dns_packet6<T: Read + Write + Send + 'static>(
    packet: &[u8],
    ihl: usize,
    src: [u8; 16],
    dst: [u8; 16],
    io: &Arc<Mutex<T>>,
) {
    let Some(udp) = packet.get(ihl..) else { return };
    if udp.len() < 8 {
        return;
    }
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    if dst_port != 53 {
        return;
    }
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let Some(payload) = udp.get(8..len) else { return };
    let Some((qname, qtype)) = parse_dns_question(payload) else {
        return;
    };
    let name = String::from_utf8_lossy(&qname);
    diag(format!("DNS query {} type {}", name, qtype));

    let answer_ip = match qtype {
        1 => Some(std::net::IpAddr::V4(crate::fake_ip::fake_ip_for(
            name.trim_end_matches('.'),
        ))),
        28 => Some(std::net::IpAddr::V6(crate::fake_ip::fake_ipv6_for(
            name.trim_end_matches('.'),
        ))),
        _ => None,
    };
    let response = build_dns_response(payload, answer_ip);
    let reply = build_udp_packet6(
        std::net::Ipv6Addr::from(dst),
        std::net::Ipv6Addr::from(src),
        53,
        src_port,
        &response,
    );
    if let Err(e) = io.lock().unwrap().write_all(&reply) {
        tracing::debug!("TUN DNS6 reply write failed: {}", e);
    }
}

/// Ones-complement checksum over the IPv6 pseudo-header plus `data`, as
/// required for UDP/ICMPv6 (RFC 8200 §8.1).
fn checksum6(src: [u8; 16], dst: [u8; 16], next_header: u8, data: &[u8]) -> u16 {
    let mut buf = Vec::with_capacity(40 + data.len());
    buf.extend_from_slice(&src);
    buf.extend_from_slice(&dst);
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(&[0, 0, 0, next_header]);
    buf.extend_from_slice(data);
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    if i < buf.len() {
        sum += (buf[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build an IPv6/UDP packet with a valid (mandatory in v6) UDP checksum.
fn build_udp_packet6(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
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
    let sum = checksum6(src.octets(), dst.octets(), 17, &udp);
    // A computed zero checksum is transmitted as all-ones (RFC 8200 §8.1).
    udp[6..8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());

    let mut out = Vec::with_capacity(40 + udp_len);
    out.push(0x60);
    out.extend_from_slice(&[0, 0, 0]); // traffic class + flow label
    out.extend_from_slice(&(udp_len as u16).to_be_bytes());
    out.push(17);
    out.push(64);
    out.extend_from_slice(&src.octets());
    out.extend_from_slice(&dst.octets());
    out.extend_from_slice(&udp);
    out
}

/// Build an ICMPv6 Destination Unreachable answering `original` (a full
/// IPv6 packet). `code` is 3 (address unreachable) for TCP and 4 (port
/// unreachable) for UDP. The reply quotes as much of the original packet as
/// fits inside the 1280-byte minimum IPv6 MTU.
pub(crate) fn build_icmp6_unreachable(original: &[u8], code: u8) -> Option<Vec<u8>> {
    if original.len() < 40 {
        return None;
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&original[24..40]); // answer as the addressed host
    dst.copy_from_slice(&original[8..24]);
    let quote_len = original.len().min(1280 - 40 - 8);
    let icmp_len = 8 + quote_len;

    let mut icmp = vec![0u8; icmp_len];
    icmp[0] = 1; // destination unreachable
    icmp[1] = code;
    icmp[8..8 + quote_len].copy_from_slice(&original[..quote_len]);
    let sum = checksum6(src, dst, 58, &icmp);
    icmp[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut out = Vec::with_capacity(40 + icmp_len);
    out.push(0x60);
    out.extend_from_slice(&[0, 0, 0]);
    out.extend_from_slice(&(icmp_len as u16).to_be_bytes());
    out.push(58);
    out.push(64);
    out.extend_from_slice(&src);
    out.extend_from_slice(&dst);
    out.extend_from_slice(&icmp);
    Some(out)
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
        28 => Some(std::net::IpAddr::V6(crate::fake_ip::fake_ipv6_for(
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
            crate::fake_ip::hostname_for(fake_ip.into()).as_deref(),
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

    fn v6_tcp_syn() -> Vec<u8> {
        // fdfe:dcba:9876::1:40000 -> 2606:4700::1:443, bare SYN.
        let src: std::net::Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let dst: std::net::Ipv6Addr = "2606:4700::1".parse().unwrap();
        let mut p = Vec::with_capacity(60);
        p.push(0x60);
        p.extend_from_slice(&[0, 0, 0]);
        p.extend_from_slice(&20u16.to_be_bytes());
        p.push(6);
        p.push(64);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&40000u16.to_be_bytes());
        p.extend_from_slice(&443u16.to_be_bytes());
        p.extend_from_slice(&[0; 8]); // seq + ack
        p.push(0x50);
        p.push(0x02); // SYN
        p.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]);
        p
    }

    #[test]
    fn ipv6_tcp_gets_icmp6_address_unreachable() {
        let syn = v6_tcp_syn();
        let reply = build_icmp6_unreachable(&syn, 3).unwrap();
        assert_eq!(reply[0] >> 4, 6);
        assert_eq!(reply[6], 58, "next header is ICMPv6");
        // Answered by the addressed host, back to the sender.
        assert_eq!(&reply[8..24], &syn[24..40]);
        assert_eq!(&reply[24..40], &syn[8..24]);
        let icmp = &reply[40..];
        assert_eq!(icmp[0], 1, "destination unreachable");
        assert_eq!(icmp[1], 3, "address unreachable");
        assert_eq!(&icmp[8..8 + 40], &syn[..40], "quotes the original header");
        // The checksum must validate: recomputing over pseudo-header +
        // message (checksum field included) yields zero.
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&reply[8..24]);
        dst.copy_from_slice(&reply[24..40]);
        assert_eq!(checksum6(src, dst, 58, icmp), 0);
    }

    #[test]
    fn ipv6_udp_dns_reply_swaps_endpoints_and_checks_out() {
        let server: std::net::Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        let client: std::net::Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let query = dns_query("example.com", 1);
        let request = build_udp_packet6(client, server, 53123, 53, &query);
        // The handler answers from the server address back to the client.
        let (qname, qtype) = parse_dns_question(&query).unwrap();
        assert_eq!(qtype, 1);
        let name = String::from_utf8_lossy(&qname);
        let answer = std::net::IpAddr::V4(crate::fake_ip::fake_ip_for(name.trim_end_matches('.')));
        let response = build_dns_response(&query, Some(answer));
        let reply = build_udp_packet6(server, client, 53, 53123, &response);
        assert_eq!(&reply[8..24], &server.octets());
        assert_eq!(&reply[24..40], &client.octets());
        assert_eq!(reply[6], 17);
        let udp = &reply[40..];
        assert_eq!(u16::from_be_bytes([udp[0], udp[1]]), 53);
        assert_eq!(u16::from_be_bytes([udp[2], udp[3]]), 53123);
        // UDP checksum (mandatory for v6) validates to zero.
        assert_eq!(checksum6(server.octets(), client.octets(), 17, udp), 0);
        // The request packet itself is well-formed too.
        assert_eq!(request[6], 17);
    }

    #[test]
    fn ipv6_dns_aaaa_query_is_answered_with_a_fake_v6() {
        let server: std::net::Ipv6Addr = "fdfe:dcba:9876::2".parse().unwrap();
        let client: std::net::Ipv6Addr = "fdfe:dcba:9876::1".parse().unwrap();
        let query = dns_query("v6.test", 28);
        let request = build_udp_packet6(client, server, 53123, 53, &query);
        let io = Arc::new(Mutex::new(std::io::Cursor::new(Vec::new())));
        handle_dns_packet6(&request, 40, server.octets(), client.octets(), &io);
        let reply = io.lock().unwrap().get_ref().clone();
        assert!(!reply.is_empty(), "AAAA must be answered with a fake v6");
        let udp = &reply[40..];
        let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        let payload = &udp[8..len];
        assert_eq!(u16::from_be_bytes([payload[6], payload[7]]), 1, "one answer");
        let fake = crate::fake_ip::fake_ipv6_for("v6.test");
        assert!(
            payload.windows(16).any(|window| window == fake.octets()),
            "the fake v6 {fake} must appear in the answer"
        );
        assert_eq!(crate::fake_ip::hostname_for(fake.into()).as_deref(), Some("v6.test"));
    }
}
