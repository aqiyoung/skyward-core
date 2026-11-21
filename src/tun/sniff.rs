//! Bounded, passive TCP hostname recovery. Never consumes or rewrites payload.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::common::TargetAddr;
use crate::config::{SniffProtocol, SnifferConfig};
use super::relay::ByteQueue;

const LIMIT: usize = 32 * 1024;
const DEADLINE: Duration = Duration::from_millis(500);

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    More,
    Host(String),
    None,
}

fn domain_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let host = host.to_ascii_lowercase();
    if let Some(suffix) = pattern.strip_prefix("+.") {
        return host == suffix || host.ends_with(&format!(".{}", suffix));
    }
    if pattern.starts_with('.') {
        return host.ends_with(&pattern);
    }
    let escaped = regex::escape(&pattern).replace("\\*", ".*").replace("\\?", ".");
    regex::Regex::new(&format!("^{}$", escaped)).map(|re| re.is_match(&host)).unwrap_or(false)
}

fn listed(patterns: &[String], host: &str) -> bool {
    patterns.iter().any(|pattern| domain_matches(pattern, host))
}

fn address_listed(patterns: &[String], ip: IpAddr) -> bool {
    patterns.iter().any(|pattern| {
        pattern.parse::<ipnet::IpNet>().map(|net| net.contains(&ip)).unwrap_or(false)
            || pattern.parse::<IpAddr>().ok() == Some(ip)
    })
}

fn protocol<'a>(config: &'a SnifferConfig, name: &str, port: u16) -> Option<&'a SniffProtocol> {
    config.sniff.iter().find_map(|(key, value)| {
        (key.eq_ignore_ascii_case(name) && value.ports.iter().any(|range| range.contains(port))).then_some(value)
    })
}

/// Returns a route hostname plus whether to send it to the outbound. The
/// original destination remains available for IP rules and non-override dials.
pub(super) async fn inspect(
    config: &SnifferConfig,
    target: &TargetAddr,
    source: IpAddr,
    destination: IpAddr,
    queue: &ByteQueue,
    upload_closed: &AtomicBool,
) -> Option<(String, bool)> {
    if !config.enable || address_listed(&config.skip_src_address, source)
        || address_listed(&config.skip_dst_address, destination) {
        return None;
    }
    match target {
        TargetAddr::Ip(..) if !config.parse_pure_ip => return None,
        TargetAddr::Domain(host, _) => {
            if listed(&config.skip_domain, host)
                || (!config.force_dns_mapping && !listed(&config.force_domain, host)) {
                return None;
            }
        }
        _ => {}
    }
    let http = protocol(config, "HTTP", target.port());
    let tls = protocol(config, "TLS", target.port());
    if http.is_none() && tls.is_none() {
        return None;
    }
    let sniff = async {
        loop {
            let bytes = queue.peek(LIMIT);
            let (result, settings) = if bytes.first() == Some(&22) {
                (if tls.is_some() { tls_host(&bytes) } else { Parsed::None }, tls)
            } else if bytes.is_empty() {
                (Parsed::More, None)
            } else {
                (if http.is_some() { http_host(&bytes) } else { Parsed::None }, http)
            };
            match result {
                Parsed::Host(host) => {
                    if listed(&config.skip_domain, &host) { return None; }
                    let override_destination = settings.and_then(|settings| settings.override_destination)
                        .unwrap_or(config.override_destination);
                    return Some((host, override_destination));
                }
                Parsed::None => return None,
                Parsed::More if bytes.len() >= LIMIT || upload_closed.load(Ordering::Relaxed) => return None,
                Parsed::More => queue.notified().await,
            }
        }
    };
    tokio::time::timeout(DEADLINE, sniff).await.ok().flatten()
}

fn normalize_host(bytes: &[u8]) -> Option<String> {
    let host = std::str::from_utf8(bytes).ok()?.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || host.parse::<IpAddr>().is_ok()
        || !host.split('.').all(|label| !label.is_empty() && label.len() <= 63
            && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn http_host(bytes: &[u8]) -> Parsed {
    const METHODS: &[&[u8]] = &[b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"TRACE "];
    if !METHODS.iter().any(|method| bytes.starts_with(method) || method.starts_with(bytes)) {
        return Parsed::None;
    }
    let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else { return Parsed::More };
    let Ok(head) = std::str::from_utf8(&bytes[..end]) else { return Parsed::None };
    let mut host = None;
    for line in head.split("\r\n").skip(1) {
        let Some((key, value)) = line.split_once(':') else { return Parsed::None };
        if key.eq_ignore_ascii_case("host") {
            if host.is_some() { return Parsed::None; }
            let value = value.trim();
            let value = match value.rsplit_once(':') {
                Some((name, port)) if port.parse::<u16>().is_ok() => name,
                _ => value,
            };
            host = normalize_host(value.as_bytes());
            if host.is_none() { return Parsed::None; }
        }
    }
    host.map(Parsed::Host).unwrap_or(Parsed::None)
}

fn take<'a>(input: &mut &'a [u8], count: usize) -> Option<&'a [u8]> {
    if count > input.len() { return None; }
    let (value, rest) = input.split_at(count);
    *input = rest;
    Some(value)
}

fn u16_len(input: &mut &[u8]) -> Option<usize> {
    let bytes = take(input, 2)?;
    Some(u16::from_be_bytes([bytes[0], bytes[1]]) as usize)
}

fn client_hello_host(mut hello: &[u8]) -> Option<String> {
    take(&mut hello, 34)?; // legacy version and random
    let session_len = take(&mut hello, 1)?[0] as usize;
    take(&mut hello, session_len)?;
    let cipher_len = u16_len(&mut hello)?;
    take(&mut hello, cipher_len)?;
    let compression_len = take(&mut hello, 1)?[0] as usize;
    take(&mut hello, compression_len)?;
    let extension_len = u16_len(&mut hello)?;
    let mut extensions = take(&mut hello, extension_len)?;
    while !extensions.is_empty() {
        let kind = u16_len(&mut extensions)?;
        let len = u16_len(&mut extensions)?;
        let mut extension = take(&mut extensions, len)?;
        if kind == 0 {
            let list_len = u16_len(&mut extension)?;
            let mut names = take(&mut extension, list_len)?;
            while !names.is_empty() {
                let name_type = take(&mut names, 1)?[0];
                let name_len = u16_len(&mut names)?;
                let name = take(&mut names, name_len)?;
                if name_type == 0 { return normalize_host(name); }
            }
        }
    }
    None
}

fn tls_host(mut bytes: &[u8]) -> Parsed {
    let mut handshake = Vec::new();
    loop {
        if bytes.len() < 5 { return Parsed::More; }
        if bytes[0] != 22 || bytes[1] != 3 { return Parsed::None; }
        let len = u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
        if len == 0 || len > 18432 { return Parsed::None; }
        if bytes.len() < 5 + len { return Parsed::More; }
        handshake.extend_from_slice(&bytes[5..5 + len]);
        bytes = &bytes[5 + len..];
        if handshake.len() >= 4 {
            if handshake[0] != 1 { return Parsed::None; }
            let len = ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | handshake[3] as usize;
            if len + 4 > LIMIT { return Parsed::None; }
            if handshake.len() >= 4 + len {
                return client_hello_host(&handshake[4..4 + len]).map(Parsed::Host).unwrap_or(Parsed::None);
            }
        }
    }
}

#[cfg(test)]
pub(super) fn test_client_hello(host: &str, split_records: bool) -> Vec<u8> {
    let mut names = vec![0];
    names.extend_from_slice(&(host.len() as u16).to_be_bytes());
    names.extend_from_slice(host.as_bytes());
    let mut sni = (names.len() as u16).to_be_bytes().to_vec();
    sni.extend_from_slice(&names);
    let mut extensions = vec![0, 0];
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&sni);
    let mut hello = vec![3, 3];
    hello.extend_from_slice(&[0; 32]);
    hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend_from_slice(&extensions);
    let mut handshake = vec![1, 0, (hello.len() >> 8) as u8, hello.len() as u8];
    handshake.extend_from_slice(&hello);
    let chunks: Vec<&[u8]> = if split_records {
        vec![&handshake[..13], &handshake[13..]]
    } else { vec![&handshake] };
    let mut records = Vec::new();
    for chunk in chunks {
        records.extend_from_slice(&[22, 3, 1]);
        records.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
        records.extend_from_slice(chunk);
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn config() -> SnifferConfig {
        Config::from_str(r#"
sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, '8080-8880']
    TLS:
      ports: [443, '8443']
"#).unwrap().sniffer
    }

    #[test]
    fn tls_client_hello_handles_every_tcp_split_and_multiple_records() {
        for split_records in [false, true] {
            let hello = test_client_hello("WWW.Example.com", split_records);
            for split in 0..hello.len() {
                assert_eq!(tls_host(&hello[..split]), Parsed::More, "split={split}");
            }
            assert_eq!(tls_host(&hello), Parsed::Host("www.example.com".into()));
        }
    }

    #[test]
    fn http_host_requires_complete_headers_and_rejects_ambiguous_host() {
        let request = b"GET / HTTP/1.1\r\nHost: Example.com:8080\r\n\r\n";
        for split in 0..request.len() {
            assert_eq!(http_host(&request[..split]), Parsed::More);
        }
        assert_eq!(http_host(request), Parsed::Host("example.com".into()));
        assert_eq!(http_host(b"GET / HTTP/1.1\r\nHost: one.test\r\nHost: two.test\r\n\r\n"), Parsed::None);
        assert_eq!(http_host(b"GET / HTTP/1.0\r\n\r\n"), Parsed::None);
        assert_eq!(http_host(b"SSH-2.0"), Parsed::None);
    }

    #[test]
    fn malformed_tls_and_ip_or_invalid_hosts_are_not_domains() {
        assert_eq!(tls_host(&[22, 3, 1, 255, 255]), Parsed::None);
        let mut hello = test_client_hello("valid.test", false);
        hello[5] = 2; // ServerHello is not a client hostname.
        assert_eq!(tls_host(&hello), Parsed::None);
        for host in ["127.0.0.1", "", "bad/name", "-bad.test", "a..test"] {
            assert!(normalize_host(host.as_bytes()).is_none());
        }
        for byte in 0..=255 {
            let _ = tls_host(&[22, 3, 1, 0, 4, byte, byte, byte, byte]);
        }
    }

    async fn inspect_bytes(config: &SnifferConfig, target: TargetAddr, bytes: &[u8]) -> Option<(String, bool)> {
        let queue = ByteQueue::new();
        queue.push(bytes);
        let result = inspect(config, &target, "10.0.0.2".parse().unwrap(), "203.0.113.42".parse().unwrap(), &queue, &AtomicBool::new(true)).await;
        assert_eq!(queue.peek(LIMIT), bytes, "sniffing must not consume or change bytes");
        result
    }

    #[tokio::test]
    async fn respects_enable_ports_pure_ip_exclusions_and_override() {
        let mut config = config();
        let target = TargetAddr::Ip("203.0.113.42".parse().unwrap(), 443);
        let hello = test_client_hello("service.test", false);
        assert_eq!(inspect_bytes(&config, target.clone(), &hello).await, Some(("service.test".into(), true)));
        config.sniff.get_mut("TLS").unwrap().override_destination = Some(false);
        assert_eq!(inspect_bytes(&config, target.clone(), &hello).await, Some(("service.test".into(), false)));
        config.enable = false;
        assert!(inspect_bytes(&config, target.clone(), &hello).await.is_none());
        config.enable = true;
        config.parse_pure_ip = false;
        assert!(inspect_bytes(&config, target.clone(), &hello).await.is_none());
        config.parse_pure_ip = true;
        assert!(inspect_bytes(&config, TargetAddr::Ip("203.0.113.42".parse().unwrap(), 444), &hello).await.is_none());
        config.skip_src_address = vec!["10.0.0.0/8".into()];
        assert!(inspect_bytes(&config, target.clone(), &hello).await.is_none());
        config.skip_src_address.clear();
        config.skip_dst_address = vec!["203.0.113.42".into()];
        assert!(inspect_bytes(&config, target.clone(), &hello).await.is_none());
        config.skip_dst_address.clear();
        config.skip_domain = vec!["+.test".into()];
        assert!(inspect_bytes(&config, target.clone(), &hello).await.is_none());
        config.skip_domain = vec!["*.test".into()];
        assert!(inspect_bytes(&config, target, &hello).await.is_none());
    }

    #[tokio::test]
    async fn mapped_domain_force_and_skip_rules_are_honored() {
        let mut config = config();
        config.force_dns_mapping = false;
        let target = TargetAddr::Domain("mapped.test".into(), 443);
        let hello = test_client_hello("actual.test", false);
        assert!(inspect_bytes(&config, target.clone(), &hello).await.is_none());
        config.force_domain = vec!["mapped.test".into()];
        assert_eq!(inspect_bytes(&config, target.clone(), &hello).await, Some(("actual.test".into(), true)));
        config.skip_domain = vec!["mapped.test".into()];
        assert!(inspect_bytes(&config, target, &hello).await.is_none());
    }

    #[tokio::test]
    async fn waits_for_fragment_without_consuming_and_bounds_silent_flows() {
        let config = config();
        let target = TargetAddr::Ip("203.0.113.42".parse().unwrap(), 443);
        let queue = ByteQueue::new();
        let hello = test_client_hello("service.test", true);
        queue.push(&hello[..9]);
        let closed = AtomicBool::new(false);
        let sniff = inspect(&config, &target, "10.0.0.2".parse().unwrap(), "203.0.113.42".parse().unwrap(), &queue, &closed);
        let send = async {
            tokio::task::yield_now().await;
            queue.push(&hello[9..]);
        };
        let (result, _) = tokio::join!(sniff, send);
        assert_eq!(result, Some(("service.test".into(), true)));
        assert_eq!(queue.peek(LIMIT), hello);
        let empty = ByteQueue::new();
        assert!(tokio::time::timeout(Duration::from_secs(2), inspect(&config, &target,
            "10.0.0.2".parse().unwrap(), "203.0.113.42".parse().unwrap(), &empty, &closed)).await.unwrap().is_none());
    }
}
