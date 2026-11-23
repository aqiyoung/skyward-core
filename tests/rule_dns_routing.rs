//! Rule-set routing must not depend on a local DNS lookup unless an IP rule
//! actually needs one. A silent local DNS server makes regressions deterministic.
use std::path::Path;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::time::Duration;

use skyward_core::common::{TargetAddr, TrafficStats};
use skyward_core::config::Config;
use skyward_core::tunnel::Engine;
use tokio::net::UdpSocket;
use tokio::time::timeout;

async fn engine(yaml: &str, dns_addr: &str) -> Engine {
    let mut config = Config::from_str(yaml).unwrap();
    config.dns = Some(skyward_core::config::DnsConfig {
        nameserver: vec![dns_addr.into()],
        ..Default::default()
    });
    Engine::new(config, Arc::new(TrafficStats::default()), Path::new(".")).await
}

#[tokio::test]
async fn domain_rule_sets_do_not_wait_for_dns() {
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let yaml = r#"
rule-providers:
  other: {type: inline, behavior: domain, payload: ['+.other.example']}
  mixed: {type: inline, behavior: classical, payload: ['IP-CIDR,10.0.0.0/8', 'DOMAIN-SUFFIX,example.com']}
rules:
  - RULE-SET,other,DIRECT
  - RULE-SET,missing,DIRECT
  - RULE-SET,mixed,REJECT
  - MATCH,DIRECT
"#;
    let engine = engine(yaml, &dns.local_addr().unwrap().to_string()).await;
    let target = TargetAddr::Domain("www.example.com".into(), 443);
    assert_eq!(timeout(Duration::from_millis(500), engine.decide(&target)).await.unwrap(), "REJECT");
    let mut buf = [0; 512];
    assert!(timeout(Duration::from_millis(50), dns.recv_from(&mut buf)).await.is_err());
}

async fn dns_server(answer: bool) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap().to_string();
    let count = Arc::new(AtomicUsize::new(0));
    let seen = count.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 512];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            seen.fetch_add(1, Ordering::SeqCst);
            let mut response = buf[..n].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            let is_a = n >= 4 && response[n - 4..n - 2] == [0, 1];
            if answer && is_a {
                response[6..8].copy_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 1, 2, 3]);
            }
            let _ = socket.send_to(&response, peer).await;
        }
    });
    (addr, count, task)
}

#[tokio::test]
async fn ip_provider_resolves_and_keeps_rule_order() {
    let (addr, count, task) = dns_server(true).await;
    let yaml = r#"
rule-providers:
  ips: {type: inline, behavior: ipcidr, payload: ['10.0.0.0/8']}
rules:
  - RULE-SET,ips,REJECT
  - DOMAIN-SUFFIX,example.com,DIRECT
  - MATCH,DIRECT
"#;
    let engine = engine(yaml, &addr).await;
    let target = TargetAddr::Domain("www.example.com".into(), 443);
    assert_eq!(timeout(Duration::from_secs(2), engine.decide(&target)).await.unwrap(), "REJECT");
    assert_eq!(count.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn failed_lookup_is_not_repeated_for_each_ip_rule() {
    let (addr, count, task) = dns_server(false).await;
    let yaml = r#"
rules:
  - IP-CIDR,10.0.0.0/8,REJECT
  - IP-CIDR,192.168.0.0/16,REJECT
  - MATCH,DIRECT
"#;
    let engine = engine(yaml, &addr).await;
    let target = TargetAddr::Domain("missing.example".into(), 443);
    assert_eq!(timeout(Duration::from_secs(2), engine.decide(&target)).await.unwrap(), "DIRECT");
    assert_eq!(count.load(Ordering::SeqCst), 2);
    task.abort();
}

#[tokio::test]
async fn no_resolve_provider_skips_dns_and_literal_ip_still_matches() {
    let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let yaml = r#"
rule-providers:
  ips: {type: inline, behavior: ipcidr, payload: ['10.0.0.0/8']}
rules:
  - RULE-SET,ips,REJECT,no-resolve
  - MATCH,DIRECT
"#;
    let engine = engine(yaml, &dns.local_addr().unwrap().to_string()).await;
    let domain = TargetAddr::Domain("www.example.com".into(), 443);
    assert_eq!(timeout(Duration::from_millis(500), engine.decide(&domain)).await.unwrap(), "DIRECT");
    let ip = TargetAddr::Ip("10.1.2.3".parse().unwrap(), 443);
    assert_eq!(engine.decide(&ip).await, "REJECT");
    let mut buf = [0; 512];
    assert!(timeout(Duration::from_millis(50), dns.recv_from(&mut buf)).await.is_err());
}
