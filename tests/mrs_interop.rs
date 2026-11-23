//! MRS decoding against real MetaCubeX meta-rules-dat files (the same
//! CDN payloads the production config loads). Fixtures are committed
//! under tests/fixtures/ so the test stays hermetic.

use std::net::IpAddr;

use skyward_core::common::TargetAddr;
use skyward_core::geo::GeoData;
use skyward_core::rules::mrs::parse_mrs;
use skyward_core::rules::provider::{Behavior, RuleProvider};

/// Fixtures are stored base64-encoded (the repo tooling is text-only);
/// decode with a minimal decoder so the test needs no extra crates.
fn fixture_bytes(file: &str) -> Vec<u8> {
    let text = std::fs::read_to_string(format!("tests/fixtures/{}.b64", file)).unwrap();
    let mut table = [255u8; 256];
    for (i, c) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".iter().enumerate() {
        table[*c as usize] = i as u8;
    }
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for byte in text.bytes() {
        let value = table[byte as usize];
        if value == 255 {
            continue;
        }
        acc = (acc << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

fn provider_from_fixture(file: &str, behavior: Behavior) -> RuleProvider {
    let raw = fixture_bytes(file);
    let entries = parse_mrs(&raw, behavior).unwrap();
    assert!(!entries.is_empty(), "{} decoded to no entries", file);
    RuleProvider::from_entries(file.into(), behavior, entries)
}

#[test]
fn google_mrs_matches_google_domains() {
    let provider = provider_from_fixture("google.mrs", Behavior::Domain);
    assert!(!provider.needs_resolve(&TargetAddr::Domain("google.com".into(), 443)));
    let geo = GeoData::default();
    let hits = |host: &str| provider.matches(&TargetAddr::Domain(host.into(), 443), None, &geo);
    assert!(hits("google.com"));
    assert!(hits("www.google.com"));
    assert!(hits("mail.google.com"));
    assert!(!hits("notgoogle.com"));
    assert!(!hits("google.com.evil.example"));
    assert!(!hits("example.com"));
}

#[test]
fn youtube_mrs_matches_youtube_domains() {
    let provider = provider_from_fixture("youtube.mrs", Behavior::Domain);
    let geo = GeoData::default();
    let hits = |host: &str| provider.matches(&TargetAddr::Domain(host.into(), 443), None, &geo);
    assert!(hits("youtube.com"));
    assert!(hits("www.youtube.com"));
    assert!(hits("music.youtube.com"));
    assert!(!hits("notyoutube.com"));
}

#[test]
fn private_ip_mrs_matches_private_ranges() {
    let provider = provider_from_fixture("private_ip.mrs", Behavior::IpCidr);
    assert!(provider.needs_resolve(&TargetAddr::Domain("example.com".into(), 443)));
    let geo = GeoData::default();
    let hits = |ip: &str| {
        let ip: IpAddr = ip.parse().unwrap();
        provider.matches(&TargetAddr::Ip(ip, 80), Some(ip), &geo)
    };
    assert!(hits("192.168.1.1"));
    assert!(hits("10.0.0.5"));
    assert!(hits("172.16.0.9"));
    assert!(hits("127.0.0.1"));
    assert!(!hits("8.8.8.8"));
    assert!(!hits("1.1.1.1"));
}

#[test]
fn mrs_rejects_wrong_behavior_and_garbage() {
    let raw = fixture_bytes("google.mrs");
    assert!(parse_mrs(&raw, Behavior::IpCidr).is_err());
    assert!(parse_mrs(b"not a rule set", Behavior::Domain).is_err());
}
