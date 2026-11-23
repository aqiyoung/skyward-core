//! Minimal fake-ip pool. DNS answers are returned immediately with synthetic
//! addresses from a private range; when a connection arrives for one of those
//! addresses we map it back to the hostname before applying rules/dialing.
//! This is what makes the first connection fast — no real DNS round-trip is
//! needed at connect time.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};

static POOL: OnceLock<Mutex<FakeIpPool>> = OnceLock::new();

#[derive(Default)]
struct FakeIpPool {
    next: u32,
    by_ip: HashMap<Ipv4Addr, String>,
    by_name: HashMap<String, Ipv4Addr>,
}

fn pool() -> &'static Mutex<FakeIpPool> {
    POOL.get_or_init(|| {
        Mutex::new(FakeIpPool {
            // Start above the /30 the Android VpnService uses for the TUN link
            // (198.18.0.0/30) and the DNS hijack address (198.18.0.2).
            next: 0x_c612_0004, // 198.18.0.4
            ..Default::default()
        })
    })
}

/// Return (or allocate) a fake IPv4 address for `host`.
pub fn fake_ip_for(host: &str) -> Ipv4Addr {
    let host = host.to_ascii_lowercase();
    let mut pool = pool().lock().unwrap();
    if let Some(ip) = pool.by_name.get(&host) {
        return *ip;
    }
    // Skip the reserved low addresses of 198.18.0.0/24.
    let mut value = pool.next;
    loop {
        value = value.wrapping_add(1);
        if (value & 0xff) == 0 {
            value = (value & !0xff) | 0x04;
        }
        let ip = Ipv4Addr::from(value);
        if (value & 0xff) > 3 && !pool.by_ip.contains_key(&ip) {
            break;
        }
    }
    pool.next = value;
    let ip = Ipv4Addr::from(value);
    pool.by_ip.insert(ip, host.clone());
    pool.by_name.insert(host, ip);
    ip
}

/// Reverse lookup: is `ip` a fake address, and what hostname does it stand for?
pub fn hostname_for(ip: Ipv4Addr) -> Option<String> {
    pool().lock().unwrap().by_ip.get(&ip).cloned()
}

/// True when `ip` is inside the pool's synthetic range (198.18.0.0/16). A
/// destination in this range is one of our fake addresses; if the pool no
/// longer knows it, nothing can be dialed there.
pub fn is_in_fake_range(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && ip.octets()[1] == 18
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_reversible() {
        let ip = fake_ip_for("example.com");
        assert_eq!(ip, fake_ip_for("EXAMPLE.com"));
        assert_eq!(hostname_for(ip).as_deref(), Some("example.com"));
        assert_ne!(ip, fake_ip_for("other.com"));
    }

    #[test]
    fn fake_range_check() {
        assert!(is_in_fake_range("198.18.0.13".parse().unwrap()));
        assert!(is_in_fake_range("198.18.255.200".parse().unwrap()));
        assert!(!is_in_fake_range("198.19.0.13".parse().unwrap()));
        assert!(!is_in_fake_range("198.17.0.13".parse().unwrap()));
        assert!(!is_in_fake_range("203.0.113.7".parse().unwrap()));
    }
}
