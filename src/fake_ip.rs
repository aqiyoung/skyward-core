//! Minimal fake-ip pool. DNS answers are returned immediately with synthetic
//! addresses from a private range; when a connection arrives for one of those
//! addresses we map it back to the hostname before applying rules/dialing.
//! This is what makes the first connection fast — no real DNS round-trip is
//! needed at connect time.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Mutex, OnceLock};

static POOL: OnceLock<Mutex<FakeIpPool>> = OnceLock::new();

#[derive(Default)]
struct FakeIpPool {
    next: u32,
    by_ip: HashMap<Ipv4Addr, String>,
    by_name: HashMap<String, Ipv4Addr>,
    /// Unique-local addresses handed out for AAAA answers, so IPv6-only apps
    /// resolve through the same immediate, rule-matchable path.
    next6: u128,
    by_ip6: HashMap<Ipv6Addr, String>,
    by_name6: HashMap<String, Ipv6Addr>,
}

fn pool() -> &'static Mutex<FakeIpPool> {
    POOL.get_or_init(|| {
        Mutex::new(FakeIpPool {
            // Start above the /30 the Android VpnService uses for the TUN link
            // (198.18.0.0/30) and the DNS hijack address (198.18.0.2).
            next: 0x_c612_0004, // 198.18.0.4
            next6: 1,
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

/// Return (or allocate) a fake IPv6 address for `host`.
pub fn fake_ipv6_for(host: &str) -> Ipv6Addr {
    let host = host.to_ascii_lowercase();
    let mut pool = pool().lock().unwrap();
    if let Some(ip) = pool.by_name6.get(&host) {
        return *ip;
    }
    loop {
        let value = pool.next6;
        pool.next6 = pool.next6.wrapping_add(1);
        // Stay inside the fd00::/64 prefix.
        if value == 0 || value > 0xffff_ffff_ffff_ffff {
            pool.next6 = 1;
            continue;
        }
        let ip = fake_ipv6(value);
        if !pool.by_ip6.contains_key(&ip) {
            pool.by_ip6.insert(ip, host.clone());
            pool.by_name6.insert(host, ip);
            return ip;
        }
    }
}

fn fake_ipv6(value: u128) -> Ipv6Addr {
    let mut octets = [0u8; 16];
    octets[0] = 0xfd; // unique-local prefix
    octets[8..16].copy_from_slice(&value.to_be_bytes()[8..16]);
    Ipv6Addr::from(octets)
}

/// Reverse lookup: is `ip` a fake address, and what hostname does it stand for?
pub fn hostname_for(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V4(v4) => pool().lock().unwrap().by_ip.get(&v4).cloned(),
        IpAddr::V6(v6) => pool().lock().unwrap().by_ip6.get(&v6).cloned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_and_reversible() {
        let ip = fake_ip_for("example.com");
        assert_eq!(ip, fake_ip_for("EXAMPLE.com"));
        assert_eq!(hostname_for(ip.into()).as_deref(), Some("example.com"));
        assert_ne!(ip, fake_ip_for("other.com"));
    }

    #[test]
    fn ipv6_pool_is_stable_and_reversible() {
        let ip = fake_ipv6_for("example.com");
        assert_eq!(ip.octets()[0], 0xfd, "unique-local prefix");
        assert_eq!(ip, fake_ipv6_for("EXAMPLE.com"));
        assert_eq!(hostname_for(IpAddr::V6(ip)).as_deref(), Some("example.com"));
        assert_ne!(ip, fake_ipv6_for("other.com"));
    }
}
