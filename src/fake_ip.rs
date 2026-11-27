//! Minimal fake-ip pool. DNS answers are returned immediately with synthetic
//! addresses from a private range; when a connection arrives for one of those
//! addresses we map it back to the hostname before applying rules/dialing.
//! This is what makes the first connection fast — no real DNS round-trip is
//! needed at connect time.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};

static POOL: OnceLock<Mutex<FakeIpPool>> = OnceLock::new();

const BASE: u32 = 0xc612_0000; // 198.18.0.0
const RANGE: u32 = 0x0001_0000; // /16 = 65536 addresses
const MAX_ENTRIES: usize = 60_000; // leave headroom below the full range

#[derive(Default)]
struct FakeIpPool {
    next: u32,
    by_ip: HashMap<Ipv4Addr, String>,
    by_name: HashMap<String, Ipv4Addr>,
    /// Allocation order for LRU-ish reuse when the pool fills up.
    order: std::collections::VecDeque<Ipv4Addr>,
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

/// Return (or allocate) a fake IPv4 address for `host`. The allocation stays
/// inside 198.18.0.0/16 and is bounded: when the pool fills, the oldest
/// mapping is recycled instead of spinning forever (which used to hang the
/// whole DNS path and could wander into real public IP space).
pub fn fake_ip_for(host: &str) -> Ipv4Addr {
    let host = host.to_ascii_lowercase();
    let mut pool = pool().lock().unwrap();
    if let Some(ip) = pool.by_name.get(&host) {
        return *ip;
    }
    // Find a free address within the range, at most a full pass.
    let mut ip = None;
    for _ in 0..RANGE {
        let value = pool.next.wrapping_add(1);
        // Wrap back to the start of the /16 instead of spilling into 198.19.
        let offset = if value >= BASE && value < BASE + RANGE {
            value - BASE
        } else {
            1
        };
        let next_ip = BASE + offset;
        pool.next = next_ip;
        let addr = Ipv4Addr::from(next_ip);
        let host_byte = (next_ip & 0xff) as u8;
        if host_byte > 3 && !pool.by_ip.contains_key(&addr) {
            ip = Some(addr);
            break;
        }
    }
    let addr = match ip {
        Some(a) => a,
        None => {
            // Pool exhausted: recycle the oldest mapping so DNS never stalls.
            let oldest = pool
                .order
                .pop_front()
                .unwrap_or_else(|| Ipv4Addr::from(BASE + 4));
            if let Some(old_host) = pool.by_ip.remove(&oldest) {
                pool.by_name.remove(&old_host);
            }
            oldest
        }
    };
    pool.by_ip.insert(addr, host.clone());
    pool.by_name.insert(host, addr);
    pool.order.push_back(addr);
    // Keep the mapping map bounded even if order/out-of-band inserts drift.
    while pool.by_ip.len() > MAX_ENTRIES {
        if let Some(oldest) = pool.order.pop_front() {
            if let Some(old_host) = pool.by_ip.remove(&oldest) {
                pool.by_name.remove(&old_host);
            }
        } else {
            break;
        }
    }
    addr
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
