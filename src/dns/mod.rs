//! Minimal DNS layer. The Go kernel has a full fake-ip / DoH / DoT resolver;
//! this slice provides a cached async forward resolver, which is enough for
//! IP-CIDR rule matching and for establishing direct connections.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::DnsConfig;

static SHARED: OnceLock<Resolver> = OnceLock::new();
static SYSTEM_UPSTREAMS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static NETWORK_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

pub fn update_system_dns(servers: &str) {
    *SYSTEM_UPSTREAMS.lock().unwrap() = servers.split(',').map(str::trim)
        .filter(|server| parse_upstream(server).is_some()).map(str::to_owned).collect();
    clear_caches();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_change_invalidates_engine_and_shared_dns_caches() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let resolver = Resolver::new(DnsConfig::default());
        resolver.cache.lock().unwrap().insert("test.example".into(), Entry {
            expires: Instant::now() + Duration::from_secs(60),
            addrs: vec!["192.0.2.1".parse().unwrap()],
            epoch: NETWORK_EPOCH.load(std::sync::atomic::Ordering::SeqCst),
        });
        assert!(resolver.cached("test.example").is_some());
        update_system_dns("192.0.2.53:53,not-a-server,[2001:db8::53]:53");
        assert!(resolver.cached("test.example").is_none());
        assert_eq!(resolver.upstreams(), vec!["192.0.2.53:53", "[2001:db8::53]:53"]);
        update_system_dns("");
    }
}

pub fn clear_caches() {
    NETWORK_EPOCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Some(resolver) = SHARED.get() {
        resolver.cache.lock().unwrap().clear();
    }
}

/// Accept `host`, `host:port` or a bare IP; reject URLs and other schemes.
fn parse_upstream(server: &str) -> Option<std::net::SocketAddr> {
    if let Ok(addr) = server.parse::<std::net::SocketAddr>() {
        return Some(addr);
    }
    if let Ok(ip) = server.parse::<IpAddr>() {
        return Some(std::net::SocketAddr::new(ip, 53));
    }
    None
}

/// Resolve through the core's protected DNS path. The system resolver must not
/// be used here: once the VPN is up it forwards queries to the TUN address and
/// the lookup loops back into the tunnel we are hosting.
pub async fn resolve_host(host: &str) -> std::io::Result<Vec<IpAddr>> {
    SHARED
        .get_or_init(|| Resolver::new(DnsConfig::default()))
        .resolve(host)
        .await
}

#[derive(Debug)]
struct Entry {
    expires: Instant,
    addrs: Vec<IpAddr>,
    epoch: u64,
}

#[derive(Debug, Clone)]
pub struct Resolver {
    cache: Arc<Mutex<HashMap<String, Entry>>>,
    ttl: Duration,
    #[allow(dead_code)]
    config: DnsConfig,
}

impl Resolver {
    pub fn new(config: DnsConfig) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            ttl: Duration::from_secs(60),
            config,
        }
    }

    pub async fn resolve(&self, host: &str) -> std::io::Result<Vec<IpAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        if let Some(addrs) = self.cached(host) {
            return Ok(addrs);
        }

        let epoch = NETWORK_EPOCH.load(std::sync::atomic::Ordering::SeqCst);
        let mut addrs = Vec::new();
        for server in self.upstreams() {
            let Some(addr) = parse_upstream(&server) else {
                continue;
            };
            let (v4, v6) = tokio::join!(
                crate::net::dns_query(addr, host, 1),
                crate::net::dns_query(addr, host, 28),
            );
            addrs.extend(v4.unwrap_or_default());
            addrs.extend(v6.unwrap_or_default());
            if !addrs.is_empty() {
                break;
            }
        }
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("no DNS answer for {}", host),
            ));
        }

        let mut cache = self.cache.lock().unwrap();
        cache.insert(
            host.to_string(),
            Entry {
                expires: Instant::now() + self.ttl,
                addrs: addrs.clone(),
                epoch,
            },
        );
        Ok(addrs)
    }

    pub async fn resolve_first(&self, host: &str) -> std::io::Result<IpAddr> {
        self.resolve(host)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "empty DNS answer"))
    }

    /// DNS servers to query. Configured nameservers that are not plain
    /// `host[:port]` (for example DoH URLs) are ignored, and if none remain we
    /// fall back to public resolvers so a lookup can still succeed.
    fn upstreams(&self) -> Vec<String> {
        let valid: Vec<String> = self
            .config
            .nameserver
            .iter()
            .filter(|s| parse_upstream(s).is_some())
            .cloned()
            .collect();
        if valid.is_empty() {
            let system = SYSTEM_UPSTREAMS.lock().unwrap().clone();
            if system.is_empty() {
                vec!["223.5.5.5".to_string(), "8.8.8.8".to_string()]
            } else {
                system
            }
        } else {
            valid
        }
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap();
        match cache.get(host) {
            Some(entry) if entry.expires > Instant::now()
                && entry.epoch == NETWORK_EPOCH.load(std::sync::atomic::Ordering::SeqCst) => Some(entry.addrs.clone()),
            _ => None,
        }
    }
}
