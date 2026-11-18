//! Minimal DNS layer. The Go kernel has a full fake-ip / DoH / DoT resolver;
//! this slice provides a cached async forward resolver, which is enough for
//! IP-CIDR rule matching and for establishing direct connections.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::config::DnsConfig;

static SHARED: OnceLock<Resolver> = OnceLock::new();

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

        let mut addrs = Vec::new();
        for server in self.upstreams() {
            let Some(addr) = format!("{}:53", server).parse::<std::net::SocketAddr>().ok() else {
                continue;
            };
            for qtype in [1u16, 28u16] {
                if let Ok(mut found) = crate::net::dns_query(addr, host, qtype).await {
                    addrs.append(&mut found);
                }
            }
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

    /// DNS servers to query, falling back to public resolvers when the config
    /// does not name any.
    fn upstreams(&self) -> Vec<String> {
        if self.config.nameserver.is_empty() {
            vec!["223.5.5.5".to_string(), "8.8.8.8".to_string()]
        } else {
            self.config.nameserver.clone()
        }
    }

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap();
        match cache.get(host) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.addrs.clone()),
            _ => None,
        }
    }
}
