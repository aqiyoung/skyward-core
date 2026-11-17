//! Minimal DNS layer. The Go kernel has a full fake-ip / DoH / DoT resolver;
//! this slice provides a cached async forward resolver, which is enough for
//! IP-CIDR rule matching and for establishing direct connections.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::DnsConfig;

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
        let lookup = tokio::net::lookup_host((host, 0)).await?;
        for socket in lookup {
            let ip = socket.ip();
            if !addrs.contains(&ip) {
                addrs.push(ip);
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

    fn cached(&self, host: &str) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap();
        match cache.get(host) {
            Some(entry) if entry.expires > Instant::now() => Some(entry.addrs.clone()),
            _ => None,
        }
    }
}
