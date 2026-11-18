//! Shared types and primitives used across the kernel.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Kernel version reported by the CLI and the REST API.
pub const VERSION: &str = "0.1.0-alpha.1";

/// Process-wide traffic counters.
#[derive(Debug, Default)]
pub struct TrafficStats {
    upload: AtomicU64,
    download: AtomicU64,
}

impl TrafficStats {
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up: self.upload.load(Ordering::Relaxed),
            down: self.download.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
pub struct TrafficSnapshot {
    pub up: u64,
    pub down: u64,
}

pub type SharedTraffic = Arc<TrafficStats>;

/// A connection target as it appears on the wire. Keeping the hostname separate
/// from the resolved IP is what lets domain rules and IP rules both work.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TargetAddr {
    Domain(String, u16),
    Ip(IpAddr, u16),
}

impl TargetAddr {
    pub fn host(&self) -> String {
        match self {
            TargetAddr::Domain(h, _) => h.clone(),
            TargetAddr::Ip(ip, _) => ip.to_string(),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Domain(_, p) | TargetAddr::Ip(_, p) => *p,
        }
    }

    /// `host:port`, formatted so it can be handed to `TcpStream::connect`.
    pub fn address(&self) -> String {
        let host = match self {
            TargetAddr::Domain(h, _) => h.clone(),
            TargetAddr::Ip(ip, _) => match ip {
                IpAddr::V4(_) => ip.to_string(),
                IpAddr::V6(_) => format!("[{}]", ip),
            },
        };
        format!("{}:{}", host, self.port())
    }

    /// All candidate socket addresses, so callers can fall back from e.g. ::1
    /// to 127.0.0.1 when only one address family is actually listening.
    pub async fn resolve_all(&self) -> std::io::Result<Vec<SocketAddr>> {
        match self {
            TargetAddr::Ip(ip, port) => Ok(vec![SocketAddr::new(*ip, *port)]),
            TargetAddr::Domain(host, port) => {
                let ips = crate::dns::resolve_host(host).await?;
                if ips.is_empty() {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "no address for host",
                    ))
                } else {
                    Ok(ips.into_iter().map(|ip| SocketAddr::new(ip, *port)).collect())
                }
            }
        }
    }

    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        self.resolve_all().await?.into_iter().next().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::NotFound, "no address for host")
        })
    }
}
