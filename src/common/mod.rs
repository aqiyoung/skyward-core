//! Shared types and primitives used across the kernel.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Kernel version reported by the CLI and the REST API.
pub const VERSION: &str = "0.1.0-alpha.1";

/// Process-wide traffic counters.
#[derive(Debug, Default)]
pub struct TrafficStats {
    upload: AtomicU64,
    download: AtomicU64,
    rate_sample: Mutex<Option<(Instant, TrafficSnapshot, TrafficSnapshot)>>,
    persist: Mutex<Option<PersistSlot>>,
}

#[derive(Debug)]
struct PersistSlot {
    path: PathBuf,
    last_write: Instant,
}

/// Mirroring cadence. Tests shorten it so they do not have to sleep.
const PERSIST_INTERVAL: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(5)
};

impl TrafficStats {
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
        self.note_change();
    }

    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
        self.note_change();
    }

    /// Zero the cumulative counters, as the App's "reset traffic" action does.
    pub fn reset(&self) {
        self.upload.store(0, Ordering::Relaxed);
        self.download.store(0, Ordering::Relaxed);
        if let Ok(mut sample) = self.rate_sample.lock() {
            *sample = None;
        }
        self.write_now();
    }

    /// Restore the cumulative totals from `path` and mirror later changes back
    /// to it, so a process restart does not lose the running total.
    pub fn enable_persistence(&self, path: PathBuf) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                let up = value.get("up").and_then(|v| v.as_u64()).unwrap_or(0);
                let down = value.get("down").and_then(|v| v.as_u64()).unwrap_or(0);
                self.upload.store(up, Ordering::Relaxed);
                self.download.store(down, Ordering::Relaxed);
            }
        }
        if let Ok(mut slot) = self.persist.lock() {
            *slot = Some(PersistSlot { path, last_write: Instant::now() });
        }
        self.write_now();
    }

    fn note_change(&self) {
        let Ok(mut slot) = self.persist.lock() else { return };
        let Some(slot) = slot.as_mut() else { return };
        if slot.last_write.elapsed() < PERSIST_INTERVAL {
            return;
        }
        slot.last_write = Instant::now();
        self.write_locked(&slot.path);
    }

    fn write_now(&self) {
        if let Ok(mut slot) = self.persist.lock() {
            if let Some(slot) = slot.as_mut() {
                slot.last_write = Instant::now();
                self.write_locked(&slot.path);
            }
        }
    }

    fn write_locked(&self, path: &Path) {
        let body = format!(
            "{{\"up\":{},\"down\":{}}}",
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed)
        );
        let _ = std::fs::write(path, body);
    }

    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up: self.upload.load(Ordering::Relaxed),
            down: self.download.load(Ordering::Relaxed),
        }
    }

    pub fn rate(&self) -> TrafficSnapshot {
        self.rate_at(Instant::now())
    }

    fn rate_at(&self, now: Instant) -> TrafficSnapshot {
        let mut sample = self.rate_sample.lock().unwrap();
        let current = self.snapshot();
        let (last_time, last, rate) =
            sample.get_or_insert((now, current, TrafficSnapshot::default()));
        let elapsed = now.saturating_duration_since(*last_time);
        if elapsed >= Duration::from_secs(1) {
            let per_second = |bytes: u64| (bytes as f64 / elapsed.as_secs_f64()) as u64;
            *rate = TrafficSnapshot {
                up: per_second(current.up.saturating_sub(last.up)),
                down: per_second(current.down.saturating_sub(last.down)),
            };
            *last_time = now;
            *last = current;
        }
        *rate
    }
}

#[derive(Debug, Default, Clone, Copy, serde::Serialize)]
pub struct TrafficSnapshot {
    pub up: u64,
    pub down: u64,
}

pub type SharedTraffic = Arc<TrafficStats>;

#[cfg(test)]
#[test]
fn cumulative_totals_survive_a_fresh_stats_instance() {
    let dir = std::env::temp_dir().join(format!("skyward-traffic-{}", rand::random::<u64>()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("traffic.json");
    let first = TrafficStats::default();
    first.enable_persistence(path.clone());
    first.add_upload(11);
    first.add_download(13);
    first.reset();
    first.add_upload(1);
    std::thread::sleep(Duration::from_millis(80));
    first.add_upload(0); // a change past the mirror interval flushes

    let second = TrafficStats::default();
    second.enable_persistence(path);
    assert_eq!(second.snapshot().up, 1);
    assert_eq!(second.snapshot().down, 0);
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn traffic_rate_is_per_second_and_does_not_consume_totals() {
    let traffic = TrafficStats::default();
    let start = Instant::now();
    assert_eq!(traffic.rate_at(start).up, 0);
    traffic.add_upload(200);
    traffic.add_download(600);
    let rate = traffic.rate_at(start + Duration::from_secs(2));
    assert_eq!((rate.up, rate.down), (100, 300));
    assert_eq!(traffic.rate_at(start + Duration::from_secs(2)).down, 300);
    assert_eq!(traffic.rate_at(start + Duration::from_secs(3)).down, 0);
    assert_eq!(traffic.snapshot().down, 600);
}

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
                    Ok(ips
                        .into_iter()
                        .map(|ip| SocketAddr::new(ip, *port))
                        .collect())
                }
            }
        }
    }

    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        self.resolve_all()
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no address for host"))
    }
}
