//! Shared types and primitives used across the kernel.

use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Kernel version reported by the CLI and the REST API. Kept in step with the
/// App release line the Rust core ships in.
pub const VERSION: &str = "1.0.1.4";

/// DIRECT and REJECT are the built-in non-proxy outbounds; every other name
/// counts towards the App's proxy-only statistics.
pub fn is_proxied_outbound(name: &str) -> bool {
    !matches!(name, "DIRECT" | "REJECT")
}

/// Process-wide traffic counters.
#[derive(Debug, Default)]
pub struct TrafficStats {
    upload: AtomicU64,
    download: AtomicU64,
    /// The same totals restricted to connections that left through a proxy
    /// (the App's "only count proxy traffic" setting).
    proxy_upload: AtomicU64,
    proxy_download: AtomicU64,
    rate_sample: Mutex<Option<(Instant, TrafficSnapshot, TrafficSnapshot)>>,
    proxy_rate_sample: Mutex<Option<(Instant, (u64, u64), (u64, u64))>>,
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

    /// Count proxy-only bytes alongside the totals; DIRECT and REJECT flows
    /// never call these.
    pub fn add_proxy_upload(&self, bytes: u64) {
        self.proxy_upload.fetch_add(bytes, Ordering::Relaxed);
        self.note_change();
    }

    pub fn add_proxy_download(&self, bytes: u64) {
        self.proxy_download.fetch_add(bytes, Ordering::Relaxed);
        self.note_change();
    }

    /// Zero the cumulative counters, as the App's "reset traffic" action does.
    pub fn reset(&self) {
        self.upload.store(0, Ordering::Relaxed);
        self.download.store(0, Ordering::Relaxed);
        self.proxy_upload.store(0, Ordering::Relaxed);
        self.proxy_download.store(0, Ordering::Relaxed);
        if let Ok(mut sample) = self.rate_sample.lock() {
            *sample = None;
        }
        if let Ok(mut sample) = self.proxy_rate_sample.lock() {
            *sample = None;
        }
        self.write_now();
    }

    pub fn snapshot_proxied(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            up: self.proxy_upload.load(Ordering::Relaxed),
            down: self.proxy_download.load(Ordering::Relaxed),
        }
    }

    pub fn rate_proxied(&self) -> TrafficSnapshot {
        self.rate_proxied_at(Instant::now())
    }

    fn rate_proxied_at(&self, now: Instant) -> TrafficSnapshot {
        let mut sample = self.proxy_rate_sample.lock().unwrap();
        let current = self.snapshot_proxied();
        let (last_time, last, rate) = sample.get_or_insert((now, (current.up, current.down), (0, 0)));
        let elapsed = now.saturating_duration_since(*last_time);
        if elapsed >= Duration::from_secs(1) {
            let per_second = |bytes: u64| (bytes as f64 / elapsed.as_secs_f64()) as u64;
            *rate = (
                per_second(current.up.saturating_sub(last.0)),
                per_second(current.down.saturating_sub(last.1)),
            );
            *last_time = now;
            *last = (current.up, current.down);
        }
        TrafficSnapshot { up: rate.0, down: rate.1 }
    }

    /// Restore the cumulative totals from `path` and mirror later changes back
    /// to it, so a process restart does not lose the running total.
    pub fn enable_persistence(&self, path: PathBuf) {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
                let up = value.get("up").and_then(|v| v.as_u64()).unwrap_or(0);
                let down = value.get("down").and_then(|v| v.as_u64()).unwrap_or(0);
                let proxy_up = value.get("proxyUp").and_then(|v| v.as_u64()).unwrap_or(0);
                let proxy_down = value.get("proxyDown").and_then(|v| v.as_u64()).unwrap_or(0);
                self.upload.store(up, Ordering::Relaxed);
                self.download.store(down, Ordering::Relaxed);
                self.proxy_upload.store(proxy_up, Ordering::Relaxed);
                self.proxy_download.store(proxy_down, Ordering::Relaxed);
            } else {
                tracing::warn!(
                    "unreadable {}: restarting totals at zero",
                    path.display()
                );
            }
        }
        if let Ok(mut slot) = self.persist.lock() {
            *slot = Some(PersistSlot { path, last_write: Instant::now() });
        }
        self.write_now();
    }

    /// Flush the current totals to the persistence file now, so a kill
    /// shortly after is less likely to lose the latest window.
    pub fn flush(&self) {
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
            "{{\"up\":{},\"down\":{},\"proxyUp\":{},\"proxyDown\":{}}}",
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
            self.proxy_upload.load(Ordering::Relaxed),
            self.proxy_download.load(Ordering::Relaxed)
        );
        // Write to a sibling temp file and rename: a crash mid-write must
        // not truncate the running total, and a corrupt file must be
        // detectable and replaced, not silently read as zero.
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return;
        };
        let tmp = path.with_file_name(format!("{name}.tmp"));
        if std::fs::write(&tmp, body.as_bytes()).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
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
    first.add_proxy_upload(4);
    std::thread::sleep(Duration::from_millis(80));
    first.add_upload(0); // a change past the mirror interval flushes

    let second = TrafficStats::default();
    second.enable_persistence(path);
    assert_eq!(second.snapshot().up, 1);
    assert_eq!(second.snapshot().down, 0);
    assert_eq!(second.snapshot_proxied().up, 4);
    assert_eq!(second.snapshot_proxied().down, 0);
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
