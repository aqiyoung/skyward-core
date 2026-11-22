//! Live connection registry backing the `/connections` API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::Notify;

use crate::common::TargetAddr;

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Epoch milliseconds as RFC 3339 UTC, e.g. `2026-11-19T13:34:48.123Z`.
fn iso8601(millis: u64) -> String {
    let secs = millis / 1000;
    let ms = millis % 1000;
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year,
        month,
        day,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60,
        ms
    )
}

/// Days since the Unix epoch to a proleptic Gregorian date.
/// (Howard Hinnant's civil_from_days.)
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionMeta {
    #[serde(default)]
    pub network: String,
    #[serde(rename = "sourceIP", default)]
    pub source_ip: String,
    #[serde(rename = "sourcePort", default)]
    pub source_port: String,
    #[serde(rename = "destinationIP", default)]
    pub destination_ip: String,
    #[serde(rename = "destinationPort", default)]
    pub destination_port: String,
    #[serde(default)]
    pub host: String,
    /// Android package name. The App's Dart `Metadata.process` reads this key;
    /// without it the usage breakdown collects everything under "unknown".
    #[serde(default)]
    pub process: String,
    #[serde(rename = "processPath", default)]
    pub process_path: String,
    #[serde(rename = "remoteDestination", default)]
    pub remote_destination: String,
    #[serde(rename = "sourceGeoIP", default)]
    pub source_geo_ip: Vec<String>,
    #[serde(rename = "destinationGeoIP", default)]
    pub destination_geo_ip: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub metadata: ConnectionMeta,
    pub chains: Vec<String>,
    pub rule: String,
    #[serde(rename = "rulePayload")]
    pub rule_payload: String,
    #[serde(rename = "upload")]
    pub upload: u64,
    #[serde(rename = "download")]
    pub download: u64,
    /// RFC 3339, as the App's `DateTime.parse` expects; epoch milliseconds would
    /// throw and drop every connection from the list.
    pub start: String,
}

struct Counters {
    upload: Arc<std::sync::atomic::AtomicU64>,
    download: Arc<std::sync::atomic::AtomicU64>,
}

struct Entry {
    info: ConnectionInfo,
    counters: Counters,
    cancel: Arc<Notify>,
}

pub struct ConnectionLease {
    id: String,
    tracker: Arc<ConnectionTracker>,
    cancel: Arc<Notify>,
}

impl ConnectionLease {
    pub async fn closed(&self) {
        self.cancel.notified().await;
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.tracker.entries.write().unwrap().remove(&self.id);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Default)]
pub struct ConnectionTracker {
    entries: RwLock<HashMap<String, Entry>>,
    /// Last traffic totals reported to the App per connection id; the
    /// request-traffic watch diffs against this map.
    watch_reported: Mutex<HashMap<String, (u64, u64)>>,
    watch_running: AtomicBool,
}

/// The App's request-list event for one new connection (its
/// `CoreEventType.request` payload is a TrackerInfo object).
fn request_event_json(info: &ConnectionInfo) -> String {
    serde_json::json!({ "type": "request", "data": info }).to_string()
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(
        self: &Arc<Self>,
        target: &TargetAddr,
        rule: &str,
        rule_payload: &str,
        chain: Vec<String>,
        network: Network,
        source: Option<(String, u16)>,
        process: Option<String>,
    ) -> (ConnectionLease, Arc<AtomicU64>, Arc<AtomicU64>) {
        let id = format!("{:032x}", rand::random::<u128>());
        let cancel = Arc::new(Notify::new());
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));
        let (host, destination_ip) = match target {
            TargetAddr::Domain(h, _) => (h.clone(), String::new()),
            TargetAddr::Ip(ip, _) => (ip.to_string(), ip.to_string()),
        };
        let (source_ip, source_port) = match source {
            Some((ip, port)) => (ip, port.to_string()),
            None => (String::new(), String::new()),
        };
        let info = ConnectionInfo {
            id: id.to_string(),
            kind: match network { Network::Tcp => "tcp".into(), Network::Udp => "udp".into() },
            metadata: ConnectionMeta {
                network: match network { Network::Tcp => "tcp".into(), Network::Udp => "udp".into() },
                source_ip,
                source_port,
                destination_ip,
                destination_port: target.port().to_string(),
                host,
                process: process.unwrap_or_default(),
                process_path: String::new(),
                remote_destination: String::new(),
                source_geo_ip: Vec::new(),
                destination_geo_ip: Vec::new(),
            },
            chains: chain,
            rule: rule.to_string(),
            rule_payload: rule_payload.to_string(),
            upload: 0,
            download: 0,
            start: iso8601(now_millis()),
        };
        self.entries.write().unwrap().insert(id.clone(), Entry {
            info: info.clone(),
            counters: Counters { upload: upload.clone(), download: download.clone() },
            cancel: cancel.clone(),
        });
        // The App's request list is event-fed (the Go core announces each
        // connection as it opens); without this event the list stays empty.
        crate::jni::emit_event_json(&request_event_json(&info));
        self.watch_reported.lock().unwrap().insert(id.to_string(), (0, 0));
        if !self.watch_running.swap(true, Ordering::SeqCst) {
            let tracker = self.clone();
            tokio::spawn(async move { tracker.run_traffic_watch().await });
        }
        (ConnectionLease { id, tracker: self.clone(), cancel }, upload, download)
    }

    /// One-second traffic reports for the App's request list, mirroring
    /// the Go core's requestTraffic watch: only changed totals are sent,
    /// and the watch stops once no connection remains.
    async fn run_traffic_watch(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let live: HashMap<String, (u64, u64)> = self
                .snapshot()
                .await
                .into_iter()
                .map(|info| (info.id, (info.upload, info.download)))
                .collect();
            let mut changed = Vec::new();
            let drained = {
                let mut reported = self.watch_reported.lock().unwrap();
                for (id, current) in &live {
                    if reported.get(id) != Some(current) {
                        changed.push(serde_json::json!({
                            "id": id,
                            "upload": current.0,
                            "download": current.1,
                        }));
                        reported.insert(id.clone(), *current);
                    }
                }
                reported.retain(|id, _| live.contains_key(id));
                reported.is_empty()
            };
            if !changed.is_empty() {
                crate::jni::emit_event_json(
                    &serde_json::json!({ "type": "requestTraffic", "data": changed }).to_string(),
                );
            }
            if drained {
                self.watch_running.store(false, Ordering::SeqCst);
                // An add() may have raced in after the drain; hand the
                // watch over instead of leaving its entry unwatched.
                let again = !self.watch_reported.lock().unwrap().is_empty();
                if again && !self.watch_running.swap(true, Ordering::SeqCst) {
                    continue;
                }
                return;
            }
        }
    }

    pub async fn snapshot(&self) -> Vec<ConnectionInfo> {
        let entries = self.entries.read().unwrap();
        let mut items: Vec<ConnectionInfo> = entries.values().map(|entry| {
            let mut info = entry.info.clone();
            info.upload = entry.counters.upload.load(Ordering::Relaxed);
            info.download = entry.counters.download.load(Ordering::Relaxed);
            info
        }).collect();
        items.sort_by_key(|i| i.start.clone());
        items
    }

    /// Go-compatible `statistic.Snapshot` shape for the App's connection page.
    pub async fn snapshot_json(&self) -> serde_json::Value {
        let items = self.snapshot().await;
        let upload_total: u64 = items.iter().map(|i| i.upload).sum();
        let download_total: u64 = items.iter().map(|i| i.download).sum();
        serde_json::json!({
            "uploadTotal": upload_total,
            "downloadTotal": download_total,
            "connections": items,
            "memory": 0,
        })
    }

    pub async fn count(&self) -> usize {
        self.entries.read().unwrap().len()
    }

    /// Close a connection by id. Returns false when it does not exist.
    pub async fn close(&self, id: &str) -> bool {
        let entry = self.entries.write().unwrap().remove(id);
        if let Some(entry) = entry {
            entry.cancel.notify_one();
            true
        } else {
            false
        }
    }

    pub async fn close_all(&self) -> usize {
        let mut entries = self.entries.write().unwrap();
        let count = entries.len();
        for (_, entry) in entries.drain() {
            entry.cancel.notify_one();
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracks_connection_lifecycle() {
        let tracker = Arc::new(ConnectionTracker::new());
        let target = TargetAddr::Domain("example.com".into(), 443);
        let (id, up, down) = tracker.add(&target, "MATCH", "", vec!["DIRECT".into()], Network::Tcp, None, None).await;
        up.store(12, Ordering::Relaxed);
        down.store(34, Ordering::Relaxed);
        let snapshot = tracker.snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upload, 12);
        assert_eq!(snapshot[0].download, 34);
        assert_eq!(snapshot[0].chains, vec!["DIRECT"]);
        assert_eq!(snapshot[0].rule_payload, "");
        assert!(snapshot[0].start.ends_with('Z'));
        let wire = serde_json::to_value(&snapshot[0]).unwrap();
        assert!(wire["metadata"].is_object(), "metadata must decode as a map");
        assert_eq!(wire["rulePayload"], "");
        assert_eq!(wire["chains"][0], "DIRECT");
        assert!(tracker.close(&id.id).await);
        tokio::time::timeout(Duration::from_secs(1), id.closed()).await.unwrap();
        assert!(tracker.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn request_event_carries_tracker_info() {
        let tracker = Arc::new(ConnectionTracker::new());
        let target = TargetAddr::Domain("example.com".into(), 443);
        let (id, _, _) = tracker.add(
            &target, "MATCH", "", vec!["DIRECT".into()], Network::Tcp, None,
            Some("com.example.app".into()),
        ).await;
        let snapshot = tracker.snapshot().await;
        let event: serde_json::Value =
            serde_json::from_str(&request_event_json(&snapshot[0])).unwrap();
        assert_eq!(event["type"], "request");
        assert_eq!(event["data"]["id"], id.id);
        assert_eq!(event["data"]["metadata"]["host"], "example.com");
        assert_eq!(event["data"]["metadata"]["process"], "com.example.app");
        assert_eq!(event["data"]["rule"], "MATCH");
        let all = tracker.snapshot_json();
        assert_eq!(all["connections"][0]["metadata"]["process"], "com.example.app");
    }

    #[test]
    fn iso8601_matches_utc_civil_date() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_795_095_288_000), "2026-11-19T13:34:48.000Z");
        assert_eq!(iso8601(1_795_095_288_123), "2026-11-19T13:34:48.123Z");
    }
}
