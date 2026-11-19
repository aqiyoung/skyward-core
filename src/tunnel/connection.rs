//! Live connection registry backing the `/connections` API.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::RwLock;

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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Default)]
pub struct ConnectionTracker {
    next_id: AtomicU64,
    entries: RwLock<HashMap<u64, Entry>>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn add(
        &self,
        target: &TargetAddr,
        rule: &str,
        rule_payload: &str,
        chain: Vec<String>,
        network: Network,
        source: Option<(String, u16)>,
    ) -> (String, Arc<AtomicU64>, Arc<AtomicU64>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
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
            kind: "tcp".to_string(),
            metadata: ConnectionMeta {
                network: match network { Network::Tcp => "tcp".into(), Network::Udp => "udp".into() },
                source_ip,
                source_port,
                destination_ip,
                destination_port: target.port().to_string(),
                host,
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
        self.entries.write().await.insert(id, Entry {
            info,
            counters: Counters { upload: upload.clone(), download: download.clone() },
        });
        (id.to_string(), upload, download)
    }

    pub async fn remove(&self, id: &str) {
        if let Ok(numeric) = id.parse::<u64>() {
            self.entries.write().await.remove(&numeric);
        }
    }

    pub async fn snapshot(&self) -> Vec<ConnectionInfo> {
        let entries = self.entries.read().await;
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
        self.entries.read().await.len()
    }

    /// Close a connection by id. Returns false when it does not exist.
    pub async fn close(&self, id: &str) -> bool {
        let Ok(numeric) = id.parse::<u64>() else { return false };
        self.entries.write().await.remove(&numeric).is_some()
    }

    pub async fn close_all(&self) -> usize {
        let mut entries = self.entries.write().await;
        let count = entries.len();
        entries.clear();
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tracks_connection_lifecycle() {
        let tracker = ConnectionTracker::new();
        let target = TargetAddr::Domain("example.com".into(), 443);
        let (id, up, down) = tracker.add(&target, "MATCH", "", vec!["DIRECT".into()], Network::Tcp, None).await;
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
        tracker.remove(&id).await;
        assert!(tracker.snapshot().await.is_empty());
    }

    #[test]
    fn iso8601_matches_utc_civil_date() {
        assert_eq!(iso8601(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso8601(1_795_095_288_000), "2026-11-19T13:34:48.000Z");
        assert_eq!(iso8601(1_795_095_288_123), "2026-11-19T13:34:48.123Z");
    }
}
