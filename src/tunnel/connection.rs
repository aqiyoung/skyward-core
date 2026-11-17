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

#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInfo {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub network: String,
    pub host: String,
    #[serde(rename = "dstIP")]
    pub dst_ip: String,
    pub port: u16,
    pub rule: String,
    pub chain: Vec<String>,
    #[serde(rename = "upload")]
    pub upload: u64,
    #[serde(rename = "download")]
    pub download: u64,
    #[serde(rename = "start")]
    pub start: u64,
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
        chain: Vec<String>,
        network: Network,
    ) -> (String, Arc<AtomicU64>, Arc<AtomicU64>) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));
        let (host, dst_ip) = match target {
            TargetAddr::Domain(h, _) => (h.clone(), String::new()),
            TargetAddr::Ip(ip, _) => (ip.to_string(), ip.to_string()),
        };
        let info = ConnectionInfo {
            id: id.to_string(),
            kind: "tcp".to_string(),
            network: match network { Network::Tcp => "tcp".into(), Network::Udp => "udp".into() },
            host,
            dst_ip,
            port: target.port(),
            rule: rule.to_string(),
            chain,
            upload: 0,
            download: 0,
            start: now_millis(),
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
        items.sort_by_key(|i| i.start);
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
        let (id, up, down) = tracker.add(&target, "MATCH", vec!["DIRECT".into()], Network::Tcp).await;
        up.store(12, Ordering::Relaxed);
        down.store(34, Ordering::Relaxed);
        let snapshot = tracker.snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].upload, 12);
        assert_eq!(snapshot[0].download, 34);
        assert_eq!(snapshot[0].chain, vec!["DIRECT"]);
        tracker.remove(&id).await;
        assert!(tracker.snapshot().await.is_empty());
    }
}
