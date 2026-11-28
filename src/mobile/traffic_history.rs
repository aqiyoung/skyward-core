//! Native traffic history backing `getTrafficHistory`.
//!
//! On Android the App *forces* the native-history path
//! (`nativeTrafficHistoryEnabled = system.isAndroid`): it ignores the
//! `request`/`requestTraffic` events and only reads `getTrafficHistory`.
//! Without this method the statistics page is permanently empty.
//!
//! This mirrors the Go core's `core/traffic_history.go`: hourly buckets keyed
//! by (hour, host, rule, rulePayload, node, network, process), a monotonic
//! revision, and `rows` filtered by `revision > since`. Buckets are persisted
//! as JSON so history survives a VPN/core restart.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::tunnel::connection::ConnectionInfo;

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Start of the *local* hour containing `now_ms`, in epoch milliseconds.
/// The App queries by local-day boundaries, so UTC buckets would shift
/// "today" by the device UTC offset.
fn local_hour_start_ms(now_ms: i64) -> i64 {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let mut t = (now_ms / 1000) as libc::time_t;
    if unsafe { libc::localtime_r(&mut t, &mut tm) }.is_null() {
        return (now_ms / 3_600_000) * 3_600_000;
    }
    // `timegm` reads the tm fields as UTC. To turn a local hour into epoch
    // millis, compute the device's UTC offset first, then subtract it from
    // the hour interpreted as UTC.
    let mut as_utc = tm;
    as_utc.tm_isdst = -1;
    let as_utc_t = unsafe { libc::timegm(&mut as_utc) };
    let mut hour = tm;
    hour.tm_min = 0;
    hour.tm_sec = 0;
    hour.tm_isdst = -1;
    let hour_as_utc = unsafe { libc::timegm(&mut hour) };
    if as_utc_t < 0 || hour_as_utc < 0 {
        return (now_ms / 3_600_000) * 3_600_000;
    }
    let offset = as_utc_t - t;
    ((hour_as_utc - offset) as i64) * 1000
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct HistoryRow {
    id: String,
    hour: i64,
    host: String,
    rule: String,
    #[serde(rename = "rulePayload", default)]
    rule_payload: String,
    node: String,
    network: String,
    process: String,
    upload: u64,
    download: u64,
    runtime: i64,
    connections: u64,
    revision: u64,
}

#[derive(Debug, Default)]
struct HistoryState {
    rows: HashMap<String, HistoryRow>,
    /// Last sampled cumulative (upload, download) per connection id. Deltas
    /// are computed against this; closed connections are dropped each sample.
    last: HashMap<String, (u64, u64)>,
    /// Connection ids already counted, so a connection is counted once.
    seen: HashSet<String>,
    revision: u64,
    last_sample_ms: i64,
    path: Option<PathBuf>,
}

static HISTORY: OnceLock<Mutex<HistoryState>> = OnceLock::new();
fn history() -> &'static Mutex<HistoryState> {
    HISTORY.get_or_init(|| Mutex::new(HistoryState::default()))
}

fn history_path() -> Option<PathBuf> {
    crate::mobile::home_dir().map(|h| h.join("traffic-history.json"))
}

#[derive(Serialize, Deserialize)]
struct Persisted {
    rows: Vec<HistoryRow>,
    revision: u64,
    last_sample_ms: i64,
}

fn load(state: &mut HistoryState) {
    if state.path.is_none() {
        state.path = history_path();
    }
    let Some(path) = &state.path else { return };
    let Ok(text) = fs::read_to_string(path) else { return };
    let Ok(saved) = serde_json::from_str::<Persisted>(&text) else { return };
    state.rows = saved
        .rows
        .into_iter()
        .map(|row| (row.id.clone(), row))
        .collect();
    state.revision = saved.revision;
    state.last_sample_ms = saved.last_sample_ms;
}

fn save(state: &HistoryState) {
    let Some(path) = &state.path else { return };
    let persisted = Persisted {
        rows: state.rows.values().cloned().collect(),
        revision: state.revision,
        last_sample_ms: state.last_sample_ms,
    };
    if let Ok(text) = serde_json::to_string(&persisted) {
        let _ = fs::write(path, text);
    }
}

fn bucket_key(
    hour: i64,
    host: &str,
    rule: &str,
    rule_payload: &str,
    node: &str,
    network: &str,
    process: &str,
) -> String {
    // A stable, collision-free-enough key without pulling in a hash crate:
    // length-prefix every field so separators cannot collide with content.
    let mut key = String::new();
    for part in [hour.to_string(), host.into(), rule.into(), rule_payload.into(),
                 node.into(), network.into(), process.into()] {
        key.push_str(&part.len().to_string());
        key.push(':');
        key.push_str(&part);
    }
    key
}

/// Fold one second's connection snapshot into hourly buckets.
fn sample_at(snapshot: Vec<ConnectionInfo>, now_ms: i64) {
    let mut s = history().lock().unwrap();
    load_once(&mut s);

    let hour = local_hour_start_ms(now_ms);
    // bucket id -> a row seeded with this second's metadata and deltas
    let mut deltas: HashMap<String, HistoryRow> = HashMap::new();

    for info in &snapshot {
        let prev = s.last.get(&info.id).copied().unwrap_or((0, 0));
        let up = info.upload.saturating_sub(prev.0);
        let down = info.download.saturating_sub(prev.1);
        let fresh = !s.seen.contains(&info.id);
        if up == 0 && down == 0 && !fresh {
            continue;
        }
        if fresh {
            s.seen.insert(info.id.clone());
        }
        let node = info.chains.last().cloned().unwrap_or_default();
        let id = bucket_key(
            hour,
            &info.metadata.host,
            &info.rule,
            &info.rule_payload,
            &node,
            &info.metadata.network,
            &info.metadata.process,
        );
        let row = deltas.entry(id.clone()).or_insert_with(|| HistoryRow {
            id: id.clone(),
            hour,
            host: info.metadata.host.clone(),
            rule: info.rule.clone(),
            rule_payload: info.rule_payload.clone(),
            node: node.clone(),
            network: info.metadata.network.clone(),
            process: info.metadata.process.clone(),
            ..Default::default()
        });
        row.upload += up;
        row.download += down;
        if fresh {
            row.connections += 1;
        }
    }

    // Runtime row, mirroring Go's `runtime/<hour>` rows so uptime stats work.
    let runtime_delta = if s.last_sample_ms > 0 && now_ms > s.last_sample_ms {
        now_ms - s.last_sample_ms
    } else {
        0
    };
    if runtime_delta > 0 {
        let id = format!("runtime/{}", hour);
        let row = deltas
            .entry(id.clone())
            .or_insert_with(|| HistoryRow { id: id.clone(), hour, ..Default::default() });
        row.runtime += runtime_delta;
    }

    for (id, delta) in deltas {
        // Advance the revision with a local first so the `s.rows` entry borrow
        // below does not overlap a `s.revision` access.
        let rev = s.revision + 1;
        s.revision = rev;
        let row = s.rows.entry(id.clone()).or_insert_with(|| HistoryRow {
            id: id.clone(),
            hour: delta.hour,
            host: delta.host.clone(),
            rule: delta.rule.clone(),
            rule_payload: delta.rule_payload.clone(),
            node: delta.node.clone(),
            network: delta.network.clone(),
            process: delta.process.clone(),
            ..Default::default()
        });
        row.upload += delta.upload;
        row.download += delta.download;
        row.connections += delta.connections;
        row.runtime += delta.runtime;
        row.revision = rev;
    }

    // `last` holds the newest totals for live connections; sample_with resets
    // it to the current snapshot after this function returns.
    s.last_sample_ms = now_ms;
    save(&s);
}

/// Load persisted history once, on the first sample/read.
fn load_once(s: &mut HistoryState) {
    if s.path.is_none() {
        s.path = history_path();
        load(s);
    }
}

/// Fold a snapshot taken at `now_ms`, preserving the live connections' latest
/// totals for the next delta computation.
fn sample_with(snapshot: Vec<ConnectionInfo>, now_ms: i64) {
    let live_totals: HashMap<String, (u64, u64)> = snapshot
        .iter()
        .map(|i| (i.id.clone(), (i.upload, i.download)))
        .collect();
    sample_at(snapshot, now_ms);
    let mut s = history().lock().unwrap();
    s.last = live_totals;
    // Bounded bookkeeping: connection ids that are gone cannot appear again.
    let live: HashSet<String> = s.last.keys().cloned().collect();
    s.seen.retain(|id| live.contains(id));
}

/// Public sample entry point (used by the background sampler and tests).
pub fn sample(snapshot: Vec<ConnectionInfo>) {
    sample_with(snapshot, now_millis());
}

/// Answer `getTrafficHistory(since)`: all rows whose revision advanced past
/// `since`, plus the current revision.
pub fn read(since: u64) -> Value {
    let mut s = history().lock().unwrap();
    load_once(&mut s);
    let rows: Vec<&HistoryRow> = s
        .rows
        .values()
        .filter(|r| r.revision > since)
        .collect();
    json!({
        "rows": rows,
        "revision": s.revision,
    })
}

static SAMPLER_STARTED: AtomicBool = AtomicBool::new(false);

/// Start a once-per-second sampler that folds the live connection snapshot
/// into history. Called on the first `getTrafficHistory`; the App polls that
/// method regularly, so sampling begins as soon as the core is connected.
pub fn ensure_sampler() {
    if SAMPLER_STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    let Some(rt) = crate::jni::tokio_runtime() else {
        SAMPLER_STARTED.store(false, Ordering::SeqCst);
        return;
    };
    rt.spawn(async {
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        loop {
            ticker.tick().await;
            let snapshot = match crate::runtime_state::engine().await {
                Some(engine) => engine.connections.snapshot().await,
                None => Vec::new(),
            };
            sample(snapshot);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::TargetAddr;
    use crate::tunnel::connection::{ConnectionTracker, Network};
    use std::sync::{Arc, Mutex};

    // These tests share the global HISTORY; keep them from stomping on each
    // other when cargo runs them in parallel.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn info(id: &str, host: &str, up: u64, down: u64) -> ConnectionInfo {
        ConnectionInfo {
            id: id.into(),
            kind: "tcp".into(),
            metadata: crate::tunnel::connection::ConnectionMeta {
                network: "tcp".into(),
                source_ip: String::new(),
                source_port: String::new(),
                destination_ip: String::new(),
                destination_port: "443".into(),
                host: host.into(),
                process: "com.example".into(),
                process_path: String::new(),
                remote_destination: String::new(),
                source_geo_ip: Vec::new(),
                destination_geo_ip: Vec::new(),
            },
            chains: vec!["DIRECT".into()],
            rule: "MATCH".into(),
            rule_payload: "".into(),
            upload: up,
            download: down,
            start: "2026-01-01T00:00:00.000Z".into(),
        }
    }

    #[test]
    fn sample_accumulates_and_read_filters_by_revision() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Isolate from any persistent file and previous state.
        *history().lock().unwrap() = HistoryState::default();

        let base = 1_700_000_000_000i64;
        sample_with(vec![info("a", "example.com", 100, 200)], base);
        let r0 = read(0);
        let rows = r0["rows"].as_array().unwrap();
        assert!(rows.iter().any(|r| r["host"] == "example.com"
            && r["upload"] == 100
            && r["download"] == 200));
        let rev = r0["revision"].as_u64().unwrap();
        assert!(rev >= 1);

        // No new traffic -> no new rows past the current revision.
        let r1 = read(rev);
        assert!(r1["rows"].as_array().unwrap().is_empty());

        // More traffic on the same bucket accumulates into the same row
        // (Go stores cumulative totals, not per-interval deltas).
        sample_with(vec![info("a", "example.com", 250, 500)], base + 1000);
        let r2 = read(rev);
        let rows = r2["rows"].as_array().unwrap();
        let row = rows
            .iter()
            .find(|r| r["host"] == "example.com" && r["node"] == "DIRECT")
            .unwrap();
        assert_eq!(row["upload"].as_u64().unwrap(), 250);
        assert_eq!(row["download"].as_u64().unwrap(), 500);
    }

    #[test]
    fn hour_bucket_uses_local_midnight() {
        // local_hour_start_ms must land on an exact hour boundary.
        let now = 1_700_000_000_000i64;
        let hour = local_hour_start_ms(now);
        assert_eq!(hour % 3_600_000, 0);
        assert!(hour <= now && now - hour < 3_600_000);
    }

    #[test]
    fn connection_tracker_snapshot_feeds_history() {
        let _guard = TEST_LOCK.lock().unwrap();
        *history().lock().unwrap() = HistoryState::default();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let tracker = Arc::new(ConnectionTracker::new());
            let target = TargetAddr::Domain("tracker.test".into(), 443);
            let (lease, up, down) = tracker
                .add(&target, "MATCH", "", vec!["DIRECT".into()], Network::Tcp, None, None)
                .await;
            up.store(42, Ordering::Relaxed);
            down.store(84, Ordering::Relaxed);
            let snap = tracker.snapshot().await;
            drop(lease);
            let base = 1_700_000_000_000i64;
            sample_with(snap, base);
        });
        let rows = read(0)["rows"].as_array().unwrap().clone();
        assert!(rows.iter().any(|r| r["host"] == "tracker.test"
            && r["upload"] == 42
            && r["download"] == 84
            && r["connections"] == 1));
    }
}
