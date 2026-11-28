//! gomobile-compatible `invokeMethod` protocol.
//!
//! The Skyward Flutter App talks to its core by calling `invokeMethod(data)`
//! with a JSON `MethodCall` and receiving a JSON `MethodResponse` via a
//! callback. This module reproduces that wire contract in Rust so the core can
//! be bound to the App's `com.follow.clash.core.mobile.Mobile` JNI interface.
//!
//! Scope of this first slice: protocol framing + stateless/lifecycle methods.
//! Methods needing full runtime state return a structured `not_implemented`
//! error (same shape as the Go core) until they are ported.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use crate::common::VERSION;

pub mod log_bridge;
pub mod profile_base;
pub mod rcx;
pub mod share_links;

#[derive(Debug, Clone, Deserialize)]
pub struct MethodCall {
    #[serde(default)]
    pub id: String,
    pub method: String,
    #[serde(default)]
    pub arguments: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodError {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodResponse {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    pub result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<MethodError>,
}

static IS_INIT: AtomicBool = AtomicBool::new(false);
static SEQ: AtomicU64 = AtomicU64::new(0);
static HOME_DIR: OnceLock<String> = OnceLock::new();

/// The core home dir (set by initClash), where mihomo keeps geoip.dat /
/// geosite.dat. Used by the engine to locate GeoX data.
pub fn home_dir() -> Option<PathBuf> {
    HOME_DIR.get().filter(|s| !s.is_empty()).map(PathBuf::from)
}

fn ok(id: &str, result: Value) -> Vec<u8> {
    encode(MethodResponse {
        id: id.to_string(),
        result,
        error: None,
    })
}

fn err(id: &str, code: &str, message: impl Into<String>) -> Vec<u8> {
    encode(MethodResponse {
        id: id.to_string(),
        result: Value::Null,
        error: Some(MethodError {
            code: code.to_string(),
            message: message.into(),
            details: None,
        }),
    })
}

fn encode(response: MethodResponse) -> Vec<u8> {
    serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec())
}

/// Dispatch one call and return the encoded response bytes.
pub fn invoke(data: &[u8]) -> Vec<u8> {
    let call: MethodCall = match serde_json::from_slice(data) {
        Ok(c) => c,
        Err(e) => return err("", "invalid_arguments", format!("decode method call: {}", e)),
    };
    SEQ.fetch_add(1, Ordering::Relaxed);

    match call.method.as_str() {
        "coreVersion" => ok(&call.id, Value::String(core_version())),
        "getIsInit" => ok(&call.id, Value::Bool(IS_INIT.load(Ordering::Relaxed))),
        "initClash" => handle_init_clash(&call),
        "forceGc" => ok(&call.id, Value::Bool(true)),
        "shutdown" => {
            IS_INIT.store(false, Ordering::Relaxed);
            ok(&call.id, Value::Bool(true))
        }
        "startListener" => handle_start_listener(&call),
        "stopListener" => handle_stop_listener(&call),
        "getProxies" => handle_get_proxies(&call),
        "changeProxy" => handle_change_proxy(&call),
        "asyncTestDelay" => handle_test_delay(&call),
        "probe" => handle_probe(&call),
        "serviceCheck" => handle_service_check(&call),
        "outboundIp" => handle_outbound_ip(&call),
        "getMemoryStats" => handle_memory_stats(&call),
        "validateProxies" => handle_validate_proxies(&call),
        "validateFilters" => handle_validate_filters(&call),
        "buildProfile" => handle_build_profile(&call),
        "startLog" => handle_start_log(&call),
        "stopLog" => handle_stop_log(&call),
        "watchRoute" => handle_watch_route(&call),
        "clearEffect" => handle_clear_effect(&call),
        "updateExternalProvider" => handle_update_external_provider(&call),
        "sideLoadExternalProvider" => handle_update_external_provider(&call),
        "getTraffic" => handle_get_traffic(&call, false),
        "getTotalTraffic" => handle_get_traffic(&call, true),
        "resetTraffic" => handle_reset_traffic(&call),
        "encodeShareLinks" => handle_encode_share_links(&call),
        "decodeShareLinks" => handle_decode_share_links(&call),
        "convertProxies" => handle_convert_proxies(&call),
        "getConfig" => handle_get_config(&call),
        "getProfileBase" => handle_get_profile_base(&call),
        "getProfileOutbounds" => handle_get_profile_outbounds(&call),
        "getProxyDefinition" => handle_get_proxy_definition(&call),
        "getExternalProviders" => handle_external_providers(&call),
        "getExternalProvider" => handle_external_provider(&call),
        "updateDns" => handle_update_dns(&call),
        "updateGeoData" => handle_update_geo_data(&call),
        "getConnections" => handle_get_connections(&call),
        "getConnectionCount" => handle_connection_count(&call),
        "closeConnections" => handle_close_connections(&call),
        "resetConnections" => handle_close_connections(&call),
        "closeConnection" => handle_close_connection(&call),
        "clearDnsCache" => ok(&call.id, Value::Bool(true)),
        "getChainReports" => handle_get_chain_reports(&call),
        "rcxStatus" => ok(&call.id, block_on(rcx::status()).unwrap_or_else(|_| rcx::status_sync())),
        "rcxSetPolicy" => {
            let args = call.arguments.clone();
            ok(&call.id, block_on(rcx::set_policy(args)).unwrap_or_else(|_| rcx::status_sync()))
        }
        "rcxHints" => ok(&call.id, rcx::hints(&call.arguments)),
        "rcxExplain" => ok(&call.id, rcx::explain(call.arguments.as_str().unwrap_or(""))),
        "rcxJournal" => ok(&call.id, rcx::journal(&call.arguments)),
        "rcxAction" => {
            let args = call.arguments.clone();
            ok(&call.id, block_on(rcx::action(args)).unwrap_or_else(|_| json!({"decision":{"action":"hold","reason":{"code":""}}})))
        }
        "rcxProfiles" => ok(&call.id, rcx::profiles()),
        "rcxStudio" => ok(&call.id, rcx::studio(&call.arguments)),
        "validateConfig" => handle_validate_config(&call),
        "setupConfig" => handle_setup_config(&call),
        "updateConfig" => handle_setup_config(&call),
        "quickSetup" => handle_quick_setup(&call),
        "message" => ok(&call.id, Value::Null),
        other => err(&call.id, "not_implemented", format!("unknown method: {}", other)),
    }
}

fn core_version() -> String {
    // A branded name so the diagnostics page shows this is the Skyward Rust
    // core, not the upstream Go core. The `clash.meta/` prefix needed for
    // subscription format detection is added by the App's uaFor(), so it is
    // deliberately not part of this string.
    format!("Skyward Core (Rust) v{}", VERSION)
}

fn handle_init_clash(call: &MethodCall) -> Vec<u8> {
    #[derive(Deserialize, Default)]
    struct InitParams {
        #[serde(rename = "home-dir", default)]
        home_dir: String,
    }
    let params: InitParams = serde_json::from_value(call.arguments.clone()).unwrap_or_default();
    let _ = HOME_DIR.set(params.home_dir);
    IS_INIT.store(true, Ordering::Relaxed);
    ok(&call.id, Value::Bool(true))
}

pub(crate) fn android_quick_setup(init: &str, setup: &str) -> String {
    let Ok(init) = serde_json::from_str::<Value>(init) else {
        return "invalid core initialization parameters".into();
    };
    let Some(home) = init.get("home-dir").and_then(Value::as_str).filter(|p| !p.is_empty()) else {
        return "core home directory is missing".into();
    };
    let Ok(mut arguments) = serde_json::from_str::<Value>(setup) else {
        return "invalid saved setup parameters".into();
    };
    let Some(params) = arguments.as_object_mut() else {
        return "invalid saved setup parameters".into();
    };
    let has_path = params.get("base").and_then(|base| base.get("path")).and_then(Value::as_str)
        .is_some_and(|p| !p.is_empty()) || params.get("path").and_then(Value::as_str)
        .is_some_and(|p| !p.is_empty());
    if !has_path {
        params.insert("path".into(), json!(PathBuf::from(home).join("config.yaml")));
    }

    let _ = HOME_DIR.set(home.to_owned());
    IS_INIT.store(true, Ordering::Relaxed);
    let result = handle_setup_config(&MethodCall {
        id: String::new(), method: "setupConfig".into(), arguments,
    });
    serde_json::from_slice::<Value>(&result).ok()
        .and_then(|value| value.get("result").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_else(|| "invalid core setup response".into())
}

fn handle_get_proxies(call: &MethodCall) -> Vec<u8> {
    let future = async {
        let engine = crate::runtime_state::engine().await;
        let Some(engine) = engine else {
            return json!({"proxies": {}, "all": []});
        };
        let snapshots = engine.outbounds.snapshot();
        let mut views = serde_json::Map::new();
        for item in &snapshots {
            let mut view = serde_json::Map::new();
            view.insert("name".into(), Value::String(item.name.clone()));
            // App's GroupType enum matches on PascalCase names (Selector,
            // URLTest, ...) via `type.name == proxy.type`. Nodes already use
            // PascalCase kinds; map group kinds from config values as well.
            let display_type = match item.kind.as_str() {
                "select" | "GLOBAL" => "Selector",
                "url-test" => "URLTest",
                "fallback" => "Fallback",
                "load-balance" => "LoadBalance",
                "relay" => "Relay",
                other => other,
            };
            view.insert("type".into(), Value::String(display_type.to_string()));
            if !item.members.is_empty() {
                view.insert("all".into(), json!(item.members));
                if let Some(sel) = &item.selected {
                    view.insert("now".into(), Value::String(sel.clone()));
                }
                // The App filters groups with `hidden == false`; the built-in
                // GLOBAL is hidden, exactly like the Go kernel.
                view.insert("hidden".into(), Value::Bool(item.name == "GLOBAL"));
            }
            views.insert(item.name.clone(), Value::Object(view));
        }
        // `all` is the group list in config order (GLOBAL first), matching the
        // Go kernel; nodes are reached through their group's `all`.
        let mut all: Vec<String> = engine.config.proxy_groups.iter()
            .map(|g| g.name.clone())
            .collect();
        if !all.iter().any(|n| n == "GLOBAL") {
            all.insert(0, "GLOBAL".to_string());
        }
        let result = json!({"proxies": views, "all": all});
        // Diagnostics: report group member counts so an empty strategy group is
        // visible in the log.
        let groups_info: Vec<String> = result["proxies"].as_object()
            .map(|m| m.iter()
                .filter_map(|(k, v)| {
                    v.get("all").map(|members| format!(
                        "{}({})={}",
                        k,
                        members.as_array().map(|a| a.len()).unwrap_or(0),
                        v["type"].as_str().unwrap_or("?")
                    ))
                })
                .collect())
            .unwrap_or_default();
        crate::jni::emit_log_event(&format!(
            "[rust-core] getProxies returning {} entries, all=[{}], {} groups: {}",
            result["proxies"].as_object().map(|m| m.len()).unwrap_or(0),
            result["all"].as_array().map(|a| a.iter()
                .filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", ")).unwrap_or_default(),
            groups_info.len(),
            groups_info.iter().take(10).cloned().collect::<Vec<_>>().join(", ")
        ));
        result
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"proxies": {}, "all": []})))
}

fn handle_change_proxy(call: &MethodCall) -> Vec<u8> {
    #[derive(Deserialize, Default)]
    struct Params {
        #[serde(rename = "group-name")]
        group_name: String,
        #[serde(rename = "proxy-name")]
        proxy_name: String,
    }
    let params: Params = serde_json::from_value(call.arguments.clone()).unwrap_or_default();
    let future = async move {
        let Some(engine) = crate::runtime_state::engine().await else {
            return json!({"message": "not initialized", "changed": false});
        };
        let before = engine.outbounds.groups.get(&params.group_name).and_then(|g| g.selected());
        let ok_change = engine.outbounds.set_selection(&params.group_name, &params.proxy_name);
        let after = engine.outbounds.groups.get(&params.group_name).and_then(|g| g.selected());
        if !ok_change {
            return json!({"message": "group not found", "changed": false});
        }
        json!({"message": "", "changed": before != after})
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"message": "error", "changed": false})))
}

/// Minimal HTTP GET through a named outbound; returns (status, body, delay_ms).
async fn http_probe(
    name: &str,
    url: &str,
    timeout_ms: i64,
) -> Option<(u16, String, i64)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next()?;
    let port: u16 = authority.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::common::TargetAddr::Ip(ip, port),
        Err(_) => crate::common::TargetAddr::Domain(host.to_string(), port),
    };
    let path = format!("/{}", rest.split_once('/').map(|(_, p)| p).unwrap_or(""));
    let engine = crate::runtime_state::engine().await?;
    let dial_future = async {
        if name.is_empty() {
            engine.dial(&target).await
        } else {
            engine.dial_named(name, &target).await
        }
    };
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms.max(1) as u64),
        dial_future,
    )
    .await.ok()?.ok()?;
    let start = std::time::Instant::now();
    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, authority);
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms.max(1) as u64),
        stream.write_all(request.as_bytes()),
    ).await.ok()?.ok()?;
    let mut body = Vec::new();
    loop {
        let mut buf = [0u8; 4096];
        let n = tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms.max(1) as u64),
            stream.read(&mut buf),
        ).await.ok()?.ok()?;
        if n == 0 { break; }
        body.extend_from_slice(&buf[..n]);
        if body.len() > 64 * 1024 { break; }
    }
    let delay = start.elapsed().as_millis() as i64;
    let head_end = body.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let head = String::from_utf8_lossy(&body[..head_end]);
    let status = head.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0);
    let body_text = String::from_utf8_lossy(&body[head_end..]).into_owned();
    Some((status, body_text, delay))
}

fn handle_probe(call: &MethodCall) -> Vec<u8> {
    #[derive(Deserialize, Default)]
    struct Params {
        url: String,
        #[serde(rename = "proxy-name")]
        proxy_name: String,
        timeout: i64,
    }
    let params: Params = serde_json::from_value(call.arguments.clone()).unwrap_or_default();
    let url = if params.url.is_empty() { "http://www.gstatic.com/generate_204".to_string() } else { params.url.clone() };
    let future = async move {
        match http_probe(&params.proxy_name, &url, params.timeout).await {
            Some((status, body, delay)) => json!({
                "status-code": status, "delay": delay, "body": body, "url": url,
                "chains": [], "rule": "", "rule-payload": "",
            }),
            None => json!({
                "status-code": 0, "delay": -2i64, "body": "", "url": url,
                "chains": [], "rule": "", "rule-payload": "",
                "error": "connect failed", "message": "connect failed",
            }),
        }
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"status-code": 0, "delay": -2})))
}

fn handle_outbound_ip(call: &MethodCall) -> Vec<u8> {
    #[derive(Deserialize, Default)]
    struct Params {
        #[serde(rename = "proxy-name")]
        proxy_name: String,
        urls: Vec<String>,
        timeout: i64,
    }
    let params: Params = serde_json::from_value(call.arguments.clone()).unwrap_or_default();
    let urls = if params.urls.is_empty() {
        vec!["https://api.ipify.org".to_string()]
    } else {
        params.urls.clone()
    };
    let future = async move {
        // The App rejects a probe whose stamp is older than the route it is
        // drawing, so every answer has to carry the counters it was made under.
        let (_, version) = route_snapshot().await;
        let epoch = crate::runtime_state::core_epoch();
        // First URL that answers wins (Dart supplies the parsers).
        for url in &urls {
            let probe_url = if url.starts_with("http://") || url.starts_with("https://") {
                url.replace("https://", "http://")
            } else {
                format!("http://{}", url)
            };
            if let Some((status, body, delay)) = http_probe(&params.proxy_name, &probe_url, params.timeout).await {
                if status >= 200 && status < 400 {
                    return json!({
                        "url": url, "body": body, "delay": delay, "chains": [],
                        "core-epoch": epoch, "picks-version": version,
                    });
                }
            }
        }
        json!({
            "url": urls.first().cloned().unwrap_or_default(), "body": "", "delay": -2i64,
            "chains": [], "error": "probe failed",
            "core-epoch": epoch, "picks-version": version,
        })
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"error": "probe failed"})))
}

fn handle_memory_stats(call: &MethodCall) -> Vec<u8> {
    let rss = process_mem_kb("VmRSS:").unwrap_or(0) * 1024;
    // Report the Rust core's own footprint, the way Go reports runtime.MemStats.
    // The App carves this out of the process RSS and shows the remainder as the
    // app, so claiming the whole process here inverted the two numbers.
    let heap_inuse = crate::alloc::allocated_bytes();
    // Thread stacks (tokio workers, the TUN relay, the JNI thread) and the
    // allocator/runtime bookkeeping are not part of the counted heap.
    let stack_inuse = 4 * 1024 * 1024;
    let runtime_other = 2 * 1024 * 1024;
    let heap_idle = 0u64;
    let device_total = device_mem_total().unwrap_or(4 * 1024 * 1024 * 1024);
    let budget = (device_total / 4) as i64;
    let result = json!({
        "rss": rss,
        "heapInuse": heap_inuse,
        "heapIdle": heap_idle,
        "stackInuse": stack_inuse,
        "runtimeOther": runtime_other,
        "budget": budget,
        "gcPercent": 0i32,
        "deviceTotal": device_total,
    });
    crate::jni::emit_log_event(&format!(
        "[rust-core] memory rss={} core_heap={} returning={}",
        rss, heap_inuse, result
    ));
    ok(&call.id, result)
}

/// Total physical RAM, from `/proc/meminfo` (0 when unreadable).
fn device_mem_total() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb = rest.split_whitespace().next()?.parse::<u64>().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

/// Read a kB-valued field from /proc/self/status (e.g. "VmRSS:").
fn process_mem_kb(field: &str) -> Option<u64> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(field) {
            return rest.split_whitespace().next().and_then(|v| v.parse::<u64>().ok());
        }
    }
    None
}

fn handle_start_log(call: &MethodCall) -> Vec<u8> {
    log_bridge::start();
    ok(&call.id, Value::Bool(true))
}

fn handle_stop_log(call: &MethodCall) -> Vec<u8> {
    log_bridge::stop();
    ok(&call.id, Value::Bool(true))
}

fn handle_watch_route(call: &MethodCall) -> Vec<u8> {
    // The App keeps the route map fresh from two things: this snapshot and the
    // `routeChanged` events the core publishes while a watch is open. Go's core
    // re-reads the picks once a second; without the events the map only moves
    // when something else makes the App call watchRoute again.
    let watch = call.arguments.as_bool().unwrap_or(false);
    if watch {
        start_route_watch();
    } else {
        stop_route_watch();
    }
    let (picks, version) = block_on(route_snapshot()).unwrap_or_else(|_| (serde_json::Map::new(), 0));
    ok(&call.id, route_json(&picks, version))
}

/// The picks last reported to the App, with the monotonic version they carry.
/// A probe is judged against these, so the version must only ever move forward
/// (the App treats a higher stamp as "behind" and a differing one as stale).
static ROUTE_REPORTED: std::sync::Mutex<Option<(serde_json::Map<String, Value>, u64)>> =
    std::sync::Mutex::new(None);
static ROUTE_WATCH_CANCEL: std::sync::Mutex<Option<Arc<tokio::sync::Notify>>> =
    std::sync::Mutex::new(None);

/// Task handles for the HTTP/SOCKS/mixed inbound listeners opened for the
/// App's system-proxy mode. Kept so stopListener can close the ports.
static LISTENER_TASKS: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>> =
    std::sync::Mutex::new(Vec::new());
/// The App calls startListener as a preload BEFORE applying the profile, so
/// no engine exists yet and the ports cannot be bound then. Remember the
/// request and open the listeners once setupConfig has loaded a config.
static LISTENER_WANTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn route_json(picks: &serde_json::Map<String, Value>, version: u64) -> Value {
    json!({
        "core-epoch": crate::runtime_state::core_epoch(),
        "picks-version": version,
        "picks": picks,
    })
}

/// Read the live picks and advance the reported version when they changed.
async fn route_snapshot() -> (serde_json::Map<String, Value>, u64) {
    let picks = match crate::runtime_state::engine().await {
        Some(engine) => {
            let mut map = serde_json::Map::new();
            for (name, group) in &engine.outbounds.groups {
                if let Some(sel) = group.selected() {
                    map.insert(name.clone(), Value::String(sel));
                }
            }
            map
        }
        None => serde_json::Map::new(),
    };
    (picks.clone(), reported_version(&picks))
}

/// The version the App sees for `picks`: stable while they hold, and one step
/// forward the moment any group's selection moves.
fn reported_version(picks: &serde_json::Map<String, Value>) -> u64 {
    let mut reported = ROUTE_REPORTED.lock().unwrap();
    let version = match reported.as_ref() {
        Some((last, v)) if *last == *picks => *v,
        Some((_, v)) => {
            let next = v.wrapping_add(1);
            *reported = Some((picks.clone(), next));
            next
        }
        None => {
            *reported = Some((picks.clone(), 1));
            1
        }
    };
    version
}

fn start_route_watch() {
    stop_route_watch();
    let cancel = Arc::new(tokio::sync::Notify::new());
    *ROUTE_WATCH_CANCEL.lock().unwrap() = Some(cancel.clone());
    let Some(rt) = crate::jni::tokio_runtime() else { return };
    rt.spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(1));
        ticker.tick().await; // the first tick fires immediately
        let (_, mut last_version) = route_snapshot().await;
        let mut last_epoch = crate::runtime_state::core_epoch();
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                _ = cancel.notified() => return,
            }
            let (picks, version) = route_snapshot().await;
            let epoch = crate::runtime_state::core_epoch();
            if version == last_version && epoch == last_epoch {
                continue;
            }
            last_version = version;
            last_epoch = epoch;
            crate::jni::emit_event_json(
                &json!({
                    "type": "routeChanged",
                    "data": route_json(&picks, version),
                })
                .to_string(),
            );
        }
    });
}

fn stop_route_watch() {
    if let Some(cancel) = ROUTE_WATCH_CANCEL.lock().unwrap().take() {
        cancel.notify_one();
    }
}

fn handle_clear_effect(call: &MethodCall) -> Vec<u8> {
    // No persistent provider cache in this slice; acknowledged.
    ok(&call.id, Value::String(String::new()))
}

fn handle_update_external_provider(call: &MethodCall) -> Vec<u8> {
    // Provider reload would re-fetch the subscription; in this slice the data
    // is loaded once at config time. Acknowledge so the UI does not hang.
    ok(&call.id, Value::String(String::new()))
}

fn handle_validate_proxies(call: &MethodCall) -> Vec<u8> {
    let mappings = call.arguments.as_array().cloned().unwrap_or_default();
    let results: Vec<String> = mappings.iter().map(|m| {
        let obj = match m.as_object() { Some(o) => o, None => return "invalid proxy".to_string() };
        let kind = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let supported = matches!(kind, "direct" | "reject" | "ss" | "shadowsocks" | "ssr" | "vmess" | "vless" | "trojan" | "snell" | "http" | "socks5");
        if !supported {
            return format!("unsupported proxy type: {}", kind);
        }
        if obj.get("name").and_then(|v| v.as_str()).unwrap_or("").is_empty() {
            return "proxy name is required".to_string();
        }
        String::new()
    }).collect();
    ok(&call.id, json!(results))
}

/// Mirror Go's `handleValidateFilters`: each filter is a set of regex parts
/// separated by backticks; the result list carries, per filter, the first
/// compile error or an empty string.
fn handle_validate_filters(call: &MethodCall) -> Vec<u8> {
    let filters = call.arguments.as_array().cloned().unwrap_or_default();
    let results: Vec<String> = filters
        .iter()
        .map(|f| {
            let text = f.as_str().unwrap_or("");
            for part in text.split('`') {
                if let Err(e) = regex::Regex::new(part) {
                    return e.to_string();
                }
            }
            String::new()
        })
        .collect();
    ok(&call.id, json!(results))
}

/// Mirror Go's `handleBuildProfile`: merge the profile with the App's
/// overlay and write the result into the spill directory (`<home>/responses`),
/// returning its path for the host to read back.
fn handle_build_profile(call: &MethodCall) -> Vec<u8> {
    let path = call.arguments.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let overlay = call.arguments.get("overlay").and_then(|v| v.as_str()).unwrap_or("");
    let merged = (|| -> Result<String, String> {
        let profile_text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        profile_base::merge_profile_base(&profile_text, overlay)
    })();
    let merged = match merged {
        Ok(m) => m,
        Err(e) => return err(&call.id, "core_error", e),
    };
    let Some(home) = home_dir() else {
        return err(&call.id, "core_error", "core home dir not set".to_string());
    };
    let dir = home.join("responses");
    if let Err(e) = std::fs::create_dir_all(&dir) {
        return err(&call.id, "core_error", e.to_string());
    }
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "profile-{}-{}.yaml",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    );
    let out = dir.join(name);
    match std::fs::write(&out, merged) {
        Ok(()) => ok(&call.id, Value::String(out.to_string_lossy().into_owned())),
        Err(e) => err(&call.id, "core_error", e.to_string()),
    }
}

/// Rate-limited delay-test diagnostics so a log export shows node failures.
fn delay_diag(message: &str) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 10 {
        crate::jni::emit_log_event(&format!("[rust-core] delay: {}", message));
    }
}

fn handle_test_delay(call: &MethodCall) -> Vec<u8> {
    #[derive(Deserialize, Default)]
    struct Params {
        #[serde(rename = "proxy-name")]
        proxy_name: String,
        #[serde(rename = "test-url")]
        test_url: String,
        timeout: i64,
    }
    let params: Params = serde_json::from_value(call.arguments.clone()).unwrap_or_default();
    let name = params.proxy_name.clone();
    let url = if params.test_url.is_empty() {
        "http://www.gstatic.com/generate_204".to_string()
    } else {
        params.test_url.clone()
    };
    let timeout_ms = if params.timeout > 0 { params.timeout } else { 5000 };
    crate::jni::emit_log_event(&format!("[rust-core] delay: start {} {}", name, url));
    let future = async move {
        let engine = match crate::runtime_state::engine().await {
            Some(e) => e,
            None => {
                return json!({"url": url, "name": name, "value": -2, "message": "not initialized"});
            }
        };
        let delay = measure_delay(&engine, &name, &url, timeout_ms).await;
        match delay {
            Some(ms) => {
                crate::jni::emit_log_event(&format!("[rust-core] delay: end {} = {}ms", name, ms));
                json!({"url": url, "name": name, "value": ms})
            }
            None => {
                delay_diag(&format!("{} -> {} failed", name, url));
                json!({"url": url, "name": name, "value": -2, "message": "connect failed"})
            }
        }
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"value": -2})))
}

async fn measure_delay(
    engine: &std::sync::Arc<crate::tunnel::Engine>,
    name: &str,
    url: &str,
    timeout_ms: i64,
) -> Option<i32> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // The App's default test URL is https://...; plain http:// is supported too.
    let (scheme, rest) = url.split_once("://")?;
    let use_tls = match scheme {
        "http" => false,
        "https" => true,
        other => {
            delay_diag(&format!("{} unsupported scheme '{}'", name, other));
            return None;
        }
    };
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next()?;
    let default_port = if use_tls { 443 } else { 80 };
    let port: u16 = authority
        .split(':')
        .nth(1)
        .and_then(|p| p.parse().ok())
        .unwrap_or(default_port);
    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::common::TargetAddr::Ip(ip, port),
        Err(_) => crate::common::TargetAddr::Domain(host.to_string(), port),
    };
    let path = format!("/{}", rest.split_once('/').map(|(_, p)| p).unwrap_or(""));
    let timeout = std::time::Duration::from_millis(timeout_ms as u64);

    let stream = match tokio::time::timeout(timeout, engine.dial_named(name, &target)).await {
        Err(_) => {
            delay_diag(&format!("{} dial {} timed out", name, target.address()));
            return None;
        }
        Ok(Err(e)) => {
            delay_diag(&format!("{} dial {} failed: {}", name, target.address(), e));
            return None;
        }
        Ok(Ok(s)) => s,
    };

    let mut stream = if use_tls {
        // The Go kernel's delay probe does not verify the target certificate and
        // speaks HTTP/1.1, so the target must not negotiate HTTP/2.
        match tokio::time::timeout(timeout, crate::adapter::tls::connect_tls_http1(host, stream, false)).await {
            Err(_) => {
                delay_diag(&format!("{} tls handshake timed out", name));
                return None;
            }
            Ok(Err(e)) => {
                delay_diag(&format!("{} tls handshake failed: {}", name, e));
                return None;
            }
            Ok(Ok(s)) => s,
        }
    } else {
        stream
    };

    let start = std::time::Instant::now();
    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, authority);
    match tokio::time::timeout(timeout, stream.write_all(request.as_bytes())).await {
        Err(_) => {
            delay_diag(&format!("{} request write timed out", name));
            return None;
        }
        Ok(Err(e)) => {
            delay_diag(&format!("{} request write failed: {}", name, e));
            return None;
        }
        Ok(Ok(_)) => {}
    }

    let mut buf = [0u8; 64];
    let n = match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
        Err(_) => {
            delay_diag(&format!("{} response read timed out", name));
            return None;
        }
        Ok(Err(e)) => {
            delay_diag(&format!("{} response read failed: {}", name, e));
            return None;
        }
        Ok(Ok(n)) => n,
    };
    if n == 0 {
        delay_diag(&format!("{} empty response", name));
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    if text.contains(" 200 ") || text.contains(" 204 ") {
        Some(start.elapsed().as_millis() as i32)
    } else {
        delay_diag(&format!(
            "{} unexpected status: {:?}",
            name,
            text.lines().next().unwrap_or("")
        ));
        None
    }
}

/// URL each service check probes. The set matches the Go kernel's checkers.
fn service_check_url(name: &str) -> Option<&'static str> {
    Some(match name {
        "google" => "https://www.google.com/generate_204",
        "github" => "https://github.com/",
        "youtube" => "https://www.youtube.com/generate_204",
        "chatgpt" => "https://chat.openai.com/",
        "claude" => "https://claude.ai/",
        "gemini" => "https://gemini.google.com/app",
        "netflix" => "https://www.netflix.com/",
        "disney-plus" => "https://www.disneyplus.com/",
        "prime-video" => "https://www.primevideo.com/",
        "spotify" => "https://www.spotify.com/",
        "tiktok" => "https://www.tiktok.com/",
        "discord" => "https://discord.com/",
        "bilibili" => "https://www.bilibili.com/",
        _ => return None,
    })
}

enum ProbeError {
    Timeout,
    Other,
}

async fn timed<T>(
    timeout: std::time::Duration,
    stage: &str,
    fut: impl std::future::Future<Output = std::io::Result<T>>,
) -> Result<T, ProbeError> {
    match tokio::time::timeout(timeout, fut).await {
        Err(_) => {
            probe_diag(&format!("{}: timeout after {:?}", stage, timeout));
            Err(ProbeError::Timeout)
        }
        Ok(Ok(v)) => Ok(v),
        Ok(Err(e)) => {
            // Previously the IO error was swallowed, leaving only a bare
            // "unavailable" with no clue which stage failed. Surface it.
            probe_diag(&format!("{}: {}", stage, e));
            Err(ProbeError::Other)
        }
    }
}

fn probe_diag(message: &str) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 200 {
        crate::jni::emit_log_event(&format!("[rust-core] probe: {}", message));
    }
}

/// A reachability probe for one service. Region-specific parsing is not
/// implemented; availability is reported from the HTTP status.
async fn service_probe(
    engine: &std::sync::Arc<crate::tunnel::Engine>,
    proxy_name: &str,
    url: &str,
    timeout_ms: i64,
) -> Result<(), ProbeError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (scheme, rest) = url.split_once("://").ok_or(ProbeError::Other)?;
    let use_tls = scheme == "https";
    let authority = rest.split('/').next().ok_or(ProbeError::Other)?;
    let host = authority.split(':').next().ok_or(ProbeError::Other)?;
    let port = authority
        .split(':')
        .nth(1)
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(if use_tls { 443 } else { 80 });
    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::common::TargetAddr::Ip(ip, port),
        Err(_) => crate::common::TargetAddr::Domain(host.to_string(), port),
    };
    let path = format!("/{}", rest.split_once('/').map(|(_, p)| p).unwrap_or(""));
    let timeout = std::time::Duration::from_millis(timeout_ms as u64);

    let stream = if proxy_name.is_empty() {
        timed(timeout, "dial", engine.dial(&target)).await?
    } else {
        timed(timeout, "dial_named", engine.dial_named(proxy_name, &target)).await?
    };
    let mut stream = if use_tls {
        timed(timeout, "target_tls", crate::adapter::tls::connect_tls_http1(host, stream, false)).await?
    } else {
        stream
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
        path, authority
    );
    timed(timeout, "request", stream.write_all(request.as_bytes())).await?;
    // A single read may return a partial status line or an interim 1xx, so
    // keep reading until a complete "HTTP/x.y NNN" line is present or the
    // budget runs out.
    let mut response = Vec::with_capacity(512);
    let mut buf = [0u8; 512];
    let ok = loop {
        let n = timed(timeout, "read", stream.read(&mut buf)).await?;
        if n == 0 {
            break false;
        }
        response.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&response);
        if let Some(line) = text.lines().find(|l| l.starts_with("HTTP/")) {
            if let Some(code) = line.split_whitespace().nth(1) {
                break code.starts_with('2') || code.starts_with('3');
            }
        }
        if response.len() > 16 * 1024 {
            break false;
        }
    };
    if ok {
        Ok(())
    } else {
        probe_diag(&format!(
            "read: no 2xx/3xx status in {} bytes",
            response.len()
        ));
        Err(ProbeError::Other)
    }
}

fn handle_service_check(call: &MethodCall) -> Vec<u8> {
    #[derive(Deserialize, Default)]
    struct Params {
        #[serde(rename = "proxy-name", default)]
        proxy_name: String,
        #[serde(default)]
        names: Vec<String>,
        timeout: i64,
    }
    let params: Params = serde_json::from_value(call.arguments.clone()).unwrap_or_default();
    let timeout_ms = if params.timeout > 0 { params.timeout } else { 5000 };
    let proxy_name = params.proxy_name.clone();
    let names = params.names.clone();
    let future = async move {
        let engine = match crate::runtime_state::engine().await {
            Some(e) => e,
            None => return Value::Array(Vec::new()),
        };
        let (_, version) = route_snapshot().await;
        let epoch = crate::runtime_state::core_epoch();
        let mut items = Vec::new();
        for name in names {
            let Some(url) = service_check_url(&name) else { continue };
            let started = std::time::Instant::now();
            let (status, delay) = match service_probe(&engine, &proxy_name, url, timeout_ms).await {
                Ok(()) => ("available", started.elapsed().as_millis() as i64),
                Err(ProbeError::Timeout) => ("timeout", -1i64),
                Err(ProbeError::Other) => ("unavailable", -1i64),
            };
            let checked_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            items.push(json!({
                "name": name,
                "status": status,
                "delay": delay,
                "chains": Vec::<String>::new(),
                "checked-at": checked_at,
                "core-epoch": epoch,
                "picks-version": version,
            }));
        }
        Value::Array(items)
    };
    ok(&call.id, block_on(future).unwrap_or(Value::Array(Vec::new())))
}

fn handle_get_traffic(call: &MethodCall, total: bool) -> Vec<u8> {
    let snap = crate::runtime_state::traffic_snapshot(total);
    if total {
        static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
        let should_log = {
            let mut last = LAST.lock().unwrap();
            let due = last.map_or(true, |t| t.elapsed().as_secs() >= 10);
            if due {
                *last = Some(std::time::Instant::now());
            }
            due
        };
        if should_log {
            crate::jni::emit_log_event(&format!("[rust-core] getTotalTraffic: up={} down={}", snap.up, snap.down));
        }
    }
    ok(&call.id, json!(snap))
}

fn handle_reset_traffic(call: &MethodCall) -> Vec<u8> {
    ok(&call.id, Value::Bool(true))
}

fn handle_encode_share_links(call: &MethodCall) -> Vec<u8> {
    let mappings = call.arguments.as_array().cloned().unwrap_or_default();
    ok(&call.id, json!(share_links::encode_links(&mappings)))
}

fn handle_convert_proxies(call: &MethodCall) -> Vec<u8> {
    // The App passes a path to a file containing either a YAML config or a
    // list of share links. Return the proxies as a list of maps.
    let arg = call.arguments.as_str().unwrap_or("");
    let text = read_config_text(arg);
    let mut proxies: Vec<serde_json::Value> = Vec::new();

    // First try a YAML config with a `proxies:` list.
    if let Ok(value) = serde_yaml::from_str::<serde_json::Value>(&text) {
        if let Some(arr) = value.get("proxies").and_then(|v| v.as_array()) {
            proxies.extend(arr.iter().cloned());
        }
    }

    // Otherwise treat each non-empty, non-YAML line as a share link.
    if proxies.is_empty() {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.contains(':') && !line.contains("://") {
                continue;
            }
            let decoded = share_links::decode_lines(&[line.to_string()]);
            if let Some(first) = decoded.first() {
                proxies.extend(first.iter().map(|m| serde_json::Value::Object(m.clone())));
            }
        }
    }
    ok(&call.id, json!(proxies))
}

fn handle_decode_share_links(call: &MethodCall) -> Vec<u8> {
    let lines: Vec<String> = call.arguments.as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    ok(&call.id, json!(share_links::decode_lines(&lines)))
}

fn handle_get_config(call: &MethodCall) -> Vec<u8> {
    let path = call.arguments.as_str().map(str::to_string);
    let future = async move { crate::runtime_state::read_raw_config(path.as_deref()).await };
    finish_fallible(&call.id, block_on(future))
}

fn fallible_err(id: &str, message: &str) -> Vec<u8> {
    encode(MethodResponse {
        id: id.to_string(),
        result: Value::Null,
        error: Some(MethodError {
            code: "config_error".into(),
            message: message.to_string(),
            details: None,
        }),
    })
}

/// Collapse the nested Result from block_on into a withFallible response.
fn finish_fallible(id: &str, result: Result<Result<Value, String>, String>) -> Vec<u8> {
    match result {
        Ok(Ok(value)) => ok(id, value),
        Ok(Err(e)) => fallible_err(id, &e),
        Err(e) => fallible_err(id, &e),
    }
}

fn handle_get_profile_base(call: &MethodCall) -> Vec<u8> {
    let path = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        // Go hashes the file's raw bytes and strips the sections the core
        // re-injects at merge time (proxies / proxy-groups / rules /
        // sub-rules). Returning them here would double-count them in the App
        // and duplicate the profile's rules in the generated overlay.
        let bytes = if path.is_empty() {
            let active = crate::runtime_state::config_path()
                .await
                .ok_or_else(|| "no config applied".to_string())?;
            std::fs::read(&active).map_err(|e| e.to_string())?
        } else {
            std::fs::read(&path).map_err(|e| e.to_string())?
        };
        let digest = sha256_hex(&bytes);
        let text = String::from_utf8_lossy(&bytes);
        let mut value: Value =
            serde_yaml::from_str(&text).map_err(|e| format!("parse profile: {}", e))?;
        let count = |key: &str| {
            value
                .get(key)
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0)
        };
        let counts = (
            count("proxies"),
            count("proxy-groups"),
            count("rules"),
        );
        let match_rules = profile_base::match_rules_of(&value);
        if let Some(obj) = value.as_object_mut() {
            for section in ["proxies", "proxy-groups", "rules", "sub-rules"] {
                obj.remove(section);
            }
        }
        Ok::<_, String>(json!({
            "config": value,
            "digest": digest,
            "match-rules": match_rules,
            "proxies": counts.0,
            "proxy-groups": counts.1,
            "rules": counts.2,
        }))
    };
    finish_fallible(&call.id, block_on(future))
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex_encode(&h.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(H[(b >> 4) as usize] as char);
        out.push(H[(b & 0x0f) as usize] as char);
    }
    out
}

fn handle_get_profile_outbounds(call: &MethodCall) -> Vec<u8> {
    let path = call.arguments.as_str().map(str::to_string);
    let future = async move {
        let value = crate::runtime_state::read_raw_config(path.as_deref()).await?;
        let extract = |key: &str| -> Vec<serde_json::Value> {
            value.get(key).and_then(|v| v.as_array()).map(|arr| arr.iter().map(|item| {
                json!({
                    "name": item.get("name").and_then(|v| v.as_str()).unwrap_or(""),
                    "type": item.get("type").and_then(|v| v.as_str()).unwrap_or(""),
                })
            }).collect()).unwrap_or_default()
        };
        Ok::<_, String>(json!({
            "proxies": extract("proxies"),
            "proxy-groups": extract("proxy-groups"),
        }))
    };
    finish_fallible(&call.id, block_on(future))
}

fn handle_get_proxy_definition(call: &MethodCall) -> Vec<u8> {
    let name = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        let value = crate::runtime_state::read_raw_config(None).await.unwrap_or(Value::Null);
        let find = |key: &str| -> Option<serde_json::Value> {
            value.get(key).and_then(|v| v.as_array()).and_then(|arr| {
                arr.iter().find(|item| item.get("name").and_then(|n| n.as_str()) == Some(&name)).cloned()
            })
        };
        Ok(find("proxies").or_else(|| find("proxy-groups")).unwrap_or(Value::Null))
    };
    finish_fallible(&call.id, block_on(future))
}

fn handle_external_providers(call: &MethodCall) -> Vec<u8> {
    let future = async {
        match crate::runtime_state::engine().await {
            Some(engine) => engine.proxy_providers.external_provider_json(),
            None => json!([]),
        }
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!([])))
}

fn handle_external_provider(call: &MethodCall) -> Vec<u8> {
    let name = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        match crate::runtime_state::engine().await {
            Some(engine) => engine.proxy_providers.external_provider_named(&name)
                .unwrap_or(Value::Null),
            None => Value::Null,
        }
    };
    ok(&call.id, block_on(future).unwrap_or(Value::Null))
}

fn handle_update_dns(call: &MethodCall) -> Vec<u8> {
    // DNS reload is a no-op in this slice (the resolver cache is per-engine).
    ok(&call.id, Value::Bool(true))
}

fn handle_get_connections(call: &MethodCall) -> Vec<u8> {
    let future = async {
        match crate::runtime_state::engine().await {
            Some(engine) => engine.connections.snapshot_json().await,
            None => json!({"uploadTotal": 0, "downloadTotal": 0, "connections": [], "memory": 0}),
        }
    };
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"connections": []})))
}

fn handle_get_chain_reports(call: &MethodCall) -> Vec<u8> {
    let future = async {
        match crate::runtime_state::engine().await {
            Some(engine) => serde_json::to_value(engine.config.chain_reports())
                .unwrap_or(Value::Null),
            None => Value::Array(Vec::new()),
        }
    };
    ok(&call.id, block_on(future).unwrap_or(Value::Array(Vec::new())))
}

fn handle_connection_count(call: &MethodCall) -> Vec<u8> {
    let future = async {
        match crate::runtime_state::engine().await {
            Some(engine) => engine.connections.count().await,
            None => 0,
        }
    };
    ok(&call.id, json!(block_on(future).unwrap_or(0)))
}

fn handle_close_connections(call: &MethodCall) -> Vec<u8> {
    let future = async {
        if let Some(engine) = crate::runtime_state::engine().await {
            engine.close_connections().await;
        }
    };
    let _ = block_on(future);
    ok(&call.id, Value::Bool(true))
}

fn handle_close_connection(call: &MethodCall) -> Vec<u8> {
    let id = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        match crate::runtime_state::engine().await {
            Some(engine) => engine.connections.close(&id).await,
            None => false,
        }
    };
    ok(&call.id, Value::Bool(block_on(future).unwrap_or(false)))
}

/// Merge a profile file with the App's overlay (Go's `mergeProfileBase`) and
/// write the result to the running config path, `<home>/config.yaml`, like
/// Go's `loadConfigWithBase` does. Returns that path on success.
fn merge_base_to_running_config(profile_path: &str, overlay: &str) -> Result<String, String> {
    let profile_text = std::fs::read_to_string(profile_path).map_err(|e| e.to_string())?;
    let merged = profile_base::merge_profile_base(&profile_text, overlay)?;
    let home = home_dir().ok_or_else(|| "core home dir not set".to_string())?;
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let target = home.join("config.yaml");
    let tmp = home.join(".config-merged.yaml");
    std::fs::write(&tmp, &merged).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, &target).map_err(|e| e.to_string())?;
    crate::jni::emit_log_event(&format!(
        "[rust-core] setupConfig base: merged {} + overlay -> {}",
        profile_path,
        target.display()
    ));
    Ok(target.to_string_lossy().into_owned())
}

fn handle_setup_config(call: &MethodCall) -> Vec<u8> {
    // Arguments: {"base":{"path":"...","overlay":"..."},"test-url":"...","selected-map":{...}}
    //
    // When the App sends a base, the config to load is NOT the profile file
    // alone: Go merges it with the overlay (patch settings, added rules,
    // injected providers) first. Loading the raw profile discarded all of
    // that, so App-side settings silently never took effect.
    let mut effective_path: Option<String> = None;
    if let Some(base) = call.arguments.get("base") {
        let profile_path = base.get("path").and_then(|p| p.as_str()).unwrap_or("");
        if !profile_path.is_empty() {
            let overlay = base.get("overlay").and_then(|o| o.as_str()).unwrap_or("");
            match merge_base_to_running_config(profile_path, overlay) {
                Ok(merged_path) => effective_path = Some(merged_path),
                Err(e) => {
                    crate::jni::emit_log_event(&format!(
                        "[rust-core] setupConfig base merge FAILED: {}",
                        e
                    ));
                    return ok(&call.id, Value::String(e));
                }
            }
        }
    }
    let path = effective_path
        .as_deref()
        .or_else(|| {
            call.arguments
                .get("base")
                .and_then(|b| b.get("path"))
                .and_then(|p| p.as_str())
                .filter(|p| !p.is_empty())
        })
        .or_else(|| call.arguments.get("path").and_then(|p| p.as_str()));

    let Some(path) = path else {
        // No path supplied. That is how the App sends a generated profile: it
        // assembles the YAML (subscription, script, overrides) and writes it to
        // `<home>/config.yaml` first. Loading that file is what makes a profile
        // or script switch take effect — keeping the previous engine is why a
        // switch looked like it did nothing. Only when the file is absent (a
        // plain service restart) do we keep the engine that is already running.
        let selected: Vec<(String, String)> = call
            .arguments
            .get("selected-map")
            .and_then(|v| v.as_object())
            .map(|m| m.iter().filter_map(|(g, p)| p.as_str().map(|s| (g.clone(), s.to_string()))).collect())
            .unwrap_or_default();
        let future = async move {
            let config_file = home_dir().map(|h| h.join("config.yaml"));
            if let Some(file) = config_file.filter(|f| f.is_file()) {
                let file = file.to_string_lossy().into_owned();
                crate::jni::emit_log_event(&format!(
                    "[rust-core] setupConfig no-path: applying {}",
                    file
                ));
                if let Err(e) = crate::runtime_state::apply_config_from_path(&file).await {
                    return e;
                }
                if let Some(engine) = crate::runtime_state::engine().await {
                    let mut applied = 0;
                    for (group, proxy) in selected {
                        if engine.outbounds.set_selection(&group, &proxy) {
                            applied += 1;
                        }
                    }
                    crate::jni::emit_log_event(&format!(
                        "[rust-core] setupConfig no-path: applied {} selection(s), {} proxies / {} groups",
                        applied,
                        engine.outbounds.outbounds.len(),
                        engine.outbounds.groups.len()
                    ));
                }
                return String::new();
            }
            match crate::runtime_state::engine().await {
                Some(engine) => {
                    for (group, proxy) in selected {
                        engine.outbounds.set_selection(&group, &proxy);
                    }
                    crate::jni::emit_log_event("[rust-core] setupConfig no-path: kept existing engine");
                }
                None => {
                    crate::jni::emit_log_event("[rust-core] setupConfig no-path: no engine, using default");
                    let _ = crate::runtime_state::apply_config(
                        crate::config::Config::default(),
                        std::path::PathBuf::from("config.yaml"),
                        std::path::PathBuf::from("."),
                    )
                    .await;
                }
            }
            String::new()
        };
        return match block_on(future) {
            Ok(message) => ok(&call.id, Value::String(message)),
            Err(e) => ok(&call.id, Value::String(e)),
        };
    };

    // The App sends the user's current selection for every selector group
    // together with the config path. Go applies this with patchSelectGroup()
    // right after loading the config; without it every group falls back to its
    // first member (usually DIRECT), so no traffic ever reaches a proxy.
    let selected: Vec<(String, String)> = call
        .arguments
        .get("selected-map")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(group, proxy)| proxy.as_str().map(|p| (group.clone(), p.to_string())))
                .collect()
        })
        .unwrap_or_default();

    let path_owned = path.to_string();
    let diag_path = path_owned.clone();
    let future = async move {
        let result = crate::runtime_state::apply_config_from_path(&path_owned).await;
        if result.is_ok() {
            if let Some(engine) = crate::runtime_state::engine().await {
                // Mirror Go's patchSelectGroup after a config load.
                let mut applied = 0;
                let mut missing = Vec::new();
                for (group, proxy) in &selected {
                    if engine.outbounds.set_selection(group, proxy) {
                        applied += 1;
                    } else {
                        missing.push(group.clone());
                    }
                }
                crate::jni::emit_log_event(&format!(
                    "[rust-core] setupConfig selected-map: {} applied, {} missing ({})",
                    applied,
                    missing.len(),
                    missing.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
                ));
                let msg = format!(
                    "[rust-core] config applied: {} proxies, {} groups, {} rules",
                    engine.outbounds.outbounds.len(),
                    engine.outbounds.groups.len(),
                    engine.rules.rules.len()
                );
                tracing::info!("{}", msg);
                crate::jni::emit_log_event(&msg);
                // Show the MATCH fallback group's kind and first members so a
                // chain ending in DIRECT is visible in one line.
                if let Some(target) = crate::runtime_state::engine().await
                    .and_then(|e| e.rules.rules.iter().rev()
                        .find(|r| matches!(r.kind, crate::rules::RuleKind::Match))
                        .map(|r| r.target.clone()))
                {
                    let detail = engine.outbounds.groups.get(&target).map(|g| format!(
                        "kind={} members={:?} selected={:?}",
                        g.kind,
                        g.members.iter().take(5).cloned().collect::<Vec<_>>(),
                        g.selected()
                    )).unwrap_or_else(|| "not a group".to_string());
                    let resolved = engine.outbounds.resolve(&target).await;
                    crate::jni::emit_log_event(&format!(
                        "[rust-core] MATCH target={} {} resolved={}",
                        target, detail, resolved
                    ));
                }
            }
        }
        result
    };
    // Emit the path we are reading to aid diagnosis.
    crate::jni::emit_log_event(&format!("[rust-core] setupConfig reading path: {}", diag_path));
    let outcome = match block_on(future) {
        Ok(Ok(())) => ok(&call.id, Value::String(String::new())),
        Ok(Err(e)) => {
            crate::jni::emit_log_event(&format!("[rust-core] setupConfig FAILED: {}", e));
            ok(&call.id, Value::String(e))
        }
        Err(e) => ok(&call.id, Value::String(e)),
    };
    // The App preloads startListener before the config exists. Now that a
    // config is loaded, open the local proxy ports it asked for so system-
    // proxy traffic (browser / Google apps) is not sent to a dead port.
    if LISTENER_WANTED.load(Ordering::Relaxed) {
        open_inbound_listeners();
    }
    outcome
}

/// Download a GeoX resource and reload the active engine so its rules pick up
/// the new geoip/geosite data. Returns an empty string on success.
fn handle_update_geo_data(call: &MethodCall) -> Vec<u8> {
    let geo_type = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        let home = match home_dir() {
            Some(h) => h,
            None => return "core home dir not set".to_string(),
        };
        match crate::geo::download_geo(&geo_type, &home).await {
            Ok(n) => {
                crate::jni::emit_log_event(&format!(
                    "[rust-core] updateGeoData {} ok ({} bytes)",
                    geo_type, n
                ));
                // Reload the engine so GEOIP/GEOSITE rules use the fresh data.
                let path = crate::runtime_state::config_path().await;
                if let Some(path) = path {
                    let path = path.to_string_lossy().into_owned();
                    if let Err(e) = crate::runtime_state::apply_config_from_path(&path).await {
                        crate::jni::emit_log_event(&format!(
                            "[rust-core] updateGeoData reload failed: {}",
                            e
                        ));
                    } else {
                        crate::jni::emit_log_event("[rust-core] updateGeoData engine reloaded");
                    }
                }
                String::new()
            }
            Err(e) => {
                crate::jni::emit_log_event(&format!("[rust-core] updateGeoData {} failed: {}", geo_type, e));
                e
            }
        }
    };
    match block_on(future) {
        Ok(message) => ok(&call.id, Value::String(message)),
        Err(e) => ok(&call.id, Value::String(e)),
    }
}

/// Apply per-run overrides (test-url, selected-map, skip-cert-verify) to the
/// running engine. The App calls this on every service start; replacing the
/// engine here would throw away the loaded profile and its strategy groups.
fn handle_quick_setup(call: &MethodCall) -> Vec<u8> {
    let selected: Vec<(String, String)> = call
        .arguments
        .get("selected-map")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(group, proxy)| {
                    proxy.as_str().map(|p| (group.clone(), p.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();
    let applied = selected.len();
    let future = async move {
        match crate::runtime_state::engine().await {
            Some(engine) => {
                for (group, proxy) in selected {
                    engine.outbounds.set_selection(&group, &proxy);
                }
                crate::jni::emit_log_event(&format!(
                    "[rust-core] quickSetup: applied {} selection(s), keeping {} proxies / {} groups",
                    applied,
                    engine.outbounds.outbounds.len(),
                    engine.outbounds.groups.len()
                ));
                Ok(())
            }
            None => {
                let config = crate::config::Config::default();
                let _ = crate::runtime_state::apply_config(
                    config,
                    std::path::PathBuf::from("config.yaml"),
                    std::path::PathBuf::from("."),
                )
                .await;
                Ok(())
            }
        }
    };
    match block_on(future) {
        Ok(Ok(())) => ok(&call.id, Value::String(String::new())),
        Ok(Err(e)) => ok(&call.id, Value::String(e)),
        Err(e) => ok(&call.id, Value::String(e)),
    }
}

/// Inline block_on for the small setup futures (they run on a dedicated thread
/// in the JNI path; this keeps `invoke` synchronous as gomobile expects).
/// Open the configured inbound listeners (HTTP/SOCKS/mixed/REST) so the App's
/// system-proxy mode has a local proxy to send browser/app traffic to. Without
/// this, Android's HTTP proxy points at a port nobody listens on and every
/// proxied app fails, while the core's own dial_named probes still work.
fn handle_start_listener(call: &MethodCall) -> Vec<u8> {
    LISTENER_WANTED.store(true, Ordering::Relaxed);
    let opened = open_inbound_listeners();
    ok(&call.id, Value::Bool(opened))
}

/// Bind the configured inbound ports using the currently loaded engine.
/// Returns true when at least one listener was opened, false when no config
/// is loaded yet (the deferred call after setupConfig will retry).
fn open_inbound_listeners() -> bool {
    stop_listener_tasks();
    // The listener tasks are spawned with tokio::spawn inside spawn_listeners,
    // so they live on whichever runtime is driving this future. A throwaway
    // block_on runtime would be dropped on return and close the ports again;
    // use the App's persistent runtime so the proxy port stays open.
    let Some(rt) = crate::jni::tokio_runtime() else {
        crate::jni::emit_log_event("[rust-core] startListener failed: no runtime");
        return false;
    };
    let result: Result<Vec<tokio::task::JoinHandle<()>>, String> = rt.block_on(async {
        let engine = match crate::runtime_state::engine().await {
            Some(e) => e,
            None => return Err("no engine loaded".to_string()),
        };
        let config_path = crate::runtime_state::config_path()
            .await
            .unwrap_or_else(|| PathBuf::from("config.yaml"));
        let state = crate::AppState {
            engine: tokio::sync::RwLock::new(engine),
            config_path: tokio::sync::RwLock::new(config_path),
            traffic: crate::runtime_state::traffic(),
        };
        Ok(crate::spawn_listeners(Arc::new(state)).await)
    });
    match result {
        Ok(handles) => {
            let count = handles.len();
            if count == 0 {
                // A config that asks for ports but bound none leaves the
                // system proxy pointing at a dead port. Report failure so the
                // App knows not to rely on it.
                crate::jni::emit_log_event(
                    "[rust-core] startListener: no inbound port could be bound",
                );
                return false;
            }
            *LISTENER_TASKS.lock().unwrap() = handles;
            crate::jni::emit_log_event(&format!(
                "[rust-core] startListener: {} inbound(s) opened",
                count
            ));
            true
        }
        Err(e) => {
            crate::jni::emit_log_event(&format!("[rust-core] startListener deferred: {}", e));
            false
        }
    }
}

fn stop_listener_tasks() {
    for task in LISTENER_TASKS.lock().unwrap().drain(..) {
        task.abort();
    }
}

fn handle_stop_listener(call: &MethodCall) -> Vec<u8> {
    LISTENER_WANTED.store(false, Ordering::Relaxed);
    stop_listener_tasks();
    ok(&call.id, Value::Bool(true))
}

fn block_on<F: std::future::Future + Send + 'static>(future: F) -> Result<F::Output, String>
where
    F::Output: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| e.to_string());
        match rt {
            Ok(rt) => {
                let out = rt.block_on(future);
                let _ = tx.send(Ok(out));
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        }
    });
    rx.recv().map_err(|_| "setup task failed".to_string())?
}

/// Read the argument as a file path first (the App writes subscription data to
/// a temp file and passes its path), falling back to treating it as inline YAML
/// content for compatibility with callers that pass the text directly.
fn read_config_text(arg: &str) -> String {
    if !arg.is_empty() && std::path::Path::new(arg).is_absolute() {
        if let Ok(bytes) = std::fs::read(arg) {
            return String::from_utf8_lossy(&bytes).into_owned();
        }
    }
    arg.to_string()
}

fn handle_validate_config(call: &MethodCall) -> Vec<u8> {
    let arg = call.arguments.as_str().unwrap_or("");
    let text = read_config_text(arg);
    // A subscription may be a share-link list rather than a YAML config. Accept
    // plain http/https/ss/etc. lines as valid (the App will convert them next).
    let trimmed = text.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://")
        || trimmed.starts_with("ss://") || trimmed.starts_with("ssr://")
        || trimmed.starts_with("vmess://") || trimmed.starts_with("vless://")
        || trimmed.starts_with("trojan://") {
        return ok(&call.id, Value::String(String::new()));
    }
    match crate::config::Config::from_str(&text) {
        Ok(_) => ok(&call.id, Value::String(String::new())),
        Err(e) => ok(&call.id, Value::String(e.to_string())),
    }
}

pub fn is_init() -> bool {
    IS_INIT.load(Ordering::Relaxed)
}

pub fn sequence() -> u64 {
    SEQ.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response(data: Vec<u8>) -> Value {
        serde_json::from_slice(&data).unwrap()
    }

    #[test]
    fn memory_stats_reports_real_rss() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let r = response(invoke(br#"{"method":"getMemoryStats"}"#));
        let rss = r["result"]["rss"].as_u64().unwrap_or(0);
        let heap = r["result"]["heapInuse"].as_u64().unwrap_or(0);
        assert!(rss > 0, "process RSS should be readable");
        assert!(heap > 0, "core heap estimate should be readable");
        assert!(heap <= rss, "core heap must not exceed total RSS");
    }

    #[test]
    fn core_version_is_branded_skyward_rust() {
        let r = response(invoke(br#"{"method":"coreVersion"}"#));
        let v = r["result"].as_str().unwrap();
        assert!(v.starts_with("Skyward Core (Rust) v"), "{v}");
        assert!(!v.contains("clash.meta/"), "uaFor adds that prefix: {v}");
        assert!(r["error"].is_null());
    }

    #[test]
    fn route_version_advances_only_when_picks_move() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        *ROUTE_REPORTED.lock().unwrap() = None;
        let mut a = serde_json::Map::new();
        a.insert("g".to_string(), Value::String("a".to_string()));
        let mut b = serde_json::Map::new();
        b.insert("g".to_string(), Value::String("b".to_string()));
        let v1 = reported_version(&a);
        assert_eq!(reported_version(&a), v1, "unchanged picks must keep their version");
        let v2 = reported_version(&b);
        assert!(v2 > v1, "a moved pick must move the version forward");
        assert_eq!(reported_version(&b), v2);
        *ROUTE_REPORTED.lock().unwrap() = None;
    }

    #[test]
    fn init_then_get_is_init() {
        let r = response(invoke(br#"{"id":"1","method":"initClash","arguments":{"home-dir":"/tmp/x","version":1}}"#));
        assert_eq!(r["id"], "1");
        assert_eq!(r["result"], true);
        let r = response(invoke(br#"{"method":"getIsInit"}"#));
        assert_eq!(r["result"], true);
    }

    #[test]
    fn rcx_methods_respond_not_unimplemented() {
        for method in [
            "rcxStatus", "rcxSetPolicy", "rcxHints", "rcxExplain",
            "rcxJournal", "rcxAction", "rcxProfiles", "rcxStudio",
        ] {
            let input = format!(r#"{{"id":"x","method":"{}"}}"#, method);
            let r = response(invoke(input.as_bytes()));
            assert!(
                r["error"].is_null(),
                "{} should be implemented: {:?}", method, r["error"]
            );
        }
        // A manual action returns a decision object the App can parse.
        let r = response(invoke(
            br#"{"method":"rcxAction","arguments":{"group":"Proxy","action":"change","node":"n1"}}"#,
        ));
        assert!(r["result"]["decision"].is_object());
    }

    #[test]
    fn unknown_method_is_not_implemented() {
        let r = response(invoke(br#"{"id":"x","method":"doesNotExist"}"#));
        assert_eq!(r["error"]["code"], "not_implemented");
        assert!(r["error"]["message"].as_str().unwrap().contains("doesNotExist"));
    }

    #[test]
    fn validate_config_ok_and_error() {
        let r = response(invoke(br#"{"method":"validateConfig","arguments":"mode: rule\nrules:\n  - MATCH,DIRECT\n"}"#));
        assert_eq!(r["result"], "");
        let r = response(invoke(br#"{"method":"validateConfig","arguments":"mode: bogus"}"#));
        assert!(r["result"].as_str().unwrap().contains("invalid mode"));
    }

    #[test]
    fn validate_config_accepts_file_path() {
        // Reproduces the real-device bug: the App passes a temp file path.
        let dir = std::env::temp_dir().join(format!("skyward-val-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("sub.yaml");
        std::fs::write(&file, "mode: rule\nrules:\n  - MATCH,DIRECT\n").unwrap();
        let payload = serde_json::json!({"method": "validateConfig", "arguments": file.to_string_lossy()}).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["result"], "", "path-based validateConfig must read the file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_config_accepts_share_link_file() {
        let dir = std::env::temp_dir().join(format!("skyward-share-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("sub.txt");
        std::fs::write(&file, "ss://YWVzLTI1Ni1nY206cHc@1.2.3.4:8388#node\n").unwrap();
        let payload = serde_json::json!({"method": "validateConfig", "arguments": file.to_string_lossy()}).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["result"], "");
        let payload = serde_json::json!({"method": "convertProxies", "arguments": file.to_string_lossy()}).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["result"][0]["type"], "ss");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_call_is_reported() {
        let r = response(invoke(b"not json"));
        assert_eq!(r["error"]["code"], "invalid_arguments");
    }

    #[test]
    fn setup_config_without_path_succeeds() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let r = response(invoke(br#"{"method":"setupConfig","arguments":{}}"#));
        assert_eq!(r["error"], Value::Null);
        assert_eq!(r["result"], "");
    }

    #[test]
    fn quick_setup_keeps_profile_groups() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let _ = block_on(crate::runtime_state::apply_config(
            crate::config::Config::from_str(
                "proxies:\n  - {name: n1, type: direct}\nproxy-groups:\n  - {name: g1, type: select, proxies: [n1, DIRECT]}\n",
            ).unwrap(),
            std::path::PathBuf::from("c.yaml"),
            std::path::PathBuf::from("."),
        ));
        let payload = serde_json::json!({
            "method": "quickSetup",
            "arguments": {"selected-map": {"g1": "n1"}}
        }).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["error"], Value::Null);
        let r = response(invoke(br#"{"method":"getProxies"}"#));
        assert!(r["result"]["proxies"]["g1"]["all"].as_array().is_some());
        assert_eq!(r["result"]["proxies"]["g1"]["now"], "n1");
    }

    #[test]
    fn get_proxies_returns_all_and_views() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        // Ensure an engine exists from a config with a group.
        let _ = block_on(crate::runtime_state::apply_config(
            crate::config::Config::from_str(
                "proxies:\n  - {name: n1, type: direct}\nproxy-groups:\n  - {name: g1, type: select, proxies: [n1, DIRECT]}\n",
            ).unwrap(),
            std::path::PathBuf::from("c.yaml"),
            std::path::PathBuf::from("."),
        ));
        let r = response(invoke(br#"{"method":"getProxies"}"#));
        assert!(r["result"]["all"].as_array().unwrap().iter().any(|n| n == "g1"));
        assert!(r["result"]["proxies"]["g1"]["all"].as_array().is_some());
        assert_eq!(r["result"]["proxies"]["g1"]["now"], "n1");
        // App's GroupType matches PascalCase names.
        assert_eq!(r["result"]["proxies"]["g1"]["type"], "Selector");
        // The App hides groups whose `hidden` is not exactly false; the
        // built-in GLOBAL is hidden, matching the Go kernel.
        assert_eq!(r["result"]["proxies"]["g1"]["hidden"], false);
        assert_eq!(r["result"]["proxies"]["GLOBAL"]["hidden"], true);
    }

    #[test]
    fn change_proxy_updates_selection() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        // Set up an engine with a group first (tests share global state).
        let _ = block_on(crate::runtime_state::apply_config(
            crate::config::Config::from_str(
                "proxies:\n  - {name: n1, type: direct}\nproxy-groups:\n  - {name: g1, type: select, proxies: [n1, DIRECT]}\n",
            ).unwrap(),
            std::path::PathBuf::from("c.yaml"),
            std::path::PathBuf::from("."),
        ));
        let payload = serde_json::json!({
            "method": "changeProxy",
            "arguments": {"group-name": "g1", "proxy-name": "DIRECT"}
        }).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["result"]["changed"], true);
    }

    #[test]
    fn log_and_route_methods() {
        let r = response(invoke(br#"{"method":"startLog"}"#));
        assert_eq!(r["result"], true);
        let r = response(invoke(br#"{"method":"watchRoute"}"#));
        assert!(r["result"].get("picks").is_some());
        assert!(r["result"].get("core-epoch").is_some());
        let r = response(invoke(br#"{"method":"stopLog"}"#));
        assert_eq!(r["result"], true);
    }

    #[test]
    fn provider_update_is_acknowledged() {
        let r = response(invoke(br#"{"method":"updateExternalProvider","arguments":"p1"}"#));
        assert_eq!(r["result"], "");
    }

    #[test]
    fn memory_stats_has_all_fields() {
        let r = response(invoke(br#"{"method":"getMemoryStats"}"#));
        assert!(r["result"].get("rss").is_some());
        assert!(r["result"].get("heapInuse").is_some());
        assert!(r["result"].get("deviceTotal").is_some());
    }

    #[test]
    fn validate_proxies_reports_errors() {
        let payload = serde_json::json!({
            "method": "validateProxies",
            "arguments": [
                {"type": "ss", "name": "ok", "server": "x", "port": 1, "cipher": "aes-256-gcm", "password": "p"},
                {"type": "bogus", "name": "bad"},
                {"type": "ss"}
            ]
        }).to_string();
        let r = response(invoke(payload.as_bytes()));
        let arr = r["result"].as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert_eq!(arr[0], "");
        assert!(arr[1].as_str().unwrap().contains("bogus"));
        assert!(arr[2].as_str().unwrap().contains("name"));
    }

    #[test]
    fn get_config_and_profile_outbounds() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("skyward-cfg-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("c.yaml");
        std::fs::write(&file, "proxies:\n  - {name: n1, type: ss, server: x, port: 1, cipher: aes-256-gcm, password: p}\nproxy-groups:\n  - {name: g1, type: select, proxies: [n1]}\nrules:\n  - MATCH,DIRECT\n").unwrap();
        let path = file.to_string_lossy().to_string();

        let payload = serde_json::json!({"method": "getConfig", "arguments": path}).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["error"], Value::Null);
        assert!(r["result"]["proxies"].is_array());

        let payload = serde_json::json!({"method": "getProfileOutbounds", "arguments": path}).to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["result"]["proxies"][0]["name"], "n1");
        assert_eq!(r["result"]["proxy-groups"][0]["name"], "g1");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn get_external_providers_returns_array() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let r = response(invoke(br#"{"method":"getExternalProviders"}"#));
        assert!(r["result"].is_array());
    }

    #[test]
    fn get_connections_returns_snapshot_shape() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let r = response(invoke(br#"{"method":"getConnections"}"#));
        assert!(r["result"]["connections"].is_array());
        assert!(r["result"].get("uploadTotal").is_some());
        assert!(r["result"].get("downloadTotal").is_some());
    }

    #[test]
    fn setup_config_from_file() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("skyward-setup-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("config.yaml");
        std::fs::write(&file, "mode: direct\nrules:\n  - MATCH,DIRECT\n").unwrap();
        let payload = serde_json::json!({
            "method": "setupConfig",
            "arguments": { "base": { "path": file.to_string_lossy() } }
        })
        .to_string();
        let r = response(invoke(payload.as_bytes()));
        assert_eq!(r["result"], "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn android_quick_setup_requires_saved_config_and_returns_plain_message() {
        let _guard = crate::runtime_state::TEST_LOCK.lock().unwrap();
        let dir = std::env::temp_dir().join(format!("skyward-quick-{}", rand::random::<u64>()));
        std::fs::create_dir(&dir).unwrap();
        let init = json!({"home-dir": dir}).to_string();
        assert!(!android_quick_setup(&init, "null").is_empty());
        assert!(!android_quick_setup(&init, "{}").is_empty());
        let file = dir.join("config.yaml");
        std::fs::write(&file, "mode: global\nrules:\n  - MATCH,REJECT\n").unwrap();
        assert_eq!(android_quick_setup(&init, "{}"), "");
        assert_eq!(block_on(crate::runtime_state::config_path()).unwrap(), Some(file));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
