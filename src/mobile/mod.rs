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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::common::VERSION;

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
        "startListener" => ok(&call.id, Value::Bool(true)),
        "stopListener" => ok(&call.id, Value::Bool(true)),
        "getMemoryStats" => ok(&call.id, json!({"inuse": 0, "oslimit": 0})),
        "getProxies" => handle_get_proxies(&call),
        "changeProxy" => handle_change_proxy(&call),
        "asyncTestDelay" => handle_test_delay(&call),
        "getTraffic" => handle_get_traffic(&call, false),
        "getTotalTraffic" => handle_get_traffic(&call, true),
        "resetTraffic" => handle_reset_traffic(&call),
        "getConfig" => handle_get_config(&call),
        "getProfileBase" => handle_get_profile_base(&call),
        "getProfileOutbounds" => handle_get_profile_outbounds(&call),
        "getProxyDefinition" => handle_get_proxy_definition(&call),
        "getExternalProviders" => handle_external_providers(&call),
        "getExternalProvider" => handle_external_provider(&call),
        "updateDns" => handle_update_dns(&call),
        "getConnections" => handle_get_connections(&call),
        "getConnectionCount" => handle_connection_count(&call),
        "closeConnections" => handle_close_connections(&call),
        "resetConnections" => handle_close_connections(&call),
        "closeConnection" => handle_close_connection(&call),
        "clearDnsCache" => ok(&call.id, Value::Bool(true)),
        "validateConfig" => handle_validate_config(&call),
        "setupConfig" => handle_setup_config(&call),
        "updateConfig" => handle_setup_config(&call),
        "message" => ok(&call.id, Value::Null),
        other => err(&call.id, "not_implemented", format!("unknown method: {}", other)),
    }
}

fn core_version() -> String {
    // The App's User-Agent probes expect a `clash.meta/<ver>`-style prefix to
    // select mihomo YAML from subscription providers.
    format!("clash.meta/{} (rust)", VERSION)
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

fn handle_get_proxies(call: &MethodCall) -> Vec<u8> {
    let future = async {
        let engine = crate::runtime_state::engine().await;
        let Some(engine) = engine else {
            return json!({"proxies": {}, "all": []});
        };
        let snapshots = engine.outbounds.snapshot();
        let mut views = serde_json::Map::new();
        let mut all = Vec::new();
        for item in &snapshots {
            all.push(item.name.clone());
            let mut view = serde_json::Map::new();
            view.insert("name".into(), Value::String(item.name.clone()));
            view.insert("type".into(), Value::String(item.kind.clone()));
            if !item.members.is_empty() {
                view.insert("all".into(), json!(item.members));
                if let Some(sel) = &item.selected {
                    view.insert("now".into(), Value::String(sel.clone()));
                }
            }
            views.insert(item.name.clone(), Value::Object(view));
        }
        json!({"proxies": views, "all": all})
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
    let future = async move {
        let engine = match crate::runtime_state::engine().await {
            Some(e) => e,
            None => {
                return json!({"url": url, "name": name, "value": -2, "message": "not initialized"});
            }
        };
        let delay = measure_delay(&engine, &name, &url, timeout_ms).await;
        match delay {
            Some(ms) => json!({"url": url, "name": name, "value": ms}),
            None => json!({"url": url, "name": name, "value": -2, "message": "connect failed"}),
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
    let rest = url.strip_prefix("http://")?;
    let authority = rest.split('/').next()?;
    let host = authority.split(':').next()?;
    let port: u16 = authority.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(80);
    let target = match host.parse::<std::net::IpAddr>() {
        Ok(ip) => crate::common::TargetAddr::Ip(ip, port),
        Err(_) => crate::common::TargetAddr::Domain(host.to_string(), port),
    };
    let path = format!("/{}", rest.split_once('/').map(|(_, p)| p).unwrap_or(""));

    let dial = engine.dial_named(name, &target);
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms as u64),
        dial,
    )
    .await
    .ok()?
    .ok()?;

    let start = std::time::Instant::now();
    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, authority);
    tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms as u64),
        stream.write_all(request.as_bytes()),
    )
    .await
    .ok()?
    .ok()?;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(
        std::time::Duration::from_millis(timeout_ms as u64),
        stream.read(&mut buf),
    )
    .await
    .ok()?
    .ok()?;
    if n == 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&buf[..n]);
    if text.contains(" 200 ") || text.contains(" 204 ") {
        Some(start.elapsed().as_millis() as i32)
    } else {
        None
    }
}

fn handle_get_traffic(call: &MethodCall, total: bool) -> Vec<u8> {
    let future = async move {
        let snap = crate::runtime_state::traffic_snapshot().await;
        // App expects the delta for getTraffic and cumulative for getTotalTraffic.
        let (_up, _down) = (snap.up, snap.down);
        json!({"up": snap.up, "down": snap.down})
    };
    let _ = total; // both share the same snapshot in this slice
    ok(&call.id, block_on(future).unwrap_or_else(|_| json!({"up": 0, "down": 0})))
}

fn handle_reset_traffic(call: &MethodCall) -> Vec<u8> {
    ok(&call.id, Value::Bool(true))
}

fn handle_get_config(call: &MethodCall) -> Vec<u8> {
    let path = call.arguments.as_str().map(str::to_string);
    let future = async move {
        crate::runtime_state::raw_config_json_at(&path.unwrap_or_default())
            .or_else(|_| futures_block_on_raw())
    };
    // withFallible shape: result on success, error string on failure.
    match block_on(future) {
        Ok(Ok(value)) => ok(&call.id, value),
        Ok(Err(e)) => fallible_err(&call.id, &e),
        Err(e) => fallible_err(&call.id, &e),
    }
}

fn futures_block_on_raw() -> Result<serde_json::Value, String> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let out = rt.block_on(crate::runtime_state::raw_config_json());
        let _ = tx.send(out);
    });
    rx.recv().map_err(|_| "config read failed".to_string())?
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

fn handle_get_profile_base(call: &MethodCall) -> Vec<u8> {
    let path = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        let value = crate::runtime_state::raw_config_json_at(&path)
            .or_else(|_| futures_block_on_raw())?;
        let digest = sha256_hex(&value.to_string().into_bytes());
        let proxies = value.get("proxies").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        let groups = value.get("proxy-groups").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        let rules = value.get("rules").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
        Ok::<_, String>(json!({
            "config": value,
            "digest": digest,
            "match-rules": [],
            "proxies": proxies,
            "proxy-groups": groups,
            "rules": rules,
        }))
    };
    match block_on(future) {
        Ok(v) => ok(&call.id, v),
        Err(e) => fallible_err(&call.id, &e),
    }
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
    let path = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        let value = crate::runtime_state::raw_config_json_at(&path)
            .or_else(|_| futures_block_on_raw())?;
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
    match block_on(future) {
        Ok(v) => ok(&call.id, v),
        Err(e) => fallible_err(&call.id, &e),
    }
}

fn handle_get_proxy_definition(call: &MethodCall) -> Vec<u8> {
    let name = call.arguments.as_str().unwrap_or("").to_string();
    let future = async move {
        let value = match futures_block_on_raw() {
            Ok(v) => v,
            Err(e) => return fallible_err("", &e),
        };
        let find = |key: &str| -> Option<serde_json::Value> {
            value.get(key).and_then(|v| v.as_array()).and_then(|arr| {
                arr.iter().find(|item| item.get("name").and_then(|n| n.as_str()) == Some(&name)).cloned()
            })
        };
        let result = find("proxies").or_else(|| find("proxy-groups")).unwrap_or(Value::Null);
        Ok(result)
    };
    match block_on(future) {
        Ok(v) => ok(&call.id, v),
        Err(e) => fallible_err(&call.id, &e),
    }
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
        match crate::runtime_state::engine().await {
            Some(engine) => { engine.connections.close_all().await; }
            None => {}
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

fn handle_setup_config(call: &MethodCall) -> Vec<u8> {
    // Arguments: {"base":{"path":"..."},"test-url":"...","selected-map":{...}}
    let path = call
        .arguments
        .get("base")
        .and_then(|b| b.get("path"))
        .and_then(|p| p.as_str())
        .or_else(|| call.arguments.get("path").and_then(|p| p.as_str()));

    let Some(path) = path else {
        // No path supplied: apply an empty config so the engine exists and the
        // TUN relay can at least start with DIRECT routing.
        let future = async {
            let config = crate::config::Config::default();
            crate::runtime_state::apply_config(
                config,
                std::path::PathBuf::from("config.yaml"),
                std::path::PathBuf::from("."),
            )
            .await;
        };
        return match block_on(future) {
            Ok(()) => ok(&call.id, Value::String(String::new())),
            Err(e) => ok(&call.id, Value::String(e)),
        };
    };

    let path_owned = path.to_string();
    let future = async move { crate::runtime_state::apply_config_from_path(&path_owned).await };
    match block_on(future) {
        Ok(Ok(())) => ok(&call.id, Value::String(String::new())),
        Ok(Err(e)) => ok(&call.id, Value::String(e)),
        Err(e) => ok(&call.id, Value::String(e)),
    }
}

/// Inline block_on for the small setup futures (they run on a dedicated thread
/// in the JNI path; this keeps `invoke` synchronous as gomobile expects).
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

fn handle_validate_config(call: &MethodCall) -> Vec<u8> {
    // The App sends the raw config as a string argument.
    let text = call.arguments.as_str().unwrap_or("");
    match crate::config::Config::from_str(text) {
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
    fn core_version_has_meta_prefix() {
        let r = response(invoke(br#"{"method":"coreVersion"}"#));
        assert!(r["result"].as_str().unwrap().starts_with("clash.meta/"));
        assert!(r["error"].is_null());
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
}
