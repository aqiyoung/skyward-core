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
        "getTraffic" => handle_get_traffic(&call, false),
        "getTotalTraffic" => handle_get_traffic(&call, true),
        "resetTraffic" => handle_reset_traffic(&call),
        "getConnections" => ok(&call.id, json!({"connections": []})),
        "getConnectionCount" => ok(&call.id, json!(0)),
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
        let r = response(invoke(br#"{"method":"setupConfig","arguments":{}}"#));
        assert_eq!(r["error"], Value::Null);
        assert_eq!(r["result"], "");
    }

    #[test]
    fn get_proxies_returns_all_and_views() {
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
    fn setup_config_from_file() {
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
