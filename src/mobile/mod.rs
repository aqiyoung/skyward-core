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
        "getTraffic" => ok(&call.id, json!({"up": 0, "down": 0})),
        "getTotalTraffic" => ok(&call.id, json!({"up": 0, "down": 0})),
        "resetTraffic" => ok(&call.id, Value::Bool(true)),
        "getProxies" => ok(&call.id, json!({"proxies": [], "groups": []})),
        "getConnections" => ok(&call.id, json!({"connections": []})),
        "getConnectionCount" => ok(&call.id, json!(0)),
        "clearDnsCache" => ok(&call.id, Value::Bool(true)),
        "validateConfig" => handle_validate_config(&call),
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

    fn response(data: &[u8]) -> Value {
        serde_json::from_slice(data).unwrap()
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
}
