//! Global runtime state shared by the JNI bridge, the mobile `invokeMethod`
//! handlers and the TUN loop: the active engine and its config path.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::common::TrafficStats;
use crate::config::Config;
use crate::tunnel::Engine;

/// The live engine, swapped atomically by setupConfig/updateConfig.
static ENGINE: RwLock<Option<Arc<Engine>>> = RwLock::const_new(None);
static CONFIG_PATH: RwLock<Option<PathBuf>> = RwLock::const_new(None);
static TRAFFIC: std::sync::OnceLock<Arc<TrafficStats>> = std::sync::OnceLock::new();

fn traffic() -> Arc<TrafficStats> {
    TRAFFIC.get_or_init(|| Arc::new(TrafficStats::default())).clone()
}

pub async fn engine() -> Option<Arc<Engine>> {
    ENGINE.read().await.clone()
}

/// Build an engine from a config and install it as the active one.
pub async fn apply_config(config: Config, config_path: PathBuf, data_dir: PathBuf) -> Arc<Engine> {
    let engine = Arc::new(Engine::new(config, traffic(), &data_dir).await);
    *ENGINE.write().await = Some(engine.clone());
    *CONFIG_PATH.write().await = Some(config_path);
    engine
}

/// Install an already-built engine (used on first startup / fallback).
pub async fn set_engine(engine: Arc<Engine>) {
    *ENGINE.write().await = Some(engine);
}

/// Load config from `path`, parse it, and apply. Returns an error string on
/// failure (matching the Go `withMessage` convention).
pub async fn apply_config_from_path(path: &str) -> Result<(), String> {
    let log = |m: &str| {
        tracing::info!("{}", m);
        crate::jni::emit_log_event(&format!("[rust-core] {}", m));
    };
    log(&format!("apply_config: loading {}", path));
    let config_path = PathBuf::from(path);
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            log(&format!("apply_config: PARSE FAILED: {}", e));
            return Err(e.to_string());
        }
    };
    log(&format!("apply_config: parsed {} proxies, {} groups, {} rules, {} providers",
        config.proxies.len(), config.proxy_groups.len(), config.rules.len(),
        config.proxy_providers.len()));
    let data_dir = config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    log("apply_config: building engine...");
    apply_config(config, config_path, data_dir).await;
    log("apply_config: engine built and installed");
    Ok(())
}

pub async fn traffic_snapshot() -> crate::common::TrafficSnapshot {
    traffic().snapshot()
}

pub async fn config_path() -> Option<PathBuf> {
    CONFIG_PATH.read().await.clone()
}

/// Read the active config file and decode it to a JSON value (RawConfig shape).
pub async fn raw_config_json() -> Result<serde_json::Value, String> {
    let path = config_path().await.ok_or("no config applied")?;
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_yaml::from_str(&text).map_err(|e| e.to_string())?;
    Ok(value)
}

/// Read a specific config file path and decode to JSON.
pub fn raw_config_json_at(path: &str) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_yaml::from_str(&text).map_err(|e| e.to_string())
}

/// Read raw config JSON from an optional path, falling back to the active one.
pub async fn read_raw_config(path: Option<&str>) -> Result<serde_json::Value, String> {
    if let Some(p) = path {
        if !p.is_empty() {
            return raw_config_json_at(p);
        }
    }
    raw_config_json().await
}

/// Test-only lock to serialize tests that mutate the global engine.
#[cfg(test)]
pub static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn applies_config_and_exposes_engine() {
        let _guard = TEST_LOCK.lock().unwrap();
        // Global state is shared across tests in one process; don't assume it
        // starts empty — just verify an applied engine is retrievable.
        let config = Config::from_str("mode: rule\nrules:\n  - MATCH,DIRECT\n").unwrap();
        let e = apply_config(config, PathBuf::from("c.yaml"), PathBuf::from(".")).await;
        assert!(Arc::ptr_eq(&e, &engine().await.unwrap()));
    }
}
