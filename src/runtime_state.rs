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
    let config_path = PathBuf::from(path);
    let config = Config::load(&config_path).map_err(|e| e.to_string())?;
    let data_dir = config_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    apply_config(config, config_path, data_dir).await;
    Ok(())
}

pub async fn traffic_snapshot() -> crate::common::TrafficSnapshot {
    traffic().snapshot()
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
