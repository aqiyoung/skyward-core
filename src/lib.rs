//! skyward-core (Rust) — a mihomo-compatible proxy kernel, rewritten incrementally.

pub mod adapter;
pub mod common;
pub mod config;
pub mod dns;
pub mod geo;
pub mod hub;
pub mod inbound;
pub mod rules;
pub mod tunnel;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;

use crate::common::SharedTraffic;
use crate::config::Config;
use crate::tunnel::Engine;

/// Shared application state. The engine is swapped atomically on reload so
/// in-flight connections keep using the configuration they started with.
pub struct AppState {
    pub engine: RwLock<Arc<Engine>>,
    pub config_path: RwLock<PathBuf>,
    pub traffic: SharedTraffic,
}

impl AppState {
    pub fn new(engine: Engine, config_path: PathBuf, traffic: SharedTraffic) -> Self {
        Self {
            engine: RwLock::new(Arc::new(engine)),
            config_path: RwLock::new(config_path),
            traffic,
        }
    }

    pub async fn reload(&self) -> anyhow::Result<()> {
        let path = self.config_path.read().await.clone();
        let config = Config::load(&path)?;
        let data_dir = path.parent().unwrap_or_else(|| Path::new("."));
        *self.engine.write().await = Arc::new(Engine::new(config, self.traffic.clone(), data_dir).await);
        tracing::info!("configuration reloaded from {}", path.display());
        Ok(())
    }
}
