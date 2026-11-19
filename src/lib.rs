//! skyward-core (Rust) — a mihomo-compatible proxy kernel, rewritten incrementally.

pub mod adapter;
pub mod common;
pub mod config;
pub mod dns;
pub mod ffi;
pub mod fake_ip;
pub mod fetch;
pub mod geo;
pub mod hub;
pub mod inbound;
pub mod jni;
pub mod mobile;
pub mod net;
pub mod rules;
pub mod runtime_state;
pub mod tunnel;
pub mod tun;

// Re-export for the REST controller.
pub use tunnel::connection::{ConnectionInfo, Network};

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::RwLock;
use tokio::task::JoinHandle;

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

    /// Swap in a freshly built engine (used by FFI `apply_config`, where the
    /// config comes from a byte buffer rather than a file path).
    pub async fn replace_engine(&self, engine: Engine) {
        *self.engine.write().await = Arc::new(engine);
    }
}

/// Spawn all configured listeners (inbounds + REST controller) and return their
/// task handles so a caller (CLI or FFI) can shut them down. The config is
/// read from the current engine snapshot.
pub async fn spawn_listeners(state: Arc<AppState>) -> Vec<JoinHandle<()>> {
    let engine = state.engine.read().await.clone();
    let config = &engine.config;
    let host = if config.allow_lan { "0.0.0.0" } else { "127.0.0.1" };
    let mut specs: Vec<(&'static str, u16)> = Vec::new();
    if let Some(p) = config.socks_port { specs.push(("socks5", p)); }
    if let Some(p) = config.port { specs.push(("http", p)); }
    if let Some(p) = config.mixed_port { specs.push(("mixed", p)); }
    if let Some(p) = config.redir_port { specs.push(("redir", p)); }
    if let Some(p) = config.tproxy_port { specs.push(("tproxy", p)); }
    let controller = config.external_controller.clone();
    drop(engine);

    let mut handles = Vec::new();
    for (kind, port) in specs {
        let transparent = kind == "redir" || kind == "tproxy";
        let addr = format!("{}:{}", if transparent { "0.0.0.0" } else { host }, port);
        let bound = if kind == "redir" {
            inbound::transparent::bind_redir(port).await
        } else if kind == "tproxy" {
            inbound::transparent::bind_tproxy(port).await
        } else {
            inbound::bind(&addr).await
        };
        match bound {
            Ok(listener) => {
                tracing::info!("{} inbound listening on {}", kind, addr);
                let st = state.clone();
                handles.push(tokio::spawn(async move {
                    match kind {
                        "socks5" => inbound::serve_socks(listener, st).await,
                        "http" => inbound::serve_http(listener, st).await,
                        "redir" => inbound::transparent::serve_redir(listener, st).await,
                        "tproxy" => inbound::transparent::serve_tproxy(listener, st).await,
                        _ => inbound::serve_mixed(listener, st).await,
                    }
                }));
            }
            Err(e) => tracing::error!("failed to bind {} on {}: {}", kind, addr, e),
        }
    }
    if let Some(addr) = controller {
        let st = state.clone();
        tracing::info!("REST controller listening on {}", addr);
        handles.push(tokio::spawn(async move {
            if let Err(e) = hub::serve(&addr, st).await {
                tracing::error!("REST controller on {} stopped: {}", addr, e);
            }
        }));
    }
    handles
}
