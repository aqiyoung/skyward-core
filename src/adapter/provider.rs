//! Proxy providers (`proxy-providers`) and subscription loading.

use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use regex::Regex;
use serde::Deserialize;

use crate::adapter::{build_outbound, Outbound};
use crate::config::{Config, ProxyDef, ProxyProviderDef};
use crate::fetch::fetch_url;

pub struct ProviderProxy {
    pub def: ProxyDef,
    pub outbound: Arc<dyn Outbound>,
    pub alive: bool,
    pub latency: Option<Duration>,
}

pub struct ProxyProvider {
    pub name: String,
    pub kind: String,
    proxies: Vec<ProviderProxy>,
}

impl ProxyProvider {
    fn alive_names(&self) -> Vec<String> {
        let mut items: Vec<(Duration, String)> = self.proxies.iter()
            .filter(|p| p.alive)
            .map(|p| (p.latency.unwrap_or(Duration::from_secs(3600)), p.def.name.clone()))
            .collect();
        items.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        items.into_iter().map(|(_, name)| name).collect()
    }

    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    pub fn all_outbounds(&self) -> Vec<(String, Arc<dyn Outbound>)> {
        self.proxies.iter().map(|p| (p.def.name.clone(), p.outbound.clone())).collect()
    }
}

#[derive(Default)]
pub struct ProxyProviderRegistry {
    providers: HashMap<String, ProxyProvider>,
}

impl ProxyProviderRegistry {
    pub async fn load(config: &Config, data_dir: &Path) -> Self {
        let mut registry = Self::default();
        for (name, def) in &config.proxy_providers {
            // Skip http providers without a local cache so startup is instant.
            if def.kind == "http" {
                let cached = def.path.as_ref().map(|p| {
                    if Path::new(p).is_absolute() { Path::new(p).to_path_buf() } else { data_dir.join(p) }
                });
                if !cached.map(|p| p.exists()).unwrap_or(false) {
                    tracing::warn!("proxy provider {} skipped (no local cache, http)", name);
                    continue;
                }
            }
            match Self::build(name, def, data_dir).await {
                Ok(provider) => {
                    tracing::info!("proxy provider {} loaded ({} nodes)", name, provider.len());
                    registry.providers.insert(name.clone(), provider);
                }
                Err(e) => tracing::warn!("failed to load proxy provider {}: {}", name, e),
            }
        }
        registry
    }

    async fn build(name: &str, def: &ProxyProviderDef, data_dir: &Path) -> io::Result<ProxyProvider> {
        let raw: Vec<u8> = match def.kind.as_str() {
            "inline" => Vec::new(),
            "file" => {
                let path = def.path.as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file provider needs path"))?;
                let path = if Path::new(path).is_absolute() {
                    Path::new(path).to_path_buf()
                } else {
                    data_dir.join(path)
                };
                tokio::fs::read(&path).await.map_err(|e| io::Error::new(e.kind(), format!("read {}: {}", path.display(), e)))?
            }
            "http" => {
                // Prefer cached copy to keep core startup fast and offline-safe.
                if let Some(path) = &def.path {
                    let cached = if Path::new(path).is_absolute() {
                        Path::new(path).to_path_buf()
                    } else {
                        data_dir.join(path)
                    };
                    if let Ok(bytes) = tokio::fs::read(&cached).await {
                        bytes
                    } else {
                        let url = def.url.as_ref()
                            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "http provider needs url"))?;
                        let bytes = fetch_url(url).await?;
                        let _ = tokio::fs::write(&cached, &bytes).await;
                        bytes
                    }
                } else {
                    let url = def.url.as_ref()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "http provider needs url"))?;
                    fetch_url(url).await?
                }
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown provider type '{}'", other))),
        };

        let mut definitions: Vec<ProxyDef> = if raw.is_empty() {
            def.payload.clone()
        } else {
            #[derive(Deserialize)]
            struct Subscription {
                #[serde(default, alias = "Proxy", alias = "PROXIES")]
                proxies: Vec<ProxyDef>,
            }
            let sub: Subscription = serde_yaml::from_slice(&raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("subscription YAML: {}", e)))?;
            sub.proxies
        };

        let include = def.filter.as_deref().and_then(|s| Regex::new(s).ok());
        let exclude = def.exclude_filter.as_deref().and_then(|s| Regex::new(s).ok());
        let exclude_type = def.exclude_type.as_deref();
        definitions.retain(|d| {
            if include.as_ref().map(|re| !re.is_match(&d.name)).unwrap_or(false) {
                return false;
            }
            if exclude.as_ref().map(|re| re.is_match(&d.name)).unwrap_or(false) {
                return false;
            }
            if exclude_type.map(|t| d.kind == t).unwrap_or(false) {
                return false;
            }
            true
        });

        // Do NOT run health probes during startup: with hundreds of nodes this
        // would block core readiness for minutes. Mark all nodes alive and let
        // on-demand delay tests (asyncTestDelay) measure them later.
        let _ = &def.health_check;
        let mut proxies = Vec::with_capacity(definitions.len());
        for d in definitions {
            let outbound = build_outbound(&d);
            proxies.push(ProviderProxy {
                def: d,
                outbound,
                alive: true,
                latency: Some(Duration::ZERO),
            });
        }

        Ok(ProxyProvider {
            name: name.to_string(),
            kind: def.kind.clone(),
            proxies,
        })
    }

    /// Expand `use:` entries into concrete proxy names, ordered by latency.
    pub fn member_names(&self, names: &[String]) -> Vec<String> {
        let mut out = Vec::new();
        for name in names {
            match self.providers.get(name) {
                Some(provider) => out.extend(provider.alive_names()),
                None => out.push(name.clone()),
            }
        }
        out
    }

    pub fn all_outbounds(&self) -> Vec<(String, Arc<dyn Outbound>)> {
        self.providers.values().flat_map(|p| p.all_outbounds()).collect()
    }

    pub fn snapshot(&self) -> Vec<ProviderInfo> {
        let mut items: Vec<ProviderInfo> = self.providers.values().map(|p| ProviderInfo {
            name: p.name.clone(),
            kind: p.kind.clone(),
            count: p.len(),
            alive: p.proxies.iter().filter(|x| x.alive).count(),
        }).collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }

    /// Go-compatible ExternalProvider shape for the App's provider page.
    pub fn external_provider_json(&self) -> serde_json::Value {
        let items: Vec<serde_json::Value> = self.snapshot().into_iter().map(|p| {
            serde_json::json!({
                "name": p.name,
                "type": "Proxy",
                "vehicle-type": p.kind,
                "count": p.count,
                "path": "",
                "update-at": "0001-01-01T00:00:00Z",
                "subscription-info": null,
            })
        }).collect();
        serde_json::Value::Array(items)
    }

    pub fn external_provider_named(&self, name: &str) -> Option<serde_json::Value> {
        self.providers.get(name).map(|p| serde_json::json!({
            "name": p.name,
            "type": "Proxy",
            "vehicle-type": p.kind,
            "count": p.len(),
            "path": "",
            "update-at": "0001-01-01T00:00:00Z",
            "subscription-info": null,
        }))
    }
}

#[derive(serde::Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub kind: String,
    pub count: usize,
    pub alive: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_def(name: String) -> ProxyDef {
        ProxyDef {
            name,
            kind: "direct".into(),
            server: None,
            port: None,
            cipher: None,
            password: None,
            psk: None,
            version: None,
            protocol: None,
            obfs: None,
            username: None,
            uuid: None,
            sni: None,
            tls: None,
            server_name: None,
            skip_cert_verify: None,
        }
    }

    fn provider_with_nodes(latencies: Vec<Option<Duration>>) -> ProxyProvider {
        let proxies = latencies.into_iter().enumerate().map(|(i, latency)| {
            let def = dummy_def(format!("node{}", i));
            let outbound = build_outbound(&def);
            ProviderProxy {
                def,
                outbound,
                alive: latency.is_some(),
                latency,
            }
        }).collect();
        ProxyProvider { name: "test".into(), kind: "inline".into(), proxies }
    }

    #[test]
    fn alive_names_are_latency_ordered() {
        let provider = provider_with_nodes(vec![
            Some(Duration::from_millis(50)),
            None,
            Some(Duration::from_millis(10)),
        ]);
        assert_eq!(provider.alive_names(), vec!["node2", "node0"]);
    }

    #[test]
    fn registry_expands_provider_members() {
        let mut registry = ProxyProviderRegistry::default();
        registry.providers.insert("test".into(), provider_with_nodes(vec![Some(Duration::ZERO)]));
        let members = registry.member_names(&["test".into(), "DIRECT".into()]);
        assert_eq!(members, vec!["node0", "DIRECT"]);
    }

    #[test]
    fn snapshot_reports_counts() {
        let mut registry = ProxyProviderRegistry::default();
        registry.providers.insert("test".into(), provider_with_nodes(vec![Some(Duration::ZERO), None]));
        let snap = registry.snapshot();
        assert_eq!(snap[0].count, 2);
        assert_eq!(snap[0].alive, 1);
    }
}
