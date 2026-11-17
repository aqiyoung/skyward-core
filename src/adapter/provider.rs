//! Proxy providers (`proxy-providers`) and subscription loading.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::adapter::{build_outbound, Outbound};
use crate::common::TargetAddr;
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
                let url = def.url.as_ref()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "http provider needs url"))?;
                let bytes = fetch_url(url).await?;
                if let Some(path) = &def.path {
                    let path = if Path::new(path).is_absolute() {
                        Path::new(path).to_path_buf()
                    } else {
                        data_dir.join(path)
                    };
                    let _ = tokio::fs::write(&path, &bytes).await;
                }
                bytes
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

        let check_enabled = def.health_check.enable;
        let check_url = def.health_check.url.as_deref();
        let mut proxies = Vec::with_capacity(definitions.len());
        for d in definitions {
            let outbound = build_outbound(&d);
            let latency = if check_enabled {
                match check_url {
                    Some(url) => check_proxy(&outbound, url).await,
                    None => Some(Duration::ZERO),
                }
            } else {
                Some(Duration::ZERO)
            };
            proxies.push(ProviderProxy {
                def: d,
                outbound,
                alive: latency.is_some(),
                latency,
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
}

#[derive(serde::Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub kind: String,
    pub count: usize,
    pub alive: usize,
}

/// Run one HTTP health check through the given outbound.
async fn check_proxy(outbound: &Arc<dyn Outbound>, url: &str) -> Option<Duration> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme != "http" {
        return None;
    }
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{}", path);
    let (host, port) = authority.rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|port| (h.to_string(), port)))
        .unwrap_or((authority.to_string(), 80));
    let target = match host.parse::<IpAddr>() {
        Ok(ip) => TargetAddr::Ip(ip, port),
        Err(_) => TargetAddr::Domain(host.clone(), port),
    };

    let started = Instant::now();
    let mut stream = timeout(Duration::from_secs(5), outbound.connect(&target)).await.ok()?.ok()?;
    let request = format!("GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n", path, host);
    timeout(Duration::from_secs(5), stream.write_all(request.as_bytes())).await.ok()?.ok()?;
    let mut response = [0u8; 64];
    let n = timeout(Duration::from_secs(5), stream.read(&mut response)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&response[..n]);
    if text.contains(" 200 ") || text.contains(" 204 ") {
        Some(started.elapsed())
    } else {
        None
    }
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
            username: None,
            uuid: None,
            sni: None,
            tls: None,
            server_name: None,
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
