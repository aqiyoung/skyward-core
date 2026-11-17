//! Outbound abstraction and proxy groups. In the Go kernel this is the
//! `adapter/` + `adapter/outboundgroup/` tree. Only DIRECT and REJECT terminate
//! connections in this slice; other protocol types are parsed and surfaced but
//! report a clear "not implemented" error when selected.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::RwLock;
use tokio::time::timeout;

use crate::common::TargetAddr;
use crate::config::Config;

pub mod http_proxy;
pub mod shadowsocks;
pub mod socks5;
pub mod tls;
pub mod trojan;
pub mod vless;
pub mod vmess;

use http_proxy::HttpOutbound;
use shadowsocks::ShadowsocksOutbound;
use socks5::Socks5Outbound;
use trojan::TrojanOutbound;
use vless::VlessOutbound;
use vmess::VmessOutbound;

pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

#[async_trait]
pub trait Outbound: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &str;
    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream>;
}

pub struct DirectOutbound {
    name: String,
}
impl DirectOutbound {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}
#[async_trait]
impl Outbound for DirectOutbound {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { "Direct" }
    async fn connect(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let mut last_error = None;
        for addr in target.resolve_all().await? {
            match tokio::net::TcpStream::connect(addr).await {
                Ok(stream) => return Ok(Box::new(stream)),
                Err(e) => last_error = Some(e),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no reachable address")
        }))
    }
}

pub struct RejectOutbound {
    name: String,
}
impl RejectOutbound {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}
#[async_trait]
impl Outbound for RejectOutbound {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { "Reject" }
    async fn connect(&self, _target: &TargetAddr) -> io::Result<BoxedStream> {
        Err(io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by rule"))
    }
}

/// Placeholder for protocols that are not ported yet (ss, vless, vmess, …).
pub struct UnimplementedOutbound {
    name: String,
    kind: String,
}
#[async_trait]
impl Outbound for UnimplementedOutbound {
    fn name(&self) -> &str { &self.name }
    fn kind(&self) -> &str { &self.kind }
    async fn connect(&self, _target: &TargetAddr) -> io::Result<BoxedStream> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("outbound '{}' (type '{}') is not implemented in the Rust core yet",
                    self.name, self.kind),
        ))
    }
}

#[derive(Debug)]
pub struct GroupState {
    pub name: String,
    pub kind: String,
    pub members: Vec<String>,
    pub url: Option<String>,
    /// Selected index for `select`; rolling counter for `load-balance`.
    cursor: AtomicUsize,
}

impl GroupState {
    pub fn selected(&self) -> Option<String> {
        self.members.get(self.cursor.load(Ordering::Relaxed) % self.members.len().max(1)).cloned()
    }

    pub fn set_selected(&self, name: &str) -> bool {
        if let Some(i) = self.members.iter().position(|m| m == name) {
            self.cursor.store(i, Ordering::Release);
            true
        } else {
            false
        }
    }
}

#[derive(serde::Serialize)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<String>,
    pub selected: Option<String>,
}

/// Owns the outbound registry and group-selection logic.
pub struct OutboundManager {
    pub outbounds: HashMap<String, Arc<dyn Outbound>>,
    pub groups: HashMap<String, GroupState>,
    health: RwLock<HashMap<String, (Instant, String)>>,
}

impl OutboundManager {
    pub fn new(config: &Config) -> Self {
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert("DIRECT".into(), Arc::new(DirectOutbound::new("DIRECT")));
        outbounds.insert("REJECT".into(), Arc::new(RejectOutbound::new("REJECT")));

        for def in &config.proxies {
            let outbound: Arc<dyn Outbound> = match def.kind.as_str() {
                "direct" => Arc::new(DirectOutbound::new(def.name.clone())),
                "reject" => Arc::new(RejectOutbound::new(def.name.clone())),
                "http" => {
                    let made = match (def.server.as_deref(), def.port) {
                        (Some(server), Some(port)) => HttpOutbound::try_new(
                            &def.name,
                            server,
                            port,
                            def.username.as_deref(),
                            def.password.as_deref(),
                            def.tls.unwrap_or(false),
                            def.sni.as_deref().or(def.server_name.as_deref()),
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "http (invalid config)".into(),
                        }))
                }
                "socks5" => {
                    let made = match (def.server.as_deref(), def.port) {
                        (Some(server), Some(port)) => Socks5Outbound::try_new(
                            &def.name,
                            server,
                            port,
                            def.username.as_deref(),
                            def.password.as_deref(),
                            def.tls.unwrap_or(false),
                            def.sni.as_deref().or(def.server_name.as_deref()),
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "socks5 (invalid config)".into(),
                        }))
                }
                "ss" | "shadowsocks" => {
                    let made = match (def.server.as_deref(), def.port, def.cipher.as_deref(), def.password.as_deref()) {
                        (Some(server), Some(port), Some(cipher), Some(password)) => {
                            ShadowsocksOutbound::try_new(&def.name, server, port, cipher, password)
                        }
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: format!("ss ({})", def.cipher.as_deref().unwrap_or("invalid config")),
                        }))
                }
                "vmess" => {
                    let made = match (def.server.as_deref(), def.port, def.uuid.as_deref()) {
                        (Some(server), Some(port), Some(uuid)) => VmessOutbound::try_new(
                            &def.name,
                            server,
                            port,
                            uuid,
                            def.cipher.as_deref().unwrap_or("auto"),
                            def.tls.unwrap_or(false),
                            def.sni.as_deref().or(def.server_name.as_deref()),
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "vmess (invalid config)".into(),
                        }))
                }
                "vless" => {
                    let made = match (def.server.as_deref(), def.port, def.uuid.as_deref()) {
                        (Some(server), Some(port), Some(uuid)) => VlessOutbound::try_new(
                            &def.name,
                            server,
                            port,
                            uuid,
                            def.tls.unwrap_or(false),
                            def.sni.as_deref().or(def.server_name.as_deref()),
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "vless (invalid config)".into(),
                        }))
                }
                "trojan" => {
                    let made = match (def.server.as_deref(), def.port, def.password.as_deref()) {
                        (Some(server), Some(port), Some(password)) => TrojanOutbound::try_new(
                            &def.name,
                            server,
                            port,
                            password,
                            def.sni.as_deref(),
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "trojan (invalid config)".into(),
                        }))
                }
                _ => Arc::new(UnimplementedOutbound {
                    name: def.name.clone(),
                    kind: def.kind.clone(),
                }),
            };
            outbounds.insert(def.name.clone(), outbound);
        }

        // GLOBAL is a synthetic group over every named proxy, like mihomo.
        let mut global_members: Vec<String> = config.proxies.iter().map(|p| p.name.clone()).collect();
        global_members.push("DIRECT".into());
        let mut groups: HashMap<String, GroupState> = HashMap::new();
        for g in &config.proxy_groups {
            groups.insert(g.name.clone(), GroupState {
                name: g.name.clone(),
                kind: g.kind.clone(),
                members: g.proxies.clone(),
                url: g.url.clone(),
                cursor: AtomicUsize::new(0),
            });
        }
        groups.insert("GLOBAL".into(), GroupState {
            name: "GLOBAL".into(),
            kind: "select".into(),
            members: global_members,
            url: None,
            cursor: AtomicUsize::new(0),
        });

        Self { outbounds, groups, health: RwLock::new(HashMap::new()) }
    }

    /// Resolve a rule target down to a concrete outbound name.
    pub async fn resolve(&self, name: &str) -> String {
        let group = match self.groups.get(name) {
            Some(g) => g,
            None => return name.to_string(),
        };
        let candidates: Vec<String> = group.members.iter()
            .filter(|m| self.outbounds.contains_key(*m) || self.groups.contains_key(*m))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return "DIRECT".to_string();
        }

        match group.kind.as_str() {
            "load-balance" => {
                let i = group.cursor.fetch_add(1, Ordering::Relaxed) % candidates.len();
                candidates[i].clone()
            }
            "url-test" | "fallback" => self.pick_healthiest(group, &candidates).await,
            _ => group.selected().unwrap_or_else(|| candidates[0].clone()),
        }
    }

    async fn pick_healthiest(&self, group: &GroupState, candidates: &[String]) -> String {
        {
            let cache = self.health.read().await;
            if let Some((at, name)) = cache.get(&group.name) {
                if at.elapsed() < Duration::from_secs(60) && candidates.contains(name) {
                    return name.clone();
                }
            }
        }

        let mut best: Option<(Duration, String)> = None;
        for name in candidates {
            if let Some(d) = self.probe(name).await {
                if best.as_ref().map(|(bd, _)| d < *bd).unwrap_or(true) {
                    best = Some((d, name.clone()));
                }
            }
        }
        let chosen = best.map(|(_, n)| n).unwrap_or_else(|| candidates[0].clone());
        self.health.write().await.insert(group.name.clone(), (Instant::now(), chosen.clone()));
        chosen
    }

    /// Measure how long a TCP connect through an outbound takes. Unimplemented
    /// outbounds fail the probe and are therefore never selected.
    async fn probe(&self, name: &str) -> Option<Duration> {
        let outbound = self.outbounds.get(name)?;
        let target = TargetAddr::Domain("www.gstatic.com".into(), 80);
        let started = Instant::now();
        match timeout(Duration::from_millis(800), outbound.connect(&target)).await {
            Ok(Ok(_)) => Some(started.elapsed()),
            _ => None,
        }
    }

    pub fn outbound(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(name).cloned()
    }

    pub fn snapshot(&self) -> Vec<ProxyInfo> {
        let mut items: Vec<ProxyInfo> = self.outbounds.values().map(|o| ProxyInfo {
            name: o.name().to_string(),
            kind: o.kind().to_string(),
            members: Vec::new(),
            selected: None,
        }).collect();
        let mut groups: Vec<ProxyInfo> = self.groups.values().map(|g| ProxyInfo {
            name: g.name.clone(),
            kind: g.kind.clone(),
            members: g.members.clone(),
            selected: g.selected(),
        }).collect();
        items.append(&mut groups);
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }

    pub fn set_selection(&self, group: &str, member: &str) -> bool {
        self.groups.get(group).map(|g| g.set_selected(member)).unwrap_or(false)
    }
}

// Keep IpAddr referenced so the import stays meaningful for future IP rules.
#[allow(dead_code)]
fn _ip_marker(_: Option<IpAddr>) {}
