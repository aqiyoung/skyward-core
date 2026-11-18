//! Outbound abstraction and proxy groups. In the Go kernel this is the
//! `adapter/` + `adapter/outboundgroup/` tree. Only DIRECT and REJECT terminate
//! connections in this slice; other protocol types are parsed and surfaced but
//! report a clear "not implemented" error when selected.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::common::TargetAddr;
use crate::config::{Config, ProxyDef};

pub mod http_proxy;
pub mod provider;
pub mod shadowsocks;
pub mod snell;
pub mod socks5;
pub mod ssr;
pub mod tls;
pub mod trojan;
pub mod vless;
pub mod vmess;

use http_proxy::HttpOutbound;
use shadowsocks::ShadowsocksOutbound;
use snell::SnellOutbound;
use socks5::Socks5Outbound;
use ssr::SsrOutbound;
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
            match crate::net::connect_tcp(addr).await {
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
    /// Whether an explicit selection (from the App's selected-map or a
    /// changeProxy call) has been applied. Health-based groups default to the
    /// first real node until the App picks one.
    explicit: AtomicBool,
}

impl GroupState {
    pub fn selected(&self) -> Option<String> {
        let kind = self.kind.as_str();
        let is_health = matches!(kind, "url-test" | "fallback");
        let idx = self.cursor.load(Ordering::Relaxed);
        let chosen = if is_health && !self.explicit.load(Ordering::Relaxed) {
            // mihomo would pick the healthiest node here. Without probes, pick
            // the first real proxy rather than a DIRECT/REJECT sentinel, or
            // the group routes every connection straight out.
            self.members
                .iter()
                .position(|m| !matches!(m.as_str(), "DIRECT" | "REJECT"))
                .unwrap_or(0)
        } else {
            idx % self.members.len().max(1)
        };
        self.members.get(chosen).cloned()
    }

    pub fn set_selected(&self, name: &str) -> bool {
        if let Some(i) = self.members.iter().position(|m| m == name) {
            self.cursor.store(i, Ordering::Release);
            self.explicit.store(true, Ordering::Release);
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
}

pub fn build_outbound(def: &ProxyDef) -> Arc<dyn Outbound> {
    // Per-node TLS verification, matching the Go kernel (which governs proxy
    // outbound TLS by `skip-cert-verify` in the proxy config).
    let verify = !def.skip_cert_verify.unwrap_or(false);
    match def.kind.as_str() {
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
                            verify,
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
                            verify,
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "socks5 (invalid config)".into(),
                        }))
                }
                "ssr" | "shadowsocksr" => {
                    let made = match (def.server.as_deref(), def.port, def.password.as_deref(), def.cipher.as_deref()) {
                        (Some(server), Some(port), Some(password), Some(cipher)) => SsrOutbound::try_new(
                            &def.name,
                            server,
                            port,
                            password,
                            cipher,
                            def.protocol.as_deref(),
                            def.obfs.as_deref(),
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "ssr (unsupported cipher/protocol/obfs or invalid config)".into(),
                        }))
                }
                "snell" => {
                    let made = match (def.server.as_deref(), def.port, def.psk.as_deref().or(def.password.as_deref())) {
                        (Some(server), Some(port), Some(psk)) => SnellOutbound::try_new(
                            &def.name,
                            server,
                            port,
                            psk,
                            def.version.unwrap_or(1),
                            def.tls.unwrap_or(false),
                            def.sni.as_deref().or(def.server_name.as_deref()),
                            verify,
                        ),
                        _ => None,
                    };
                    made.map(|o| Arc::new(o) as Arc<dyn Outbound>)
                        .unwrap_or_else(|| Arc::new(UnimplementedOutbound {
                            name: def.name.clone(),
                            kind: "snell (invalid config or unsupported version)".into(),
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
                            verify,
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
                            verify,
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
                            verify,
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
            }
}

impl OutboundManager {
    pub fn new(config: &Config) -> Self {
        let mut outbounds: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        outbounds.insert("DIRECT".into(), Arc::new(DirectOutbound::new("DIRECT")));
        outbounds.insert("REJECT".into(), Arc::new(RejectOutbound::new("REJECT")));

        for def in &config.proxies {
            let outbound = build_outbound(def);
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
                explicit: AtomicBool::new(false),
            });
        }
        groups.insert("GLOBAL".into(), GroupState {
            name: "GLOBAL".into(),
            kind: "select".into(),
            members: global_members,
            url: None,
            cursor: AtomicUsize::new(0),
            explicit: AtomicBool::new(false),
        });

        Self { outbounds, groups }
    }

    /// Resolve a rule target down to a concrete outbound name. A group's
    /// selected member may itself be a group (the rule chain), so keep
    /// following the chain until an outbound is reached, like mihomo.
    pub async fn resolve(&self, name: &str) -> String {
        let mut current = name.to_string();
        for _ in 0..16 {
            let Some(group) = self.groups.get(&current) else {
                return current;
            };
            let candidates: Vec<String> = group.members.iter()
                .filter(|m| self.outbounds.contains_key(*m) || self.groups.contains_key(*m))
                .cloned()
                .collect();
            if candidates.is_empty() {
                return "DIRECT".to_string();
            }

            // Never block the data path on health probes: probing every
            // candidate (hundreds of nodes at up to 800ms each) stalled every
            // connection for minutes. Use the current selection, which the
            // App's delay tests keep up to date.
            let next = match group.kind.as_str() {
                "load-balance" => {
                    let i = group.cursor.fetch_add(1, Ordering::Relaxed) % candidates.len();
                    candidates[i].clone()
                }
                _ => group
                    .selected()
                    .filter(|name| candidates.contains(name))
                    .unwrap_or_else(|| candidates[0].clone()),
            };
            if next == current {
                return current;
            }
            current = next;
        }
        current
    }

    pub fn outbound(&self, name: &str) -> Option<Arc<dyn Outbound>> {
        self.outbounds.get(name).cloned()
    }

    pub fn register(&mut self, name: String, outbound: Arc<dyn Outbound>) {
        self.outbounds.insert(name, outbound);
    }

    pub fn set_group_members(&mut self, name: &str, members: Vec<String>) {
        if let Some(group) = self.groups.get_mut(name) {
            group.members = members;
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolve_follows_nested_groups() {
        let config = crate::config::Config::from_str(
            "proxies:\n  - {name: n1, type: direct}\nproxy-groups:\n  - {name: g2, type: select, proxies: [n1]}\n  - {name: g1, type: select, proxies: [g2]}\n",
        ).unwrap();
        let manager = OutboundManager::new(&config);
        assert_eq!(manager.resolve("g1").await, "n1");
        assert_eq!(manager.resolve("g2").await, "n1");
        // A concrete outbound resolves to itself.
        assert_eq!(manager.resolve("n1").await, "n1");
        assert_eq!(manager.resolve("DIRECT").await, "DIRECT");
    }
}
