//! The tunnel glues inbound connections to rules and outbound adapters.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

pub mod connection;

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::adapter::provider::ProxyProviderRegistry;
use crate::adapter::{BoxedStream, OutboundManager};
use crate::common::{SharedTraffic, TargetAddr};
use crate::config::Config;
use crate::dns::Resolver;
use crate::geo::GeoData;
use crate::rules::provider::ProviderRegistry;
use crate::rules::RuleSet;

use connection::{ConnectionTracker, Network};

/// AsyncWrite wrapper that feeds bytes moved through it into the traffic counters.
struct CountingWriter<W> {
    inner: W,
    counter: Arc<AtomicU64>,
    traffic: SharedTraffic,
    upload: bool,
}

impl<W> CountingWriter<W> {
    fn new(inner: W, counter: Arc<AtomicU64>, traffic: SharedTraffic, upload: bool) -> Self {
        Self { inner, counter, traffic, upload }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.counter.fetch_add(n as u64, Ordering::Relaxed);
                if this.upload {
                    this.traffic.add_upload(n as u64);
                } else {
                    this.traffic.add_download(n as u64);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

pub struct Engine {
    pub config: Config,
    pub rules: RuleSet,
    pub resolver: Resolver,
    pub outbounds: OutboundManager,
    pub traffic: SharedTraffic,
    pub mode: RwLock<String>,
    pub geo: Arc<GeoData>,
    pub providers: Arc<ProviderRegistry>,
    pub proxy_providers: Arc<ProxyProviderRegistry>,
    pub connections: Arc<ConnectionTracker>,
    /// Fires when the App asks for the connection list to be closed, so the
    /// relays stop instead of leaving established flows on the old outbound.
    pub close_signal: Arc<tokio::sync::Notify>,
}

/// Rate-limited diagnostics for connection routing, so the log shows which
/// rule/outbound a connection used.
fn dial_diag(message: String) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 200 {
        crate::jni::emit_log_event(&format!("[rust-core] {}", message));
    }
}

impl Engine {
    pub async fn new(config: Config, traffic: SharedTraffic, data_dir: &Path) -> Self {
        let t0 = std::time::Instant::now();
        let log = |s: String| {
            tracing::info!("{}", s);
            crate::jni::emit_log_event(&format!("[rust-core] {}", s));
        };
        let rules = RuleSet::new(&config.rules);
        let resolver = Resolver::new(config.dns.clone().unwrap_or_default());
        // Diagnostics: show the mode and the final (MATCH) rule target. If all
        // traffic resolves to DIRECT, the mode or the fallback rule is the cause.
        let match_rule = rules
            .rules
            .iter()
            .rev()
            .find(|r| matches!(r.kind, crate::rules::RuleKind::Match));
        log(format!(
            "engine: mode={} rules={} match_target={:?}",
            config.mode,
            rules.rules.len(),
            match_rule.map(|r| r.target.as_str())
        ));
        log(format!("engine: rules/resolver done ({:?})", t0.elapsed()));
        let proxy_providers = Arc::new(ProxyProviderRegistry::load(&config, data_dir).await);
        log(format!("engine: proxy_providers done ({:?})", t0.elapsed()));
        let mut outbounds = OutboundManager::new(&config);
        log(format!("engine: outbounds done ({:?})", t0.elapsed()));

        // Provider nodes become first-class outbounds so groups and rules can
        // refer to them by name.
        let provider_nodes = proxy_providers.all_outbounds();
        for (name, outbound) in &provider_nodes {
            outbounds.register(name.clone(), outbound.clone());
        }
        for g in &config.proxy_groups {
            if !g.use_providers.is_empty() {
                let mut members = g.proxies.clone();
                members.extend(proxy_providers.member_names(&g.use_providers));
                outbounds.set_group_members(&g.name, members);
            }
        }
        if let Some(global) = outbounds.groups.get_mut("GLOBAL") {
            global.members.extend(provider_nodes.into_iter().map(|(name, _)| name));
        }

        let mode = RwLock::new(config.mode.clone());
        log(format!("engine: loading geo ({:?})", t0.elapsed()));
        // mihomo keeps GeoX files in the core home dir, which may differ from
        // the config file's parent. Search both so GEOIP/GEOSITE rules work.
        let home = crate::mobile::home_dir();
        let geo_dirs: Vec<&Path> = match home.as_deref() {
            Some(h) if h != data_dir => vec![data_dir, h],
            _ => vec![data_dir],
        };
        let geo = Arc::new(GeoData::load_from(&geo_dirs));
        log(format!("engine: geo done ({:?}) geoip={} geosite={} ({:?})",
            t0.elapsed(), geo.geoip.len(), geo.geosite.len(), t0.elapsed()));
        let providers = Arc::new(ProviderRegistry::load(&config, data_dir).await);
        log(format!("engine: rule providers done ({:?})", t0.elapsed()));
        let connections = Arc::new(ConnectionTracker::new());
        Self {
            config,
            rules,
            resolver,
            outbounds,
            traffic,
            mode,
            geo,
            providers,
            proxy_providers,
            connections,
            close_signal: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Close every tracked connection and stop the relays behind them.
    pub async fn close_connections(&self) -> usize {
        let count = self.connections.close_all().await;
        self.close_signal.notify_waiters();
        count
    }

    /// Choose a rule target based on the active mode and the rule set.
    pub async fn decide(&self, target: &TargetAddr) -> String {
        let mode = self.mode.read().await.clone();
        match mode.as_str() {
            "direct" => "DIRECT".to_string(),
            "global" => "GLOBAL".to_string(),
            _ => {
                let resolved = match target {
                    TargetAddr::Domain(h, _) => self.resolver.resolve_first(h).await.ok(),
                    TargetAddr::Ip(ip, _) => Some(*ip),
                };
                match self.rules.find(target, resolved, Some(&self.geo), Some(&self.providers)) {
                    Some(rule) => rule.target.clone(),
                    None => {
                        // No rule matched (e.g. GEOIP/GEOSITE with empty geo data,
                        // or RULE-SET with no provider). Say why instead of
                        // silently routing to DIRECT.
                        static NO_MATCH: std::sync::atomic::AtomicUsize =
                            std::sync::atomic::AtomicUsize::new(0);
                        if NO_MATCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 10 {
                            crate::jni::emit_log_event(&format!(
                                "[rust-core] no rule matched for {} (geoip={} geosite={} rule-providers={}); using DIRECT",
                                target.address(), self.geo.geoip.len(), self.geo.geosite.len(), self.providers.len()
                            ));
                        }
                        "DIRECT".to_string()
                    }
                }
            }
        }
    }

    /// Dial a target through the rule/outbound pipeline without relaying.
    /// Used by the TUN stack, which drives the socket itself and only needs a
    /// connected stream to bridge bytes into.
    pub async fn dial(&self, target: &TargetAddr) -> io::Result<BoxedStream> {
        let rule_target = self.decide(target).await;
        let final_name = self.outbounds.resolve(&rule_target).await;
        dial_diag(format!(
            "dial {} -> rule={} outbound={}",
            target.address(),
            rule_target,
            final_name
        ));
        let outbound = self.outbounds.outbound(&final_name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown outbound '{}'", final_name))
        })?;
        match outbound.connect(target).await {
            Ok(stream) => Ok(stream),
            Err(e) => {
                dial_diag(format!(
                    "dial {} via {} FAILED: {}",
                    target.address(),
                    final_name,
                    e
                ));
                Err(e)
            }
        }
    }

    /// Open a UDP packet session to `target` through the rule/outbound
    /// pipeline. Used by the TUN stack's UDP session manager.
    pub async fn dial_udp(
        &self,
        target: &TargetAddr,
    ) -> io::Result<Box<dyn crate::adapter::PacketConn>> {
        let rule_target = self.decide(target).await;
        let final_name = self.outbounds.resolve(&rule_target).await;
        let outbound = self.outbounds.outbound(&final_name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown outbound '{}'", final_name))
        })?;
        outbound.connect_udp(target).await.map_err(|e| {
            dial_diag(format!(
                "dial_udp {} via {} FAILED: {}",
                target.address(),
                final_name,
                e
            ));
            e
        })
    }

    /// Dial a target through a specific outbound/group name (used by delay tests).
    pub async fn dial_named(&self, name: &str, target: &TargetAddr) -> io::Result<BoxedStream> {
        let final_name = self.outbounds.resolve(name).await;
        let outbound = self.outbounds.outbound(&final_name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown outbound '{}'", final_name))
        })?;
        outbound.connect(target).await
    }

    /// Drive a single inbound connection to completion. `prefix` carries bytes
    /// already consumed from the inbound during handshakes (e.g. an HTTP head).
    pub async fn handle(&self, target: TargetAddr, inbound: TcpStream, prefix: &[u8]) -> io::Result<()> {
        let rule_target = self.decide(&target).await;
        let final_name = self.outbounds.resolve(&rule_target).await;

        tracing::info!(
            target = %target.address(),
            rule = %rule_target,
            outbound = %final_name,
            "establish"
        );

        let source = inbound
            .peer_addr()
            .ok()
            .map(|addr| (addr.ip().to_string(), addr.port()));
        let (id, up_counter, down_counter) = self.connections
            .add(&target, &rule_target, "", vec![final_name.clone(), rule_target.clone()], Network::Tcp, source)
            .await;

        let outbound = self.outbounds.outbound(&final_name);
        let result = match outbound {
            Some(outbound) => {
                match outbound.connect(&target).await {
                    Err(e) => {
                        dial_diag(format!(
                            "dial {} via {} FAILED: {}",
                            target.address(),
                            final_name,
                            e
                        ));
                        Err(e)
                    }
                    Ok(mut remote) => {
                        if !prefix.is_empty() {
                            remote.write_all(prefix).await?;
                        }
                        let (mut rin, mut win) = tokio::io::split(inbound);
                        let (mut rout, mut wout) = tokio::io::split(remote);
                        let mut up = CountingWriter::new(&mut wout, up_counter, self.traffic.clone(), true);
                        let mut down = CountingWriter::new(&mut win, down_counter, self.traffic.clone(), false);
                        let result = tokio::select! {
                            r = tokio::io::copy(&mut rin, &mut up) => r.map(|_| ()),
                            r = tokio::io::copy(&mut rout, &mut down) => r.map(|_| ()),
                        };
                        let _ = wout.shutdown().await;
                        let _ = win.shutdown().await;
                        result
                    }
                }
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, format!("unknown outbound '{}'", final_name))),
        };

        self.connections.remove(&id).await;
        result
    }
}
