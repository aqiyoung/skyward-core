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
use crate::adapter::OutboundManager;
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
}

impl Engine {
    pub async fn new(config: Config, traffic: SharedTraffic, data_dir: &Path) -> Self {
        let rules = RuleSet::new(&config.rules);
        let resolver = Resolver::new(config.dns.clone().unwrap_or_default());
        let proxy_providers = Arc::new(ProxyProviderRegistry::load(&config, data_dir).await);
        let mut outbounds = OutboundManager::new(&config);

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
        let geo = Arc::new(GeoData::load(data_dir));
        let providers = Arc::new(ProviderRegistry::load(&config, data_dir).await);
        let connections = Arc::new(ConnectionTracker::new());
        Self { config, rules, resolver, outbounds, traffic, mode, geo, providers, proxy_providers, connections }
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
                self.rules.find(target, resolved, Some(&self.geo), Some(&self.providers))
                    .map(|r| r.target.clone())
                    .unwrap_or_else(|| "DIRECT".to_string())
            }
        }
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

        let (id, up_counter, down_counter) = self.connections
            .add(&target, &rule_target, vec![final_name.clone(), rule_target.clone()], Network::Tcp)
            .await;

        let outbound = self.outbounds.outbound(&final_name);
        let result = match outbound {
            Some(outbound) => {
                match outbound.connect(&target).await {
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
                    Err(e) => Err(e),
                }
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, format!("unknown outbound '{}'", final_name))),
        };

        self.connections.remove(&id).await;
        result
    }
}
