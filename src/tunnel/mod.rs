//! The tunnel glues inbound connections to rules and outbound adapters.

use std::io;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::adapter::OutboundManager;
use crate::common::{SharedTraffic, TargetAddr};
use crate::config::Config;
use crate::dns::Resolver;
use crate::geo::GeoData;
use crate::rules::RuleSet;

/// AsyncWrite wrapper that feeds bytes moved through it into the traffic counters.
struct CountingWriter<W> {
    inner: W,
    traffic: SharedTraffic,
    upload: bool,
}

impl<W> CountingWriter<W> {
    fn new(inner: W, traffic: SharedTraffic, upload: bool) -> Self {
        Self { inner, traffic, upload }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for CountingWriter<W> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
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
}

impl Engine {
    pub fn new(config: Config, traffic: SharedTraffic, data_dir: &Path) -> Self {
        let rules = RuleSet::new(&config.rules);
        let resolver = Resolver::new(config.dns.clone().unwrap_or_default());
        let outbounds = OutboundManager::new(&config);
        let mode = RwLock::new(config.mode.clone());
        let geo = Arc::new(GeoData::load(data_dir));
        Self { config, rules, resolver, outbounds, traffic, mode, geo }
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
                self.rules.find(target, resolved, Some(&self.geo))
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

        let outbound = self.outbounds.outbound(&final_name).ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, format!("unknown outbound '{}'", final_name))
        })?;
        let mut remote = outbound.connect(&target).await?;
        if !prefix.is_empty() {
            remote.write_all(prefix).await?;
        }

        let (mut rin, mut win) = tokio::io::split(inbound);
        let (mut rout, mut wout) = tokio::io::split(remote);
        let mut up = CountingWriter::new(&mut wout, self.traffic.clone(), true);
        let mut down = CountingWriter::new(&mut win, self.traffic.clone(), false);

        let result = tokio::select! {
            r = tokio::io::copy(&mut rin, &mut up) => r.map(|_| ()),
            r = tokio::io::copy(&mut rout, &mut down) => r.map(|_| ()),
        };

        // Best-effort: signal EOF to the other side; ignore errors on teardown.
        let _ = wout.shutdown().await;
        let _ = win.shutdown().await;
        result
    }
}
