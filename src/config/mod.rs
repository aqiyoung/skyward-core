//! Deserialization of the mihomo-compatible YAML configuration.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Plain HTTP proxy port (`port` in mihomo).
    pub port: Option<u16>,
    /// SOCKS5 proxy port.
    #[serde(rename = "socks-port")]
    pub socks_port: Option<u16>,
    /// Combined HTTP + SOCKS5 port.
    #[serde(rename = "mixed-port")]
    pub mixed_port: Option<u16>,
    #[serde(rename = "redir-port")]
    pub redir_port: Option<u16>,
    #[serde(rename = "tproxy-port")]
    pub tproxy_port: Option<u16>,
    #[serde(rename = "allow-lan")]
    pub allow_lan: bool,
    pub mode: String,
    #[serde(rename = "log-level")]
    pub log_level: String,
    #[serde(rename = "external-controller")]
    pub external_controller: Option<String>,
    #[serde(rename = "external-ui")]
    pub external_ui: Option<String>,
    pub secret: String,
    pub proxies: Vec<ProxyDef>,
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupDef>,
    #[serde(rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderDef>,
    #[serde(rename = "proxy-providers")]
    pub proxy_providers: HashMap<String, ProxyProviderDef>,
    pub rules: Vec<String>,
    pub dns: Option<DnsConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            port: None,
            socks_port: None,
            mixed_port: None,
            redir_port: None,
            tproxy_port: None,
            allow_lan: false,
            mode: "rule".to_string(),
            log_level: "info".to_string(),
            external_controller: None,
            external_ui: None,
            secret: String::new(),
            proxies: Vec::new(),
            proxy_groups: Vec::new(),
            rule_providers: HashMap::new(),
            proxy_providers: HashMap::new(),
            rules: Vec::new(),
            dns: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ProxyDef {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub cipher: Option<String>,
    pub password: Option<String>,
    pub psk: Option<String>,
    pub version: Option<i32>,
    pub protocol: Option<String>,
    pub obfs: Option<String>,
    #[serde(rename = "obfs-password")]
    pub obfs_password: Option<String>,
    /// Hysteria2 bandwidth hints, e.g. `100 Mbps`.
    pub up: Option<String>,
    pub down: Option<String>,
    /// TUIC UDP relay mode: `native` (QUIC datagrams, default) or
    /// `quic` (packet streams).
    #[serde(rename = "udp-relay-mode")]
    pub udp_relay_mode: Option<String>,
    /// WireGuard keys and interface addresses (classic single-peer
    /// form; the `peers` list form is honoured too).
    #[serde(rename = "private-key")]
    pub private_key: Option<String>,
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    #[serde(rename = "preshared-key")]
    pub preshared_key: Option<String>,
    pub ip: Option<String>,
    pub ipv6: Option<String>,
    pub peers: Option<Vec<WireguardPeer>>,
    pub username: Option<String>,
    pub uuid: Option<String>,
    pub sni: Option<String>,
    pub tls: Option<bool>,
    #[serde(rename = "server-name")]
    pub server_name: Option<String>,
    /// mihomo spells the TLS server name `servername` (no dash).
    pub servername: Option<String>,
    #[serde(rename = "skip-cert-verify")]
    pub skip_cert_verify: Option<bool>,
    /// Transport: `tcp` (default), `ws`, `grpc`, `h2`, `quic`, `http`.
    pub network: Option<String>,
    /// VLESS/VMess flow, e.g. `xtls-rprx-vision`.
    pub flow: Option<String>,
    /// VLESS security: `none`, `tls`, `reality`.
    pub security: Option<String>,
    #[serde(rename = "client-fingerprint")]
    pub client_fingerprint: Option<String>,
    pub fingerprint: Option<String>,
    #[serde(rename = "reality-opts")]
    pub reality_opts: Option<RealityOpts>,
    #[serde(rename = "ws-opts")]
    pub ws_opts: Option<WsOpts>,
    #[serde(rename = "grpc-opts")]
    pub grpc_opts: Option<GrpcOpts>,
    #[serde(rename = "xhttp-opts")]
    pub xhttp_opts: Option<XHttpOpts>,
    #[serde(rename = "http-opts")]
    pub http_opts: Option<HttpOpts>,
    /// Chain this node through another proxy. The core builds a dial chain
    /// at dial time: this node's TCP connection to its own server is opened
    /// through the named proxy, mirroring mihomo's `dialer-proxy`.
    #[serde(rename = "dialer-proxy")]
    pub dialer_proxy: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct HttpOpts {
    /// mihomo allows path as a string or a list of candidate paths
    /// (one is picked per connection); a list appears in real
    /// subscriptions and must not fail the whole config parse.
    #[serde(default, deserialize_with = "de_host_list")]
    pub path: Option<String>,
    /// mihomo spells host as a list; a single string also appears.
    #[serde(default, deserialize_with = "de_host_list")]
    pub host: Option<String>,
}

fn de_host_list<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<serde_yaml::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_yaml::Value::String(s)) => Some(s),
        Some(serde_yaml::Value::Sequence(seq)) => seq
            .first()
            .and_then(|v| v.as_str().map(str::to_string)),
        _ => None,
    })
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct XHttpOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    /// auto | packet-up | stream-up | stream-one
    #[serde(default)]
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WireguardPeer {
    pub server: Option<String>,
    pub port: Option<u16>,
    #[serde(rename = "public-key")]
    pub public_key: Option<String>,
    #[serde(rename = "preshared-key")]
    pub preshared_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct RealityOpts {
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub short_id: Option<String>,
    #[serde(default)]
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct WsOpts {
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
    #[serde(rename = "max-early-data", default)]
    pub max_early_data: Option<u64>,
    #[serde(rename = "early-data-header-name", default)]
    pub early_data_header_name: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct GrpcOpts {
    #[serde(rename = "grpc-service-name", default)]
    pub service_name: Option<String>,
}

impl ProxyDef {
    /// The TLS server name the node asks for. mihomo spells it `servername`;
    /// `sni` and `server-name` appear in older/other configs.
    pub fn tls_server_name(&self) -> Option<&str> {
        self.sni
            .as_deref()
            .or(self.servername.as_deref())
            .or(self.server_name.as_deref())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProxyGroupDef {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub proxies: Vec<String>,
    /// Provider names whose proxies should be included as members (`use:`).
    #[serde(rename = "use", default)]
    pub use_providers: Vec<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuleProviderDef {
    #[serde(rename = "type")]
    pub kind: String,
    pub behavior: String,
    pub path: Option<String>,
    pub url: Option<String>,
    pub format: Option<String>,
    pub interval: Option<u64>,
    #[serde(default)]
    pub payload: Vec<String>,
}

impl Default for RuleProviderDef {
    fn default() -> Self {
        Self {
            kind: String::new(),
            behavior: "classical".to_string(),
            path: None,
            url: None,
            format: None,
            interval: None,
            payload: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HealthCheckConfig {
    pub enable: bool,
    pub url: Option<String>,
    pub interval: Option<u64>,
    #[serde(rename = "expected-status")]
    pub expected_status: Option<String>,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enable: false,
            url: Some("http://www.gstatic.com/generate_204".to_string()),
            interval: Some(300),
            expected_status: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ProxyProviderDef {
    #[serde(rename = "type")]
    pub kind: String,
    pub path: Option<String>,
    pub url: Option<String>,
    pub interval: Option<u64>,
    pub filter: Option<String>,
    #[serde(rename = "exclude-filter")]
    pub exclude_filter: Option<String>,
    #[serde(rename = "exclude-type")]
    pub exclude_type: Option<String>,
    #[serde(rename = "health-check")]
    pub health_check: HealthCheckConfig,
    pub payload: Vec<ProxyDef>,
}

impl Default for ProxyProviderDef {
    fn default() -> Self {
        Self {
            kind: String::new(),
            path: None,
            url: None,
            interval: None,
            filter: None,
            exclude_filter: None,
            exclude_type: None,
            health_check: HealthCheckConfig::default(),
            payload: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub enable: bool,
    #[serde(rename = "enhanced-mode")]
    pub enhanced_mode: String,
    pub nameserver: Vec<String>,
    pub fallback: Vec<String>,
    #[serde(rename = "fake-ip-range")]
    pub fake_ip_range: Option<String>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enable: true,
            enhanced_mode: "redir-host".to_string(),
            nameserver: Vec::new(),
            fallback: Vec::new(),
            fake_ip_range: None,
        }
    }
}

impl Config {
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let cfg: Config = serde_yaml::from_str(s)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read config {}: {}", path.display(), e))?;
        Self::from_str(&text)
    }

    fn validate(&self) -> anyhow::Result<()> {
        const MODES: [&str; 3] = ["rule", "direct", "global"];
        if !MODES.contains(&self.mode.as_str()) {
            anyhow::bail!("invalid mode '{}' (expected rule/direct/global)", self.mode);
        }
        // mihomo keys proxies and groups by name and lets a later entry replace
        // an earlier one, so a repeat is a warning here rather than a load
        // failure. Real subscriptions rely on it: naming a group GLOBAL (a
        // built-in group) or reusing a proxy's name parses fine there, and
        // rejecting it left the core with no config at all.
        let mut seen: Vec<&str> = vec!["DIRECT", "REJECT", "GLOBAL"];
        for (i, name) in self.proxies.iter().map(|p| p.name.as_str()).enumerate() {
            if name.is_empty() {
                anyhow::bail!("proxy name at index {} is empty", i);
            }
            if seen.contains(&name) {
                tracing::warn!("duplicate proxy name '{}' (the last one wins, as mihomo does)", name);
            } else {
                seen.push(name);
            }
        }
        for (i, name) in self.proxy_groups.iter().map(|g| g.name.as_str()).enumerate() {
            if name.is_empty() {
                anyhow::bail!("proxy group name at index {} is empty", i);
            }
            if seen.contains(&name) {
                tracing::warn!(
                    "proxy group '{}' shares its name with a proxy or a built-in group (mihomo allows this)",
                    name
                );
            } else {
                seen.push(name);
            }
        }
        Ok(())
    }

    /// Apply command-line overrides on top of the file configuration.
    pub fn apply_overrides(&mut self, o: &Overrides) {
        if let Some(p) = o.socks_port { self.socks_port = Some(p); }
        if let Some(p) = o.http_port { self.port = Some(p); }
        if let Some(p) = o.mixed_port { self.mixed_port = Some(p); }
        if let Some(c) = &o.external_controller { self.external_controller = Some(c.clone()); }
    }
}

#[derive(Default, Debug)]
pub struct Overrides {
    pub socks_port: Option<u16>,
    pub http_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub external_controller: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_opts_path_accepts_string_or_list() {
        // Real-world subscriptions spell http-opts.path as a YAML
        // list; that must parse (first entry wins), not fail the
        // whole config (device log 2026-11-20: proxies[245]).
        let yaml = r#"
proxies:
  - name: h2node
    type: vless
    server: example.com
    port: 443
    network: h2
    http-opts:
      path:
        - /first
        - /second
      host:
        - example.com
"#;
        let c = Config::from_str(yaml).unwrap();
        let opts = c.proxies[0].http_opts.as_ref().unwrap();
        assert_eq!(opts.path.as_deref(), Some("/first"));
        assert_eq!(opts.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn parses_mihomo_kebab_case_keys() {
        let yaml = r#"
socks-port: 7891
mixed-port: 7892
allow-lan: true
log-level: debug
external-controller: 127.0.0.1:9090
proxy-groups:
  - name: auto
    type: url-test
    proxies: [DIRECT]
dns:
  enhanced-mode: fake-ip
rules:
  - MATCH,DIRECT
"#;
        let c = Config::from_str(yaml).unwrap();
        assert_eq!(c.socks_port, Some(7891));
        assert_eq!(c.mixed_port, Some(7892));
        assert!(c.allow_lan);
        assert_eq!(c.log_level, "debug");
        assert_eq!(c.external_controller.as_deref(), Some("127.0.0.1:9090"));
        assert_eq!(c.proxy_groups.len(), 1);
        assert_eq!(c.dns.unwrap().enhanced_mode, "fake-ip");
    }

    #[test]
    fn duplicate_names_load_like_mihomo() {
        // A group named GLOBAL is a built-in group's name; mihomo accepts it.
        let yaml = r#"
proxy-groups:
  - {name: GLOBAL, type: select, proxies: [DIRECT]}
"#;
        assert!(Config::from_str(yaml).is_ok());
        // A repeated proxy name is last-wins, not a load failure.
        let yaml = r#"
proxies:
  - {name: dup, type: ss, server: a, port: 1}
  - {name: dup, type: ss, server: b, port: 2}
"#;
        let c = Config::from_str(yaml).unwrap();
        assert_eq!(c.proxies.len(), 2);
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(Config::from_str("mode: bogus").is_err());
    }
}
