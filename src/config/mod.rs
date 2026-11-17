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

#[derive(Debug, Clone, Deserialize)]
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
    pub username: Option<String>,
    pub uuid: Option<String>,
    pub sni: Option<String>,
    pub tls: Option<bool>,
    #[serde(rename = "server-name")]
    pub server_name: Option<String>,
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
        let mut names: Vec<&str> = vec!["DIRECT", "REJECT", "GLOBAL"];
        names.extend(self.proxies.iter().map(|p| p.name.as_str()));
        names.extend(self.proxy_groups.iter().map(|g| g.name.as_str()));
        for (i, name) in names.iter().enumerate() {
            if name.is_empty() {
                anyhow::bail!("proxy name at index {} is empty", i);
            }
            if names[..i].contains(name) {
                anyhow::bail!("duplicate proxy/group name '{}'", name);
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
    fn rejects_duplicate_proxy_names() {
        let yaml = r#"
proxies:
  - {name: dup, type: ss, server: a, port: 1}
  - {name: dup, type: ss, server: b, port: 2}
"#;
        assert!(Config::from_str(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_mode() {
        assert!(Config::from_str("mode: bogus").is_err());
    }
}
