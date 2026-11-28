//! Rule providers (`rule-providers` + `RULE-SET` rules). Supports file, inline
//! and http(s) vehicles, with yaml / text / mrs payloads and the three Go
//! behaviors. Remote providers are fetched (and cached to their `path`) at
//! config load, concurrently, like mihomo.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use ipnet::IpNet;
use crate::fetch::fetch_url_timeout;
use crate::common::TargetAddr;
use crate::config::{Config, RuleProviderDef};
use crate::geo::GeoData;
use crate::rules::mrs::parse_mrs;
use crate::rules::Rule;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Behavior {
    Domain,
    IpCidr,
    Classical,
}

impl Behavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::IpCidr => "ipcidr",
            Self::Classical => "classical",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "domain" => Some(Self::Domain),
            "ipcidr" => Some(Self::IpCidr),
            "classical" | "" => Some(Self::Classical),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainMode {
    /// "example.com" — the host itself only.
    Exact,
    /// "+.example.com" — the host and all its subdomains.
    Suffix,
    /// ".example.com" / "*.example.com" — subdomains only.
    SubOnly,
}

#[derive(Debug, Clone)]
pub enum Entry {
    Domain { value: String, mode: DomainMode },
    Cidr(IpNet),
    IpRange(IpAddr, IpAddr),
    Classical(Rule),
}

/// Parse one domain-behavior line into an entry, with mihomo's prefix
/// semantics. Lines carrying a `/` or a leftover `*` segment are not
/// plain domains and are dropped, as the Go domain strategy drops them.
pub(crate) fn domain_entry(line: &str) -> Option<Entry> {
    let line = line.trim().to_ascii_lowercase();
    if line.is_empty() || line.contains('/') {
        return None;
    }
    let (value, mode) = if let Some(rest) = line.strip_prefix("+.") {
        (rest, DomainMode::Suffix)
    } else if let Some(rest) = line.strip_prefix('.') {
        (rest, DomainMode::SubOnly)
    } else if let Some(rest) = line.strip_prefix("*.") {
        (rest, DomainMode::SubOnly)
    } else {
        (line.as_str(), DomainMode::Exact)
    };
    if value.is_empty() || value.contains('*') {
        return None;
    }
    Some(Entry::Domain { value: value.to_string(), mode })
}

fn ip_in_range(ip: IpAddr, from: IpAddr, to: IpAddr) -> bool {
    match (ip, from, to) {
        (IpAddr::V4(a), IpAddr::V4(f), IpAddr::V4(t)) => {
            let (a, f, t) = (u32::from(a), u32::from(f), u32::from(t));
            f <= a && a <= t
        }
        (IpAddr::V6(a), IpAddr::V6(f), IpAddr::V6(t)) => {
            let (a, f, t) = (u128::from(a), u128::from(f), u128::from(t));
            f <= a && a <= t
        }
        _ => false,
    }
}

#[derive(Debug)]
pub struct RuleProvider {
    pub name: String,
    behavior: Behavior,
    entries: Vec<Entry>,
}

impl RuleProvider {
    pub fn new(name: String, behavior: Behavior, lines: Vec<String>) -> Self {
        let mut entries = Vec::new();
        for line in lines {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            let entry = match behavior {
                Behavior::Domain => match domain_entry(line) {
                    Some(entry) => entry,
                    None => continue,
                },
                Behavior::IpCidr => match IpNet::from_str(line.trim_start_matches("IP-CIDR,")) {
                    Ok(net) => Entry::Cidr(net),
                    Err(_) => continue,
                },
                Behavior::Classical => {
                    // Provider entries have no adapter; add a synthetic one so
                    // the ordinary rule parser can be reused.
                    match Rule::parse(&format!("{},__provider__", line)) {
                        Some(rule) => Entry::Classical(rule),
                        None => continue,
                    }
                }
            };
            entries.push(entry);
        }
        Self { name, behavior, entries }
    }

    pub fn from_entries(name: String, behavior: Behavior, entries: Vec<Entry>) -> Self {
        Self { name, behavior, entries }
    }

    pub fn matches(&self, addr: &TargetAddr, resolved: Option<IpAddr>, geo: &GeoData) -> bool {
        let ip = resolved.or_else(|| match addr {
            TargetAddr::Ip(ip, _) => Some(*ip),
            _ => None,
        });
        self.entries.iter().any(|entry| match entry {
            Entry::Domain { value, mode } => match addr {
                TargetAddr::Domain(host, _) => {
                    let host = host.to_ascii_lowercase();
                    match mode {
                        DomainMode::Exact => host == *value,
                        DomainMode::Suffix => {
                            host == *value || host.ends_with(&format!(".{}", value))
                        }
                        DomainMode::SubOnly => host.ends_with(&format!(".{}", value)),
                    }
                }
                _ => false,
            },
            Entry::Cidr(net) => ip.map(|ip| net.contains(&ip)).unwrap_or(false),
            Entry::IpRange(from, to) => ip.map(|ip| ip_in_range(ip, *from, *to)).unwrap_or(false),
            Entry::Classical(rule) => {
                let entry_ip = if rule.no_resolve && matches!(addr, TargetAddr::Domain(..)) {
                    None
                } else {
                    ip
                };
                rule.matches(addr, entry_ip, Some(geo), None)
            },
        })
    }

    /// Whether any entry can use a DNS result for this domain. Domain-only
    /// providers (including MRS domain sets) must not trigger DNS lookups.
    pub fn needs_resolve(&self, addr: &TargetAddr) -> bool {
        if !matches!(addr, TargetAddr::Domain(..)) {
            return false;
        }
        self.entries.iter().any(|entry| match entry {
            Entry::Cidr(_) | Entry::IpRange(_, _) => true,
            Entry::Classical(rule) => rule.needs_resolve(addr),
            Entry::Domain { .. } => false,
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[derive(Debug, Default)]
pub struct ProviderRegistry {
    providers: HashMap<String, RuleProvider>,
}

impl ProviderRegistry {
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Build all providers. Network/file failures are logged and skipped so
    /// the kernel still starts with the remaining rules.
    pub async fn load(config: &Config, data_dir: &Path) -> Self {
        let mut registry = Self::default();
        // Providers build concurrently: a profile can carry dozens of
        // remote sets and first load would otherwise serialize their
        // downloads. Failures stay per-provider so one bad set cannot
        // block the rest of the rules.
        let mut tasks = Vec::new();
        for (name, def) in &config.rule_providers {
            let name = name.clone();
            let def = def.clone();
            let data_dir = data_dir.to_path_buf();
            tasks.push(tokio::spawn(async move {
                let provider = Self::build(&name, &def, &data_dir).await;
                (name, provider)
            }));
        }
        for task in tasks {
            match task.await {
                Ok((name, Ok(provider))) => {
                    tracing::info!("rule provider {} loaded ({} entries)", name, provider.len());
                    registry.providers.insert(name, provider);
                }
                Ok((name, Err(e))) => {
                    tracing::warn!("failed to load rule provider {}: {}", name, e)
                }
                Err(e) => tracing::warn!("rule provider task failed: {}", e),
            }
        }
        registry
    }

    async fn build(name: &str, def: &RuleProviderDef, data_dir: &Path) -> io::Result<RuleProvider> {
        let behavior = Behavior::parse(&def.behavior).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("unknown provider behavior '{}'", def.behavior))
        })?;
        let format = def.format.as_deref().unwrap_or("yaml").to_ascii_lowercase();
        let raw: Vec<u8> = match def.kind.as_str() {
            "inline" => Vec::new(),
            "file" => {
                let path = def.path.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file provider needs path"))?;
                let path = resolve_path(path, data_dir);
                tokio::fs::read(&path).await.map_err(|e| io::Error::new(e.kind(), format!("read {}: {}", path.display(), e)))?
            }
            "http" => {
                // Prefer the cached copy so startup is instant and offline-safe.
                let cached = match &def.path {
                    Some(path) => tokio::fs::read(resolve_path(path, data_dir)).await.ok(),
                    None => None,
                };
                match cached {
                    Some(bytes) => bytes,
                    None => {
                        let url = def.url.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "http provider needs url"))?;
                        let bytes = fetch_url_timeout(url, Duration::from_secs(15), crate::fetch::MAX_BODY).await?;
                        if let Some(path) = &def.path {
                            let path = resolve_path(path, data_dir);
                            if let Some(parent) = path.parent() {
                                let _ = tokio::fs::create_dir_all(parent).await;
                            }
                            let _ = tokio::fs::write(&path, &bytes).await;
                        }
                        bytes
                    }
                }
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown provider type '{}'", other))),
        };
        if format == "mrs" {
            let entries = parse_mrs(&raw, behavior)?;
            return Ok(RuleProvider::from_entries(name.to_string(), behavior, entries));
        }
        let lines = if raw.is_empty() {
            def.payload.clone()
        } else {
            parse_payload(&raw, &format)
        };
        let _ = def.interval; // periodic refresh is not implemented yet
        Ok(RuleProvider::new(name.to_string(), behavior, lines))
    }

    pub fn insert(&mut self, provider: RuleProvider) {
        self.providers.insert(provider.name.clone(), provider);
    }

    pub fn matches(&self, name: &str, addr: &TargetAddr, resolved: Option<IpAddr>, geo: &GeoData) -> bool {
        self.providers.get(name)
            .map(|p| p.matches(addr, resolved, geo))
            .unwrap_or(false)
    }

    pub fn needs_resolve(&self, name: &str, addr: &TargetAddr) -> bool {
        self.providers.get(name).map(|p| p.needs_resolve(addr)).unwrap_or(false)
    }

    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.providers.keys().map(String::as_str).collect();
        names.sort();
        names
    }

    pub fn snapshot(&self) -> Vec<ProviderInfo> {
        let mut items: Vec<ProviderInfo> = self.providers.values().map(|p| ProviderInfo {
            name: p.name.clone(),
            behavior: p.behavior.as_str().to_string(),
            count: p.len(),
        }).collect();
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items
    }
}

#[derive(serde::Serialize)]
pub struct ProviderInfo {
    pub name: String,
    pub behavior: String,
    pub count: usize,
}

fn resolve_path(path: &str, data_dir: &Path) -> std::path::PathBuf {
    let p = Path::new(path);
    if p.is_absolute() { p.to_path_buf() } else { data_dir.join(p) }
}

/// Extract payload lines from a yaml (`payload:` / `rules:`) or text document.
fn parse_payload(raw: &[u8], format: &str) -> Vec<String> {
    let text = String::from_utf8_lossy(raw);
    if format == "text" {
        return text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("//"))
            .map(str::to_string)
            .collect();
    }
    let mut lines = Vec::new();
    let mut in_payload = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if !line.starts_with(' ') && !line.starts_with('\t') {
            in_payload = trimmed.starts_with("payload:") || trimmed.starts_with("rules:");
            continue;
        }
        if in_payload {
            if let Some(value) = trimmed.strip_prefix("- ") {
                lines.push(value.trim().trim_matches('"').trim_matches('\'').to_string());
            }
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_yaml_payload() {
        let raw = b"payload:\n  - DOMAIN-SUFFIX,example.com\n  - 'DOMAIN-KEYWORD,ads'\nrules:\n  - 1.2.3.0/24\n";
        let lines = parse_payload(raw, "yaml");
        assert_eq!(lines, vec!["DOMAIN-SUFFIX,example.com", "DOMAIN-KEYWORD,ads", "1.2.3.0/24"]);
    }

    #[test]
    fn parses_text_payload() {
        let raw = b"# comment\nexample.com\n// premium comment\n.ads.example.com\n\n";
        let lines = parse_payload(raw, "text");
        assert_eq!(lines, vec!["example.com", ".ads.example.com"]);
    }

    #[test]
    fn domain_behavior_matches_mihomo_modes() {
        // mihomo domain semantics: a bare domain is exact-only, "+."
        // covers the host and its subdomains, "." is subdomains only.
        let provider = RuleProvider::new(
            "p".into(),
            Behavior::Domain,
            vec!["example.com".into(), "+.suffix.org".into(), ".ads.net".into()],
        );
        let geo = GeoData::default();
        let hits = |host: &str| provider.matches(&TargetAddr::Domain(host.into(), 80), None, &geo);
        assert!(hits("example.com"));
        assert!(!hits("www.example.com"));
        assert!(!hits("notexample.com"));
        assert!(hits("suffix.org"));
        assert!(hits("www.suffix.org"));
        assert!(!hits("notsuffix.org"));
        assert!(hits("cdn.ads.net"));
        assert!(!hits("ads.net"));
    }

    #[test]
    fn ipcidr_behavior_matches_ip() {
        let provider = RuleProvider::new("p".into(), Behavior::IpCidr, vec!["IP-CIDR,10.0.0.0/8".into()]);
        let geo = GeoData::default();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        assert!(provider.matches(&TargetAddr::Ip(ip, 80), Some(ip), &geo));
        let other: IpAddr = "8.8.8.8".parse().unwrap();
        assert!(!provider.matches(&TargetAddr::Ip(other, 80), Some(other), &geo));
    }

    #[test]
    fn classical_no_resolve_does_not_use_a_previously_resolved_domain() {
        let provider = RuleProvider::new(
            "p".into(), Behavior::Classical,
            vec!["IP-CIDR,10.0.0.0/8,no-resolve".into()],
        );
        let geo = GeoData::default();
        let ip: IpAddr = "10.1.2.3".parse().unwrap();
        let domain = TargetAddr::Domain("example.com".into(), 443);
        assert!(!provider.needs_resolve(&domain));
        assert!(!provider.matches(&domain, Some(ip), &geo));
        assert!(provider.matches(&TargetAddr::Ip(ip, 443), None, &geo));
    }

    #[test]
    fn classical_behavior_uses_rules() {
        let provider = RuleProvider::new("p".into(), Behavior::Classical, vec!["DOMAIN-KEYWORD,ads".into()]);
        let geo = GeoData::default();
        assert!(provider.matches(&TargetAddr::Domain("ads.example".into(), 80), None, &geo));
        assert!(!provider.matches(&TargetAddr::Domain("example.com".into(), 80), None, &geo));
    }
}
