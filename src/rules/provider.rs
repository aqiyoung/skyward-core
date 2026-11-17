//! Rule providers (`rule-providers` + `RULE-SET` rules). Supports file, inline
//! and http(s) vehicles, with yaml / text payloads and the three Go behaviors.

use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::path::Path;

use ipnet::IpNet;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::adapter::tls::connect_tls;
use crate::adapter::BoxedStream;
use crate::common::TargetAddr;
use crate::config::{Config, RuleProviderDef};
use crate::geo::GeoData;
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

#[derive(Debug, Clone)]
enum Entry {
    Domain(String),
    Cidr(IpNet),
    Classical(Rule),
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
                Behavior::Domain => {
                    if line.contains('/') {
                        continue;
                    }
                    Entry::Domain(line.trim_start_matches('.').to_ascii_lowercase())
                }
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

    pub fn matches(&self, addr: &TargetAddr, resolved: Option<IpAddr>, geo: &GeoData) -> bool {
        let ip = resolved.or_else(|| match addr {
            TargetAddr::Ip(ip, _) => Some(*ip),
            _ => None,
        });
        self.entries.iter().any(|entry| match entry {
            Entry::Domain(value) => match addr {
                TargetAddr::Domain(host, _) => {
                    let host = host.to_ascii_lowercase();
                    host == *value || host.ends_with(&format!(".{}", value))
                }
                _ => false,
            },
            Entry::Cidr(net) => ip.map(|ip| net.contains(&ip)).unwrap_or(false),
            Entry::Classical(rule) => rule.matches(addr, ip, Some(geo), None),
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
    /// Build all providers. Network/file failures are logged and skipped so
    /// the kernel still starts with the remaining rules.
    pub async fn load(config: &Config, data_dir: &Path) -> Self {
        let mut registry = Self::default();
        for (name, def) in &config.rule_providers {
            match Self::build(name, def, data_dir).await {
                Ok(provider) => {
                    tracing::info!("rule provider {} loaded ({} entries)", name, provider.len());
                    registry.providers.insert(name.clone(), provider);
                }
                Err(e) => tracing::warn!("failed to load rule provider {}: {}", name, e),
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
                let url = def.url.as_ref().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "http provider needs url"))?;
                let bytes = fetch_url(url).await?;
                if let Some(path) = &def.path {
                    let path = resolve_path(path, data_dir);
                    let _ = tokio::fs::write(&path, &bytes).await;
                }
                bytes
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("unknown provider type '{}'", other))),
        };
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
        return text.lines().map(str::to_string).collect();
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

/// Minimal HTTP/HTTPS GET. Uses the shared TLS connector for https URLs.
async fn fetch_url(url: &str) -> io::Result<Vec<u8>> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid URL"))?;
    let use_tls = match scheme {
        "http" => false,
        "https" => true,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, "unsupported URL scheme")),
    };
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let path = format!("/{}", path);
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad IPv6 URL"))?;
        let host = stripped[..end].to_string();
        let port = stripped[end + 1..].strip_prefix(':').and_then(|p| p.parse().ok()).unwrap_or(if use_tls { 443 } else { 80 });
        (host, port)
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        let port = p.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bad port"))?;
        (h.to_string(), port)
    } else {
        (authority.to_string(), if use_tls { 443 } else { 80 })
    };

    let mut last_error = None;
    let mut tcp = None;
    let addresses = tokio::net::lookup_host((host.as_str(), port)).await?;
    for addr in addresses {
        match TcpStream::connect(addr).await {
            Ok(stream) => { tcp = Some(stream); break; }
            Err(e) => last_error = Some(e),
        }
    }
    let tcp = tcp.ok_or_else(|| last_error.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))?;
    let mut stream: BoxedStream = if use_tls {
        connect_tls(&host, tcp).await?
    } else {
        Box::new(tcp)
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: skyward-core\r\nConnection: close\r\n\r\n",
        path, authority
    );
    stream.write_all(request.as_bytes()).await?;

    let mut head = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        if head.len() > 64 * 1024 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "HTTP head too large"));
        }
        if stream.read(&mut byte).await? == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "incomplete HTTP response"));
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head_text = String::from_utf8_lossy(&head);
    let status = head_text.lines().next().and_then(|l| l.split_whitespace().nth(1)).and_then(|s| s.parse::<u16>().ok()).unwrap_or(0);
    if status != 200 {
        return Err(io::Error::new(io::ErrorKind::Other, format!("HTTP {}", status)));
    }
    let chunked = head_text.lines().any(|l| l.to_ascii_lowercase().contains("transfer-encoding: chunked"));

    if chunked {
        let mut body = Vec::new();
        loop {
            let mut size_line = Vec::new();
            loop {
                if stream.read(&mut byte).await? == 0 { return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "bad chunk")); }
                size_line.push(byte[0]);
                if size_line.ends_with(b"\r\n") { break; }
            }
            let size_text = String::from_utf8_lossy(&size_line);
            let size = usize::from_str_radix(size_text.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 { break; }
            let mut chunk = vec![0u8; size];
            stream.read_exact(&mut chunk).await?;
            body.extend_from_slice(&chunk);
            let mut crlf = [0u8; 2];
            stream.read_exact(&mut crlf).await?;
        }
        Ok(body)
    } else {
        let mut body = Vec::new();
        stream.read_to_end(&mut body).await?;
        Ok(body)
    }
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
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[1], "example.com");
    }

    #[test]
    fn domain_behavior_matches_suffix() {
        let provider = RuleProvider::new("p".into(), Behavior::Domain, vec!["example.com".into(), ".ads.net".into()]);
        let geo = GeoData::default();
        assert!(provider.matches(&TargetAddr::Domain("www.example.com".into(), 80), None, &geo));
        assert!(!provider.matches(&TargetAddr::Domain("notexample.com".into(), 80), None, &geo));
        assert!(provider.matches(&TargetAddr::Domain("cdn.ads.net".into(), 80), None, &geo));
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
    fn classical_behavior_uses_rules() {
        let provider = RuleProvider::new("p".into(), Behavior::Classical, vec!["DOMAIN-KEYWORD,ads".into()]);
        let geo = GeoData::default();
        assert!(provider.matches(&TargetAddr::Domain("ads.example".into(), 80), None, &geo));
        assert!(!provider.matches(&TargetAddr::Domain("example.com".into(), 80), None, &geo));
    }
}
