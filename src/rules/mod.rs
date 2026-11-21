//! Rule parsing and matching. Mirrors the `rules/` package of the Go kernel.
//! Source-address, process and logic rules are intentionally not present: the
//! tunnel does not carry that metadata yet.

use ipnet::IpNet;
use regex::Regex;
use std::net::IpAddr;
use std::str::FromStr;

use crate::common::TargetAddr;
use crate::geo::GeoData;

pub mod mrs;
pub mod provider;

use provider::ProviderRegistry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainRegex,
    DomainWildcard,
    IpCidr,
    IpSuffix,
    GeoIp,
    GeoSite,
    DstPort,
    RuleSet,
    Match,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub kind: RuleKind,
    pub value: String,
    pub target: String,
    pub no_resolve: bool,
    pub raw: String,
    net: Option<IpNet>,
    regex: Option<Regex>,
    port: Option<u16>,
    provider: Option<String>,
}

fn wildcard_regex(pattern: &str) -> Option<Regex> {
    let mut out = String::from("^");
    for ch in pattern.to_ascii_lowercase().chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c => out.push_str(&regex::escape(&c.to_string())),
        }
    }
    out.push('$');
    Regex::new(&out).ok()
}

impl Rule {
    /// mihomo-compatible names consumed by the App's request list.
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            RuleKind::Domain => "Domain",
            RuleKind::DomainSuffix => "DomainSuffix",
            RuleKind::DomainKeyword => "DomainKeyword",
            RuleKind::DomainRegex => "DomainRegex",
            RuleKind::DomainWildcard => "DomainWildcard",
            RuleKind::IpCidr => "IPCIDR",
            RuleKind::IpSuffix => "IPSuffix",
            RuleKind::GeoIp => "GeoIP",
            RuleKind::GeoSite => "GeoSite",
            RuleKind::DstPort => "DstPort",
            RuleKind::RuleSet => "RuleSet",
            RuleKind::Match => "Match",
        }
    }

    pub fn parse(line: &str) -> Option<Self> {
        let raw = line.trim().to_string();
        if raw.is_empty() || raw.starts_with('#') {
            return None;
        }
        let parts: Vec<&str> = raw.split(',').map(|p| p.trim()).collect();
        if parts.len() < 2 {
            return None;
        }

        // A rule ends in a proxy name; modifiers like `no-resolve` follow the
        // value but must not be mistaken for the target.
        let no_resolve = parts.iter().any(|p| p.eq_ignore_ascii_case("no-resolve"));
        let target = parts
            .iter()
            .rev()
            .find(|p| !p.eq_ignore_ascii_case("no-resolve"))?
            .to_string();
        let kind = match parts[0].to_ascii_uppercase().as_str() {
            "DOMAIN" => RuleKind::Domain,
            "DOMAIN-SUFFIX" => RuleKind::DomainSuffix,
            "DOMAIN-KEYWORD" => RuleKind::DomainKeyword,
            "DOMAIN-REGEX" => RuleKind::DomainRegex,
            "DOMAIN-WILDCARD" => RuleKind::DomainWildcard,
            "IP-CIDR" | "IP-CIDR6" => RuleKind::IpCidr,
            "IP-SUFFIX" => RuleKind::IpSuffix,
            "GEOIP" => RuleKind::GeoIp,
            "GEOSITE" => RuleKind::GeoSite,
            "DST-PORT" => RuleKind::DstPort,
            "RULE-SET" => RuleKind::RuleSet,
            "MATCH" => RuleKind::Match,
            _ => return None,
        };

        let value = if kind == RuleKind::Match {
            String::new()
        } else if parts.len() >= 3 {
            parts[1].to_string()
        } else {
            return None;
        };

        let net = if kind == RuleKind::IpCidr {
            match IpNet::from_str(&value) {
                Ok(n) => Some(n),
                Err(_) => return None,
            }
        } else {
            None
        };
        let regex = match kind {
            RuleKind::DomainRegex => match Regex::new(&value) {
                Ok(re) => Some(re),
                Err(_) => return None,
            },
            RuleKind::DomainWildcard => match wildcard_regex(&value) {
                Some(re) => Some(re),
                None => return None,
            },
            _ => None,
        };
        let port = if kind == RuleKind::DstPort {
            match value.parse::<u16>() {
                Ok(p) => Some(p),
                Err(_) => return None,
            }
        } else {
            None
        };

        let provider = if kind == RuleKind::RuleSet { Some(value.clone()) } else { None };
        Some(Self {
            kind,
            value,
            target,
            no_resolve,
            raw,
            net,
            regex,
            port,
            provider,
        })
    }

    pub fn matches(
        &self,
        addr: &TargetAddr,
        resolved: Option<IpAddr>,
        geo: Option<&GeoData>,
        providers: Option<&ProviderRegistry>,
    ) -> bool {
        match self.kind {
            RuleKind::Match => true,
            RuleKind::Domain => match addr {
                TargetAddr::Domain(h, _) => h.eq_ignore_ascii_case(&self.value),
                _ => false,
            },
            RuleKind::DomainSuffix => match addr {
                TargetAddr::Domain(h, _) => {
                    let h = h.to_ascii_lowercase();
                    let suffix = self.value.to_ascii_lowercase();
                    h == suffix || h.ends_with(&format!(".{}", suffix))
                }
                _ => false,
            },
            RuleKind::DomainKeyword => match addr {
                TargetAddr::Domain(h, _) => h.to_ascii_lowercase().contains(&self.value.to_ascii_lowercase()),
                _ => false,
            },
            RuleKind::DomainRegex | RuleKind::DomainWildcard => match addr {
                TargetAddr::Domain(h, _) => self.regex.as_ref().map(|re| re.is_match(h)).unwrap_or(false),
                _ => false,
            },
            RuleKind::IpCidr => {
                if let Some(ip) = resolved {
                    return self.net.as_ref().map(|n| n.contains(&ip)).unwrap_or(false);
                }
                match addr {
                    TargetAddr::Ip(ip, _) => self.net.as_ref().map(|n| n.contains(ip)).unwrap_or(false),
                    _ => false,
                }
            }
            RuleKind::IpSuffix => match resolved.or_else(|| match addr {
                TargetAddr::Ip(ip, _) => Some(*ip),
                _ => None,
            }) {
                Some(ip) => ip.to_string().ends_with(&self.value),
                None => false,
            },
            RuleKind::GeoIp => match resolved.or_else(|| match addr {
                TargetAddr::Ip(ip, _) => Some(*ip),
                _ => None,
            }) {
                Some(ip) => {
                    if self.value.eq_ignore_ascii_case("lan") {
                        // The built-in LAN shortcut needs no geodata file.
                        GeoData::geoip_is_lan(ip)
                    } else {
                        geo.map(|g| g.geoip.contains(&self.value, ip)).unwrap_or(false)
                    }
                }
                None => false,
            },
            RuleKind::GeoSite => match addr {
                TargetAddr::Domain(h, _) => geo
                    .map(|g| g.geosite.matches(&self.value, h))
                    .unwrap_or(false),
                _ => false,
            },
            RuleKind::DstPort => self.port.map(|p| p == addr.port()).unwrap_or(false),
            RuleKind::RuleSet => match (providers, geo, &self.provider) {
                (Some(registry), Some(geo), Some(name)) => registry.matches(name, addr, resolved, geo),
                _ => false,
            },
        }
    }
}

#[derive(Debug, Default)]
pub struct RuleSet {
    pub rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(lines: &[String]) -> Self {
        Self {
            rules: lines.iter().filter_map(|l| Rule::parse(l)).collect(),
        }
    }

    pub fn find(
        &self,
        addr: &TargetAddr,
        resolved: Option<IpAddr>,
        geo: Option<&GeoData>,
        providers: Option<&ProviderRegistry>,
    ) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(addr, resolved, geo, providers))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_suffix_and_match() {
        let set = RuleSet::new(&[
            "DOMAIN-SUFFIX,example.com,proxy".into(),
            "MATCH,DIRECT".into(),
        ]);
        let hit = TargetAddr::Domain("cdn.example.com".into(), 443);
        assert_eq!(set.find(&hit, None, None, None).unwrap().target, "proxy");
        let miss = TargetAddr::Domain("example.org".into(), 443);
        assert_eq!(set.find(&miss, None, None, None).unwrap().target, "DIRECT");
    }

    #[test]
    fn ip_cidr_uses_resolved_address() {
        let set = RuleSet::new(&[
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".into(),
            "MATCH,REJECT".into(),
        ]);
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let addr = TargetAddr::Domain("inside.local".into(), 80);
        assert_eq!(set.find(&addr, Some(ip), None, None).unwrap().target, "DIRECT");
        assert_eq!(set.find(&addr, None, None, None).unwrap().target, "REJECT");
    }

    #[test]
    fn no_resolve_flag_is_parsed() {
        let rule = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap();
        assert!(rule.no_resolve);
        assert_eq!(rule.kind, RuleKind::IpCidr);
    }

    #[test]
    fn domain_regex_and_wildcard() {
        let set = RuleSet::new(&[
            "DOMAIN-REGEX,^ads[0-9]+\\.example\\.com$,REJECT".into(),
            "DOMAIN-WILDCARD,*.tracker.*,REJECT".into(),
            "MATCH,DIRECT".into(),
        ]);
        let a = TargetAddr::Domain("ads12.example.com".into(), 80);
        assert_eq!(set.find(&a, None, None, None).unwrap().target, "REJECT");
        let b = TargetAddr::Domain("a.tracker.net".into(), 80);
        assert_eq!(set.find(&b, None, None, None).unwrap().target, "REJECT");
        let c = TargetAddr::Domain("example.com".into(), 80);
        assert_eq!(set.find(&c, None, None, None).unwrap().target, "DIRECT");
    }

    #[test]
    fn dst_port_and_ip_suffix() {
        let set = RuleSet::new(&[
            "DST-PORT,8080,DIRECT".into(),
            "IP-SUFFIX,.7,proxy".into(),
            "MATCH,REJECT".into(),
        ]);
        let port = TargetAddr::Domain("example.com".into(), 8080);
        assert_eq!(set.find(&port, None, None, None).unwrap().target, "DIRECT");
        let ip: IpAddr = "10.0.0.7".parse().unwrap();
        let addr = TargetAddr::Ip(ip, 443);
        assert_eq!(set.find(&addr, None, None, None).unwrap().target, "proxy");
    }

    #[test]
    fn geoip_lan_without_database() {
        let set = RuleSet::new(&["GEOIP,lan,DIRECT".into(), "MATCH,REJECT".into()]);
        let lan: IpAddr = "192.168.1.1".parse().unwrap();
        let wan: IpAddr = "8.8.8.8".parse().unwrap();
        assert_eq!(set.find(&TargetAddr::Ip(lan, 80), None, None, None).unwrap().target, "DIRECT");
        assert_eq!(set.find(&TargetAddr::Ip(wan, 80), None, None, None).unwrap().target, "REJECT");
    }

    fn pb_varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut b = (v & 0x7f) as u8;
            let next = v >> 7;
            if next != 0 { b |= 0x80; }
            out.push(b);
            if next == 0 { break; }
            v = next;
        }
        out
    }

    fn pb_bytes(number: u32, bytes: &[u8]) -> Vec<u8> {
        let mut out = pb_varint(((number as u64) << 3) | 2);
        out.extend_from_slice(&pb_varint(bytes.len() as u64));
        out.extend_from_slice(bytes);
        out
    }

    #[test]
    fn geosite_matches_with_database() {
        let dir = std::env::temp_dir().join(format!("skyward-geo-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        // GeoSiteList { entry: GeoSite { country_code "cn", Domain(Domain, example.cn) } }
        let mut domain = pb_varint((1u64 << 3) | 0);
        domain.extend_from_slice(&pb_varint(2));
        domain.extend_from_slice(&pb_bytes(2, b"example.cn"));
        let mut site = pb_bytes(1, b"cn");
        site.extend_from_slice(&pb_bytes(2, &domain));
        let list = pb_bytes(1, &site);
        std::fs::write(dir.join("geosite.dat"), &list).unwrap();

        let data = GeoData::load(&dir);
        let set = RuleSet::new(&["GEOSITE,cn,proxy".into(), "MATCH,DIRECT".into()]);
        let target = TargetAddr::Domain("www.example.cn".into(), 80);
        assert_eq!(set.find(&target, None, Some(&data), None).unwrap().target, "proxy");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rule_set_uses_provider_registry() {
        use provider::{Behavior, ProviderRegistry, RuleProvider};

        let mut registry = ProviderRegistry::default();
        registry.insert(RuleProvider::new(
            "ads".into(),
            Behavior::Domain,
            vec!["+.ads.example.com".into(), "bare.example.org".into()],
        ));
        let geo = GeoData::default();
        let set = RuleSet::new(&["RULE-SET,ads,REJECT".into(), "MATCH,DIRECT".into()]);
        let target = TargetAddr::Domain("cdn.ads.example.com".into(), 80);
        assert_eq!(set.find(&target, None, Some(&geo), Some(&registry)).unwrap().target, "REJECT");
        let bare = TargetAddr::Domain("bare.example.org".into(), 80);
        assert_eq!(set.find(&bare, None, Some(&geo), Some(&registry)).unwrap().target, "REJECT");
        let bare_sub = TargetAddr::Domain("www.bare.example.org".into(), 80);
        assert_eq!(set.find(&bare_sub, None, Some(&geo), Some(&registry)).unwrap().target, "DIRECT");
        let clean = TargetAddr::Domain("example.com".into(), 80);
        assert_eq!(set.find(&clean, None, Some(&geo), Some(&registry)).unwrap().target, "DIRECT");
    }
}
