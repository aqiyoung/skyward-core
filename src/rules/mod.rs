//! Rule parsing and matching. Mirrors the `rules/` package of the Go kernel,
//! covering the matcher types most configs rely on.

use ipnet::IpNet;
use std::net::IpAddr;
use std::str::FromStr;

use crate::common::TargetAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    IpCidr,
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
}

impl Rule {
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
        let no_resolve = parts
            .iter()
            .any(|p| p.eq_ignore_ascii_case("no-resolve"));
        let target = parts
            .iter()
            .rev()
            .find(|p| !p.eq_ignore_ascii_case("no-resolve"))?
            .to_string();
        let kind = match parts[0].to_ascii_uppercase().as_str() {
            "DOMAIN" => RuleKind::Domain,
            "DOMAIN-SUFFIX" => RuleKind::DomainSuffix,
            "DOMAIN-KEYWORD" => RuleKind::DomainKeyword,
            "IP-CIDR" | "IP-CIDR6" => RuleKind::IpCidr,
            "MATCH" => RuleKind::Match,
            _ => return None, // GEOIP / PROCESS-NAME / RULE-SET: reserved
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

        Some(Self {
            kind,
            value,
            target,
            no_resolve,
            raw,
            net,
        })
    }

    pub fn matches(&self, addr: &TargetAddr, resolved: Option<IpAddr>) -> bool {
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
            RuleKind::IpCidr => {
                if let Some(ip) = resolved {
                    return self.net.as_ref().map(|n| n.contains(&ip)).unwrap_or(false);
                }
                match addr {
                    TargetAddr::Ip(ip, _) => self.net.as_ref().map(|n| n.contains(ip)).unwrap_or(false),
                    _ => false, // no-resolve: domain targets are deliberately skipped
                }
            }
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

    pub fn find(&self, addr: &TargetAddr, resolved: Option<IpAddr>) -> Option<&Rule> {
        self.rules.iter().find(|r| r.matches(addr, resolved))
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
        assert_eq!(set.find(&hit, None).unwrap().target, "proxy");
        let miss = TargetAddr::Domain("example.org".into(), 443);
        assert_eq!(set.find(&miss, None).unwrap().target, "DIRECT");
    }

    #[test]
    fn ip_cidr_uses_resolved_address() {
        let set = RuleSet::new(&[
            "IP-CIDR,192.168.0.0/16,DIRECT,no-resolve".into(),
            "MATCH,REJECT".into(),
        ]);
        let ip: IpAddr = "192.168.1.20".parse().unwrap();
        let addr = TargetAddr::Domain("inside.local".into(), 80);
        assert_eq!(set.find(&addr, Some(ip)).unwrap().target, "DIRECT");
        assert_eq!(set.find(&addr, None).unwrap().target, "REJECT");
    }

    #[test]
    fn no_resolve_flag_is_parsed() {
        let rule = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap();
        assert!(rule.no_resolve);
        assert_eq!(rule.kind, RuleKind::IpCidr);
    }
}
