//! Rule-set compilation behind the App's `compileRuleSet`, mirroring the Go
//! core's `core/rule_set.go`: sniff the source format (yaml `payload`/`rules`
//! or plain text), classify it (domain / ipcidr / classical), and emit an mrs
//! file for the two set behaviors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use ipnet::IpNet;
use serde_yaml::Value as Yaml;

use super::mrs_write::{domain_set_body, ipcidr_set_body, mrs_document};
use super::provider::Behavior;

#[derive(Debug)]
pub enum CompileError {
    /// No usable entry, and an empty set is not allowed here.
    Empty,
    /// The set mixes domains and IP ranges.
    Mixed,
    /// Not a readable mrs file.
    Invalid,
}

pub struct Compiled {
    pub behavior: Behavior,
    /// "yaml" | "text" | "mrs"
    pub format: &'static str,
    /// The compiled set, when the behavior has an mrs form.
    pub mrs: Option<Vec<u8>>,
}

/// Compile a staged rule-set body. `allow_empty` marks content the App wrote
/// itself (a download may not be empty).
pub fn compile(buf: &[u8], allow_empty: bool) -> Result<Compiled, CompileError> {
    if buf.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        for behavior in [Behavior::Domain, Behavior::IpCidr] {
            if super::mrs::parse_mrs(buf, behavior).is_ok() {
                return Ok(Compiled { behavior, format: "mrs", mrs: None });
            }
        }
        return Err(CompileError::Invalid);
    }

    let (format, entries) = rule_set_entries(buf);
    if entries.is_empty() && allow_empty {
        return Ok(Compiled { behavior: Behavior::Classical, format, mrs: None });
    }
    let (behavior, keys) = classify(&entries)?;
    if behavior == Behavior::Classical {
        return Ok(Compiled { behavior, format, mrs: None });
    }

    let count;
    let mrs = if behavior == Behavior::Domain {
        let mut keys_v = Vec::new();
        count = keys.iter().filter(|key| builder_add(&mut keys_v, key)).count();
        if count == 0 {
            return Err(CompileError::Empty);
        }
        mrs_document(behavior, count, &domain_set_body(&keys_v).ok_or(CompileError::Empty)?)
    } else {
        let mut ranges = Vec::new();
        for key in &keys {
            if let Some(range) = range_of(key) {
                ranges.push(range);
            }
        }
        count = ranges.len();
        if count == 0 {
            return Err(CompileError::Empty);
        }
        mrs_document(behavior, count, &ipcidr_set_body(&ranges).ok_or(CompileError::Empty)?)
    };
    Ok(Compiled { behavior, format, mrs: Some(mrs) })
}

/// Entries of a source: yaml `payload`/`rules` lists, or plain text lines.
fn rule_set_entries(buf: &[u8]) -> (&'static str, Vec<String>) {
    if let Ok(Yaml::Mapping(map)) = serde_yaml::from_slice::<Yaml>(buf) {
        let payload = map.get(Yaml::String("payload".into()));
        let rules = map.get(Yaml::String("rules".into()));
        if payload.is_some() || rules.is_some() {
            let mut entries = Vec::new();
            for list in [payload, rules].into_iter().flatten() {
                if let Yaml::Sequence(items) = list {
                    for item in items {
                        if let Some(text) = item.as_str() {
                            let text = text.trim();
                            if !text.is_empty() {
                                entries.push(text.to_string());
                            }
                        }
                    }
                }
            }
            return ("yaml", entries);
        }
    }
    let mut entries = Vec::new();
    if let Ok(text) = std::str::from_utf8(buf) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            entries.push(line.to_string());
        }
    }
    ("text", entries)
}

fn classify(entries: &[String]) -> Result<(Behavior, Vec<String>), CompileError> {
    if entries.is_empty() {
        return Err(CompileError::Empty);
    }
    if entries.iter().any(|entry| entry.contains(',')) {
        return classify_classical(entries);
    }
    let mut cidrs = Vec::new();
    for entry in entries {
        if let Some(cidr) = parse_cidr(entry) {
            cidrs.push(cidr);
        }
    }
    match cidrs.len() {
        0 => Ok((Behavior::Domain, entries.to_vec())),
        n if n == entries.len() => Ok((Behavior::IpCidr, cidrs)),
        _ => Err(CompileError::Mixed),
    }
}

/// Classical lines may still be a pure domain / ipcidr set in rule form.
fn classify_classical(entries: &[String]) -> Result<(Behavior, Vec<String>), CompileError> {
    let mut domains = Vec::new();
    let mut cidrs = Vec::new();
    for entry in entries {
        let Some((kind, value)) = entry.split_once(',') else {
            return Ok((Behavior::Classical, Vec::new()));
        };
        if value.contains(',') {
            return Ok((Behavior::Classical, Vec::new()));
        }
        let value = value.trim();
        match kind.trim().to_ascii_uppercase().as_str() {
            "DOMAIN" if plain_domain(value) => domains.push(value.to_string()),
            "DOMAIN-SUFFIX" if plain_domain(value) => domains.push(format!("+.{value}")),
            "IP-CIDR" | "IP-CIDR6" if IpNet::from_str(value).is_ok() => {
                cidrs.push(value.to_string())
            }
            _ => return Ok((Behavior::Classical, Vec::new())),
        }
    }
    match (cidrs.is_empty(), domains.is_empty()) {
        (true, false) => Ok((Behavior::Domain, domains)),
        (false, true) => Ok((Behavior::IpCidr, cidrs)),
        _ => Ok((Behavior::Classical, Vec::new())),
    }
}

/// A domain set reads a leading dot, "+" and "*" as wildcards.
fn plain_domain(value: &str) -> bool {
    !value.is_empty() && !value.starts_with('.') && !value.contains(['+', '*', '/'])
}

fn parse_cidr(entry: &str) -> Option<String> {
    if IpNet::from_str(entry).is_ok() {
        return Some(entry.to_string());
    }
    let ip = IpAddr::from_str(entry).ok()?;
    let bits = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Some(format!("{ip}/{bits}"))
}

fn range_of(prefix: &str) -> Option<(IpAddr, IpAddr)> {
    let net = IpNet::from_str(prefix).ok()?;
    let bits = net.prefix_len();
    Some(match net.addr() {
        IpAddr::V4(addr) => {
            let base = u32::from(addr);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (
                IpAddr::V4(Ipv4Addr::from(base & mask)),
                IpAddr::V4(Ipv4Addr::from((base & mask) | !mask)),
            )
        }
        IpAddr::V6(addr) => {
            let base = u128::from(addr);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (
                IpAddr::V6(Ipv6Addr::from(base & mask)),
                IpAddr::V6(Ipv6Addr::from((base & mask) | !mask)),
            )
        }
    })
}

// ---- domain pattern validation, mirroring component/trie/domain.go ---------

fn valid_and_split_domain(domain: &str) -> Option<Vec<String>> {
    if domain.is_empty() || domain.ends_with('.') {
        return None;
    }
    if domain.chars().next().is_some_and(char::is_whitespace)
        || domain.chars().last().is_some_and(char::is_whitespace)
    {
        return None;
    }
    let lower = domain.to_ascii_lowercase();
    let parts: Vec<&str> = lower.split('.').collect();
    if parts.len() == 1 {
        if parts[0].is_empty() {
            return None;
        }
    } else if parts[1..].iter().any(|part| part.is_empty()) {
        return None;
    }
    for (index, part) in parts.iter().enumerate() {
        if part.contains('+') && (*part != "+" || index != 0 || parts.len() == 1) {
            return None;
        }
        if part.contains('*') && *part != "*" {
            return None;
        }
    }
    Some(parts.into_iter().map(str::to_string).collect())
}

fn reverse(text: &str) -> String {
    text.chars().rev().collect()
}

fn builder_insert(keys: &mut Vec<String>, parts: &[String]) {
    let joined = if parts[0].is_empty() {
        let mut parts = parts.to_vec();
        parts[0] = "+".to_string();
        parts.join(".")
    } else {
        parts.join(".")
    };
    keys.push(reverse(&joined));
}

/// Accept one pattern the way `DomainSetBuilder.Insert` does; false drops it.
fn builder_add(keys: &mut Vec<String>, domain: &str) -> bool {
    if domain.contains('/') {
        return false;
    }
    let Some(parts) = valid_and_split_domain(domain) else {
        return false;
    };
    if parts[0] == "+" {
        builder_insert(keys, &parts[1..]);
        builder_insert(keys, &parts);
    } else {
        builder_insert(keys, &parts);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_domain_set_compiles_to_a_loadable_mrs() {
        let compiled = compile(b"example.com\n+.example.com\n", false).unwrap();
        assert_eq!(compiled.behavior, Behavior::Domain);
        assert_eq!(compiled.format, "text");
        let mrs = compiled.mrs.expect("domain set has an mrs");
        assert!(!super::super::mrs::parse_mrs(&mrs, Behavior::Domain).unwrap().is_empty());
    }

    #[test]
    fn yaml_payload_is_read_as_yaml() {
        let compiled =
            compile(b"payload:\n  - a.test\n  - b.test\n", false).unwrap();
        assert_eq!(compiled.format, "yaml");
        assert_eq!(compiled.behavior, Behavior::Domain);
    }

    #[test]
    fn classical_lines_become_a_domain_or_ipcidr_set() {
        let domain = compile(b"DOMAIN-SUFFIX,example.com\n", false).unwrap();
        assert_eq!(domain.behavior, Behavior::Domain);

        let cidr = compile(b"IP-CIDR,10.0.0.0/24\n", false).unwrap();
        assert_eq!(cidr.behavior, Behavior::IpCidr);
        assert!(cidr.mrs.is_some());

        let classical = compile(b"DST-PORT,443,DIRECT\n", false).unwrap();
        assert_eq!(classical.behavior, Behavior::Classical);
        assert!(classical.mrs.is_none());
    }

    #[test]
    fn mixed_sets_are_rejected_and_empty_downloads_too() {
        assert!(matches!(
            compile(b"a.test\n10.0.0.0/24\n", false),
            Err(CompileError::Mixed)
        ));
        assert!(matches!(compile(b"", false), Err(CompileError::Empty)));
        let empty = compile(b"", true).unwrap();
        assert_eq!(empty.behavior, Behavior::Classical);
        assert!(empty.mrs.is_none());
    }
}


