//! RCX selection-strategy parsing and preview, ported from the Go core's
//! `core/rcx/strategy.go` and `core/rcx_strategy.go`.
//!
//! A strategy is YAML describing an ordered ladder of levels. The editor
//! (`routing_strategy.dart`) asks for `strategyLevels` — for each level, the
//! member names that match its filter — which this module computes.

use std::collections::HashMap;

use serde::Deserialize;

use super::country_table::{COUNTRY_NAMES, NAME_ALIASES};

const BUILTIN_TARGETS: &[&str] = &[
    "DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE", "GLOBAL",
];
const PICKS: &[&str] = &[
    "manual", "first", "hold", "latency", "round-robin", "weighted", "sticky",
    "sticky-session",
];
const MAX_TEXT: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Strategy {
    pub version: i32,
    #[serde(default)]
    pub exclude: StrategyMatch,
    pub levels: Vec<StrategyLevel>,
}

#[derive(Debug, Deserialize, Default, Clone)]
#[serde(deny_unknown_fields)]
pub struct StrategyMatch {
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(rename = "name-contains", default)]
    pub name_contains: String,
    #[serde(default)]
    pub countries: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrategyLevel {
    #[serde(rename = "match", default)]
    pub matcher: StrategyMatch,
    pub pick: String,
    #[serde(default)]
    pub weights: HashMap<String, i32>,
    #[serde(rename = "return-after", default)]
    pub return_after: Option<String>,
    #[serde(rename = "tolerance-ms", default)]
    pub tolerance_ms: Option<i64>,
}

impl StrategyMatch {
    pub fn is_empty(&self) -> bool {
        self.members.is_empty() && self.name_contains.is_empty() && self.countries.is_empty()
    }

    pub fn matches(&self, name: &str, country: &str) -> bool {
        (self.members.is_empty() || self.members.iter().any(|m| m == name))
            && name.contains(&self.name_contains)
            && (self.countries.is_empty() || self.countries.iter().any(|c| c == country))
    }

    fn validate(&self) -> Result<(), String> {
        if self.members.len() > 1024 {
            return Err("too many members in a strategy match".into());
        }
        if self.countries.len() > 250 {
            return Err("too many countries in a strategy match".into());
        }
        if self.name_contains.chars().count() > 256 {
            return Err("name-contains is too long".into());
        }
        for c in &self.countries {
            if c.len() != 2 || !c.bytes().all(|b| b.is_ascii_uppercase()) {
                return Err(format!("invalid country code {:?}", c));
            }
        }
        Ok(())
    }
}

/// Go's `time.ParseDuration` subset: sequences of `<number><unit>`.
fn parse_duration_ms(value: &str) -> Option<i64> {
    // Go's ParseDuration treats a trailing "ms" as milliseconds, not
    // "minutes then seconds"; handle it before the h/m/s loop.
    if let Some(ms) = value.strip_suffix("ms") {
        let n: i64 = ms.parse().ok()?;
        return if n >= 0 { Some(n) } else { None };
    }
    let mut total = 0i64;
    let mut number = String::new();
    for ch in value.chars() {
        if ch.is_ascii_digit() {
            number.push(ch);
            continue;
        }
        if number.is_empty() {
            return None;
        }
        let n: i64 = number.parse().ok()?;
        number.clear();
        let multiplier = match ch {
            'h' => 3_600_000,
            'm' => 60_000,
            's' => 1_000,
            _ => return None,
        };
        total += n * multiplier;
    }
    if !number.is_empty() {
        return None;
    }
    Some(total)
}

pub fn parse(text: &str) -> Result<Strategy, String> {
    if text.len() > MAX_TEXT {
        return Err("strategy document is too large".into());
    }
    let strategy: Strategy =
        serde_yaml::from_str(text).map_err(|e| format!("invalid strategy: {}", e))?;
    if strategy.version != 1 {
        return Err("unsupported strategy version".into());
    }
    if strategy.levels.is_empty() || strategy.levels.len() > 16 {
        return Err("a strategy needs between 1 and 16 levels".into());
    }
    strategy.exclude.validate()?;
    for level in &strategy.levels {
        level.matcher.validate()?;
        if !PICKS.contains(&level.pick.as_str()) {
            return Err(format!("unknown pick {:?}", level.pick));
        }
        if let Some(value) = &level.return_after {
            let ms = parse_duration_ms(value)
                .ok_or_else(|| format!("invalid return-after {:?}", value))?;
            if !(0..=3_600_000).contains(&ms) {
                return Err("return-after must be within 1 hour".into());
            }
        }
        if let Some(tolerance) = level.tolerance_ms {
            if !(0..=10_000).contains(&tolerance) {
                return Err("tolerance-ms must be between 0 and 10000".into());
            }
            if level.pick != "latency" {
                return Err("tolerance-ms only applies to latency".into());
            }
        }
        if !level.weights.is_empty()
            && !matches!(level.pick.as_str(), "weighted" | "sticky" | "sticky-session")
        {
            return Err("weights only apply to weighted/sticky picks".into());
        }
        for weight in level.weights.values() {
            if !(1..=1000).contains(weight) {
                return Err("weights must be between 1 and 1000".into());
            }
        }
    }
    Ok(strategy)
}

/// Country a server name declares: flag emoji first, then a standalone
/// uppercase two-letter token, then a spelled-out English country name.
pub fn country_of_name(name: &str) -> String {
    let chars: Vec<char> = name.chars().collect();
    // Regional-indicator flag (two consecutive code points).
    for pair in chars.windows(2) {
        let (a, b) = (pair[0] as u32, pair[1] as u32);
        if (0x1F1E6..=0x1F1FF).contains(&a) && (0x1F1E6..=0x1F1FF).contains(&b) {
            let code = format!(
                "{}{}",
                char::from_u32('A' as u32 + (a - 0x1F1E6)).unwrap(),
                char::from_u32('A' as u32 + (b - 0x1F1E6)).unwrap()
            );
            if COUNTRY_NAMES.iter().any(|(c, _)| *c == code) {
                return code;
            }
        }
    }
    // Runs of ASCII letters: a two-letter uppercase run standing as a word.
    let mut run = String::new();
    let mut runs: Vec<String> = Vec::new();
    for ch in name.chars() {
        if ch.is_ascii_alphabetic() {
            run.push(ch);
        } else if !run.is_empty() {
            runs.push(std::mem::take(&mut run));
        }
    }
    if !run.is_empty() {
        runs.push(run);
    }
    for token in runs {
        if token.len() != 2 || token.to_uppercase() != token {
            continue;
        }
        if let Some((_, code)) = NAME_ALIASES.iter().find(|(alias, _)| *alias == token) {
            return (*code).to_string();
        }
        if COUNTRY_NAMES.iter().any(|(code, _)| *code == token) {
            return token;
        }
    }
    // Spelled-out names, longest first so "United Arab Emirates" wins over
    // a shorter overlapping word.
    let lower = name.to_lowercase();
    let mut spelled: Vec<(&str, &str)> = COUNTRY_NAMES
        .iter()
        .map(|(code, full)| (*code, *full))
        .collect();
    spelled.sort_by_key(|(_, full)| std::cmp::Reverse(full.len()));
    for (code, full) in spelled {
        if contains_word(&lower, &full.to_lowercase()) {
            return code.to_string();
        }
    }
    String::new()
}

fn contains_word(haystack: &str, word: &str) -> bool {
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(word) {
        let at = start + pos;
        let before = haystack[..at].chars().next_back();
        let after = haystack[at + word.len()..].chars().next();
        let boundary = |c: Option<char>| c.map_or(true, |c| !c.is_alphanumeric());
        if boundary(before) && boundary(after) {
            return true;
        }
        start = at + word.len();
        if start >= haystack.len() {
            break;
        }
    }
    false
}

fn member_allowed(group: &str, name: &str, is_direct: bool, level: &StrategyLevel) -> bool {
    if name == "DNS" || name == "PASS-RULE" {
        return false;
    }
    if is_direct {
        return level.matcher.members.iter().any(|m| m == name);
    }
    name != group && !BUILTIN_TARGETS.contains(&name)
}

/// Produce the editor preview: for every level, the matching member names in
/// the caller's order. Mirrors Go `strategyStudio` lines 879-894.
pub fn strategy_levels(
    text: &str,
    group: &str,
    members: &[(String, bool)],
) -> Result<Vec<Vec<String>>, String> {
    let strategy = parse(text)?;
    let mut levels = vec![Vec::<String>::new(); strategy.levels.len()];
    for (index, level) in strategy.levels.iter().enumerate() {
        let mut seen: Vec<&str> = Vec::new();
        for (name, is_direct) in members {
            if seen.contains(&name.as_str())
                || !member_allowed(group, name, *is_direct, level)
            {
                continue;
            }
            let country = country_of_name(name);
            let excluded = !strategy.exclude.is_empty()
                && strategy.exclude.matches(name, &country);
            if !excluded && level.matcher.matches(name, &country) {
                seen.push(name);
                levels[index].push(name.clone());
            }
        }
    }
    Ok(levels)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_strategy() {
        let s = parse("version: 1\nlevels:\n  - pick: hold\n").unwrap();
        assert_eq!(s.levels.len(), 1);
        assert_eq!(s.levels[0].pick, "hold");
    }

    #[test]
    fn rejects_unknown_fields_and_picks() {
        assert!(parse("version: 1\nlevels:\n  - pick: bogus\n").is_err());
        assert!(parse("version: 1\nbogus: 3\nlevels:\n  - pick: hold\n").is_err());
    }

    #[test]
    fn levels_match_members_exclude_and_country() {
        let text = "version: 1\nexclude: {members: [BAD 01]}\nlevels:\n  - match: {name-contains: Fast}\n    pick: latency\n  - match: {countries: [US]}\n    pick: hold\n";
        let members = vec![
            ("Fast US 01".to_string(), false),
            ("Fast BAD 01".to_string(), false),
            ("Slow US 02".to_string(), false),
            ("DIRECT".to_string(), false),
            ("DIRECT".to_string(), true),
            ("GLOBAL".to_string(), false),
        ];
        let levels = strategy_levels(text, "Proxy", &members).unwrap();
        assert_eq!(levels.len(), 2);
        assert_eq!(levels[0], vec!["Fast US 01"]);
        // "Fast BAD 01" is excluded; DIRECT is a direct proxy not explicitly
        // named in the match, GLOBAL is a builtin target.
        assert_eq!(levels[1], vec!["Fast US 01", "Slow US 02"]);
    }

    #[test]
    fn country_from_flag_and_alias() {
        assert_eq!(country_of_name("🇷🇺 RU Node"), "RU");
        assert_eq!(country_of_name("Holland 01"), "NL");
        assert_eq!(country_of_name("US 01"), "US");
    }
}
