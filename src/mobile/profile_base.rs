//! Profile-base handling, mirroring the Go core's `core/profile_base.go`.
//!
//! The App splits a normal (non-custom, non-script) profile in two: the
//! subscription file on disk and an *overlay* YAML the App generates from it
//! (patch settings — mode, ports, TUN, DNS — plus the user's added rules and
//! any injected providers). The core is responsible for joining them back
//! together, both for `buildProfile` (preview) and for `setupConfig` (the
//! config the engine actually runs). The Go merge semantics are:
//!
//! - the overlay is the root document;
//! - `proxies`, `proxy-groups` and `sub-rules` are taken from the profile;
//! - `rules` is the overlay's rules followed by the profile's rules.
//!
//! Dropping the overlay (the previous behaviour here) silently discarded
//! every App-side setting and added rule for subscription profiles.

use serde_yaml::{Mapping, Value};

/// Top-level sections the profile file contributes to the merged document.
const PROFILE_SECTIONS: [&str; 3] = ["proxies", "proxy-groups", "sub-rules"];

fn as_mapping(value: Value) -> Result<Mapping, String> {
    match value {
        Value::Mapping(m) => Ok(m),
        Value::Null => Ok(Mapping::new()),
        _ => Err("a config must be a mapping".to_string()),
    }
}

fn key(text: &str) -> Value {
    Value::String(text.to_string())
}

/// Join a profile file's text with the App-generated overlay, Go-style.
/// Returns the merged YAML document.
pub fn merge_profile_base(profile_text: &str, overlay_text: &str) -> Result<String, String> {
    let profile = as_mapping(
        serde_yaml::from_str::<Value>(profile_text).map_err(|e| format!("parse profile: {}", e))?,
    )?;
    let mut root = as_mapping(
        serde_yaml::from_str::<Value>(overlay_text).map_err(|e| format!("parse overlay: {}", e))?,
    )?;

    for section in PROFILE_SECTIONS {
        if let Some(value) = profile.get(key(section)) {
            root.insert(key(section), value.clone());
        }
    }

    // Rules: the overlay's (the host's additions) in front of the profile's.
    if let Some(profile_rules) = profile.get(key("rules")) {
        let overlay_rules = root.get(key("rules")).cloned();
        let merged = match overlay_rules {
            None => Some(profile_rules.clone()),
            Some(Value::Null) => Some(profile_rules.clone()),
            Some(Value::Sequence(added)) if added.is_empty() => Some(profile_rules.clone()),
            Some(Value::Sequence(added)) => match profile_rules {
                Value::Sequence(own) => {
                    let mut all = added;
                    all.extend(own.iter().cloned());
                    Some(Value::Sequence(all))
                }
                Value::Null => Some(Value::Sequence(added)),
                _ => return Err("rules must be a list".to_string()),
            },
            Some(_) => return Err("rules must be a list".to_string()),
        };
        if let Some(rules) = merged {
            root.insert(key("rules"), rules);
        }
    }

    serde_yaml::to_string(&Value::Mapping(root)).map_err(|e| format!("encode merged config: {}", e))
}

/// The `match-rules` of a profile: its rules whose action is `MATCH`,
/// mirroring Go's `isMatchRule` (type read from the first comma field).
pub fn match_rules_of(config: &serde_json::Value) -> Vec<String> {
    let Some(rules) = config.get("rules").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    rules
        .iter()
        .filter_map(|r| r.as_str())
        .filter(|r| {
            let kind = r.split(',').next().unwrap_or("").trim();
            kind.eq_ignore_ascii_case("MATCH")
        })
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "\
proxies:
  - name: node1
    type: vless
    server: example.com
    port: 443
proxy-groups:
  - name: PROXY
    type: select
    proxies: [node1]
rules:
  - DOMAIN,example.com,PROXY
  - MATCH,PROXY
dns:
  enable: true
";

    const OVERLAY: &str = "\
mode: rule
mixed-port: 7890
rules:
  - DOMAIN,ads.example.com,REJECT
tun:
  enable: true
";

    #[test]
    fn merge_takes_sections_and_appends_rules() {
        let merged = merge_profile_base(PROFILE, OVERLAY).unwrap();
        let doc: Value = serde_yaml::from_str(&merged).unwrap();
        // Overlay wins for its own keys.
        assert_eq!(doc.get("mode").and_then(|v| v.as_str()), Some("rule"));
        assert_eq!(doc.get("mixed-port").and_then(|v| v.as_u64()), Some(7890));
        // Profile sections are injected.
        assert_eq!(doc.get("proxies").and_then(|v| v.as_sequence()).map(|s| s.len()), Some(1));
        assert_eq!(
            doc.get("proxy-groups").and_then(|v| v.as_sequence()).map(|s| s.len()),
            Some(1)
        );
        // The profile's dns survives only if the overlay lacks it — Go takes
        // the overlay as root, so a key only in the profile (other than the
        // merged sections) is dropped.
        assert!(doc.get("dns").is_none());
        // Rules: overlay first, then the profile's.
        let rules: Vec<&str> = doc
            .get("rules")
            .and_then(|v| v.as_sequence())
            .unwrap()
            .iter()
            .filter_map(|r| r.as_str())
            .collect();
        assert_eq!(
            rules,
            vec!["DOMAIN,ads.example.com,REJECT", "DOMAIN,example.com,PROXY", "MATCH,PROXY"]
        );
    }

    #[test]
    fn merge_without_overlay_rules_uses_profile_rules() {
        let merged = merge_profile_base(PROFILE, "mode: global\n").unwrap();
        let doc: Value = serde_yaml::from_str(&merged).unwrap();
        let rules = doc.get("rules").and_then(|v| v.as_sequence()).unwrap();
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn merge_rejects_non_list_rules() {
        let bad_profile = "rules: notalist\n";
        assert!(merge_profile_base(bad_profile, OVERLAY).is_err());
    }

    #[test]
    fn match_rules_picks_match_only() {
        let config = serde_json::json!({
            "rules": ["DOMAIN,x,PROXY", "MATCH,PROXY", "match , DIRECT"]
        });
        assert_eq!(match_rules_of(&config), vec!["MATCH,PROXY", "match , DIRECT"]);
    }
}
