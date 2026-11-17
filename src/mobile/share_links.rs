//! Share-link encode/decode for the subscription editor.
//! Implements the common SIP002 / Xray forms for ss, vless, trojan, socks5/http
//! and vmess. Unsupported fields are ignored rather than corrupting the link.

use base64::Engine;
use serde_json::{json, Map, Value};

const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

fn s(map: &Map<String, Value>, key: &str) -> String {
    match map.get(key) {
        Some(Value::String(v)) => v.clone(),
        Some(Value::Number(v)) => v.to_string(),
        Some(Value::Bool(v)) => v.to_string(),
        _ => String::new(),
    }
}

fn flag(map: &Map<String, Value>, key: &str) -> bool {
    matches!(map.get(key), Some(Value::Bool(true)))
}

fn pct(text: &str) -> String {
    let mut out = String::new();
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

fn host_port(map: &Map<String, Value>) -> String {
    let host = s(map, "server");
    let port = s(map, "port");
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn encode(map: &Map<String, Value>) -> String {
    if s(map, "server").is_empty() {
        return String::new();
    }
    match s(map, "type").as_str() {
        "ss" => {
            let userinfo = B64.encode(format!("{}:{}", s(map, "cipher"), s(map, "password")));
            let name = pct(&s(map, "name"));
            format!("ss://{}@{}#{}", userinfo, host_port(map), name)
        }
        "vless" => {
            let mut q = Vec::new();
            if flag(map, "tls") {
                q.push("security=tls".to_string());
            }
            if !s(map, "sni").is_empty() {
                q.push(format!("sni={}", pct(&s(map, "sni"))));
            }
            if !s(map, "flow").is_empty() {
                q.push(format!("flow={}", pct(&s(map, "flow"))));
            }
            let suffix = if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) };
            format!("vless://{}@{}{}#{}", pct(&s(map, "uuid")), host_port(map), suffix, pct(&s(map, "name")))
        }
        "trojan" => {
            let mut q = Vec::new();
            if !s(map, "sni").is_empty() {
                q.push(format!("sni={}", pct(&s(map, "sni"))));
            }
            let suffix = if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) };
            format!("trojan://{}@{}{}#{}", pct(&s(map, "password")), host_port(map), suffix, pct(&s(map, "name")))
        }
        "socks5" | "http" => {
            let scheme = if s(map, "type") == "http" && flag(map, "tls") {
                "https".to_string()
            } else {
                s(map, "type")
            };
            let user = s(map, "username");
            let auth = if user.is_empty() { String::new() } else { format!("{}:{}@", pct(&user), pct(&s(map, "password"))) };
            format!("{}://{}{}#{}", scheme, auth, host_port(map), pct(&s(map, "name")))
        }
        "vmess" => {
            // Plain Xray form: base64url of a minimal v2rayN-style config.
            let cfg = json!({
                "v": "2", "ps": s(map, "name"), "add": s(map, "server"),
                "port": s(map, "port"), "id": s(map, "uuid"),
                "aid": s(map, "alterId"), "net": "tcp", "type": "none",
                "host": "", "path": "", "tls": if flag(map, "tls") { "tls" } else { "" },
            });
            format!("vmess://{}", B64.encode(cfg.to_string().as_bytes()))
        }
        _ => String::new(),
    }
}

fn split_tag(rest: &str) -> (&str, String) {
    if let Some(i) = rest.find('#') {
        (&rest[..i], percent_decode(&rest[i + 1..]))
    } else {
        (rest, String::new())
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_host_port(authority: &str) -> (String, String) {
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            let host = stripped[..end].to_string();
            let port = stripped[end + 1..].strip_prefix(':').unwrap_or("").to_string();
            return (host, port);
        }
    }
    if let Some((h, p)) = authority.rsplit_once(':') {
        return (h.to_string(), p.to_string());
    }
    (authority.to_string(), String::new())
}

fn query_value(query: &str, key: &str) -> String {
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return percent_decode(v);
            }
        }
    }
    String::new()
}

fn decode(line: &str) -> Vec<Map<String, Value>> {
    let line = line.trim();
    if line.is_empty() {
        return vec![];
    }
    let (scheme, rest) = match line.split_once("://") {
        Some(v) => v,
        None => return vec![],
    };
    let (before_tag, name) = split_tag(rest);
    let (authority, query) = match before_tag.split_once('?') {
        Some((a, q)) => (a, q),
        None => (before_tag, ""),
    };

    let mut map = Map::new();
    map.insert("name".into(), Value::String(name.clone()));
    let (host, port) = parse_host_port(authority);

    match scheme {
        "ss" => {
            let userinfo = authority.split('@').next().unwrap_or("");
            let decoded = B64.decode(userinfo).or_else(|_| B64URL.decode(userinfo));
            if let Ok(creds) = decoded {
                let creds = String::from_utf8_lossy(&creds);
                if let Some((cipher, password)) = creds.split_once(':') {
                    map.insert("cipher".into(), Value::String(cipher.into()));
                    map.insert("password".into(), Value::String(password.into()));
                }
            }
            map.insert("type".into(), Value::String("ss".into()));
        }
        "vless" => {
            let user = authority.split('@').next().unwrap_or("");
            map.insert("uuid".into(), Value::String(percent_decode(user)));
            map.insert("type".into(), Value::String("vless".into()));
            if !query_value(query, "security").is_empty() {
                map.insert("tls".into(), Value::Bool(true));
            }
            if let v = query_value(query, "sni") { if !v.is_empty() { map.insert("sni".into(), Value::String(v)); } }
            if let v = query_value(query, "flow") { if !v.is_empty() { map.insert("flow".into(), Value::String(v)); } }
        }
        "trojan" => {
            let user = authority.split('@').next().unwrap_or("");
            map.insert("password".into(), Value::String(percent_decode(user)));
            map.insert("type".into(), Value::String("trojan".into()));
            if let v = query_value(query, "sni") { if !v.is_empty() { map.insert("sni".into(), Value::String(v)); } }
        }
        "socks5" | "http" | "https" => {
            map.insert("type".into(), Value::String(if scheme == "https" { "http".into() } else { scheme.into() }));
            map.insert("tls".into(), Value::Bool(scheme == "https"));
        }
        "vmess" => {
            if let Ok(raw) = B64.decode(rest.split('#').next().unwrap_or(rest)) {
                if let Ok(Value::Object(cfg)) = serde_json::from_slice::<Value>(&raw) {
                    for (k, v) in cfg {
                        map.insert(k, v);
                    }
                    map.insert("type".into(), Value::String("vmess".into()));
                    return vec![map];
                }
            }
            return vec![];
        }
        _ => return vec![],
    }
    map.insert("server".into(), Value::String(host));
    map.insert("port".into(), Value::String(port));
    vec![map]
}

pub fn encode_links(mappings: &[Value]) -> Vec<String> {
    mappings.iter().map(|v| match v.as_object() {
        Some(m) => encode(m),
        None => String::new(),
    }).collect()
}

pub fn decode_lines(lines: &[String]) -> Vec<Vec<Map<String, Value>>> {
    lines.iter().map(|l| decode(l)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_shadowsocks_sip002() {
        let m = serde_json::from_str::<Value>(
            r#"{"type":"ss","server":"1.2.3.4","port":"8388","cipher":"aes-256-gcm","password":"pw","name":"node"}"#
        ).unwrap().as_object().unwrap().clone();
        let link = encode(&m);
        assert!(link.starts_with("ss://"));
        assert!(link.ends_with("#node"));
    }

    #[test]
    fn encodes_vless_and_trojan() {
        let v = serde_json::from_str::<Value>(
            r#"{"type":"vless","server":"x.com","port":"443","uuid":"abc","tls":true,"sni":"x.com","name":"v"}"#
        ).unwrap().as_object().unwrap().clone();
        assert!(encode(&v).contains("security=tls"));
        let t = serde_json::from_str::<Value>(
            r#"{"type":"trojan","server":"x.com","port":"443","password":"pw","name":"t"}"#
        ).unwrap().as_object().unwrap().clone();
        assert!(encode(&t).starts_with("trojan://"));
    }

    #[test]
    fn roundtrip_vless() {
        let original = serde_json::from_str::<Value>(
            r#"{"type":"vless","server":"x.com","port":"443","uuid":"abc-123","tls":true,"sni":"x.com","name":"v"}"#
        ).unwrap().as_object().unwrap().clone();
        let link = encode(&original);
        let decoded = decode(&link);
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0]["uuid"], "abc-123");
        assert_eq!(decoded[0]["server"], "x.com");
        assert_eq!(decoded[0]["name"], "v");
    }

    #[test]
    fn roundtrip_ss() {
        let original = serde_json::from_str::<Value>(
            r#"{"type":"ss","server":"1.2.3.4","port":"8388","cipher":"aes-256-gcm","password":"pw","name":"n"}"#
        ).unwrap().as_object().unwrap().clone();
        let link = encode(&original);
        let decoded = decode(&link);
        assert_eq!(decoded[0]["cipher"], "aes-256-gcm");
        assert_eq!(decoded[0]["password"], "pw");
    }

    #[test]
    fn encode_links_batch() {
        let v = serde_json::from_str::<Value>(r#"[{"type":"ss","server":"1.2.3.4","port":"1","cipher":"c","password":"p","name":"a"}]"#).unwrap();
        let arr = v.as_array().unwrap();
        let links = encode_links(arr);
        assert_eq!(links.len(), 1);
    }
}
