//! Auto-route (RCX) core methods. The App sends a "user layer" (saved
//! scenarios + profiles + per-group bindings); this module reports a live
//! status and applies manual actions to the engine's selections. It mirrors
//! the shape of the Go kernel's rcx protocol so the App's routing pages work.

use serde_json::{json, Map, Value};
use std::sync::{Mutex, OnceLock};

#[derive(Default)]
struct RcxState {
    /// Latest user layer received from the App (raw JSON, preserved so the
    /// App can read back profiles/scenarios it owns).
    layer: Value,
    /// Group name -> chosen node set by a manual pin/change action.
    pinned: std::collections::HashMap<String, String>,
    /// Group name -> control mode ("auto" / "manual" / "pinned").
    modes: std::collections::HashMap<String, String>,
    /// Foreground hint from the App.
    foreground: bool,
}

static STATE: OnceLock<Mutex<RcxState>> = OnceLock::new();
fn state() -> &'static Mutex<RcxState> {
    STATE.get_or_init(|| Mutex::new(RcxState::default()))
}

fn as_obj(v: &Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap_or_default()
}

/// Build the rcxStatus object the App parses into RcxStatus. Auto-route is
/// reported as running whenever a profile is loaded, with one entry per
/// select/url-test group so the routing pages have real data to show.
pub async fn status() -> Value {
    let engine = crate::runtime_state::engine().await;
    let (layer, pinned, modes) = {
        let s = state().lock().unwrap();
        (s.layer.clone(), s.pinned.clone(), s.modes.clone())
    };
    let running = engine.is_some();
    let mut groups = Vec::new();
    if let Some(engine) = engine {
        // Group snapshots: name, current node, members, and control mode.
        for g in engine.outbounds.groups.values() {
            let name = &g.name;
            let now = g.selected().unwrap_or_default();
            let mode = modes
                .get(name)
                .cloned()
                .unwrap_or_else(|| "auto".to_string());
            let binding = layer
                .get("groups")
                .and_then(|v| v.get(name))
                .cloned()
                .unwrap_or_else(|| json!({}));
            let now_value = if now.is_empty() {
                Value::Null
            } else {
                Value::String(now)
            };
            groups.push(json!({
                "name": name,
                "source": "profile",
                "profile": "",
                "profileTitle": "",
                "level": "simple",
                "offered": g.members.clone(),
                "binding": binding,
                "control": { "mode": mode },
                "now": now_value,
                "members": g.members.clone(),
            }));
        }
    }
    // A scenario is active only when the layer actually names one.
    let scenario_name = layer
        .get("scenario")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let scenario = scenario_name.map(|id| {
        let title = layer
            .get("scenarios")
            .and_then(|v| v.get(&id))
            .and_then(|v| v.get("title"))
            .and_then(|v| v.as_str())
            .unwrap_or(&id)
            .to_string();
        json!({ "id": id, "title": title, "source": "user", "groups": {} })
    });
    json!({
        "running": running,
        "mode": if running { "rule" } else { "stopped" },
        "strategySupport": false,
        "strategies": {},
        "network": "",
        "groups": groups,
        "energy": { "level": "balanced" },
        "problems": [],
        "split": "",
        "library": 0,
        "scenario": scenario,
        "tunnelMode": "rule",
        "reload": false,
    })
}

/// Receive the user layer from the App, then return the full live status --
/// the App applies this response directly to rcxStatusState, so it must carry
/// the groups/scenario, not a placeholder.
pub async fn set_policy(args: Value) -> Value {
    set_layer(args);
    status().await
}

/// Store the user layer that the App attaches to setupConfig (`rcx` key).
/// This is the primary path: the App sends the whole routing layer when it
/// applies a profile, before any rcxSetPolicy call.
pub fn set_layer(args: Value) {
    let mut s = state().lock().unwrap();
    s.layer = args;
}

pub fn hints(args: &Value) -> Value {
    if let Some(v) = args.get("foreground").and_then(|v| v.as_bool()) {
        state().lock().unwrap().foreground = v;
    }
    Value::Bool(true)
}

pub fn explain(group: &str) -> Value {
    json!({
        "group": group,
        "profile": "",
        "decision": { "action": "hold", "target": "", "reason": { "code": "" } },
        "freshnessSeconds": 0,
    })
}

pub fn journal(_args: &Value) -> Value {
    Value::Array(Vec::new())
}

/// Pull a top-level scalar (or a quoted one) out of a small YAML file.
/// The built-in metadata is simple enough that a full YAML parser is overkill.
fn yaml_scalar(text: &str, key: &str) -> String {
    for line in text.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix(key) {
            if let Some(rest) = rest.strip_prefix(':') {
                let v = rest.trim();
                if v.is_empty() || v.starts_with('{') || v.starts_with('[') {
                    continue;
                }
                return v.trim_matches(|c| c == '"' || c == '\'').to_string();
            }
        }
    }
    String::new()
}

/// One built-in entry: (filename without extension, is_scenario, YAML text).
const BUILTIN_PROFILES: &[(&str, &str)] = &[
    ("bypass-cn", include_str!("rcx_builtin/bypass-cn.yaml")),
    ("bypass-ir", include_str!("rcx_builtin/bypass-ir.yaml")),
    ("bypass-ru", include_str!("rcx_builtin/bypass-ru.yaml")),
    ("fastest", include_str!("rcx_builtin/fastest.yaml")),
    ("from-list", include_str!("rcx_builtin/from-list.yaml")),
    ("simple", include_str!("rcx_builtin/simple.yaml")),
    ("stable", include_str!("rcx_builtin/stable.yaml")),
    ("whitelist-ru", include_str!("rcx_builtin/whitelist-ru.yaml")),
];
const BUILTIN_SCENARIOS: &[(&str, &str)] = &[
    ("every-group", include_str!("rcx_builtin/scenarios/every-group.yaml")),
    ("whitelist-ru", include_str!("rcx_builtin/scenarios/whitelist-ru.yaml")),
];

pub fn profiles() -> Value {
    let layer = state().lock().unwrap().layer.clone();
    let mut out = Vec::new();

    // Built-in library, mirroring the Go kernel's embedded builtin/*.yaml and
    // builtin/scenarios/*.yaml. These give the App a non-empty library so the
    // "use scenario" toggle is enabled and route profiles resolve by id.
    for (name, text) in BUILTIN_PROFILES {
        out.push(json!({
            "id": format!("builtin/{}", name),
            "kind": "",
            "title": yaml_scalar(text, "title"),
            "description": yaml_scalar(text, "description"),
            "level": yaml_scalar(text, "level"),
            "source": "builtin",
            "text": text,
        }));
    }
    for (name, text) in BUILTIN_SCENARIOS {
        out.push(json!({
            "id": format!("builtin/{}", name),
            "kind": "scenario",
            "title": yaml_scalar(text, "title"),
            "description": yaml_scalar(text, "description"),
            "source": "builtin",
            "text": text,
        }));
    }

    // User/subscription entries sent in the routing layer.
    for (key, kind) in [("scenarios", "scenario"), ("profiles", "")] {
        let Some(map) = layer.get(key).and_then(|v| v.as_object()) else {
            continue;
        };
        for (id, v) in map {
            out.push(json!({
                "id": id,
                "kind": kind,
                "title": v.get("title").and_then(|x| x.as_str()).unwrap_or(id),
                "text": v.as_str().unwrap_or(""),
                "source": "user",
            }));
        }
    }
    Value::Array(out)
}

/// Apply a manual action to a group's selection. change/pin set the node and
/// switch the group to manual/pinned; auto/manual clear the override so the
/// engine falls back to its normal selection.
pub async fn action(args: Value) -> Value {
    let group = args.get("group").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let act = args.get("action").and_then(|v| v.as_str()).unwrap_or("hold").to_string();
    let node = args.get("node").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut target = String::new();
    match act.as_str() {
        "change" | "pin" => {
            if !node.is_empty() {
                state().lock().unwrap().pinned.insert(group.clone(), node.clone());
                state().lock().unwrap().modes.insert(group.clone(), act.clone());
                target = node.clone();
            }
        }
        "auto" | "manual" | "check" => {
            state().lock().unwrap().pinned.remove(&group);
            state().lock().unwrap().modes.insert(group.clone(), act.clone());
        }
        _ => {}
    }
    if let Some(engine) = crate::runtime_state::engine().await {
        if !target.is_empty() {
            engine.outbounds.set_selection(&group, &target);
        }
    }
    json!({
        "decision": {
            "action": if target.is_empty() { "hold" } else { "change" },
            "target": target,
            "reason": { "code": "" },
        }
    })
}

pub fn studio(_args: &Value) -> Value {
    json!({ "text": "", "strategyLevels": [], "errors": [], "warnings": [] })
}

/// A cheap status for set_policy's immediate response; the full status is
/// fetched by the App's following rcxStatus call.
pub fn status_sync() -> Value {
    json!({ "running": true, "mode": "rule", "groups": [] })
}
