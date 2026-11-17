//! HTTP REST controller, exposing a subset of mihomo's external controller API.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};

pub mod websocket;

use crate::common::VERSION;
use crate::AppState;

pub async fn serve(addr: &str, state: Arc<AppState>) -> anyhow::Result<()> {
    let normalized = if let Some(rest) = addr.strip_prefix(':') {
        format!("127.0.0.1:{}", rest)
    } else {
        addr.to_string()
    };
    let socket: SocketAddr = normalized.parse()?;

    let make_service = make_service_fn(move |_| {
        let state = state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let state = state.clone();
                async move { Ok::<_, Infallible>(route(req, state).await) }
            }))
        }
    });

    Server::bind(&socket).serve(make_service).await?;
    Ok(())
}

async fn route(req: Request<Body>, state: Arc<AppState>) -> Response<Body> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();
    let query = req.uri().query().map(str::to_string);
    let secret = state.engine.read().await.config.secret.clone();

    if path != "/" && !authorized(&req, &secret, query.as_deref()) {
        return json(StatusCode::UNAUTHORIZED, serde_json::json!({ "error": "unauthorized" }));
    }

    // WebSocket upgrade must be handled before consuming the body.
    if path == "/traffic" && is_websocket_upgrade(&req) {
        let key = req.headers().get("sec-websocket-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let upgrade = hyper::upgrade::on(req);
        let traffic = state.engine.read().await.traffic.clone();
        tokio::spawn(async move {
            match upgrade.await {
                Ok(upgraded) => stream_traffic(upgraded, traffic).await,
                Err(e) => tracing::debug!("traffic ws upgrade failed: {}", e),
            }
        });
        return Response::builder()
            .status(StatusCode::SWITCHING_PROTOCOLS)
            .header("upgrade", "websocket")
            .header("connection", "Upgrade")
            .header("sec-websocket-accept", ws_accept(&key))
            .body(Body::empty())
            .unwrap();
    }

    if is_websocket_upgrade(&req) {
        return json(StatusCode::NOT_FOUND, serde_json::json!({ "error": "not found" }));
    }

    let (_, body) = req.into_parts();
    let body_bytes = hyper::body::to_bytes(body).await.unwrap_or_default();

    match (method, path.as_str()) {
        (Method::GET, "/") => Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .body(Body::from("<h1>skyward-core (rust)</h1><p>REST controller is running.</p>"))
            .unwrap(),

        (Method::GET, "/version") => {
            let mode = state.engine.read().await.mode.read().await.clone();
            json(StatusCode::OK, serde_json::json!({
                "version": VERSION,
                "core": "skyward-core-rust",
                "mode": mode,
            }))
        }

        (Method::GET, "/configs") => {
            let engine = state.engine.read().await;
            json(StatusCode::OK, serde_json::json!({
                "mode": engine.mode.read().await.clone(),
                "allow_lan": engine.config.allow_lan,
                "port": engine.config.port,
                "socks_port": engine.config.socks_port,
                "mixed_port": engine.config.mixed_port,
                "rules": engine.rules.rules.len(),
                "proxies": engine.outbounds.outbounds.len(),
                "groups": engine.outbounds.groups.len(),
            }))
        }

        (Method::GET, "/proxies") => {
            let engine = state.engine.read().await;
            json(StatusCode::OK, serde_json::json!(engine.outbounds.snapshot()))
        }

        (Method::GET, "/providers/proxies") => {
            let engine = state.engine.read().await;
            json(StatusCode::OK, serde_json::json!(engine.proxy_providers.snapshot()))
        }

        (Method::GET, "/providers/rule") => {
            let engine = state.engine.read().await;
            json(StatusCode::OK, serde_json::json!(engine.providers.snapshot()))
        }

        (Method::GET, "/rules") => {
            let engine = state.engine.read().await;
            let rules: Vec<&str> = engine.rules.rules.iter().map(|r| r.raw.as_str()).collect();
            json(StatusCode::OK, serde_json::json!(rules))
        }

        (Method::GET, "/traffic") => {
            let snap = state.engine.read().await.traffic.snapshot();
            json(StatusCode::OK, serde_json::json!({ "up": snap.up, "down": snap.down }))
        }

        (Method::GET, "/connections") => {
            let items = state.engine.read().await.connections.snapshot().await;
            json(StatusCode::OK, serde_json::json!({ "connections": items }))
        }

        (Method::DELETE, "/connections") => {
            json(StatusCode::OK, serde_json::json!({ "status": "ok" }))
        }

        (Method::PUT, "/configs") => match state.reload().await {
            Ok(()) => json(StatusCode::OK, serde_json::json!({ "status": "ok" })),
            Err(e) => json(StatusCode::BAD_REQUEST, serde_json::json!({ "error": e.to_string() })),
        },

        (Method::PUT, "/mode") => {
            let name = query_param(query.as_deref(), "name")
                .or_else(|| body_field(&body_bytes, "mode"))
                .unwrap_or_default();
            if !["rule", "direct", "global"].contains(&name.as_str()) {
                return json(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid mode" }));
            }
            let engine = state.engine.read().await;
            *engine.mode.write().await = name.clone();
            json(StatusCode::OK, serde_json::json!({ "mode": name }))
        }

        (Method::PUT, p) if p.starts_with("/proxies/") => {
            let group = p.trim_start_matches("/proxies/").to_string();
            let member = query_param(query.as_deref(), "name")
                .or_else(|| body_field(&body_bytes, "name"))
                .unwrap_or_default();
            let engine = state.engine.read().await;
            if engine.outbounds.set_selection(&group, &member) {
                json(StatusCode::OK, serde_json::json!({ "status": "ok" }))
            } else {
                json(StatusCode::NOT_FOUND, serde_json::json!({ "error": "unknown group or member" }))
            }
        }

        _ => json(StatusCode::NOT_FOUND, serde_json::json!({ "error": "not found" })),
    }
}

fn authorized(req: &Request<Body>, secret: &str, query: Option<&str>) -> bool {
    if secret.is_empty() {
        return true;
    }
    if query_param(query, "token").as_deref() == Some(secret) {
        return true;
    }
    req.headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or(v) == secret)
        .unwrap_or(false)
}

fn query_param(query: Option<&str>, key: &str) -> Option<String> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if k == key { Some(v.replace('+', " ")) } else { None }
    })
}

fn body_field(bytes: &[u8], field: &str) -> Option<String> {
    let value: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    value.get(field)?.as_str().map(str::to_string)
}

fn json(status: StatusCode, value: serde_json::Value) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    req.headers().get("upgrade").and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

fn ws_accept(key: &str) -> String {
    let response = websocket::Websocket::accept(key);
    let text = String::from_utf8_lossy(&response);
    text.lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Accept: "))
        .unwrap_or("")
        .to_string()
}

async fn stream_traffic(upgraded: hyper::upgrade::Upgraded, traffic: crate::common::SharedTraffic) {
    let mut ws = websocket::Websocket::new(upgraded);
    let mut previous = traffic.snapshot();
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
        let current = traffic.snapshot();
        let payload = serde_json::json!({
            "up": current.up.saturating_sub(previous.up),
            "down": current.down.saturating_sub(previous.down),
            "upTotal": current.up,
            "downTotal": current.down,
        });
        if ws.send_text(&payload.to_string()).await.is_err() {
            break;
        }
        // Keep reading so we notice a client close frame.
        match tokio::time::timeout(std::time::Duration::from_millis(100), ws.recv_frame()).await {
            Ok(Ok(None)) | Ok(Err(_)) | Err(_) => {}
            Ok(Ok(Some(_))) => {}
        }
        previous = current;
    }
}
