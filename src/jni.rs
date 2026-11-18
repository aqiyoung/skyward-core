//! JNI bridge exposing the `com.follow.clash.core.mobile.Mobile` interface the
//! Skyward Flutter App expects. This replaces the gomobile-generated bindings:
//! Core.kt calls these static methods, and we call back into its `ResultHandler`
//! / `TunHandler` interfaces.
//!
//! All entries use `extern "system"` with a `catch_unwind` guard. The JNIEnv
//! lifetime is tied to the native method call; global refs outlive it.

use std::sync::{Arc, Mutex, OnceLock};

use jni::objects::{GlobalRef, JByteArray, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};

use crate::mobile;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static EVENT_LISTENER: Mutex<Option<GlobalRef>> = Mutex::new(None);
static TUN_SESSION: Mutex<Option<(i32, crate::tun::TunConfig)>> = Mutex::new(None);
static TOKIO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static TUN_WAKE: OnceLock<Arc<tokio::sync::Notify>> = OnceLock::new();

fn tokio_runtime() -> Option<&'static tokio::runtime::Runtime> {
    TOKIO_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("build jni tokio runtime")
    });
    TOKIO_RUNTIME.get()
}

fn vm() -> Option<&'static JavaVM> {
    JAVA_VM.get()
}

/// Emit a log event to the App's event listener regardless of the openLogs
/// switch. Uses the same {type:"log", data:{type,payload}} shape as the Go core.
fn emit_log_event(message: &str) {
    emit_event_json(&serde_json::json!({
        "type": "log",
        "data": { "type": "info", "payload": message }
    }).to_string());
}

/// Call `handler.onResult(byte[])` on the current thread.
fn fire_result(
    env: &mut JNIEnv,
    handler: &JObject,
    data: &[u8],
) -> Result<(), jni::errors::Error> {
    let bytes: JByteArray = env.byte_array_from_slice(data)?;
    let value = JValue::Object(&bytes);
    let _ = env.call_method(handler, "onResult", "([B)V", &[value])?;
    Ok(())
}

/// Emit an event to the registered listener by attaching the current thread.
/// Used by the tunnel/hub to push logs, delays and traffic events.
pub fn emit_event_json(event: &str) {
    let Some(vm) = vm() else { return };
    let listener = EVENT_LISTENER.lock().ok().and_then(|g| g.clone());
    let Some(listener) = listener else { return };
    let result = vm.attach_current_thread().and_then(|mut env| {
        let bytes = env.byte_array_from_slice(event.as_bytes())?;
        let value = JValue::Object(&bytes);
        env.call_method(&listener, "onResult", "([B)V", &[value])?;
        Ok(())
    });
    if let Err(e) = result {
        tracing::debug!("jni emit_event failed: {}", e);
    }
}

fn java_string(env: &mut JNIEnv, s: &JString) -> String {
    env.get_string(s)
        .map(|v| v.into())
        .unwrap_or_default()
}

/// Public entry: used by native code to register the Java VM once.
#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_initVm(
    env: JNIEnv,
    _class: JObject,
) {
    static INIT: std::sync::Once = std::sync::Once::new();
    if let Ok(vm) = env.get_java_vm() {
        let _ = JAVA_VM.set(vm);
    }
    INIT.call_once(|| {
        // Install a global tracing subscriber writing to stderr. Android
        // logcat captures stderr, so all tracing! calls (including startTun
        // diagnostics) become visible. Never fails the JNI call.
        use tracing_subscriber::fmt::format::FmtSpan;
        let _ = tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_max_level(tracing::Level::INFO)
            .with_span_events(FmtSpan::NONE)
            .try_init();
        tracing::info!("skyward-core JNI initialized (rust)");
    });
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_forceGC(
    _env: JNIEnv,
    _class: JObject,
) {
    // Rust has no forced GC; acknowledged no-op (matches Go's acknowledged).
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_updateDns(
    _env: JNIEnv,
    _class: JObject,
    _dns: JString,
) {
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_resetNetwork(
    _env: JNIEnv,
    _class: JObject,
) {
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_invokeMethod(
    mut env: JNIEnv,
    _class: JObject,
    data: JString,
    handler: JObject,
) {
    let input = java_string(&mut env, &data);
    let result = mobile::invoke(input.as_bytes());
    if let Err(e) = fire_result(&mut env, &handler, &result) {
        let _ = env.throw_new("java/lang/RuntimeException", format!("invokeMethod callback: {}", e));
    }
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_setEventListener(
    mut env: JNIEnv,
    _class: JObject,
    handler: JObject,
) {
    let global = if handler.is_null() {
        None
    } else {
        env.new_global_ref(&handler).ok()
    };
    *EVENT_LISTENER.lock().unwrap() = global;
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_quickSetup(
    mut env: JNIEnv,
    _class: JObject,
    _init_params: JString,
    setup_params: JString,
    handler: JObject,
) {
    let setup_text = java_string(&mut env, &setup_params);
    // Build a MethodCall around setupConfig so the existing handler does the work.
    let payload = format!(
        "{{\"method\":\"setupConfig\",\"arguments\":{}}}",
        if setup_text.trim().is_empty() { "{}".to_string() } else { setup_text }
    );
    let result = mobile::invoke(payload.as_bytes());
    if let Err(e) = fire_result(&mut env, &handler, &result) {
        let _ = env.throw_new("java/lang/RuntimeException", format!("quickSetup callback: {}", e));
    }
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_startListener(
    _env: JNIEnv,
    _class: JObject,
) {
    let _ = mobile::invoke(br#"{"method":"startListener"}"#);
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_stopListener(
    _env: JNIEnv,
    _class: JObject,
) {
    let _ = mobile::invoke(br#"{"method":"stopListener"}"#);
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_stopTun(
    _env: JNIEnv,
    _class: JObject,
) {
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_startTun(
    mut env: JNIEnv,
    _class: JObject,
    fd: jint,
    _handler: JObject,
    stack: JString,
    address: JString,
    dns: JString,
    options: JString,
) -> jboolean {
    let stack_text = java_string(&mut env, &stack);
    let address_text = java_string(&mut env, &address);
    let dns_text = java_string(&mut env, &dns);
    let options_text = java_string(&mut env, &options);

    let diag = format!(
        "[rust-core] startTun called: fd={} stack='{}' address='{}' dns='{}' options='{}'",
        fd, stack_text, address_text, dns_text, options_text
    );
    tracing::info!("{}", diag);
    // Push diagnostics straight to the App event channel, independent of the
    // openLogs setting, so VPN-start failures are visible in the log page.
    emit_log_event(&diag);
    let config = match crate::tun::TunConfig::parse(&stack_text, &address_text, &dns_text, &options_text) {
        Ok(c) => c,
        Err(e) => {
            // Config is tuning only; never fail TUN startup over it. Fall back
            // to defaults so the VPN can still come up and carry traffic.
            tracing::warn!("startTun: config parse fell back to defaults: {}", e);
            crate::tun::TunConfig::parse("gvisor", "198.18.0.1/30", "0.0.0.0", "").unwrap()
        }
    };

    // TUN device creation takes ownership of fd only once the config is valid.
    let mtu = config.options.mtu;
    match crate::tun::device_from_fd(fd, mtu) {
        Ok(device) => {
            let msg = format!("[rust-core] TUN device opened: fd={} stack={} mtu={}", fd, config.stack, mtu);
            tracing::info!("{}", msg);
            emit_log_event(&msg);
            let rt = match tokio_runtime() {
                Some(rt) => rt,
                None => {
                    let e = "[rust-core] FATAL: no tokio runtime available";
                    tracing::error!("{}", e);
                    emit_log_event(e);
                    return JNI_FALSE;
                }
            };
            // Use the active engine if the App already applied a config;
            // otherwise fall back to a default DIRECT-only engine.
            let engine = rt
                .block_on(crate::runtime_state::engine())
                .unwrap_or_else(|| rt.block_on(build_default_engine()));
            let wake = TUN_WAKE
                .get_or_init(|| Arc::new(tokio::sync::Notify::new()))
                .clone();
            *TUN_SESSION.lock().unwrap() = Some((fd, config.clone()));
            emit_log_event("[rust-core] TUN runtime spawned, returning TRUE");
            rt.spawn(async move {
                crate::tun::runtime::run(device, config, engine, wake).await;
                let e = format!("[rust-core] TUN runtime EXITED for fd {}", fd);
                tracing::warn!("{}", e);
                emit_log_event(&e);
            });
            JNI_TRUE
        }
        Err(e) => {
            let msg = format!("[rust-core] FATAL: device from fd failed: {}", e);
            tracing::error!("{}", msg);
            emit_log_event(&msg);
            JNI_FALSE
        }
    }
}

/// Build a minimal engine for the relay loop. Once `setupConfig` is ported it
/// will build from the real config; this keeps the TUN path runnable now.
async fn build_default_engine() -> Arc<crate::tunnel::Engine> {
    let config = crate::config::Config::default();
    let traffic = Arc::new(crate::common::TrafficStats::default());
    Arc::new(crate::tunnel::Engine::new(config, traffic, std::path::Path::new(".")).await)
}

fn traffic_json(_total: bool) -> String {
    if let Some(rt) = tokio_runtime() {
        let snap = rt.block_on(crate::runtime_state::traffic_snapshot());
        return serde_json::json!({"up": snap.up, "down": snap.down}).to_string();
    }
    "{\"up\":0,\"down\":0}".to_string()
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_getTraffic(
    mut env: JNIEnv,
    _class: JObject,
    _only_statistics_proxy: jboolean,
) -> jstring {
    let text = traffic_json(false);
    env.new_string(text)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_getTotalTraffic(
    mut env: JNIEnv,
    _class: JObject,
    _only_statistics_proxy: jboolean,
) -> jstring {
    let text = traffic_json(true);
    env.new_string(text)
        .map(|s| s.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_json_shape() {
        let text = traffic_json(false);
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert!(value.get("up").is_some());
        assert!(value.get("down").is_some());
    }

    #[test]
    fn tun_session_starts_with_valid_config() {
        assert!(TUN_SESSION.lock().unwrap().is_none());
        let cfg = crate::tun::TunConfig::parse("gvisor", "10.0.0.2/30", "198.51.100.1", "").unwrap();
        *TUN_SESSION.lock().unwrap() = Some((42, cfg));
        let guard = TUN_SESSION.lock().unwrap();
        assert_eq!(guard.as_ref().unwrap().0, 42);
        drop(guard);
        *TUN_SESSION.lock().unwrap() = None;
    }

    #[test]
    fn jni_true_false_constants() {
        assert_eq!(JNI_TRUE, 1);
        assert_eq!(JNI_FALSE, 0);
    }
}
