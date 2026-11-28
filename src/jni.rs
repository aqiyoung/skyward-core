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
struct TunSession {
    cancel: Arc<tokio::sync::Notify>,
    task: tokio::task::JoinHandle<()>,
}

static TUN_SESSION: Mutex<Option<TunSession>> = Mutex::new(None);
static TUN_HANDLER: Mutex<Option<GlobalRef>> = Mutex::new(None);
static TOKIO_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static TUN_WAKE: OnceLock<Arc<tokio::sync::Notify>> = OnceLock::new();

/// Ask Android's VpnService to keep a socket out of the VPN tunnel. Every
/// outbound connection the core makes must go through this, otherwise the
/// kernel routes it back into our own TUN and nothing can connect.
pub fn protect_fd(fd: i32) -> bool {
    let handler = TUN_HANDLER.lock().unwrap();
    let Some(handler) = handler.as_ref() else {
        protect_diag("no protect handler registered");
        return false;
    };
    let Some(vm) = JAVA_VM.get() else {
        protect_diag("no JavaVM for protect");
        return false;
    };
    let Ok(mut env) = vm.attach_current_thread() else {
        protect_diag("attach_current_thread failed for protect");
        return false;
    };
    let result = env.call_method(handler.as_obj(), "protect", "(I)Z", &[JValue::Int(fd)]);
    match result {
        Ok(v) => {
            let ok = v.z().unwrap_or(false);
            if !ok {
                protect_diag(&format!("protect({}) returned false", fd));
            }
            ok
        }
        Err(e) => {
            protect_diag(&format!("protect({}) failed: {}", fd, e));
            false
        }
    }
}

/// Report protect() problems, but only the first few so the log stays readable.
fn protect_diag(message: &str) {
    static COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    if COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 10 {
        emit_log_event(&format!("[rust-core] protect: {}", message));
    }
}

pub const IPPROTO_TCP: i32 = 6;
pub const IPPROTO_UDP: i32 = 17;

/// Attribute a flow to its owning Android package, mirroring the Go core's
/// TunHandler.resolveUid -> resolvePackage path. Called at TUN packet time
/// (before dialling) while the owning socket is still live; the uid lookup
/// would fail if we waited until the connection is registered afterwards.
///
/// Returns None off-Android or when the host did not supply a resolver, so
/// desktop behaviour is unchanged. Any Java exception is cleared here: an
/// uncleared pending exception would crash the next JNI call.
pub fn resolve_app_package(protocol: i32, source: &str, target: &str) -> Option<String> {
    static FAIL_COUNT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let fail = |why: &str| {
        if FAIL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) < 10 {
            emit_log_event(&format!("[rust-core] resolve_package: {}", why));
        }
        None
    };

    let handler = TUN_HANDLER.lock().ok()?.as_ref()?.clone();
    let vm = vm()?;
    let mut env = match vm.attach_current_thread() {
        Ok(e) => e,
        Err(_) => return fail("attach_current_thread failed"),
    };

    let src = match env.new_string(source) {
        Ok(s) => s,
        Err(_) => return fail("new_string(source) failed"),
    };
    let dst = match env.new_string(target) {
        Ok(s) => s,
        Err(_) => return fail("new_string(target) failed"),
    };
    let uid_result = env.call_method(
        handler.as_obj(),
        "resolveUid",
        "(ILjava/lang/String;Ljava/lang/String;)I",
        &[
            JValue::Int(protocol),
            JValue::Object(src.as_ref()),
            JValue::Object(dst.as_ref()),
        ],
    );
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return fail("resolveUid threw");
    }
    let uid = match uid_result.and_then(|v| v.i()) {
        Ok(uid) => uid,
        Err(_) => return fail("resolveUid failed"),
    };
    if uid < 0 {
        return None;
    }

    let name_result = env.call_method(
        handler.as_obj(),
        "resolvePackage",
        "(I)Ljava/lang/String;",
        &[JValue::Int(uid)],
    );
    if env.exception_check().unwrap_or(false) {
        let _ = env.exception_clear();
        return fail("resolvePackage threw");
    }
    let obj = match name_result.and_then(|v| v.l()) {
        Ok(o) => o,
        Err(_) => return fail("resolvePackage failed"),
    };
    if obj.is_null() {
        return None;
    }
    let name = java_string(&mut env, &JString::from(obj));
    if name.is_empty() {
        return None;
    }
    Some(name)
}

pub(crate) fn tokio_runtime() -> Option<&'static tokio::runtime::Runtime> {
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
/// switch. The data fields must match the App's Log model: `LogLevel`,
/// `Payload` and a `dateTime` key (the Dart parser ignores its value).
pub fn emit_log_event(message: &str) {
    emit_event_json(&serde_json::json!({
        "type": "log",
        "data": { "LogLevel": "info", "Payload": message, "dateTime": "" }
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
    // The App decodes native bytes as a CoreMethodCall, then reads
    // `arguments` as a list of events. Wrap the bare event accordingly:
    //   {"method":"message","arguments":[ <event> ]}
    let envelope = match serde_json::from_str::<serde_json::Value>(event) {
        Ok(ev) => serde_json::json!({ "method": "message", "arguments": [ev] }).to_string(),
        Err(_) => event.to_string(),
    };
    let result = vm.attach_current_thread().and_then(|mut env| {
        let bytes = env.byte_array_from_slice(envelope.as_bytes())?;
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
    // Flutter delivers core calls on one serial queue. Like the Go bridge,
    // return immediately for network probes so polling can continue.
    if serde_json::from_str::<mobile::MethodCall>(&input)
        .is_ok_and(|call| matches!(call.method.as_str(), "asyncTestDelay" | "probe" | "serviceCheck" | "outboundIp"))
    {
        if let (Some(vm), Some(rt)) = (vm(), tokio_runtime()) {
            if let Ok(handler) = env.new_global_ref(&handler) {
                rt.spawn_blocking(move || {
                    let result = mobile::invoke(input.as_bytes());
                    if let Ok(mut env) = vm.attach_current_thread() {
                        if let Err(e) = fire_result(&mut env, handler.as_obj(), &result) {
                            tracing::warn!("async invokeMethod callback: {}", e);
                            let _ = env.exception_clear();
                        }
                    }
                });
                return;
            }
        }
    }
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
    init_params: JString,
    setup_params: JString,
    handler: JObject,
) {
    let init = java_string(&mut env, &init_params);
    let setup = java_string(&mut env, &setup_params);
    let result = mobile::android_quick_setup(&init, &setup);
    if let Err(e) = fire_result(&mut env, &handler, result.as_bytes()) {
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
    let mut session = TUN_SESSION.lock().unwrap();
    if let Some(previous) = session.take() {
        if let Some(rt) = tokio_runtime() {
            finish_tun(rt, previous);
        }
    }
    *TUN_HANDLER.lock().unwrap() = None;
}

fn finish_tun(rt: &tokio::runtime::Runtime, session: TunSession) {
    session.cancel.notify_one();
    if let Err(error) = rt.block_on(session.task) {
        tracing::warn!(%error, "TUN task failed while stopping");
    }
}

#[no_mangle]
pub extern "system" fn Java_com_follow_clash_core_mobile_Mobile_startTun(
    mut env: JNIEnv,
    _class: JObject,
    fd: jint,
    handler: JObject,
    stack: JString,
    address: JString,
    dns: JString,
    options: JString,
) -> jboolean {
    let stack_text = java_string(&mut env, &stack);
    let address_text = java_string(&mut env, &address);
    let dns_text = java_string(&mut env, &dns);
    let options_text = java_string(&mut env, &options);

    let mut session = TUN_SESSION.lock().unwrap();
    let Some(rt) = tokio_runtime() else { return JNI_FALSE };
    let Some(engine) = rt.block_on(crate::runtime_state::engine()) else {
        emit_log_event("[rust-core] startTun: no profile has been loaded");
        return JNI_FALSE;
    };
    let handler = match env.new_global_ref(handler) {
        Ok(global) => global,
        Err(e) => {
            emit_log_event(&format!("[rust-core] unable to retain protect handler: {}", e));
            return JNI_FALSE;
        }
    };

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
            let wake = TUN_WAKE
                .get_or_init(|| Arc::new(tokio::sync::Notify::new()))
                .clone();
            if let Some(previous) = session.take() {
                finish_tun(rt, previous);
            }
            *TUN_HANDLER.lock().unwrap() = Some(handler);
            let cancel = Arc::new(tokio::sync::Notify::new());
            let stop = cancel.clone();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let task = rt.spawn(async move {
                crate::tun::runtime::run(device, config, engine, wake, stop, Some(ready_tx)).await;
            });
            // The App establishes() the VPN before calling startTun, so DNS may
            // already be queued on the fd. Wait until the reader is live before
            // reporting success, otherwise the first DNS burst is dropped and
            // the network stays down until the resolver retries.
            let _ = rt.block_on(async {
                tokio::time::timeout(std::time::Duration::from_secs(2), ready_rx).await
            });
            *session = Some(TunSession { cancel, task });
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

fn traffic_json(total: bool) -> String {
    serde_json::json!(crate::runtime_state::traffic_snapshot(total)).to_string()
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
    fn stopping_tun_waits_for_the_task_to_release_its_resources() {
        let rt = tokio_runtime().unwrap();
        let cancel = Arc::new(tokio::sync::Notify::new());
        let stop = cancel.clone();
        let resource = Arc::new(());
        let task_resource = resource.clone();
        let task = rt.spawn(async move {
            stop.notified().await;
            tokio::task::yield_now().await;
            drop(task_resource);
        });
        finish_tun(rt, TunSession { cancel, task });
        assert_eq!(Arc::strong_count(&resource), 1);
    }

    #[test]
    fn jni_true_false_constants() {
        assert_eq!(JNI_TRUE, 1);
        assert_eq!(JNI_FALSE, 0);
    }
}
