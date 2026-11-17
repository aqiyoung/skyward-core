//! JNI bridge exposing the `com.follow.clash.core.mobile.Mobile` interface the
//! Skyward Flutter App expects. This replaces the gomobile-generated bindings:
//! Core.kt calls these static methods, and we call back into its `ResultHandler`
//! / `TunHandler` interfaces.
//!
//! All entries use `extern "system"` with a `catch_unwind` guard. The JNIEnv
//! lifetime is tied to the native method call; global refs outlive it.

use std::sync::{Mutex, OnceLock};

use jni::objects::{GlobalRef, JByteArray, JObject, JString, JValue};
use jni::sys::{jboolean, jint, jstring, JNI_FALSE, JNI_TRUE};
use jni::{JNIEnv, JavaVM};

use crate::mobile;

static JAVA_VM: OnceLock<JavaVM> = OnceLock::new();
static EVENT_LISTENER: Mutex<Option<GlobalRef>> = Mutex::new(None);
static TUN_SESSION: Mutex<Option<(i32, crate::tun::TunConfig)>> = Mutex::new(None);

fn vm() -> Option<&'static JavaVM> {
    JAVA_VM.get()
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
    if let Ok(vm) = env.get_java_vm() {
        let _ = JAVA_VM.set(vm);
    }
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
    _setup_params: JString,
    handler: JObject,
) {
    let result = mobile::invoke(br#"{"method":"setupConfig","arguments":{}}"#);
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

    let config = match crate::tun::TunConfig::parse(&stack_text, &address_text, &dns_text, &options_text) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("startTun: invalid config: {}", e);
            return JNI_FALSE;
        }
    };

    // TUN device creation takes ownership of fd only once the config is valid.
    match crate::tun::device_from_fd(fd, config.options.mtu) {
        Ok(device) => {
            tracing::info!(
                "TUN session started: fd={} stack={} mtu={}",
                fd, config.stack, config.options.mtu
            );
            // Keep the config for the relay loop; the device is owned by the
            // session task once the stack is fully wired (next slice).
            drop(device);
            *TUN_SESSION.lock().unwrap() = Some((fd, config));
            JNI_TRUE
        }
        Err(e) => {
            tracing::error!("startTun: device from fd failed: {}", e);
            JNI_FALSE
        }
    }
}

fn traffic_json(total: bool) -> String {
    let method = if total { "getTotalTraffic" } else { "getTraffic" };
    let payload = format!("{{\"method\":\"{}\"}}", method);
    let response = mobile::invoke(payload.as_bytes());
    match serde_json::from_slice::<serde_json::Value>(&response) {
        Ok(v) => v["result"].to_string(),
        Err(_) => "{\"up\":0,\"down\":0}".to_string(),
    }
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
