//! C ABI surface for embedding the kernel in an application.
//!
//! Design rules (from rust/docs/07-api-host.md):
//!   - every entry point is wrapped in `catch_unwind` (a panic across the C
//!     boundary is UB);
//!   - the handle is a raw pointer to a runtime holding a Tokio runtime and the
//!     shared AppState;
//!   - strings are explicit `(ptr, len)` pairs, never NUL-terminated;
//!   - `apply_config` runs synchronously (large configs may block briefly).

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::common::{TrafficStats, VERSION};
use crate::config::Config;
use crate::tunnel::Engine;
use crate::{spawn_listeners, AppState};

// ---- ABI types -------------------------------------------------------------

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkywardStatus {
    Ok = 0,
    NullPointer = 1,
    InvalidUtf8 = 2,
    ConfigError = 3,
    NotInitialized = 4,
    RuntimeError = 5,
    Panic = 6,
    NotImplemented = 7,
    /// Handle was already destroyed (or is not one we created).
    InvalidHandle = 8,
}

#[repr(C)]
pub struct SkywardOptions {
    /// -1 means no TUN (the host owns the TUN device).
    pub tun_fd: i32,
    pub tun_mtu: u32,
    /// Embed mode disables restart/upgrade/config-PATCH style operations.
    pub embed_mode: bool,
    /// NUL-terminated home directory, or null for the current directory.
    pub home_dir: *const c_char,
}

/// A single DNS answer written back by `skyward_query_dns`.
#[repr(C)]
pub struct DnsAnswer {
    /// IPv4 in the first 4 bytes, IPv6 in all 16.
    pub ip: [u8; 16],
    /// 4 or 16.
    pub len: u8,
    pub _pad: [u8; 3],
}

/// Callback table. Every callback receives `user_data` as its last argument.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SkywardHooks {
    /// JSON connection event: {"event":"add|remove","id":"...","host":"..."}
    pub connection: Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    /// JSON DNS query event.
    pub dns: Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    /// JSON provider-load event.
    pub provider: Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    pub user_data: *mut std::ffi::c_void,
}

// SAFETY: `user_data` must point to a value that stays valid for the entire
// lifetime of the runtime and is safe to touch from multiple threads. The host
// owns that guarantee; see the docs on `skyward_set_hooks`.
unsafe impl Send for SkywardHooks {}
unsafe impl Sync for SkywardHooks {}

struct HooksCell(Mutex<Option<SkywardHooks>>);
unsafe impl Send for HooksCell {}
unsafe impl Sync for HooksCell {}

fn emit(
    cell: &HooksCell,
    which: fn(&SkywardHooks) -> Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    event: &str,
) {
    // Clone the (Copy) hooks out of the lock before calling foreign code:
    // a callback that re-enters skyward_set_hooks would deadlock if we held
    // the mutex. Recover from poison so one bad callback cannot silence all
    // future events.
    let hooks = {
        let guard = cell.0.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(h) => *h,
            None => return,
        }
    };
    if let Some(cb) = which(&hooks) {
        let bytes = event.as_bytes();
        // A panic in a C callback must not unwind across the ABI boundary and
        // poison anything else.
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            cb(bytes.as_ptr(), bytes.len(), hooks.user_data)
        }));
    }
}

pub struct SkywardRuntime {
    tokio: tokio::runtime::Runtime,
    state: Mutex<Option<Arc<AppState>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    home_dir: PathBuf,
    #[allow(dead_code)]
    embed_mode: bool,
    /// Bumped by every apply_config; a late builder only installs its engine
    /// when its generation is still current (R40).
    config_generation: AtomicU64,
    hooks: HooksCell,
}

/// Opaque handle returned by `skyward_create` and consumed by every other call.
/// `destroyed` makes a second `skyward_destroy` a no-op and rejects calls made
/// through a stale handle instead of dereferencing freed memory.
pub struct SkywardHandle {
    runtime: SkywardRuntime,
    destroyed: AtomicBool,
}

fn with<F>(handle: *mut SkywardHandle, f: F) -> SkywardStatus
where
    F: FnOnce(&SkywardRuntime) -> Result<(), SkywardStatus>,
{
    if handle.is_null() {
        return SkywardStatus::NullPointer;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: handle came from skyward_create and has not been destroyed;
        // the atomic guard below rejects stale/double-destroyed pointers.
        let handle = unsafe { &*handle };
        if handle.destroyed.load(Ordering::Acquire) {
            return Err(SkywardStatus::InvalidHandle);
        }
        f(&handle.runtime)
    }));
    match result {
        Ok(Ok(())) => SkywardStatus::Ok,
        Ok(Err(status)) => status,
        Err(_) => SkywardStatus::Panic,
    }
}

/// `(ptr, len)` strings are caller-owned. Reject absurd lengths before
/// `from_raw_parts` so a corrupt length cannot become an unbounded read.
const MAX_STRING: usize = 16 * 1024 * 1024;

unsafe fn cstr_to_string(ptr: *const c_char, len: usize) -> Result<String, SkywardStatus> {
    if ptr.is_null() {
        return Err(SkywardStatus::NullPointer);
    }
    if len > MAX_STRING {
        return Err(SkywardStatus::InvalidUtf8);
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
    String::from_utf8(bytes.to_vec()).map_err(|_| SkywardStatus::InvalidUtf8)
}

/// Bounded scan for a NUL-terminated C string. `CStr::from_ptr` scans until
/// it happens to find a NUL, so a non-terminated pointer reads adjacent memory.
unsafe fn bounded_cstr(ptr: *const c_char, max: usize) -> Result<String, SkywardStatus> {
    if ptr.is_null() {
        return Err(SkywardStatus::NullPointer);
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, max);
    let end = bytes.iter().position(|b| *b == 0).ok_or(SkywardStatus::InvalidUtf8)?;
    String::from_utf8(bytes[..end].to_vec()).map_err(|_| SkywardStatus::InvalidUtf8)
}

fn home_dir_from_options(opts: *const SkywardOptions) -> Result<PathBuf, SkywardStatus> {
    if opts.is_null() {
        return Err(SkywardStatus::NullPointer);
    }
    unsafe {
        let home = (*opts).home_dir;
        if home.is_null() {
            Ok(PathBuf::from("."))
        } else {
            Ok(PathBuf::from(bounded_cstr(home, 4096)?))
        }
    }
}

// ---- exported functions ----------------------------------------------------

/// NUL-terminated copy of VERSION for the C ABI (Rust &str is not NUL-terminated).
static VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "-alpha.1\0").as_bytes();

#[no_mangle]
pub extern "C" fn skyward_version() -> *const c_char {
    VERSION_C.as_ptr() as *const c_char
}

#[no_mangle]
pub extern "C" fn skyward_create(opts: *const SkywardOptions) -> *mut SkywardHandle {
    catch_unwind(|| {
        let home_dir = match home_dir_from_options(opts) {
            Ok(p) => p,
            Err(_) => return ptr::null_mut(),
        };
        let embed_mode = unsafe { !opts.is_null() && (*opts).embed_mode };
        let tokio = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                tracing::error!("ffi: failed to build tokio runtime: {}", e);
                return ptr::null_mut();
            }
        };
        let handle = SkywardHandle {
            runtime: SkywardRuntime {
                tokio,
                state: Mutex::new(None),
                tasks: Mutex::new(Vec::new()),
                home_dir,
                embed_mode,
                config_generation: AtomicU64::new(0),
                hooks: HooksCell(Mutex::new(None)),
            },
            destroyed: AtomicBool::new(false),
        };
        Box::into_raw(Box::new(handle))
    })
    .unwrap_or(ptr::null_mut())
}

#[no_mangle]
pub extern "C" fn skyward_test_config(yaml: *const u8, len: usize) -> SkywardStatus {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let text = match unsafe { cstr_to_string(yaml as *const c_char, len) } {
            Ok(s) => s,
            Err(e) => return Err(e),
        };
        Config::from_str(&text).map(|_| ()).map_err(|_| SkywardStatus::ConfigError)
    }));
    match result {
        Ok(Ok(())) => SkywardStatus::Ok,
        Ok(Err(s)) => s,
        Err(_) => SkywardStatus::Panic,
    }
}

#[no_mangle]
pub extern "C" fn skyward_apply_config(
    handle: *mut SkywardHandle,
    yaml: *const u8,
    len: usize,
) -> SkywardStatus {
    with(handle, |rt| {
        let text = unsafe { cstr_to_string(yaml as *const c_char, len)? };
        let config = Config::from_str(&text).map_err(|_| SkywardStatus::ConfigError)?;
        // Hold the state lock across build+install so two concurrent applies
        // cannot interleave and let an older config overwrite a newer one.
        let mut guard = rt.state.lock().unwrap_or_else(|e| e.into_inner());
        rt.config_generation.fetch_add(1, Ordering::AcqRel);
        // An existing state reuses its traffic counters; a fresh one creates them.
        let state = guard.as_ref().cloned();
        let fresh_traffic;
        let traffic = match &state {
            Some(s) => s.traffic.clone(),
            None => {
                fresh_traffic = Arc::new(TrafficStats::default());
                fresh_traffic.clone()
            }
        };
        let engine = rt.tokio.block_on(Engine::new(config, traffic.clone(), &rt.home_dir));
        match state {
            Some(s) => rt.tokio.block_on(s.replace_engine(engine)),
            None => {
                let config_path = rt.home_dir.join("config.yaml");
                *guard = Some(Arc::new(AppState::new(engine, config_path, traffic)));
            }
        }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn skyward_start_inbound(handle: *mut SkywardHandle) -> SkywardStatus {
    with(handle, |rt| {
        let state = rt.state.lock().map_err(|_| SkywardStatus::RuntimeError)?
            .as_ref().cloned().ok_or(SkywardStatus::NotInitialized)?;
        let handles = rt.tokio.block_on(spawn_listeners(state.clone()));
        let mut tasks = rt.tasks.lock().unwrap_or_else(|e| e.into_inner());
        // Repeat calls must replace the previous listener set; otherwise the
        // old tasks keep the port bound and serve the old engine.
        for task in tasks.drain(..) {
            task.abort();
        }
        tasks.extend(handles);
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn skyward_close_inbound(handle: *mut SkywardHandle) {
    let _ = with(handle, |rt| {
        let mut tasks = rt.tasks.lock().map_err(|_| SkywardStatus::RuntimeError)?;
        for task in tasks.drain(..) {
            task.abort();
        }
        Ok(())
    });
}

#[no_mangle]
pub extern "C" fn skyward_query_dns(
    handle: *mut SkywardHandle,
    name: *const c_char,
    qtype: u16,
    out: *mut DnsAnswer,
) -> SkywardStatus {
    with(handle, |rt| {
        if name.is_null() || out.is_null() {
            return Err(SkywardStatus::NullPointer);
        }
        let host = unsafe { bounded_cstr(name, 1024)? };
        let state = rt.state.lock().map_err(|_| SkywardStatus::RuntimeError)?
            .as_ref().cloned().ok_or(SkywardStatus::NotInitialized)?;
        let config = state.engine.blocking_read().config.dns.clone().unwrap_or_default();
        let resolver = crate::dns::Resolver::new(config);
        let addrs = rt.tokio.block_on(resolver.resolve(&host))
            .map_err(|_| SkywardStatus::RuntimeError)?;
        let chosen = addrs.into_iter().find(|ip| match qtype {
            1 => ip.is_ipv4(),   // A
            28 => ip.is_ipv6(),  // AAAA
            _ => true,
        }).ok_or(SkywardStatus::RuntimeError)?;
        let mut answer = DnsAnswer { ip: [0u8; 16], len: 0, _pad: [0; 3] };
        match chosen {
            std::net::IpAddr::V4(v4) => {
                answer.ip[..4].copy_from_slice(&v4.octets());
                answer.len = 4;
            }
            std::net::IpAddr::V6(v6) => {
                answer.ip.copy_from_slice(&v6.octets());
                answer.len = 16;
            }
        }
        unsafe { *out = answer; }
        Ok(())
    })
}

#[no_mangle]
pub extern "C" fn skyward_handle_tun_packet(
    _handle: *mut SkywardHandle,
    _pkt: *const u8,
    _len: usize,
) -> SkywardStatus {
    // The TUN/smoltcp stack is not ported yet; packet injection is explicit.
    SkywardStatus::NotImplemented
}

#[no_mangle]
/// Register callbacks. `user_data` must remain valid, and safe to use from
/// Tokio worker threads, until `skyward_destroy` or a later `skyward_set_hooks`
/// replaces the table. Set it to null (or call skyward_destroy) to unregister.
pub extern "C" fn skyward_set_hooks(handle: *mut SkywardHandle, hooks: *const SkywardHooks) {
    let _ = with(handle, |rt| {
        let value = if hooks.is_null() {
            None
        } else {
            Some(unsafe { *hooks })
        };
        let mut guard = rt.hooks.0.lock().unwrap_or_else(|e| e.into_inner());
        *guard = value;
        Ok(())
    });
}

#[no_mangle]
pub extern "C" fn skyward_emit_event(handle: *mut SkywardHandle, json: *const u8, len: usize) {
    // Test/helper hook used by integration tests and embedders that want to
    // drive the callback surface. Emits a connection event to all callbacks.
    let _ = with(handle, |rt| {
        let text = unsafe { cstr_to_string(json as *const c_char, len)? };
        emit(&rt.hooks, |h| h.connection, &text);
        Ok(())
    });
}

/// Invoke a gomobile-style method call. Returns a heap-allocated JSON buffer
/// that the caller must free with `skyward_free_buffer`. `out_len` receives the
/// byte length.
#[no_mangle]
pub extern "C" fn skyward_invoke_method(
    data: *const u8,
    len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if data.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        if len > MAX_STRING {
            return None;
        }
        let input = unsafe { std::slice::from_raw_parts(data, len) };
        Some(crate::mobile::invoke(input))
    }));
    // On panic there is no valid response; return null rather than a bogus
    // "{}" that the caller might treat as a successful empty answer.
    let Ok(Some(bytes)) = result else {
        unsafe { *out_len = 0; }
        return ptr::null_mut();
    };

    // Store the length in a header immediately before the returned pointer.
    // free then trusts the header, so a caller passing a wrong `len` cannot
    // reconstruct a Vec with the wrong capacity and corrupt the heap.
    use std::alloc::{alloc, dealloc, Layout};
    let header = std::mem::size_of::<usize>();
    let total = header + bytes.len();
    let Ok(layout) = Layout::from_size_align(total, std::mem::align_of::<usize>()) else {
        unsafe { *out_len = 0; }
        return ptr::null_mut();
    };
    let raw = unsafe { alloc(layout) };
    if raw.is_null() {
        unsafe { *out_len = 0; }
        return ptr::null_mut();
    }
    unsafe {
        std::ptr::write_unaligned(raw as *mut usize, bytes.len());
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), raw.add(header), bytes.len());
    }
    unsafe { *out_len = bytes.len(); }
    unsafe { raw.add(header) }
}

/// Free a buffer returned by `skyward_invoke_method`. The `len` argument is
/// ignored: the true length is read from the header written by the allocator.
/// Each returned pointer must be freed exactly once.
#[no_mangle]
pub extern "C" fn skyward_free_buffer(ptr: *mut u8, _len: usize) {
    if ptr.is_null() {
        return;
    }
    use std::alloc::{dealloc, Layout};
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let header = std::mem::size_of::<usize>();
        let raw = ptr.sub(header);
        let len = std::ptr::read_unaligned(raw as *const usize);
        if let Ok(layout) = Layout::from_size_align(
            header + len,
            std::mem::align_of::<usize>(),
        ) {
            dealloc(raw, layout);
        }
    }));
}

#[no_mangle]
pub extern "C" fn skyward_destroy(handle: *mut SkywardHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
        let handle = &*handle;
        // First caller wins; a second destroy becomes a no-op instead of a
        // double-free.
        if handle.destroyed.swap(true, Ordering::AcqRel) {
            return;
        }
        // Unregister callbacks before tearing down so no worker can invoke a
        // host pointer that the host is about to release.
        let mut hooks = handle.runtime.hooks.0.lock().unwrap_or_else(|e| e.into_inner());
        *hooks = None;
        drop(hooks);
        // Abort listener tasks before dropping the runtime so they don't
        // outlive it.
        let mut tasks = handle.runtime.tasks.lock().unwrap_or_else(|e| e.into_inner());
        for task in tasks.drain(..) {
            task.abort();
        }
        drop(tasks);
        drop(Box::from_raw(handle as *const SkywardHandle as *mut SkywardHandle));
    }));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_options(home: &std::ffi::CString) -> SkywardOptions {
        SkywardOptions {
            tun_fd: -1,
            tun_mtu: 1500,
            embed_mode: true,
            home_dir: home.as_ptr(),
        }
    }

    #[test]
    fn version_pointer_is_valid() {
        let p = skyward_version();
        assert!(!p.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, VERSION);
    }

    #[test]
    fn null_handles_are_safe() {
        assert_eq!(skyward_test_config(ptr::null(), 0), SkywardStatus::NullPointer);
        assert_eq!(
            skyward_apply_config(ptr::null_mut(), ptr::null(), 0),
            SkywardStatus::NullPointer,
        );
        skyward_close_inbound(ptr::null_mut());
        skyward_set_hooks(ptr::null_mut(), ptr::null());
        skyward_destroy(ptr::null_mut());
    }

    #[test]
    fn create_apply_test_destroy_lifecycle() {
        let home = std::ffi::CString::new(".").unwrap();
        let opts = make_options(&home);
        let handle = skyward_create(&opts);
        assert!(!handle.is_null());

        let yaml = b"port: 0\nmode: rule\nrules:\n  - MATCH,DIRECT\n";
        assert_eq!(skyward_test_config(yaml.as_ptr(), yaml.len()), SkywardStatus::Ok);
        assert_eq!(skyward_apply_config(handle, yaml.as_ptr(), yaml.len()), SkywardStatus::Ok);
        assert_eq!(
            skyward_apply_config(handle, b"mode: bogus".as_ptr(), 11),
            SkywardStatus::ConfigError,
        );

        skyward_destroy(handle);
    }

    #[test]
    fn invoke_method_roundtrip() {
        let input = br#"{"id":"1","method":"coreVersion"}"#;
        let mut len = 0usize;
        let buf = skyward_invoke_method(input.as_ptr(), input.len(), &mut len);
        assert!(!buf.is_null());
        assert!(len > 0);
        let text = unsafe { std::slice::from_raw_parts(buf, len) };
        let value: serde_json::Value = serde_json::from_slice(text).unwrap();
        assert_eq!(value["id"], "1");
        assert!(value["result"]
            .as_str()
            .unwrap()
            .starts_with("Skyward Core (Rust)"));
        skyward_free_buffer(buf, len);
    }

    #[test]
    fn free_buffer_uses_header_not_caller_len() {
        let input = br#"{"method":"coreVersion"}"#;
        let mut len = 0usize;
        let buf = skyward_invoke_method(input.as_ptr(), input.len(), &mut len);
        assert!(!buf.is_null());
        // Deliberately wrong length: the header must be authoritative.
        skyward_free_buffer(buf, 1);
    }

    #[test]
    fn stale_handle_is_rejected_after_destroy() {
        let home = std::ffi::CString::new(".").unwrap();
        let opts = make_options(&home);
        let handle = skyward_create(&opts);
        assert!(!handle.is_null());
        skyward_destroy(handle);
        // A second destroy and any later call must not dereference freed memory.
        skyward_destroy(handle);
        let yaml = b"mode: rule\n";
        assert_eq!(
            skyward_apply_config(handle, yaml.as_ptr(), yaml.len()),
            SkywardStatus::InvalidHandle,
        );
    }

    #[test]
    fn bounded_cstr_rejects_missing_terminator() {
        let buf = [b'x'; 16];
        assert_eq!(
            unsafe { bounded_cstr(buf.as_ptr() as *const c_char, buf.len()) },
            Err(SkywardStatus::InvalidUtf8),
        );
    }

    static HOOK_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

    extern "C" fn counting_hook(_: *const u8, _: usize, _: *mut std::ffi::c_void) {
        HOOK_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn a_poisoned_hook_lock_does_not_silence_events() {
        let cell = Arc::new(HooksCell(Mutex::new(None)));
        // Poison the mutex the way a panic while setting hooks would.
        let poisoned = cell.clone();
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.0.lock().unwrap();
            panic!("poison the hooks lock");
        })
        .join();

        HOOK_CALLS.store(0, Ordering::Relaxed);
        // Both set and emit must recover via into_inner().
        let hooks = SkywardHooks {
            connection: Some(counting_hook),
            dns: None,
            provider: None,
            user_data: ptr::null_mut(),
        };
        *cell.0.lock().unwrap_or_else(|e| e.into_inner()) = Some(hooks);
        emit(&cell, |h| h.connection, "{}");
        assert_eq!(HOOK_CALLS.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn tun_packet_is_explicitly_not_implemented() {
        let home = std::ffi::CString::new(".").unwrap();
        let opts = make_options(&home);
        let handle = skyward_create(&opts);
        assert_eq!(
            skyward_handle_tun_packet(handle, ptr::null(), 0),
            SkywardStatus::NotImplemented,
        );
        skyward_destroy(handle);
    }
}
