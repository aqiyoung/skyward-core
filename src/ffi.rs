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
pub struct SkywardHooks {
    /// JSON connection event: {"event":"add|remove","id":"...","host":"..."}
    pub connection: Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    /// JSON DNS query event.
    pub dns: Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    /// JSON provider-load event.
    pub provider: Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>,
    pub user_data: *mut std::ffi::c_void,
}

// SAFETY: hooks are only ever invoked from the runtime's Tokio threads with the
// user_data pointer supplied by the caller, which the caller must keep valid.
unsafe impl Send for SkywardHooks {}
unsafe impl Sync for SkywardHooks {}

struct HooksCell(Mutex<Option<SkywardHooks>>);
unsafe impl Send for HooksCell {}
unsafe impl Sync for HooksCell {}

fn emit(cell: &HooksCell, which: fn(&SkywardHooks) -> Option<extern "C" fn(*const u8, usize, *mut std::ffi::c_void)>, event: &str) {
    if let Ok(guard) = cell.0.lock() {
        if let Some(hooks) = guard.as_ref() {
            if let Some(cb) = which(hooks) {
                let bytes = event.as_bytes();
                unsafe { cb(bytes.as_ptr(), bytes.len(), hooks.user_data) };
            }
        }
    }
}

pub struct SkywardRuntime {
    tokio: tokio::runtime::Runtime,
    state: Mutex<Option<Arc<AppState>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    home_dir: PathBuf,
    #[allow(dead_code)]
    embed_mode: bool,
    hooks: HooksCell,
}

/// Opaque handle returned by `skyward_create` and consumed by every other call.
pub struct SkywardHandle(SkywardRuntime);

fn with<F>(handle: *mut SkywardHandle, f: F) -> SkywardStatus
where
    F: FnOnce(&SkywardRuntime) -> Result<(), SkywardStatus>,
{
    if handle.is_null() {
        return SkywardStatus::NullPointer;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: the caller guarantees a live handle from skyward_create.
        let rt = unsafe { &(*handle).0 };
        f(rt)
    }));
    match result {
        Ok(Ok(())) => SkywardStatus::Ok,
        Ok(Err(status)) => status,
        Err(_) => SkywardStatus::Panic,
    }
}

unsafe fn cstr_to_string(ptr: *const c_char, len: usize) -> Result<String, SkywardStatus> {
    if ptr.is_null() {
        return Err(SkywardStatus::NullPointer);
    }
    let bytes = std::slice::from_raw_parts(ptr as *const u8, len);
    String::from_utf8(bytes.to_vec()).map_err(|_| SkywardStatus::InvalidUtf8)
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
            Ok(PathBuf::from(std::ffi::CStr::from_ptr(home).to_string_lossy().into_owned()))
        }
    }
}

// ---- exported functions ----------------------------------------------------

#[no_mangle]
pub extern "C" fn skyward_version() -> *const c_char {
    // VERSION is 'static, so a pointer to its bytes stays valid forever.
    VERSION.as_ptr() as *const c_char
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
        let handle = SkywardHandle(SkywardRuntime {
            tokio,
            state: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
            home_dir,
            embed_mode,
            hooks: HooksCell(Mutex::new(None)),
        });
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
        // An existing state reuses its traffic counters; a fresh one creates them.
        let state = {
            let guard = rt.state.lock().map_err(|_| SkywardStatus::RuntimeError)?;
            guard.as_ref().cloned()
        };
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
                *rt.state.lock().map_err(|_| SkywardStatus::RuntimeError)? =
                    Some(Arc::new(AppState::new(engine, config_path, traffic)));
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
        let mut tasks = rt.tasks.lock().map_err(|_| SkywardStatus::RuntimeError)?;
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
        let host = unsafe { std::ffi::CStr::from_ptr(name) }
            .to_str().map_err(|_| SkywardStatus::InvalidUtf8)?.to_string();
        let state = rt.state.lock().map_err(|_| SkywardStatus::RuntimeError)?
            .as_ref().cloned().ok_or(SkywardStatus::NotInitialized)?;
        let resolver = state.engine.blocking_read().resolver.clone();
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
pub extern "C" fn skyward_set_hooks(handle: *mut SkywardHandle, hooks: *const SkywardHooks) {
    let _ = with(handle, |rt| {
        if hooks.is_null() {
            *rt.hooks.0.lock().map_err(|_| SkywardStatus::RuntimeError)? = None;
        } else {
            let value = unsafe { *(hooks as *const SkywardHooks) };
            *rt.hooks.0.lock().map_err(|_| SkywardStatus::RuntimeError)? = Some(value);
        }
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

#[no_mangle]
pub extern "C" fn skyward_destroy(handle: *mut SkywardHandle) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        // Abort tasks before dropping the runtime so they don't outlive it.
        let _ = skyward_close_inbound(handle);
        unsafe { drop(Box::from_raw(handle)); }
    });
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
