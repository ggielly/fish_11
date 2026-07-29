//! FiSH_11 DLL Abstraction Bridge
//!
//! Calls `fish_11.dll` / `libfish_11.so` exported C functions dynamically or links directly
//! with `fish_11_dll` for cross-platform autonomous CLI execution (Windows & Linux).

use std::ffi::{CStr, CString, c_char};
use std::os::raw::c_int;
use std::path::Path;

use anyhow::{Result, anyhow};
use tracing::{info, warn};

/// mIRC DLL function signature matching `dll_function_identifier!` macro output.
///
/// The HWND type (`*mut *mut c_void`) is Win32-specific; on non-Windows platforms
/// the bridge compiles against the internal Rust subsystem instead.
#[cfg(windows)]
type MircDllFn = unsafe extern "system" fn(
    m_wnd: *mut *mut std::ffi::c_void,
    a_wnd: *mut *mut std::ffi::c_void,
    data: *mut c_char,
    parms: *mut c_char,
    show: *mut c_int,
    nopause: *mut c_int,
) -> c_int;

/// Must match fish_11_core::globals::DLL_BUFFER_SIZE
const DLL_BUFFER_SIZE: usize = 8192;

/// DLL Client Bridge wrapper
pub struct DllBridge {
    loaded_lib: Option<libloading::Library>,
}

impl Default for DllBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DllBridge {
    pub fn new() -> Self {
        let dll_name = if cfg!(windows) { "fish_11.dll" } else { "libfish_11.so" };
        let mut loaded = None;

        if Path::new(dll_name).exists() {
            match unsafe { libloading::Library::new(dll_name) } {
                Ok(lib) => {
                    info!("Loaded external DLL: {}", dll_name);
                    loaded = Some(lib);
                }
                Err(e) => {
                    warn!("Failed to load {}: {}. Using integrated Rust subsystem.", dll_name, e);
                }
            }
        } else {
            info!("No external {} found. Using integrated Rust subsystem.", dll_name);
        }

        Self { loaded_lib: loaded }
    }

    pub fn call_dll_fn(&self, fn_name: &str, input: &str) -> Result<String> {
        let mut buffer = vec![0u8; DLL_BUFFER_SIZE];
        let input_bytes = input.as_bytes();
        let copy_len = input_bytes.len().min(buffer.len() - 1);
        buffer[..copy_len].copy_from_slice(&input_bytes[..copy_len]);

        // SAFETY: Force null-termination at the last byte so that even if the
        // external DLL writes a non-null-terminated string, CStr::from_ptr won't
        // read beyond the allocated buffer (avoids UB from malicious/buggy DLLs).
        buffer[DLL_BUFFER_SIZE - 1] = 0;

        if let Some(ref lib) = self.loaded_lib {
            let c_fn_name = CString::new(fn_name)?;
            unsafe {
                let func: libloading::Symbol<MircDllFn> = lib
                    .get(c_fn_name.as_bytes_with_nul())
                    .map_err(|e| anyhow!("DLL symbol '{}' not found: {}", fn_name, e))?;

                let null_hwnd: *mut *mut std::ffi::c_void = std::ptr::null_mut();
                let null_parms: *mut c_char = std::ptr::null_mut();
                let null_show: *mut c_int = std::ptr::null_mut();
                let null_nopause: *mut c_int = std::ptr::null_mut();

                // SAFETY: The external DLL is expected to write a C string into `buffer`.
                // We guarantee null-termination at `buffer[DLL_BUFFER_SIZE - 1] = 0` above,
                // so CStr::from_ptr will never read beyond the allocated buffer.
                // The function pointer type MircDllFn matches the mIRC DLL calling convention
                // (see dll_function_identifier! macro in fish_11_dll).
                let ret_code = func(
                    null_hwnd,
                    null_hwnd,
                    buffer.as_mut_ptr() as *mut c_char,
                    null_parms,
                    null_show,
                    null_nopause,
                );

                // SAFETY: buffer is valid for reads up to DLL_BUFFER_SIZE bytes and is
                // guaranteed null-terminated at index DLL_BUFFER_SIZE - 1.
                let c_out = CStr::from_ptr(buffer.as_ptr() as *const c_char);
                let out_str = c_out.to_str().unwrap_or_default().to_string();

                if ret_code == 0 {
                    Err(anyhow!("DLL call '{}' halted: {}", fn_name, out_str))
                } else {
                    Ok(out_str)
                }
            }
        } else {
            call_internal_dll_fn(fn_name, buffer.as_mut_ptr() as *mut c_char)
        }
    }
}

/// Fallback direct caller for internal `fish_11_dll` functions
///
/// # Safety
///
/// `data` must be a valid pointer to a buffer of at least `DLL_BUFFER_SIZE` bytes
/// that outlives this function call. The buffer will be read as a null-terminated
/// C string after the internal function returns.
fn call_internal_dll_fn(fn_name: &str, data: *mut c_char) -> Result<String> {
    use fish_11::dll_interface::*;

    let null_hwnd: *mut *mut std::ffi::c_void = std::ptr::null_mut();
    let null_parms: *mut c_char = std::ptr::null_mut();
    let null_show: *mut c_int = std::ptr::null_mut();
    let null_nopause: *mut c_int = std::ptr::null_mut();

    let ret_code = match fn_name {
        "FiSH11_FCEP2_InitDevice" => {
            FiSH11_FCEP2_InitDevice(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause)
        }
        "FiSH11_FCEP2_GenKeyPackage" => FiSH11_FCEP2_GenKeyPackage(
            null_hwnd,
            null_hwnd,
            data,
            null_parms,
            null_show,
            null_nopause,
        ),
        "FiSH11_FCEP2_CreateGroup" => FiSH11_FCEP2_CreateGroup(
            null_hwnd,
            null_hwnd,
            data,
            null_parms,
            null_show,
            null_nopause,
        ),
        "FiSH11_FCEP2_ProcessMessage" => FiSH11_FCEP2_ProcessMessage(
            null_hwnd,
            null_hwnd,
            data,
            null_parms,
            null_show,
            null_nopause,
        ),
        "FiSH11_FCEP2_EncryptMsg" => {
            FiSH11_FCEP2_EncryptMsg(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause)
        }
        "FiSH11_FCEP2_DecryptMsg" => {
            FiSH11_FCEP2_DecryptMsg(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause)
        }
        "FiSH11_FCEP2_GetGroupState" => FiSH11_FCEP2_GetGroupState(
            null_hwnd,
            null_hwnd,
            data,
            null_parms,
            null_show,
            null_nopause,
        ),
        "FiSH11_FCEP2_ResolveConflict" => FiSH11_FCEP2_ResolveConflict(
            null_hwnd,
            null_hwnd,
            data,
            null_parms,
            null_show,
            null_nopause,
        ),
        "FiSH11_FCEP2_SetTrust" => {
            FiSH11_FCEP2_SetTrust(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause)
        }
        _ => return Err(anyhow!("Unknown DLL function: {}", fn_name)),
    };

    // SAFETY: `data` is a mutable pointer to a buffer that outlives this function
    // (allocated in `call_dll_fn` which waits for our return). The buffer is
    // null-terminated at `DLL_BUFFER_SIZE - 1` by the caller.
    // `CStr::from_ptr` assumes a valid C string : we guarantee null-termination.
    let c_out = unsafe { CStr::from_ptr(data as *const c_char) };
    let out_str = c_out.to_str().unwrap_or_default().to_string();

    if ret_code == 0 {
        Err(anyhow!("DLL call '{}' halted: {}", fn_name, out_str))
    } else {
        Ok(out_str)
    }
}
