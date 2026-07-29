//! FiSH_11 DLL Abstraction Bridge for the MLS Test Bot
//!
//! Calls `fish_11.dll` / `libfish_11.so` exported C functions dynamically.
//! When the `integrated` feature is enabled, links directly against the
//! `fish_11_dll` crate without external DLL loading.
//!
//! Adapted from `fish_11_relay::dll_bridge`.

use std::ffi::{CStr, CString, c_char};
use std::os::raw::c_int;
use std::path::Path;
use anyhow::{Result, anyhow};
use tracing::{info, warn};

/// mIRC DLL function signature matching `dll_function_identifier!` macro output.
#[cfg(windows)]
type MircDllFn = unsafe extern "C" fn(
    m_wnd: *mut *mut std::ffi::c_void,
    a_wnd: *mut *mut std::ffi::c_void,
    data: *mut c_char,
    parms: *mut c_char,
    show: *mut c_int,
    nopause: *mut c_int,
) -> c_int;

/// Buffer size matching fish_11_core::globals::DLL_BUFFER_SIZE
const DLL_BUFFER_SIZE: usize = 8192;

/// DLL bridge for calling fish_11 exported functions
pub struct DllBridge {
    loaded_lib: Option<libloading::Library>,
}

impl Default for DllBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl DllBridge {
    /// Create a new DLL bridge, trying to load the shared library.
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

    /// Call a named DLL function with the given input string.
    ///
    /// The function is called with null HWND/parms/show/nopause (standalone mode).
    /// Returns the output string written into the data buffer by the DLL.
    pub fn call_dll_fn(&self, fn_name: &str, input: &str) -> Result<String> {
        let mut buffer = vec![0u8; DLL_BUFFER_SIZE];
        let input_bytes = input.as_bytes();
        let copy_len = input_bytes.len().min(buffer.len() - 1);
        buffer[..copy_len].copy_from_slice(&input_bytes[..copy_len]);
        buffer[DLL_BUFFER_SIZE - 1] = 0;

        if let Some(ref lib) = self.loaded_lib {
            let c_fn_name = CString::new(fn_name)?;
            unsafe {
                let func: libloading::Symbol<MircDllFn> = lib.get(c_fn_name.as_bytes_with_nul())
                    .map_err(|e| anyhow!("DLL symbol '{}' not found: {}", fn_name, e))?;

                let null_hwnd: *mut *mut std::ffi::c_void = std::ptr::null_mut();
                let null_parms: *mut c_char = std::ptr::null_mut();
                let null_show: *mut c_int = std::ptr::null_mut();
                let null_nopause: *mut c_int = std::ptr::null_mut();

                let ret_code = func(
                    null_hwnd, null_hwnd,
                    buffer.as_mut_ptr() as *mut c_char,
                    null_parms,
                    null_show, null_nopause,
                );

                let c_out = CStr::from_ptr(buffer.as_ptr() as *const c_char);
                let out_str = c_out.to_str().unwrap_or_default().to_string();

                if ret_code == 0 {
                    Err(anyhow!("DLL call '{}' halted: {}", fn_name, out_str))
                } else {
                    Ok(out_str)
                }
            }
        } else {
            #[cfg(feature = "integrated")]
            {
                call_internal_dll_fn(fn_name, buffer.as_mut_ptr() as *mut c_char)
            }
            #[cfg(not(feature = "integrated"))]
            {
                let _ = buffer;
                Err(anyhow!(
                    "No external DLL loaded and 'integrated' feature not enabled. \
                     Cannot call '{}'", fn_name
                ))
            }
        }
    }
}

/// Fallback direct caller for internal `fish_11_dll` functions (integrated mode).
///
/// # Safety
///
/// `data` must be a valid pointer to a buffer of at least `DLL_BUFFER_SIZE` bytes
/// that outlives this function call.
#[cfg(feature = "integrated")]
fn call_internal_dll_fn(fn_name: &str, data: *mut c_char) -> Result<String> {
    use fish_11::dll_interface::*;

    let null_hwnd: *mut *mut std::ffi::c_void = std::ptr::null_mut();
    let null_parms: *mut c_char = std::ptr::null_mut();
    let null_show: *mut c_int = std::ptr::null_mut();
    let null_nopause: *mut c_int = std::ptr::null_mut();

    let ret_code = match fn_name {
        "FiSH11_FCEP2_InitDevice" =>
            FiSH11_FCEP2_InitDevice(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_GenKeyPackage" =>
            FiSH11_FCEP2_GenKeyPackage(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_CreateGroup" =>
            FiSH11_FCEP2_CreateGroup(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_ProcessMessage" =>
            FiSH11_FCEP2_ProcessMessage(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_EncryptMsg" =>
            FiSH11_FCEP2_EncryptMsg(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_DecryptMsg" =>
            FiSH11_FCEP2_DecryptMsg(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_GetGroupState" =>
            FiSH11_FCEP2_GetGroupState(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_ResolveConflict" =>
            FiSH11_FCEP2_ResolveConflict(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_SetTrust" =>
            FiSH11_FCEP2_SetTrust(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_SubmitProposal" =>
            FiSH11_FCEP2_SubmitProposal(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_SendCommit" =>
            FiSH11_FCEP2_SendCommit(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_RemoveDevice" =>
            FiSH11_FCEP2_RemoveDevice(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_SyncGroup" =>
            FiSH11_FCEP2_SyncGroup(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_ProcessSync" =>
            FiSH11_FCEP2_ProcessSync(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_ExportState" =>
            FiSH11_FCEP2_ExportState(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_ImportState" =>
            FiSH11_FCEP2_ImportState(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        "FiSH11_FCEP2_RequestKeyPackage" =>
            FiSH11_FCEP2_RequestKeyPackage(null_hwnd, null_hwnd, data, null_parms, null_show, null_nopause),
        _ => return Err(anyhow!("Unknown DLL function: {}", fn_name)),
    };

    let c_out = unsafe { CStr::from_ptr(data as *const c_char) };
    let out_str = c_out.to_str().unwrap_or_default().to_string();

    if ret_code == 0 {
        Err(anyhow!("DLL call '{}' halted: {}", fn_name, out_str))
    } else {
        Ok(out_str)
    }
}
