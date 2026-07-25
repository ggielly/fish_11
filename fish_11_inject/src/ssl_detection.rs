use std::ffi::CString;

use log::{debug, error};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetModuleFileNameA, GetProcAddress};
use windows::core::PCSTR;

use crate::pointer_validation::unsafe_transmute_validated;

#[derive(Debug, Clone)]
pub struct OpenSslInfo {
    pub module_handle: HMODULE,
    pub dll_name: String,
    pub version: String,
    pub ssl_read_addr: *const u8,
    pub ssl_write_addr: *const u8,
}

/// List of possible OpenSSL DLL names to check
const OPENSSL_DLL_NAMES: &[&str] = &[
    // OpenSSL 3.x
    "libssl-3.dll",
    "libssl-3-x64.dll",
    "ssleay32.dll",
    "libssl-1_1.dll",
    "libssl-1_1-x64.dll",
    "libeay32.dll",
    "ssleay32.dll",
    "ssl.dll",
    "openssl.dll",
    "libssl.dll",
    "openssl32.dll",
    "openssl64.dll",
];

/// Get OpenSSL version string from loaded module
unsafe fn get_openssl_version(module: HMODULE) -> Option<String> {
    // Try different version function names
    let version_functions = [
        "OpenSSL_version",      // OpenSSL 1.1.0+
        "SSLeay_version",       // OpenSSL 1.0.x
        "OPENSSL_VERSION_TEXT", // Fallback
    ];

    for func_name in &version_functions {
        let func_name_cstr = CString::new(*func_name).ok()?;
        let version_fn =
            GetProcAddress(module, PCSTR::from_raw(func_name_cstr.as_ptr() as *const u8));

        if version_fn.is_some() {
            if func_name == &"OPENSSL_VERSION_TEXT" {
                // This is a string constant, not a function.
                // SAFETY: version_fn is guaranteed Some by the is_some() check above.
                // OPENSSL_VERSION_TEXT is a static const char*, ABI-compatible with *const i8.
                let version_ptr: *const i8 = std::mem::transmute(version_fn.unwrap());

                if !version_ptr.is_null() {
                    let version_cstr = std::ffi::CStr::from_ptr(version_ptr);
                    if let Ok(version_str) = version_cstr.to_str() {
                        return Some(version_str.to_string());
                    }
                }
            } else {
                // This is a function
                type VersionFn = unsafe extern "C" fn(i32) -> *const i8;

                // Validate and transmute safely
                if let Ok(version_fn_validated) =
                    unsafe_transmute_validated::<VersionFn>(version_fn, Some(module))
                {
                    let version_ptr = version_fn_validated(0); // OPENSSL_VERSION

                    if !version_ptr.is_null() {
                        let version_cstr = std::ffi::CStr::from_ptr(version_ptr);
                        if let Ok(version_str) = version_cstr.to_str() {
                            return Some(version_str.to_string());
                        }
                    }
                } else {
                    error!("Failed to validate OpenSSL version function pointer");
                }
            }
        }
    }

    None
}

/// Find SSL functions in the given module
unsafe fn find_ssl_functions(module: HMODULE) -> Option<(*const u8, *const u8)> {
    let ssl_read_name = CString::new("SSL_read").unwrap();
    let ssl_write_name = CString::new("SSL_write").unwrap();

    let ssl_read = GetProcAddress(module, PCSTR::from_raw(ssl_read_name.as_ptr() as *const u8));
    let ssl_write = GetProcAddress(module, PCSTR::from_raw(ssl_write_name.as_ptr() as *const u8));

    if ssl_read.is_none() || ssl_write.is_none() {
        #[cfg(debug_assertions)]
        debug!("SSL functions not found in module {:?}", module);

        return None;
    }

    // SAFETY: Both ssl_read and ssl_write are guaranteed Some by the is_none() check above.
    // We transmute to *const u8 for address comparison / raw pointer storage.
    // These are not called through this pointer — actual calls go through the
    // generic_detour trampoline installed elsewhere.
    let read_ptr: *const u8 = std::mem::transmute(ssl_read.unwrap());
    let write_ptr: *const u8 = std::mem::transmute(ssl_write.unwrap());

    Some((read_ptr, write_ptr))
}

/// Get module file name
unsafe fn get_module_filename(module: HMODULE) -> Option<String> {
    let mut filename = vec![0u8; 260]; // MAX_PATH
    // GetModuleFileNameExA signature in windows crate typically takes &mut [u8]
    // returns u32 length
    let len = GetModuleFileNameA(Some(module), &mut filename);

    if len > 0 {
        filename.truncate(len as usize);

        if let Ok(name) = String::from_utf8(filename) {
            // Extract just the filename
            if let Some(filename_only) = name.split('\\').last() {
                return Some(filename_only.to_string());
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openssl_info_struct() {
        // Just verify that our OpenSslInfo struct has the expected fields
        let info = OpenSslInfo {
            module_handle: HMODULE::default(),
            dll_name: "test.dll".to_string(),
            version: "1.0.0".to_string(),
            ssl_read_addr: std::ptr::null(),
            ssl_write_addr: std::ptr::null(),
        };

        assert_eq!(info.dll_name, "test.dll");
        assert_eq!(info.version, "1.0.0");
    }

    #[test]
    fn test_openssl_dll_names_array() {
        assert!(!OPENSSL_DLL_NAMES.is_empty());
        assert!(OPENSSL_DLL_NAMES.contains(&"libssl-3.dll"));
    }
}
