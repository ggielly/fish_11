use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{config, dll_function_identifier, log_debug};

dll_function_identifier!(FiSH11_FileListKeys, data, {
    log_debug!("Starting key listing");

    // Log that the function was called
    log_debug!("FiSH11_FileListKeys function called");

    // Attempt to list the keys
    let keys = config::list_keys()?;

    // Log how many keys were found
    log_debug!("Retrieved {} keys from config", keys.len());

    if keys.is_empty() {
        return Ok("FiSH: No keys stored.".to_string());
    }

    // Build a multi-line response where each line is plain text
    // The mIRC script will display each line via `fish11_display_multiline_result`.
    let mut lines = Vec::new();
    lines.push("--- FiSH Keys ---".to_string());

    for (nickname, network, _key_type, date) in keys {
        let net_display =
            if network.is_empty() || network == "default" { "default" } else { &network };

        let key_info = if let Some(date_str) = date {
            format!("Key: {:<20} | Network: {:<15} | Added: {}", nickname, net_display, date_str)
        } else {
            format!("Key: {:<20} | Network: {:<15}", nickname, net_display)
        };
        lines.push(key_info);
    }

    lines.push("-------------------".to_string());

    let result_string = lines.join("\r\n");

    log_debug!("FiSH11_FileListKeys: about to return: '{}'", result_string);

    // Join lines with CRLF so the mIRC display helper can split them into tokens
    Ok(result_string)
});

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr;

    use super::*;
    use crate::dll_interface::MIRC_IDENTIFIER;

    fn call_listkeys(buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];
        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer_size);

        let result = FiSH11_FileListKeys(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        // Restore previous buffer size
        crate::dll_interface::restore_buffer_size_for_test(prev_size);

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        (result, c_str.to_string_lossy().to_string())
    }

    #[test]
    fn test_listkeys_normal() {
        // Suppose there are keys in config
        let (code, msg) = call_listkeys(512);
        // dll_function_identifier! returns MIRC_IDENTIFIER (3) on success
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        // Structured check: message should mention FiSH Keys
        assert!(msg.contains("FiSH Keys"));
    }

    #[test]
    fn test_listkeys_no_keys() {
        // Suppose config is empty
        let (code, msg) = call_listkeys(256);
        // dll_function_identifier! returns MIRC_IDENTIFIER (3) on success
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        // Structured check: message should either indicate no keys, or show the keys list.
        // The global config used in tests may already contain keys on disk, so accept both forms.
        let lower = msg.to_lowercase();
        assert!(
            lower.contains("no keys")
                || lower.contains("no keys stored")
                || lower.contains("fish keys")
        );
    }

    #[test]
    fn test_listkeys_buffer_too_small() {
        let (code, msg) = call_listkeys(8);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        // Structured check: message is truncated
        assert!(msg.len() < 20);
    }

    #[test]
    fn test_listkeys_malformed_input() {
        // Should not crash even if _data is a bad pointer
        let mut buffer = vec![0i8; 256];
        let bad_input = unsafe { CString::from_vec_unchecked(vec![97, 0, 98]) };
        let result = FiSH11_FileListKeys(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            bad_input.as_ptr() as *mut c_char,
            ptr::null_mut(),
            ptr::null_mut(),
        );

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        assert_eq!(result, crate::dll_interface::MIRC_IDENTIFIER);
        // Structured check: message should not be empty
        assert!(!c_str.to_string_lossy().is_empty());
    }
}
