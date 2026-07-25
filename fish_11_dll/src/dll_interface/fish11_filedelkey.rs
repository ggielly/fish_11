use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::utils::normalize_nick;
use crate::{buffer_utils, config, dll_function_identifier};

dll_function_identifier!(FiSH11_FileDelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    let input_trimmed = input.trim();

    let parts: Vec<&str> = input_trimmed.splitn(2, ' ').collect();
    let (network, nickname_raw) = if parts.len() == 2 {
        (parts[0], parts[1])
    } else {
        ("default", parts[0])
    };

    let normalized_target = crate::utils::normalize_target(nickname_raw);
    let nickname = normalize_nick(normalized_target);

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    #[cfg(debug_assertions)]
    log::info!(
        "Key deletion requested for nickname/channel: {} on network: {} (original: {})",
        nickname,
        network,
        input_trimmed
    );

    config::delete_key(&nickname, Some(network))?;

    let message = format!("Key deleted for {}", nickname);

    #[cfg(debug_assertions)]
    log::info!("{}", message);

    // Return success message (raw format, script will format display)
    Ok(message)
});

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::ptr;

    use super::*;

    fn call_delkey(input: &str, buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];

        // Copy input string to buffer
        let c_input = CString::new(input).unwrap();
        let input_bytes = c_input.as_bytes_with_nul();
        let copy_len = input_bytes.len().min(buffer_size);
        unsafe {
            std::ptr::copy_nonoverlapping(
                input_bytes.as_ptr(),
                buffer.as_mut_ptr() as *mut u8,
                copy_len,
            );
        }

        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer_size);

        let result = FiSH11_FileDelKey(
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
    fn test_delkey_normal() {
        // Create a test key for "bob" first
        let test_key = [1u8; 32];
        config::set_key_default("bob", &test_key, true).unwrap();

        let (code, msg) = call_delkey("bob", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        // Structured check: message should mention bob
        assert!(msg.contains("bob"));
    }

    #[test]
    fn test_delkey_nickname_empty() {
        let (code, msg) = call_delkey("   ", 256);
        assert_eq!(code, crate::dll_interface::MIRC_COMMAND);
        // Structured check: message should mention empty input or missing parameter
        assert!(msg.to_lowercase().contains("empty") || msg.to_lowercase().contains("missing"));
    }

    #[test]
    fn test_delkey_key_not_found() {
        let (code, msg) = call_delkey("unknown_nick", 256);
        assert_eq!(code, crate::dll_interface::MIRC_COMMAND);
        // Structured check: message should mention no encryption key
        assert!(msg.to_lowercase().contains("no encryption key"));
    }

    #[test]
    fn test_delkey_buffer_too_small() {
        // Create a test key for "alice" first
        let test_key = [1u8; 32];
        config::set_key_default("alice", &test_key, true).unwrap();

        let (code, msg) = call_delkey("alice", 8);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        // Structured check: message is truncated
        assert!(msg.len() < 20);
    }

    #[test]
    fn test_delkey_malformed_input() {
        // Test with a buffer containing null byte in the middle
        let mut buffer = vec![0i8; 256];
        // Write "a\0b" to the buffer
        buffer[0] = b'a' as i8;
        buffer[1] = 0;
        buffer[2] = b'b' as i8;

        // Override buffer size for this test
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer.len());

        let result = FiSH11_FileDelKey(
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
        assert_eq!(result, crate::dll_interface::MIRC_COMMAND);
        // The function will read "a" and try to delete key for "a"
        // It should return an error message (key not found or similar)
        assert!(c_str.to_string_lossy().len() > 0);
    }

    #[test]
    fn test_delkey_with_network_parameter() {
        let test_key = [2u8; 32];
        config::set_key("netuser", &test_key, Some("EFnet"), true, false).unwrap();

        let (code, msg) = call_delkey("EFnet netuser", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.contains("netuser"));
    }

    #[test]
    fn test_delkey_network_only_deletes_correct_key() {
        let test_key1 = [3u8; 32];
        let test_key2 = [4u8; 32];
        config::set_key("multiuser", &test_key1, Some("EFnet"), true, false).unwrap();
        config::set_key("multiuser", &test_key2, Some("QuakeNet"), true, false).unwrap();

        let (code, _msg) = call_delkey("EFnet multiuser", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);

        assert!(config::get_key("multiuser", Some("EFnet")).is_err());
        assert!(config::get_key("multiuser", Some("QuakeNet")).is_ok());
    }

    #[test]
    fn test_delkey_no_network_defaults_to_default() {
        let test_key = [5u8; 32];
        config::set_key_default("defaultuser", &test_key, true).unwrap();

        let (code, msg) = call_delkey("defaultuser", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.contains("defaultuser"));
    }

    #[test]
    fn test_roundtrip_set_get_delete_with_network() {
        let key = [10u8; 32];
        config::set_key("roundtrip_user", &key, Some("TestNet"), true, false).unwrap();

        let retrieved = config::get_key("roundtrip_user", Some("TestNet")).unwrap();
        assert_eq!(retrieved, key);

        let (code, msg) = call_delkey("TestNet roundtrip_user", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.contains("roundtrip_user"));

        assert!(config::get_key("roundtrip_user", Some("TestNet")).is_err());
    }

    #[test]
    fn test_roundtrip_set_get_delete_default_network() {
        let key = [11u8; 32];
        config::set_key_default("roundtrip_default", &key, true).unwrap();

        let retrieved = config::get_key_default("roundtrip_default").unwrap();
        assert_eq!(retrieved, key);

        let (code, msg) = call_delkey("roundtrip_default", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.contains("roundtrip_default"));

        assert!(config::get_key_default("roundtrip_default").is_err());
    }
}
