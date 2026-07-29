//! FiSH 10 Legacy Set Key Function
//!
//! This function allows setting legacy Blowfish keys for compatibility
//! with FiSH 10 encryption.

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::dll_interface::utility;
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, legacy, log_debug, log_info};

dll_function_identifier!(FiSH10_SetKey, data, {
    // Parse input: <target> <key>
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parsed = utility::parse_input(&input_str)?;

    let target = parsed.target.to_lowercase();
    let key_input = parsed.message.trim();

    // Use the enhanced set_legacy_key function that handles both hex and plain text
    legacy::set_legacy_key(&target, key_input)?;

    log_info!("FiSH10: Successfully set legacy key for '{}'", target);

    Ok(format!("Legacy key set for {}", target))
});

#[cfg(test)]
mod tests {
    use super::*;

    // Test helper that mirrors the logic used by the DLL entrypoint.
    fn fish10_set_key_impl(input: &str) -> Result<String, DllError> {
        let parsed = utility::parse_input(input)?;
        let target = parsed.target;
        let key_input = parsed.message.trim();

        // Use the enhanced set_legacy_key function that handles both hex and plain text
        legacy::set_legacy_key(&target, key_input)?;

        #[cfg(debug_assertions)]
        log_debug!("FiSH10: successfully set legacy key for '{}'", target);

        Ok(format!("Legacy key set for {}", target))
    }

    #[test]
    fn test_fish10_set_key_valid() {
        // Test with valid hex key
        let result = fish10_set_key_impl("#test 6162636465666768"); // "abcdefgh" in hex
        assert!(result.unwrap().contains("Legacy key set"));
    }

    #[test]
    fn test_fish10_set_key_valid_text() {
        // Test with plain text key (should be converted to hex internally)
        let result = fish10_set_key_impl("#test MyPlainTextKey");
        assert!(result.unwrap().contains("Legacy key set"));
    }

    #[test]
    fn test_fish10_set_key_invalid_length() {
        // Test with invalid key length (too short)
        let result = fish10_set_key_impl("#test 6162"); // Only 2 bytes
        assert!(result.is_err());
    }
}
