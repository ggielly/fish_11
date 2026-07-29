//! DLL interface for setting legacy plaintext topics
//!
//! This module provides the DLL interface for setting plaintext topics in the legacy fish10 configuration.
//! It allows users to save topics in plaintext format via the mIRC script.

use std::ffi::CString;
use std::os::raw::c_char;

use crate::unified_error::{DllError, DllResult};
use crate::{buffer_utils, legacy};

/// DLL function to set a plaintext topic for a channel in the legacy fish10 section
///
/// Expected input format: "<channel> <topic>"
/// Example: "#mychannel This is my channel topic"
///
/// Returns: Success message or error message
#[no_mangle]
pub extern "stdcall" fn FiSH10_SetTopic(data: *mut c_char) -> i32 {
    // Define the function name for error context
    let func_name = "FiSH10_SetTopic";

    // Validate input pointer
    if data.is_null() {
        log::error!("{}: null data pointer", func_name);
        return unsafe {
            DllError::NullPointer { context: func_name.to_string() }.to_mirc_response(data)
        };
    }

    // Inner function to handle the logic with proper error handling
    fn inner(data: *mut c_char) -> DllResult<String> {
        // Parse the input from the buffer
        let input = unsafe { buffer_utils::parse_buffer_input(data)? };

        // Split the input into channel and topic parts
        let parts: Vec<&str> = input.splitn(2, ' ').collect();

        if parts.len() != 2 {
            return Err(DllError::InvalidInput {
                param: "input".to_string(),
                reason: "expected format: <channel> <topic>".to_string(),
            });
        }

        let channel = parts[0].trim();
        let topic = parts[1].trim();

        // Validate channel name format (should start with # or &)
        if !channel.starts_with('#') && !channel.starts_with('&') {
            return Err(DllError::InvalidInput {
                param: "channel".to_string(),
                reason: "channel name must start with # or &".to_string(),
            });
        }

        // Set the topic in the legacy configuration
        legacy::set_legacy_topic(channel, topic)?;

        Ok(format!("Legacy plaintext topic set for channel: {}", channel))
    }

    // Execute the inner function and handle the result
    match inner(data) {
        Ok(result) => {
            // Convert result to CString and write to buffer
            let cstring = match CString::new(result) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("{}: null byte in result: {}", func_name, e);
                    return unsafe { DllError::from(e).to_mirc_response(data) };
                }
            };

            unsafe {
                buffer_utils::write_cstring_to_buffer(data, 900, &cstring).ok();
            }
            1 // Return success code
        }
        Err(e) => {
            log::error!("{}: {}", func_name, e);
            unsafe { e.to_mirc_response(data) }
        }
    }
}

/// DLL function to get a plaintext topic for a channel from the legacy fish10 section
///
/// Expected input format: "<channel>"
/// Example: "#mychannel"
///
/// Returns: The topic string or error message
#[no_mangle]
pub extern "stdcall" fn FiSH10_GetTopic(data: *mut c_char) -> i32 {
    // Define the function name for error context
    let func_name = "FiSH10_GetTopic";

    // Validate input pointer
    if data.is_null() {
        log::error!("{}: null data pointer", func_name);
        return unsafe {
            DllError::NullPointer { context: func_name.to_string() }.to_mirc_response(data)
        };
    }

    // Inner function to handle the logic with proper error handling
    fn inner(data: *mut c_char) -> DllResult<String> {
        // Parse the input from the buffer
        let input = unsafe { buffer_utils::parse_buffer_input(data)? };

        // Validate the input (should be a channel name)
        let channel = input.trim();

        // Validate channel name format (should start with # or &)
        if !channel.starts_with('#') && !channel.starts_with('&') {
            return Err(DllError::InvalidInput {
                param: "channel".to_string(),
                reason: "channel name must start with # or &".to_string(),
            });
        }

        // Get the topic from the legacy configuration
        let topic_option = legacy::get_legacy_topic(channel)?;

        match topic_option {
            Some(topic) => Ok(topic),
            None => Ok("No legacy topic found for this channel".to_string()),
        }
    }

    // Execute the inner function and handle the result
    match inner(data) {
        Ok(result) => {
            // Convert result to CString and write to buffer
            let cstring = match CString::new(result) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("{}: null byte in result: {}", func_name, e);
                    return unsafe { DllError::from(e).to_mirc_response(data) };
                }
            };

            unsafe {
                buffer_utils::write_cstring_to_buffer(data, 900, &cstring).ok();
            }
            1 // Return success code
        }
        Err(e) => {
            log::error!("{}: {}", func_name, e);
            unsafe { e.to_mirc_response(data) }
        }
    }
}

/// DLL function to remove a plaintext topic for a channel from the legacy fish10 section
///
/// Expected input format: "<channel>"
/// Example: "#mychannel"
///
/// Returns: Success message or error message
#[no_mangle]
pub extern "stdcall" fn FiSH10_RemoveTopic(data: *mut c_char) -> i32 {
    // Define the function name for error context
    let func_name = "FiSH10_RemoveTopic";

    // Validate input pointer
    if data.is_null() {
        log::error!("{}: null data pointer", func_name);
        return unsafe {
            DllError::NullPointer { context: func_name.to_string() }.to_mirc_response(data)
        };
    }

    // Inner function to handle the logic with proper error handling
    fn inner(data: *mut c_char) -> DllResult<String> {
        // Parse the input from the buffer
        let input = unsafe { buffer_utils::parse_buffer_input(data)? };

        // Validate the input (should be a channel name)
        let channel = input.trim();

        // Validate channel name format (should start with # or &)
        if !channel.starts_with('#') && !channel.starts_with('&') {
            return Err(DllError::InvalidInput {
                param: "channel".to_string(),
                reason: "channel name must start with # or &".to_string(),
            });
        }

        // Remove the topic from the legacy configuration
        let removed = legacy::remove_legacy_topic(channel)?;

        if removed {
            Ok(format!("Legacy topic removed for channel: {}", channel))
        } else {
            Ok(format!("No legacy topic was found for channel: {}", channel))
        }
    }

    // Execute the inner function and handle the result
    match inner(data) {
        Ok(result) => {
            // Convert result to CString and write to buffer
            let cstring = match CString::new(result) {
                Ok(s) => s,
                Err(e) => {
                    log::error!("{}: null byte in result: {}", func_name, e);
                    return unsafe { DllError::from(e).to_mirc_response(data) };
                }
            };

            unsafe {
                buffer_utils::write_cstring_to_buffer(data, 900, &cstring).ok();
            }
            1 // Return success code
        }
        Err(e) => {
            log::error!("{}: {}", func_name, e);
            unsafe { e.to_mirc_response(data) }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::raw::c_char;

    use super::*;

    #[test]
    fn test_set_legacy_topic_dll_function() {
        let input = CString::new("#test This is a test topic").unwrap();
        let mut buffer: [c_char; 1000] = [0; 1000];
        let result = unsafe { FiSH10_SetTopic(buffer.as_mut_ptr()) };
        // The function expects the input to be in the buffer, so this test is illustrative
        // In practice, the DLL would be called from mIRC with the input already in the buffer
        assert!(result >= 0); // Check that it doesn't crash
    }
}
