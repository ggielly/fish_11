//! DLL interface for setting plaintext topics
//!
//! This module provides the DLL interface for setting plaintext topics in the configuration.
//! It allows users to save topics in plaintext format via the mIRC script.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use crate::unified_error::{DllError, DllResult};
use crate::{buffer_utils, config, dll_interface::get_buffer_size};

/// DLL function to set a plaintext topic for a channel
///
/// Expected input format: "<channel> <topic>"
/// Example: "#mychannel This is my channel topic"
///
/// Returns: Success message or error message
#[no_mangle]
pub extern "stdcall" fn FiSH11_SetTopic(data: *mut c_char) -> i32 {
    // Define the function name for error context
    let func_name = "FiSH11_SetTopic";

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

        // Set the topic in the configuration
        config::with_config_mut(|config| config::topics::set_topic(config, channel, topic))
            .map_err(DllError::from)?;

        Ok(format!("Plaintext topic set for channel: {}", channel))
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
                buffer_utils::write_cstring_to_buffer(data, get_buffer_size(), &cstring).ok();
            }
            1 // Return success code
        }
        Err(e) => {
            log::error!("{}: {}", func_name, e);
            unsafe { e.to_mirc_response(data) }
        }
    }
}

/// DLL function to get a plaintext topic for a channel
///
/// Expected input format: "<channel>"
/// Example: "#mychannel"
///
/// Returns: The topic string or error message
#[no_mangle]
pub extern "stdcall" fn FiSH11_GetTopic(data: *mut c_char) -> i32 {
    // Define the function name for error context
    let func_name = "FiSH11_GetTopic";

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

        // Get the topic from the configuration
        let topic_option = config::with_config(|config| config::topics::get_topic(config, channel))
            .map_err(DllError::from)?;

        match topic_option {
            Some(topic) => Ok(topic),
            None => Ok("No topic found for this channel".to_string()),
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
                buffer_utils::write_cstring_to_buffer(data, get_buffer_size(), &cstring).ok();
            }
            1 // Return success code
        }
        Err(e) => {
            log::error!("{}: {}", func_name, e);
            unsafe { e.to_mirc_response(data) }
        }
    }
}

/// DLL function to remove a plaintext topic for a channel
///
/// Expected input format: "<channel>"
/// Example: "#mychannel"
///
/// Returns: Success message or error message
#[no_mangle]
pub extern "stdcall" fn FiSH11_RemoveTopic(data: *mut c_char) -> i32 {
    // Define the function name for error context
    let func_name = "FiSH11_RemoveTopic";

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

        // Remove the topic from the configuration
        let removed =
            config::with_config_mut(|config| config::topics::remove_topic(config, channel))
                .map_err(DllError::from)?;

        if removed {
            Ok(format!("Topic removed for channel: {}", channel))
        } else {
            Ok(format!("No topic was found for channel: {}", channel))
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
                buffer_utils::write_cstring_to_buffer(data, get_buffer_size(), &cstring).ok();
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
    fn test_set_topic_dll_function() {
        let input = CString::new("#test This is a test topic").unwrap();
        let mut buffer: [c_char; 1000] = [0; 1000];
        let result = unsafe { FiSH11_SetTopic(buffer.as_mut_ptr()) };
        // The function expects the input to be in the buffer, so this test is illustrative
        // In practice, the DLL would be called from mIRC with the input already in the buffer
        assert!(result >= 0); // Check that it doesn't crash
    }

    #[test]
    fn test_topic_roundtrip_set_get_remove() {
        let channel = "#roundtrip_test";
        let topic = "Hello roundtrip world!";

        config::with_config_mut(|config| {
            config::topics::set_topic(config, channel, topic)
        }).unwrap();

        let result = config::with_config(|config| {
            config::topics::get_topic(config, channel)
        }).unwrap();
        assert_eq!(result, Some(topic.to_string()));

        let removed = config::with_config_mut(|config| {
            config::topics::remove_topic(config, channel)
        }).unwrap();
        assert!(removed);

        let result = config::with_config(|config| {
            config::topics::get_topic(config, channel)
        }).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_get_topic_nonexistent_returns_none() {
        let result = config::with_config(|config| {
            config::topics::get_topic(config, "#nonexistent_channel")
        }).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn test_remove_topic_nonexistent_returns_false() {
        let removed = config::with_config_mut(|config| {
            config::topics::remove_topic(config, "#nonexistent_channel")
        }).unwrap();
        assert!(!removed);
    }
}
