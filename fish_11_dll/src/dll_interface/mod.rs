//use once_cell::sync::Lazy;
//use regex::Regex;
use std::ffi::CStr;
use std::ptr;

mod fish11_decryptmsg;
mod fish11_encryptmsg;
mod fish11_filedelkey;
mod fish11_filegetkey;
mod fish11_filelistkeys;
mod fish11_filelistkeysitem;
mod fish11_genkey;
mod fish11_getconfigpath;
mod fish11_getkeyttl;
mod fish11_help;
mod fish11_setnetwork;
mod fish_11_coreversion;
mod key_management;
mod utility;

pub mod dll_error;
pub mod fish11_exchangekey;
pub mod fish11_setkey;
pub mod fish11_setkeyfromplaintext;
pub mod fish11_setmircdir;
pub mod function_template;
pub mod ini_types;

pub(crate) mod core;

// Re-export fish_11_core globals for use within fish_11_dll
pub use fish_11_core::globals::{
    CRATE_VERSION, DEFAULT_MIRC_BUFFER_SIZE, FUNCTION_TIMEOUT_SECONDS,
    KEY_EXCHANGE_TIMEOUT_SECONDS, MAX_MIRC_BUFFER_SIZE, MIRC_BUFFER_SIZE, MIRC_COMMAND,
    MIRC_CONTINUE, MIRC_ERROR, MIRC_HALT, MIRC_IDENTIFIER, MIRC_TYPICAL_BUFFER_SIZE,
    NICK_VALIDATOR,
};

/// Returns the maximum amount of data that can be written into the output buffer.
/// This implementation includes fallback to global buffer size if LOAD_INFO is not available.
pub(crate) fn get_buffer_size() -> usize {
    use self::core::LOAD_INFO;

    // First try to get buffer size from mIRC information
    let buffer_size = {
        let guard = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");

        guard.as_ref().map(|info| info.m_bytes as usize).unwrap_or_else(|| {
            // Fall back to our global buffer size
            match MIRC_BUFFER_SIZE.lock() {
                Ok(size) => *size,
                Err(_) => DEFAULT_MIRC_BUFFER_SIZE,
            }
        })
    };

    // Always leave room for null terminator, and cap to MAX_MIRC_BUFFER_SIZE
    let available = buffer_size.saturating_sub(1);
    std::cmp::min(available, MAX_MIRC_BUFFER_SIZE)
}

#[cfg(test)]
/// Test helper: temporarily override both MIRC_BUFFER_SIZE and LOAD_INFO
/// to ensure get_buffer_size() returns the test's actual buffer size.
/// Returns the previous values so they can be restored.
pub(crate) fn override_buffer_size_for_test(size: usize) -> Option<usize> {
    use self::core::LOAD_INFO;

    // Clear LOAD_INFO so get_buffer_size() will use MIRC_BUFFER_SIZE
    let _ = LOAD_INFO.lock().ok().map(|mut guard| *guard = None);

    // Set MIRC_BUFFER_SIZE to the test's buffer size
    MIRC_BUFFER_SIZE.lock().ok().map(|mut g| {
        let prev = *g;
        *g = size;
        prev
    })
}

#[cfg(test)]
mod ini_tests;

#[cfg(test)]
/// Test helper: restore the buffer size after a test
pub(crate) fn restore_buffer_size_for_test(prev_size: Option<usize>) {
    if let Some(size) = prev_size {
        let _ = MIRC_BUFFER_SIZE.lock().ok().map(|mut g| *g = size);
    }
}

pub use crate::channel_encryption::init_key::FiSH11_InitChannelKey;
pub use crate::channel_encryption::process_key::FiSH11_ProcessChannelKey;

pub use fish11_getkeyttl::FiSH11_GetKeyTTL;
