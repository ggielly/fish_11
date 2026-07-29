//! Unified error handling system for FiSH_11 DLL
//!
//! This module provides a comprehensive, standardized error handling approach
//! for the entire DLL, replacing fragmented error types with a single unified system.

use std::error::Error;
use std::ffi::{NulError, c_char};
use std::os::raw::c_int;

use fish_11_core::globals::MAX_MESSAGE_SIZE;
use thiserror::Error;

use crate::buffer_utils;
use crate::buffer_utils::BufferError;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};
pub use crate::error::FishError;

/// Unified error type for all DLL operations
///
/// This enum consolidates all possible error conditions across the DLL,
/// providing a single, consistent error type for all operations.
///
/// Uses `thiserror` for automatic Display and Error trait implementations.
#[derive(Error, Debug)]
pub enum DllError {
    // ===== Legacy Compatibility Errors =====
    /// Legacy FiSH 10 compatibility error
    #[error("legacy FiSH 10 error: {context} - {cause}")]
    LegacyError { context: String, cause: String },

    // ===== Configuration Errors =====
    /// Configuration file not found or inaccessible
    #[error("configuration file not found: {0}")]
    ConfigNotFound(String),

    /// Configuration file is malformed or contains invalid data
    #[error("configuration malformed: {0}")]
    ConfigMalformed(String),

    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Configuration setting has invalid value
    #[error("invalid config value for '{key}': '{value}' ({reason})")]
    ConfigInvalidValue { key: String, value: String, reason: String },

    // ===== Cryptography Errors =====
    /// Key not found for specified target (nick/channel)
    #[error("no encryption key found for '{0}'")]
    KeyNotFound(String),

    /// Key has expired and needs to be re-exchanged
    #[error("encryption key for '{nickname}' has expired")]
    KeyExpired { nickname: String },

    /// Not connected to IRC server
    #[error("not connected to IRC: {0}")]
    NotConnected(String),

    /// Key has invalid length or format
    #[error("invalid key: {reason}")]
    KeyInvalid { reason: String },

    /// Key has an invalid size
    #[error("invalid key size: expected {expected} bytes, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Encryption operation failed
    #[error("encryption failed ({context}): {cause}")]
    EncryptionFailed { context: String, cause: String },

    /// Decryption operation failed
    #[error("decryption failed ({context}): {cause}")]
    DecryptionFailed { context: String, cause: String },

    /// Key exchange protocol error
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// Message authentication failed (AEAD tag mismatch)
    #[error("message authentication failed (possibly tampered)")]
    AuthenticationFailed,

    /// Potential replay attack detected
    #[error("potential replay attack detected on channel {channel}")]
    ReplayAttackDetected { channel: String },

    /// Ratchet state not found for a channel
    #[error("ratchet state not found for channel {channel}")]
    RatchetStateNotFound { channel: String },

    /// Message size exceeds security limits
    #[error("message too large ({size} bytes, limit: {limit})")]
    MessageTooLarge { size: usize, limit: usize },

    // ===== Input Validation Errors =====
    /// Input parameter is null or empty
    #[error("invalid input for '{param}': {reason}")]
    InvalidInput { param: String, reason: String },

    /// Input contains invalid characters or format
    #[error("malformed input: '{input}' (expected: {expected})")]
    MalformedInput { input: String, expected: String },

    /// Input exceeds maximum allowed length
    #[error("input too long ({length} chars, max: {max})")]
    InputTooLong { length: usize, max: usize },

    /// Required parameter is missing
    #[error("missing required parameter: {0}")]
    MissingParameter(String),

    // ===== Buffer & Memory Errors =====
    /// Buffer pointer is null
    #[error("null pointer in {context}")]
    NullPointer { context: String },

    /// Buffer size is invalid or insufficient
    #[error("buffer too small ({size} bytes, need: {required})")]
    InvalidBufferSize { size: usize, required: usize },

    /// Failed to write to output buffer
    #[error("failed to write to buffer: {0}")]
    BufferWriteFailed(String),

    /// String contains null byte (incompatible with C strings)
    #[error("null byte in string ({context})")]
    NullByteInString { context: String },

    // ===== I/O Errors =====
    /// File system operation failed with underlying cause
    #[error("I/O error during {operation} on '{path}': {source}")]
    IoError {
        operation: String,
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Simple I/O error wrapper (for use with #[from])
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File not found
    #[error("file not found: {0}")]
    FileNotFound(String),

    /// Permission denied
    #[error("permission denied: {resource}")]
    PermissionDenied { resource: String },

    // ===== Encoding Errors =====
    /// Base64 encoding/decoding failed with underlying cause
    #[error("base64 error ({context}): {source}")]
    Base64Error {
        context: String,
        #[source]
        source: base64::DecodeError,
    },

    /// Base64 decoding failed with context
    #[error("base64 decoding failed ({context}): {cause}")]
    Base64DecodeFailed { context: String, cause: String },

    /// Simple Base64 error wrapper (for use with #[from])
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),

    /// UTF-8 encoding/decoding failed
    #[error("invalid UTF-8 ({context})")]
    Utf8Error { context: String },

    /// Simple UTF-8 string error wrapper (for use with #[from])
    #[error("UTF-8 conversion failed: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// Simple UTF-8 validation error wrapper (for use with #[from])
    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Simple null byte error wrapper (for use with #[from])
    #[error("null byte in string: {0}")]
    NulByte(#[from] NulError),

    /// Non-ASCII character in ASCII-only context
    #[error("non-ASCII character '{char}' in {context}")]
    NonAsciiCharacter { char: char, context: String },

    // ===== State & Logic Errors =====
    /// Duplicate entry (e.g., key already exists)
    #[error("entry already exists: {0}")]
    DuplicateEntry(String),

    /// Operation attempted in invalid state
    #[error("invalid state: {current} (required: {required})")]
    InvalidState { current: String, required: String },

    /// Operation timeout
    #[error("operation '{operation}' timed out after {duration_secs}s during stage: {stage}")]
    Timeout { operation: String, duration_secs: u64, stage: String },

    // ===== Network & Protocol Errors =====
    /// Invalid network name
    #[error("invalid network name: {0}")]
    InvalidNetwork(String),

    /// Protocol version mismatch
    #[error("protocol version mismatch: expected {expected}, got {got}")]
    ProtocolMismatch { expected: String, got: String },

    // ===== System Errors =====
    /// Cryptographically secure random number generation failed
    #[error("RNG failed: {context}")]
    RngFailed { context: String },

    /// Internal error (should never happen in production)
    #[error("internal error: {0}")]
    Internal(String),

    /// General processing error
    #[error("processing error: {0}")]
    ProcessingError(String),

    /// TLS codec serialization/deserialization error
    #[error("TLS codec error: {0}")]
    TlsCodec(String),

    /// Keychain is locked (master key not available)
    #[error("keychain is locked - use /fish11_unlock <password> to unlock it")]
    MasterKeyLocked,

    /// Feature not implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),

    /// Key derivation failed
    #[error("key derivation failed")]
    KeyDerivationFailed,
}

impl DllError {
    /// Convert error to mIRC response code and write error message to buffer
    ///
    /// # Safety
    ///
    /// `data` must point to a valid mIRC buffer with sufficient size
    pub unsafe fn to_mirc_response(self, data: *mut c_char) -> c_int {
        // Handle null pointer case specially (cannot write error message)
        if let DllError::NullPointer { .. } = self {
            log_error!("DLL Error: null pointer provided, cannot write error message");
            return MIRC_HALT;
        }

        if data.is_null() {
            log_error!("DLL Error: {}, but buffer pointer is null", self);
            return MIRC_HALT;
        }

        // Log the error with its full source chain for debugging
        if let Some(source) = self.source() {
            log_error!("DLL Error: {} (caused by: {})", self, source);

            // Log sensitive content if DEBUG flag is enabled for sensitive content
            #[cfg(debug_assertions)]
            if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
                #[cfg(debug_assertions)]
                log_debug!(
                    "Unified_Error: detailed error context - Error: {}, Source: {}",
                    self,
                    source
                );
            }

            // Log the full error chain if available
            let mut current_source = source.source();
            let mut depth = 1;
            while let Some(src) = current_source {
                log_error!("  [{}] caused by: {}", depth, src);
                current_source = src.source();
                depth += 1;
            }
        } else {
            log_error!("DLL error: {}", self);

            // Log sensitive content if DEBUG flag is enabled for sensitive content
            #[cfg(debug_assertions)]
            if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
                #[cfg(debug_assertions)]
                log_debug!("Unified_Error: error details - Error: {}", self);
            }
        }

        // Special handling for KeyExpired to trigger re-exchange
        if let DllError::KeyExpired { nickname } = self {
            // Log the expiration event for security monitoring
            #[cfg(debug_assertions)]
            log_debug!("Key expiration detected for user: {}", nickname);

            // Return a simple, parseable identifier instead of a full command.
            // The mIRC script will be responsible for handling this output.
            let mirc_identifier = format!("KEY_EXPIRED {}", nickname);

            if let Ok(cstring) = std::ffi::CString::new(mirc_identifier) {
                let buf_size = crate::dll_interface::get_buffer_size();
                let _ = buffer_utils::write_cstring_to_buffer(data, buf_size, &cstring);
            }
            return MIRC_COMMAND;
        }

        // Write error message to mIRC buffer (using thiserror-generated Display)
        let error_msg = self.to_string();
        match std::ffi::CString::new(error_msg) {
            Ok(cstring) => {
                let buf_size = crate::dll_interface::get_buffer_size();
                let _ = buffer_utils::write_cstring_to_buffer(data, buf_size, &cstring);
            }
            Err(e) => {
                log::error!("Failed to convert error message to CString: {}", e);
                // Fallback: write generic error
                let fallback = std::ffi::CString::new("Error: message contains null byte").unwrap();
                let buf_size = crate::dll_interface::get_buffer_size();
                let _ = buffer_utils::write_cstring_to_buffer(data, buf_size, &fallback);
            }
        }

        // Determine return code based on error severity
        match self {
            // Fatal errors that should halt execution
            DllError::NullPointer { .. }
            | DllError::Internal(_)
            | DllError::InvalidBufferSize { .. } => MIRC_HALT,

            // Non-fatal errors (command executed, but with error message)
            _ => MIRC_COMMAND,
        }
    }

    /// Create error with context helper
    pub fn with_context(self, context: &str) -> Self {
        match self {
            DllError::EncryptionFailed { cause, .. } => {
                DllError::EncryptionFailed { context: context.to_string(), cause }
            }
            DllError::DecryptionFailed { cause, .. } => {
                DllError::DecryptionFailed { context: context.to_string(), cause }
            }
            _ => self,
        }
    }
}

// ===== Conversions from existing error types =====

impl From<FishError> for DllError {
    fn from(err: FishError) -> Self {
        match err {
            FishError::ConfigError(msg) => DllError::ConfigMalformed(msg),
            FishError::CryptoError(msg) => {
                DllError::EncryptionFailed { context: "crypto operation".to_string(), cause: msg }
            }
            FishError::IoError(e) => {
                DllError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
            FishError::InvalidInput(msg) => {
                DllError::InvalidInput { param: "unknown".to_string(), reason: msg }
            }
            FishError::KeyNotFound(target) => DllError::KeyNotFound(target),
            FishError::DuplicateEntry(name) => DllError::DuplicateEntry(name),
            FishError::InvalidNetworkName(name) => DllError::InvalidNetwork(name),
            FishError::MalformedEntry(entry) => DllError::MalformedInput {
                input: entry,
                expected: "valid entry format".to_string(),
            },
            FishError::InvalidKeyLength(len) => DllError::KeyInvalid {
                reason: format!("invalid length: {} bytes (expected 32)", len),
            },
            FishError::AuthenticationFailed => DllError::AuthenticationFailed,
            FishError::NonceReuse => {
                DllError::ReplayAttackDetected { channel: "unknown".to_string() }
            }
            FishError::OversizedMessage => {
                DllError::MessageTooLarge { size: 0, limit: MAX_MESSAGE_SIZE }
            }
            FishError::InvalidCiphertext => DllError::DecryptionFailed {
                context: "ciphertext validation".to_string(),
                cause: "invalid format or corrupted data".to_string(),
            },
            FishError::Base64Error(e) => DllError::Base64(e),
            FishError::NullByteInString => {
                DllError::NullByteInString { context: "string conversion".to_string() }
            }
            FishError::NonAsciiCharacter(c) => {
                DllError::NonAsciiCharacter { char: c, context: "ASCII validation".to_string() }
            }
            FishError::KeyExpired(nick) => DllError::KeyExpired { nickname: nick },
        }
    }
}

impl From<BufferError> for DllError {
    fn from(err: BufferError) -> Self {
        match err {
            BufferError::NullPointer => {
                DllError::NullPointer { context: "buffer operation".to_string() }
            }
            BufferError::InvalidBufferSize => DllError::InvalidBufferSize { size: 0, required: 1 },
            BufferError::MessageTooLarge => {
                DllError::BufferWriteFailed("message exceeds buffer capacity".to_string())
            }
            BufferError::EncodingError => {
                DllError::Utf8Error { context: "buffer encoding".to_string() }
            }
        }
    }
}

impl From<&str> for DllError {
    fn from(err: &str) -> Self {
        DllError::InvalidInput { param: "data".to_string(), reason: err.to_string() }
    }
}

impl From<String> for DllError {
    fn from(err: String) -> Self {
        DllError::InvalidInput { param: "data".to_string(), reason: err }
    }
}

/// Result type for DLL operations
pub type DllResult<T> = Result<T, DllError>;

/// Helper macro for DLL functions with automatic error handling
///
/// # Example
///
/// ```rust
/// dll_function!(FiSH11_MyFunction, data, {
///     let input = parse_input(data)?;
///     let result = do_work(&input)?;
///     Ok(result)
/// });
/// ```
#[macro_export]
macro_rules! dll_function {
    ($name:ident, $data:ident, $body:block) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "system" fn $name(
            _m_wnd: *mut HWND,
            _a_wnd: *mut HWND,
            $data: *mut c_char,
            _parms: *mut c_char,
            _show: *mut BOOL,
            _nopause: *mut BOOL,
        ) -> c_int {
            use $crate::unified_error::DllResult;
            // Note: mIRC passes input parameters in the `_parms` pointer when using
            // the $dll(...) or .dll <dll> <func> <buffer|parms> calling forms.
            // The output buffer pointer is in `$data`. Ensure inner() receives
            // `_parms` so parsing functions read the caller-provided input.
            fn inner(_parms: *mut c_char, outbuf: *mut c_char) -> DllResult<String> {
                // Determine which pointer contains caller-supplied input. Some
                // mIRC calling modes place parameters in `_parms`, others in
                // the `data`/outbuf pointer. Try `_parms` first (the normal
                // convention), but fall back to `outbuf` if `_parms` is null or
                // empty.
                let input_ptr: *mut c_char = unsafe {
                    use std::ffi::CStr;

                    // Helper to check if a pointer has non-empty content
                    let is_non_empty = |ptr: *mut c_char| -> bool {
                        if ptr.is_null() {
                            return false;
                        }
                        match CStr::from_ptr(ptr).to_bytes().len() {
                            0 => false,
                            _ => true,
                        }
                    };

                    if is_non_empty(_parms) {
                        _parms
                    } else if is_non_empty(outbuf) {
                        outbuf
                    } else {
                        // Both empty or null, default to _parms
                        _parms
                    }
                };

                // Bind the identifier expected by existing function bodies
                #[allow(unused_variables)]
                let $data = input_ptr;
                $body
            }
            match inner(_parms, $data) {
                Ok(result) => {
                    unsafe {
                        let cstring = match std::ffi::CString::new(result) {
                            Ok(s) => s,
                            Err(e) => return DllError::from(e).to_mirc_response($data),
                        };

                        // Use the runtime-determined buffer size to avoid overwriting caller memory
                        let buf_size = $crate::dll_interface::get_buffer_size();
                        $crate::buffer_utils::write_cstring_to_buffer($data, buf_size, &cstring)
                            .ok();

                        // SECURITY: Zeroize the buffer after use
                        use zeroize::Zeroize;
                        let mut bytes = cstring.into_bytes_with_nul();
                        bytes.zeroize();
                    }
                    $crate::dll_interface::MIRC_COMMAND
                }
                Err(e) => unsafe { e.to_mirc_response($data) },
            }
        }
    };
}

/// Similar to dll_function! but returns MIRC_IDENTIFIER instead of MIRC_COMMAND.
/// Use this for functions that return data values (not mIRC commands to execute).
/// The caller will receive the returned string as a value in $result/$dll(...).
///
/// # Example
/// ```ignore
/// dll_function_identifier!(FiSH11_GetData, data, {
///     let input = parse_input(data)?;
///     let result = compute_result(&input)?;
///     Ok(result)
/// });
/// ```
#[macro_export]
macro_rules! dll_function_identifier {
    ($name:ident, $data:ident, $body:block) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "system" fn $name(
            _m_wnd: *mut HWND,
            _a_wnd: *mut HWND,
            $data: *mut c_char,
            _parms: *mut c_char,
            _show: *mut BOOL,
            _nopause: *mut BOOL,
        ) -> c_int {
            use $crate::unified_error::DllResult;
            use zeroize::Zeroize;
            // See comment in dll_function! : ensure inner() operates on the
            // `_parms` pointer which contains the caller-supplied input.
            fn inner(_parms: *mut c_char, outbuf: *mut c_char) -> DllResult<String> {
                let input_ptr: *mut c_char = unsafe {
                    use std::ffi::CStr;

                    // Helper to check if a pointer has non-empty content
                    let is_non_empty = |ptr: *mut c_char| -> bool {
                        if ptr.is_null() {
                            return false;
                        }
                        match CStr::from_ptr(ptr).to_bytes().len() {
                            0 => false,
                            _ => true,
                        }
                    };

                    if is_non_empty(_parms) {
                        _parms
                    } else if is_non_empty(outbuf) {
                        outbuf
                    } else {
                        // Both empty or null, default to _parms
                        _parms
                    }
                };

                #[allow(unused_variables)]
                let $data = input_ptr;
                $body
            }
            match inner(_parms, $data) {
                Ok(result) => {
                    unsafe {
                        let cstring = match std::ffi::CString::new(result) {
                            Ok(s) => s,
                            Err(e) => return DllError::from(e).to_mirc_response($data),
                        };

                        // Use the runtime-determined buffer size to avoid overwriting caller memory
                        let buf_size = $crate::dll_interface::get_buffer_size();

                        $crate::buffer_utils::write_cstring_to_buffer($data, buf_size, &cstring)
                            .ok();

                        // SECURITY: Zeroize the buffer after use to prevent plaintext/keys
                        // from lingering in memory.
                        let mut bytes = cstring.into_bytes_with_nul();
                        bytes.zeroize();
                    }
                    $crate::dll_interface::MIRC_IDENTIFIER
                }
                Err(e) => unsafe { e.to_mirc_response($data) },
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DllError::KeyNotFound("alice".to_string());
        assert_eq!(err.to_string(), "no encryption key found for 'alice'");

        let err = DllError::InvalidInput {
            param: "message".to_string(),
            reason: "empty string".to_string(),
        };

        assert_eq!(err.to_string(), "invalid input for 'message': empty string");
    }

    #[test]
    fn test_fish_error_conversion() {
        let fish_err = FishError::KeyNotFound("bob".to_string());
        let dll_err: DllError = fish_err.into();

        assert!(matches!(dll_err, DllError::KeyNotFound(_)));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let dll_err: DllError = io_err.into();

        assert!(matches!(dll_err, DllError::Io(_)));
    }

    #[test]
    fn test_key_expired_error() {
        let err = DllError::KeyExpired { nickname: "test_user".to_string() };
        assert_eq!(err.to_string(), "encryption key for 'test_user' has expired");
    }
}
