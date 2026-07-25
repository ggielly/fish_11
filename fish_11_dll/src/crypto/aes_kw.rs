//! NIST AES Key Wrap (RFC 3394) implementation.
//!
//! Provides industry-standard key wrapping for channel keys using AES-KW.
//! This replaces the ChaCha20-based key wrapping with a NIST-approved algorithm.

use aes_keywrap::Aes256KeyWrapAligned;

use crate::error::{FishError, Result};
use crate::utils::{base64_decode, base64_encode};

/// Wraps a 32-byte channel key using NIST AES-KW (RFC 3394).
///
/// # Arguments
/// * `channel_key` - The 32-byte channel key to wrap
/// * `wrapping_key` - The 32-byte key used for wrapping (pre-shared with recipient)
///
/// # Returns
/// Base64-encoded wrapped key (40 bytes: 8-byte header + 32-byte wrapped key)
pub fn wrap_key_aes_kw(channel_key: &[u8; 32], wrapping_key: &[u8; 32]) -> Result<String> {
    let wrapper = Aes256KeyWrapAligned::new(wrapping_key);
    
    let wrapped = wrapper.encapsulate(channel_key)
        .map_err(|e| FishError::CryptoError(format!("AES-KW wrap failed: {}", e)))?;
    
    Ok(base64_encode(&wrapped))
}

/// Unwraps a channel key using NIST AES-KW (RFC 3394).
///
/// # Arguments
/// * `wrapped_key_b64` - Base64-encoded wrapped key
/// * `wrapping_key` - The 32-byte key used for unwrapping
///
/// # Returns
/// The unwrapped 32-byte channel key
pub fn unwrap_key_aes_kw(wrapped_key_b64: &str, wrapping_key: &[u8; 32]) -> Result<[u8; 32]> {
    let wrapped_bytes = base64_decode(wrapped_key_b64)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 in wrapped key: {}", e)))?;
    
    // AES-KW produces output of key_len + 8 bytes (32 + 8 = 40 bytes)
    if wrapped_bytes.len() != 40 {
        return Err(FishError::CryptoError(format!(
            "Invalid wrapped key length: expected 40 bytes, got {}",
            wrapped_bytes.len()
        )));
    }
    
    let wrapper = Aes256KeyWrapAligned::new(wrapping_key);
    
    let unwrapped = wrapper.decapsulate(&wrapped_bytes)
        .map_err(|_| FishError::AuthenticationFailed)?;
    
    let mut result = [0u8; 32];
    result.copy_from_slice(&unwrapped);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate_random_bytes;

    #[test]
    fn test_wrap_unwrap_roundtrip() {
        let wrapping_key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let channel_key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        
        let wrapped = wrap_key_aes_kw(&channel_key, &wrapping_key).unwrap();
        let unwrapped = unwrap_key_aes_kw(&wrapped, &wrapping_key).unwrap();
        
        assert_eq!(channel_key, unwrapped);
    }

    #[test]
    fn test_unwrap_rejects_wrong_key() {
        let wrapping_key1: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let wrapping_key2: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let channel_key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        
        let wrapped = wrap_key_aes_kw(&channel_key, &wrapping_key1).unwrap();
        let result = unwrap_key_aes_kw(&wrapped, &wrapping_key2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_wrap_produces_correct_length() {
        let wrapping_key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let channel_key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        
        let wrapped = wrap_key_aes_kw(&channel_key, &wrapping_key).unwrap();
        let decoded = base64_decode(&wrapped).unwrap();
        
        // AES-KW output: 32 bytes key + 8 bytes header = 40 bytes
        assert_eq!(decoded.len(), 40);
    }

    #[test]
    fn test_unwrap_rejects_invalid_length() {
        let wrapping_key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let invalid_wrapped = base64_encode(&[0u8; 32]); // 32 bytes, not 40
        
        let result = unwrap_key_aes_kw(&invalid_wrapped, &wrapping_key);
        assert!(result.is_err());
    }
}
