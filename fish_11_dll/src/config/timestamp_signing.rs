//! Timestamp signing module for integrity protection.
//!
//! Provides HMAC-SHA256 signing of timestamps to prevent tampering
//! with key creation dates in the configuration file.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::error::{FishError, Result};
use crate::utils::base64_encode;

type HmacSha256 = Hmac<Sha256>;

/// Size of the HMAC-SHA256 signature in bytes
pub const TIMESTAMP_SIGNATURE_SIZE: usize = 32;

/// A signed timestamp: "YYYY-MM-DD HH:MM:SS.hmac_base64"
/// The HMAC signature is appended after a dot separator.
pub const SIGNED_TIMESTAMP_DELIMITER: char = '.';

/// Sign a timestamp with HMAC-SHA256 using the provided key.
///
/// # Arguments
/// * `timestamp` - The timestamp string to sign (e.g., "2025-01-15 10:30:00")
/// * `signing_key` - A 32-byte key used for HMAC signing
///
/// # Returns
/// A signed timestamp string in format: "timestamp.base64_hmac"
pub fn sign_timestamp(timestamp: &str, signing_key: &[u8; 32]) -> Result<String> {
    let mut mac = HmacSha256::new_from_slice(signing_key)
        .map_err(|e| FishError::CryptoError(format!("HMAC key error: {}", e)))?;
    
    mac.update(timestamp.as_bytes());
    let signature = mac.finalize().into_bytes();
    
    Ok(format!("{}{}{}", timestamp, SIGNED_TIMESTAMP_DELIMITER, base64_encode(&signature)))
}

/// Verify a signed timestamp.
///
/// # Arguments
/// * `signed_timestamp` - The signed timestamp string to verify
/// * `signing_key` - The 32-byte key used for HMAC signing
///
/// # Returns
/// The original timestamp string if verification succeeds, or an error.
pub fn verify_timestamp(signed_timestamp: &str, signing_key: &[u8; 32]) -> Result<String> {
    // Find the delimiter between timestamp and signature
    let delimiter_pos = signed_timestamp
        .rfind(SIGNED_TIMESTAMP_DELIMITER)
        .ok_or_else(|| FishError::CryptoError("Invalid signed timestamp format: missing delimiter".to_string()))?;
    
    let timestamp = &signed_timestamp[..delimiter_pos];
    let signature_b64 = &signed_timestamp[delimiter_pos + 1..];
    
    // Decode the signature
    let signature = crate::utils::base64_decode(signature_b64)
        .map_err(|e| FishError::CryptoError(format!("Invalid signature base64: {}", e)))?;
    
    if signature.len() != TIMESTAMP_SIGNATURE_SIZE {
        return Err(FishError::CryptoError(format!(
            "Invalid signature length: expected {} bytes, got {}",
            TIMESTAMP_SIGNATURE_SIZE,
            signature.len()
        )));
    }
    
    // Verify the HMAC
    let mut mac = HmacSha256::new_from_slice(signing_key)
        .map_err(|e| FishError::CryptoError(format!("HMAC key error: {}", e)))?;
    
    mac.update(timestamp.as_bytes());
    
    let mut signature_array = [0u8; TIMESTAMP_SIGNATURE_SIZE];
    signature_array.copy_from_slice(&signature);
    
    mac.verify_slice(&signature_array)
        .map_err(|_| FishError::AuthenticationFailed)?;
    
    Ok(timestamp.to_string())
}

/// Check if a timestamp string is signed (contains the delimiter).
pub fn is_signed_timestamp(s: &str) -> bool {
    // Check if there's a delimiter and it's not at the start
    if let Some(pos) = s.rfind(SIGNED_TIMESTAMP_DELIMITER) {
        // The signature part should be base64 (44 chars for 32 bytes with padding)
        let sig_part = &s[pos + 1..];
        // Base64 of 32 bytes = 44 characters (with padding)
        sig_part.len() >= 40 && sig_part.len() <= 48
    } else {
        false
    }
}

/// Extract the raw timestamp from a signed timestamp string.
pub fn extract_timestamp(signed_timestamp: &str) -> Result<String> {
    if is_signed_timestamp(signed_timestamp) {
        let pos = signed_timestamp
            .rfind(SIGNED_TIMESTAMP_DELIMITER)
            .unwrap();
        Ok(signed_timestamp[..pos].to_string())
    } else {
        // Not signed, return as-is (backward compatibility)
        Ok(signed_timestamp.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate_random_bytes;

    #[test]
    fn test_sign_and_verify_timestamp() {
        let key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let timestamp = "2025-01-15 10:30:00";
        
        let signed = sign_timestamp(timestamp, &key).unwrap();
        let verified = verify_timestamp(&signed, &key).unwrap();
        
        assert_eq!(verified, timestamp);
    }

    #[test]
    fn test_verify_rejects_tampered_timestamp() {
        let key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let timestamp = "2025-01-15 10:30:00";
        
        let signed = sign_timestamp(timestamp, &key).unwrap();
        
        // Tamper with the timestamp
        let tampered = format!("2025-01-15 10:30:01{}", &signed[signed.find('.').unwrap()..]);
        
        let result = verify_timestamp(&tampered, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_rejects_wrong_key() {
        let key1: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let key2: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let timestamp = "2025-01-15 10:30:00";
        
        let signed = sign_timestamp(timestamp, &key1).unwrap();
        let result = verify_timestamp(&signed, &key2);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_is_signed_timestamp() {
        let key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let timestamp = "2025-01-15 10:30:00";
        
        let signed = sign_timestamp(timestamp, &key).unwrap();
        
        assert!(is_signed_timestamp(&signed));
        assert!(!is_signed_timestamp(timestamp));
        assert!(!is_signed_timestamp("2025-01-15 10:30:00.something"));
    }

    #[test]
    fn test_extract_timestamp() {
        let key: [u8; 32] = generate_random_bytes(32).try_into().unwrap();
        let timestamp = "2025-01-15 10:30:00";
        
        let signed = sign_timestamp(timestamp, &key).unwrap();
        
        let extracted = extract_timestamp(&signed).unwrap();
        assert_eq!(extracted, timestamp);
        
        // Unsigned timestamp should be returned as-is
        let extracted_unsigned = extract_timestamp(timestamp).unwrap();
        assert_eq!(extracted_unsigned, timestamp);
    }
}
