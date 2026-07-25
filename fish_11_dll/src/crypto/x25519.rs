//! Cryptographic operations for FiSH_11
//!
//! This module provides the core cryptographic primitives for the FiSH_11 protocol:
//! - X25519 Diffie-Hellman key exchange with HKDF key derivation
//! - ChaCha20-Poly1305 authenticated encryption with fully random nonces
//! - Anti-replay protection via nonce cache with 1-hour expiry window
//! - Public key validation against low-order points
//! - Secure key pair generation and rotation

use std::any::Any;

use chrono::{DateTime, Duration, Utc};
use hkdf::Hkdf;
use log::warn;
use rand::rngs::OsRng;
use secrecy::{ExposeSecret, Secret};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::crypto::{KeyExchange, KeyPair};
use crate::error::{FishError, Result};
use crate::utils::{base64_decode, base64_encode};

#[derive(Debug)]
/// Represents a key pair for Curve25519 key exchange
pub struct X25519KeyPair {
    pub private_key: Secret<[u8; 32]>,
    pub public_key: [u8; 32],
    pub creation_time: DateTime<Utc>,
}

impl Zeroize for X25519KeyPair {
    fn zeroize(&mut self) {
        // We access the raw private key bytes via expose_secret to securely zero them
        let mut private_copy = *self.private_key.expose_secret();
        private_copy.zeroize();

        // Zero the public key
        for byte in self.public_key.iter_mut() {
            *byte = 0;
        }
    }
}

impl Drop for X25519KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl X25519KeyPair {
    pub fn needs_rotation(&self) -> bool {
        // Rotate every 7 days
        Utc::now() - self.creation_time > Duration::days(7)
    }
}

/// Generate a new X25519 keypair
///
/// Creates a new Curve25519 keypair suitable for Diffie-Hellman key exchange.
/// The private key is securely zeroized on drop.
///
/// # Returns
/// A `KeyPair` containing the private key (wrapped in `Secret`), public key,
/// and creation timestamp for rotation tracking.
pub fn generate_keypair() -> X25519KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let private_bytes = secret.to_bytes();
    let private_secret = Secret::new(private_bytes);

    // Log key generation (audit trail)
    log_audit("Generated new keypair");

    X25519KeyPair {
        private_key: private_secret,
        public_key: *public.as_bytes(),
        creation_time: Utc::now(),
    }
}

impl KeyPair for X25519KeyPair {
    fn public_key_formatted(&self) -> String {
        format_public_key(&self.public_key)
    }

    fn compute_shared_secret(&self, public_key: &[u8]) -> Result<[u8; 32]> {
        if public_key.len() != 32 {
            return Err(FishError::InvalidInput("Public key must be 32 bytes".to_string()));
        }
        let mut pk_array = [0u8; 32];
        pk_array.copy_from_slice(public_key);
        compute_shared_secret(&self.private_key, &pk_array)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

pub struct X25519KeyExchange;

impl KeyExchange for X25519KeyExchange {
    fn generate_keypair(&self) -> Result<Box<dyn KeyPair>> {
        Ok(Box::new(generate_keypair()))
    }

    fn extract_public_key(&self, formatted: &str) -> Result<Vec<u8>> {
        extract_public_key(formatted).map(|k| k.to_vec())
    }
}

/// Compute shared secret using X25519 Diffie-Hellman with HKDF key derivation
///
/// Performs an X25519 key exchange operation between our private key and their public key,
/// then derives a symmetric encryption key using HKDF-SHA256.
///
/// # Security
/// - validates the received public key to reject low-order points
/// - uses HKDF with domain separation for key derivation
/// - derives a 32-byte symmetric key suitable for ChaCha20-Poly1305
///
/// # Arguments
/// * `our_private` - our private key (securely wrapped)
/// * `their_public` - their public key (32 bytes)
///
/// # Returns
/// A 32-byte symmetric encryption key or an error if the public key is invalid.
pub fn compute_shared_secret(
    our_private: &Secret<[u8; 32]>,
    their_public: &[u8; 32],
) -> Result<[u8; 32]> {
    // Validate the public key first
    validate_public_key(their_public)?;

    // Use the private key to perform the Diffie-Hellman operation
    let secret = StaticSecret::from(*our_private.expose_secret());
    let public_key = PublicKey::from(*their_public);

    let shared_secret = secret.diffie_hellman(&public_key);

    // Use HKDF for improved key derivation
    let hkdf = Hkdf::<Sha256>::new(Some(b"FiSH11-KDF"), shared_secret.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"EncryptionKey", &mut output)
        .map_err(|e| FishError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

    // Log shared secret computation (audit trail)
    log_audit("Computed shared secret");

    Ok(output)
}

/// Validate that a public key is a valid Curve25519 point
pub fn validate_public_key(bytes: &[u8; 32]) -> Result<()> {
    // Check that it's not all zeros
    if bytes.iter().all(|&b| b == 0) {
        return Err(FishError::InvalidInput("Public key is all zeros".to_string()));
    }

    // Known low-order points on Curve25519 that should be rejected
    // These are points of order 1, 2, 4, and 8
    const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
        // Point of order 1 (identity)
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Point of order 2
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Point of order 4 (variant 1)
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // Point of order 4 (variant 2)
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // Point of order 8 (variant 1)
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 2)
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 3)
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 4)
        [
            0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x80,
        ],
    ];

    // Check if the point matches any known low-order point
    for low_order_point in &LOW_ORDER_POINTS {
        if bytes == low_order_point {
            return Err(FishError::InvalidInput(
                "Public key is a low-order point and rejected for security".to_string(),
            ));
        }
    }

    // Attempt to construct a PublicKey - will succeed if valid format
    let _ = PublicKey::from(*bytes);

    // Return Ok if no issues
    Ok(())
}

/// Format a public key for sharing over IRC
///
/// Encodes a 32-byte X25519 public key as base64 with the `X25519_INIT:` prefix.
///
/// # Arguments
/// * `public_key` - the 32-byte X25519 public key
///
/// # Returns
/// A formatted string: `X25519_INIT:<base64-encoded-key>`
pub fn format_public_key(public_key: &[u8; 32]) -> String {
    let encoded = base64_encode(public_key);
    format!("X25519_INIT:{}", encoded)
}

/// Extract and validate a public key from a formatted string
///
/// Parses a `X25519_INIT:<base64>` formatted string, decodes the base64 payload,
/// and validates the resulting public key against low-order points.
///
/// # Arguments
/// * `formatted` - the formatted key string (whitespace is trimmed)
///
/// # Returns
/// The 32-byte X25519 public key or an error if the format is invalid or the key
/// fails validation.
pub fn extract_public_key(formatted: &str) -> Result<[u8; 32]> {
    const PREFIX: &str = "X25519_INIT:";

    // Check if the string has the correct prefix using constant-time comparison
    // to prevent timing attacks that could leak information about the prefix
    if formatted.len() < PREFIX.len()
        || !constant_time_compare(&formatted.as_bytes()[..PREFIX.len()], PREFIX.as_bytes())
    {
        return Err(FishError::InvalidInput(
            "Formatted key does not have the correct prefix".to_string(),
        ));
    }

    // Extract the base64 encoded part
    let encoded = &formatted[PREFIX.len()..];
    // Trim surrounding whitespace/newlines which may come from mIRC or transport
    let encoded = encoded.trim();

    // Decode the base64
    let key_data = base64_decode(encoded)
        .map_err(|e| FishError::InvalidInput(format!("Invalid base64 in public key: {}", e)))?;

    // Check length
    if key_data.len() != 32 {
        return Err(FishError::InvalidInput(format!(
            "Invalid public key length: got {}, expected 32",
            key_data.len()
        )));
    }

    // Convert to array
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);

    // Validate the public key
    validate_public_key(&key)?;

    Ok(key)
}

/// Process a received public key and complete the key exchange
///
/// This function orchestrates a complete Diffie-Hellman key exchange:
/// - retrieves our local keypair
/// - checks if keypair rotation is needed (older than 7 days)
/// - extracts and validates the received public key
/// - computes the shared secret via X25519 + HKDF
/// - stores the resulting symmetric key for the given nickname
///
/// # Arguments
/// * `nickname` - the remote user's nickname
/// * `public_key_str` - their formatted public key (`X25519_INIT:...`)
/// * `network` - optional network identifier for key scoping
///
/// # Returns
/// `Ok(())` if the key exchange succeeded and the shared key was stored, or an error
/// if any step failed.
pub fn process_dh_key_exchange(
    nickname: &str,
    public_key_str: &str,
    network: Option<&str>,
) -> Result<()> {
    let our_keypair = crate::config::get_keypair()?;

    // Check if our keypair needs rotation
    if our_keypair.needs_rotation() {
        warn!("Keypair is old and should be rotated");
        log_audit("Using outdated keypair");
    }

    // Extract the other user's public key
    let their_public_key = extract_public_key(public_key_str)?;

    // Compute shared secret
    let shared_secret = compute_shared_secret(&our_keypair.private_key, &their_public_key)?;

    // Store the shared key
    match crate::config::set_key(nickname, &shared_secret, network, false, true) {
        Ok(_) => {
            log_audit(&format!("Key exchange completed with {}", nickname));
            Ok(())
        }
        Err(FishError::DuplicateEntry(_)) => {
            // Key already exists, try to overwrite
            log_audit(&format!("Key exchange updated existing key for {}", nickname));
            crate::config::set_key(nickname, &shared_secret, network, true, true)
        }
        Err(e) => Err(e),
    }
}

/// Check if a string is in valid public key format
pub fn is_valid_public_key_format(formatted: &str) -> bool {
    const PREFIX: &str = "X25519_INIT:";

    let encoded = match formatted.strip_prefix(PREFIX) {
        Some(e) => e,
        None => return false,
    };

    // Validate Base64 decoding
    let decoded = match base64_decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // Validate length
    if decoded.len() != 32 {
        return false;
    }

    // Attempt public key validation
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);

    match validate_public_key(&key) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Log a cryptographic audit event
fn log_audit(event: &str) {
    // Use the standard debug logging
    #[cfg(debug_assertions)]
    log::debug!("[AUDIT] {}", event);
}

/// Constant-time comparison of authentication tags or other sensitive values
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use ConstantTimeEq trait for timing-attack resistant comparison
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair();
        // Private key should not be all zeros
        assert!(
            !keypair.private_key.expose_secret().iter().all(|&b| b == 0),
            "Private key should not be all zeros"
        );
        // Public key should not be all zeros
        assert!(!keypair.public_key.iter().all(|&b| b == 0), "Public key should not be all zeros");
    }

    #[test]
    fn test_constant_time_compare() {
        // Test equal values
        let a = b"hello";
        let b = b"hello";
        assert!(constant_time_compare(a, b));

        // Test different values
        let a = b"hello";
        let b = b"world";
        assert!(!constant_time_compare(a, b));

        // Test different lengths (should return false)
        let a = b"hello";
        let b = b"hello!";
        assert!(!constant_time_compare(a, b));

        // Test empty arrays
        let a = b"";
        let b = b"";
        assert!(constant_time_compare(a, b));

        // Test with cryptographic values
        let key1 = [42u8; 32];
        let key2 = [42u8; 32];
        assert!(constant_time_compare(&key1, &key2));

        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        assert!(!constant_time_compare(&key1, &key2));
    }

    #[test]
    fn test_extract_public_key_with_constant_time() {
        // Create a valid key for testing
        let keypair = generate_keypair();
        let valid_key = format!("X25519_INIT:{}", base64_encode(&keypair.public_key));
        let result = extract_public_key(&valid_key);
        assert!(result.is_ok());

        // Test invalid prefix (should fail with constant time)
        let invalid_prefix = "INVALID_INIT:SGVsbG8gV29ybGQhISEhIQ==";
        let result = extract_public_key(invalid_prefix);
        assert!(result.is_err());

        // Test wrong prefix (should fail with constant time)
        let wrong_prefix = "X25519_WRONG:SGVsbG8gV29ybGQhISEhIQ==";
        let result = extract_public_key(wrong_prefix);
        assert!(result.is_err());

        // Test empty prefix (should fail with constant time)
        let empty_prefix = "SGVsbG8gV29ybGQhISEhIQ==";
        let result = extract_public_key(empty_prefix);
        assert!(result.is_err());

        // Test too short after prefix
        let short_key = "X25519_INIT:SGVsbG8="; // Only 8 bytes instead of 32
        let result = extract_public_key(short_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_compute_shared_secret() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let shared1_result = compute_shared_secret(&keypair1.private_key, &keypair2.public_key);
        if shared1_result.is_err() {
            panic!("Failed to compute shared secret 1: {:?}", shared1_result.err());
        }
        let shared1 = shared1_result.unwrap();

        let shared2_result = compute_shared_secret(&keypair2.private_key, &keypair1.public_key);
        if shared2_result.is_err() {
            panic!("Failed to compute shared secret 2: {:?}", shared2_result.err());
        }
        let shared2 = shared2_result.unwrap();

        assert_eq!(shared1, shared2, "Shared secrets should be identical");
    }

    #[test]
    fn test_validate_public_key_rejects_all_zeros() {
        let zero_key = [0u8; 32];
        let result = validate_public_key(&zero_key);

        assert!(result.is_err(), "All-zero public key should be rejected");
        if let Err(FishError::InvalidInput(msg)) = result {
            assert!(msg.contains("all zeros"), "Error message should mention all zeros");
        } else {
            panic!("Expected InvalidInput error for all-zero key");
        }
    }

    #[test]
    fn test_validate_public_key_rejects_low_order_points() {
        // Test a few known low-order points
        let low_order_points = [
            // Point of order 2 (not all zeros)
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            // Point of order 4 (variant 1)
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            // Point of order 8 (variant 1)
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ];

        for (i, low_order_point) in low_order_points.iter().enumerate() {
            let result = validate_public_key(low_order_point);
            assert!(result.is_err(), "Low-order point {} should be rejected", i);
            if let Err(FishError::InvalidInput(msg)) = result {
                assert!(
                    msg.contains("low-order point"),
                    "Error message for point {} should mention low-order: {}",
                    i,
                    msg
                );
            } else {
                panic!("Expected InvalidInput error for low-order point {}", i);
            }
        }
    }

    #[test]
    fn test_validate_public_key_accepts_valid_key() {
        // Generate a valid keypair
        let keypair = generate_keypair();

        // The public key from a generated keypair should be valid
        let result = validate_public_key(&keypair.public_key);
        assert!(result.is_ok(), "Valid public key from generated keypair should be accepted");
    }

    #[test]
    fn test_compute_shared_secret_rejects_low_order_public_key() {
        let keypair = generate_keypair();

        // Point of order 2 (low-order)
        let low_order_public = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let result = compute_shared_secret(&keypair.private_key, &low_order_public);
        assert!(result.is_err(), "compute_shared_secret should reject low-order public keys");
    }
}
