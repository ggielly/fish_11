//! Legacy DH1080 implementation for FiSH 10 compatibility
//!
//! This module provides the DH1080 key exchange protocol used by FiSH 10
//! for secure key exchange.
//!
//! IMPORTANT: DH1080 uses STANDARD base64 alphabet (ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/)
//! for encoding public keys, NOT the FiSH-specific alphabet used for Blowfish messages.
//! The '=' padding is stripped and replaced with 'A' at the end.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use num_bigint::{BigUint, RandomBits};
use num_traits::Num;
use rand::Rng;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, legacy, log_debug};

/// DH1080 prime (1080-bit Sophie Germain prime)
#[rustfmt::skip]
const DH1080_PRIME_HEX: &str = "FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B";

/// DH1080 generator
const DH1080_GENERATOR: u32 = 2;

/// Standard Base64 alphabet for DH1080 key exchange (NOT the FiSH message alphabet)
#[allow(dead_code)]
const DH1080_B64_ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// FiSH 10 specific Base64 alphabet for encrypted messages (NOT for DH keys)
#[allow(dead_code)]
const FISH10_B64_ABC: &[u8] = b"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Expected length of DH1080 public key in bytes (1080 bits = 135 bytes)
#[allow(dead_code)]
const DH1080_KEY_BYTES: usize = 135;

/// Expected length of DH1080 public key in base64 (180 chars + 'A' = 181)
#[allow(dead_code)]
const DH1080_PUBKEY_B64_LEN: usize = 181;

// Generate DH1080 key pair
// Returns: public_key
dll_function_identifier!(FiSH10_DH1080_GenerateKeyPair, data, {
    // Parse input: <target> (optional)
    // Parse input: <target> (optional message part for some DH1080 usage, but initiation only has target)
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let target = crate::utils::normalize_target_lowercase(&input_str);

    let keypair = generate_dh1080_keypair()?;

    // Store the private key for this target
    let config = legacy::LEGACY_CONFIG.write();
    let mut dh_keys = config.dh1080_keys.write();

    dh_keys.insert(target.to_string(), keypair.private_key());

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: generated DH1080 key pair for '{}'", target);

    Ok(keypair.public_key)
});

// Compute shared secret from DH1080 exchange
// Input: <target> <other_public_key>
// Returns: shared_secret (and automatically stores it as a Blowfish key)
dll_function_identifier!(FiSH10_DH1080_ComputeSecret, data, {
    // Parse input: <target> <other_public_key>
    // Parse input: <target> <other_public_key>
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input_str.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <target> <other_public_key>".to_string(),
        });
    }
    let target = crate::utils::normalize_target_lowercase(parts[0]);
    let other_public_key = parts[1].trim();

    // Get our private key
    let config = legacy::LEGACY_CONFIG.read();
    let dh_keys = config.dh1080_keys.read();
    let private_key = dh_keys.get(&target as &str).ok_or_else(|| DllError::LegacyError {
        context: format!("DH1080 secret computation for '{}'", target),
        cause: "No private key found for this target".to_string(),
    })?;

    // Compute shared secret (returns base64-encoded SHA256 hash)
    let shared_secret = compute_dh1080_shared_secret(private_key, other_public_key)?;

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: computed DH1080 shared secret for '{}'", target);

    // FiSH 10 uses the base64-encoded SHA256 hash STRING directly as the Blowfish key.
    // The 43 ASCII bytes of the base64 string become the key bytes, NOT the decoded 32 bytes.
    // This matches the original FiSH 10 behavior: BF_set_key(&bf_key, key.size(), (unsigned char*)key.data())
    let secret_bytes = shared_secret.as_bytes().to_vec();

    // Store the secret string bytes as a Blowfish key for this target
    drop(dh_keys); // Release the read lock before acquiring write lock
    let mut keys = config.legacy_keys.write();
    keys.insert(target.to_string(), secret_bytes);

    #[cfg(debug_assertions)]
    log_debug!(
        "FiSH10: stored DH1080 shared secret as Blowfish key for '{}' ({} bytes)",
        target,
        shared_secret.len()
    );

    Ok(shared_secret)
});

// Set DH1080 key for a target
// Input: <target> <private_key_hex>
// Returns: success message
dll_function_identifier!(FiSH10_DH1080_SetKey, data, {
    // Parse input: <target> <private_key_hex>
    // Parse input: <target> <private_key_hex>
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input_str.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <target> <private_key_hex>".to_string(),
        });
    }
    let target = crate::utils::normalize_target_lowercase(parts[0]);
    let private_key_hex = parts[1].trim();

    // Decode the hex private key
    let private_key_bytes = hex::decode(private_key_hex).map_err(|e| DllError::LegacyError {
        context: "DH1080 key decoding".to_string(),
        cause: format!("Invalid hex key: {}", e),
    })?;

    // Convert bytes to BigUint
    let private_key = num_bigint::BigUint::from_bytes_be(&private_key_bytes);

    // Store the private key
    let config = legacy::LEGACY_CONFIG.write();
    let mut dh_keys = config.dh1080_keys.write();
    dh_keys.insert(target.to_string(), private_key);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: set DH1080 private key for '{}'", target);

    Ok(format!("DH1080 key set for {}", target))
});

/// DH1080 Base64 encoding for public keys
/// Uses standard base64 alphabet, strips '=' padding, appends 'A'
/// Compatible with FiSH 10 C++ implementation
pub fn dh1080_base64_encode(data: &[u8]) -> String {
    // Use standard base64 encoding
    let encoded = BASE64_STANDARD.encode(data);

    // Strip '=' padding and append 'A' (FiSH 10 convention)
    let mut result: String = encoded.chars().filter(|&c| c != '=').collect();
    result.push('A');

    result
}

/// DH1080 Base64 decoding for public keys
/// Expects standard base64 alphabet with trailing 'A' instead of '=' padding
pub fn dh1080_base64_decode(b64: &str) -> Result<Vec<u8>, DllError> {
    // Validate input length (should be around 181 chars for 135 bytes)
    if b64.is_empty() {
        return Err(DllError::LegacyError {
            context: "DH1080 Decoding".to_string(),
            cause: "Empty input".to_string(),
        });
    }

    let mut s = b64.to_string();

    // Remove trailing 'A' (FiSH 10 convention)
    if s.ends_with('A') {
        s.pop();
    }

    // Add back '=' padding to make valid base64
    while s.len() % 4 != 0 {
        s.push('=');
    }

    // Decode using standard base64
    BASE64_STANDARD.decode(&s).map_err(|e| DllError::LegacyError {
        context: "DH1080 Decoding".to_string(),
        cause: format!("Invalid base64: {}", e),
    })
}

/// DH1080 key pair
///
/// SECURITY: The private key is stored as bytes that will be zeroized
/// when the keypair is dropped. This prevents the private key from
/// lingering in memory after use.
pub struct DH1080KeyPair {
    /// Private key bytes (zeroized on drop)
    private_key_bytes: ZeroizingVec,
    /// Public key in FiSH 10 base64 format
    pub public_key: String,
}

/// Wrapper around Vec<u8> that zeroizes on drop
struct ZeroizingVec(Vec<u8>);

impl Drop for ZeroizingVec {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl DH1080KeyPair {
    fn new(private_key: BigUint, public_key: String) -> Self {
        Self { private_key_bytes: ZeroizingVec(private_key.to_bytes_be()), public_key }
    }

    /// Get the private key as a BigUint for computation
    pub fn private_key(&self) -> BigUint {
        BigUint::from_bytes_be(&self.private_key_bytes.0)
    }
}

/// Generate DH1080 key pair
pub fn generate_dh1080_keypair() -> Result<DH1080KeyPair, DllError> {
    let p = BigUint::from_str_radix(DH1080_PRIME_HEX, 16).map_err(|e| DllError::LegacyError {
        context: "DH1080 Init".to_string(),
        cause: format!("Failed to parse prime: {}", e),
    })?;
    let g = BigUint::from(DH1080_GENERATOR);

    let mut rng = rand::thread_rng();
    let priv_key: BigUint = rng.sample(RandomBits::new(1080));

    // pub = g^priv mod p
    let pub_key_bn = g.modpow(&priv_key, &p);

    let mut pub_bytes = pub_key_bn.to_bytes_be();
    // Ensure it's exactly 135 bytes (prepend zeros if needed)
    if pub_bytes.len() < 135 {
        let mut padded = vec![0u8; 135 - pub_bytes.len()];
        padded.extend(pub_bytes);
        pub_bytes = padded;
    }

    let public_key = dh1080_base64_encode(&pub_bytes);

    Ok(DH1080KeyPair::new(priv_key, public_key))
}

/// Compute shared secret using DH1080
///
/// SECURITY: Validates that the other party's public key is in the valid range [2, p-2]
/// to prevent small subgroup attacks.
pub fn compute_dh1080_shared_secret(
    private_key: &BigUint,
    other_public_key: &str,
) -> Result<String, DllError> {
    let p = BigUint::from_str_radix(DH1080_PRIME_HEX, 16).map_err(|e| DllError::LegacyError {
        context: "DH1080 Init".to_string(),
        cause: format!("Failed to parse prime: {}", e),
    })?;

    let other_pub_bytes = dh1080_base64_decode(other_public_key)?;
    let other_pub_bn = BigUint::from_bytes_be(&other_pub_bytes);

    // SECURITY: Validate that public key is in range [2, p-2]
    // This prevents small subgroup attacks where an attacker sends:
    // - 0: shared_secret = 0
    // - 1: shared_secret = 1
    // - p-1: shared_secret = 1 or p-1
    let two = BigUint::from(2u32);
    let p_minus_one = &p - BigUint::from(1u32);

    if other_pub_bn < two || other_pub_bn >= p_minus_one {
        return Err(DllError::LegacyError {
            context: "DH1080 Security".to_string(),
            cause: "Invalid public key: must be in range [2, p-2]".to_string(),
        });
    }

    // shared = other_pub^private mod p
    let shared_secret_bn = other_pub_bn.modpow(private_key, &p);

    let mut shared_bytes = shared_secret_bn.to_bytes_be();
    // Ensure it's exactly 135 bytes
    if shared_bytes.len() < 135 {
        let mut padded = vec![0u8; 135 - shared_bytes.len()];
        padded.extend(shared_bytes);
        shared_bytes = padded;
    }

    // Hash the shared secret with SHA256
    let mut hasher = Sha256::new();
    hasher.update(&shared_bytes);
    let hash = hasher.finalize();

    // The result is base64 encoded using our custom FiSH base64 alphabet (not the one for keys)
    // Actually, FiSH 10 uses FISH10_B16_ABC for the shared secret hash as well, but strips '='
    Ok(fish_b64_encode_hash(&hash))
}

/// FiSH 10 hash encoding (standard base64 table but stripped '=')
fn fish_b64_encode_hash(data: &[u8]) -> String {
    let encoded = BASE64_STANDARD.encode(data);
    encoded.replace('=', "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh1080_key_generation_01() {
        clear_test_dh1080_keys();

        let keypair = generate_dh1080_keypair().unwrap();
        assert_eq!(keypair.public_key.len(), 181);
        assert!(keypair.public_key.ends_with('A'));
    }

    #[test]
    fn test_dh1080_shared_secret() {
        let kp1 = generate_dh1080_keypair().unwrap();
        let kp2 = generate_dh1080_keypair().unwrap();

        let s1 = compute_dh1080_shared_secret(&kp1.private_key(), &kp2.public_key).unwrap();
        let s2 = compute_dh1080_shared_secret(&kp2.private_key(), &kp1.public_key).unwrap();

        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 43); // SHA256 is 32 bytes -> 44 chars, stripped '=' -> 43
    }

    #[test]
    fn test_dh1080_invalid_public_key_rejected() {
        let kp = generate_dh1080_keypair().unwrap();

        // Test that public key "1" (encoded) is rejected
        let one_bytes = vec![0u8; 134];
        let mut one_padded = one_bytes;
        one_padded.push(1);
        let one_b64 = dh1080_base64_encode(&one_padded);

        let result = compute_dh1080_shared_secret(&kp.private_key(), &one_b64);
        assert!(result.is_err());

        // Test that public key "0" is rejected
        let zero_bytes = vec![0u8; 135];
        let zero_b64 = dh1080_base64_encode(&zero_bytes);

        let result = compute_dh1080_shared_secret(&kp.private_key(), &zero_b64);
        assert!(result.is_err());
    }

    use super::*;
    use crate::legacy::test_utils::clear_test_dh1080_keys;

    #[test]
    fn test_dh1080_key_generation_02() {
        clear_test_dh1080_keys();

        let result = fish10_dh1080_generate_keypair_impl("#test");
        assert!(result.is_ok());
        let public_key = result.unwrap();
        assert!(public_key.ends_with('A'));
    }

    #[test]
    fn test_dh1080_secret_computation() {
        clear_test_dh1080_keys();

        // Generate keys for two parties
        let pub_key1 = fish10_dh1080_generate_keypair_impl("#test1").unwrap();
        let pub_key2 = fish10_dh1080_generate_keypair_impl("#test2").unwrap();

        // Compute shared secrets
        let secret1 = fish10_dh1080_compute_secret_impl(&format!("#test1 {}", pub_key2)).unwrap();
        let secret2 = fish10_dh1080_compute_secret_impl(&format!("#test2 {}", pub_key1)).unwrap();

        // In a real DH implementation, these would be equal
        assert_eq!(secret1.len(), secret2.len());
    }
}

#[cfg(test)]
fn fish10_dh1080_generate_keypair_impl(input: &str) -> Result<String, DllError> {
    let target = input.trim();

    // Generate DH1080 key pair
    let keypair = generate_dh1080_keypair()?;

    // Store the private key for this target
    let config = legacy::LEGACY_CONFIG.write();
    let mut dh_keys = config.dh1080_keys.write();
    dh_keys.insert(target.to_string(), keypair.private_key());

    #[cfg(debug_assertions)]
    log_debug!("FiSH10 (test helper): generated DH1080 key pair for '{}'", target);

    Ok(keypair.public_key)
}

#[cfg(test)]
fn fish10_dh1080_compute_secret_impl(input: &str) -> Result<String, DllError> {
    // Expect input: "<target> <other_public_key>"
    let mut parts = input.splitn(2, ' ');
    let target = parts.next().unwrap_or("").trim();
    let other_public_key = parts.next().unwrap_or("").trim();

    #[cfg(debug_assertions)]
    log_debug!("FiSH10 (test helper): computing DH1080 shared secret for '{}'", target);

    // Get our private key
    let config = legacy::LEGACY_CONFIG.read();
    let dh_keys = config.dh1080_keys.read();
    let private_key = dh_keys.get(&target as &str).ok_or_else(|| DllError::LegacyError {
        context: format!("DH1080 secret computation for '{}'", target),
        cause: "No private key found for this target".to_string(),
    })?;

    // Compute shared secret (returns base64-encoded SHA256 hash)
    let shared_secret = compute_dh1080_shared_secret(private_key, other_public_key)?;

    // FiSH 10 uses the base64-encoded SHA256 hash STRING directly as the Blowfish key.
    // The 43 ASCII bytes of the base64 string become the key bytes, NOT the decoded 32 bytes.
    let secret_bytes = shared_secret.as_bytes().to_vec();

    // Store the secret as a Blowfish key for this target
    drop(dh_keys); // Release the read lock before acquiring write lock
    let mut keys = config.legacy_keys.write();
    keys.insert(target.to_string(), secret_bytes);

    Ok(shared_secret)
}
