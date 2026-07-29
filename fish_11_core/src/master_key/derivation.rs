//! Key derivation module for master key system
//!
//! Handles the derivation of the master key from a password using Argon2id,
//! and derivation of subkeys using HKDF with proper context separation.

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// Prefix for all HKDF contexts to ensure separation from other applications
const HKDF_PREFIX: &str = "fish11:";

/// Derive the master key from a password and salt using Argon2id
///
/// # Arguments
/// * `password` - The user's master password
/// * `salt` - The salt (if None, generates a new random salt)
///
/// # Returns
/// * `Result<([u8; 32], String), String>` - The derived 32-byte master key and the salt string
pub fn derive_master_key_with_salt(
    password: &str,
    salt: Option<&str>,
) -> Result<([u8; 32], String), String> {
    use argon2::password_hash::rand_core::OsRng;

    // Use provided salt or generate a new one
    let salt_string = if let Some(s) = salt {
        SaltString::from_b64(s).map_err(|e| format!("Invalid salt: {}", e))?
    } else {
        SaltString::generate(&mut OsRng)
    };

    // Create Argon2id instance with parameters
    // Use lighter params in test mode to avoid timeouts (~50ms vs ~500ms per derivation)
    #[cfg(not(test))]
    let (m_cost, t_cost, p_cost) = (65536, 3, 4); // 64 MB, 3 iterations, 4 lanes
    #[cfg(test)]
    let (m_cost, t_cost, p_cost) = (1024, 1, 1); // 1 MB, 1 iteration, 1 lane

    let params = Params::new(
        m_cost,   // memory cost
        t_cost,   // time cost
        p_cost,   // parallelism
        Some(32), // output length
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Hash the password
    let password_hash = argon2
        .hash_password(password.as_bytes(), salt_string.as_salt())
        .map_err(|e| format!("Argon2 hashing error: {}", e))?;

    // Extract the hash and convert to 32-byte array
    let hash = password_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    let mut key = [0u8; 32];

    key.copy_from_slice(hash_bytes);

    Ok((key, salt_string.to_string()))
}

/// Derive the master key from a password (generates new random salt)
///
/// # Arguments
/// * `password` - The user's master password
///
/// # Returns
/// * `Result<([u8; 32], String), String>` - The derived 32-byte master key and salt
pub fn derive_master_key(password: &str) -> Result<([u8; 32], String), String> {
    derive_master_key_with_salt(password, None)
}

/// Derive a subkey from the master key using HKDF
///
/// # Arguments
/// * `master_key` - The master key (32 bytes)
/// * `context` - The context string for HKDF (without prefix, e.g., "config", "logs")
///
/// # Returns
/// * `[u8; 32]` - The derived 32-byte subkey
pub fn derive_subkey(master_key: &[u8; 32], context: &str) -> [u8; 32] {
    let full_context = format!("{}{}", HKDF_PREFIX, context);

    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];

    hk.expand(full_context.as_bytes(), &mut okm)
        .expect("HKDF expansion failed - this should never happen with 32-byte output");
    okm
}

/// Derive the config KEK from master key
pub fn derive_config_kek(master_key: &[u8; 32]) -> [u8; 32] {
    derive_subkey(master_key, "config")
}

/// Derive the export KEK from master key
pub fn derive_export_kek(master_key: &[u8; 32]) -> [u8; 32] {
    derive_subkey(master_key, "export")
}

/// Derive a channel-specific key from config KEK
pub fn derive_channel_key(config_kek: &[u8; 32], channel: &str, generation: u32) -> [u8; 32] {
    let context = format!("channel:{}:gen:{}", channel, generation);
    derive_subkey(config_kek, &context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let password = "test_password_123";

        let (key1, salt1) = derive_master_key(password).expect("Failed to derive key");
        let (key2, salt2) = derive_master_key(password).expect("Failed to derive key again");

        // Keys should be different due to random salt
        assert_ne!(key1, key2);
        assert_ne!(salt1, salt2);
    }

    #[test]
    fn test_derive_master_key_with_same_salt() {
        let password = "test_password_123";
        let (key1, salt) = derive_master_key(password).expect("Failed to derive key");
        let (key2, _) = derive_master_key_with_salt(password, Some(&salt))
            .expect("Failed to derive key with salt");

        // Keys should be same with same password and salt
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_subkey() {
        let master_key = [1u8; 32]; // Use a fixed key for testing

        let subkey1 = derive_subkey(&master_key, "config");
        let subkey2 = derive_subkey(&master_key, "logs");

        // Subkeys should be different for different contexts
        assert_ne!(subkey1, subkey2);

        // Same context should produce same subkey
        let subkey3 = derive_subkey(&master_key, "config");
        assert_eq!(subkey1, subkey3);
    }

    #[test]
    fn test_hkdf_prefix() {
        let master_key = [1u8; 32];

        // Verify that fish11: prefix is used
        let config_kek = derive_config_kek(&master_key);
        let export_kek = derive_export_kek(&master_key);

        // Distinct contexts should produce distinct KEKs
        assert_ne!(config_kek, export_kek);
    }

    #[test]
    fn test_channel_key_generation() {
        let config_kek = [2u8; 32];
        let chan1_gen0 = derive_channel_key(&config_kek, "#test", 0);
        let chan1_gen1 = derive_channel_key(&config_kek, "#test", 1);
        let chan2_gen0 = derive_channel_key(&config_kek, "#other", 0);

        // Different generations should produce different keys

        assert_ne!(chan1_gen0, chan1_gen1);
        // Different channels should produce different keys
        assert_ne!(chan1_gen0, chan2_gen0);
    }
}
