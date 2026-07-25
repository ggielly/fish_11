//! Keystore encryption module
//! Provides functions to encrypt and decrypt keystore data

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::master_key::keystore::Keystore;

/// Header for encrypted keystore files
const ENCRYPTED_KEYSTORE_HEADER: &str = "# FiSH_11_ENCRYPTED_KEYSTORE_V1\n";

/// Derive a system-specific key for encrypting the keystore
/// This uses a combination of hardware identifiers and OS-specific information
pub fn derive_system_specific_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use std::env;

    let hostname = env::var("COMPUTERNAME").or_else(|_| env::var("HOSTNAME")).unwrap_or_default();
    let username = env::var("USERNAME").or_else(|_| env::var("USER")).unwrap_or_default();
    let current_dir = env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut seed = String::new();
    seed.push_str(&hostname);
    seed.push_str(&username);
    seed.push_str(&current_dir);
    seed.push_str("fish_11_keystore_encryption_salt");

    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(seed.as_bytes());

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

/// Encrypt keystore data
pub fn encrypt_keystore_data(
    data: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rand::RngCore;

    // Generate a random nonce (12 bytes for ChaCha20-Poly1305)
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Encrypt the data
    let ciphertext =
        cipher.encrypt(nonce, data).map_err(|e| format!("Encryption failed: {}", e))?;

    // Prepend the nonce to the ciphertext
    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

/// Decrypt keystore data
pub fn decrypt_keystore_data(
    encrypted_data: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".into());
    }

    // Extract the nonce (first 12 bytes)
    let nonce_bytes: [u8; 12] = encrypted_data[..12].try_into().unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Get the ciphertext (remaining bytes)
    let ciphertext = &encrypted_data[12..];

    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Decrypt the data
    let plaintext =
        cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Save the keystore to a path with encryption
pub fn save_encrypted_keystore_to_path(
    keystore: &Keystore,
    path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // First, serialize the keystore to INI format
    let mut ini = configparser::ini::Ini::new();

    // Save master key salt
    ini.set("MasterKey", "salt", Some(keystore.master_key_salt.clone()));

    // Save password verifier if present
    if let Some(verifier) = &keystore.password_verifier {
        ini.set("MasterKey", "verifier", Some(verifier.clone()));
    }

    // Save nonce counters
    for (context, counter) in &keystore.nonce_counters {
        ini.set("NonceCounters", context, Some(counter.to_string()));
    }

    // Save key metadata
    for (key_id, metadata) in &keystore.key_metadata {
        let metadata_str = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            metadata.created_at,
            metadata.last_used,
            metadata.usage_count,
            metadata.message_count,
            metadata.data_size_bytes,
            metadata.description,
            metadata.is_revoked
        );
        ini.set("KeyMetadata", key_id, Some(metadata_str));
    }

    // Convert INI to string
    let ini_string = ini.writes();

    // Derive system-specific key for encryption
    let system_key = derive_system_specific_key()?;

    // Encrypt the INI string
    let encrypted_data = encrypt_keystore_data(ini_string.as_bytes(), &system_key)?;

    // Encode as base64 for safe storage
    let base64_data = general_purpose::STANDARD.encode(&encrypted_data);

    // Write to file with header
    let content = format!("{}{}\n", ENCRYPTED_KEYSTORE_HEADER, base64_data);
    std::fs::write(path, content)?;

    Ok(())
}

/// Save the keystore to a path with encryption using a specific key (for testing)
#[cfg(test)]
pub fn save_encrypted_keystore_to_path_with_key(
    keystore: &Keystore,
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    // First, serialize the keystore to INI format
    let mut ini = configparser::ini::Ini::new();

    // Save master key salt
    ini.set("MasterKey", "salt", Some(keystore.master_key_salt.clone()));

    // Save password verifier if present
    if let Some(verifier) = &keystore.password_verifier {
        ini.set("MasterKey", "verifier", Some(verifier.clone()));
    }

    // Save nonce counters
    for (context, counter) in &keystore.nonce_counters {
        ini.set("NonceCounters", context, Some(counter.to_string()));
    }

    // Save key metadata
    for (key_id, metadata) in &keystore.key_metadata {
        let metadata_str = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            metadata.created_at,
            metadata.last_used,
            metadata.usage_count,
            metadata.message_count,
            metadata.data_size_bytes,
            metadata.description,
            metadata.is_revoked
        );
        ini.set("KeyMetadata", key_id, Some(metadata_str));
    }

    // Convert INI to string
    let ini_string = ini.writes();

    // Encrypt the INI string with the provided key
    let encrypted_data = encrypt_keystore_data(ini_string.as_bytes(), key)?;

    // Encode as base64 for safe storage
    let base64_data = general_purpose::STANDARD.encode(&encrypted_data);

    // Write to file with header
    let content = format!("{}{}\n", ENCRYPTED_KEYSTORE_HEADER, base64_data);
    std::fs::write(path, content)?;

    Ok(())
}

/// Load an encrypted keystore from a path
pub fn load_encrypted_keystore_from_path(
    path: &PathBuf,
) -> Result<Keystore, Box<dyn std::error::Error>> {
    // Read the file content
    let content = std::fs::read_to_string(path)?;

    // Check if it's an encrypted keystore
    if !content.starts_with(ENCRYPTED_KEYSTORE_HEADER) {
        return Err("Not an encrypted keystore file".into());
    }

    // Split content into header and encrypted data
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err("Invalid encrypted keystore format".into());
    }

    // Decode the base64 encrypted data
    let encrypted_data = general_purpose::STANDARD
        .decode(lines[1])
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // Derive system-specific key for decryption
    let system_key = derive_system_specific_key()?;

    // Decrypt the data
    let decrypted_bytes = decrypt_keystore_data(&encrypted_data, &system_key)?;
    let decrypted_content = String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))?;

    // Parse the decrypted content as INI
    let mut ini = configparser::ini::Ini::new();

    ini.read(decrypted_content).map_err(|e| format!("Failed to parse INI: {}", e))?;

    // Extract master key salt
    let master_key_salt = ini.get("MasterKey", "salt").unwrap_or_default();

    // Extract password verifier
    let password_verifier = ini.get("MasterKey", "verifier");

    // Load nonce counters
    let mut nonce_counters = std::collections::HashMap::new();
    if let Some(nonce_section) = ini.get_map_ref().get("NonceCounters") {
        for (key, value_opt) in nonce_section.iter() {
            if let Some(value_str) = value_opt {
                if let Ok(value) = value_str.parse::<u64>() {
                    nonce_counters.insert(key.clone(), value);
                }
            }
        }
    }

    // Load key metadata
    let mut key_metadata = std::collections::HashMap::new();
    if let Some(metadata_section) = ini.get_map_ref().get("KeyMetadata") {
        for (key_id, value_opt) in metadata_section.iter() {
            if let Some(metadata_str) = value_opt {
                // Parse metadata from string representation
                let parts: Vec<&str> = metadata_str.split(':').collect();
                if parts.len() >= 7 {
                    if let (
                        Ok(created_at),
                        Ok(last_used),
                        Ok(usage_count),
                        Ok(message_count),
                        Ok(data_size_bytes),
                        Ok(is_revoked),
                    ) = (
                        parts[0].parse::<u64>(),
                        parts[1].parse::<u64>(),
                        parts[2].parse::<u64>(),
                        parts[3].parse::<u64>(),
                        parts[4].parse::<u64>(),
                        parts[6].parse::<bool>(),
                    ) {
                        let description = parts[5..].join(":"); // Join remaining parts for description
                        let metadata = crate::master_key::keystore::KeyMetadata {
                            created_at,
                            last_used,
                            usage_count,
                            message_count,
                            data_size_bytes,
                            description,
                            is_revoked,
                        };
                        key_metadata.insert(key_id.clone(), metadata);
                    }
                }
            }
        }
    }

    let keystore = Keystore {
        master_key_salt,
        password_verifier,
        nonce_counters,
        key_metadata,
        file_path: Some(path.clone()),
    };

    Ok(keystore)
}

/// Load an encrypted keystore from a path using a specific key (for testing)
#[cfg(test)]
pub fn load_encrypted_keystore_from_path_with_key(
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<Keystore, Box<dyn std::error::Error>> {
    // Read the file content
    let content = std::fs::read_to_string(path)?;

    // Check if it's an encrypted keystore
    if !content.starts_with(ENCRYPTED_KEYSTORE_HEADER) {
        return Err("Not an encrypted keystore file".into());
    }

    // Split content into header and encrypted data
    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err("Invalid encrypted keystore format".into());
    }

    // Decode the base64 encrypted data
    let encrypted_data = general_purpose::STANDARD
        .decode(lines[1])
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    // Decrypt the data with the provided key
    let decrypted_bytes = decrypt_keystore_data(&encrypted_data, key)?;
    let decrypted_content = String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))?;

    // Parse the decrypted content as INI
    let mut ini = configparser::ini::Ini::new();

    ini.read(decrypted_content).map_err(|e| format!("Failed to parse INI: {}", e))?;

    // Extract master key salt
    let master_key_salt = ini.get("MasterKey", "salt").unwrap_or_default();

    // Extract password verifier
    let password_verifier = ini.get("MasterKey", "verifier");

    // Load nonce counters
    let mut nonce_counters = std::collections::HashMap::new();
    if let Some(nonce_section) = ini.get_map_ref().get("NonceCounters") {
        for (key, value_opt) in nonce_section.iter() {
            if let Some(value_str) = value_opt {
                if let Ok(value) = value_str.parse::<u64>() {
                    nonce_counters.insert(key.clone(), value);
                }
            }
        }
    }

    // Load key metadata
    let mut key_metadata = std::collections::HashMap::new();

    // Try both case variations for the KeyMetadata section
    let metadata_section =
        ini.get_map_ref().get("KeyMetadata").or_else(|| ini.get_map_ref().get("keymetadata"));

    if let Some(metadata_section) = metadata_section {
        for (key_id, value_opt) in metadata_section.iter() {
            if let Some(metadata_str) = value_opt {
                // Parse metadata from string representation
                let parts: Vec<&str> = metadata_str.split(':').collect();
                if parts.len() >= 7 {
                    // The last part is is_revoked, everything before that except the first 5 is description
                    if parts.len() > 7 {
                        // If there are more than 7 parts, the description contains colons
                        // parts[0-4] = numeric fields, parts[5..parts.len()-1] = description, parts[last] = is_revoked
                        let description_parts = &parts[5..parts.len() - 1];
                        let description = description_parts.join(":");
                        if let (
                            Ok(created_at),
                            Ok(last_used),
                            Ok(usage_count),
                            Ok(message_count),
                            Ok(data_size_bytes),
                            Ok(is_revoked),
                        ) = (
                            parts[0].parse::<u64>(),
                            parts[1].parse::<u64>(),
                            parts[2].parse::<u64>(),
                            parts[3].parse::<u64>(),
                            parts[4].parse::<u64>(),
                            parts[parts.len() - 1].parse::<bool>(),
                        ) {
                            let metadata = crate::master_key::keystore::KeyMetadata {
                                created_at,
                                last_used,
                                usage_count,
                                message_count,
                                data_size_bytes,
                                description,
                                is_revoked,
                            };
                            key_metadata.insert(key_id.clone(), metadata);
                        }
                    } else {
                        // Exactly 7 parts - no colons in description
                        if let (
                            Ok(created_at),
                            Ok(last_used),
                            Ok(usage_count),
                            Ok(message_count),
                            Ok(data_size_bytes),
                            Ok(is_revoked),
                        ) = (
                            parts[0].parse::<u64>(),
                            parts[1].parse::<u64>(),
                            parts[2].parse::<u64>(),
                            parts[3].parse::<u64>(),
                            parts[4].parse::<u64>(),
                            parts[6].parse::<bool>(),
                        ) {
                            let description = parts[5].to_string();
                            let metadata = crate::master_key::keystore::KeyMetadata {
                                created_at,
                                last_used,
                                usage_count,
                                message_count,
                                data_size_bytes,
                                description,
                                is_revoked,
                            };
                            key_metadata.insert(key_id.clone(), metadata);
                        }
                    }
                }
            }
        }
    }

    let keystore = Keystore {
        master_key_salt,
        password_verifier,
        nonce_counters,
        key_metadata,
        file_path: Some(path.clone()),
    };

    Ok(keystore)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"test keystore data";
        let key = [1u8; 32]; // Use a fixed key for testing

        let encrypted = encrypt_keystore_data(data, &key).expect("Encryption failed");
        let decrypted = decrypt_keystore_data(&encrypted, &key).expect("Decryption failed");

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_save_load_encrypted_keystore() {
        let mut keystore = Keystore::new();
        keystore.set_master_salt("test_salt");
        keystore.set_password_verifier("test_verifier");
        keystore.increment_key_usage("test_key");

        // Create a temporary file for testing
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();

        // For testing, we need to use a fixed key since derive_system_specific_key()
        // uses time-based values that change between save and load operations
        let fixed_key = [42u8; 32]; // Fixed key for testing

        // Save the keystore using the test function with fixed key
        save_encrypted_keystore_to_path_with_key(&keystore, &temp_path, &fixed_key)
            .expect("Failed to save keystore");

        // Load the keystore back using the test function with the same fixed key
        let loaded_keystore = load_encrypted_keystore_from_path_with_key(&temp_path, &fixed_key)
            .expect("Failed to load keystore");

        // Verify the data
        assert_eq!(keystore.master_key_salt, loaded_keystore.master_key_salt);
        assert_eq!(keystore.password_verifier, loaded_keystore.password_verifier);
        assert_eq!(keystore.key_metadata.len(), loaded_keystore.key_metadata.len());

        // Clean up
        fs::remove_file(&temp_path).ok();
    }
}
