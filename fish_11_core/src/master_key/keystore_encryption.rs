use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

use crate::master_key::keystore::Keystore;

const ENCRYPTED_KEYSTORE_HEADER: &str = "# FiSH_11_ENCRYPTED_KEYSTORE_V1\n";

pub fn derive_system_specific_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
    use std::env;

    use sha2::{Digest, Sha256};

    let hostname = env::var("COMPUTERNAME").or_else(|_| env::var("HOSTNAME")).unwrap_or_default();
    let username = env::var("USERNAME").or_else(|_| env::var("USER")).unwrap_or_default();
    let current_dir =
        env::current_dir().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();

    let mut seed = String::new();
    seed.push_str(&hostname);
    seed.push_str(&username);
    seed.push_str(&current_dir);
    seed.push_str("fish_11_keystore_encryption_salt");

    let hash = Sha256::digest(seed.as_bytes());

    let mut key = [0u8; 32];
    key.copy_from_slice(&hash);
    Ok(key)
}

pub fn encrypt_keystore_data(
    data: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use rand::RngCore;

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let ciphertext =
        cipher.encrypt(nonce, data).map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_keystore_data(
    encrypted_data: &[u8],
    key: &[u8; 32],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if encrypted_data.len() < 12 {
        return Err("Encrypted data too short".into());
    }

    let nonce_bytes: [u8; 12] = encrypted_data[..12].try_into().unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = &encrypted_data[12..];

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    let plaintext =
        cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

fn encrypt_and_write(
    keystore: &Keystore,
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let ini_string = keystore.to_ini_string()?;
    let encrypted_data = encrypt_keystore_data(ini_string.as_bytes(), key)?;
    let base64_data = general_purpose::STANDARD.encode(&encrypted_data);
    let content = format!("{}{}\n", ENCRYPTED_KEYSTORE_HEADER, base64_data);
    std::fs::write(path, content)?;
    Ok(())
}

fn read_decrypt_parse(
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<Keystore, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;

    if !content.starts_with(ENCRYPTED_KEYSTORE_HEADER) {
        return Err("Not an encrypted keystore file".into());
    }

    let lines: Vec<&str> = content.lines().collect();
    if lines.len() < 2 {
        return Err("Invalid encrypted keystore format".into());
    }

    let encrypted_data = general_purpose::STANDARD
        .decode(lines[1])
        .map_err(|e| format!("Failed to decode base64: {}", e))?;

    let decrypted_bytes = decrypt_keystore_data(&encrypted_data, key)?;
    let decrypted_content = String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))?;

    let mut keystore = Keystore::from_ini_string(&decrypted_content)?;
    keystore.file_path = Some(path.clone());
    Ok(keystore)
}

pub fn save_encrypted_keystore_to_path(
    keystore: &Keystore,
    path: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let system_key = derive_system_specific_key()?;
    encrypt_and_write(keystore, path, &system_key)
}

#[cfg(test)]
pub fn save_encrypted_keystore_to_path_with_key(
    keystore: &Keystore,
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    encrypt_and_write(keystore, path, key)
}

pub fn load_encrypted_keystore_from_path(
    path: &PathBuf,
) -> Result<Keystore, Box<dyn std::error::Error>> {
    let system_key = derive_system_specific_key()?;
    read_decrypt_parse(path, &system_key)
}

#[cfg(test)]
pub fn load_encrypted_keystore_from_path_with_key(
    path: &PathBuf,
    key: &[u8; 32],
) -> Result<Keystore, Box<dyn std::error::Error>> {
    read_decrypt_parse(path, key)
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"test keystore data";
        let key = [1u8; 32];

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

        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();

        let fixed_key = [42u8; 32];

        save_encrypted_keystore_to_path_with_key(&keystore, &temp_path, &fixed_key)
            .expect("Failed to save keystore");

        let loaded_keystore = load_encrypted_keystore_from_path_with_key(&temp_path, &fixed_key)
            .expect("Failed to load keystore");

        assert_eq!(keystore.master_key_salt, loaded_keystore.master_key_salt);
        assert_eq!(keystore.password_verifier, loaded_keystore.password_verifier);
        assert_eq!(keystore.key_metadata.len(), loaded_keystore.key_metadata.len());

        std::fs::remove_file(&temp_path).ok();
    }
}
