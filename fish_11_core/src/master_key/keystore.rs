//! Secure keystore for master key system
//!
//! Handles persistent storage of sensitive data like salts, nonce counters, etc.

use std::collections::HashMap;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ini::Ini;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Metadata associated with keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub created_at: u64,      // Unix timestamp
    pub last_used: u64,       // Unix timestamp
    pub usage_count: u64,     // Number of times used
    pub message_count: u64,   // Number of messages processed with this key (kept for compatibility)
    pub data_size_bytes: u64, // Total data size (bytes) processed with this key
    pub description: String,  // Description of the key's purpose
    pub is_revoked: bool,     // Whether the key has been revoked
}

impl Default for KeyMetadata {
    fn default() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

        Self {
            created_at: now,
            last_used: now,
            usage_count: 0,
            message_count: 0,
            data_size_bytes: 0,
            description: "New key".to_string(),
            is_revoked: false,
        }
    }
}

impl KeyMetadata {
    /// Create a new KeyMetadata with an initial message count (compat shim)
    pub fn new(initial_message_count: u64) -> Self {
        let mut km = Self::default();
        km.message_count = initial_message_count;
        km
    }
}

/// A secure keystore that manages sensitive data
pub struct Keystore {
    /// Salt used for deriving the master key
    pub master_key_salt: String,

    /// Password verifier (hash of the derived master key) for password verification
    pub password_verifier: Option<String>,

    /// Nonce counters for different contexts
    pub nonce_counters: HashMap<String, u64>,

    /// Metadata for various keys
    pub key_metadata: HashMap<String, KeyMetadata>,

    /// File path where this keystore is persisted
    pub file_path: Option<PathBuf>,
}

impl Keystore {
    /// Create a new keystore with a random salt
    pub fn new() -> Self {
        use rand::RngCore;
        let mut salt_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt = general_purpose::STANDARD.encode(&salt_bytes);

        Self {
            master_key_salt: salt,
            password_verifier: None,
            nonce_counters: HashMap::new(),
            key_metadata: HashMap::new(),
            file_path: None,
        }
    }

    /// Create a keystore with a specific salt
    pub fn with_salt(salt: &str) -> Self {
        Self {
            master_key_salt: salt.to_string(),
            password_verifier: None,
            nonce_counters: HashMap::new(),
            key_metadata: HashMap::new(),
            file_path: None,
        }
    }

    /// Get or create a nonce counter for a specific context
    pub fn get_nonce(&mut self, context: &str) -> u64 {
        let counter = self.nonce_counters.entry(context.to_string()).or_insert(0);
        *counter += 1;
        *counter - 1 // Return the previous value as the nonce
    }

    /// Increment the usage count for a key
    pub fn increment_key_usage(&mut self, key_id: &str) {
        let metadata =
            self.key_metadata.entry(key_id.to_string()).or_insert_with(KeyMetadata::default);
        metadata.usage_count += 1;

        use std::time::{SystemTime, UNIX_EPOCH};
        metadata.last_used =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();
    }

    /// Mark a key as revoked
    pub fn revoke_key(&mut self, key_id: &str) {
        let metadata =
            self.key_metadata.entry(key_id.to_string()).or_insert_with(KeyMetadata::default);
        metadata.is_revoked = true;
    }

    /// Check if a key is revoked
    pub fn is_key_revoked(&self, key_id: &str) -> bool {
        self.key_metadata.get(key_id).map(|metadata| metadata.is_revoked).unwrap_or(false)
    }

    /// Get the master key salt
    pub fn get_master_salt(&self) -> Option<&str> {
        Some(&self.master_key_salt)
    }

    /// Set the master key salt
    pub fn set_master_salt(&mut self, salt: &str) {
        self.master_key_salt = salt.to_string();
    }

    /// Set the password verifier (hash of the derived master key)
    pub fn set_password_verifier(&mut self, verifier: &str) {
        self.password_verifier = Some(verifier.to_string());
    }

    /// Get the password verifier
    pub fn get_password_verifier(&self) -> Option<&str> {
        self.password_verifier.as_deref()
    }

    /// Clear the password verifier
    pub fn clear_password_verifier(&mut self) {
        self.password_verifier = None;
    }

    /// Load keystore from default path
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = Self::default_path()?;
        Self::load_from_file(&path)
    }

    /// Save keystore to default path
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::default_path()?;
        self.save_to_path(&path)
    }

    /// Load keystore from a file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        // Read the file content
        let file_content = std::fs::read(path)?;

        // Check if the data is encrypted
        let ini_string = if Self::is_encrypted_data(&file_content) {
            // Try to decrypt the data
            match Self::decrypt_keystore_data(&file_content) {
                Ok(decrypted) => decrypted,
                Err(e) => {
                    log::warn!("Failed to decrypt keystore, trying as plaintext: {}", e);
                    // Fall back to plaintext if decryption fails
                    String::from_utf8(file_content)
                        .map_err(|e| format!("Failed to read keystore as plaintext: {}", e))?
                }
            }
        } else {
            // Try to read as plaintext
            String::from_utf8(file_content)
                .map_err(|e| format!("Failed to read keystore as plaintext: {}", e))?
        };

        // Parse the INI content
        let ini = Ini::load_from_str(&ini_string)
            .map_err(|e| format!("Failed to parse keystore INI: {}", e))?;

        let master_key_salt = ini.get_from(Some("MasterKey"), "salt").unwrap_or_default().to_string();

        // Load nonce counters
        let mut nonce_counters = HashMap::new();
        if let Some(nonce_section) = ini.section(Some("NonceCounters")) {
            for (key, value) in nonce_section.iter() {
                if let Ok(value) = value.parse::<u64>() {
                    nonce_counters.insert(key.to_string(), value);
                }
            }
        }

        // Load password verifier
        let password_verifier = ini.get_from(Some("MasterKey"), "verifier").map(|s| s.to_string());

        // Load key metadata
        let mut key_metadata = HashMap::new();
        if let Some(metadata_section) = ini.section(Some("KeyMetadata")) {
            for (key_id, metadata_str) in metadata_section.iter() {
                // Parse metadata from string representation
                // Format: "created_at:last_used:usage_count:message_count:data_size_bytes:description:is_revoked"
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
                        let metadata = KeyMetadata {
                            created_at,
                            last_used,
                            usage_count,
                            message_count,
                            data_size_bytes,
                            description,
                            is_revoked,
                        };
                        key_metadata.insert(key_id.to_string(), metadata);
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

    /// Save keystore to a file
    pub fn save_to_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref path) = self.file_path {
            self.save_to_path(path)
        } else {
            Err("No file path specified for keystore".into())
        }
    }

    /// Save keystore to a specific file path
    pub fn save_to_path(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let mut ini = Ini::new();

        // Save master key salt
        ini.with_section(Some("MasterKey")).set("salt", self.master_key_salt.as_str());

        // Save password verifier if present
        if let Some(verifier) = &self.password_verifier {
            ini.with_section(Some("MasterKey")).set("verifier", verifier.as_str());
        }

        // Save nonce counters
        for (context, counter) in &self.nonce_counters {
            ini.with_section(Some("NonceCounters")).set(context.as_str(), counter.to_string().as_str());
        }

        // Save key metadata
        for (key_id, metadata) in &self.key_metadata {
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
            ini.with_section(Some("KeyMetadata")).set(key_id.as_str(), metadata_str.as_str());
        }

        // Convert INI to string
        let mut buffer = std::io::Cursor::new(Vec::new());
        ini.write_to(&mut buffer)
            .map_err(|e| format!("Failed to write INI: {}", e))?;
        let ini_string = String::from_utf8(buffer.into_inner())
            .map_err(|e| format!("Failed to convert INI to UTF-8: {}", e))?;

        // Encrypt the keystore data
        let encrypted_data = Self::encrypt_keystore_data(&ini_string)?;

        // Write encrypted data to file
        std::fs::write(path, encrypted_data)?;

        Ok(())
    }

    /// Serialize the keystore to an INI string
    pub fn to_ini_string(&self) -> Result<String, Box<dyn std::error::Error>> {
        let mut ini = Ini::new();

        ini.with_section(Some("MasterKey")).set("salt", self.master_key_salt.as_str());

        if let Some(verifier) = &self.password_verifier {
            ini.with_section(Some("MasterKey")).set("verifier", verifier.as_str());
        }

        for (context, counter) in &self.nonce_counters {
            ini.with_section(Some("NonceCounters")).set(context.as_str(), counter.to_string().as_str());
        }

        for (key_id, metadata) in &self.key_metadata {
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
            ini.with_section(Some("KeyMetadata")).set(key_id.as_str(), metadata_str.as_str());
        }

        let mut buffer = std::io::Cursor::new(Vec::new());
        ini.write_to(&mut buffer)
            .map_err(|e| format!("Failed to write INI: {}", e))?;
        let ini_string = String::from_utf8(buffer.into_inner())
            .map_err(|e| format!("Failed to convert INI to UTF-8: {}", e))?;

        Ok(ini_string)
    }

    /// Deserialize a keystore from an INI string
    pub fn from_ini_string(ini_string: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let ini = Ini::load_from_str(ini_string)
            .map_err(|e| format!("Failed to parse keystore INI: {}", e))?;

        let master_key_salt = ini.get_from(Some("MasterKey"), "salt").unwrap_or_default().to_string();
        let password_verifier = ini.get_from(Some("MasterKey"), "verifier").map(|s| s.to_string());

        let mut nonce_counters = HashMap::new();
        if let Some(section) = ini.section(Some("NonceCounters")) {
            for (key, value) in section.iter() {
                if let Ok(value) = value.parse::<u64>() {
                    nonce_counters.insert(key.to_string(), value);
                }
            }
        }

        let mut key_metadata = HashMap::new();
        if let Some(section) = ini.section(Some("KeyMetadata")) {
            for (key_id, metadata_str) in section.iter() {
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
                        let description = parts[5..].join(":");
                        key_metadata.insert(key_id.to_string(), KeyMetadata {
                            created_at,
                            last_used,
                            usage_count,
                            message_count,
                            data_size_bytes,
                            description,
                            is_revoked,
                        });
                    }
                }
            }
        }

        Ok(Keystore {
            master_key_salt,
            password_verifier,
            nonce_counters,
            key_metadata,
            file_path: None,
        })
    }

    /// Get the default keystore path
    pub fn default_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Use the same directory as the config file
        use std::env;

        match env::var("MIRCDIR") {
            Ok(mirc_path) => {
                let mut path = PathBuf::from(mirc_path);
                path.push("fish_11_keystore.ini");
                Ok(path)
            }
            Err(_) => {
                // Fallback to current directory
                let mut path = env::current_dir()?;
                path.push("fish_11_keystore.ini");
                Ok(path)
            }
        }
    }

    /// Derive a system-specific encryption key for keystore protection
    /// This key is derived from system-specific information and is not stored
    fn derive_keystore_encryption_key() -> Result<[u8; 32], Box<dyn std::error::Error>> {
        use std::env;

        // Get system-specific information
        let hostname = env::var("COMPUTERNAME").or_else(|_| env::var("HOSTNAME"));
        let username = env::var("USERNAME").or_else(|_| env::var("USER"));
        let current_dir = env::current_dir()?;

        // Create a seed from system information
        let mut seed = String::new();
        if let Ok(h) = hostname {
            seed.push_str(&h);
        }
        if let Ok(u) = username {
            seed.push_str(&u);
        }
        seed.push_str(&current_dir.to_string_lossy());

        // Add some fixed salt for consistency
        seed.push_str("fish_11_keystore_encryption_salt");

        // Derive a 32-byte key using SHA-256
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);

        Ok(key)
    }

    /// Encrypt keystore data
    fn encrypt_keystore_data(data: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Self::derive_keystore_encryption_key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // Generate a random nonce
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt the data
        let ciphertext = cipher
            .encrypt(nonce, data.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Combine nonce and ciphertext for storage
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(nonce.as_slice());
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt keystore data
    fn decrypt_keystore_data(encrypted_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        if encrypted_data.len() < 12 {
            return Err("Encrypted data too short".into());
        }

        let key = Self::derive_keystore_encryption_key()?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));

        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt the data
        let plaintext =
            cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption failed: {}", e))?;

        // Convert to string
        let result = String::from_utf8(plaintext)
            .map_err(|e| format!("Invalid UTF-8 in decrypted data: {}", e))?;

        Ok(result)
    }

    /// Check if keystore data is encrypted
    fn is_encrypted_data(data: &[u8]) -> bool {
        // Encrypted data should start with a random nonce (not all zeros)
        if data.len() < 12 {
            return false;
        }

        // Check if the first 12 bytes (nonce) are not all zeros
        let nonce = &data[0..12];
        !nonce.iter().all(|&b| b == 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_creation() {
        let keystore = Keystore::new();
        assert!(!keystore.master_key_salt.is_empty());
        assert!(keystore.nonce_counters.is_empty());
        assert!(keystore.key_metadata.is_empty());
    }

    #[test]
    fn test_nonce_counter() {
        let mut keystore = Keystore::new();

        let nonce1 = keystore.get_nonce("test_context");
        assert_eq!(nonce1, 0);

        let nonce2 = keystore.get_nonce("test_context");
        assert_eq!(nonce2, 1);

        // Different context should have its own counter
        let nonce3 = keystore.get_nonce("another_context");
        assert_eq!(nonce3, 0);
    }

    #[test]
    fn test_key_metadata() {
        let mut keystore = Keystore::new();

        keystore.increment_key_usage("test_key");
        assert_eq!(keystore.key_metadata.get("test_key").unwrap().usage_count, 1);

        keystore.increment_key_usage("test_key");
        assert_eq!(keystore.key_metadata.get("test_key").unwrap().usage_count, 2);

        keystore.revoke_key("test_key");
        assert!(keystore.is_key_revoked("test_key"));
    }
}
