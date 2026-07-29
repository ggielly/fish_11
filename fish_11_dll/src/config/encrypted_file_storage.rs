//! Encrypted file storage operations for configuration
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose;
use fish_11_core::master_key::{EncryptedBlob, decrypt_data, derive_config_kek, encrypt_data};
use ini::Ini;

use crate::config::ini_helpers;
use crate::config::models::FishConfig;
use crate::dll_interface::fish11_masterkey::is_master_key_unlocked;
use crate::error::{FishError, Result};
use crate::log_debug;

/// Configuration header for encrypted files
const ENCRYPTED_CONFIG_HEADER: &str = "# FiSH_11_ENCRYPTED_CONFIG_V1";

/// Initialize the encrypted config file if it doesn't exist
pub fn init_encrypted_config_file() -> Result<()> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        return Ok(());
    }

    let mut ini = Ini::new();

    ini.with_section(Some("FiSH11"))
        .set("process_incoming", "true")
        .set("plain_prefix", "+p ")
        .set("encryption_prefix", "+FiSH")
        .set("fish_prefix", "0");

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    ini.write_to_file(&config_path)?;

    Ok(())
}

/// Check if the config file is encrypted
fn is_encrypted_config(config_path: &PathBuf) -> Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }

    let content = fs::read_to_string(config_path)
        .map_err(|e| FishError::ConfigError(format!("Failed to read config file: {}", e)))?;

    // Check if the file starts with our encrypted header
    Ok(content.starts_with(ENCRYPTED_CONFIG_HEADER))
}

/// Load the configuration from an encrypted file or regular INI file
pub fn load_encrypted_config(path_override: Option<PathBuf>) -> Result<FishConfig> {
    let config_path = match &path_override {
        Some(path) => path.clone(),
        None => get_config_path()?,
    };

    #[cfg(debug_assertions)]
    log_debug!("load_encrypted_config: config path: {}", config_path.display());

    // Check if file exists
    if !config_path.exists() {
        crate::log_info!("load_encrypted_config: config file does not exist, creating default");
        return Ok(FishConfig::new());
    }

    // Check if the file is encrypted
    if is_encrypted_config(&config_path)? {
        #[cfg(debug_assertions)]
        log_debug!("load_encrypted_config: detected encrypted config file");

        load_encrypted_config_from_file(&config_path)
    } else {
        log_debug!("load_encrypted_config: detected regular config file");

        // Fall back to regular loading
        crate::config::file_storage::load_config(path_override)
    }
}

/// Load configuration from an encrypted file
fn load_encrypted_config_from_file(config_path: &PathBuf) -> Result<FishConfig> {
    let content = fs::read_to_string(config_path)
        .map_err(|e| FishError::ConfigError(format!("Failed to read encrypted config: {}", e)))?;

    let lines: Vec<&str> = content.lines().collect();

    if lines.is_empty() || !lines[0].starts_with(ENCRYPTED_CONFIG_HEADER) {
        return Err(FishError::ConfigError("Invalid encrypted config header".to_string()));
    }

    if lines.len() < 2 {
        return Err(FishError::ConfigError("Encrypted config file is malformed".to_string()));
    }

    let encrypted_data = lines[1];

    let encrypted_bytes = general_purpose::STANDARD
        .decode(encrypted_data)
        .map_err(|e| FishError::ConfigError(format!("Failed to decode encrypted data: {}", e)))?;

    let encrypted_blob = EncryptedBlob::from_bytes(&encrypted_bytes)
        .ok_or_else(|| FishError::ConfigError("Failed to parse encrypted blob".to_string()))?;

    if !is_master_key_available() {
        return Err(FishError::ConfigError(
            "Encrypted config detected but keychain is locked. Use /fish11_unlock to unlock it first."
                .to_string(),
        ));
    }

    let master_key = crate::dll_interface::fish11_masterkey::get_master_key_from_memory()
        .ok_or_else(|| FishError::ConfigError("Keychain not available in memory - has it been unlocked?".to_string()))?;

    let config_kek = derive_config_kek(&master_key);

    let decrypted_bytes = decrypt_data(&encrypted_blob, &config_kek)
        .map_err(|e| FishError::ConfigError(format!("Failed to decrypt config: {}", e)))?;

    let decrypted_content = String::from_utf8(decrypted_bytes).map_err(|e| {
        FishError::ConfigError(format!("Failed to convert decrypted data to string: {}", e))
    })?;

    let ini = Ini::load_from_str(&decrypted_content).map_err(|e| {
        FishError::ConfigError(format!("Failed to parse decrypted INI content: {}", e))
    })?;

    Ok(ini_helpers::ini_to_config(&ini))
}

/// Check if master key is available in memory
pub fn is_master_key_available() -> bool {
    // Check if the master key is currently held in memory
    is_master_key_unlocked()
}

/// Save configuration to an encrypted file
pub fn save_encrypted_config(config: &FishConfig, path_override: Option<PathBuf>) -> Result<()> {
    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };

    #[cfg(debug_assertions)]
    log_debug!("save_encrypted_config: config path: {}", config_path.display());

    let ini = ini_helpers::config_to_ini(config);

    let mut buffer = Cursor::new(Vec::new());
    ini.write_to(&mut buffer)?;
    let ini_string = String::from_utf8(buffer.into_inner())
        .map_err(|e| FishError::ConfigError(format!("Failed to convert INI to string: {}", e)))?;

    if !is_master_key_available() {
        return Err(FishError::ConfigError("Cannot save encrypted config: keychain is locked. Use /fish11_unlock to unlock it first.".to_string()));
    }

    let master_key = crate::dll_interface::fish11_masterkey::get_master_key_from_memory()
        .ok_or_else(|| FishError::ConfigError("Master key not available in memory".to_string()))?;

    let config_kek = derive_config_kek(&master_key);

    let encrypted_blob = encrypt_data(ini_string.as_bytes(), &config_kek, "config", 0)
        .map_err(|e| FishError::ConfigError(format!("Encryption failed: {}", e)))?;

    let encrypted_bytes = encrypted_blob.to_bytes();
    let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted_bytes);

    let content = format!("{}\n{}\n", ENCRYPTED_CONFIG_HEADER, encrypted_b64);

    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    std::fs::write(&config_path, content)
        .map_err(|e| FishError::ConfigError(format!("Failed to write encrypted config: {}", e)))?;

    Ok(())
}

/// Get the path to the config file
pub fn get_config_path() -> Result<PathBuf> {
    crate::config::file_storage::get_config_path()
}
