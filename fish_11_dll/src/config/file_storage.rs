//! File storage operations for configuration
use std::fs;
use std::path::PathBuf;

use ini::Ini;
use secrecy::ExposeSecret;

use crate::config::models::FishConfig;
use crate::config::ini_helpers;
use crate::error::{FishError, Result};
use crate::utils::base64_encode;
use crate::{crypto, log_debug, log_error, log_info, log_trace, log_warn};

/// Initialize the config file if it doesn't exist
pub fn init_config_file() -> Result<()> {
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

/// Get the path to the config file
pub fn get_config_path() -> Result<PathBuf> {
    #[cfg(debug_assertions)]
    log_debug!("get_config_path: Determining configuration file path");

    // Use environment variable for mIRC directory
    match std::env::var("MIRCDIR") {
        Ok(mirc_path) => {
            #[cfg(debug_assertions)]
            log_debug!("get_config_path: Found MIRCDIR environment variable: {}", mirc_path);

            let mut path = PathBuf::from(mirc_path);

            #[cfg(debug_assertions)]
            log_debug!("get_config_path: Created path from MIRCDIR: {}", path.display());

            // Validate path - detect directory traversal attempts
            if path.to_string_lossy().contains("..") {
                log_error!(
                    "get_config_path: Invalid path containing directory traversal: {}",
                    path.display()
                );
                return Err(FishError::ConfigError(
                    "Invalid config path: potential directory traversal".to_string(),
                ));
            }

            path.push("fish_11.ini");

            #[cfg(debug_assertions)]
            log_info!("get_config_path: using config path from MIRCDIR: {}", path.display());

            Ok(path)
        }
        Err(e) => {
            log_warn!("get_config_path: MIRCDIR environment variable not found: {}", e);

            // FALLBACK: Use current directory if MIRCDIR is not set
            // This prevents crashes and allows the DLL to work even if the environment variable is missing
            let mut path = match std::env::current_dir() {
                Ok(dir) => dir,
                Err(e) => {
                    log_error!("get_config_path: failed to get current directory: {}", e);
                    // Fallback: use "fish_11.ini" in current directory
                    PathBuf::new()
                }
            };
            path.push("fish_11.ini");

            log_warn!(
                "get_config_path: using fallback config path (current directory): {}",
                path.display()
            );

            Ok(path)
        }
    }
}

/// Loads the configuration from the disk or creates a new one if it doesn't exist.
///
/// This function will:
/// 1. Check if the config file exists at the expected location
/// 2. If it doesn't exist, generate a new keypair and create a default configuration
/// 3. If it exists, load all configuration sections (Keys, KeyPair, NickNetworks, etc.)
///
/// # Returns
///
/// - `Result<FishConfig>` - The loaded configuration or an error
pub fn load_config(path_override: Option<PathBuf>) -> Result<FishConfig> {
    let total_start = std::time::Instant::now();

    log_warn!("=== load_config: starting configuration load ===");

    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);

    let mut config = FishConfig::new();

    let path_start = std::time::Instant::now();
    let config_path = match path_override {
        Some(path) => {
            #[cfg(debug_assertions)]
            log_debug!("load_config: using override path: {}", path.display());
            path
        }
        None => get_config_path()?,
    };
    log_warn!("load_config: get_config_path took {:?}", path_start.elapsed());

    #[cfg(debug_assertions)]
    log_debug!("load_config: config path: {}", config_path.display());

    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError("Configuration loading timed out".to_string()));
    }

    let file_exists = config_path.exists();

    if !file_exists {
        #[cfg(debug_assertions)]
        log_info!("load_config: config file does not exist, generating new keypair");

        let keypair = crypto::generate_keypair();
        config.our_private_key = Some(base64_encode(keypair.private_key.expose_secret()));
        config.our_public_key = Some(base64_encode(&keypair.public_key));

        save_config(&config, None)?;

        log_warn!("load_config: TOTAL (new file) {:?}", total_start.elapsed());
        return Ok(config);
    }

    log_trace!("load_config: loading existing config file");

    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out before ini load".to_string(),
        ));
    }

    let ini_start = std::time::Instant::now();

    let ini = Ini::load_from_file(&config_path).map_err(|e| {
        FishError::ConfigError(format!(
            "Failed to load INI file from {}: {}",
            config_path.display(),
            e
        ))
    })?;

    log_warn!("load_config: ini.load() took {:?}", ini_start.elapsed());

    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out after ini load".to_string(),
        ));
    }

    config = ini_helpers::ini_to_config(&ini);

    log_warn!(
        "load_config: entries loaded: {}",
        config.entries.len()
    );

    log_warn!("=== load_config: TOTAL {:?} ===", total_start.elapsed());
    Ok(config)
}

/// Saves the configuration to disk.
///
/// This function serializes the entire FishConfig object to an INI format and writes it to the
/// standard configuration file location. It will create any necessary parent directories
/// if they don't already exist.
///
/// # Arguments
///
/// * `config` - A reference to the FishConfig object to be saved
///
/// # Returns
///
/// - `Result<()>` - Success (unit type) or an error
pub fn save_config(config: &FishConfig, path_override: Option<PathBuf>) -> Result<()> {
    let start_time = std::time::Instant::now();

    #[cfg(debug_assertions)]
    log_debug!(
        "save_config: starting (entries: {}, keys: {})",
        config.entries.len(),
        config.keys.len()
    );

    let ini = ini_helpers::config_to_ini(config);

    let entries_start = std::time::Instant::now();
    let entries_duration = entries_start.elapsed();
    if entries_duration.as_millis() > 100 {
        log_warn!(
            "save_config: entries processing took {:?} for {} entries",
            entries_duration,
            config.entries.len()
        );
    }

    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };

    #[cfg(debug_assertions)]
    log_debug!("save_config: Config path: {}", config_path.display());

    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            #[cfg(debug_assertions)]
            log_debug!("save_config: creating parent directory: {}", parent.display());

            fs::create_dir_all(parent)?;
        }
    }

    let temp_path = config_path.with_extension("tmp");

    let write_start = std::time::Instant::now();

    match ini.write_to_file(&temp_path) {
        Ok(_) => {
            let write_duration = write_start.elapsed();

            match fs::rename(&temp_path, &config_path) {
                Ok(_) => {
                    let total_duration = start_time.elapsed();

                    #[cfg(debug_assertions)]
                    log_debug!(
                        "save_config: completed in {:?} (write: {:?}, entries: {:?})",
                        total_duration,
                        write_duration,
                        entries_duration
                    );

                    if total_duration.as_secs() > 1 {
                        log_warn!(
                            "save_config: SLOW SAVE! Took {:?} for {} entries. Check disk I/O.",
                            total_duration,
                            config.entries.len()
                        );
                    }

                    config.mark_clean();

                    Ok(())
                }
                Err(e) => {
                    log_error!("save_config: failed to rename temp file: {}", e);
                    let _ = fs::remove_file(&temp_path);
                    Err(FishError::ConfigError(format!("Failed to finalize config file: {}", e)))
                }
            }
        }
        Err(e) => {
            log_error!("save_config: failed to write to temp file: {}", e);
            Err(FishError::ConfigError(format!("Failed to write config: {}", e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;
    use crate::config::models::{EntryData, FishConfig};
    use crate::utils::generate_random_bytes;

    // Helper to create a dummy config for testing
    fn create_dummy_config() -> FishConfig {
        let mut config = FishConfig::new();
        config.nick_networks.insert("test_nick".to_string(), "test_net".to_string());
        config.our_private_key = Some(base64_encode(&generate_random_bytes(32)));
        config.our_public_key = Some(base64_encode(&generate_random_bytes(32)));
        config.fish11.process_incoming = false;
        config.fish11.plain_prefix = "!!".to_string();
        // Note: configparser library trims whitespace from INI values, so we can't have leading spaces
        config.fish11.mark_encrypted = "12$chr(183)".to_string();
        config.startup_data.date = Some(123456789);
        config.entries.insert(
            "test_entry@test_net".to_string(),
            EntryData {
                key: Some("entry_key_b64".to_string()),
                date: Some("2025-01-01 00:00:00".to_string()),
                is_exchange: Some(false),
            },
        );
        config.entries.insert(
            "test_chan@test_net".to_string(),
            EntryData {
                key: Some("chan_key_b64".to_string()),
                date: Some("2025-01-02 00:00:00".to_string()),
                is_exchange: Some(false),
            },
        );
        config
    }

    #[test]
    fn test_save_and_load_config_roundtrip() {
        // Tests that a config can be saved to a temporary file and loaded back correctly.
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();

        let original_config = create_dummy_config();

        // Save the config to the temporary path
        save_config(&original_config, Some(temp_path.clone())).expect("Failed to save config");

        // Load the config back from the temporary path
        let loaded_config = load_config(Some(temp_path.clone())).expect("Failed to load config");

        // Assert that the loaded config matches the original
        assert_eq!(original_config, loaded_config);

        // Ensure the temp file is cleaned up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_load_non_existent_config_creates_default() {
        // Tests that loading a non-existent config creates a default one.
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();
        let _ = fs::remove_file(&temp_path); // Ensure it doesn't exist

        let loaded_config =
            load_config(Some(temp_path.clone())).expect("Failed to load non-existent config");

        // Check some default values
        assert!(loaded_config.our_private_key.is_some());
        assert!(loaded_config.our_public_key.is_some());
        assert_eq!(loaded_config.fish11.process_incoming, true);
        assert_eq!(loaded_config.fish11.plain_prefix, "+p ".to_string());

        // Ensure the temp file is cleaned up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_get_config_path_with_mircdir() {
        // Set a temporary directory for MIRCDIR
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        unsafe {
            std::env::set_var("MIRCDIR", temp_dir.path());
        }

        // Call the function
        let path_result = get_config_path();

        // Check that we got a valid path
        assert!(path_result.is_ok());

        let path = path_result.unwrap();

        // Check that the path is correct
        let mut expected_path = temp_dir.path().to_path_buf();
        expected_path.push("fish_11.ini");
        assert_eq!(path, expected_path);
    }

    #[test]
    fn test_get_config_path_no_mircdir() {
        // Ensure MIRCDIR is not set
        unsafe {
            std::env::remove_var("MIRCDIR");
        }

        // Call the function
        let path_result = get_config_path();

        // Vérifie que le fallback fonctionne : le chemin doit être fish_11.ini dans le répertoire courant
        assert!(path_result.is_ok());
        let path = path_result.unwrap();
        let mut expected_path = std::env::current_dir().unwrap();
        expected_path.push("fish_11.ini");
        assert_eq!(path, expected_path);
    }

    #[test]
    fn test_ttl_persistence() {
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();

        let mut config = create_dummy_config();
        // Set a specific TTL
        config.fish11.key_ttl = Some(12345);

        // Save
        save_config(&config, Some(temp_path.clone())).expect("Failed to save");

        // Load
        let loaded = load_config(Some(temp_path.clone())).expect("Failed to load");

        // Verify
        assert_eq!(loaded.fish11.key_ttl, Some(12345));

        // Cleanup
        let _ = fs::remove_file(&temp_path);
    }
}
