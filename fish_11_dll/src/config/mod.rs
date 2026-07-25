//! Configuration module for FiSH_11

use parking_lot::RwLock;
pub mod channel_key_utils;
pub mod channel_keys;
pub mod config_access;
pub mod encrypted_file_storage;
pub mod entries;
pub mod file_storage;
pub mod ini_helpers;
pub mod key_management;
pub mod manual_channel_keys;
pub mod models;
pub mod networks;
pub mod timestamp_signing;
pub use networks::{
    count_network_mappings, count_unique_networks, delete_network, get_all_network_mappings,
    get_all_networks, get_network_for_nick, get_nicknames_by_network, has_network, merge_networks,
    remove_network_for_nick, rename_network, set_network_for_nick,
};
pub use settings::{
    get_encryption_mark, get_fish11_config, get_plain_prefix, get_startup_time,
    get_startup_time_formatted, is_fish10_legacy_disabled, should_encrypt_message,
    should_process_incoming, should_process_outgoing, update_fish11_config, update_startup_time,
};
pub use state_management::{add_nonce, check_nonce, init_ratchet_state, with_ratchet_state_mut};

pub mod settings;
pub mod state_management;
pub mod topics;
use std::thread;
use std::time::{Duration, Instant};

pub use channel_key_utils::{get_channel_key_type, get_channel_key_with_fallback, has_channel_key};
pub use channel_keys::{get_channel_key, set_channel_key};
pub use config_access::{read_config, with_config, with_config_mut, write_config};
pub use entries::{
    get_channel_data, get_user_data, list_channel_entries, list_user_entries, set_channel_data,
    set_user_data,
};
pub use file_storage::{get_config_path, init_config_file, load_config, save_config};
pub use key_management::{
    delete_key, delete_key_default, get_all_keys_with_ttl, get_configured_key_ttl, get_key,
    get_key_default, get_key_status, get_key_status_human_readable, get_key_ttl,
    get_key_ttl_human_readable, get_keypair, get_our_keypair, is_key_about_to_expire, list_keys,
    set_configured_key_ttl, set_key, set_key_default, store_keypair,
};
pub use manual_channel_keys::{
    get_manual_channel_key, list_manual_channel_keys, set_manual_channel_key,
};
pub use models::{EncryptionMetrics, EntryData, Fish11Section, FishConfig, StartupSection};
use once_cell::sync::Lazy;
pub use topics::{get_topic, list_topics, remove_topic, set_topic};

/// Global configuration instance
/// Using parking_lot::Mutex for better performance and no poisoning
pub static CONFIG: Lazy<RwLock<FishConfig>> = Lazy::new(|| {
    #[cfg(debug_assertions)]
    log::info!("CONFIG: Initializing global configuration...");

    // Try to load config from disk, or create a new one if it doesn't exist
    match file_storage::get_config_path() {
        Ok(path) => {
            #[cfg(debug_assertions)]
            log::info!("CONFIG: config path obtained: {}", path.display());

            match file_storage::load_config(Some(path.clone())) {
                Ok(config) => {
                    #[cfg(debug_assertions)]
                    log::info!("CONFIG: configuration loaded successfully from {}", path.display());
                    RwLock::new(config)
                }
                Err(e) => {
                    #[cfg(debug_assertions)]
                    log::error!("CONFIG: failed to load config from {}: {}", path.display(), e);

                    log::warn!("CONFIG: using default configuration due to load error");
                    RwLock::new(FishConfig::new())
                }
            }
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            log::error!("CONFIG: failed to get config path: {}", e);

            log::warn!("CONFIG: using default configuration (MIRCDIR not set)");

            #[cfg(debug_assertions)]
            log::info!("CONFIG: creating new FishConfig...");

            let new_config = FishConfig::new();

            #[cfg(debug_assertions)]
            log::info!("CONFIG: FishConfig created successfully");

            #[cfg(debug_assertions)]
            log::info!("CONFIG: Creating RwLock wrapper...");

            let lock = RwLock::new(new_config);

            #[cfg(debug_assertions)]
            log::info!("CONFIG: RwLock created successfully");

            #[cfg(debug_assertions)]
            log::info!("CONFIG: returning from Lazy::new...");

            lock
        }
    }
});

/// Force initialization of the CONFIG lazy static
/// This must be called during DLL initialization to avoid deadlocks
pub fn init_config() {
    #[cfg(debug_assertions)]
    log::info!("init_config: forcing CONFIG initialization...");

    // Just access CONFIG to trigger Lazy initialization
    let _ = &*CONFIG;

    #[cfg(debug_assertions)]
    log::info!("init_config: CONFIG initialized successfully");
}

/// Tries to perform an operation with exponential backoff
/// This function is useful for operations that might fail due to temporary conditions
/// and should be retried after a delay.
pub fn with_retry<F, T>(
    mut operation: F,
    max_attempts: usize,
    timeout: Duration,
) -> Result<T, String>
where
    F: FnMut() -> Result<T, String>,
{
    let start = Instant::now();
    let mut attempts = 0;

    while attempts < max_attempts {
        // Check for timeout
        if start.elapsed() > timeout {
            return Err(format!("Operation timed out after {} attempts", attempts));
        }

        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                attempts += 1;
                if attempts >= max_attempts {
                    return Err(format!("Operation failed after {} attempts: {}", attempts, e));
                }

                // Exponential backoff with jitter
                let base_ms = 10.0;
                let max_ms = 500.0;
                let backoff_ms = (base_ms * (1.5_f64.powi(attempts as i32))).min(max_ms);
                let jitter = rand::random::<f64>() * 0.1 * backoff_ms; // 10% jitter
                let sleep_ms = (backoff_ms + jitter) as u64;

                thread::sleep(Duration::from_millis(sleep_ms));
            }
        }
    }

    Err(format!("Operation failed after {} attempts", attempts))
}

/// Get the configuration directory path.
///
/// Resolution order:
/// 1. `MIRCDIR` environment variable (if set and exists)
/// 2. Platform-specific default:
///    - Windows: `%APPDATA%/mIRC` (mIRC convention)
///    - Linux/FreeBSD/macOS: `$XDG_CONFIG_HOME/fish_11` or `~/.config/fish_11`
pub fn get_mirc_directory() -> Result<std::path::PathBuf, String> {
    // Try environment variable first
    if let Ok(mirc_dir) = std::env::var("MIRCDIR") {
        let path = std::path::PathBuf::from(mirc_dir);
        if path.exists() {
            return Ok(path);
        }
    }

    // Platform-specific default
    #[cfg(windows)]
    let mut path = dirs::config_dir().ok_or("Could not determine config directory")?;
    #[cfg(windows)]
    path.push("mIRC");

    #[cfg(not(windows))]
    let path = {
        // Respect XDG_CONFIG_HOME on Linux/FreeBSD/macOS
        let config_base = std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(std::path::PathBuf::from)
            .or_else(|| dirs::home_dir().map(|h| h.join(".config")));
        config_base.ok_or("Could not determine config directory")?.join("fish_11")
    };

    // Create directory if it doesn't exist
    if !path.exists() {
        if let Err(e) = std::fs::create_dir_all(&path) {
            return Err(format!("Failed to create config directory: {}", e));
        }
    }

    Ok(path)
}

// Helper functions for channel key management
pub fn has_manual_channel_key(channel_name: &str) -> bool {
    get_manual_channel_key(channel_name).is_ok()
}

pub fn has_ratchet_channel_key(channel_name: &str) -> bool {
    // For now, we'll check if there's a ratchet state for this channel
    // This is a simplified check - in a real implementation, you'd want to
    // verify that the ratchet state has a valid current key
    with_config(|config| {
        let normalized_channel = channel_name.to_lowercase();
        Ok(config.channel_ratchet_states.contains_key(&normalized_channel))
    })
    .unwrap_or(false)
}

pub fn remove_manual_channel_key(channel_name: &str) -> Result<(), crate::error::FishError> {
    let normalized_channel = channel_name.to_lowercase();
    let safe_channel_name = normalized_channel.replace('#', "hash_");
    let entry_key = format!("channel_key_{}", safe_channel_name);

    with_config_mut(|config| {
        config.entries.remove(&entry_key);
        Ok(())
    })
}

pub fn remove_ratchet_channel_key(channel_name: &str) -> Result<(), crate::error::FishError> {
    let normalized_channel = channel_name.to_lowercase();

    with_config_mut(|config| {
        // Remove ratchet state for this channel
        config.channel_ratchet_states.remove(&normalized_channel);
        Ok(())
    })
}

/// Get the count of stored keys
pub fn count_keys() -> Result<usize, crate::error::FishError> {
    with_config(|config| {
        // Count user keys and channel keys
        let user_keys = config.entries.iter().filter(|(k, _)| k.starts_with("key_")).count();

        let channel_keys = config.channel_keys.len();
        let manual_channel_keys =
            config.entries.iter().filter(|(k, _)| k.starts_with("channel_key_")).count();

        Ok(user_keys + channel_keys + manual_channel_keys)
    })
}

/// Get the count of encryption operations
pub fn get_encryption_count() -> Result<usize, crate::error::FishError> {
    with_config(|config| Ok(config.metrics.encryption_count))
}

/// Get the count of decryption operations
pub fn get_decryption_count() -> Result<usize, crate::error::FishError> {
    with_config(|config| Ok(config.metrics.decryption_count))
}

/// Get the count of key exchange operations
pub fn get_key_exchange_count() -> Result<usize, crate::error::FishError> {
    with_config(|config| Ok(config.metrics.key_exchange_count))
}

/// Increment encryption counter
pub fn increment_encryption_counter() {
    with_config_mut(|config| {
        config.metrics.encryption_count = config.metrics.encryption_count.saturating_add(1);
        Ok(())
    })
    .ok();
}

/// Increment decryption counter
pub fn increment_decryption_counter() {
    with_config_mut(|config| {
        config.metrics.decryption_count = config.metrics.decryption_count.saturating_add(1);
        Ok(())
    })
    .ok();
}

/// Increment key exchange counter
pub fn increment_key_exchange_counter() {
    with_config_mut(|config| {
        config.metrics.key_exchange_count = config.metrics.key_exchange_count.saturating_add(1);
        Ok(())
    })
    .ok();
}
