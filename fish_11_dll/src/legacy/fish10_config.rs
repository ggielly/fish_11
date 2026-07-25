//! Legacy configuration management for FiSH 10 compatibility
//!
//! This module handles loading and saving legacy blowfish.ini files
//! and managing legacy key configuration.

use std::path::PathBuf;

use crate::unified_error::DllError;

/// Load legacy configuration from blowfish.ini
pub fn load_legacy_config() -> Result<(), DllError> {
    // Get the blowfish.ini path
    let ini_path = get_blowfish_ini_path()?;

    log::info!("LEGACY: Loading configuration from {}", ini_path.display());

    // Update the global legacy configuration
    {
        let mut config = super::LEGACY_CONFIG.write();
        config.blowfish_ini_path = Some(ini_path.to_string_lossy().into_owned());
    }

    // Check if the file exists
    if !ini_path.exists() {
        log::info!("LEGACY: blowfish.ini not found, starting with empty legacy config");
        return Ok(());
    }

    // Load keys from the blowfish.ini file
    let keys = load_keys_from_blowfish_ini(&ini_path)?;

    // Update the key store
    let config = super::LEGACY_CONFIG.read();
    let mut legacy_keys = config.legacy_keys.write();

    for (target, key) in keys {
        legacy_keys.insert(target, key);
    }

    log::info!("LEGACY: Loaded {} legacy keys", legacy_keys.len());

    Ok(())
}

/// Get the path to blowfish.ini file
fn get_blowfish_ini_path() -> Result<PathBuf, DllError> {
    // Try to get the mIRC directory from the main config
    let mirc_dir = crate::config::get_mirc_directory()?;

    let ini_path = mirc_dir.join("blowfish.ini");
    Ok(ini_path)
}

/// Load keys from blowfish.ini file
/// Supports both legacy format (target=hexkey) and FiSH 10 format with sections
fn load_keys_from_blowfish_ini(
    path: &std::path::Path,
) -> Result<std::collections::HashMap<String, Vec<u8>>, DllError> {
    use std::fs;
    use std::io::BufRead;

    let mut keys = std::collections::HashMap::new();
    let mut current_section: Option<String> = None;

    // Read the file line by line
    let file = fs::File::open(path).map_err(|e| DllError::LegacyError {
        context: "Reading blowfish.ini".to_string(),
        cause: format!("Failed to open file: {}", e),
    })?;

    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| DllError::LegacyError {
            context: "Reading blowfish.ini".to_string(),
            cause: format!("Failed to read line: {}", e),
        })?;

        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with(';') || (line.starts_with('#') && !line.contains('='))
        {
            continue;
        }

        // Check for section headers like [network:target] or [target]
        if line.starts_with('[') && line.ends_with(']') {
            let section_name = &line[1..line.len() - 1];
            current_section = Some(section_name.to_string());

            #[cfg(debug_assertions)]
            log::debug!("LEGACY: Found section [{}]", section_name);

            continue;
        }

        // Parse key=value format
        if let Some((key_name, key_value)) = parse_ini_line(line) {
            // Determine the target name
            let target = if key_name.eq_ignore_ascii_case("key") {
                // If the key name is "key", use the section name as target
                match &current_section {
                    Some(section) => section.clone(),
                    None => {
                        #[cfg(debug_assertions)]
                        log::warn!("LEGACY: Found 'key=' without a section, skipping");

                        continue;
                    }
                }
            } else {
                // Use the key name as target (legacy format: target=key)
                key_name.clone()
            };

            // Decode the key value - handle both hex and plaintext formats
            let key_bytes = decode_key_value(&key_value)?;

            // Validate key length (Blowfish accepts 4-56 bytes)
            if key_bytes.len() >= 4 && key_bytes.len() <= 56 {
                let normalized_target = crate::utils::normalize_target_lowercase(&target);

                keys.insert(normalized_target.clone(), key_bytes);

                #[cfg(debug_assertions)]
                log::debug!("LEGACY: Loaded key for '{}'", normalized_target);
            } else {
                #[cfg(debug_assertions)]
                log::warn!(
                    "LEGACY: Invalid key length for '{}' ({} bytes), skipping",
                    target,
                    key_bytes.len()
                );
            }
        }
    }

    Ok(keys)
}

/// Decode a key value from blowfish.ini
/// Supports:
/// - Hex encoded keys (e.g., "6162636465666768")
/// - Plaintext keys with +OK prefix (e.g., "+OK secretpassword")
/// - Plain text keys (e.g., "mysecretkey")
fn decode_key_value(value: &str) -> Result<Vec<u8>, DllError> {
    let value = value.trim();

    // Check for +OK prefix (FiSH 10 plaintext key format)
    if let Some(plaintext) = value.strip_prefix("+OK ") {
        return Ok(plaintext.as_bytes().to_vec());
    }

    // Check for mcps prefix (CBC mode plaintext key)
    if let Some(plaintext) = value.strip_prefix("mcps ") {
        return Ok(plaintext.as_bytes().to_vec());
    }

    // Try to decode as hex
    if value.chars().all(|c| c.is_ascii_hexdigit()) && value.len() % 2 == 0 {
        return hex::decode(value).map_err(|e| DllError::LegacyError {
            context: "Decoding hex key".to_string(),
            cause: format!("Invalid hex: {}", e),
        });
    }

    // Assume it's a plaintext key
    Ok(value.as_bytes().to_vec())
}

/// Parse a blowfish.ini line in format: target=hexkey
fn parse_ini_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();

    if parts.len() == 2 {
        let target = parts[0].trim().to_string();
        let key_hex = parts[1].trim().to_string();

        // Skip empty targets or keys
        if !target.is_empty() && !key_hex.is_empty() {
            return Some((target, key_hex));
        }
    }

    None
}

/// Save a key to blowfish.ini file (replaces existing if found)
pub fn save_key_to_blowfish_ini(target: &str, key: &[u8], path: &str) -> Result<(), DllError> {
    update_blowfish_ini_key(target, Some(key), path)
}

/// Remove a key from blowfish.ini file
pub fn remove_key_from_blowfish_ini(target: &str, path: &str) -> Result<(), DllError> {
    update_blowfish_ini_key(target, None, path)
}

/// Internal helper to add, update, or remove a key in blowfish.ini
fn update_blowfish_ini_key(
    target: &str,
    key: Option<&[u8]>,
    path_str: &str,
) -> Result<(), DllError> {
    use std::fs;
    use std::io::{BufRead, BufReader, Write};
    use std::path::Path;

    let path = Path::new(path_str);
    let mut lines = Vec::new();
    let mut found = false;
    let target_lower = target.to_lowercase();

    if path.exists() {
        let file = fs::File::open(path).map_err(|e| DllError::LegacyError {
            context: "Updating blowfish.ini".to_string(),
            cause: format!("Failed to open file: {}", e),
        })?;
        let reader = BufReader::new(file);

        let mut current_section: Option<String> = None;

        for line in reader.lines() {
            let line = line.map_err(|e| DllError::LegacyError {
                context: "Updating blowfish.ini".to_string(),
                cause: format!("Failed to read line: {}", e),
            })?;

            let trimmed = line.trim();

            // Handle section headers
            if trimmed.starts_with('[') && trimmed.ends_with(']') {
                current_section = Some(trimmed[1..trimmed.len() - 1].to_string());
                lines.push(line);
                continue;
            }

            if let Some((key_name, _)) = parse_ini_line(trimmed) {
                // Determine what target this line refers to
                let line_target = if key_name.eq_ignore_ascii_case("key") {
                    // If it's "key=...", it refers to the current section
                    current_section.clone()
                } else {
                    // Otherwise it's "target=..."
                    Some(key_name.clone())
                };

                if let Some(t) = line_target {
                    if t.to_lowercase() == target_lower {
                        found = true;
                        if let Some(k) = key {
                            // Preserve the format (either key=value or target=value)
                            if key_name.eq_ignore_ascii_case("key") {
                                lines.push(format!("key={}", hex::encode(k)));
                            } else {
                                lines.push(format!("{}={}", target, hex::encode(k)));
                            }
                        }
                        // If key is None, we skip (delete)
                        continue;
                    }
                }
            }
            lines.push(line);
        }
    }

    if !found {
        if let Some(k) = key {
            lines.push(format!("{}={}", target, hex::encode(k)));
        }
    }

    let mut file = fs::File::create(path).map_err(|e| DllError::LegacyError {
        context: "Updating blowfish.ini".to_string(),
        cause: format!("Failed to create file: {}", e),
    })?;

    for line in lines {
        writeln!(file, "{}", line).map_err(|e| DllError::LegacyError {
            context: "Updating blowfish.ini".to_string(),
            cause: format!("Failed to write: {}", e),
        })?;
    }

    #[cfg(debug_assertions)]
    if let Some(_) = key {
        log::debug!("LEGACY: Updated key for '{}' in {}", target, path_str);
    } else {
        log::debug!("LEGACY: Removed key for '{}' from {}", target, path_str);
    }

    Ok(())
}

/// Get the topic encryption setting for a channel
pub fn get_encrypt_topic_setting(network: &str, channel: &str) -> Result<bool, DllError> {
    // Try to get the blowfish.ini path
    let ini_path = match get_blowfish_ini_path() {
        Ok(path) => path,
        Err(_) => return Ok(false), // Default to false if we can't get the path
    };

    // Check if the file exists
    if !ini_path.exists() {
        return Ok(false); // Default to false if file doesn't exist
    }

    // Try to read the INI file
    let file_content = match std::fs::read_to_string(&ini_path) {
        Ok(content) => content,
        Err(_) => return Ok(false), // Default to false if we can't read the file
    };

    // Parse the INI content to find the channel section and encrypt_topic setting
    let section_name = format!("{}:{}", network, channel);
    let mut in_section = false;
    let mut encrypt_topic = false;

    for line in file_content.lines() {
        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        // Check for section headers
        if line.starts_with('[') && line.ends_with(']') {
            let current_section = &line[1..line.len() - 1];
            in_section = current_section == section_name;
            continue;
        }

        // If we're in the right section, look for encrypt_topic setting
        if in_section && line.starts_with("encrypt_topic=") {
            let value = line.split('=').nth(1).unwrap_or("").trim();
            encrypt_topic = value == "1" || value.eq_ignore_ascii_case("true");
            break;
        }
    }

    Ok(encrypt_topic)
}

/// Set the topic encryption setting for a channel
pub fn set_encrypt_topic_setting(
    network: &str,
    channel: &str,
    enabled: bool,
) -> Result<(), DllError> {
    use ini::Ini;
    let ini_path = get_blowfish_ini_path()?;

    let section_name = format!("{}:{}", network, channel);
    let value = if enabled { "1" } else { "0" };

    let mut conf = if std::path::Path::new(&ini_path).exists() {
        Ini::load_from_file(&ini_path).map_err(|e| DllError::LegacyError {
            context: "Loading blowfish.ini".to_string(),
            cause: format!("Failed to load: {}", e),
        })?
    } else {
        Ini::new()
    };

    conf.with_section(Some(section_name.clone())).set("encrypt_topic", value);

    conf.write_to_file(&ini_path).map_err(|e| DllError::LegacyError {
        context: "Writing to blowfish.ini".to_string(),
        cause: format!("Failed to write: {}", e),
    })?;

    #[cfg(debug_assertions)]
    log::debug!("LEGACY: Set encrypt_topic={} for {}", enabled, section_name);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_parse_ini_line() {
        let result = parse_ini_line("#test=6162636465666768");
        assert!(result.is_some());
        let (target, key) = result.unwrap();
        assert_eq!(target, "#test");
        assert_eq!(key, "6162636465666768");
    }

    #[test]
    fn test_parse_ini_line_invalid() {
        let result = parse_ini_line("invalidline");
        assert!(result.is_none());
    }

    #[test]
    fn test_load_keys_from_ini_legacy_format() {
        // Create a temporary blowfish.ini file with legacy format
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "#test=6162636465666768").unwrap();
        writeln!(temp_file, "#another=1234567890abcdef").unwrap();
        writeln!(temp_file, "; This is a comment").unwrap();
        writeln!(temp_file, "").unwrap();

        let path = temp_file.path();
        let result = load_keys_from_blowfish_ini(path);

        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("#test"));
        assert!(keys.contains_key("#another"));
    }

    #[test]
    fn test_load_keys_from_ini_section_format() {
        // Create a temporary blowfish.ini file with section format
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "[irc.server.net:#channel]").unwrap();
        writeln!(temp_file, "key=6162636465666768").unwrap();
        writeln!(temp_file, "[user:nickname]").unwrap();
        writeln!(temp_file, "key=0102030405060708").unwrap();

        let path = temp_file.path();
        let result = load_keys_from_blowfish_ini(path);

        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("irc.server.net:#channel"));
        assert!(keys.contains_key("user:nickname"));
    }

    #[test]
    fn test_decode_key_value_hex() {
        let result = decode_key_value("6162636465666768");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"abcdefgh");
    }

    #[test]
    fn test_decode_key_value_plaintext_ok() {
        let result = decode_key_value("+OK mysecretkey");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"mysecretkey");
    }

    #[test]
    fn test_decode_key_value_plaintext_mcps() {
        let result = decode_key_value("mcps cbcsecret");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"cbcsecret");
    }

    #[test]
    fn test_decode_key_value_plaintext_fallback() {
        let result = decode_key_value("notahexkey123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"notahexkey123");
    }

    #[test]
    fn test_encrypt_topic_setting() {
        // Test getting the setting for a non-existent network/channel (should default to false)
        let result =
            get_encrypt_topic_setting("nonexistent_network_12345", "#nonexistent_channel_67890");
        assert!(result.is_ok());
        // The function should return false by default when the setting is not found
        let value = result.unwrap();
        eprintln!("DEBUG: encrypt_topic setting value: {}", value);
        assert!(!value); // Should default to false
    }

    #[test]
    fn test_encrypt_topic_setting_nonexistent() {
        // Test getting setting for non-existent file
        let result = get_encrypt_topic_setting("nonexistent", "#channel");
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should default to false
    }
}
