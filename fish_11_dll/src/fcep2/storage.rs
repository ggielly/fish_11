//! FCEP-2 Persistence Manager (fish_fcep.ini)
//!
//! Handles saving and loading FCEP-2 device state, group bindings, KeyPackages,
//! and serialized MLS group states in `fish_fcep.ini` with automatic master key encryption support.

use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ini::Ini;

use super::mls_engine::LocalDevice;
use super::types::PersistedGroup;
use crate::unified_error::DllError;

const ENCRYPTED_FCEP_HEADER: &str = "# FiSH_11_ENCRYPTED_FCEP_V1";
const FCEP_INI_FILENAME: &str = "fish_fcep.ini";

/// Locate path to `fish_fcep.ini`
pub fn get_fcep_ini_path() -> PathBuf {
    if let Ok(mirc_dir) = std::env::var("MIRCDIR") {
        if !mirc_dir.trim().is_empty() {
            let mut path = PathBuf::from(mirc_dir);
            path.push(FCEP_INI_FILENAME);
            return path;
        }
    }
    PathBuf::from(FCEP_INI_FILENAME)
}

/// FCEP-2 Persistence Controller
pub struct FcepStorage {
    ini_path: PathBuf,
}

impl Default for FcepStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl FcepStorage {
    pub fn new() -> Self {
        Self { ini_path: get_fcep_ini_path() }
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { ini_path: path }
    }

    /// Load or initialize local device identity from `fish_fcep.ini`
    pub fn load_or_create_device(&self, label: &str) -> Result<LocalDevice, DllError> {
        let ini = self.load_ini()?;

        if let Some(sec) = ini.section(Some("device")) {
            if let (Some(dev_id_hex), Some(seed_hex)) =
                (sec.get("device_id"), sec.get("signing_seed"))
            {
                let dev_id_bytes = hex::decode(dev_id_hex).map_err(|e| DllError::InvalidInput {
                    param: "device_id".to_string(),
                    reason: e.to_string(),
                })?;
                let seed_bytes = hex::decode(seed_hex).map_err(|e| DllError::InvalidInput {
                    param: "signing_seed".to_string(),
                    reason: e.to_string(),
                })?;

                if dev_id_bytes.len() == 16 && seed_bytes.len() == 32 {
                    let mut dev_id = [0u8; 16];
                    dev_id.copy_from_slice(&dev_id_bytes);

                    let mut seed = [0u8; 32];
                    seed.copy_from_slice(&seed_bytes);

                    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                    let verifying_key = signing_key.verifying_key();

                    return Ok(LocalDevice {
                        device_id: dev_id,
                        signing_key,
                        verifying_key,
                        display_label: label.to_string(),
                    });
                }
            }
        }

        // Generate fresh local device
        let dev = LocalDevice::generate(label);
        self.save_device(&dev)?;
        Ok(dev)
    }

    /// Save local device parameters to `fish_fcep.ini`
    pub fn save_device(&self, dev: &LocalDevice) -> Result<(), DllError> {
        let mut ini = self.load_ini().unwrap_or_else(|_| Ini::new());

        ini.with_section(Some("device"))
            .set("device_id", hex::encode(dev.device_id))
            .set("signing_seed", hex::encode(dev.signing_key.to_bytes()))
            .set("display_label", &dev.display_label);

        self.save_ini(&ini)
    }

    /// Save a `PersistedGroup` to `fish_fcep.ini`
    pub fn save_group(&self, group: &PersistedGroup) -> Result<(), DllError> {
        let mut ini = self.load_ini().unwrap_or_else(|_| Ini::new());

        let section_name = format!("group_{}", hex::encode(&group.binding.mls_group_id));
        let serialized_json =
            serde_json::to_string(group).map_err(|e| DllError::ProcessingError(e.to_string()))?;

        ini.with_section(Some(&section_name))
            .set("canonical_channel", &group.binding.canonical_channel)
            .set("current_epoch", group.current_epoch.to_string())
            .set("data", STANDARD.encode(serialized_json));

        self.save_ini(&ini)
    }

    /// Load a `PersistedGroup` by MLS Group ID
    pub fn load_group(&self, mls_group_id: &[u8]) -> Result<Option<PersistedGroup>, DllError> {
        let ini = self.load_ini()?;
        let section_name = format!("group_{}", hex::encode(mls_group_id));

        if let Some(sec) = ini.section(Some(&section_name)) {
            if let Some(b64_data) = sec.get("data") {
                let decoded_bytes =
                    STANDARD.decode(b64_data).map_err(|e| DllError::InvalidInput {
                        param: "group_data".to_string(),
                        reason: e.to_string(),
                    })?;
                let json_str =
                    String::from_utf8(decoded_bytes).map_err(|e| DllError::InvalidInput {
                        param: "group_data".to_string(),
                        reason: e.to_string(),
                    })?;
                let group: PersistedGroup = serde_json::from_str(&json_str)
                    .map_err(|e| DllError::ProcessingError(e.to_string()))?;
                return Ok(Some(group));
            }
        }
        Ok(None)
    }

    /// Load INI content with automatic Master Key decryption if encrypted
    fn load_ini(&self) -> Result<Ini, DllError> {
        if !self.ini_path.exists() {
            return Ok(Ini::new());
        }

        let content = fs::read_to_string(&self.ini_path).map_err(DllError::from)?;

        if content.starts_with(ENCRYPTED_FCEP_HEADER) {
            let lines: Vec<&str> = content.lines().collect();
            if lines.len() < 2 {
                return Err(DllError::InvalidInput {
                    param: "fcep_ini".to_string(),
                    reason: "Malformed encrypted fcep.ini header".to_string(),
                });
            }

            if !crate::dll_interface::fish11_masterkey::is_master_key_unlocked() {
                return Err(DllError::MasterKeyLocked);
            }

            let master_key = crate::dll_interface::fish11_masterkey::get_master_key_from_memory()
                .ok_or(DllError::MasterKeyLocked)?;

            let encrypted_bytes = STANDARD.decode(lines[1]).map_err(|e| {
                DllError::InvalidInput { param: "fcep_ini".to_string(), reason: e.to_string() }
            })?;

            let blob = fish_11_core::master_key::EncryptedBlob::from_bytes(&encrypted_bytes)
                .ok_or_else(|| DllError::ProcessingError("Invalid encrypted blob".to_string()))?;

            let kek = fish_11_core::master_key::derive_config_kek(&master_key);
            let decrypted_bytes = fish_11_core::master_key::decrypt_data(&blob, &kek)
                .map_err(|e| DllError::ProcessingError(format!("Decryption failed: {}", e)))?;

            let decrypted_str = String::from_utf8(decrypted_bytes)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;
            Ini::load_from_str(&decrypted_str).map_err(|e| DllError::ProcessingError(e.to_string()))
        } else {
            Ini::load_from_str(&content).map_err(|e| DllError::ProcessingError(e.to_string()))
        }
    }

    /// Save INI content with automatic Master Key encryption if master key unlocked.
    /// Uses crash-safe write: temp file => fsync => rename => directory sync.
    fn save_ini(&self, ini: &Ini) -> Result<(), DllError> {
        use std::io::Write;

        let mut buffer = Cursor::new(Vec::new());
        ini.write_to(&mut buffer).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        let raw_ini_str = String::from_utf8(buffer.into_inner())
            .map_err(|e| DllError::ProcessingError(e.to_string()))?;

        let is_unlocked = crate::dll_interface::fish11_masterkey::is_master_key_unlocked();

        let final_content = if is_unlocked {
            if let Some(master_key) =
                crate::dll_interface::fish11_masterkey::get_master_key_from_memory()
            {
                let kek = fish_11_core::master_key::derive_config_kek(&master_key);
                let blob = fish_11_core::master_key::encrypt_data(
                    raw_ini_str.as_bytes(),
                    &kek,
                    "fcep_ini",
                    0,
                )
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;
                let enc_b64 = STANDARD.encode(blob.to_bytes());
                format!("{}\n{}\n", ENCRYPTED_FCEP_HEADER, enc_b64)
            } else {
                raw_ini_str
            }
        } else {
            raw_ini_str
        };

        if let Some(parent) = self.ini_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).map_err(DllError::from)?;
            }
        }

        // Crash-safe write: unique temp file => write => fsync => rename => dir sync
        let mut temp_path = self.ini_path.clone();
        let mut rng_seed = [0u8; 8];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut rng_seed);
        temp_path.set_extension(format!("tmp.{:016x}", u64::from_be_bytes(rng_seed)));

        // Step 1: Write to temp file
        {
            let mut file = fs::File::create(&temp_path).map_err(DllError::from)?;
            file.write_all(final_content.as_bytes()).map_err(DllError::from)?;
            // Step 2: fsync the file data
            file.sync_all().map_err(DllError::from)?;
        }

        // Step 3: Atomic rename (same filesystem guaranteed by temp_path being in same dir)
        fs::rename(&temp_path, &self.ini_path).map_err(|e| {
            // Clean up temp file on rename failure
            let _ = fs::remove_file(&temp_path);
            DllError::from(e)
        })?;

        // Step 4: Sync parent directory to ensure rename is durable
        if let Some(parent) = self.ini_path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                // Best-effort directory sync; not all filesystems support this
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// Save outbox state for a group
    pub fn save_outbox(
        &self,
        group_id: &[u8],
        outbox: &super::types::OutboxState,
    ) -> Result<(), DllError> {
        let mut ini = self.load_ini().unwrap_or_else(|_| Ini::new());
        let section = format!("outbox_{}", hex::encode(group_id));
        let data =
            serde_json::to_string(outbox).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        ini.with_section(Some(&section)).set("data", STANDARD.encode(data));
        self.save_ini(&ini)
    }

    /// Load outbox state for a group
    pub fn load_outbox(
        &self,
        group_id: &[u8],
    ) -> Result<Option<super::types::OutboxState>, DllError> {
        let ini = self.load_ini()?;
        let section = format!("outbox_{}", hex::encode(group_id));
        if let Some(sec) = ini.section(Some(&section)) {
            if let Some(b64) = sec.get("data") {
                let bytes = STANDARD.decode(b64).map_err(|e| DllError::InvalidInput {
                    param: "outbox_data".to_string(),
                    reason: e.to_string(),
                })?;
                let json = String::from_utf8(bytes).map_err(|e| DllError::InvalidInput {
                    param: "outbox_data".to_string(),
                    reason: e.to_string(),
                })?;
                let outbox: super::types::OutboxState = serde_json::from_str(&json)
                    .map_err(|e| DllError::ProcessingError(e.to_string()))?;
                return Ok(Some(outbox));
            }
        }
        Ok(None)
    }

    /// Save KeyPackage pool
    pub fn save_keypackage_pool(
        &self,
        pool: &[super::types::KeyPackagePoolEntry],
    ) -> Result<(), DllError> {
        let mut ini = self.load_ini().unwrap_or_else(|_| Ini::new());
        let data =
            serde_json::to_string(pool).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        ini.with_section(Some("keypackage_pool")).set("data", STANDARD.encode(data));
        self.save_ini(&ini)
    }

    /// Load KeyPackage pool
    pub fn load_keypackage_pool(&self) -> Result<Vec<super::types::KeyPackagePoolEntry>, DllError> {
        let ini = self.load_ini()?;
        if let Some(sec) = ini.section(Some("keypackage_pool")) {
            if let Some(b64) = sec.get("data") {
                let bytes = STANDARD.decode(b64).map_err(|e| DllError::InvalidInput {
                    param: "pool_data".to_string(),
                    reason: e.to_string(),
                })?;
                let json = String::from_utf8(bytes).map_err(|e| DllError::InvalidInput {
                    param: "pool_data".to_string(),
                    reason: e.to_string(),
                })?;
                let pool: Vec<super::types::KeyPackagePoolEntry> = serde_json::from_str(&json)
                    .map_err(|e| DllError::ProcessingError(e.to_string()))?;
                return Ok(pool);
            }
        }
        Ok(Vec::new())
    }

    /// Save diagnostics log
    pub fn save_diagnostics(
        &self,
        events: &[super::types::DiagnosticEvent],
    ) -> Result<(), DllError> {
        let mut ini = self.load_ini().unwrap_or_else(|_| Ini::new());
        let data =
            serde_json::to_string(events).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        ini.with_section(Some("diagnostics")).set("data", STANDARD.encode(data));
        self.save_ini(&ini)
    }

    /// Load diagnostics log
    pub fn load_diagnostics(&self) -> Result<Vec<super::types::DiagnosticEvent>, DllError> {
        let ini = self.load_ini()?;
        if let Some(sec) = ini.section(Some("diagnostics")) {
            if let Some(b64) = sec.get("data") {
                let bytes = STANDARD.decode(b64).map_err(|e| DllError::InvalidInput {
                    param: "diag_data".to_string(),
                    reason: e.to_string(),
                })?;
                let json = String::from_utf8(bytes).map_err(|e| DllError::InvalidInput {
                    param: "diag_data".to_string(),
                    reason: e.to_string(),
                })?;
                let events: Vec<super::types::DiagnosticEvent> = serde_json::from_str(&json)
                    .map_err(|e| DllError::ProcessingError(e.to_string()))?;
                return Ok(events);
            }
        }
        Ok(Vec::new())
    }

    /// Export a group as a base64-encoded JSON blob for backup/transfer
    pub fn export_group_json(
        &self,
        group: &super::types::PersistedGroup,
    ) -> Result<String, DllError> {
        let json =
            serde_json::to_string(group).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        Ok(STANDARD.encode(json))
    }

    /// Import a group from a base64-encoded JSON blob
    pub fn import_group_json(
        &self,
        b64_json: &str,
    ) -> Result<super::types::PersistedGroup, DllError> {
        let bytes = STANDARD.decode(b64_json).map_err(|e| DllError::InvalidInput {
            param: "import_data".to_string(),
            reason: e.to_string(),
        })?;
        let json = String::from_utf8(bytes).map_err(|e| DllError::InvalidInput {
            param: "import_data".to_string(),
            reason: e.to_string(),
        })?;
        let group: super::types::PersistedGroup =
            serde_json::from_str(&json).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        Ok(group)
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn test_storage_device_and_group() {
        let tmp_file = NamedTempFile::new().unwrap();
        let path = tmp_file.path().to_path_buf();
        let storage = FcepStorage::with_path(path);

        let dev = storage.load_or_create_device("TestUser").unwrap();
        assert_eq!(dev.display_label, "TestUser");

        let loaded_dev = storage.load_or_create_device("TestUser").unwrap();
        assert_eq!(loaded_dev.device_id, dev.device_id);
    }
}
