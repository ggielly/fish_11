//! FCEP-2 Encrypted Persistence Layer
//!
//! Provides atomic, encrypted, rollback-resistant storage for MLS group state
//! and outbox records. Replaces the old `fish_fcep.ini` plaintext approach.
//!
//! # Security guarantees
//!
//! - All sensitive data (MLS group state, key references) is encrypted at rest.
//! - Writes are atomic: temp file => fsync => rename => parent fsync.
//! - If the secret is locked, no read or write is permitted : no silent plaintext fallback.
//! - Rollback detection requires an external monotonic counter (see notes).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::types::{CommitConflict, GroupBinding};
use crate::unified_error::DllError;

// ===== SecretBox Trait =====

/// Encryption/decryption interface for persistent MLS state.
///
/// Implementations should use platform-appropriate secure storage:
/// - Windows: DPAPI (CryptProtectData, current-user scope)
/// - Linux/macOS: platform secret service or AEAD key derived via Argon2id
///
/// When the secret is locked/unavailable, the implementation MUST return
/// an error : it MUST NOT fall back to plaintext.
pub trait SecretBox: Send + Sync {
    /// Encrypt `plaintext` with associated data `aad`.
    fn seal(&self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DllError>;
    /// Decrypt `ciphertext` with associated data `aad`.
    fn open(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, DllError>;
}

/// A SecretBox that provides no encryption (plaintext).
///
/// Used for development/testing only. Production MUST use a real encryption
/// implementation (DPAPI, Argon2id+AEAD, etc.).
pub struct NoopSecretBox;

impl SecretBox for NoopSecretBox {
    fn seal(&self, plaintext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, DllError> {
        Ok(plaintext.to_vec())
    }
    fn open(&self, ciphertext: &[u8], _aad: &[u8]) -> Result<Vec<u8>, DllError> {
        Ok(ciphertext.to_vec())
    }
}

// ===== Group Record ────────────────────────────────────────────────

/// Complete group record stored on disk.
///
/// `openmls_state` contains the OpenMLS-managed group state blob : opaque bytes
/// produced/consumed by the OpenMLS StorageProvider. The transport layer MUST
/// NOT inspect or interpret this data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupRecord {
    pub schema_version: u32,
    pub binding: Binding,
    /// Opaque OpenMLS group state bytes.
    pub openmls_state: Vec<u8>,
    pub unresolved_conflict: Option<ConflictRecord>,
    pub outbox: Vec<OutboxRecord>,
    pub next_outbox_sequence: u64,
}

/// Serializable binding (transport-safe, no crypto material).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Binding {
    pub protocol_version: u16,
    pub network_id: [u8; 32],
    pub canonical_channel: String,
    pub mls_group_id: Vec<u8>,
    pub created_at_unix: i64,
}

/// Serializable outbox record with retry metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxRecord {
    pub id: [u8; 16],
    pub sequence: u64,
    pub kind: u8,
    pub target: String,
    /// The complete IRC-ready line (pre-budget-checked).
    pub wire_payload: String,
    pub expires_at_unix: i64,
    pub retry_count: u8,
    pub last_attempt_at_unix: i64,
}

/// Serialized commit conflict evidence (raw MLS bytes only, no plaintext).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub parent_epoch: u64,
    /// Raw TLS-serialized MLS Commit messages.
    pub competing_commits: Vec<Vec<u8>>,
    pub detected_at_unix: i64,
    pub source_diagnostics: Vec<String>,
}

// ===== Encrypted File Store ────────────────────────────────────────

/// Encrypted, atomic file store for MLS group records.
///
/// Each group is stored in a separate encrypted file under `root/`.
/// File naming: `{hex(group_id)}.state`
pub struct EncryptedFileStore<S: SecretBox> {
    root: PathBuf,
    secret: S,
}

impl<S: SecretBox> EncryptedFileStore<S> {
    pub fn new(root: PathBuf, secret: S) -> Self {
        Self { root, secret }
    }

    fn path(&self, gid: &[u8]) -> PathBuf {
        self.root.join(format!("{}.state", hex::encode(gid)))
    }

    /// Load a group record from disk.
    ///
    /// Returns `None` if the file does not exist.
    /// Returns an error if the secret is locked, the file is corrupt, or
    /// decryption fails.
    pub fn load(&self, gid: &[u8]) -> Result<Option<GroupRecord>, DllError> {
        let path = self.path(gid);
        if !path.exists() {
            return Ok(None);
        }
        let ct = fs::read(&path).map_err(|e| {
            DllError::ConfigError(format!(
                "Failed to read state file for group {}: {}",
                hex::encode(gid),
                e
            ))
        })?;
        let pt = self
            .secret
            .open(&ct, gid)
            .map_err(|_| DllError::ConfigError("Secret locked or decryption failed".to_string()))?;
        let record: GroupRecord = serde_json::from_slice(&pt).map_err(|e| {
            DllError::ConfigError(format!("Failed to deserialize group record: {}", e))
        })?;
        Ok(Some(record))
    }

    /// Save a group record atomically.
    ///
    /// Sequence: serialize => encrypt => write temp => fsync => rename => parent fsync
    /// If encryption fails (secret locked), the write is aborted : no plaintext is persisted.
    pub fn save(&self, record: &GroupRecord) -> Result<(), DllError> {
        fs::create_dir_all(&self.root).map_err(|e| {
            DllError::ConfigError(format!("Failed to create store directory: {}", e))
        })?;
        let pt = serde_json::to_vec(record)
            .map_err(|e| DllError::ConfigError(format!("Serialization failed: {}", e)))?;
        let ct = self.secret.seal(&pt, &record.binding.mls_group_id).map_err(|_| {
            DllError::ConfigError("Secret locked: cannot persist group state".to_string())
        })?;
        atomic_replace(&self.path(&record.binding.mls_group_id), &ct)?;
        Ok(())
    }

    /// Delete a group record from disk.
    pub fn delete(&self, gid: &[u8]) -> Result<(), DllError> {
        let path = self.path(gid);
        if path.exists() {
            fs::remove_file(&path).map_err(|e| {
                DllError::ConfigError(format!("Failed to delete state file: {}", e))
            })?;
        }
        Ok(())
    }
}

// ===== Atomic File Write ───────────────────────────────────────────

/// Atomically replace a file with new content.
///
/// 1. Write to a unique temporary file (`.{name}.{random}.tmp`)
/// 2. `sync_all()` to force data to disk
/// 3. `rename()` atomically to the final path
/// 4. Best-effort `sync_all()` on parent directory
pub fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<(), DllError> {
    let parent = path
        .parent()
        .ok_or_else(|| DllError::ConfigError("Path has no parent directory".to_string()))?;
    fs::create_dir_all(parent)
        .map_err(|e| DllError::ConfigError(format!("Failed to create parent directory: {}", e)))?;

    let file_name = path.file_name().unwrap().to_string_lossy();
    let rand_suffix: u64 = rand::random();
    let tmp_path = parent.join(format!(".{}.{}.tmp", file_name, rand_suffix));

    // Write to temp file
    {
        let mut f = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&tmp_path)
            .map_err(|e| DllError::ConfigError(format!("Failed to create temp file: {}", e)))?;
        f.write_all(bytes).map_err(|e| DllError::ConfigError(format!("Write failed: {}", e)))?;
        f.sync_all().map_err(|e| DllError::ConfigError(format!("Fsync temp failed: {}", e)))?;
    }

    // Atomic rename
    fs::rename(&tmp_path, path)
        .map_err(|e| DllError::ConfigError(format!("Rename failed: {}", e)))?;

    // Best-effort parent directory sync
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(())
}

// ===== Conversion helpers (old types => new types) ──────────────────

impl From<&GroupBinding> for Binding {
    fn from(b: &GroupBinding) -> Self {
        Self {
            protocol_version: b.protocol_version,
            network_id: b.network_id,
            canonical_channel: b.canonical_channel.clone(),
            mls_group_id: b.mls_group_id.clone(),
            created_at_unix: b.created_at_unix,
        }
    }
}

impl From<Binding> for GroupBinding {
    fn from(b: Binding) -> Self {
        Self {
            protocol_version: b.protocol_version,
            network_id: b.network_id,
            canonical_channel: b.canonical_channel,
            mls_group_id: b.mls_group_id,
            creator_fingerprint: [0u8; 32], // filled externally
            created_at_unix: b.created_at_unix,
        }
    }
}

impl From<&CommitConflict> for ConflictRecord {
    fn from(c: &CommitConflict) -> Self {
        Self {
            parent_epoch: c.old_epoch,
            competing_commits: c.conflicting_commits.clone(),
            detected_at_unix: c.detected_at_unix,
            source_diagnostics: c.source_diagnostics.clone(),
        }
    }
}

impl From<ConflictRecord> for CommitConflict {
    fn from(c: ConflictRecord) -> Self {
        Self {
            group_id: Vec::new(), // filled externally
            old_epoch: c.parent_epoch,
            conflicting_commits: c.competing_commits,
            detected_at_unix: c.detected_at_unix,
            source_diagnostics: c.source_diagnostics,
        }
    }
}
