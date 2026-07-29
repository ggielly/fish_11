//! State persistence for FCEP-2 groups
//!
//! Handles atomic read/write of MLS group state, device identity,
//! known devices, commit conflicts, and outbox entries.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Fcep2Error, Result};
use crate::identity::{DeviceIdentity, GroupBinding, TrustState};

/// Maximum outbox age before automatic discard (24 hours).
pub const OUTBOX_MAX_AGE_SECS: i64 = 86400;

/// Maximum outbox retries before permanent failure.
pub const OUTBOX_MAX_RETRIES: u8 = 5;

/// Delay between outbox retries (exponential backoff: 30s, 60s, 120s, ...).
pub const OUTBOX_RETRY_BASE_SECS: u64 = 30;

/// Persisted state for a single FCEP-2 group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedGroup {
    /// Group binding (IRC network + channel + MLS group ID).
    pub binding: GroupBindingData,
    /// Serialized MLS group state (provider-specific format).
    pub serialized_mls_group: Vec<u8>,
    /// Local device identifier.
    pub local_device_id: [u8; 16],
    /// Known member devices.
    pub known_devices: Vec<DeviceIdentityData>,
    /// Commit conflict state, if any.
    pub conflict: Option<CommitConflictData>,
    /// Persistent outbox of undelivered objects.
    pub outbox: Vec<OutboxEntryData>,
    /// Schema version for migration.
    pub schema_version: u32,
    /// Monotonic counter for outbox sequence numbers (durable across restarts).
    pub next_outbox_sequence: u64,
}

/// Serializable group binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBindingData {
    pub protocol_version: u16,
    pub network_id: [u8; 32],
    pub canonical_channel: String,
    pub mls_group_id: Vec<u8>,
    pub creator_fingerprint: [u8; 32],
    pub created_at_unix: i64,
}

/// Serializable device identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentityData {
    pub device_id: [u8; 16],
    pub fingerprint: [u8; 32],
    pub label: String,
    pub trust: TrustState,
}

/// Serializable commit conflict state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitConflictData {
    pub group_id: Vec<u8>,
    pub old_epoch: u64,
    pub conflicting_commits: Vec<Vec<u8>>,
    pub detected_at_unix: i64,
    pub source_diagnostics: Vec<String>,
}

/// Serializable outbox entry with retry tracking and monotonic sequence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntryData {
    /// 128-bit random entry identifier.
    pub id: [u8; 16],
    /// Serialized FCEP-2 envelope to deliver.
    pub envelope: Vec<u8>,
    /// Unix timestamp of creation.
    pub created_at_unix: i64,
    /// Whether delivery has been confirmed.
    pub delivered: bool,
    /// Monotonic sequence number (per-outbox, guaranteed increasing).
    pub sequence: u64,
    /// Number of delivery attempts so far.
    pub retry_count: u8,
    /// Unix timestamp of last delivery attempt (0 if never attempted).
    pub last_attempt_at_unix: i64,
}

impl PersistedGroup {
    /// Save the group state atomically with full durability guarantees.
    ///
    /// §19.3: The sequence is:
    /// 1. Serialize to JSON (or encrypted blob, see note below)
    /// 2. Write to a **unique** temporary file (path.with_extension with PID/random)
    /// 3. `sync_all()` on the temp file to force data to disk
    /// 4. `rename` atomically to the final path
    /// 5. `sync_all()` on the parent directory (Unix) to guarantee the rename is durable
    ///
    /// # Security note : §19.3 / §23.8
    ///
    /// `serialized_mls_group` contains the raw OpenMLS key material (private keys,
    /// epoch secrets, credential). Storing this in plain JSON is **not** compliant.
    /// A production deployment MUST:
    /// - Use a platform keystore (TPM, macOS Keychain, Windows DPAPI) OR
    /// - Encrypt the payload with AEAD (AES-256-GCM) derived from a user-provided
    ///   passphrase or biometric key, using a random 12-byte nonce per write.
    /// - Never store the encryption key alongside the data.
    pub fn save(&self, path: &Path) -> Result<()> {
        // TODO: Encrypt serialized_mls_group with AEAD before writing,
        // using a key derived from a user secret (see security note above).
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| Fcep2Error::Persistence(format!("Serialization failed: {}", e)))?;

        // Use a unique temp file name to prevent race conditions
        let rand_suffix: u64 = rand::random();
        let temp_path = path.with_extension(format!("tmp.{}", rand_suffix));

        // Write to temp file with write permissions, then fsync before rename
        {
            use std::io::Write;
            let mut file = fs::File::create(&temp_path)
                .map_err(|e| Fcep2Error::Persistence(format!("Create temp failed: {}", e)))?;
            file.write_all(&json)
                .map_err(|e| Fcep2Error::Persistence(format!("Write failed: {}", e)))?;
            // fsync to force data to disk before rename (§19.3)
            file.sync_all()
                .map_err(|e| Fcep2Error::Persistence(format!("Sync temp failed: {}", e)))?;
        }

        // Atomically replace the target file
        fs::rename(&temp_path, path)
            .map_err(|e| Fcep2Error::Persistence(format!("Rename failed: {}", e)))?;

        // Sync the parent directory (best-effort on Unix, may be no-op on Windows)
        if let Some(parent) = path.parent() {
            if let Ok(dir) = fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        Ok(())
    }

    /// Load group state from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let json =
            fs::read(path).map_err(|e| Fcep2Error::Persistence(format!("Read failed: {}", e)))?;

        serde_json::from_slice(&json)
            .map_err(|e| Fcep2Error::Persistence(format!("Deserialization failed: {}", e)))
    }

    /// Clean up the outbox: discard entries older than OUTBOX_MAX_AGE_SECS.
    pub fn cleanup_outbox(&mut self) {
        let cutoff = chrono::Utc::now().timestamp() - OUTBOX_MAX_AGE_SECS;
        self.outbox.retain(|e| e.created_at_unix > cutoff);
    }

    /// Mark an outbox entry as delivered.
    pub fn mark_delivered(&mut self, entry_id: &[u8; 16]) {
        if let Some(entry) = self.outbox.iter_mut().find(|e| &e.id == entry_id) {
            entry.delivered = true;
        }
    }

    /// Get the next monotonic sequence number for a new outbox entry.
    /// Uses a durable counter that never regresses, even after outbox cleanup.
    pub fn next_sequence(&self) -> u64 {
        self.next_outbox_sequence
    }

    /// Add a new outbox entry with a guaranteed monotonic sequence number.
    /// Uses a durable counter that advances atomically.
    pub fn push_outbox_entry(&mut self, id: [u8; 16], envelope: Vec<u8>) -> u64 {
        let sequence = self.next_outbox_sequence;
        self.next_outbox_sequence = self.next_outbox_sequence.saturating_add(1);
        let now = chrono::Utc::now().timestamp();
        self.outbox.push(OutboxEntryData {
            id,
            envelope,
            created_at_unix: now,
            delivered: false,
            sequence,
            retry_count: 0,
            last_attempt_at_unix: 0,
        });
        sequence
    }

    /// Get pending (undelivered) outbox entries ordered by sequence, excluding
    /// entries that have exceeded the max retry count.
    pub fn pending_outbox_entries(&self) -> Vec<&OutboxEntryData> {
        let mut pending: Vec<&OutboxEntryData> = self
            .outbox
            .iter()
            .filter(|e| !e.delivered && e.retry_count < OUTBOX_MAX_RETRIES)
            .collect();
        pending.sort_by_key(|e| e.sequence);
        pending
    }

    /// Get the next outbox entry to retry, based on exponential backoff.
    /// Returns `None` if no entry is due for retry yet.
    pub fn next_expired_retry(&self) -> Option<&OutboxEntryData> {
        let now = chrono::Utc::now().timestamp();
        self.outbox.iter().find(|e| {
            if e.delivered || e.retry_count >= OUTBOX_MAX_RETRIES {
                return false;
            }
            if e.last_attempt_at_unix == 0 {
                return true; // never attempted
            }
            let delay = OUTBOX_RETRY_BASE_SECS as i64 * (1i64 << (e.retry_count as u32).min(5));
            let next_attempt = e.last_attempt_at_unix + delay;
            now >= next_attempt
        })
    }

    /// Record a delivery attempt for an outbox entry (increments retry_count).
    pub fn record_attempt(&mut self, entry_id: &[u8; 16]) {
        let now = chrono::Utc::now().timestamp();
        if let Some(entry) = self.outbox.iter_mut().find(|e| &e.id == entry_id) {
            entry.retry_count = entry.retry_count.saturating_add(1);
            entry.last_attempt_at_unix = now;
        }
    }
}

impl From<&GroupBinding> for GroupBindingData {
    fn from(b: &GroupBinding) -> Self {
        Self {
            protocol_version: b.protocol_version,
            network_id: b.network_id,
            canonical_channel: b.canonical_channel.clone(),
            mls_group_id: b.mls_group_id.clone(),
            creator_fingerprint: b.creator_fingerprint,
            created_at_unix: b.created_at_unix,
        }
    }
}

impl From<&DeviceIdentity> for DeviceIdentityData {
    fn from(d: &DeviceIdentity) -> Self {
        Self {
            device_id: d.device_id,
            fingerprint: d.fingerprint,
            label: d.label.clone(),
            trust: d.trust.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_persisted_group() -> PersistedGroup {
        PersistedGroup {
            binding: GroupBindingData {
                protocol_version: 2,
                network_id: [0x42; 32],
                canonical_channel: "#test".to_string(),
                mls_group_id: vec![0x01; 16],
                creator_fingerprint: [0xAA; 32],
                created_at_unix: 1700000000,
            },
            serialized_mls_group: vec![0x00; 64],
            local_device_id: [0x01; 16],
            known_devices: vec![],
            conflict: None,
            outbox: vec![],
            schema_version: 1,
            next_outbox_sequence: 1,
        }
    }

    #[test]
    fn test_save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("group.json");

        let original = test_persisted_group();
        original.save(&path).unwrap();

        let loaded = PersistedGroup::load(&path).unwrap();
        assert_eq!(loaded.binding.canonical_channel, "#test");
        assert_eq!(loaded.schema_version, 1);
        assert_eq!(loaded.serialized_mls_group.len(), 64);
    }

    #[test]
    fn test_outbox_cleanup() {
        let mut group = test_persisted_group();
        let now = chrono::Utc::now().timestamp();

        group.outbox.push(OutboxEntryData {
            id: [0x01; 16],
            envelope: vec![],
            created_at_unix: now - 100000, // old
            delivered: false,
            sequence: 1,
            retry_count: 0,
            last_attempt_at_unix: 0,
        });
        group.outbox.push(OutboxEntryData {
            id: [0x02; 16],
            envelope: vec![],
            created_at_unix: now, // fresh
            delivered: false,
            sequence: 2,
            retry_count: 0,
            last_attempt_at_unix: 0,
        });

        group.cleanup_outbox();
        assert_eq!(group.outbox.len(), 1);
        assert_eq!(group.outbox[0].id, [0x02; 16]);
    }
}
