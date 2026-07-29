//! Group Actor : single-owner per MLS group.
//!
//! Each active MLS group is owned by exactly one `GroupActor` instance.
//! This ensures serialized access to the OpenMLS state and enforces the
//! required transaction order:
//!
//!   mutate MLS => persist state + outbox => send transport object
//!
//! Never send first and persist later. If persistence fails, the mutation
//! is aborted and the transport is never contacted.

use sha2::{Digest, Sha256};

use crate::fcep2::openmls_adapter::OpenMlsContext;
use crate::fcep2::persistence::{ConflictRecord, EncryptedFileStore, GroupRecord, SecretBox};
use crate::unified_error::DllError;

/// Group actor: owns the MLS state for a single group.
///
/// WARNING: This module requires the `openmls` crate dependency to be added
/// to `fish_11_dll/Cargo.toml`. All functions currently return
/// `NotConnected` errors until the OpenMLS dependency is wired.
pub struct GroupActor<S: SecretBox> {
    /// OpenMLS context (provider + signer + credential).
    pub ctx: OpenMlsContext,
    /// Persisted group record (includes OpenMLS state and outbox).
    pub record: GroupRecord,
    /// Encrypted file store for persistence.
    pub store: EncryptedFileStore<S>,
    /// Current unresolved conflict, if any.
    pub conflict: Option<ConflictRecord>,
}

impl<S: SecretBox> GroupActor<S> {
    /// Persist the current group record (state + outbox + conflict) to disk.
    /// Must be called before any network send.
    fn persist(&mut self) -> Result<(), DllError> {
        self.record.unresolved_conflict = self.conflict.clone();
        self.store.save(&self.record)
    }

    // ===== Application Messages ────────────────────────────────────

    /// Send an application message to the group.
    ///
    /// Transaction:
    /// 1. OpenMLS encrypts the plaintext
    /// 2. Persist the new group state
    /// 3. Only then: queue for transport
    pub fn send_application(&mut self, _plaintext: &[u8]) -> Result<(), DllError> {
        if self.conflict.is_some() {
            return Err(DllError::EncryptionFailed {
                context: "send_application".to_string(),
                cause: "group is in CommitConflict; sending disabled".to_string(),
            });
        }
        // TODO: Wire OpenMLS encrypt_application when openmls crate is available
        Err(DllError::NotConnected("OpenMLS not yet compiled".to_string()))
    }

    /// Receive and decrypt an application message.
    pub fn receive_message(&mut self, _raw_mls: &[u8]) -> Result<Option<Vec<u8>>, DllError> {
        Err(DllError::NotConnected("OpenMLS not yet compiled".to_string()))
    }

    // ===== Commit Processing ───────────────────────────────────────

    /// Receive and process a Commit message.
    pub fn receive_commit(
        &mut self,
        raw_mls: &[u8],
        _source: String,
        _parent_epoch: u64,
    ) -> Result<(), DllError> {
        if self.conflict.is_some() {
            return Err(DllError::EncryptionFailed {
                context: "receive_commit".to_string(),
                cause: "group is in CommitConflict; auto-merge disabled".to_string(),
            });
        }
        let _digest: [u8; 32] = Sha256::digest(raw_mls).into();
        // TODO: Wire OpenMLS process_message when openmls crate is available
        Err(DllError::NotConnected("OpenMLS not yet compiled".to_string()))
    }

    // ===== Member Management ───────────────────────────────────────

    /// Invite a new member using their serialized KeyPackage.
    pub fn invite_member(
        &mut self,
        _key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), DllError> {
        Err(DllError::NotConnected("OpenMLS not yet compiled".to_string()))
    }

    /// Remove a member by their leaf index.
    pub fn remove_member(&mut self, _leaf_index: u32) -> Result<Vec<u8>, DllError> {
        Err(DllError::NotConnected("OpenMLS not yet compiled".to_string()))
    }

    // ===== Sync ────────────────────────────────────────────────────

    /// Apply a batch of sync commits from a relay.
    ///
    /// Each commit is processed sequentially via OpenMLS.
    /// The relay's epoch counter and member list are advisory only.
    pub fn apply_sync(&mut self, raw_commits: &[Vec<u8>]) -> Result<(), DllError> {
        for raw_commit in raw_commits {
            self.receive_commit(raw_commit, "relay-sync".to_string(), 0)?;
        }
        Ok(())
    }
}
