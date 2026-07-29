//! SQLite-backed `StorageProvider` implementation for OpenMLS.
//!
//! Follows the exact same key construction and serialization pattern as
//! `MemoryStorage` (openmls_memory_storage-0.5.0), but with `rusqlite`
//! as the backing store and AEAD encryption for all values at rest.

use std::sync::Mutex;

use openmls_traits::storage::*;
use rusqlite::Connection;

use super::sqlite_crypto::{self, StorageKeys};

/// Error type for SQLite storage operations.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum SqliteStorageError {
    #[error("SQLite error: {0}")]
    Sqlite(String),
    #[error("Error serializing value.")]
    SerializationError,
    #[error("The key store does not allow storing serialized values.")]
    UnsupportedValueTypeBytes,
    #[error("Internal mutex poisoned")]
    MutexPoisoned,
    #[error("Storage locked: master key not available")]
    Locked,
}

impl From<rusqlite::Error> for SqliteStorageError {
    fn from(e: rusqlite::Error) -> Self {
        SqliteStorageError::Sqlite(e.to_string())
    }
}

impl From<serde_json::Error> for SqliteStorageError {
    fn from(_: serde_json::Error) -> Self {
        SqliteStorageError::SerializationError
    }
}

/// SQLite-backed OpenMLS key-value store with mandatory AEAD encryption.
///
/// Uses a single table `openmls_store` with columns `(label, key, value)`.
/// Every value is encrypted at rest with XChaCha20-Poly1305 using per-value
/// random nonces and AAD binding (label + storage_key).
///
/// # Security
///
/// `StorageKeys` MUST be derived from the FiSH-11 master key via
/// [`StorageKeys::derive_from_master_key`] before opening the store.
/// Opening without keys is structurally impossible.
#[derive(Debug)]
pub struct SqliteStorage {
    conn: Mutex<Connection>,
    keys: StorageKeys,
}

// ===== Label constants (matching MemoryStorage) ─────────────────────

const KEY_PACKAGE_LABEL: &[u8] = b"KeyPackage";
const PSK_LABEL: &[u8] = b"Psk";
const ENCRYPTION_KEY_PAIR_LABEL: &[u8] = b"EncryptionKeyPair";
const SIGNATURE_KEY_PAIR_LABEL: &[u8] = b"SignatureKeyPair";
const EPOCH_KEY_PAIRS_LABEL: &[u8] = b"EpochKeyPairs";
const TREE_LABEL: &[u8] = b"Tree";
const GROUP_CONTEXT_LABEL: &[u8] = b"GroupContext";
const INTERIM_TRANSCRIPT_HASH_LABEL: &[u8] = b"InterimTranscriptHash";
const CONFIRMATION_TAG_LABEL: &[u8] = b"ConfirmationTag";
const JOIN_CONFIG_LABEL: &[u8] = b"MlsGroupJoinConfig";
const OWN_LEAF_NODES_LABEL: &[u8] = b"OwnLeafNodes";
const GROUP_STATE_LABEL: &[u8] = b"GroupState";
const QUEUED_PROPOSAL_LABEL: &[u8] = b"QueuedProposal";
const PROPOSAL_QUEUE_REFS_LABEL: &[u8] = b"ProposalQueueRefs";
const OWN_LEAF_NODE_INDEX_LABEL: &[u8] = b"OwnLeafNodeIndex";
const EPOCH_SECRETS_LABEL: &[u8] = b"EpochSecrets";
const RESUMPTION_PSK_STORE_LABEL: &[u8] = b"ResumptionPsk";
const MESSAGE_SECRETS_LABEL: &[u8] = b"MessageSecrets";
#[cfg(feature = "extensions-draft-08")]
const APPLICATION_EXPORT_TREE_LABEL: &[u8] = b"ApplicationExportTree";

impl SqliteStorage {
    /// Lock the mutex, returning an error if poisoned.
    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Connection>, SqliteStorageError> {
        self.conn.lock().map_err(|_| SqliteStorageError::MutexPoisoned)
    }

    /// Open (or create) the SQLite database at `path` with mandatory encryption keys.
    ///
    /// All values are encrypted at rest with XChaCha20-Poly1305 using per-value
    /// random nonces and AAD binding (label + storage_key).
    ///
    /// # Panics
    ///
    /// This function does not panic. It returns `SqliteStorageError` on I/O or SQL failure.
    pub fn new(
        path: impl AsRef<std::path::Path>,
        keys: StorageKeys,
    ) -> Result<Self, SqliteStorageError> {
        let conn = Connection::open(path.as_ref())?;

        // Configure connection safety and integrity
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        conn.execute_batch("PRAGMA synchronous=NORMAL;")?;
        // Enable WAL mode for better concurrent read performance
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;

        // Create the key-value store table
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS openmls_store (
                label BLOB NOT NULL,
                key   BLOB NOT NULL,
                value BLOB NOT NULL,
                PRIMARY KEY (label, key)
            );",
        )?;

        Ok(Self { conn: Mutex::new(conn), keys })
    }

    /// Open an in-memory SQLite database (useful for testing).
    ///
    /// Requires valid `StorageKeys` like any other store : use a test-derived
    /// master key to create them.
    pub fn in_memory(keys: StorageKeys) -> Result<Self, SqliteStorageError> {
        Self::new(":memory:", keys)
    }

    // ===== Internal helpers (matching MemoryStorage pattern) ──────

    /// Encrypt value with AAD binding.
    fn encrypt_val(
        &self,
        label: &[u8],
        storage_key: &[u8],
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, SqliteStorageError> {
        let aad = sqlite_crypto::build_aad(label, storage_key);
        sqlite_crypto::seal_value(&self.keys.value_key, &plaintext, &aad)
    }

    /// Decrypt value with AAD binding.
    fn decrypt_val(
        &self,
        label: &[u8],
        storage_key: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, SqliteStorageError> {
        let aad = sqlite_crypto::build_aad(label, storage_key);
        sqlite_crypto::open_value(&self.keys.value_key, ciphertext, &aad)
    }

    fn write_storage<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), SqliteStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let store_val = self.encrypt_val(label, &storage_key, value)?;
        let conn = self.lock()?;
        conn.execute(
            "INSERT OR REPLACE INTO openmls_store (label, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params![label, storage_key, store_val],
        )?;
        Ok(())
    }

    fn read_storage<const V: u16, T: serde::de::DeserializeOwned>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Option<T>, SqliteStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT value FROM openmls_store WHERE label = ?1 AND key = ?2")?;
        let mut rows = stmt.query(rusqlite::params![label, storage_key])?;
        match rows.next()? {
            Some(row) => {
                let blob: Vec<u8> = row.get(0)?;
                let dec = self.decrypt_val(label, &storage_key, &blob)?;
                let value: T = serde_json::from_slice(&dec)?;
                Ok(Some(value))
            }
            None => Ok(None),
        }
    }

    fn read_list_storage<const V: u16, T: serde::de::DeserializeOwned>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<Vec<T>, SqliteStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT value FROM openmls_store WHERE label = ?1 AND key = ?2")?;
        let mut rows = stmt.query(rusqlite::params![label, storage_key])?;
        match rows.next()? {
            Some(row) => {
                let blob: Vec<u8> = row.get(0)?;
                let dec = self.decrypt_val(label, &storage_key, &blob)?;
                let list: Vec<Vec<u8>> = serde_json::from_slice(&dec)?;
                list.iter()
                    .map(|b| {
                        serde_json::from_slice(b)
                            .map_err(|_| SqliteStorageError::SerializationError)
                    })
                    .collect()
            }
            None => Ok(Vec::new()),
        }
    }

    fn append_storage<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), SqliteStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let conn = self.lock()?;

        let existing = {
            let mut stmt =
                conn.prepare("SELECT value FROM openmls_store WHERE label = ?1 AND key = ?2")?;
            let mut rows = stmt.query(rusqlite::params![label, storage_key])?;
            match rows.next()? {
                Some(row) => {
                    let b: Vec<u8> = row.get(0)?;
                    self.decrypt_val(label, &storage_key, &b)?
                }
                None => b"[]".to_vec(),
            }
        };

        let mut list: Vec<Vec<u8>> = serde_json::from_slice(&existing)?;
        list.push(value);
        let new_blob = serde_json::to_vec(&list)?;
        let protected = self.encrypt_val(label, &storage_key, new_blob)?;
        conn.execute(
            "INSERT OR REPLACE INTO openmls_store (label, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params![label, storage_key, protected],
        )?;
        Ok(())
    }

    fn remove_item_storage<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
        value: Vec<u8>,
    ) -> Result<(), SqliteStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let conn = self.lock()?;

        let existing = {
            let mut stmt =
                conn.prepare("SELECT value FROM openmls_store WHERE label = ?1 AND key = ?2")?;
            let mut rows = stmt.query(rusqlite::params![label, storage_key])?;
            match rows.next()? {
                Some(row) => {
                    let b: Vec<u8> = row.get(0)?;
                    self.decrypt_val(label, &storage_key, &b)?
                }
                None => return Ok(()),
            }
        };

        let mut list: Vec<Vec<u8>> = serde_json::from_slice(&existing)?;
        list.retain(|stored| stored != &value);
        let new_blob = serde_json::to_vec(&list)?;
        let protected = self.encrypt_val(label, &storage_key, new_blob)?;
        conn.execute(
            "INSERT OR REPLACE INTO openmls_store (label, key, value) VALUES (?1, ?2, ?3)",
            rusqlite::params![label, storage_key, protected],
        )?;
        Ok(())
    }

    fn delete_storage<const V: u16>(
        &self,
        label: &[u8],
        key: &[u8],
    ) -> Result<(), SqliteStorageError> {
        let storage_key = build_key_from_vec::<V>(label, key.to_vec());
        let conn = self.lock()?;
        conn.execute(
            "DELETE FROM openmls_store WHERE label = ?1 AND key = ?2",
            rusqlite::params![label, storage_key],
        )?;
        Ok(())
    }
}

// ===== StorageProvider implementation ───────────────────────────────

impl StorageProvider<CURRENT_VERSION> for SqliteStorage {
    type Error = SqliteStorageError;

    fn write_mls_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        config: &MlsGroupJoinConfig,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(config)?,
        )
    }

    fn append_own_leaf_node<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        leaf_node: &LeafNode,
    ) -> Result<(), Self::Error> {
        self.append_storage::<CURRENT_VERSION>(
            OWN_LEAF_NODES_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(leaf_node)?,
        )
    }

    fn queue_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
        proposal: &QueuedProposal,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.write_storage::<CURRENT_VERSION>(
            QUEUED_PROPOSAL_LABEL,
            &key,
            serde_json::to_vec(proposal)?,
        )?;
        self.append_storage::<CURRENT_VERSION>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(proposal_ref)?,
        )?;
        Ok(())
    }

    fn write_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        tree: &TreeSync,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            TREE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(tree)?,
        )
    }

    fn write_interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        interim_transcript_hash: &InterimTranscriptHash,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(interim_transcript_hash)?,
        )
    }

    fn write_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_context: &GroupContext,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            GROUP_CONTEXT_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_context)?,
        )
    }

    fn write_confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        confirmation_tag: &ConfirmationTag,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(confirmation_tag)?,
        )
    }

    fn write_group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_state: &GroupState,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_state)?,
        )
    }

    fn write_message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        message_secrets: &MessageSecrets,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(message_secrets)?,
        )
    }

    fn write_resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        resumption_psk_store: &ResumptionPskStore,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(resumption_psk_store)?,
        )
    }

    fn write_own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        own_leaf_index: &LeafNodeIndex,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(own_leaf_index)?,
        )
    }

    fn write_group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        group_epoch_secrets: &GroupEpochSecrets,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(group_epoch_secrets)?,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn write_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        application_export_tree: &ApplicationExportTree,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            APPLICATION_EXPORT_TREE_LABEL,
            &serde_json::to_vec(group_id)?,
            serde_json::to_vec(application_export_tree)?,
        )
    }

    // ===== Crypto writers ────────────────────────────────────────────

    fn write_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
        signature_key_pair: &SignatureKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
            serde_json::to_vec(signature_key_pair)?,
        )
    }

    fn write_encryption_key_pair<
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
        key_pair: &HpkeKeyPair,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
            serde_json::to_vec(key_pair)?,
        )
    }

    fn write_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
        key_pairs: &[HpkeKeyPair],
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id::<CURRENT_VERSION>(group_id, epoch, leaf_index)?;
        self.write_storage::<CURRENT_VERSION>(
            EPOCH_KEY_PAIRS_LABEL,
            &key,
            serde_json::to_vec(key_pairs)?,
        )
    }

    fn write_key_package<
        HashReference: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &HashReference,
        key_package: &KeyPackage,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            KEY_PACKAGE_LABEL,
            &serde_json::to_vec(hash_ref)?,
            serde_json::to_vec(key_package)?,
        )
    }

    fn write_psk<
        PskId: traits::PskId<CURRENT_VERSION>,
        PskBundle: traits::PskBundle<CURRENT_VERSION>,
    >(
        &self,
        psk_id: &PskId,
        psk: &PskBundle,
    ) -> Result<(), Self::Error> {
        self.write_storage::<CURRENT_VERSION>(
            PSK_LABEL,
            &serde_json::to_vec(psk_id)?,
            serde_json::to_vec(psk)?,
        )
    }

    // ===== Getters for group state ───────────────────────────────────

    fn mls_group_join_config<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MlsGroupJoinConfig: traits::MlsGroupJoinConfig<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MlsGroupJoinConfig>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, MlsGroupJoinConfig>(
            JOIN_CONFIG_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn own_leaf_nodes<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNode: traits::LeafNode<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<LeafNode>, Self::Error> {
        self.read_list_storage::<CURRENT_VERSION, LeafNode>(
            OWN_LEAF_NODES_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn queued_proposal_refs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<ProposalRef>, Self::Error> {
        self.read_list_storage::<CURRENT_VERSION, ProposalRef>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn queued_proposals<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
        QueuedProposal: traits::QueuedProposal<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<(ProposalRef, QueuedProposal)>, Self::Error> {
        let refs: Vec<ProposalRef> = self.read_list_storage::<CURRENT_VERSION, ProposalRef>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )?;

        refs.into_iter()
            .map(|proposal_ref| {
                let key = serde_json::to_vec(&(group_id, &proposal_ref))?;
                let proposal: QueuedProposal = self
                    .read_storage::<CURRENT_VERSION, QueuedProposal>(QUEUED_PROPOSAL_LABEL, &key)?
                    .ok_or(SqliteStorageError::SerializationError)?;
                Ok((proposal_ref, proposal))
            })
            .collect::<Result<Vec<_>, _>>()
    }

    fn tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        TreeSync: traits::TreeSync<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<TreeSync>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, TreeSync>(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn group_context<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupContext: traits::GroupContext<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupContext>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, GroupContext>(
            GROUP_CONTEXT_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn interim_transcript_hash<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        InterimTranscriptHash: traits::InterimTranscriptHash<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<InterimTranscriptHash>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, InterimTranscriptHash>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn confirmation_tag<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ConfirmationTag: traits::ConfirmationTag<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ConfirmationTag>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, ConfirmationTag>(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn group_state<
        GroupState: traits::GroupState<CURRENT_VERSION>,
        GroupId: traits::GroupId<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupState>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, GroupState>(
            GROUP_STATE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn message_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        MessageSecrets: traits::MessageSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<MessageSecrets>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, MessageSecrets>(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn resumption_psk_store<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ResumptionPskStore: traits::ResumptionPskStore<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ResumptionPskStore>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, ResumptionPskStore>(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn own_leaf_index<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        LeafNodeIndex: traits::LeafNodeIndex<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<LeafNodeIndex>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, LeafNodeIndex>(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn group_epoch_secrets<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        GroupEpochSecrets: traits::GroupEpochSecrets<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<GroupEpochSecrets>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, GroupEpochSecrets>(
            EPOCH_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    #[cfg(feature = "extensions-draft-08")]
    fn application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<Option<ApplicationExportTree>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, ApplicationExportTree>(
            APPLICATION_EXPORT_TREE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    // ===== Getters for crypto objects ────────────────────────────────

    fn signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
        SignatureKeyPair: traits::SignatureKeyPair<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<Option<SignatureKeyPair>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, SignatureKeyPair>(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    fn encryption_key_pair<
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
        EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<Option<HpkeKeyPair>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, HpkeKeyPair>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    fn encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
        HpkeKeyPair: traits::HpkeKeyPair<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<Vec<HpkeKeyPair>, Self::Error> {
        let key = epoch_key_pairs_id::<CURRENT_VERSION>(group_id, epoch, leaf_index)?;
        match self.read_storage::<CURRENT_VERSION, Vec<HpkeKeyPair>>(EPOCH_KEY_PAIRS_LABEL, &key)? {
            Some(pairs) => Ok(pairs),
            None => Ok(Vec::new()),
        }
    }

    fn key_package<
        KeyPackageRef: traits::HashReference<CURRENT_VERSION>,
        KeyPackage: traits::KeyPackage<CURRENT_VERSION>,
    >(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<Option<KeyPackage>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, KeyPackage>(
            KEY_PACKAGE_LABEL,
            &serde_json::to_vec(hash_ref)?,
        )
    }

    fn psk<PskBundle: traits::PskBundle<CURRENT_VERSION>, PskId: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskId,
    ) -> Result<Option<PskBundle>, Self::Error> {
        self.read_storage::<CURRENT_VERSION, PskBundle>(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    // ===== Deleters for group state ──────────────────────────────────

    fn remove_proposal<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        proposal_ref: &ProposalRef,
    ) -> Result<(), Self::Error> {
        let key = serde_json::to_vec(group_id)?;
        let value = serde_json::to_vec(proposal_ref)?;
        self.remove_item_storage::<CURRENT_VERSION>(PROPOSAL_QUEUE_REFS_LABEL, &key, value)?;
        let proposal_key = serde_json::to_vec(&(group_id, proposal_ref))?;
        self.delete_storage::<CURRENT_VERSION>(QUEUED_PROPOSAL_LABEL, &proposal_key)
    }

    fn delete_own_leaf_nodes<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(OWN_LEAF_NODES_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_group_config<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(JOIN_CONFIG_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_tree<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(TREE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_confirmation_tag<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            CONFIRMATION_TAG_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_group_state<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(GROUP_STATE_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_context<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(GROUP_CONTEXT_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn delete_interim_transcript_hash<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            INTERIM_TRANSCRIPT_HASH_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_message_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            MESSAGE_SECRETS_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_all_resumption_psk_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            RESUMPTION_PSK_STORE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_own_leaf_index<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            OWN_LEAF_NODE_INDEX_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }

    fn delete_group_epoch_secrets<GroupId: traits::GroupId<CURRENT_VERSION>>(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(EPOCH_SECRETS_LABEL, &serde_json::to_vec(group_id)?)
    }

    fn clear_proposal_queue<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ProposalRef: traits::ProposalRef<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        let refs: Vec<ProposalRef> = self.read_list_storage::<CURRENT_VERSION, ProposalRef>(
            PROPOSAL_QUEUE_REFS_LABEL,
            &serde_json::to_vec(group_id)?,
        )?;
        let conn = self.lock()?;
        for proposal_ref in &refs {
            let key = serde_json::to_vec(&(group_id, proposal_ref))?;
            conn.execute(
                "DELETE FROM openmls_store WHERE label = ?1 AND key = ?2",
                rusqlite::params![QUEUED_PROPOSAL_LABEL, key],
            )?;
        }
        let storage_key = build_key_from_vec::<CURRENT_VERSION>(
            PROPOSAL_QUEUE_REFS_LABEL,
            serde_json::to_vec(group_id)?,
        );
        conn.execute(
            "DELETE FROM openmls_store WHERE label = ?1 AND key = ?2",
            rusqlite::params![PROPOSAL_QUEUE_REFS_LABEL, storage_key],
        )?;
        Ok(())
    }

    // ===== Deleters for crypto objects ───────────────────────────────

    fn delete_signature_key_pair<
        SignaturePublicKey: traits::SignaturePublicKey<CURRENT_VERSION>,
    >(
        &self,
        public_key: &SignaturePublicKey,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            SIGNATURE_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    fn delete_encryption_key_pair<EncryptionKey: traits::EncryptionKey<CURRENT_VERSION>>(
        &self,
        public_key: &EncryptionKey,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            ENCRYPTION_KEY_PAIR_LABEL,
            &serde_json::to_vec(public_key)?,
        )
    }

    fn delete_encryption_epoch_key_pairs<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        EpochKey: traits::EpochKey<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
        epoch: &EpochKey,
        leaf_index: u32,
    ) -> Result<(), Self::Error> {
        let key = epoch_key_pairs_id::<CURRENT_VERSION>(group_id, epoch, leaf_index)?;
        self.delete_storage::<CURRENT_VERSION>(EPOCH_KEY_PAIRS_LABEL, &key)
    }

    fn delete_key_package<KeyPackageRef: traits::HashReference<CURRENT_VERSION>>(
        &self,
        hash_ref: &KeyPackageRef,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(KEY_PACKAGE_LABEL, &serde_json::to_vec(hash_ref)?)
    }

    fn delete_psk<PskKey: traits::PskId<CURRENT_VERSION>>(
        &self,
        psk_id: &PskKey,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(PSK_LABEL, &serde_json::to_vec(psk_id)?)
    }

    #[cfg(feature = "extensions-draft-08")]
    fn delete_application_export_tree<
        GroupId: traits::GroupId<CURRENT_VERSION>,
        ApplicationExportTree: traits::ApplicationExportTree<CURRENT_VERSION>,
    >(
        &self,
        group_id: &GroupId,
    ) -> Result<(), Self::Error> {
        self.delete_storage::<CURRENT_VERSION>(
            APPLICATION_EXPORT_TREE_LABEL,
            &serde_json::to_vec(group_id)?,
        )
    }
}

// ===== Helper functions (matching MemoryStorage) ────────────────────

fn build_key_from_vec<const V: u16>(label: &[u8], key: Vec<u8>) -> Vec<u8> {
    let mut key_out = label.to_vec();
    key_out.extend_from_slice(&key);
    key_out.extend_from_slice(&u16::to_be_bytes(V));
    key_out
}

fn epoch_key_pairs_id<const V: u16>(
    group_id: &impl traits::GroupId<V>,
    epoch: &impl traits::EpochKey<V>,
    leaf_index: u32,
) -> Result<Vec<u8>, SqliteStorageError> {
    let mut key = serde_json::to_vec(group_id)?;
    key.extend_from_slice(&serde_json::to_vec(epoch)?);
    key.extend_from_slice(&serde_json::to_vec(&leaf_index)?);
    Ok(key)
}
