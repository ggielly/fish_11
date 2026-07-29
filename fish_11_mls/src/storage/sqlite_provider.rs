//! Encrypted `OpenMlsProvider` wrapping RustCrypto + SQLite.
//!
//! Replaces `MemoryStorage` with `SqliteStorage`, making MLS group state,
//! key pairs, key packages, PSKs, and proposal queues durable and encrypted.
//!
//! ```ignore
//! use fish_11_mls::storage::{SqliteOpenMlsProvider, StorageKeys};
//!
//! let keys = StorageKeys::derive_from_master_key(&master_key);
//! let provider = SqliteOpenMlsProvider::open("fcep2-openmls.db", keys)?;
//! ```

use openmls_rust_crypto::RustCrypto;
use openmls_traits::OpenMlsProvider;

use super::sqlite_crypto::StorageKeys;
use super::sqlite_storage::{SqliteStorage, SqliteStorageError};

/// OpenMLS provider with encrypted SQLite storage.
///
/// Combines `RustCrypto` with `SqliteStorage`. All values are encrypted
/// at rest with XChaCha20-Poly1305.
#[derive(Debug)]
pub struct SqliteOpenMlsProvider {
    crypto: RustCrypto,
    storage: SqliteStorage,
}

impl SqliteOpenMlsProvider {
    /// Open (or create) the encrypted SQLite store.
    ///
    /// Keys must be derived via [`StorageKeys::derive_from_master_key`].
    pub fn open(
        db_path: impl AsRef<std::path::Path>,
        keys: StorageKeys,
    ) -> Result<Self, SqliteStorageError> {
        let storage = SqliteStorage::new(db_path, keys)?;
        Ok(Self { crypto: RustCrypto::default(), storage })
    }

    /// In-memory provider (for testing).
    ///
    /// Requires valid `StorageKeys` like any other store.
    pub fn in_memory(keys: StorageKeys) -> Result<Self, SqliteStorageError> {
        let storage = SqliteStorage::in_memory(keys)?;
        Ok(Self { crypto: RustCrypto::default(), storage })
    }

    /// Reference to the underlying SQLite storage.
    pub fn storage(&self) -> &SqliteStorage {
        &self.storage
    }
}

impl OpenMlsProvider for SqliteOpenMlsProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
