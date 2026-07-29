//! Encrypted SQLite storage provider for OpenMLS.
//!
//! All secrets are encrypted at rest with XChaCha20-Poly1305 using sub-keys
//! derived from the FiSH-11 master key via HKDF. `SqliteStorage` is the sole
//! authority for durable MLS state and MUST NOT be opened without `StorageKeys`.
//!
//! ```ignore
//! use fish_11_mls::storage::{SqliteOpenMlsProvider, StorageKeys};
//!
//! let master_key: [u8; 32] = fish_11::unlock_master_key_from_password(password)?;
//! let storage_keys = StorageKeys::derive_from_master_key(&master_key);
//! let provider = SqliteOpenMlsProvider::open("fcep2-openmls.db", storage_keys)?;
//! ```

mod sqlite_crypto;
mod sqlite_provider;
mod sqlite_storage;

#[doc(inline)]
pub use sqlite_crypto::StorageKeys;
pub use sqlite_provider::SqliteOpenMlsProvider;
pub use sqlite_storage::{SqliteStorage, SqliteStorageError};
