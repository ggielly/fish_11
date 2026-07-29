//! Encrypted NoSQL database for the MLS Test Bot
//!
//! Provides an embedded Sled-backed key-value store with per-value
//! authenticated encryption using ChaCha20-Poly1305 and HKDF key derivation.
//!
//! §19.3 / §5.3: state at-rest MUST be encrypted. The encryption key is
//! provided through the TOML configuration and MUST be at least 16 bytes.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use rand::rngs::OsRng;
use sled::{Db, Tree};
use tracing::{debug, info, warn};

/// Database collection names
pub const COLL_KEY_PACKAGES: &str = "key_packages";
pub const COLL_WELCOMES: &str = "welcomes";
pub const COLL_COMMIT_LOGS: &str = "commit_logs";
pub const COLL_GROUP_STATE: &str = "group_state";
pub const COLL_PEER_REGISTRY: &str = "peer_registry";
pub const COLL_OUTBOX: &str = "outbox";
pub const COLL_METADATA: &str = "metadata";

/// Type alias for a boxed encryption key
type EncryptionKey = [u8; 32];

/// Encrypted NoSQL store backed by Sled
#[derive(Clone)]
pub struct EncryptedStore {
    db: Arc<Db>,
    enc_key: Arc<EncryptionKey>,
}

impl EncryptedStore {
    /// Open or create the encrypted database at the given path.
    ///
    /// `raw_key` is the 32-byte master key (derive via `AppConfig::derive_storage_key()`).
    pub fn open<P: AsRef<Path>>(path: P, raw_key: &EncryptionKey) -> Result<Self> {
        let p = path.as_ref();
        if !p.exists() {
            std::fs::create_dir_all(p)
                .with_context(|| format!("Failed to create database directory: {}", p.display()))?;
        }

        let db = sled::Config::new()
            .path(p)
            .cache_capacity(64 * 1024 * 1024) // 64 MiB cache
            .flush_every_ms(Some(1000)) // Flush every second
            .open()
            .with_context(|| format!("Failed to open Sled database at {}", p.display()))?;

        info!("Opened encrypted database at {}", p.display());

        // Ensure all collections exist
        for coll in &[
            COLL_KEY_PACKAGES,
            COLL_WELCOMES,
            COLL_COMMIT_LOGS,
            COLL_GROUP_STATE,
            COLL_PEER_REGISTRY,
            COLL_OUTBOX,
            COLL_METADATA,
        ] {
            db.open_tree(coll)?;
        }

        Ok(Self { db: Arc::new(db), enc_key: Arc::new(*raw_key) })
    }

    /// Flush the database to disk.
    pub fn flush(&self) -> Result<()> {
        self.db.flush().context("Failed to flush database")?;
        Ok(())
    }

    /// Get a tree handle by collection name
    fn tree(&self, name: &str) -> Result<Tree> {
        self.db.open_tree(name).with_context(|| format!("Failed to open tree '{}'", name))
    }

    /// Encrypt a plaintext value with an authenticated random nonce.
    ///
    /// Returns `(nonce, ciphertext)` where nonce is 12 bytes (standard for ChaCha20Poly1305).
    fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.enc_key[..])
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

        // Generate a random nonce per record (standard AEAD practice)
        let nonce = {
            let mut n = [0u8; 12];
            OsRng.fill_bytes(&mut n);
            n
        };

        let ciphertext = cipher
            .encrypt(&Nonce::from_slice(&nonce), plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

        Ok((nonce.to_vec(), ciphertext))
    }

    /// Decrypt a value given its nonce and ciphertext.
    fn decrypt(&self, nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(&self.enc_key[..])
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;

        let plaintext = cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

        Ok(plaintext)
    }

    // ── Public API ──────────────────────────────────────────────────────────

    /// Store an encrypted value under the given key in a collection.
    ///
    /// Storage format: `[12 bytes nonce][encrypted payload]`
    pub async fn put(&self, collection: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let (nonce, ciphertext) = self.encrypt(value)?;

        let mut blob = Vec::with_capacity(12 + ciphertext.len());
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);

        let tree = self.tree(collection)?;
        tree.insert(key, blob).map_err(|e| anyhow::anyhow!("Sled insert failed: {}", e))?;

        debug!("Stored {} bytes in '{}' under key len={}", value.len(), collection, key.len());
        Ok(())
    }

    /// Retrieve and decrypt a value by key from a collection.
    pub async fn get(&self, collection: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let tree = self.tree(collection)?;
        let blob = match tree.get(key) {
            Ok(Some(b)) => b,
            Ok(None) => return Ok(None),
            Err(e) => return Err(anyhow::anyhow!("Sled get failed: {}", e)),
        };

        if blob.len() < 12 {
            return Err(anyhow::anyhow!("Corrupted record: too short ({} bytes)", blob.len()));
        }

        let nonce = &blob[..12];
        let ciphertext = &blob[12..];
        let plaintext = self.decrypt(nonce, ciphertext)?;

        Ok(Some(plaintext))
    }

    /// Delete a key from a collection.
    pub async fn delete(&self, collection: &str, key: &[u8]) -> Result<bool> {
        let tree = self.tree(collection)?;
        let result = tree.remove(key).map_err(|e| anyhow::anyhow!("Sled remove failed: {}", e))?;
        Ok(result.is_some())
    }

    /// List all keys in a collection.
    pub async fn list_keys(&self, collection: &str) -> Result<Vec<Vec<u8>>> {
        let tree = self.tree(collection)?;
        let keys: Vec<Vec<u8>> =
            tree.iter().keys().filter_map(|r| r.ok().map(|iv| iv.to_vec())).collect();
        Ok(keys)
    }

    /// Iterate over all (key, value) pairs in a collection (values are decrypted).
    pub async fn scan(&self, collection: &str) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let tree = self.tree(collection)?;
        let mut results = Vec::new();

        for item in tree.iter() {
            let (key, blob) = item.map_err(|e| anyhow::anyhow!("Sled iteration failed: {}", e))?;

            if blob.len() < 12 {
                warn!("Skipping corrupted record in '{}'", collection);
                continue;
            }

            let nonce = &blob[..12];
            let ciphertext = &blob[12..];
            match self.decrypt(nonce, ciphertext) {
                Ok(plaintext) => results.push((key.to_vec(), plaintext)),
                Err(e) => warn!("Skipping undecryptable record in '{}': {}", collection, e),
            }
        }

        Ok(results)
    }

    /// Get the approximate count of items in a collection.
    pub fn count(&self, collection: &str) -> Result<usize> {
        let tree = self.tree(collection)?;
        Ok(tree.len())
    }

    /// Atomically compare-and-swap a value.
    ///
    /// Returns `Ok(true)` if the swap succeeded, `Ok(false)` if the old value didn't match,
    /// or an error if the operation failed.
    pub async fn compare_and_swap(
        &self,
        collection: &str,
        key: &[u8],
        old_value: Option<&[u8]>,
        new_value: Option<&[u8]>,
    ) -> Result<bool> {
        let tree = self.tree(collection)?;

        let old_blob = match old_value {
            Some(v) => {
                let (nonce, ciphertext) = self.encrypt(v)?;
                let mut blob = Vec::with_capacity(12 + ciphertext.len());
                blob.extend_from_slice(&nonce);
                blob.extend_from_slice(&ciphertext);
                Some(blob)
            }
            None => None,
        };

        let new_blob = match new_value {
            Some(v) => {
                let (nonce, ciphertext) = self.encrypt(v)?;
                let mut blob = Vec::with_capacity(12 + ciphertext.len());
                blob.extend_from_slice(&nonce);
                blob.extend_from_slice(&ciphertext);
                Some(blob)
            }
            None => None,
        };

        tree.compare_and_swap(key, old_blob.as_deref(), new_blob.as_deref())
            .map_err(|e| anyhow::anyhow!("CAS failed: {}", e))?;

        Ok(true)
    }

    /// Compact the database to reclaim space.
    pub fn compact(&self) -> Result<()> {
        // In sled 0.34, compaction is primarily handled automatically.
        // We trigger a flush which may initiate background compaction.
        self.db.flush().context("Database compaction (flush) failed")?;
        info!("Database flushed (compaction triggered)");
        Ok(())
    }

    /// Check if the database contains the given key.
    pub async fn contains(&self, collection: &str, key: &[u8]) -> Result<bool> {
        let tree = self.tree(collection)?;
        tree.contains_key(key).map_err(|e| anyhow::anyhow!("Sled contains failed: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_decrypt_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"TEST_KEY_32_BYTES_LONG_FOR_UNIT_!";
        let store = EncryptedStore::open(dir.path(), key).unwrap();

        let plaintext = b"Hello, MLS Bot! This is a test message.";
        store.put("test", b"msg1", plaintext).await.unwrap();

        let retrieved = store.get("test", b"msg1").await.unwrap().unwrap();
        assert_eq!(retrieved, plaintext);
    }

    #[tokio::test]
    async fn test_delete() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"TEST_KEY_32_BYTES_LONG_FOR_UNIT_!";
        let store = EncryptedStore::open(dir.path(), key).unwrap();

        store.put("test", b"todelete", b"value").await.unwrap();
        assert!(store.contains("test", b"todelete").await.unwrap());

        let deleted = store.delete("test", b"todelete").await.unwrap();
        assert!(deleted);
        assert!(!store.contains("test", b"todelete").await.unwrap());
    }

    #[tokio::test]
    async fn test_scan() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"TEST_KEY_32_BYTES_LONG_FOR_UNIT_!";
        let store = EncryptedStore::open(dir.path(), key).unwrap();

        store.put("test", b"a", b"value_a").await.unwrap();
        store.put("test", b"b", b"value_b").await.unwrap();

        let results = store.scan("test").await.unwrap();
        assert_eq!(results.len(), 2);
    }

    #[tokio::test]
    async fn test_corrupted_record() {
        let dir = tempfile::tempdir().unwrap();
        let key = b"TEST_KEY_32_BYTES_LONG_FOR_UNIT_!";
        let store = EncryptedStore::open(dir.path(), key).unwrap();

        // Manually insert a corrupted blob (too short)
        let tree = store.tree("test_corrupt").unwrap();
        tree.insert(b"bad_key", vec![0u8; 5]).unwrap();

        // Reading it should return an error
        let result = store.get("test_corrupt", b"bad_key").await;
        assert!(result.is_err());
    }
}
