//! Application-level encryption for SQLite-backed OpenMLS storage.
//!
//! Uses HKDF-SHA-256 for key derivation from a master key, then
//! XChaCha20-Poly1305 for AEAD encryption of each value.
//!
//! # Key hierarchy
//!
//! ```text
//! MasterKey (32 bytes, from FiSH-11 user password + Argon2id)
//!   ├─ HKDF("fish11/fcep2/sqlite-value-key/v1") => SqliteValueKey
//!   └─ HKDF("fish11/fcep2/sqlite-meta-key/v1")  => SqliteMetaKey
//! ```
//!
//! # Sealed value format
//!
//! ```text
//! [0x46, 0x31, 0x31, 0x44, 0x42]  ← "F11DB" magic
//! [version: u16 BE]                ← format version (currently 1)
//! [nonce: 24 bytes]                ← XChaCha20 nonce (random)
//! [ciphertext + tag: N bytes]      ← AEAD output
//! ```

use chacha20poly1305::{AeadInPlace, KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

use super::SqliteStorageError;

// ===== Constants ───────────────────────────────────────────────────

const SEALED_MAGIC: &[u8; 5] = b"F11DB";
const SEALED_VERSION: u16 = 1;
/// XChaCha20-Poly1305 nonce is 24 bytes.
const NONCE_LEN: usize = 24;
/// XChaCha20-Poly1305 tag appended to ciphertext.
const TAG_LEN: usize = 16;
/// Overhead: magic(5) + version(2) + nonce(24) + tag(16) = 47 bytes.
pub const SEALED_OVERHEAD: usize = 5 + 2 + NONCE_LEN + TAG_LEN;

// ===== Key derivation contexts ─────────────────────────────────────

const SQLITE_VALUE_KEY_INFO: &[u8] = b"fish11/fcep2/sqlite-value-key/v1";
const SQLITE_META_KEY_INFO: &[u8] = b"fish11/fcep2/sqlite-meta-key/v1";

// ===== Key types ───────────────────────────────────────────────────

/// 32-byte AEAD key for encrypting SQLite values.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DbValueKey([u8; 32]);

impl std::fmt::Debug for DbValueKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DbValueKey").field(&"[REDACTED]").finish()
    }
}

/// 32-byte AEAD key for encrypting metadata.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct DbMetaKey([u8; 32]);

impl std::fmt::Debug for DbMetaKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DbMetaKey").field(&"[REDACTED]").finish()
    }
}

/// Holds both derived keys, zeroized on drop.
#[derive(Zeroize, Debug)]
#[zeroize(drop)]
pub struct StorageKeys {
    pub(crate) value_key: DbValueKey,
    pub(crate) meta_key: DbMetaKey,
}

impl StorageKeys {
    /// Derive both sub-keys from a 32-byte master key.
    ///
    /// Uses HKDF-SHA-256 to derive `SqliteValueKey` and `SqliteMetaKey`
    /// from the FiSH-11 master key (itself derived from user password + Argon2id).
    pub fn derive_from_master_key(master_key: &[u8; 32]) -> Self {
        let mut vk = [0u8; 32];
        let mut mk = [0u8; 32];
        Hkdf::<Sha256>::from_prk(master_key)
            .expect("32-byte PRK is valid")
            .expand(SQLITE_VALUE_KEY_INFO, &mut vk)
            .expect("expand into 32 bytes");
        Hkdf::<Sha256>::from_prk(master_key)
            .expect("32-byte PRK is valid")
            .expand(SQLITE_META_KEY_INFO, &mut mk)
            .expect("expand into 32 bytes");
        Self { value_key: DbValueKey(vk), meta_key: DbMetaKey(mk) }
    }
}

// ===== Sealed value format ─────────────────────────────────────────

/// Encrypt `plaintext` with `key`, binding `aad` as authenticated associated data.
///
/// Returns a sealed blob: `magic(5) || version(2) || nonce(24) || ciphertext+tag(N)`.
pub fn seal_value(
    key: &DbValueKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SqliteStorageError> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
        .map_err(|e| SqliteStorageError::Sqlite(format!("AEAD key setup failed: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut ciphertext = plaintext.to_vec();
    ciphertext.resize(ciphertext.len() + TAG_LEN, 0);

    cipher
        .encrypt_in_place(nonce, aad, &mut ciphertext)
        .map_err(|e| SqliteStorageError::Sqlite(format!("AEAD encrypt failed: {}", e)))?;

    let mut out = Vec::with_capacity(SEALED_OVERHEAD + plaintext.len());
    out.extend_from_slice(SEALED_MAGIC);
    out.extend_from_slice(&SEALED_VERSION.to_be_bytes());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt a sealed blob created by `seal_value`.
///
/// Returns the original plaintext on success.
/// Returns an error if the magic, version, or AEAD tag is invalid.
pub fn open_value(
    key: &DbValueKey,
    sealed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, SqliteStorageError> {
    if sealed.len() < SEALED_OVERHEAD {
        return Err(SqliteStorageError::Sqlite("Sealed value too short".to_string()));
    }

    let magic = &sealed[..5];
    if magic != SEALED_MAGIC {
        return Err(SqliteStorageError::Sqlite("Invalid sealed value magic".to_string()));
    }

    let _version = u16::from_be_bytes([sealed[5], sealed[6]]);
    let nonce = XNonce::from_slice(&sealed[7..7 + NONCE_LEN]);

    let mut ciphertext = sealed[7 + NONCE_LEN..].to_vec();

    let cipher = XChaCha20Poly1305::new_from_slice(&key.0)
        .map_err(|e| SqliteStorageError::Sqlite(format!("AEAD key setup failed: {}", e)))?;

    cipher.decrypt_in_place(nonce, aad, &mut ciphertext).map_err(|_| {
        SqliteStorageError::Sqlite("AEAD decrypt failed (wrong key or tampered)".to_string())
    })?;

    // The plaintext is ciphertext minus the 16-byte tag (already verified by decrypt_in_place)
    let plaintext_len = ciphertext.len().saturating_sub(TAG_LEN);
    ciphertext.truncate(plaintext_len);
    Ok(ciphertext)
}

/// Build the AAD for an OpenMLS storage value.
///
/// AAD = "fish11/fcep2/sqlite/v1" || label || storage_key
pub fn build_aad(label: &[u8], storage_key: &[u8]) -> Vec<u8> {
    let mut aad = b"fish11/fcep2/sqlite/v1".to_vec();
    aad.extend_from_slice(label);
    aad.extend_from_slice(storage_key);
    aad
}
