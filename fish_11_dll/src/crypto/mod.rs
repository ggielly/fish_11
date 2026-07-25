use std::any::Any;
pub mod x25519;
pub use self::x25519::*;
pub mod chacha20;
pub use self::chacha20::*;
use crate::error::Result;
pub mod blowfish;
pub mod dh1080;
// pub mod aes_kw; // TODO: fix imports before enabling (aes_keywrap API changes)

/// Trait for message encryption and decryption
pub trait MessageCipher: Any + Send + Sync {
    /// Encrypt a message
    fn encrypt(
        &self,
        key: &[u8],
        message: &str,
        recipient: Option<&str>,
        associated_data: Option<&[u8]>,
    ) -> Result<String>;

    /// Decrypt a message
    fn decrypt(
        &self,
        key: &[u8],
        encrypted_data: &str,
        associated_data: Option<&[u8]>,
    ) -> Result<String>;

    /// Generate a symmetric key
    fn generate_key(&self) -> Result<Vec<u8>>;

    /// Upcast to Any
    fn as_any(&self) -> &dyn Any;
}

/// Trait for Key Exchange operations
pub trait KeyExchange {
    fn generate_keypair(&self) -> Result<Box<dyn KeyPair>>;
    fn extract_public_key(&self, formatted: &str) -> Result<Vec<u8>>;
}

/// Trait for Key Pair operations
pub trait KeyPair {
    fn public_key_formatted(&self) -> String;
    fn compute_shared_secret(&self, public_key: &[u8]) -> Result<[u8; 32]>;
    fn as_any(&self) -> &dyn std::any::Any;
}
