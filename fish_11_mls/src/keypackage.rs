//! KeyPackage generation, serialization, and lifecycle management
//!
//! KeyPackages are public MLS objects published by a device. When consumed
//! in an Add Commit, they allow asynchronous group joining.
//!
//! # Lifecycle (§11.4)
//!
//! Each KeyPackage has a status:
//! - `Available`: ready for distribution
//! - `Published`: sent to a relay or peer (awaiting consumption)
//! - `Consumed`: used in an Add Commit (MUST NOT be reused)
//! - `Expired`: past its `not_after` or 30-day relay max
//! - `Withdrawn`: explicitly removed by the device owner
//!
//! The device SHOULD maintain at least `DEFAULT_KEYPACKAGE_COUNT` (10)
//! available KeyPackages and replenish them as they are consumed or expired.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;

use crate::error::{Fcep2Error, Result};
use crate::provider::FCEP2_CIPHERSUITE;

/// Default number of KeyPackages to maintain (aligned with spec recommendation).
pub const DEFAULT_KEYPACKAGE_COUNT: usize = 10;

/// Status of a KeyPackage in the local pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum KeyPackageStatus {
    /// Ready for distribution (not yet sent to any relay).
    Available,
    /// Published to a relay or peer; waiting for consumption.
    Published,
    /// Consumed in an Add Commit. MUST NOT be reused.
    Consumed,
    /// Past its `not_after` timestamp or 30-day relay retention.
    Expired,
    /// Explicitly withdrawn by the device owner.
    Withdrawn,
}

/// A KeyPackage tracked in the local pool with lifecycle metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TrackedKeyPackage {
    /// The serialized KeyPackage (TLS-serialized bytes).
    pub serialized: Vec<u8>,
    /// Base64url-encoded form (for IRC transport).
    pub b64: String,
    /// Device ID this KeyPackage belongs to.
    pub device_id: [u8; 16],
    /// Status in the lifecycle.
    pub status: KeyPackageStatus,
    /// Unix timestamp of creation.
    pub created_at_unix: i64,
    /// KeyPackage's `not_after` timestamp (if available), or 30 days from creation.
    pub expires_at_unix: i64,
}

/// Generate fresh MLS KeyPackages for a device.
///
/// Returns bundles containing KeyPackage + private key material, wrapped in
/// `TrackedKeyPackage` with lifecycle metadata.
///
/// The generated bundles are NOT published; call `publish_keypackage()`
/// to produce the transport-friendly Base64URL form. The caller MUST
/// associate these with a device identity and persist the pool.
pub fn generate_keypackages(
    provider: &impl openmls_traits::OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential: &CredentialWithKey,
    device_id: [u8; 16],
    count: usize,
) -> Result<Vec<(KeyPackageBundle, TrackedKeyPackage)>> {
    let now = chrono::Utc::now().timestamp();
    let expire_30d = now + 30 * 86400;
    let mut results = Vec::with_capacity(count);

    for _ in 0..count {
        let bundle = KeyPackage::builder()
            .build(FCEP2_CIPHERSUITE, provider, signer, credential.clone())
            .map_err(|e| Fcep2Error::KeyPackage(format!("Failed to build KeyPackage: {}", e)))?;

        let serialized = serialize_keypackage(bundle.key_package())?;
        let b64 = URL_SAFE_NO_PAD.encode(&serialized);

        let tracked = TrackedKeyPackage {
            serialized,
            b64,
            device_id,
            status: KeyPackageStatus::Available,
            created_at_unix: now,
            // RFC §11.4: KeyPackage expires at min(not_after, 30 days from creation)
            expires_at_unix: expire_30d,
        };

        results.push((bundle, tracked));
    }

    Ok(results)
}

/// Replenish the KeyPackage pool: generate new KeyPackages to reach the target count.
///
/// Returns only the NEWLY generated bundles. The caller should merge them
/// into the existing pool, persist, and publish the new ones.
pub fn replenish_keypackages(
    provider: &impl openmls_traits::OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential: &CredentialWithKey,
    device_id: [u8; 16],
    pool: &[TrackedKeyPackage],
    target_count: usize,
) -> Result<Vec<(KeyPackageBundle, TrackedKeyPackage)>> {
    let available = pool.iter().filter(|kp| kp.status == KeyPackageStatus::Available).count();
    if available >= target_count {
        return Ok(Vec::new());
    }

    let needed = target_count - available;
    generate_keypackages(provider, signer, credential, device_id, needed)
}

/// Mark a KeyPackage as published (sent to a relay).
pub fn mark_published(pool: &mut [TrackedKeyPackage], b64: &str) {
    if let Some(kp) = pool.iter_mut().find(|kp| kp.b64 == b64) {
        if kp.status == KeyPackageStatus::Available {
            kp.status = KeyPackageStatus::Published;
        }
    }
}

/// Mark a KeyPackage as consumed (used in an Add Commit).
pub fn mark_consumed(pool: &mut [TrackedKeyPackage], b64: &str) {
    if let Some(kp) = pool.iter_mut().find(|kp| kp.b64 == b64) {
        kp.status = KeyPackageStatus::Consumed;
    }
}

/// Evict expired and withdrawn KeyPackages from the pool.
pub fn evict_expired(pool: &mut Vec<TrackedKeyPackage>) {
    let now = chrono::Utc::now().timestamp();
    pool.retain(|kp| {
        kp.status != KeyPackageStatus::Expired
            && kp.status != KeyPackageStatus::Withdrawn
            && kp.expires_at_unix > now
    });
}

/// Serialize a KeyPackage for IRC transport.
///
/// The KeyPackage is already TLS-serialized internally; we extract the
/// bytes via the OpenMLS serialization API.
pub fn serialize_keypackage(kp: &KeyPackage) -> Result<Vec<u8>> {
    use tls_codec::Serialize;

    kp.tls_serialize_detached()
        .map_err(|e| Fcep2Error::TlsCodec(format!("KeyPackage serialization failed: {}", e)))
}

/// Serialize a Welcome message for IRC transport.
pub fn serialize_welcome(welcome: &Welcome) -> Result<Vec<u8>> {
    use tls_codec::Serialize;

    welcome
        .tls_serialize_detached()
        .map_err(|e| Fcep2Error::TlsCodec(format!("Welcome serialization failed: {}", e)))
}

/// Deserialize a Welcome message from bytes.
pub fn deserialize_welcome(data: &[u8]) -> Result<Welcome> {
    use tls_codec::Deserialize;

    Welcome::tls_deserialize(&mut &data[..])
        .map_err(|e| Fcep2Error::TlsCodec(format!("Welcome deserialization failed: {}", e)))
}

/// Serialize an MlsMessage for IRC transport.
pub fn serialize_mls_message(msg: &MlsMessageOut) -> Result<Vec<u8>> {
    use tls_codec::Serialize;

    msg.tls_serialize_detached()
        .map_err(|e| Fcep2Error::TlsCodec(format!("MlsMessage serialization failed: {}", e)))
}

/// Deserialize an MlsMessage from bytes.
pub fn deserialize_mls_message(data: &[u8]) -> Result<MlsMessageIn> {
    use tls_codec::Deserialize;

    MlsMessageIn::tls_deserialize(&mut &data[..])
        .map_err(|e| Fcep2Error::TlsCodec(format!("MlsMessage deserialization failed: {}", e)))
}

#[cfg(test)]
mod tests {
    use openmls_rust_crypto::OpenMlsRustCrypto;

    use super::*;

    #[test]
    fn test_keypackage_generation() {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(FCEP2_CIPHERSUITE.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"test-device".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let device_id = [0x42u8; 16];

        let results = generate_keypackages(&provider, &signer, &credential, device_id, 3).unwrap();
        assert_eq!(results.len(), 3);

        // Each should have a valid KeyPackage and tracked metadata
        for (bundle, tracked) in &results {
            let kp = bundle.key_package();
            assert_eq!(kp.ciphersuite(), FCEP2_CIPHERSUITE);
            assert_eq!(tracked.device_id, device_id);
            assert_eq!(tracked.status, KeyPackageStatus::Available);
            assert!(!tracked.b64.is_empty());
        }
    }

    #[test]
    fn test_keypackage_serialization() {
        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(FCEP2_CIPHERSUITE.signature_algorithm()).unwrap();
        let credential = CredentialWithKey {
            credential: BasicCredential::new(b"test-device".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let device_id = [0x42u8; 16];

        let results = generate_keypackages(&provider, &signer, &credential, device_id, 1).unwrap();
        let serialized = serialize_keypackage(results[0].0.key_package()).unwrap();
        assert!(!serialized.is_empty());
    }
}
