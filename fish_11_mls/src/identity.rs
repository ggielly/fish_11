//! Identity and device model for FCEP-2

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use rand::RngCore;

use crate::error::{Fcep2Error, Result};
use crate::provider::FCEP2_CIPHERSUITE;

/// Trust state of a known device identity.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TrustState {
    /// First observed; no out-of-band confirmation.
    Unknown,
    /// Trust on first use; fingerprint persisted locally.
    Tofu,
    /// Fingerprint confirmed out-of-band.
    Verified,
    /// Known label presented an unexpected signing key.
    Changed,
    /// Device removed from all local groups or locally blocked.
    Revoked,
}

/// A persistent device identity for FCEP-2.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// 128-bit random device identifier.
    pub device_id: [u8; 16],
    /// Ed25519 fingerprint of the signing key.
    pub fingerprint: [u8; 32],
    /// Human-readable label (e.g., "mIRC-laptop").
    pub label: String,
    /// Current trust state.
    pub trust: TrustState,
}

/// Group binding: durable association between IRC network, channel, and MLS group.
#[derive(Debug, Clone)]
pub struct GroupBinding {
    /// Protocol version (currently 2 for FCEP-2 v2.0).
    pub protocol_version: u16,
    /// 32-byte random network identifier, generated on first config.
    pub network_id: [u8; 32],
    /// Case-normalized IRC channel name.
    pub canonical_channel: String,
    /// MLS Group ID (128+ bits, CSPRNG-generated).
    pub mls_group_id: Vec<u8>,
    /// Ed25519 fingerprint of the group creator.
    pub creator_fingerprint: [u8; 32],
    /// Unix timestamp of group creation.
    pub created_at_unix: i64,
}

/// Generate a random 128-bit device identifier.
pub fn generate_device_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Generate a random 32-byte network identifier.
pub fn generate_network_id() -> [u8; 32] {
    let mut id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut id);
    id
}

/// Generate a fresh MLS signing key pair and credential.
///
/// Returns `(credential_with_key, signature_keys)` where:
/// - `credential_with_key` can be used to create MLS groups and key packages
/// - `signature_keys` is the Ed25519 signing key pair
pub fn generate_identity(
    _provider: &OpenMlsRustCrypto,
    label: &str,
) -> Result<(CredentialWithKey, SignatureKeyPair)> {
    let signature_keys =
        SignatureKeyPair::new(FCEP2_CIPHERSUITE.signature_algorithm()).map_err(|e| {
            Fcep2Error::InvalidIdentity(format!("Failed to generate signing key: {}", e))
        })?;

    let credential = BasicCredential::new(label.as_bytes().to_vec());
    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    Ok((credential_with_key, signature_keys))
}

/// Compute the Ed25519 fingerprint from a raw public key.
pub fn fingerprint_from_key(public_key: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(public_key);
    let result = hasher.finalize();
    let mut fingerprint = [0u8; 32];
    fingerprint.copy_from_slice(&result);
    fingerprint
}

/// IRC CASEMAPPING rules for channel and nickname canonicalization.
///
/// Per §6.2 and IRC RFC 1459/2812, the server advertises its casemapping
/// via ISUPPORT (RPL_ISUPPORT). The mapping MUST be obtained from the
/// server and passed here. Default is `rfc1459` (most common).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Casemapping {
    /// RFC 1459: `{}|~` mapped to `[]\\^` in addition to ASCII lowercase.
    Rfc1459,
    /// RFC 2812 ("strict-rfc1459"): only ASCII letters are case-folded.
    StrictRfc1459,
    /// ASCII-only: simple `to_ascii_lowercase()`.
    Ascii,
}

impl Casemapping {
    /// Parse from the ISUPPORT value (e.g., "rfc1459", "ascii", "strict-rfc1459").
    pub fn from_isupport(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "rfc1459" => Casemapping::Rfc1459,
            "strict-rfc1459" => Casemapping::StrictRfc1459,
            "ascii" => Casemapping::Ascii,
            _ => Casemapping::Rfc1459, // default
        }
    }

    /// Canonicalize a channel name or nickname according to the casemapping.
    pub fn canonicalize(&self, input: &str) -> String {
        match self {
            Casemapping::Ascii => input.to_ascii_lowercase(),
            Casemapping::Rfc1459 => input
                .chars()
                .map(|c| match c {
                    '[' => '{',
                    ']' => '}',
                    '\\' => '|',
                    '^' => '~',
                    _ => c.to_ascii_lowercase(),
                })
                .collect(),
            Casemapping::StrictRfc1459 => {
                input
                    .chars()
                    .map(|c| match c {
                        '[' | ']' | '\\' | '~' | '{' | '}' | '|' | '^' => c, // keep as-is
                        _ => c.to_ascii_lowercase(),
                    })
                    .collect()
            }
        }
    }
}

impl GroupBinding {
    /// Create a new group binding with fresh identifiers.
    ///
    /// `channel` is canonicalized using the provided `casemapping`.
    /// Per §6.2: "A client MUST NOT treat a nickname match as identity
    /// authentication" : the binding key is (network_id, canonical_channel, mls_group_id).
    pub fn new(
        network_id: [u8; 32],
        casemapping: Casemapping,
        channel: &str,
        mls_group_id: Vec<u8>,
        creator_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: 2,
            network_id,
            canonical_channel: casemapping.canonicalize(channel),
            mls_group_id,
            creator_fingerprint,
            created_at_unix: chrono::Utc::now().timestamp(),
        }
    }

    /// Create a new group binding with a specific canonicalized channel.
    /// Use this if you already know the canonical form (e.g., from a previous binding).
    pub fn new_with_canonical(
        network_id: [u8; 32],
        canonical_channel: String,
        mls_group_id: Vec<u8>,
        creator_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            protocol_version: 2,
            network_id,
            canonical_channel,
            mls_group_id,
            creator_fingerprint,
            created_at_unix: chrono::Utc::now().timestamp(),
        }
    }
}

impl DeviceIdentity {
    /// Create a new device identity.
    pub fn new(device_id: [u8; 16], fingerprint: [u8; 32], label: String) -> Self {
        Self { device_id, fingerprint, label, trust: TrustState::Unknown }
    }
}
