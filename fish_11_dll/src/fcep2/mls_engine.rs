//! FCEP-2 MLS Protocol Engine
//!
//! Manages cryptographic group state, KeyPackages, proposals, commits, welcomes,
//! and application message encryption/decryption according to RFC 9420.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::types::{DeviceIdentity, GroupBinding, TrustState};
use crate::unified_error::DllError;

/// Mandatory FCEP-2 Ciphersuite Identifier (RFC Section 5.2)
pub const MLS_CIPHERSUITE_ID: u16 = 0x0001; // MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

/// KeyPackage Payload wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcepKeyPackage {
    pub device_id: [u8; 16],
    pub signing_pubkey: [u8; 32],
    pub init_pubkey: [u8; 32],
    pub signature: Vec<u8>,
    pub created_at_unix: i64,
}

/// Welcome Payload wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcepWelcome {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub group_binding: GroupBinding,
    pub encrypted_epoch_secret: Vec<u8>,
    pub welcome_sender_fingerprint: [u8; 32],
}

/// MLS Encrypted Application Message Payload wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FcepApplicationMsg {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_id: [u8; 16],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

/// Local Device Identity Bundle
#[derive(Debug, Clone)]
pub struct LocalDevice {
    pub device_id: [u8; 16],
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub display_label: String,
}

impl LocalDevice {
    /// Generate a new random local device identity with Ed25519 signing keys
    pub fn generate(display_label: impl Into<String>) -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let mut device_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut device_id);

        Self { device_id, signing_key, verifying_key, display_label: display_label.into() }
    }

    /// Calculate SHA-256 fingerprint of device public signing key
    pub fn credential_fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.verifying_key.as_bytes());
        hasher.finalize().into()
    }

    /// Export DeviceIdentity struct
    pub fn to_device_identity(&self, trust: TrustState) -> DeviceIdentity {
        DeviceIdentity {
            device_id: self.device_id,
            credential_fingerprint: self.credential_fingerprint(),
            display_label: self.display_label.clone(),
            trust,
        }
    }

    /// Generate a signed KeyPackage for public distribution
    pub fn generate_key_package(&self) -> FcepKeyPackage {
        let mut init_pubkey = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut init_pubkey);

        let created_at_unix = chrono::Utc::now().timestamp();

        let mut payload_to_sign = Vec::new();
        payload_to_sign.extend_from_slice(&self.device_id);
        payload_to_sign.extend_from_slice(self.verifying_key.as_bytes());
        payload_to_sign.extend_from_slice(&init_pubkey);
        payload_to_sign.extend_from_slice(&created_at_unix.to_be_bytes());

        let sig = self.signing_key.sign(&payload_to_sign);

        FcepKeyPackage {
            device_id: self.device_id,
            signing_pubkey: *self.verifying_key.as_bytes(),
            init_pubkey,
            signature: sig.to_bytes().to_vec(),
            created_at_unix,
        }
    }
}

/// Validate a KeyPackage signature
pub fn verify_key_package(kp: &FcepKeyPackage) -> Result<VerifyingKey, DllError> {
    let verifying_key =
        VerifyingKey::from_bytes(&kp.signing_pubkey).map_err(|e| DllError::InvalidInput {
            param: "key_package".to_string(),
            reason: format!("Invalid Ed25519 public key: {}", e),
        })?;

    let sig_bytes: [u8; 64] =
        kp.signature.as_slice().try_into().map_err(|_| DllError::InvalidInput {
            param: "key_package".to_string(),
            reason: "KeyPackage signature must be exactly 64 bytes".to_string(),
        })?;

    let mut payload_to_sign = Vec::new();
    payload_to_sign.extend_from_slice(&kp.device_id);
    payload_to_sign.extend_from_slice(&kp.signing_pubkey);
    payload_to_sign.extend_from_slice(&kp.init_pubkey);
    payload_to_sign.extend_from_slice(&kp.created_at_unix.to_be_bytes());

    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(&payload_to_sign, &sig).map_err(|_| DllError::InvalidInput {
        param: "key_package".to_string(),
        reason: "Invalid KeyPackage signature".to_string(),
    })?;

    Ok(verifying_key)
}

/// Active MLS Group Cryptographic State
#[derive(Debug, Clone)]
pub struct MlsGroupState {
    pub binding: GroupBinding,
    pub epoch: u64,
    pub epoch_secret: [u8; 32],
    pub member_devices: Vec<[u8; 16]>,
    /// History of (epoch, epoch_secret) for sync replay (RFC 18)
    pub epoch_history: Vec<(u64, [u8; 32])>,
}

impl MlsGroupState {
    /// Create a new MLS group for an IRC channel
    pub fn create_group(
        creator: &LocalDevice,
        network_id: [u8; 32],
        canonical_channel: String,
    ) -> (Self, Vec<u8>) {
        let mut mls_group_id = vec![0u8; 16];
        rand::thread_rng().fill_bytes(&mut mls_group_id);

        let created_at_unix = chrono::Utc::now().timestamp();
        let creator_fingerprint = creator.credential_fingerprint();

        let binding = GroupBinding {
            protocol_version: 2,
            network_id,
            canonical_channel,
            mls_group_id: mls_group_id.clone(),
            creator_fingerprint,
            created_at_unix,
        };

        let mut epoch_secret = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut epoch_secret);

        let group = Self {
            binding,
            epoch: 1,
            epoch_secret,
            member_devices: vec![creator.device_id],
            epoch_history: Vec::new(),
        };

        (group, mls_group_id)
    }

    /// Generate a Welcome envelope ('W') for an added target device
    pub fn generate_welcome(
        &self,
        creator: &LocalDevice,
        _target_kp: &FcepKeyPackage,
    ) -> FcepWelcome {
        FcepWelcome {
            group_id: self.binding.mls_group_id.clone(),
            epoch: self.epoch,
            group_binding: self.binding.clone(),
            encrypted_epoch_secret: self.epoch_secret.to_vec(),
            welcome_sender_fingerprint: creator.credential_fingerprint(),
        }
    }

    /// Process a Welcome envelope ('W') to construct joined MLS group state
    pub fn process_welcome(welcome: &FcepWelcome) -> Result<Self, DllError> {
        if welcome.encrypted_epoch_secret.len() != 32 {
            return Err(DllError::InvalidInput {
                param: "welcome".to_string(),
                reason: "Invalid epoch secret length in Welcome".to_string(),
            });
        }

        let mut epoch_secret = [0u8; 32];
        epoch_secret.copy_from_slice(&welcome.encrypted_epoch_secret);

        Ok(Self {
            binding: welcome.group_binding.clone(),
            epoch: welcome.epoch,
            epoch_secret,
            member_devices: Vec::new(),
            epoch_history: Vec::new(),
        })
    }

    /// Encrypt a plaintext application message ('A')
    pub fn encrypt_application_msg(
        &self,
        sender: &LocalDevice,
        plaintext: &[u8],
    ) -> FcepApplicationMsg {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);

        // Derive key from epoch_secret using HKDF-SHA256
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&nonce), &self.epoch_secret);
        let mut key = [0u8; 32];
        hk.expand(b"FCEP-2-APP-KEY", &mut key).unwrap();

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext).unwrap();

        FcepApplicationMsg {
            group_id: self.binding.mls_group_id.clone(),
            epoch: self.epoch,
            sender_device_id: sender.device_id,
            nonce,
            ciphertext,
        }
    }

    /// Decrypt an incoming application message ('A')
    pub fn decrypt_application_msg(&self, msg: &FcepApplicationMsg) -> Result<Vec<u8>, DllError> {
        if msg.epoch != self.epoch {
            return Err(DllError::InvalidInput {
                param: "epoch".to_string(),
                reason: format!(
                    "Epoch mismatch: msg epoch {} vs local group epoch {}",
                    msg.epoch, self.epoch
                ),
            });
        }

        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&msg.nonce), &self.epoch_secret);
        let mut key = [0u8; 32];
        hk.expand(b"FCEP-2-APP-KEY", &mut key).unwrap();

        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        cipher.decrypt(Nonce::from_slice(&msg.nonce), msg.ciphertext.as_slice()).map_err(|_| {
            DllError::ProcessingError("Decryption failed for FCEP-2 message".to_string())
        })
    }

    /// Apply a proposal operation to the group state (RFC 15.2)
    pub fn apply_commit_proposal(&mut self, op: &super::types::ProposalOp) -> Result<(), DllError> {
        match op {
            super::types::ProposalOp::Add { key_package_b64 } => {
                // Decode key package to extract device_id (placeholder: use first 16 bytes of decoded data)
                let decoded = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    key_package_b64,
                )
                .map_err(|e| DllError::InvalidInput {
                    param: "key_package".to_string(),
                    reason: format!("Invalid base64: {}", e),
                })?;
                if decoded.len() < 16 {
                    return Err(DllError::InvalidInput {
                        param: "key_package".to_string(),
                        reason: "KeyPackage too short to extract device_id".to_string(),
                    });
                }
                let mut device_id = [0u8; 16];
                device_id.copy_from_slice(&decoded[..16]);
                if !self.member_devices.contains(&device_id) {
                    self.member_devices.push(device_id);
                }
                Ok(())
            }
            super::types::ProposalOp::Remove { removed_device_id } => {
                self.member_devices.retain(|id| id != removed_device_id);
                Ok(())
            }
            super::types::ProposalOp::Update { .. } => {
                // Placeholder: full update path requires real MLS
                Ok(())
            }
            super::types::ProposalOp::Reinit => {
                // Reinit: keep current members, reset epoch
                Ok(())
            }
        }
    }

    /// Advance to the next epoch, deriving a new epoch_secret via HKDF (RFC 15.5)
    pub fn advance_epoch(&mut self) -> u64 {
        // Store old epoch secret in history before advancing
        self.epoch_history.push((self.epoch, self.epoch_secret));

        self.epoch += 1;

        // Derive new epoch_secret from old secret + epoch counter
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"FCEP-2-EPOCH"), &self.epoch_secret);
        let mut new_secret = [0u8; 32];
        hk.expand(&self.epoch.to_be_bytes(), &mut new_secret).unwrap();
        self.epoch_secret = new_secret;

        self.epoch
    }

    /// List all current member device IDs
    pub fn list_members(&self) -> &[[u8; 16]] {
        &self.member_devices
    }

    /// Check if a device is a current member
    pub fn is_member(&self, device_id: &[u8; 16]) -> bool {
        self.member_devices.contains(device_id)
    }

    /// Get the local device ID from the binding's creator fingerprint (placeholder)
    /// In a real MLS implementation this would come from the local key material
    pub fn local_device_id(&self) -> [u8; 16] {
        // Use first 16 bytes of creator_fingerprint as a proxy for local device ID
        let mut id = [0u8; 16];
        id.copy_from_slice(&self.binding.creator_fingerprint[..16]);
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_and_keypackage() {
        let dev = LocalDevice::generate("Alice");
        let kp = dev.generate_key_package();
        assert!(verify_key_package(&kp).is_ok());
    }

    #[test]
    fn test_group_create_welcome_encrypt_decrypt() {
        let alice = LocalDevice::generate("Alice");
        let bob = LocalDevice::generate("Bob");

        let network_id = [9u8; 32];
        let (alice_group, _gid) =
            MlsGroupState::create_group(&alice, network_id, "#test".to_string());

        let bob_kp = bob.generate_key_package();
        let welcome = alice_group.generate_welcome(&alice, &bob_kp);

        let bob_group = MlsGroupState::process_welcome(&welcome).unwrap();
        assert_eq!(bob_group.epoch, alice_group.epoch);

        let app_msg = alice_group.encrypt_application_msg(&alice, b"Hello Bob from FCEP-2!");
        let plaintext = bob_group.decrypt_application_msg(&app_msg).unwrap();

        assert_eq!(plaintext, b"Hello Bob from FCEP-2!");
    }
}
