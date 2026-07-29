//! OpenMLS Adapter : thin wrapper around the pinned OpenMLS crate.
//!
//! This is the ONLY module that calls OpenMLS APIs. All MLS cryptographic
//! operations go through this adapter, which exposes only raw bytes.
//!
//! # Persistence model
//!
//! OpenMLS handles its own persistence via the `StorageProvider` trait.
//! The `OpenMlsContext` holds an `OpenMlsRustCrypto` provider. Each MLS
//! operation mutates group state and persists it through the provider.
//! Use `fish_11_mls::storage::SqliteOpenMlsProvider` for file-backed durability.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

use crate::unified_error::DllError;

/// Ciphersuite mandated by FCEP-2.
pub const FCEP2_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Default number of KeyPackages to maintain.
pub const DEFAULT_KEYPACKAGE_COUNT: usize = 10;

// ===== OpenMLS Context =====

/// Holds the OpenMLS provider, signing key, and credential for a local device.
pub struct OpenMlsContext {
    pub provider: OpenMlsRustCrypto,
    pub signer: SignatureKeyPair,
    pub credential_with_key: CredentialWithKey,
}

impl OpenMlsContext {
    pub fn new(identity: Vec<u8>) -> Result<Self, DllError> {
        let provider = OpenMlsRustCrypto::default();
        let credential = BasicCredential::new(identity);
        let signer =
            SignatureKeyPair::new(FCEP2_CIPHERSUITE.signature_algorithm()).map_err(|e| {
                DllError::EncryptionFailed {
                    context: "OpenMlsContext::new".to_string(),
                    cause: format!("Signing key generation failed: {}", e),
                }
            })?;
        signer.store(provider.storage()).map_err(|e| DllError::EncryptionFailed {
            context: "OpenMlsContext::new".to_string(),
            cause: format!("Signing key storage failed: {}", e),
        })?;
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        Ok(Self { provider, signer, credential_with_key })
    }
}

fn build_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(FCEP2_CIPHERSUITE)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(20, 2000))
        .use_ratchet_tree_extension(true)
        .build()
}

// ===== Group Operations ────────────────────────────────────────────

/// Create a new MLS group.
/// Returns (MlsGroup, serialized Welcome, serialized Commit).
pub fn create_group(
    ctx: &OpenMlsContext,
    group_id: GroupId,
    invited_key_packages: &[Vec<u8>],
) -> Result<(MlsGroup, Vec<u8>, Vec<u8>), DllError> {
    let config = build_config();
    let mut group = MlsGroup::new_with_group_id(
        &ctx.provider,
        &ctx.signer,
        &config,
        group_id,
        ctx.credential_with_key.clone(),
    )
    .map_err(|e| DllError::EncryptionFailed {
        context: "create_group".to_string(),
        cause: format!("MLS group creation failed: {}", e),
    })?;

    let keypackages: Vec<KeyPackage> = invited_key_packages
        .iter()
        .map(|bytes| -> Result<KeyPackage, DllError> {
            let kp_in = KeyPackageIn::tls_deserialize(&mut &bytes[..])
                .map_err(|e| DllError::ProcessingError(format!("Invalid KeyPackage: {}", e)))?;
            kp_in.validate(ctx.provider.crypto(), ProtocolVersion::Mls10).map_err(|e| {
                DllError::ProcessingError(format!("KeyPackage validation failed: {}", e))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let (commit, welcome_serialized, _group_info) = group
        .add_members(&ctx.provider, &ctx.signer, &keypackages)
        .map_err(|e| DllError::EncryptionFailed {
            context: "create_group".to_string(),
            cause: format!("Failed to add members: {}", e),
        })?;

    let commit_bytes =
        commit.tls_serialize_detached().map_err(|e| DllError::TlsCodec(e.to_string()))?;
    let welcome_bytes = welcome_serialized
        .tls_serialize_detached()
        .map_err(|e| DllError::TlsCodec(e.to_string()))?;
    Ok((group, welcome_bytes, commit_bytes))
}

/// Load an MlsGroup from the StorageProvider by GroupId.
pub fn load_group(ctx: &OpenMlsContext, group_id: &GroupId) -> Result<MlsGroup, DllError> {
    MlsGroup::load(ctx.provider.storage(), group_id)
        .map_err(|e| DllError::ProcessingError(format!("Storage error: {}", e)))?
        .ok_or_else(|| DllError::InvalidInput {
            param: "group_id".to_string(),
            reason: "Group not found in storage".to_string(),
        })
}

/// Join a group from a serialized Welcome. Returns (MlsGroup, group_id_bytes).
pub fn join_from_welcome(
    ctx: &OpenMlsContext,
    welcome_bytes: &[u8],
    expected_group_id: Option<&[u8]>,
) -> Result<(MlsGroup, Vec<u8>), DllError> {
    let welcome = Welcome::tls_deserialize(&mut &welcome_bytes[..])
        .map_err(|e| DllError::ProcessingError(format!("Invalid Welcome: {}", e)))?;

    if let Some(expected) = expected_group_id {
        let join_config = MlsGroupJoinConfig::default();
        let processed =
            ProcessedWelcome::new_from_welcome(&ctx.provider, &join_config, welcome.clone())
                .map_err(|e| {
                    DllError::ProcessingError(format!("Welcome processing failed: {}", e))
                })?;
        let actual = processed.unverified_group_info().group_id();
        if actual.as_slice() != expected {
            return Err(DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "Welcome group ID mismatch".to_string(),
            });
        }
    }

    let join_config = MlsGroupJoinConfig::default();
    let staged = StagedWelcome::new_from_welcome(&ctx.provider, &join_config, welcome, None)
        .map_err(|e| DllError::ProcessingError(format!("Welcome staging failed: {}", e)))?;
    let group = staged
        .into_group(&ctx.provider)
        .map_err(|e| DllError::ProcessingError(format!("Failed to join: {}", e)))?;
    let gid = group.group_id().as_slice().to_vec();
    Ok((group, gid))
}

/// Encrypt plaintext. Returns serialized MLS application message.
pub fn encrypt_application(
    group: &mut MlsGroup,
    ctx: &OpenMlsContext,
    plaintext: &[u8],
) -> Result<Vec<u8>, DllError> {
    let out = group.create_message(&ctx.provider, &ctx.signer, plaintext).map_err(|e| {
        DllError::EncryptionFailed { context: "encrypt".to_string(), cause: e.to_string() }
    })?;
    out.tls_serialize_detached().map_err(|e| DllError::TlsCodec(e.to_string()))
}

/// Decrypt an incoming MLS message. Returns plaintext (or None for commits).
pub fn process_message(
    group: &mut MlsGroup,
    ctx: &OpenMlsContext,
    incoming_bytes: &[u8],
) -> Result<Option<Vec<u8>>, DllError> {
    use openmls::framing::ProcessedMessageContent;

    let mls_msg = MlsMessageIn::tls_deserialize(&mut &incoming_bytes[..])
        .map_err(|e| DllError::ProcessingError(format!("Invalid MLS message: {}", e)))?;
    let protocol_msg = mls_msg
        .try_into_protocol_message()
        .map_err(|e| DllError::ProcessingError(format!("Not a protocol message: {}", e)))?;
    let processed = group.process_message(&ctx.provider, protocol_msg).map_err(|e| {
        DllError::DecryptionFailed { context: "process_message".to_string(), cause: e.to_string() }
    })?;

    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(app) => Ok(Some(app.into_bytes())),
        ProcessedMessageContent::StagedCommitMessage(_staged) => {
            group
                .merge_pending_commit(&ctx.provider)
                .map_err(|e| DllError::ProcessingError(format!("Merge commit failed: {}", e)))?;
            Ok(None)
        }
        _ => Ok(None),
    }
}

/// Add a member. Returns (serialized Welcome, serialized Commit).
pub fn add_member(
    group: &mut MlsGroup,
    ctx: &OpenMlsContext,
    key_package_bytes: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), DllError> {
    let kp_in = KeyPackageIn::tls_deserialize(&mut &key_package_bytes[..])
        .map_err(|e| DllError::ProcessingError(format!("Invalid KeyPackage: {}", e)))?;
    let kp = kp_in
        .validate(ctx.provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|e| DllError::ProcessingError(format!("KeyPackage validation failed: {}", e)))?;
    let (commit, welcome, _gi) =
        group.add_members(&ctx.provider, &ctx.signer, &[kp]).map_err(|e| {
            DllError::EncryptionFailed { context: "add_member".to_string(), cause: e.to_string() }
        })?;
    let cb = commit.tls_serialize_detached().map_err(|e| DllError::TlsCodec(e.to_string()))?;
    let wb = welcome.tls_serialize_detached().map_err(|e| DllError::TlsCodec(e.to_string()))?;
    Ok((wb, cb))
}

/// Remove a member. Returns serialized Commit.
pub fn remove_member(
    group: &mut MlsGroup,
    ctx: &OpenMlsContext,
    leaf_index: u32,
) -> Result<Vec<u8>, DllError> {
    let (_wo, co, _gi) = group
        .remove_members(&ctx.provider, &ctx.signer, &[LeafNodeIndex::new(leaf_index)])
        .map_err(|e| DllError::EncryptionFailed {
            context: "remove_member".to_string(),
            cause: e.to_string(),
        })?;
    let commit = co.ok_or_else(|| DllError::EncryptionFailed {
        context: "remove_member".to_string(),
        cause: "No commit produced".to_string(),
    })?;
    commit.tls_serialize_detached().map_err(|e| DllError::TlsCodec(e.to_string()))
}

// ===== KeyPackage Operations ───────────────────────────────────────

/// Generate TLS-serialized MLS KeyPackages.
pub fn generate_key_packages(ctx: &OpenMlsContext, count: usize) -> Result<Vec<Vec<u8>>, DllError> {
    (0..count)
        .map(|_| {
            KeyPackage::builder()
                .build(
                    FCEP2_CIPHERSUITE,
                    &ctx.provider,
                    &ctx.signer,
                    ctx.credential_with_key.clone(),
                )
                .map_err(|e| DllError::EncryptionFailed {
                    context: "gen_kp".to_string(),
                    cause: e.to_string(),
                })?
                .key_package()
                .tls_serialize_detached()
                .map_err(|e| DllError::TlsCodec(e.to_string()))
        })
        .collect()
}

// ===== Epoch extraction ────────────────────────────────────────────

/// Extract the epoch from a raw TLS-serialized MLS message.
///
/// Used by the relay to log commit epochs without depending on deprecated
/// custom types. Returns `None` when the bytes do not form a valid message
/// or when the wire format is not a protocol message (Welcome, KeyPackage, …).
pub fn extract_commit_epoch(raw: &[u8]) -> Option<u64> {
    use openmls::prelude::*;
    use tls_codec::Deserialize as _;

    let msg = MlsMessageIn::tls_deserialize(&mut &raw[..]).ok()?;
    let proto = msg.try_into_protocol_message().ok()?;
    Some(proto.epoch().as_u64())
}
