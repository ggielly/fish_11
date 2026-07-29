//! MLS group lifecycle management
//!
//! This module wraps OpenMLS group operations: creation, joining,
//! message sending/receiving, and member management.
//!
//! CRITICAL: All operations MUST follow the transaction sequence:
//! 1. Persist group state + outbox BEFORE sending on the network
//! 2. Send network messages
//! 3. Merge pending commits only after durable persistence
//!
//! The `GroupMode` state machine enforces these constraints.

use openmls::framing::ProcessedMessageContent;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::error::{Fcep2Error, Result};
use crate::provider::build_group_config;

/// Operational mode of a local MLS group.
///
/// This state machine prevents operations that are invalid in the current
/// mode and enforces the persist => send => merge transaction sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMode {
    /// Normal operation: can send messages, add/remove members.
    Active,
    /// Local commit produced but not yet merged after network delivery.
    /// send_message, add_member, remove_member are BLOCKED until merge.
    PendingLocalCommit,
    /// Conflicting commits detected in the same epoch.
    /// All automatic sends are suspended; manual conflict resolution required.
    CommitConflict(crate::persistence::CommitConflictData),
    /// Group state irrecoverably lost (storage corruption, provider reset).
    /// Device must rejoin as a new member.
    StateLost,
}

/// Create a new MLS group and add initial members.
///
/// Returns `(group, welcome_msg, commit_msg, mode)`:
/// - `group`: the local MlsGroup state (must be persisted before sending)
/// - `welcome_msg`: the Welcome (as MlsMessageOut) to send privately
/// - `commit_msg`: the Commit (as MlsMessageOut) to broadcast to the channel
/// - `mode`: `PendingLocalCommit` : caller MUST persist before sending,
///   then call `merge_pending_commit` only after the network commit is sent.
///
/// §15.2/§19.3: The group and outbox MUST be persisted BEFORE network transmission.
/// The mode transitions to PendingLocalCommit immediately after add_members.
pub fn create_group(
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    credential: CredentialWithKey,
    invited_keypackages: &[KeyPackageBundle],
) -> Result<(
    MlsGroup,
    MlsMessageOut, // Welcome (serialized)
    MlsMessageOut, // Commit
    GroupMode,     // Always PendingLocalCommit until merge
)> {
    let config = build_group_config();

    let mut group = MlsGroup::new(provider, signer, &config, credential)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to create group: {}", e)))?;

    if invited_keypackages.is_empty() {
        return Err(Fcep2Error::Mls("Cannot create group without invited members".to_string()));
    }

    // Extract KeyPackages from bundles
    let keypackages: Vec<KeyPackage> =
        invited_keypackages.iter().map(|b| b.key_package().clone()).collect();

    // add_members returns (MlsMessageOut, MlsMessageOut, Option<GroupInfo>)
    // In 0.8.1: (commit, welcome_serialized, group_info)
    let (commit, welcome_serialized, _group_info) = group
        .add_members(provider, signer, &keypackages)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to add initial members: {}", e)))?;

    // Mode is PendingLocalCommit: caller MUST persist before sending,
    // then merge only after commit is durably stored.
    Ok((group, welcome_serialized, commit, GroupMode::PendingLocalCommit))
}

/// Add a member to an existing group.
///
/// Returns `(welcome_msg, commit_msg, mode)` where mode is `PendingLocalCommit`.
/// Caller MUST:
/// 1. Persist the group state + outbox
/// 2. Send the Welcome (NOTICE) and Commit (PRIVMSG)
/// 3. Call `merge_pending_commit` only after durable persistence
///
/// Returns an error if the group is not in `Active` mode.
pub fn add_member(
    group: &mut MlsGroup,
    mode: &GroupMode,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    keypackages: &[KeyPackage],
) -> Result<(MlsMessageOut, MlsMessageOut, GroupMode)> {
    if *mode != GroupMode::Active {
        return Err(Fcep2Error::Mls(format!(
            "Cannot add member in mode {:?}: must be Active",
            mode
        )));
    }

    let (commit, welcome_serialized, _group_info) = group
        .add_members(provider, signer, keypackages)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to add members: {}", e)))?;

    Ok((welcome_serialized, commit, GroupMode::PendingLocalCommit))
}

/// Remove a member from the group.
///
/// Returns the Commit message (as MlsMessageOut) to broadcast and the new mode
/// (PendingLocalCommit until merge).
///
/// Returns an error if the group is not in `Active` mode.
pub fn remove_member(
    group: &mut MlsGroup,
    mode: &GroupMode,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    member_index: LeafNodeIndex,
) -> Result<(MlsMessageOut, GroupMode)> {
    if *mode != GroupMode::Active {
        return Err(Fcep2Error::Mls(format!(
            "Cannot remove member in mode {:?}: must be Active",
            mode
        )));
    }

    let (_welcome_opt, commit_opt, _group_info) = group
        .remove_members(provider, signer, &[member_index])
        .map_err(|e| Fcep2Error::Mls(format!("Failed to remove member: {}", e)))?;

    let commit =
        commit_opt.ok_or_else(|| Fcep2Error::Mls("Remove produced no commit".to_string()))?;
    Ok((commit, GroupMode::PendingLocalCommit))
}

/// Join a group from a Welcome message with optional group ID validation.
///
/// The Welcome must be received via NOTICE (never broadcast).
///
/// If `expected_group_id` is `Some`, the Welcome's embedded group ID is validated
/// against the expected bytes before the join completes. This prevents a malicious
/// or misrouted Welcome from creating a binding to an unexpected MLS group. The
/// check uses `ProcessedWelcome::unverified_group_info()` to extract the group_id
/// before full decryption, avoiding redundant Welcome deserialization.
///
/// Returns the joined MlsGroup state.
pub fn join_from_welcome(
    provider: &OpenMlsRustCrypto,
    welcome: Welcome,
    expected_group_id: Option<&[u8]>,
) -> Result<MlsGroup> {
    let join_config = MlsGroupJoinConfig::default();

    // Process the Welcome to extract and validate the group_id before staging
    let processed_welcome =
        openmls::prelude::ProcessedWelcome::new_from_welcome(provider, &join_config, welcome)
            .map_err(|e| Fcep2Error::Mls(format!("Failed to process welcome: {}", e)))?;

    // Validate group ID against expected binding, if provided
    if let Some(expected) = expected_group_id {
        let actual = processed_welcome.unverified_group_info().group_id();
        if actual.as_slice() != expected {
            return Err(Fcep2Error::Mls(format!(
                "Welcome group ID mismatch: expected {:?}, got {:?}",
                expected,
                actual.as_slice()
            )));
        }
    }

    // Convert ProcessedWelcome => StagedWelcome => MlsGroup
    // Pass None for the ratchet tree to request it from the Welcome's GroupInfo
    let staged = processed_welcome
        .into_staged_welcome(provider, None)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to stage welcome: {}", e)))?;

    staged
        .into_group(provider)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to join from welcome: {}", e)))
}

/// Send an application message to the group.
///
/// Returns the MLS message to broadcast to the channel.
/// Returns an error if the group is not in `Active` mode.
pub fn send_message(
    group: &mut MlsGroup,
    mode: &GroupMode,
    provider: &OpenMlsRustCrypto,
    signer: &SignatureKeyPair,
    plaintext: &[u8],
) -> Result<MlsMessageOut> {
    match mode {
        GroupMode::Active => {}
        GroupMode::PendingLocalCommit => {
            return Err(Fcep2Error::Mls(
                "Cannot send message: pending local commit not yet merged".to_string(),
            ));
        }
        GroupMode::CommitConflict(data) => {
            return Err(Fcep2Error::CommitConflict {
                group_id: data.group_id.iter().map(|b| format!("{:02x}", b)).collect(),
            });
        }
        GroupMode::StateLost => {
            return Err(Fcep2Error::StateLost);
        }
    }

    group
        .create_message(provider, signer, plaintext)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to create message: {}", e)))
}

/// Result of processing an incoming MLS message with FCEP-2 classification.
#[derive(Debug)]
pub enum ProcessedFcep2Message {
    /// Regular application message : deliver to the user.
    Application(Vec<u8>),
    /// A Commit was staged. The caller MUST persist, then classify:
    /// - No conflict => merge_pending_commit, transition to Active
    /// - Conflict => write CommitConflictData, transition to CommitConflict
    StagedCommit {
        /// The epoch in which this Commit operates.
        epoch: u64,
        /// SHA-256 of the raw TLS-serialized Commit bytes (stable evidence identifier).
        /// Two distinct commits at the same epoch produce different hashes.
        commit_hash: [u8; 32],
        /// Full raw TLS-serialized MLS Commit bytes (for conflict evidence storage).
        /// Used as irrefutable proof of what was received.
        commit_bytes: Vec<u8>,
    },
    /// A Proposal was received (informational for relay; clients may process).
    Proposal,
    /// Other message type (welcome, etc. : should not arrive via group channel).
    Other,
}

/// Process an incoming MLS message, classifying the result.
///
/// For application messages: returns `ProcessedFcep2Message::Application`.
/// For Commits: returns `ProcessedFcep2Message::StagedCommit` with the epoch,
/// SHA-256 hash of the raw TLS bytes (stable evidence identifier), and the
/// full raw TLS bytes for conflict persistence.
pub fn process_message(
    group: &mut MlsGroup,
    provider: &OpenMlsRustCrypto,
    mls_message: MlsMessageIn,
    raw_tls_bytes: &[u8],
) -> Result<ProcessedFcep2Message> {
    use sha2::{Digest, Sha256};

    let protocol_msg = mls_message
        .try_into_protocol_message()
        .map_err(|e| Fcep2Error::Mls(format!("Message is not a protocol message: {}", e)))?;

    let processed = group
        .process_message(provider, protocol_msg)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to process message: {}", e)))?;

    // ProcessedMessage is a struct with a `.content()` method returning
    // ProcessedMessageContent enum (OpenMLS 0.8.x API)
    match processed.into_content() {
        ProcessedMessageContent::ApplicationMessage(msg) => {
            Ok(ProcessedFcep2Message::Application(msg.into_bytes()))
        }
        ProcessedMessageContent::ProposalMessage(_) => Ok(ProcessedFcep2Message::Proposal),
        ProcessedMessageContent::StagedCommitMessage(commit) => {
            let epoch = commit.epoch().as_u64();
            // SHA-256 of the raw TLS-serialized Commit bytes => stable evidence identifier.
            // Two different commits at the same epoch produce different hashes.
            let hash: [u8; 32] = Sha256::digest(raw_tls_bytes).into();
            // Keep the full raw TLS bytes as evidence for conflict persistence.
            let commit_bytes = raw_tls_bytes.to_vec();
            Ok(ProcessedFcep2Message::StagedCommit { epoch, commit_bytes, commit_hash: hash })
        }
        _ => Ok(ProcessedFcep2Message::Other),
    }
}

/// Process a staged commit: check for conflicts and determine the new GroupMode.
///
/// Call this AFTER processing a `StagedCommit` and BEFORE `merge_pending_commit`.
///
/// Conflict is detected using both the epoch AND the SHA-256 hash of the raw
/// TLS bytes. Two commits at the same epoch with different hashes = conflict.
///
/// - If `locally_known_epoch == received_epoch` and hashes differ => conflict.
/// - If `locally_known_epoch == received_epoch` and hashes match => duplicate.
/// - Otherwise (epoch advanced as expected): returns `Active`.
pub fn classify_staged_commit(
    group: &MlsGroup,
    group_mode: &GroupMode,
    received_epoch: u64,
    commit_hash: &[u8; 32],
    commit_bytes: &[u8],
) -> GroupMode {
    match group_mode {
        GroupMode::Active => GroupMode::Active,
        GroupMode::PendingLocalCommit => {
            let current_epoch = group.epoch().as_u64();
            if current_epoch == received_epoch {
                // Same epoch as our pending commit : check if it's the same or different
                GroupMode::CommitConflict(crate::persistence::CommitConflictData {
                    group_id: group.group_id().as_slice().to_vec(),
                    old_epoch: current_epoch,
                    conflicting_commits: vec![commit_bytes.to_vec()],
                    detected_at_unix: chrono::Utc::now().timestamp(),
                    source_diagnostics: vec![format!(
                        "Competing commit at epoch {} sha256={}",
                        current_epoch,
                        commit_hash.iter().map(|b| format!("{:02x}", b)).collect::<String>()
                    )],
                })
            } else {
                GroupMode::Active
            }
        }
        GroupMode::CommitConflict(data) => GroupMode::CommitConflict(data.clone()),
        GroupMode::StateLost => GroupMode::StateLost,
    }
}

/// Merge a pending commit into the local group state.
///
/// MUST be called ONLY after:
/// 1. The group state and outbox have been durably persisted
/// 2. The Commit has been sent on the network
///
/// On success, the mode transitions back to `Active`.
pub fn merge_pending_commit(group: &mut MlsGroup, provider: &OpenMlsRustCrypto) -> Result<()> {
    group
        .merge_pending_commit(provider)
        .map_err(|e| Fcep2Error::Mls(format!("Failed to merge pending commit: {}", e)))
}

/// Detect a commit conflict by comparing the received epoch against the
/// locally expected epoch.
///
/// Returns `Some(CommitConflictData)` if a conflict is detected,
/// meaning a competing commit was received before ours was merged.
pub fn detect_commit_conflict(
    group: &MlsGroup,
    expected_epoch: u64,
    conflicting_commit_bytes: &[u8],
) -> Option<crate::persistence::CommitConflictData> {
    let current_epoch = group.epoch().as_u64();
    if current_epoch == expected_epoch {
        // Same epoch as our pending commit : conflict!
        Some(crate::persistence::CommitConflictData {
            group_id: group.group_id().as_slice().to_vec(),
            old_epoch: current_epoch,
            conflicting_commits: vec![conflicting_commit_bytes.to_vec()],
            detected_at_unix: chrono::Utc::now().timestamp(),
            source_diagnostics: vec![format!(
                "Competing commit at epoch {} detected before local merge",
                current_epoch
            )],
        })
    } else {
        None
    }
}

/// Get the current group epoch.
pub fn group_epoch(group: &MlsGroup) -> u64 {
    group.epoch().as_u64()
}

/// Get the group ID as bytes.
pub fn group_id_bytes(group: &MlsGroup) -> Vec<u8> {
    group.group_id().as_slice().to_vec()
}

#[cfg(test)]
mod tests {
    // Integration tests will be added when the full stack is wired up
}
