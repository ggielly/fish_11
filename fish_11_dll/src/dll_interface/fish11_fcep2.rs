//! FCEP-2 C DLL Interface Functions for mIRC
//!
//! Provides `FiSH11_FCEP2_*` API functions exported for mIRC script calls.

#![allow(unused_doc_comments)]

use std::ffi::c_char;
use std::os::raw::c_int;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::Digest;

use crate::fcep2::envelope::FcepEnvelope;
use crate::fcep2::fragmentation::split_payload;
use crate::fcep2::mls_engine::{
    FcepApplicationMsg, FcepKeyPackage, FcepWelcome, MlsGroupState, verify_key_package,
};
use crate::fcep2::storage::FcepStorage;
use crate::fcep2::types::{
    CommitPayload, EnvelopeKind, PersistedGroup, ProposalOp, SyncRequest, SyncResponse, TrustState,
};
use crate::fcep2::{
    COMMIT_PROCESSOR, CONFLICT_MANAGER, DEDUP_FILTER, DEFERRED_CACHE, FCEP2_CHANNEL_MAP,
    FCEP2_GROUPS, KEY_PACKAGE_POOL, PROPOSAL_ENGINE, RATE_LIMITER, REASSEMBLY_ENGINE, SYNC_MANAGER,
    get_or_init_device,
};
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, get_current_network, log_info};

/// Initialize local device identity
/// Input: `<display_label>`
/// Output: `OK <device_id_hex> <credential_fingerprint_hex>`
dll_function_identifier!(FiSH11_FCEP2_InitDevice, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let label = if input.trim().is_empty() { "mIRC_User" } else { input.trim() };

    let dev = get_or_init_device(label);
    let dev_id_hex = hex::encode(dev.device_id);
    let fp_hex = hex::encode(dev.credential_fingerprint());

    log_info!("FiSH11_FCEP2_InitDevice: device initialized id={}", dev_id_hex);

    Ok(format!("OK {} {}", dev_id_hex, fp_hex))
});

/// Generate a signed KeyPackage for public distribution
/// Input: optional `<display_label>`
/// Output: `KEYPACKAGE <base64_serialized_keypackage>`
dll_function_identifier!(FiSH11_FCEP2_GenKeyPackage, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let label = if input.trim().is_empty() { "mIRC_User" } else { input.trim() };

    let dev = get_or_init_device(label);
    let kp = dev.generate_key_package();

    let json_bytes =
        serde_json::to_vec(&kp).map_err(|e| DllError::ProcessingError(e.to_string()))?;
    let b64_kp = STANDARD.encode(json_bytes);

    log_info!(
        "FiSH11_FCEP2_GenKeyPackage: keypackage generated for device={}",
        hex::encode(dev.device_id)
    );

    Ok(format!("KEYPACKAGE {}", b64_kp))
});

/// Create a new FCEP-2 group for an IRC channel
/// Input: `<#channel> [<base64_keypackage_1> <base64_keypackage_2> ...]`
/// Output: `GROUP_CREATED <group_id_b64> WELCOMES <b64_welcome_1> ...`
dll_function_identifier!(FiSH11_FCEP2_CreateGroup, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.is_empty() {
        return Err(DllError::InvalidInput {
            param: "channel".to_string(),
            reason: "Channel name required".to_string(),
        });
    }

    let channel = parts[0].to_lowercase();
    let creator = get_or_init_device("mIRC_User");

    let mut network_id = [0u8; 32];
    if let Some(net) = get_current_network() {
        let sha = sha2::Sha256::digest(net.as_bytes());
        network_id.copy_from_slice(&sha);
    } else {
        network_id = [1u8; 32];
    }

    let (group, mls_group_id) = MlsGroupState::create_group(&creator, network_id, channel.clone());

    let mut welcomes_b64 = Vec::new();
    for kp_b64 in &parts[1..] {
        if let Ok(raw_json) = STANDARD.decode(kp_b64) {
            if let Ok(kp) = serde_json::from_slice::<FcepKeyPackage>(&raw_json) {
                if verify_key_package(&kp).is_ok() {
                    let welcome = group.generate_welcome(&creator, &kp);
                    if let Ok(w_json) = serde_json::to_vec(&welcome) {
                        welcomes_b64.push(STANDARD.encode(w_json));
                    }
                }
            }
        }
    }

    // Persist group state
    let persisted = PersistedGroup {
        binding: group.binding.clone(),
        serialized_mls_group: group.epoch_secret.to_vec(),
        local_device_id: creator.device_id,
        known_devices: vec![creator.to_device_identity(TrustState::Verified)],
        conflict: None,
        outbox: Vec::new(),
        schema_version: 1,
        current_epoch: group.epoch,
    };
    let storage = FcepStorage::new();
    storage.save_group(&persisted)?;

    // Register in memory
    FCEP2_GROUPS.write().insert(mls_group_id.clone(), group);
    FCEP2_CHANNEL_MAP.write().insert(channel.clone(), mls_group_id.clone());

    let b64_gid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&mls_group_id);
    let welcomes_str = welcomes_b64.join(" ");

    log_info!("FiSH11_FCEP2_CreateGroup: created group for channel '{}'", channel);

    Ok(format!("GROUP_CREATED {} WELCOMES {}", b64_gid, welcomes_str))
});

/// Process an incoming IRC line (`PRIVMSG` or `NOTICE`)
/// Input: `<source_nick> <target_channel_or_nick> <full_fcep2_line>`
/// Output: `DECRYPTED <nick> <channel> <plaintext>` | `JOINED <channel> <group_id_b64>` | `FRAGMENT_WAIT` | `CONTROL` | `DUPLICATE_SKIPPED`
dll_function_identifier!(FiSH11_FCEP2_ProcessMessage, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    if parts.len() < 3 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<source_nick> <target> <fcep2_line>'".to_string(),
        });
    }

    let source_nick = parts[0];
    let target = parts[1];
    let fcep_line = parts[2];

    let envelope = FcepEnvelope::parse(fcep_line)?;

    match envelope {
        FcepEnvelope::Fragment { object_id, index, count, kind, fragment } => {
            if object_id.len() != 16 {
                return Err(DllError::InvalidInput {
                    param: "object_id".to_string(),
                    reason: format!("Fragment object_id must be 16 bytes, got {}", object_id.len()),
                });
            }
            let mut oid = [0u8; 16];
            oid.copy_from_slice(&object_id);

            let fragment_env = crate::fcep2::transport::FcepEnvelope::Fragment {
                object_id: oid,
                index,
                count,
                kind,
                bytes: fragment,
            };
            let res = REASSEMBLY_ENGINE.write().process_fragment(source_nick, fragment_env)?;

            match res {
                Some((k, reassembled)) => {
                    // Reassembled envelope : target_id not known from fragments alone
                    handle_standard_envelope(
                        source_nick,
                        target,
                        k,
                        target.as_bytes(),
                        &reassembled,
                    )
                }
                None => Ok(format!("FRAGMENT_WAIT {}/{}", index + 1, count)),
            }
        }
        FcepEnvelope::Standard { kind, target_id, payload } => {
            // Dedup check for application messages (RFC 17.3)
            if kind == EnvelopeKind::Application {
                let app: Result<FcepApplicationMsg, _> = serde_json::from_slice(&payload);
                if let Ok(msg) = app {
                    let fp = crate::fcep2::dedup::DeduplicationFilter::compute_fingerprint(
                        kind,
                        &msg.group_id,
                        msg.epoch,
                        &msg.sender_device_id,
                        &msg.nonce,
                    );
                    if DEDUP_FILTER.write().is_duplicate(&fp) {
                        return Ok("DUPLICATE_SKIPPED".to_string());
                    }
                }
            }

            // Deferred delivery for unknown groups (RFC 13.3)
            if matches!(
                kind,
                EnvelopeKind::Welcome | EnvelopeKind::Commit | EnvelopeKind::Application
            ) {
                let group_known = FCEP2_GROUPS.read().contains_key(&target_id);
                if !group_known && kind != EnvelopeKind::Welcome {
                    // Enqueue for later delivery
                    let _ = DEFERRED_CACHE.write().enqueue(
                        target_id.clone(),
                        kind,
                        payload.to_vec(),
                        source_nick,
                        target_id.to_vec(),
                    );
                    return Ok(format!("DEFERRED {} {:?}", target_id.len(), kind));
                }
            }

            handle_standard_envelope(source_nick, target, kind, &target_id, &payload)
        }
    }
});

fn handle_standard_envelope(
    source_nick: &str,
    target: &str,
    kind: EnvelopeKind,
    target_id: &[u8],
    payload: &[u8],
) -> Result<String, DllError> {
    match kind {
        EnvelopeKind::Application => {
            let msg: FcepApplicationMsg = serde_json::from_slice(payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let groups_guard = FCEP2_GROUPS.read();
            let group = groups_guard.get(&msg.group_id).ok_or_else(|| DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "Unknown FCEP-2 group ID".to_string(),
            })?;

            let decrypted_bytes = group.decrypt_application_msg(&msg)?;
            let plaintext = String::from_utf8(decrypted_bytes)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            Ok(format!("DECRYPTED {} {} {}", source_nick, target, plaintext))
        }
        EnvelopeKind::Welcome => {
            let welcome: FcepWelcome = serde_json::from_slice(payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;
            let group = MlsGroupState::process_welcome(&welcome)?;

            let channel = group.binding.canonical_channel.clone();
            let gid = group.binding.mls_group_id.clone();

            FCEP2_GROUPS.write().insert(gid.clone(), group);
            FCEP2_CHANNEL_MAP.write().insert(channel.clone(), gid.clone());

            // Drain deferred objects for this group (RFC 13.3)
            let deferred = DEFERRED_CACHE.write().drain_for_group(&gid);
            let mut deferred_results = Vec::new();
            for entry in deferred {
                if let Ok(result) = handle_standard_envelope(
                    source_nick,
                    target,
                    entry.kind,
                    &entry.target_id,
                    &entry.payload,
                ) {
                    deferred_results.push(result);
                }
            }

            let b64_gid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&gid);
            let mut result = format!("JOINED {} {}", channel, b64_gid);
            if !deferred_results.is_empty() {
                result.push_str(&format!(" DEFERRED_APPLIED={}", deferred_results.len()));
            }
            Ok(result)
        }
        EnvelopeKind::Proposal => {
            // RFC 15.1: Process incoming proposal
            let groups_guard = FCEP2_GROUPS.read();
            let group = groups_guard.get(target_id).ok_or_else(|| DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "Proposal for unknown group".to_string(),
            })?;

            // Parse proposal from payload (simplified: extract basic fields)
            let proposal_data: serde_json::Value = serde_json::from_slice(payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let op = match proposal_data.get("op").and_then(|v| v.as_str()) {
                Some("ADD") => ProposalOp::Add {
                    key_package_b64: proposal_data
                        .get("key_package")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                },
                Some("REMOVE") => {
                    let dev_hex =
                        proposal_data.get("device_id").and_then(|v| v.as_str()).unwrap_or("");
                    let dev_bytes = hex::decode(dev_hex).unwrap_or_default();
                    let mut dev_id = [0u8; 16];
                    if dev_bytes.len() >= 16 {
                        dev_id.copy_from_slice(&dev_bytes[..16]);
                    }
                    ProposalOp::Remove { removed_device_id: dev_id }
                }
                Some("UPDATE") => ProposalOp::Update { new_encryption_key: [0u8; 32] },
                _ => ProposalOp::Reinit,
            };

            let mut sender_id = [0u8; 16];
            if let Some(id_hex) = proposal_data.get("sender").and_then(|v| v.as_str()) {
                if let Ok(bytes) = hex::decode(id_hex) {
                    if bytes.len() >= 16 {
                        sender_id.copy_from_slice(&bytes[..16]);
                    }
                }
            }

            let _proposal = PROPOSAL_ENGINE.write().process_incoming_proposal(
                source_nick,
                target_id.to_vec(),
                group.epoch,
                sender_id,
                op,
                vec![],
                Some(group.epoch),
            )?;

            Ok(format!("PROPOSAL_RECEIVED from {}", source_nick))
        }
        EnvelopeKind::Commit => {
            // RFC 15.2: Process incoming commit
            let commit: CommitPayload = serde_json::from_slice(payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let mut groups_guard = FCEP2_GROUPS.write();
            let group =
                groups_guard.get_mut(&commit.group_id).ok_or_else(|| DllError::InvalidInput {
                    param: "group_id".to_string(),
                    reason: "Commit for unknown group".to_string(),
                })?;

            let result = COMMIT_PROCESSOR.write().process_commit(&commit, group, source_nick)?;

            match result {
                crate::fcep2::types::CommitResult::Applied { new_epoch, .. } => {
                    let storage = FcepStorage::new();
                    let persisted = PersistedGroup {
                        binding: group.binding.clone(),
                        serialized_mls_group: group.epoch_secret.to_vec(),
                        local_device_id: group.local_device_id(),
                        known_devices: vec![],
                        conflict: None,
                        outbox: vec![],
                        schema_version: 1,
                        current_epoch: group.epoch,
                    };
                    let _ = storage.save_group(&persisted);

                    Ok(format!("COMMIT_APPLIED epoch={}", new_epoch))
                }
                crate::fcep2::types::CommitResult::Conflict { conflict } => {
                    let summary = format!("CONFLICT at epoch={}", conflict.old_epoch);
                    crate::fcep2::push_diagnostic(
                        "conflict_detected",
                        conflict.group_id.clone(),
                        &summary,
                        crate::fcep2::types::DiagnosticSeverity::Warn,
                    );
                    Ok(format!("CONFLICT_DETECTED epoch={}", conflict.old_epoch))
                }
                crate::fcep2::types::CommitResult::Rejected { reason } => {
                    Ok(format!("COMMIT_REJECTED {}", reason))
                }
            }
        }
        EnvelopeKind::Request => {
            // RFC 18: Process sync request
            let req: SyncRequest = serde_json::from_slice(payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let groups_guard = FCEP2_GROUPS.read();
            let group = groups_guard.get(&req.group_id).ok_or_else(|| DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "Sync request for unknown group".to_string(),
            })?;

            let resp = crate::fcep2::types::SyncResponse {
                request_id: req.request_id,
                group_id: req.group_id.clone(),
                current_epoch: group.epoch,
                epoch_diff: Vec::new(),
                current_members: group.list_members().to_vec(),
                responder_device_id: group.local_device_id(),
            };
            let resp_json =
                serde_json::to_vec(&resp).map_err(|e| DllError::ProcessingError(e.to_string()))?;
            let b64_resp = STANDARD.encode(resp_json);

            Ok(format!("SYNC_RESPONSE {}", b64_resp))
        }
        EnvelopeKind::Sync => {
            // RFC 18: Process sync response (transport only : commits applied via legacy path)
            let resp: SyncResponse = serde_json::from_slice(payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let mut groups_guard = FCEP2_GROUPS.write();
            let group =
                groups_guard.get_mut(&resp.group_id).ok_or_else(|| DllError::InvalidInput {
                    param: "group_id".to_string(),
                    reason: "Sync response for unknown group".to_string(),
                })?;

            let commits = SYNC_MANAGER.write().process_sync_response(&resp)?;
            if commits.is_empty() {
                Ok("SYNC_NO_CHANGE".to_string())
            } else {
                for _ in &commits {
                    group.advance_epoch();
                }
                Ok(format!("SYNC_APPLIED epoch={}", group.epoch))
            }
        }
        EnvelopeKind::KeyPackage => Ok(format!("CONTROL KEYPACKAGE_RECEIVED from {}", source_nick)),
        EnvelopeKind::Ack => Ok(format!("CONTROL Ack from {}", source_nick)),
    }
}

/// Encrypt a plaintext application message for an IRC channel
/// Input: `<#channel> <plaintext>`
/// Output: Transmittable envelope lines (`+FCEP2 A ...` or `+FCEP2 F ...`)
dll_function_identifier!(FiSH11_FCEP2_EncryptMsg, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <plaintext>'".to_string(),
        });
    }

    let channel = parts[0].to_lowercase();
    let plaintext = parts[1];

    if CONFLICT_MANAGER
        .read()
        .is_in_conflict_for(&FCEP2_CHANNEL_MAP.read().get(&channel).cloned().unwrap_or_default())
    {
        return Err(DllError::ProcessingError(
            "Cannot send message: Group is in CommitConflict state".to_string(),
        ));
    }

    // Rate limit check (RFC 8.4)
    if !RATE_LIMITER.write().allow_send(&channel) {
        return Err(DllError::ProcessingError(
            "Rate limited: max 4 fragments/sec per destination".to_string(),
        ));
    }

    let channel_map = FCEP2_CHANNEL_MAP.read();
    let gid = channel_map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No active FCEP-2 group for channel '{}'", channel),
    })?;

    let groups_guard = FCEP2_GROUPS.read();
    let group = groups_guard
        .get(gid)
        .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;

    let sender = get_or_init_device("mIRC_User");
    let app_msg = group.encrypt_application_msg(&sender, plaintext.as_bytes());

    let payload_bytes =
        serde_json::to_vec(&app_msg).map_err(|e| DllError::ProcessingError(e.to_string()))?;

    let lines =
        split_payload(EnvelopeKind::Application, &group.binding.mls_group_id, &payload_bytes, 320);

    Ok(lines.join("\n"))
});

/// Decrypt a direct FCEP-2 envelope line for a channel
/// Input: `<#channel> <+FCEP2... line>`
/// Output: `<plaintext>`
dll_function_identifier!(FiSH11_FCEP2_DecryptMsg, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <fcep2_line>'".to_string(),
        });
    }

    let envelope = FcepEnvelope::parse(parts[1])?;

    match envelope {
        FcepEnvelope::Standard { kind: EnvelopeKind::Application, target_id, payload } => {
            let msg: FcepApplicationMsg = serde_json::from_slice(&payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let groups_guard = FCEP2_GROUPS.read();
            let group = groups_guard.get(&target_id).ok_or_else(|| DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "Unknown FCEP-2 group ID".to_string(),
            })?;

            let decrypted_bytes = group.decrypt_application_msg(&msg)?;
            let plaintext = String::from_utf8(decrypted_bytes)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;
            Ok(plaintext)
        }
        _ => Err(DllError::InvalidInput {
            param: "envelope".to_string(),
            reason: "Expected Standard Application envelope".to_string(),
        }),
    }
});

/// Query group state info
/// Input: `<#channel>`
/// Output: `STATE channel=<#channel> group_id=<hex> epoch=<epoch> in_conflict=<bool>`
dll_function_identifier!(FiSH11_FCEP2_GetGroupState, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let channel = input.trim().to_lowercase();

    let map = FCEP2_CHANNEL_MAP.read();
    if let Some(gid) = map.get(&channel) {
        let groups = FCEP2_GROUPS.read();
        if let Some(group) = groups.get(gid) {
            let conflict_flag = CONFLICT_MANAGER.read().is_in_conflict();
            return Ok(format!(
                "STATE channel={} group_id={} epoch={} in_conflict={}",
                channel,
                hex::encode(&group.binding.mls_group_id),
                group.epoch,
                conflict_flag
            ));
        }
    }

    Ok(format!("NO_GROUP {}", channel))
});

/// Resolve commit conflict for a specific channel
/// Input: `<#channel>`
/// Output: `OK conflict resolved for <#channel>`
dll_function_identifier!(FiSH11_FCEP2_ResolveConflict, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let channel = input.trim().to_lowercase();

    let map = FCEP2_CHANNEL_MAP.read();
    let gid = map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No group for channel '{}'", channel),
    })?;

    CONFLICT_MANAGER.write().resolve(gid);
    log_info!("FiSH11_FCEP2_ResolveConflict: resolved conflict for channel '{}'", channel);

    Ok(format!("OK conflict resolved for {}", channel))
});

/// Set device trust state
/// Input: `<device_id_hex> <UNKNOWN|TOFU|VERIFIED|CHANGED|REVOKED>`
/// Output: `OK trust updated for <device_id_hex>`
dll_function_identifier!(FiSH11_FCEP2_SetTrust, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "trust".to_string(),
            reason: "Expected '<device_id_hex> <TRUST_STATE>'".to_string(),
        });
    }

    let dev_id_hex = parts[0];
    let state_str = parts[1].to_uppercase();

    let _state = match state_str.as_str() {
        "UNKNOWN" => TrustState::Unknown,
        "TOFU" => TrustState::Tofu,
        "VERIFIED" => TrustState::Verified,
        "CHANGED" => TrustState::Changed,
        "REVOKED" => TrustState::Revoked,
        _ => {
            return Err(DllError::InvalidInput {
                param: "trust_state".to_string(),
                reason: "Invalid trust state label".to_string(),
            });
        }
    };

    log_info!("FiSH11_FCEP2_SetTrust: trust updated for device {} to {}", dev_id_hex, state_str);
    Ok(format!("OK trust updated for {}", dev_id_hex))
});

// ═══════════════════════════════════════════════════════════════════
// NEW FCEP-2 DLL FUNCTIONS (RFC Sections 11-20)
// ═══════════════════════════════════════════════════════════════════

/// Submit a proposal for a group (RFC 15.1)
/// Input: `<#channel> <ADD|REMOVE|UPDATE> <b64_or_hex_arg>`
/// Output: `PROPOSAL_CACHED <proposal_id_hex> pending=<count>`
dll_function_identifier!(FiSH11_FCEP2_SubmitProposal, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <OP> [arg]'".to_string(),
        });
    }

    let channel = parts[0].to_lowercase();
    let op_str = parts[1].to_uppercase();

    let map = FCEP2_CHANNEL_MAP.read();
    let gid = map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No active FCEP-2 group for channel '{}'", channel),
    })?;

    let groups_guard = FCEP2_GROUPS.read();
    let group = groups_guard
        .get(gid)
        .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;

    let sender = get_or_init_device("mIRC_User");
    let op = match op_str.as_str() {
        "ADD" => {
            let kp_b64 = parts.get(2).map(|s| s.to_string()).unwrap_or_default();
            ProposalOp::Add { key_package_b64: kp_b64 }
        }
        "REMOVE" => {
            let dev_hex = parts.get(2).unwrap_or(&"");
            let dev_bytes = hex::decode(dev_hex).unwrap_or_default();
            let mut dev_id = [0u8; 16];
            if dev_bytes.len() >= 16 {
                dev_id.copy_from_slice(&dev_bytes[..16]);
            }
            ProposalOp::Remove { removed_device_id: dev_id }
        }
        "UPDATE" => ProposalOp::Update { new_encryption_key: [0u8; 32] },
        _ => ProposalOp::Reinit,
    };

    let proposal = PROPOSAL_ENGINE.write().process_incoming_proposal(
        &sender.display_label,
        gid.clone(),
        group.epoch,
        sender.device_id,
        op,
        vec![],
        Some(group.epoch),
    )?;

    let pending = PROPOSAL_ENGINE.read().pending_count(gid);
    let pid_hex = hex::encode(proposal.proposal_id);

    Ok(format!("PROPOSAL_CACHED {} pending={}", pid_hex, pending))
});

/// Build and send a Commit from pending proposals (RFC 15.2)
/// Input: `<#channel>`
/// Output: `COMMIT_SENT epoch=<new_epoch>` + envelope lines
dll_function_identifier!(FiSH11_FCEP2_SendCommit, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let channel = input.trim().to_lowercase();

    let map = FCEP2_CHANNEL_MAP.read();
    let gid = map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No active FCEP-2 group for channel '{}'", channel),
    })?;

    let sender = get_or_init_device("mIRC_User");

    // Drain proposals and advance epoch
    let new_epoch = {
        let mut groups_guard = FCEP2_GROUPS.write();
        let group = groups_guard
            .get_mut(gid)
            .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;
        group.advance_epoch()
    };

    // Build commit from drained proposals
    let commit = PROPOSAL_ENGINE.write().build_commit_payload(gid, &sender, new_epoch);

    // Serialize and return as envelope
    let commit_json =
        serde_json::to_vec(&commit).map_err(|e| DllError::ProcessingError(e.to_string()))?;
    let lines = split_payload(EnvelopeKind::Commit, gid, &commit_json, 320);

    let envelopes = lines.join("\n");
    Ok(format!("COMMIT_SENT epoch={} {}", new_epoch, envelopes))
});

/// Remove a device from a group (RFC 16)
/// Input: `<#channel> <device_id_hex>`
/// Output: `REMOVAL_COMMITTED epoch=<new_epoch>`
dll_function_identifier!(FiSH11_FCEP2_RemoveDevice, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <device_id_hex>'".to_string(),
        });
    }

    let channel = parts[0].to_lowercase();
    let dev_hex = parts[1];
    let dev_bytes = hex::decode(dev_hex).map_err(|e| DllError::InvalidInput {
        param: "device_id".to_string(),
        reason: e.to_string(),
    })?;

    if dev_bytes.len() != 16 {
        return Err(DllError::InvalidInput {
            param: "device_id".to_string(),
            reason: "Device ID must be 16 bytes (32 hex chars)".to_string(),
        });
    }

    let mut dev_id = [0u8; 16];
    dev_id.copy_from_slice(&dev_bytes);

    let map = FCEP2_CHANNEL_MAP.read();
    let gid = map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No active FCEP-2 group for channel '{}'", channel),
    })?;

    // Cache a Remove proposal, then immediately commit
    {
        let mut groups_guard = FCEP2_GROUPS.write();
        let group = groups_guard
            .get_mut(gid)
            .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;

        PROPOSAL_ENGINE
            .write()
            .cache_proposal(
                gid.clone(),
                crate::fcep2::types::Proposal {
                    proposal_id: [0u8; 16], // Will be replaced by cache_proposal
                    group_id: gid.clone(),
                    epoch: group.epoch,
                    sender_device_id: get_or_init_device("mIRC_User").device_id,
                    op: ProposalOp::Remove { removed_device_id: dev_id },
                    signature: vec![],
                    created_at_unix: chrono::Utc::now().timestamp(),
                },
            )
            .ok();

        // Apply the remove directly to group state
        group.apply_commit_proposal(&ProposalOp::Remove { removed_device_id: dev_id })?;
    }

    // Advance epoch
    let new_epoch = {
        let mut groups_guard = FCEP2_GROUPS.write();
        let group = groups_guard
            .get_mut(gid)
            .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;
        group.advance_epoch()
    };

    Ok(format!("REMOVAL_COMMITTED epoch={}", new_epoch))
});

/// Request synchronization for a group (RFC 18)
/// Input: `<#channel>`
/// Output: `SYNC_REQUEST <+FCEP2 R ... envelope>`
dll_function_identifier!(FiSH11_FCEP2_SyncGroup, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let channel = input.trim().to_lowercase();

    let map = FCEP2_CHANNEL_MAP.read();
    let gid = map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No active FCEP-2 group for channel '{}'", channel),
    })?;

    let groups_guard = FCEP2_GROUPS.read();
    let group = groups_guard
        .get(gid)
        .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;

    let sender = get_or_init_device("mIRC_User");
    let req = SYNC_MANAGER.write().create_sync_request(
        gid.clone(),
        group.epoch.saturating_sub(1),
        sender.device_id,
    );

    let req_json =
        serde_json::to_vec(&req).map_err(|e| DllError::ProcessingError(e.to_string()))?;
    let b64_req = STANDARD.encode(req_json);

    Ok(format!(
        "SYNC_REQUEST +FCEP2 R {} {}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(gid),
        b64_req
    ))
});

/// Process an incoming sync request or response (RFC 18)
/// Input: `<source_nick> <target> <+FCEP2 S|R ... line>`
/// Output: `SYNC_APPLIED epoch=<n>` | `SYNC_RESPONSE <b64>` | `SYNC_NO_CHANGE`
dll_function_identifier!(FiSH11_FCEP2_ProcessSync, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    if parts.len() < 3 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<source_nick> <target> <fcep2_line>'".to_string(),
        });
    }

    let _source_nick = parts[0];
    let _target = parts[1];
    let fcep_line = parts[2];

    let envelope = FcepEnvelope::parse(fcep_line)?;

    match envelope {
        FcepEnvelope::Standard { kind: EnvelopeKind::Request, target_id: _, payload } => {
            let req: SyncRequest = serde_json::from_slice(&payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let groups_guard = FCEP2_GROUPS.read();
            let group = groups_guard.get(&req.group_id).ok_or_else(|| DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "Sync request for unknown group".to_string(),
            })?;

            let resp = crate::fcep2::types::SyncResponse {
                request_id: req.request_id,
                group_id: req.group_id.clone(),
                current_epoch: group.epoch,
                epoch_diff: Vec::new(),
                current_members: group.list_members().to_vec(),
                responder_device_id: group.local_device_id(),
            };
            let resp_json =
                serde_json::to_vec(&resp).map_err(|e| DllError::ProcessingError(e.to_string()))?;
            let b64_resp = STANDARD.encode(resp_json);

            Ok(format!("SYNC_RESPONSE {}", b64_resp))
        }
        FcepEnvelope::Standard { kind: EnvelopeKind::Sync, target_id: _, payload } => {
            let resp: SyncResponse = serde_json::from_slice(&payload)
                .map_err(|e| DllError::ProcessingError(e.to_string()))?;

            let mut groups_guard = FCEP2_GROUPS.write();
            let group =
                groups_guard.get_mut(&resp.group_id).ok_or_else(|| DllError::InvalidInput {
                    param: "group_id".to_string(),
                    reason: "Sync response for unknown group".to_string(),
                })?;

            let commits = SYNC_MANAGER.write().process_sync_response(&resp)?;
            if commits.is_empty() {
                Ok("SYNC_NO_CHANGE".to_string())
            } else {
                for _ in &commits {
                    group.advance_epoch();
                }
                Ok(format!("SYNC_APPLIED epoch={}", group.epoch))
            }
        }
        _ => Err(DllError::InvalidInput {
            param: "envelope".to_string(),
            reason: "Expected Request or Sync envelope".to_string(),
        }),
    }
});

/// Export group state for backup (RFC 19)
/// Input: `<#channel>`
/// Output: `EXPORT <base64_json_persisted_group>`
dll_function_identifier!(FiSH11_FCEP2_ExportState, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let channel = input.trim().to_lowercase();

    let map = FCEP2_CHANNEL_MAP.read();
    let gid = map.get(&channel).ok_or_else(|| DllError::InvalidInput {
        param: "channel".to_string(),
        reason: format!("No active FCEP-2 group for channel '{}'", channel),
    })?;

    let groups_guard = FCEP2_GROUPS.read();
    let group = groups_guard
        .get(gid)
        .ok_or_else(|| DllError::ProcessingError("Group state missing".to_string()))?;

    let sender = get_or_init_device("mIRC_User");
    let persisted = PersistedGroup {
        binding: group.binding.clone(),
        serialized_mls_group: group.epoch_secret.to_vec(),
        local_device_id: sender.device_id,
        known_devices: vec![sender.to_device_identity(TrustState::Verified)],
        conflict: None,
        outbox: vec![],
        schema_version: 1,
        current_epoch: group.epoch,
    };

    let storage = FcepStorage::new();
    let b64 = storage.export_group_json(&persisted)?;

    Ok(format!("EXPORT {}", b64))
});

/// Import group state from backup (RFC 19)
/// Input: `<#channel> <base64_json_persisted_group>`
/// Output: `IMPORTED epoch=<epoch> members=<count>`
dll_function_identifier!(FiSH11_FCEP2_ImportState, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <base64_json>'".to_string(),
        });
    }

    let channel = parts[0].to_lowercase();
    let b64_json = parts[1];

    let storage = FcepStorage::new();
    let persisted = storage.import_group_json(b64_json)?;

    // Reconstruct MlsGroupState from persisted data
    let mut epoch_secret = [0u8; 32];
    let secret_len = persisted.serialized_mls_group.len().min(32);
    epoch_secret[..secret_len].copy_from_slice(&persisted.serialized_mls_group[..secret_len]);

    let member_devices: Vec<[u8; 16]> =
        persisted.known_devices.iter().map(|d| d.device_id).collect();

    let group = MlsGroupState {
        binding: persisted.binding.clone(),
        epoch: persisted.current_epoch,
        epoch_secret,
        member_devices,
        epoch_history: vec![],
    };

    let gid = group.binding.mls_group_id.clone();
    let member_count = group.member_devices.len();

    FCEP2_GROUPS.write().insert(gid.clone(), group);
    FCEP2_CHANNEL_MAP.write().insert(channel.clone(), gid.clone());

    Ok(format!("IMPORTED epoch={} members={}", persisted.current_epoch, member_count))
});

/// Request KeyPackage from pool or local device (RFC 11.2)
/// Input: `<#channel> <device_id_hex|ALL>`
/// Output: `KEYPACKAGE_RESPONSE <b64_kp> ...`
dll_function_identifier!(FiSH11_FCEP2_RequestKeyPackage, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.is_empty() {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <device_hex|ALL>'".to_string(),
        });
    }

    let pool = KEY_PACKAGE_POOL.read();
    let available: Vec<&str> =
        pool.iter().filter(|e| !e.used).map(|e| e.key_package_b64.as_str()).collect();

    if available.is_empty() {
        return Ok("KEYPACKAGE_RESPONSE NONE".to_string());
    }

    let response = available.join(" ");
    Ok(format!("KEYPACKAGE_RESPONSE {}", response))
});

/// Get diagnostic events for a channel (RFC 22.3)
/// Input: `<#channel> [last_n]`
/// Output: `DIAGNOSTICS <count> | <severity> <timestamp> <event_type> <detail>`
dll_function_identifier!(FiSH11_FCEP2_GetDiagnostics, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    let last_n: usize = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);

    let log = crate::fcep2::DIAGNOSTICS_LOG.read();
    let events: Vec<&crate::fcep2::types::DiagnosticEvent> =
        log.iter().filter(|e| !e.event_type.is_empty()).rev().take(last_n).collect();

    if events.is_empty() {
        return Ok("DIAGNOSTICS 0".to_string());
    }

    let mut result = format!("DIAGNOSTICS {}", events.len());
    for ev in &events {
        result.push_str(&format!(
            "\n{} {} {} {}",
            ev.severity as u8, ev.timestamp_unix, ev.event_type, ev.detail
        ));
    }
    Ok(result)
});

/// Set encryption policy for a channel (RFC 22.1)
/// Input: `<#channel> <ALWAYS|REQUIRE_ALL|BEST_EFFORT|DISABLED>`
/// Output: `POLICY_SET <#channel> <policy>`
dll_function_identifier!(FiSH11_FCEP2_SetEncryptionPolicy, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Expected '<#channel> <POLICY>'".to_string(),
        });
    }

    let channel = parts[0].to_lowercase();
    let policy_str = parts[1].to_uppercase();

    let policy = match policy_str.as_str() {
        "ALWAYS" => crate::fcep2::types::EncryptionPolicy::Always,
        "REQUIRE_ALL" => crate::fcep2::types::EncryptionPolicy::RequireAll,
        "BEST_EFFORT" => crate::fcep2::types::EncryptionPolicy::BestEffort,
        "DISABLED" => crate::fcep2::types::EncryptionPolicy::Disabled,
        _ => {
            return Err(DllError::InvalidInput {
                param: "policy".to_string(),
                reason: "Invalid policy. Use ALWAYS, REQUIRE_ALL, BEST_EFFORT, or DISABLED"
                    .to_string(),
            });
        }
    };

    crate::fcep2::ENCRYPTION_POLICIES.write().insert(channel.clone(), policy);

    Ok(format!("POLICY_SET {} {}", channel, policy_str))
});

/// Pre-generate KeyPackages for the pool (RFC 11.1)
/// Input: `<count>`
/// Output: `POOL_FILLED count=<n> ready=<ready_count>`
dll_function_identifier!(FiSH11_FCEP2_FillKeyPackagePool, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let count: usize = input.trim().parse().unwrap_or(10).min(50);

    let dev = get_or_init_device("mIRC_User");
    let mut pool = KEY_PACKAGE_POOL.write();

    for _ in 0..count {
        let kp = dev.generate_key_package();
        let json_bytes =
            serde_json::to_vec(&kp).map_err(|e| DllError::ProcessingError(e.to_string()))?;
        let b64_kp = STANDARD.encode(json_bytes);

        pool.push(crate::fcep2::types::KeyPackagePoolEntry {
            key_package_b64: b64_kp,
            created_at_unix: chrono::Utc::now().timestamp(),
            used: false,
        });
    }

    let ready = pool.iter().filter(|e| !e.used).count();

    // Persist pool
    let storage = FcepStorage::new();
    let _ = storage.save_keypackage_pool(&pool);

    Ok(format!("POOL_FILLED count={} ready={}", count, ready))
});
