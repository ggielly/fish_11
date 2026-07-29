//! FCEP-2 Envelope Handler for the MLS Test Bot
//!
//! Processes incoming IRC PRIVMSG and NOTICE lines, executing FCEP-2
//! relay operations (KeyPackage storage, Welcome delivery, Commit logging,
//! Sync request/response) per RFC Sections 8–13, 15, 18.
//!
//! Also handles backlog TCP messages for out-of-band MLS operations.

use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use irc::client::prelude::*;
use tracing::{debug, error, info, warn};

use crate::backlog_server::BacklogMessage;
use crate::config::AppConfig;
use crate::database::EncryptedStore;
use crate::dll_bridge::DllBridge;

/// Global fragment reassembly tracker (FCEP-2 §10)
static REASSEMBLY: once_cell::sync::Lazy<Mutex<ReassemblyTracker>> =
    once_cell::sync::Lazy::new(|| Mutex::new(ReassemblyTracker::new()));

/// Simple in-memory fragment reassembly tracker
///
/// In a full implementation this would use the ReassemblyEngine from
/// fish_11::fcep2::fragmentation. For the test bot we delegate to the DLL
/// via `FiSH11_FCEP2_ProcessMessage` for actual reassembly, and keep a
/// lightweight tracking here for logging/debug.
struct ReassemblyTracker {
    assemblies: std::collections::HashMap<String, FragmentAssembly>,
}

struct FragmentAssembly {
    object_id: [u8; 16],
    kind: char,
    count: u16,
    received: Vec<bool>,
    created_at: i64,
}

impl ReassemblyTracker {
    fn new() -> Self {
        Self { assemblies: std::collections::HashMap::new() }
    }

    fn purge_expired(&mut self) {
        let now = Utc::now().timestamp();
        self.assemblies.retain(|_, a| now - a.created_at < 120);
    }
}

/// Handle an incoming IRC message, routing FCEP-2 envelopes appropriately.
///
/// Per §9.3: FCEP-2 control traffic uses NOTICE; MLS application/proposal/commit
/// messages use PRIVMSG to the group channel.
pub async fn handle_irc_message(
    client: &Client,
    store: &EncryptedStore,
    bridge: &DllBridge,
    config: &AppConfig,
    message: &Message,
) {
    let source_nick = match message.source_nickname() {
        Some(nick) => nick.to_string(),
        None => return,
    };

    // §6.2: skip our own messages
    if source_nick.eq_ignore_ascii_case(client.current_nickname()) {
        return;
    }

    let (target, text) = match &message.command {
        Command::PRIVMSG(target, text) |
        Command::NOTICE(target, text) => (target.clone(), text.clone()),
        Command::JOIN(channel, _, _) => {
            deliver_pending_welcomes(client, store, config, &source_nick, channel).await;
            return;
        }
        _ => return,
    };

    let trimmed = text.trim();
    if !trimmed.starts_with("+FCEP2 ") {
        return;
    }

    if let Err(e) = process_fcep2_line(client, store, bridge, config, &source_nick, &target, trimmed).await {
        warn!("FCEP-2 processing error from {}: {}", source_nick, e);
    }
}

/// Deliver pending Welcomes when a user joins a channel (§13.1, §13.2)
async fn deliver_pending_welcomes(
    client: &Client,
    store: &EncryptedStore,
    config: &AppConfig,
    nick: &str,
    _channel: &str,
) {
    let key = format!("welcome:{}", nick.to_lowercase());
    match store.get("welcomes", key.as_bytes()).await {
        Ok(Some(data)) => {
            if let Ok(welcomes) = serde_json::from_slice::<Vec<serde_json::Value>>(&data) {
                let rate = config.mls.rate_limit_per_sec.max(1);
                let delay_ms = (1000.0 / rate as f64).ceil() as u64;

                for (i, welcome) in welcomes.iter().enumerate() {
                    if i > 0 {
                        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                    }
                    if let (Some(gid), Some(payload)) = (
                        welcome.get("group_id").and_then(|v| v.as_str()),
                        welcome.get("payload").and_then(|v| v.as_str()),
                    ) {
                        let envelope = format!("+FCEP2 W {} {}", gid, payload);
                        if let Err(e) = client.send_notice(nick, &envelope) {
                            error!("Failed to deliver Welcome to {}: {}", nick, e);
                            return;
                        }
                    }
                }
                // Remove delivered welcomes
                let _ = store.delete("welcomes", key.as_bytes()).await;
                info!("Delivered {} Welcome(s) to {}", welcomes.len(), nick);
            }
        }
        Ok(None) => {}
        Err(e) => warn!("Failed to read pending welcomes: {}", e),
    }
}

/// Parse and route a `+FCEP2` line (§8, §9, §10)
async fn process_fcep2_line(
    client: &Client,
    store: &EncryptedStore,
    bridge: &DllBridge,
    config: &AppConfig,
    source_nick: &str,
    target: &str,
    line: &str,
) -> Result<()> {
    // Delegate to DLL for actual MLS processing (§20.3 API)
    let dll_input = format!("{} {} {}", source_nick, target, line);
    let dll_result = bridge.call_dll_fn("FiSH11_FCEP2_ProcessMessage", &dll_input);

    // Also handle relay-level operations for non-MLS-aware envelopes
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 4 {
        let kind = parts[1];
        let target_id = parts[2];
        let payload = parts[3..].join(" ");

        match kind {
            "K" => {
                // §9.2: KeyPackage received
                store.put(
                    "key_packages",
                    format!("kp:{}:{}", target_id, source_nick).as_bytes(),
                    serde_json::json!({
                        "device_id": target_id,
                        "nickname": source_nick,
                        "payload": payload,
                        "received_at": Utc::now().to_rfc3339(),
                    }).to_string().as_bytes(),
                ).await?;
                info!("Stored KeyPackage for device {}", target_id);

                // §9.2: Send X acknowledgement
                let ack = format!("+FCEP2 X {} KP_STORED:{}",
                    target_id, URL_SAFE_NO_PAD.encode(source_nick.as_bytes()));
                client.send_notice(source_nick, &ack)?;
            }
            "W" => {
                // §13.1: Welcome received — store for delivery on JOIN
                let key = format!("welcome:{}", source_nick.to_lowercase());
                let existing = store.get("welcomes", key.as_bytes()).await?
                    .and_then(|d| serde_json::from_slice::<Vec<serde_json::Value>>(&d).ok())
                    .unwrap_or_default();

                let mut welcomes = existing;
                welcomes.push(serde_json::json!({
                    "group_id": target_id,
                    "payload": payload,
                }));

                store.put(
                    "welcomes", key.as_bytes(),
                    serde_json::to_vec(&welcomes)?.as_slice(),
                ).await?;
                info!("Stored Welcome for {} (group {})", source_nick, target_id);
            }
            "C" => {
                // §15.2: Commit logged for sync history
                let epoch = extract_epoch_from_dll(&dll_result);
                store.put(
                    "commit_logs",
                    format!("commit:{}:{}", target_id, epoch).as_bytes(),
                    serde_json::json!({
                        "group_id": target_id,
                        "epoch": epoch,
                        "payload": payload,
                        "source": source_nick,
                        "received_at": Utc::now().to_rfc3339(),
                    }).to_string().as_bytes(),
                ).await?;
            }
            "R" => {
                // §18.2: Request (KP or SYNC)
                handle_request(client, store, source_nick, target_id, &payload).await?;
            }
            "S" => {
                debug!("Sync object received for group {}", target_id);
            }
            "X" => {
                debug!("ACK from {}: {}", source_nick, payload);
            }
            _ => {}
        }
    }

    // Log the DLL result for diagnostics
    match dll_result {
        Ok(output) => debug!("DLL ProcessMessage result: {}", output),
        Err(e) => warn!("DLL ProcessMessage warning (non-fatal): {}", e),
    }

    Ok(())
}

/// Handle a backlog TCP message for out-of-band MLS operations
pub async fn handle_backlog_message(
    store: &EncryptedStore,
    msg: &BacklogMessage,
) {
    match msg {
        BacklogMessage::KeyPackage { device_id, keypackage_b64 } => {
            store.put(
                "key_packages",
                format!("kp_backlog:{}", device_id).as_bytes(),
                serde_json::json!({
                    "device_id": device_id,
                    "payload": keypackage_b64,
                    "source": "backlog",
                    "received_at": Utc::now().to_rfc3339(),
                }).to_string().as_bytes(),
            ).await.ok();
            info!("Backlog: stored KeyPackage for device {}", device_id);
        }
        BacklogMessage::Welcome { device_id, group_id_b64, welcome_b64 } => {
            let key = format!("welcome:{}", device_id.to_lowercase());
            let existing = store.get("welcomes", key.as_bytes()).await.ok()
                .flatten()
                .and_then(|d| serde_json::from_slice::<Vec<serde_json::Value>>(&d).ok())
                .unwrap_or_default();

            let mut welcomes = existing;
            welcomes.push(serde_json::json!({
                "group_id": group_id_b64,
                "payload": welcome_b64,
            }));

            store.put(
                "welcomes", key.as_bytes(),
                serde_json::to_vec(&welcomes).unwrap_or_default().as_slice(),
            ).await.ok();
            info!("Backlog: stored Welcome for device {}", device_id);
        }
        BacklogMessage::Commit { group_id_b64, epoch, .. } => {
            debug!("Backlog: Commit for group {} epoch {}", group_id_b64, epoch);
        }
        _ => {}
    }
}

/// Extract MLS epoch from DLL result for Commit logging
fn extract_epoch_from_dll(dll_result: &Result<String>) -> u64 {
    match dll_result {
        Ok(s) if s.contains("epoch=") => {
            if let Some(epoch_str) = s.split("epoch=").nth(1) {
                if let Some(num) = epoch_str.split_whitespace().next() {
                    return num.parse().unwrap_or(0);
                }
            }
            0
        }
        _ => 0,
    }
}

/// Handle `R` request envelopes (KeyPackage requests, Sync requests)
async fn handle_request(
    client: &Client,
    store: &EncryptedStore,
    source_nick: &str,
    target_id: &str,
    payload: &str,
) -> Result<()> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(());
    }

    match parts[0] {
        "KP" => {
            // §11.2: KeyPackage request
            let query = if parts.len() > 1 { parts[1] } else { source_nick };
            let key = format!("kp:{}:*", query);

            // Scan for matching KeyPackage
            let results = store.scan("key_packages").await?;
            for (_, value) in results {
                if let Ok(kp) = serde_json::from_slice::<serde_json::Value>(&value) {
                    if kp.get("device_id").and_then(|v| v.as_str()) == Some(query)
                        || kp.get("nickname").and_then(|v| v.as_str()) == Some(query)
                    {
                        if let Some(payload_b64) = kp.get("payload").and_then(|v| v.as_str()) {
                            // §9.2: K envelope
                            let resp = format!("+FCEP2 K {} {}", query, payload_b64);
                            client.send_notice(source_nick, &resp)?;
                            info!("Served KeyPackage to {} for device {}", source_nick, query);
                            return Ok(());
                        }
                    }
                }
            }

            // Not found: send NACK (§9.2)
            let nack = format!("+FCEP2 X {} {}",
                target_id, URL_SAFE_NO_PAD.encode(b"ERR_KP_UNAVAILABLE"));
            client.send_notice(source_nick, &nack)?;
        }
        "SYNC" => {
            // §18.2: Sync request
            if parts.len() >= 3 {
                let group_id_hex = parts[1];
                let known_epoch: u64 = parts[2].parse().unwrap_or(0);

                let results = store.scan("commit_logs").await?;
                let mut count = 0u64;
                for (_, value) in results {
                    if let Ok(commit) = serde_json::from_slice::<serde_json::Value>(&value) {
                        let is_match = commit.get("group_id")
                            .and_then(|v| v.as_str()) == Some(group_id_hex);
                        let epoch_gt = commit.get("epoch")
                            .and_then(|v| v.as_u64()).unwrap_or(0) > known_epoch;

                        if is_match && epoch_gt {
                            if let Some(payload) = commit.get("payload").and_then(|v| v.as_str()) {
                                let sync_line = format!("+FCEP2 S {} {}", group_id_hex, payload);
                                client.send_notice(source_nick, &sync_line)?;
                                count += 1;
                            }
                        }
                    }
                }
                info!("Served {} sync commits to {}", count, source_nick);
            }
        }
        _ => {}
    }

    Ok(())
}
