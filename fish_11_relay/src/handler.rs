//! FCEP-2 Asynchronous Message Handler
//!
//! Processes incoming IRC PRIVMSG and NOTICE lines, executing FCEP-2 relay operations.
//! Implements RFC Sections 8–13, 15, 18 (see docs/FCEP-2_DRAFT.txt).

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fish_11::fcep2::envelope::FcepEnvelope;
use fish_11::fcep2::fragmentation::ReassemblyEngine;
use fish_11::fcep2::types::EnvelopeKind;
use irc::client::prelude::*;
use tracing::{error, info, trace, warn};

use crate::config::AppConfig;
use crate::store::RelayStore;

/// Global fragment reassembly engine (per §10.3): 32 concurrent per source, 120s timeout, 1 MiB limit
static REASSEMBLY: OnceLock<Mutex<ReassemblyEngine>> = OnceLock::new();

fn reassembly_engine() -> &'static Mutex<ReassemblyEngine> {
    REASSEMBLY.get_or_init(|| Mutex::new(ReassemblyEngine::new()))
}

/// Process an incoming IRC message
pub async fn handle_irc_message(
    client: &Client,
    store: &RelayStore,
    config: &AppConfig,
    message: &Message,
) {
    let source_nick = match message.source_nickname() {
        Some(nick) => nick,
        None => return,
    };

    // §6.2: IRC nicknames are unauthenticated transport metadata : do NOT treat as identity
    if source_nick.eq_ignore_ascii_case(client.current_nickname()) {
        return;
    }

    match &message.command {
        Command::PRIVMSG(target, text) | Command::NOTICE(target, text) => {
            let trimmed = text.trim();
            if trimmed.starts_with("+FCEP2 ") {
                if let Err(e) =
                    process_fcep2_line(client, store, config, source_nick, target, trimmed).await
                {
                    warn!("Error processing FCEP2 from {}: {}", source_nick, e);
                }
            }
        }
        Command::JOIN(channel, _, _) => {
            deliver_pending_welcomes(client, store, config, source_nick, channel).await;
        }
        _ => {}
    }
}

/// Deliver pending Welcomes with rate limiting to avoid IRC kicks
///
/// Uses `rate_limit_per_sec` from config (§8.4). Delivered Welcomes are removed from the store.
async fn deliver_pending_welcomes(
    client: &Client,
    store: &RelayStore,
    config: &AppConfig,
    nick: &str,
    _channel: &str,
) {
    let pending = store.get_pending_welcomes(nick).await;
    let count = pending.len();
    if count == 0 {
        return;
    }

    // §8.4: use configured rate limit (minimum 100ms between messages)
    let rate = config.relay.rate_limit_per_sec.max(1);
    let delay_ms = (1000.0 / rate as f64).ceil() as u64;

    for (i, welcome) in pending.into_iter().enumerate() {
        if i > 0 {
            tokio::time::sleep(Duration::from_millis(delay_ms)).await;
        }
        let envelope = format!("+FCEP2 W {} {}", welcome.group_id_hex, welcome.payload_b64);
        if let Err(e) = client.send_notice(nick, &envelope) {
            error!("Failed to deliver Welcome to {}: {}", nick, e);
            return;
        }
    }

    info!("Delivered {} stored Welcome(s) to {}", count, nick);
}

/// Parse and route a `+FCEP2` line
async fn process_fcep2_line(
    client: &Client,
    store: &RelayStore,
    config: &AppConfig,
    source_nick: &str,
    target: &str,
    line: &str,
) -> anyhow::Result<()> {
    let envelope = FcepEnvelope::parse(line)?;

    match envelope {
        FcepEnvelope::Standard { kind, target_id, payload } => {
            let target_b64 = URL_SAFE_NO_PAD.encode(&target_id);
            let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);

            handle_standard_envelope(
                client,
                store,
                config,
                source_nick,
                target,
                kind,
                target_b64,
                payload_b64,
                payload,
            )
            .await?;
        }
        FcepEnvelope::Fragment { object_id, index, count, kind, fragment } => {
            // §10: Relay MUST support fragment reassembly for every FCEP-2 object type (§8.4)
            // §10.3: max 32 concurrent reassemblies per source, 120s timeout, 1 MiB limit
            if object_id.len() != 16 {
                warn!(
                    "Fragment with invalid object_id length {} from {}",
                    object_id.len(),
                    source_nick
                );
                return Ok(());
            }
            let mut oid = [0u8; 16];
            oid.copy_from_slice(&object_id);

            let source_key = source_nick.to_string();
            let result = {
                let mut engine = reassembly_engine().lock().unwrap();
                engine.process_fragment(&source_key, &[], oid, index, count, kind, fragment)?
            };

            match result {
                Some(FcepEnvelope::Standard { kind, target_id, payload }) => {
                    info!("Reassembled {} fragment(s) for {:?} from {}", count, kind, source_nick);
                    let target_b64 = URL_SAFE_NO_PAD.encode(&target_id);
                    let payload_b64 = URL_SAFE_NO_PAD.encode(&payload);
                    handle_standard_envelope(
                        client,
                        store,
                        config,
                        source_nick,
                        target,
                        kind,
                        target_b64,
                        payload_b64,
                        payload,
                    )
                    .await?;
                }
                Some(other) => {
                    // ReassemblyEngine only returns Standard envelopes on completion,
                    // but handle unexpected variants gracefully
                    warn!("Unexpected reassembly result: {:?}", other);
                }
                None => {
                    trace!(
                        "Fragment {}/{} from {} buffered for reassembly",
                        index + 1,
                        count,
                        source_nick
                    );
                }
            }
        }
    }

    Ok(())
}

/// Route a fully assembled standard envelope to the appropriate handler
async fn handle_standard_envelope(
    client: &Client,
    store: &RelayStore,
    config: &AppConfig,
    source_nick: &str,
    target: &str,
    kind: EnvelopeKind,
    target_b64: String,
    payload_b64: String,
    raw_payload: Vec<u8>,
) -> anyhow::Result<()> {
    match kind {
        EnvelopeKind::KeyPackage => {
            // §9.2: device-id is the base64url-encoded target_id, not the IRC nickname
            // §6.2: nicknames are unauthenticated transport metadata : device_id is the identity
            store
                .store_key_package(
                    target_b64.clone(),
                    source_nick.to_string(),
                    payload_b64,
                    config.relay.max_keypackages_per_device,
                )
                .await;

            // §9.2: X (ACK) format: +FCEP2 X <request-id> <payload>
            // request-id is base64url of the echoed device_id
            let ack_payload = URL_SAFE_NO_PAD.encode(format!("KP_STORED:{}", source_nick));
            let ack = format!("+FCEP2 X {} {}", target_b64, ack_payload);
            let _ = client.send_notice(source_nick, &ack);
        }
        EnvelopeKind::Welcome => {
            store.store_welcome(target.to_string(), target_b64, payload_b64).await;
            info!("Stored Welcome from {}", source_nick);
        }
        EnvelopeKind::Commit => {
            // §15.2 / §15.5: epoch MUST be extracted from the MLS Commit object
            // The relay MUST NOT invent an independent FCEP epoch counter
            let epoch = extract_epoch_from_raw_payload(&raw_payload).unwrap_or_else(|| {
                warn!(
                    "Failed to extract epoch from Commit payload for group {}; using 0",
                    target_b64
                );
                0
            });

            store
                .log_commit(target_b64, epoch, payload_b64, config.relay.commit_history_limit)
                .await;
        }
        EnvelopeKind::Request => {
            handle_request(client, store, source_nick, &target_b64, &raw_payload).await?;
        }
        EnvelopeKind::Ack => {
            // §13.3: ACK for Welcome consumption : log but the Welcome was already
            // removed from the store upon JOIN delivery (get_pending_welcomes removes on read)
            let ack_body = String::from_utf8_lossy(&raw_payload);
            trace!("Received ACK from {}: {}", source_nick, ack_body);
        }
        EnvelopeKind::Sync => {
            trace!("Received Sync object for group {}", target_b64);
        }
        EnvelopeKind::Application | EnvelopeKind::Proposal => {
            trace!("Relay pass-through for {:?} envelope", kind);
        }
    }

    Ok(())
}

/// Attempt to extract the MLS epoch from a raw Commit message
///
/// Uses OpenMLS to deserialize the TLS-serialized MLS message and read the
/// epoch. Returns `None` if parsing fails (payload may be non-MLS or encrypted
/// in a way the relay cannot decode).
fn extract_epoch_from_raw_payload(raw: &[u8]) -> Option<u64> {
    fish_11::fcep2::openmls_adapter::extract_commit_epoch(raw)
}

/// Handle `R` request envelopes
async fn handle_request(
    client: &Client,
    store: &RelayStore,
    source_nick: &str,
    target_id_b64: &str,
    payload: &[u8],
) -> anyhow::Result<()> {
    let req_str = String::from_utf8_lossy(payload);
    let parts: Vec<&str> = req_str.split_whitespace().collect();

    if parts.is_empty() {
        return Ok(());
    }

    match parts[0] {
        "KP" => {
            // §6.2 / §23.9: device_id (128-bit CSPRNG) is the identity, NOT the nickname
            // Query by device_id first, then fall back to nickname only as transport hint
            let target_query = if parts.len() > 1 { parts[1] } else { source_nick };
            if let Some(kp) = store.get_key_package(target_query).await {
                // §9.2: K envelope format: +FCEP2 K <device-id-b64> <payload-b64>
                // device_id_hex should be base64url; store already encodes it as URL_SAFE_NO_PAD
                let resp = format!("+FCEP2 K {} {}", kp.device_id_b64, kp.payload_b64);
                client.send_notice(source_nick, &resp)?;
                info!("Served KeyPackage to {}", source_nick);
            } else {
                // §9.2: NACK format: +FCEP2 X <request-id> <payload>
                let err_resp = format!(
                    "+FCEP2 X {} {}",
                    target_id_b64,
                    URL_SAFE_NO_PAD.encode("ERR_KP_UNAVAILABLE")
                );
                client.send_notice(source_nick, &err_resp)?;
            }
        }
        "SYNC" => {
            if parts.len() >= 3 {
                let group_id_hex = parts[1];
                let known_epoch: u64 = parts[2].parse().unwrap_or(0);

                let commits = store.get_sync_commits(group_id_hex, known_epoch).await;
                for commit in &commits {
                    let sync_line =
                        format!("+FCEP2 S {} {}", commit.group_id_hex, commit.payload_b64);
                    client.send_notice(source_nick, &sync_line)?;
                }
                info!("Served {} sync commits to {}", commits.len(), source_nick);
            }
        }
        _ => {}
    }

    Ok(())
}
