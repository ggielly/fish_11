//! FCEP-2 Transport Layer: Envelope Parsing, Fragmentation & Reassembly
//!
//! This module handles the IRC wire format ONLY. All MLS objects are opaque
//! byte arrays : the transport layer never inspects their internal structure.
//!
//! IRC line budget is computed precisely per command and destination,
//! following RFC Section 8.4 and the FCEP-2_DRAFT.txt line budget rules.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;

use super::types::EnvelopeKind;
use crate::unified_error::DllError;

// ===== Constants (RFC Section 8.4 / 10.3) ──────────────────────────

/// Prefix marker for all FCEP-2 payload lines
pub const FCEP2_PREFIX: &str = "+FCEP2 ";

/// Maximum IRC line length (RFC 1459)
pub const IRC_MAX_LINE: usize = 512;

/// Maximum total reassembled object size: 1 MiB (RFC Section 10.3)
pub const MAX_OBJECT_BYTES: usize = 1024 * 1024;

/// Maximum number of fragments per logical object
pub const MAX_FRAGMENTS: usize = 256;

/// Maximum concurrent reassemblies per remote source
pub const MAX_ASSEMBLIES_PER_SOURCE: usize = 32;

/// Maximum global concurrent reassemblies (DoS protection)
pub const MAX_ASSEMBLIES_GLOBAL: usize = 256;

/// Maximum total memory budget for all reassemblies: 8 MiB
pub const MAX_ASSEMBLY_BYTES_GLOBAL: usize = 8 * 1024 * 1024;

/// Reassembly timeout: 120 seconds
pub const ASSEMBLY_TTL: Duration = Duration::from_secs(120);

// ===== Envelope Types ──────────────────────────────────────────────

/// Parsed FCEP-2 Envelope
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcepEnvelope {
    /// Standard object envelope: kind, target ID (Group ID or Device/Request ID), raw binary payload
    Standard { kind: EnvelopeKind, target_id: Vec<u8>, payload: Vec<u8> },
    /// Fragment wrapper envelope (kind 'F'): 16-byte object_id, index, count, target_kind, raw bytes
    Fragment { object_id: [u8; 16], index: u16, count: u16, kind: EnvelopeKind, bytes: Vec<u8> },
}

// ===== IRC Line Budget =====

/// Compute the full wire length of an IRC command with trailing payload.
///
/// Format: `<command> <destination> :<trailing>\r\n`
/// This is what the CLIENT sends to the SERVER.
pub fn irc_wire_len(command: &str, destination: &str, trailing: &str) -> usize {
    command.len() + 1 + destination.len() + 2 + trailing.len() + 2
}

/// Validate that an FCEP-2 line fits within the IRC budget for a given command and destination.
pub fn check_line_budget(command: &str, destination: &str, line: &str) -> Result<(), DllError> {
    let wire_len = irc_wire_len(command, destination, line);
    if wire_len > IRC_MAX_LINE {
        return Err(DllError::InvalidInput {
            param: "line_budget".to_string(),
            reason: format!(
                "IRC line exceeds {} octets: {} (cmd={}, dest={})",
                IRC_MAX_LINE, wire_len, command, destination
            ),
        });
    }
    Ok(())
}

// ===== Encode / Decode Helpers ─────────────────────────────────────

/// Decode strict unpadded Base64Url string (RFC 4648 Section 5)
fn decode_unpadded_b64(input: &str) -> Result<Vec<u8>, DllError> {
    if input.contains('=') {
        return Err(DllError::InvalidInput {
            param: "base64url".to_string(),
            reason: "Base64Url padding is strictly prohibited".to_string(),
        });
    }
    // Validate characters: alphanumeric, '-', '_'
    if !input.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(DllError::InvalidInput {
            param: "base64url".to_string(),
            reason: "Invalid unpadded base64url character".to_string(),
        });
    }
    URL_SAFE_NO_PAD.decode(input.as_bytes()).map_err(|e| DllError::InvalidInput {
        param: "base64url".to_string(),
        reason: format!("Failed to decode Base64Url: {}", e),
    })
}

// ===== Envelope Encoding ───────────────────────────────────────────

/// Encode a standard FCEP-2 envelope.
///
/// Does NOT check IRC line budget : the caller must use `check_line_budget`
/// or `encode_for_irc` to validate against the actual command and destination.
pub fn encode_standard(
    kind: EnvelopeKind,
    target_id: &[u8],
    payload: &[u8],
) -> Result<String, DllError> {
    if payload.is_empty() || payload.len() > MAX_OBJECT_BYTES {
        return Err(DllError::InvalidInput {
            param: "payload".to_string(),
            reason: "Payload must be non-empty and ≤ 1 MiB".to_string(),
        });
    }
    if kind.is_group_scoped() && target_id.len() < 16 {
        return Err(DllError::InvalidInput {
            param: "group_id".to_string(),
            reason: "MLS Group ID must be at least 16 bytes".to_string(),
        });
    }
    Ok(format!(
        "{}{} {} {}",
        FCEP2_PREFIX,
        kind.to_char(),
        URL_SAFE_NO_PAD.encode(target_id),
        URL_SAFE_NO_PAD.encode(payload)
    ))
}

/// Encode a standard envelope and validate it fits within the IRC line budget.
pub fn encode_for_irc(
    command: &str,
    destination: &str,
    kind: EnvelopeKind,
    target_id: &[u8],
    payload: &[u8],
) -> Result<String, DllError> {
    let line = encode_standard(kind, target_id, payload)?;
    check_line_budget(command, destination, &line)?;
    Ok(line)
}

// ===== Fragment Encoding ───────────────────────────────────────────

/// Fragment a payload into IRC-safe lines with correct budget calculation.
///
/// Returns a vector of IRC-ready FCEP-2 fragment lines. Each line is guaranteed
/// to fit within the IRC line budget for the given command and destination.
pub fn fragment_for_irc(
    command: &str,
    destination: &str,
    kind: EnvelopeKind,
    target_id: &[u8],
    payload: &[u8],
) -> Result<Vec<String>, DllError> {
    // Try sending as a single standard envelope first
    let standard = encode_standard(kind, target_id, payload)?;
    if irc_wire_len(command, destination, &standard) <= IRC_MAX_LINE {
        return Ok(vec![standard]);
    }

    // Must fragment. Validate object size first.
    if payload.len() > MAX_OBJECT_BYTES {
        return Err(DllError::InvalidInput {
            param: "payload".to_string(),
            reason: format!("Payload exceeds max object size of {} bytes", MAX_OBJECT_BYTES),
        });
    }

    // Generate a random 16-byte object ID for this fragmentation session
    let mut object_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut object_id);
    let oid_b64 = URL_SAFE_NO_PAD.encode(object_id);

    // Calculate the maximum raw chunk size that fits in IRC budget
    // Fragment overhead: "+FCEP2 F {oid_b64} {index} {count} {kind} {data_b64}"
    // We use max index/count digits (5 digits for "65535") to compute worst-case overhead
    let fragment_overhead = FCEP2_PREFIX.len() + 1 + oid_b64.len() + 1 + 5 + 1 + 5 + 1 + 1 + 1;
    let max_line_for_fragment = IRC_MAX_LINE.saturating_sub(irc_wire_len(command, destination, ""));
    let available_for_data_b64 = max_line_for_fragment.saturating_sub(fragment_overhead);
    // Base64url output is ceil(n * 4/3). Choose a safe raw chunk size.
    let raw_chunk = ((available_for_data_b64 * 3) / 4).min(256);
    if raw_chunk == 0 {
        return Err(DllError::InvalidInput {
            param: "fragment".to_string(),
            reason: "Destination too long: no room for fragment data in IRC line".to_string(),
        });
    }

    let count = payload.len().div_ceil(raw_chunk);
    if count == 0 || count > MAX_FRAGMENTS {
        return Err(DllError::InvalidInput {
            param: "fragment_count".to_string(),
            reason: format!("Payload requires {} fragments (max {})", count, MAX_FRAGMENTS),
        });
    }

    let mut out = Vec::with_capacity(count);
    for (i, chunk) in payload.chunks(raw_chunk).enumerate() {
        let line = format!(
            "{}F {} {} {} {} {}",
            FCEP2_PREFIX,
            oid_b64,
            i,
            count,
            kind.to_char(),
            URL_SAFE_NO_PAD.encode(chunk)
        );
        // Final budget check for each fragment line
        if irc_wire_len(command, destination, &line) > IRC_MAX_LINE {
            return Err(DllError::InvalidInput {
                param: "fragment".to_string(),
                reason: format!("Fragment {} exceeds IRC line budget", i),
            });
        }
        out.push(line);
    }
    Ok(out)
}

// ===== Envelope Parsing ────────────────────────────────────────────

/// Parse a complete FCEP-2 line (content after ` :` prefix) into an envelope.
pub fn parse_envelope(input: &str) -> Result<FcepEnvelope, DllError> {
    let trimmed = input.trim();
    if !trimmed.starts_with(FCEP2_PREFIX) {
        return Err(DllError::InvalidInput {
            param: "envelope".to_string(),
            reason: "Missing +FCEP2 prefix".to_string(),
        });
    }

    let body = &trimmed[FCEP2_PREFIX.len()..];
    let parts: Vec<&str> = body.split_whitespace().collect();

    if parts.is_empty() || parts[0].len() != 1 {
        return Err(DllError::InvalidInput {
            param: "envelope_type".to_string(),
            reason: "Type token must be exactly 1 character".to_string(),
        });
    }

    let type_char = parts[0].chars().next().unwrap();

    if type_char == 'F' {
        // Fragment: +FCEP2 F <object-id> <index> <count> <kind> <data>
        if parts.len() != 6 {
            return Err(DllError::InvalidInput {
                param: "fragment".to_string(),
                reason: format!("Expected exactly 6 fields, got {}", parts.len()),
            });
        }

        // Object ID: exactly 16 bytes
        let raw_id = decode_unpadded_b64(parts[1])?;
        if raw_id.len() != 16 {
            return Err(DllError::InvalidInput {
                param: "fragment_object_id".to_string(),
                reason: "Object ID must be exactly 16 bytes".to_string(),
            });
        }
        let mut object_id = [0u8; 16];
        object_id.copy_from_slice(&raw_id);

        let index: u16 = parts[2].parse().map_err(|_| DllError::InvalidInput {
            param: "fragment_index".to_string(),
            reason: "Invalid index".to_string(),
        })?;
        let count: u16 = parts[3].parse().map_err(|_| DllError::InvalidInput {
            param: "fragment_count".to_string(),
            reason: "Invalid count".to_string(),
        })?;

        if count == 0 || count as usize > MAX_FRAGMENTS {
            return Err(DllError::InvalidInput {
                param: "fragment_count".to_string(),
                reason: format!("Count must be 1-{}", MAX_FRAGMENTS),
            });
        }
        if index >= count {
            return Err(DllError::InvalidInput {
                param: "fragment_index".to_string(),
                reason: "Index must be < count".to_string(),
            });
        }

        // Kind token must be exactly 1 character
        if parts[4].len() != 1 {
            return Err(DllError::InvalidInput {
                param: "fragment_kind".to_string(),
                reason: "Kind must be exactly 1 character".to_string(),
            });
        }
        let kind_char = parts[4].chars().next().unwrap();
        if kind_char == 'F' {
            return Err(DllError::InvalidInput {
                param: "fragment_kind".to_string(),
                reason: "Fragment target kind cannot be 'F'".to_string(),
            });
        }
        let kind = EnvelopeKind::from_char(kind_char).map_err(|e| DllError::InvalidInput {
            param: "fragment_kind".to_string(),
            reason: e,
        })?;

        let bytes = decode_unpadded_b64(parts[5])?;
        if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
            return Err(DllError::InvalidInput {
                param: "fragment_data".to_string(),
                reason: "Fragment must be non-empty and ≤ 1 MiB".to_string(),
            });
        }

        Ok(FcepEnvelope::Fragment { object_id, index, count, kind, bytes })
    } else {
        // Standard: +FCEP2 <kind> <target-id> <payload>
        if parts.len() != 3 {
            return Err(DllError::InvalidInput {
                param: "envelope".to_string(),
                reason: format!("Expected exactly 3 fields, got {}", parts.len()),
            });
        }

        let kind = EnvelopeKind::from_char(type_char).map_err(|e| DllError::InvalidInput {
            param: "envelope_kind".to_string(),
            reason: e,
        })?;

        let target_id = decode_unpadded_b64(parts[1])?;
        let payload = decode_unpadded_b64(parts[2])?;

        if kind.is_group_scoped() && target_id.len() < 16 {
            return Err(DllError::InvalidInput {
                param: "group_id".to_string(),
                reason: "MLS Group ID must be at least 16 bytes".to_string(),
            });
        }
        if payload.is_empty() || payload.len() > MAX_OBJECT_BYTES {
            return Err(DllError::InvalidInput {
                param: "payload".to_string(),
                reason: "Payload must be non-empty and ≤ 1 MiB".to_string(),
            });
        }

        Ok(FcepEnvelope::Standard { kind, target_id, payload })
    }
}

// ===== Reassembly Engine =====

/// Assembly key includes source identity, object ID, and kind to isolate
/// different object types even if they share the same object ID.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AssemblyKey {
    /// Transport source identifier (IRC nick). Advisory only : never use for MLS identity.
    transport_source: String,
    object_id: [u8; 16],
    kind: EnvelopeKind,
}

struct Assembly {
    count: u16,
    received: Vec<Option<Vec<u8>>>,
    byte_count: usize,
    started: Instant,
}

/// Fragment reassembly engine with DoS protection bounds.
pub struct ReassemblyEngine {
    assemblies: HashMap<AssemblyKey, Assembly>,
    bytes_total: usize,
}

impl ReassemblyEngine {
    pub fn new() -> Self {
        Self { assemblies: HashMap::new(), bytes_total: 0 }
    }

    /// Remove expired assemblies (> 120s).
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        self.assemblies.retain(|_, a| now.duration_since(a.started) < ASSEMBLY_TTL);
        self.bytes_total = self.assemblies.values().map(|a| a.byte_count).sum();
    }

    /// Process an incoming fragment.
    ///
    /// Returns `Ok(Some((kind, reassembled_payload)))` when assembly completes.
    /// The assembly entry is removed upon completion.
    pub fn process_fragment(
        &mut self,
        source: &str,
        fragment: FcepEnvelope,
    ) -> Result<Option<(EnvelopeKind, Vec<u8>)>, DllError> {
        self.cleanup();

        let FcepEnvelope::Fragment { object_id, index, count, kind, bytes } = fragment else {
            return Err(DllError::InvalidInput {
                param: "fragment".to_string(),
                reason: "Expected fragment envelope".to_string(),
            });
        };

        let key = AssemblyKey { transport_source: source.to_owned(), object_id, kind };

        if !self.assemblies.contains_key(&key) {
            // Check global limit
            if self.assemblies.len() >= MAX_ASSEMBLIES_GLOBAL {
                return Err(DllError::InvalidInput {
                    param: "assembly".to_string(),
                    reason: "Exceeded global max concurrent reassemblies".to_string(),
                });
            }
            // Check per-source limit
            let per_source =
                self.assemblies.keys().filter(|k| k.transport_source == source).count();
            if per_source >= MAX_ASSEMBLIES_PER_SOURCE {
                return Err(DllError::InvalidInput {
                    param: "assembly".to_string(),
                    reason: format!(
                        "Exceeded max concurrent assemblies ({}) for source",
                        MAX_ASSEMBLIES_PER_SOURCE
                    ),
                });
            }

            self.assemblies.insert(
                key.clone(),
                Assembly {
                    count,
                    received: vec![None; count as usize],
                    byte_count: 0,
                    started: Instant::now(),
                },
            );
        }

        let a = self.assemblies.get_mut(&key).unwrap();
        if a.count != count || index >= count {
            return Err(DllError::InvalidInput {
                param: "fragment".to_string(),
                reason: "Fragment metadata mismatch".to_string(),
            });
        }

        if a.received[index as usize].is_none() {
            // Check cumulative size limits BEFORE storing
            if a.byte_count + bytes.len() > MAX_OBJECT_BYTES {
                return Err(DllError::InvalidInput {
                    param: "fragment".to_string(),
                    reason: "Reassembled object would exceed 1 MiB limit".to_string(),
                });
            }
            if self.bytes_total + bytes.len() > MAX_ASSEMBLY_BYTES_GLOBAL {
                return Err(DllError::InvalidInput {
                    param: "fragment".to_string(),
                    reason: "Global assembly memory budget exceeded".to_string(),
                });
            }
            a.byte_count += bytes.len();
            self.bytes_total += bytes.len();
            a.received[index as usize] = Some(bytes);
        }

        // Check if complete
        if a.received.iter().any(|s| s.is_none()) {
            return Ok(None);
        }

        // Complete! Remove assembly and return data
        let a = self.assemblies.remove(&key).unwrap();
        self.bytes_total = self.bytes_total.saturating_sub(a.byte_count);
        let mut whole = Vec::with_capacity(a.byte_count);
        for part in a.received {
            whole.extend_from_slice(&part.expect("complete assembly"));
        }
        Ok(Some((kind, whole)))
    }

    /// Number of active assemblies.
    pub fn active_count(&self) -> usize {
        self.assemblies.len()
    }
}

impl Default for ReassemblyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irc_wire_len() {
        let len = irc_wire_len("PRIVMSG", "#fish11", "+FCEP2 A abcd efgh");
        // "PRIVMSG #fish11 :+FCEP2 A abcd efgh\r\n"
        assert!(len <= IRC_MAX_LINE);
    }

    #[test]
    fn test_standard_roundtrip() {
        let kind = EnvelopeKind::Application;
        let target_id = vec![0x42u8; 16];
        let payload = b"Hello MLS".to_vec();

        let line = encode_standard(kind, &target_id, &payload).unwrap();
        let parsed = parse_envelope(&line).unwrap();

        match parsed {
            FcepEnvelope::Standard { kind: k, target_id: tid, payload: p } => {
                assert_eq!(k, EnvelopeKind::Application);
                assert_eq!(tid, target_id);
                assert_eq!(p, payload);
            }
            _ => panic!("Expected standard envelope"),
        }
    }

    #[test]
    fn test_fragment_roundtrip() {
        let target_id = vec![0x42u8; 16];
        let payload = vec![0xABu8; 1000];

        let lines =
            fragment_for_irc("PRIVMSG", "#fish11", EnvelopeKind::Application, &target_id, &payload)
                .unwrap();
        assert!(lines.len() > 1);

        let mut engine = ReassemblyEngine::new();
        let mut final_result = None;
        for line in &lines {
            let parsed = parse_envelope(line).unwrap();
            let result = engine.process_fragment("test_user", parsed).unwrap();
            if let Some((kind, data)) = result {
                assert_eq!(kind, EnvelopeKind::Application);
                assert_eq!(data, payload);
                final_result = Some(data);
            }
        }
        assert!(final_result.is_some());
    }

    #[test]
    fn test_reject_padded_b64() {
        let result = parse_envelope("+FCEP2 A AQIDBAUGBwgJCgsMDQ4PEA== SGVsbG8=");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_short_gid() {
        let short = URL_SAFE_NO_PAD.encode(&[0u8; 8]);
        let result = parse_envelope(&format!("+FCEP2 A {} dGVzdA", short));
        assert!(result.is_err());
    }

    #[test]
    fn test_fragment_assembly_cleanup_after_completion() {
        let payload = vec![0x42u8; 500];
        let target_id = vec![0x42u8; 16];
        let lines =
            fragment_for_irc("PRIVMSG", "#fish11", EnvelopeKind::Commit, &target_id, &payload)
                .unwrap();

        let mut engine = ReassemblyEngine::new();
        let before = engine.active_count();
        for line in &lines {
            let parsed = parse_envelope(line).unwrap();
            let _ = engine.process_fragment("test", parsed).unwrap();
        }
        // After completion, the assembly must be removed
        assert_eq!(engine.active_count(), before);
    }
}
