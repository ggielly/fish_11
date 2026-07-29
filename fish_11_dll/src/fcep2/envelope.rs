//! FCEP-2 Transport Envelope Parser & Serializer
//!
//! Implements Base64Url (RFC 4648 Section 5 unpadded) parsing and formatting
//! for FCEP-2 envelopes (+FCEP2 <type> <group-id/id> <payload>).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::types::EnvelopeKind;
use crate::unified_error::DllError;

/// Prefix marker for all FCEP-2 payload lines
pub const FCEP2_PREFIX: &str = "+FCEP2 ";

/// Parsed FCEP-2 Envelope
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FcepEnvelope {
    /// Standard object envelope: kind, target ID (Group ID or Device/Request ID), and raw binary payload
    Standard { kind: EnvelopeKind, target_id: Vec<u8>, payload: Vec<u8> },
    /// Fragment wrapper envelope (kind 'F'): object_id, index, count, target_kind, raw fragment payload
    Fragment { object_id: Vec<u8>, index: u16, count: u16, kind: EnvelopeKind, fragment: Vec<u8> },
}

impl FcepEnvelope {
    /// Encode a standard FCEP-2 envelope into printable ASCII string (`+FCEP2 <kind> <target-id> <payload>`)
    pub fn encode_standard(kind: EnvelopeKind, target_id: &[u8], payload: &[u8]) -> String {
        let target_b64 = URL_SAFE_NO_PAD.encode(target_id);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        format!("+FCEP2 {} {} {}", kind.to_char(), target_b64, payload_b64)
    }

    /// Encode a fragment FCEP-2 envelope (`+FCEP2 F <object-id> <index> <count> <kind> <fragment>`)
    pub fn encode_fragment(
        object_id: &[u8; 16],
        index: u16,
        count: u16,
        kind: EnvelopeKind,
        fragment_payload: &[u8],
    ) -> String {
        let obj_b64 = URL_SAFE_NO_PAD.encode(object_id);
        let frag_b64 = URL_SAFE_NO_PAD.encode(fragment_payload);
        format!("+FCEP2 F {} {} {} {} {}", obj_b64, index, count, kind.to_char(), frag_b64)
    }

    /// Parse a line text input into a `FcepEnvelope`
    ///
    /// Strict parsing: requires exactly the correct number of tokens per type,
    /// rejects empty payloads, and validates base64url characters before decoding.
    pub fn parse(input: &str) -> Result<Self, DllError> {
        // FCEP-2 lines always start at the beginning of the trailing parameter.
        // A bare `contains()` check would match chat text. We verify the content
        // starts with the prefix after trimming.
        let trimmed = input.trim();
        if !trimmed.starts_with(FCEP2_PREFIX) || trimmed.len() == FCEP2_PREFIX.len() {
            return Err(DllError::InvalidInput {
                param: "envelope".to_string(),
                reason: "Missing +FCEP2 prefix".to_string(),
            });
        }

        let body = &trimmed[FCEP2_PREFIX.len()..];

        // Reject empty body
        if body.is_empty() {
            return Err(DllError::InvalidInput {
                param: "envelope".to_string(),
                reason: "Empty envelope body".to_string(),
            });
        }

        // Split by ASCII whitespace : strictly, not greedily
        let parts: Vec<&str> = body.split_ascii_whitespace().collect();

        if parts.is_empty() {
            return Err(DllError::InvalidInput {
                param: "envelope".to_string(),
                reason: "Empty envelope body".to_string(),
            });
        }

        // Strict: type token must be exactly 1 character (RFC Section 8.1)
        if parts[0].len() != 1 {
            return Err(DllError::InvalidInput {
                param: "envelope_type".to_string(),
                reason: format!("Type token must be exactly 1 character, got '{}'", parts[0]),
            });
        }

        let type_char = parts[0].chars().next().ok_or_else(|| DllError::InvalidInput {
            param: "envelope".to_string(),
            reason: "Invalid envelope type indicator".to_string(),
        })?;

        if type_char == 'F' {
            // Fragment envelope: +FCEP2 F <object-id> <index> <count> <kind> <fragment>
            // Strict: exactly 6 fields, no extras
            if parts.len() != 6 {
                return Err(DllError::InvalidInput {
                    param: "fragment".to_string(),
                    reason: format!(
                        "Malformed fragment; expected exactly 6 fields, got {}",
                        parts.len()
                    ),
                });
            }

            let obj_id_raw = decode_unpadded_b64(parts[1])?;
            if obj_id_raw.len() != 16 {
                return Err(DllError::InvalidInput {
                    param: "fragment".to_string(),
                    reason: "Fragment object_id must be exactly 16 bytes".to_string(),
                });
            }

            let index: u16 = parts[2].parse().map_err(|_| DllError::InvalidInput {
                param: "fragment_index".to_string(),
                reason: "Invalid fragment index integer".to_string(),
            })?;

            let count: u16 = parts[3].parse().map_err(|_| DllError::InvalidInput {
                param: "fragment_count".to_string(),
                reason: "Invalid fragment count integer".to_string(),
            })?;

            if count == 0 || count > 256 {
                return Err(DllError::InvalidInput {
                    param: "fragment_count".to_string(),
                    reason: "Fragment count must be in range 1..=256".to_string(),
                });
            }

            if index >= count {
                return Err(DllError::InvalidInput {
                    param: "fragment_index".to_string(),
                    reason: "Fragment index must be strictly less than count".to_string(),
                });
            }

            // Strict: kind token must be exactly 1 character
            if parts[4].len() != 1 {
                return Err(DllError::InvalidInput {
                    param: "fragment_kind".to_string(),
                    reason: format!(
                        "Fragment kind must be exactly 1 character, got '{}'",
                        parts[4]
                    ),
                });
            }

            let kind_char = parts[4].chars().next().unwrap();

            if kind_char == 'F' {
                return Err(DllError::InvalidInput {
                    param: "fragment_kind".to_string(),
                    reason: "Fragment target kind cannot be 'F'".to_string(),
                });
            }

            let kind = EnvelopeKind::from_char(kind_char).map_err(|reason| {
                DllError::InvalidInput { param: "fragment_kind".to_string(), reason }
            })?;

            let fragment = decode_unpadded_b64(parts[5])?;

            // Reject empty fragments (RFC Section 10.2: fragment must be non-empty)
            if fragment.is_empty() {
                return Err(DllError::InvalidInput {
                    param: "fragment_data".to_string(),
                    reason: "Fragment payload must be non-empty".to_string(),
                });
            }

            Ok(FcepEnvelope::Fragment { object_id: obj_id_raw, index, count, kind, fragment })
        } else {
            // Standard envelope: +FCEP2 <kind> <target-id> <payload>
            // Strict: exactly 3 fields, no extras
            if parts.len() != 3 {
                return Err(DllError::InvalidInput {
                    param: "envelope".to_string(),
                    reason: format!(
                        "Malformed standard envelope; expected exactly 3 fields, got {}",
                        parts.len()
                    ),
                });
            }

            let kind = EnvelopeKind::from_char(type_char).map_err(|reason| {
                DllError::InvalidInput { param: "envelope_kind".to_string(), reason }
            })?;

            let target_id = decode_unpadded_b64(parts[1])?;
            let payload = decode_unpadded_b64(parts[2])?;

            // Validation per RFC Section 8.2
            if (kind == EnvelopeKind::Application
                || kind == EnvelopeKind::Proposal
                || kind == EnvelopeKind::Commit)
                && target_id.len() < 16
            {
                return Err(DllError::InvalidInput {
                    param: "group_id".to_string(),
                    reason: "MLS Group ID must be at least 16 bytes".to_string(),
                });
            }

            // Reject empty payloads
            if payload.is_empty() {
                return Err(DllError::InvalidInput {
                    param: "payload".to_string(),
                    reason: "Envelope payload must be non-empty".to_string(),
                });
            }

            Ok(FcepEnvelope::Standard { kind, target_id, payload })
        }
    }
}

/// Check if an IRC trailing parameter is an FCEP-2 message.
///
/// Uses strict prefix matching (`+FCEP2 ` at start) to avoid false positives
/// from chat text that happens to contain the substring.
pub fn is_fcep2_line(line: &str) -> bool {
    line.trim().starts_with(FCEP2_PREFIX)
}

/// Helper to decode strict unpadded Base64Url string (RFC 4648 Section 5)
fn decode_unpadded_b64(input: &str) -> Result<Vec<u8>, DllError> {
    // Reject empty string
    if input.is_empty() {
        return Err(DllError::InvalidInput {
            param: "base64url".to_string(),
            reason: "Empty base64url string".to_string(),
        });
    }
    // Reject padding characters explicitly
    if input.contains('=') {
        return Err(DllError::InvalidInput {
            param: "base64url".to_string(),
            reason: "Base64Url padding is strictly prohibited".to_string(),
        });
    }
    // Validate characters: only base64url alphabet (A-Z, a-z, 0-9, -, _)
    if !input.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(DllError::InvalidInput {
            param: "base64url".to_string(),
            reason: "Invalid base64url character (only A-Z, a-z, 0-9, -, _ allowed)".to_string(),
        });
    }

    URL_SAFE_NO_PAD.decode(input.as_bytes()).map_err(|e| DllError::InvalidInput {
        param: "base64url".to_string(),
        reason: format!("Failed to decode Base64Url: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_envelope_roundtrip() {
        let gid = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let payload = b"Hello MLS World!".to_vec();

        let encoded = FcepEnvelope::encode_standard(EnvelopeKind::Application, &gid, &payload);
        assert!(encoded.starts_with("+FCEP2 A "));

        let parsed = FcepEnvelope::parse(&encoded).unwrap();
        match parsed {
            FcepEnvelope::Standard { kind, target_id, payload: p } => {
                assert_eq!(kind, EnvelopeKind::Application);
                assert_eq!(target_id, gid);
                assert_eq!(p, payload);
            }
            _ => panic!("Expected Standard envelope"),
        }
    }

    #[test]
    fn test_fragment_envelope_roundtrip() {
        let obj_id = [7u8; 16];
        let frag_payload = b"fragment data block".to_vec();

        let encoded =
            FcepEnvelope::encode_fragment(&obj_id, 0, 3, EnvelopeKind::Commit, &frag_payload);
        assert!(encoded.starts_with("+FCEP2 F "));

        let parsed = FcepEnvelope::parse(&encoded).unwrap();
        match parsed {
            FcepEnvelope::Fragment { object_id, index, count, kind, fragment } => {
                assert_eq!(object_id, obj_id);
                assert_eq!(index, 0);
                assert_eq!(count, 3);
                assert_eq!(kind, EnvelopeKind::Commit);
                assert_eq!(fragment, frag_payload);
            }
            _ => panic!("Expected Fragment envelope"),
        }
    }

    #[test]
    fn test_reject_padded_b64() {
        let padded = "+FCEP2 A AQIDBAUGBwgJCgsMDQ4PEA== SGVsbG8=";
        assert!(FcepEnvelope::parse(padded).is_err());
    }
}
