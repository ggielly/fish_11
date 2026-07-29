//! FCEP-2 transport envelope framing

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::error::{Fcep2Error, Result};

/// Typed envelope target, distinguishing between group IDs (for A, P, C, W, S),
/// device IDs (for K), and request IDs (for R, X) per §9.2.
///
/// This replaces the generic `group_id: Vec<u8>` field in `Fcep2Envelope`,
/// allowing the parser and serializer to apply type-specific size validation
/// and encoding rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeTarget {
    /// MLS Group ID (minimum 16 bytes). Used by A, P, C, W, S.
    GroupId(Vec<u8>),
    /// 128-bit device identifier. Used by K.
    DeviceId([u8; 16]),
    /// 128-bit request correlation identifier. Used by R, X.
    RequestId([u8; 16]),
}

impl EnvelopeTarget {
    /// Encode the target as base64url for IRC transport.
    pub fn to_base64(&self) -> String {
        match self {
            Self::GroupId(bytes) => URL_SAFE_NO_PAD.encode(bytes),
            Self::DeviceId(bytes) => URL_SAFE_NO_PAD.encode(bytes),
            Self::RequestId(bytes) => URL_SAFE_NO_PAD.encode(bytes),
        }
    }

    /// Decode a base64url string into the appropriate target type.
    pub fn from_base64(kind: Fcep2Type, encoded: &str) -> Result<Self> {
        let raw = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| Fcep2Error::Base64(format!("Invalid target '{}': {}", encoded, e)))?;

        match kind {
            // Group-scoped types: minimum 16 bytes
            Fcep2Type::Application
            | Fcep2Type::Proposal
            | Fcep2Type::Commit
            | Fcep2Type::Welcome
            | Fcep2Type::Sync => {
                if raw.len() < 16 {
                    return Err(Fcep2Error::InvalidEnvelope(format!(
                        "Group ID too short: {} bytes (minimum 16)",
                        raw.len()
                    )));
                }
                Ok(Self::GroupId(raw))
            }
            // Device-scoped types: exactly 16 bytes (128-bit device ID)
            Fcep2Type::KeyPackage => {
                let id = Self::expect_exact_16(raw, "device-id")?;
                Ok(Self::DeviceId(id))
            }
            // Request-scoped types: exactly 16 bytes (128-bit request ID)
            Fcep2Type::Request | Fcep2Type::Ack => {
                let id = Self::expect_exact_16(raw, "request-id")?;
                Ok(Self::RequestId(id))
            }
            Fcep2Type::Fragment => Err(Fcep2Error::InvalidEnvelope(
                "Fragment type F cannot have an envelope target".to_string(),
            )),
        }
    }

    fn expect_exact_16(raw: Vec<u8>, label: &str) -> Result<[u8; 16]> {
        let len = raw.len();
        let bytes: [u8; 16] = raw.try_into().map_err(|_| {
            Fcep2Error::InvalidEnvelope(format!("{} must be exactly 16 bytes, got {}", label, len))
        })?;
        Ok(bytes)
    }
}

/// IRC line budget for computing safe payload sizes.
///
/// An IRC line on the wire is: `[<prefix>] <command> <params> :<trailing>\r\n`
/// limited to 512 bytes total. This struct computes the budget for the trailing
/// portion (our FCEP-2 line) based on the actual command and destination.
#[derive(Debug, Clone, Copy)]
pub struct IrcLineBudget {
    /// Maximum total IRC line length (typically 512).
    pub max_wire: usize,
    /// Number of bytes consumed by `<command> <destination> :`.
    pub transport_overhead: usize,
}

impl IrcLineBudget {
    /// Standard IRC max line length.
    pub const STANDARD_MAX: usize = 512;

    /// Compute the budget for a PRIVMSG or NOTICE to a given destination.
    ///
    /// `command` is the IRC command (e.g., "PRIVMSG" or "NOTICE").
    /// `destination` is the target nick or channel.
    /// The reserved bytes account for: `<cmd> <dest> :` + `\r\n`.
    pub fn new(command: &str, destination: &str) -> Self {
        let transport_overhead = command.len() + 1 + destination.len() + 2 + 2; // "CMD dest :\r\n"
        Self { max_wire: Self::STANDARD_MAX, transport_overhead }
    }

    /// Return the maximum number of bytes available for the FCEP-2 line
    /// (the content after the ` :` prefix).
    pub fn available_for_line(&self) -> usize {
        self.max_wire.saturating_sub(self.transport_overhead)
    }
}

/// Default budget used when the destination is not known at serialization time.
/// Assumes a 30-char destination (long nick or channel) to be conservative.
pub const DEFAULT_IRC_BUDGET: IrcLineBudget = IrcLineBudget {
    max_wire: IrcLineBudget::STANDARD_MAX,
    transport_overhead: 8 + 1 + 30 + 2 + 2, // "PRIVMSG <30-char-target> :\r\n" = 43
};

/// FCEP-2 message type identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fcep2Type {
    /// MLS Application message.
    Application,
    /// MLS Proposal message.
    Proposal,
    /// MLS Commit message.
    Commit,
    /// MLS Welcome message.
    Welcome,
    /// KeyPackage publication or response.
    KeyPackage,
    /// Request (KeyPackage, sync, etc.).
    Request,
    /// Synchronization object.
    Sync,
    /// Acknowledgement.
    Ack,
    /// Fragment wrapper (kind F : used only in fragment headers).
    Fragment,
}

impl Fcep2Type {
    /// Convert to single ASCII character.
    pub fn to_char(self) -> u8 {
        match self {
            Self::Application => b'A',
            Self::Proposal => b'P',
            Self::Commit => b'C',
            Self::Welcome => b'W',
            Self::KeyPackage => b'K',
            Self::Request => b'R',
            Self::Sync => b'S',
            Self::Ack => b'X',
            Self::Fragment => b'F',
        }
    }

    /// Parse from a single ASCII byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            b'A' => Ok(Self::Application),
            b'P' => Ok(Self::Proposal),
            b'C' => Ok(Self::Commit),
            b'W' => Ok(Self::Welcome),
            b'K' => Ok(Self::KeyPackage),
            b'R' => Ok(Self::Request),
            b'S' => Ok(Self::Sync),
            b'X' => Ok(Self::Ack),
            _ => Err(Fcep2Error::InvalidEnvelope(format!("Unknown type byte: 0x{:02X}", b))),
        }
    }

    /// Whether this type is channel-scoped (sent as PRIVMSG).
    pub fn is_channel_scoped(self) -> bool {
        matches!(self, Self::Application | Self::Proposal | Self::Commit)
    }

    /// Whether this type is device-scoped (sent as NOTICE).
    pub fn is_device_scoped(self) -> bool {
        !self.is_channel_scoped()
    }
}

/// A parsed FCEP-2 envelope with typed target identification.
///
/// Per §9.2, the second field is either a Group ID (A, P, C, W, S),
/// a Device ID (K), or a Request ID (R, X). The `target` field encodes
/// this distinction via `EnvelopeTarget`.
#[derive(Debug, Clone)]
pub struct Fcep2Envelope {
    /// Message type.
    pub kind: Fcep2Type,
    /// Typed target (GroupId, DeviceId, or RequestId per §9.2).
    pub target: EnvelopeTarget,
    /// Payload (raw bytes, not base64).
    pub payload: Vec<u8>,
}

/// The +FCEP2 prefix that identifies FCEP-2 messages.
pub const FCEP2_PREFIX: &str = "+FCEP2 ";

/// Maximum payload size for a single fragment (320 octets per spec §8.4).
pub const MAX_FRAGMENT_PAYLOAD: usize = 240;

/// Maximum IRC line size.
pub const IRC_LINE_MAX: usize = 512;

impl Fcep2Envelope {
    /// Serialize an envelope to a single FCEP-2 line, using the default
    /// conservative IRC budget (assumes ~30-char destination).
    ///
    /// Returns `Err(LineOverflow)` if the result exceeds IRC line limits.
    pub fn serialize(&self) -> Result<String> {
        self.serialize_with_budget(&DEFAULT_IRC_BUDGET)
    }

    /// Serialize an envelope for a specific IRC command and destination.
    ///
    /// `command`: "PRIVMSG" or "NOTICE"
    /// `destination`: target channel or nickname
    ///
    /// This computes the precise IRC line budget, allowing larger payloads
    /// for short destinations and preventing overflow for long ones.
    pub fn serialize_for_irc(&self, command: &str, destination: &str) -> Result<String> {
        let budget = IrcLineBudget::new(command, destination);
        self.serialize_with_budget(&budget)
    }

    /// Serialize with a given IRC line budget.
    fn serialize_with_budget(&self, budget: &IrcLineBudget) -> Result<String> {
        let kind_char = self.kind.to_char() as char;
        let target_b64 = self.target.to_base64();
        let payload_b64 = URL_SAFE_NO_PAD.encode(&self.payload);

        let line = format!("{}{} {} {}", FCEP2_PREFIX, kind_char, target_b64, payload_b64);

        let max_line = budget.available_for_line();
        if line.len() > max_line {
            return Err(Fcep2Error::LineOverflow);
        }

        Ok(line)
    }

    /// Parse an FCEP-2 line into an envelope.
    ///
    /// Expects the full IRC line content after " :" : i.e., "+FCEP2 A <target> <payload>".
    pub fn deserialize(line: &str) -> Result<Self> {
        let line = line.trim();

        // Strip the +FCEP2 prefix
        let body = line
            .strip_prefix(FCEP2_PREFIX)
            .ok_or_else(|| Fcep2Error::InvalidEnvelope("Missing +FCEP2 prefix".to_string()))?;

        let parts: Vec<&str> = body.splitn(3, ' ').collect();
        if parts.len() < 3 {
            return Err(Fcep2Error::InvalidEnvelope(format!(
                "Expected at least 3 tokens (type target payload), got {}",
                parts.len()
            )));
        }

        // Parse type
        let kind_byte = parts[0]
            .as_bytes()
            .first()
            .ok_or_else(|| Fcep2Error::InvalidEnvelope("Empty type".to_string()))?;
        let kind = Fcep2Type::from_byte(*kind_byte)?;

        // Reject kind=F in non-fragment context (F is only for fragment wrappers)
        if kind == Fcep2Type::Fragment {
            return Err(Fcep2Error::InvalidEnvelope(
                "Kind F is reserved for fragment headers, not direct envelopes".to_string(),
            ));
        }

        // Parse typed target (validates size based on type per §9.2)
        let target = EnvelopeTarget::from_base64(kind, parts[1])?;

        // Parse payload
        let payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[2])
            .map_err(|e| Fcep2Error::Base64(format!("Invalid payload: {}", e)))?;

        Ok(Self { kind, target, payload: payload_bytes })
    }

    /// Check if a line is an FCEP-2 message.
    pub fn is_fcep2_line(line: &str) -> bool {
        line.contains(FCEP2_PREFIX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_application() {
        let env = Fcep2Envelope {
            kind: Fcep2Type::Application,
            target: EnvelopeTarget::GroupId(vec![0x42u8; 16]),
            payload: vec![0x01, 0x02, 0x03],
        };

        let serialized = env.serialize().unwrap();
        let parsed = Fcep2Envelope::deserialize(&serialized).unwrap();

        assert_eq!(parsed.kind, Fcep2Type::Application);
        assert_eq!(parsed.target, env.target);
        assert_eq!(parsed.payload, env.payload);
    }

    #[test]
    fn test_roundtrip_welcome() {
        let env = Fcep2Envelope {
            kind: Fcep2Type::Welcome,
            target: EnvelopeTarget::GroupId(vec![0xAA; 32]),
            payload: vec![0xFF; 100],
        };

        let serialized = env.serialize().unwrap();
        assert!(serialized.starts_with("+FCEP2 W "));
        let parsed = Fcep2Envelope::deserialize(&serialized).unwrap();
        assert_eq!(parsed.kind, Fcep2Type::Welcome);
    }

    #[test]
    fn test_roundtrip_keypackage() {
        let env = Fcep2Envelope {
            kind: Fcep2Type::KeyPackage,
            target: EnvelopeTarget::DeviceId([0x42u8; 16]),
            payload: vec![0x01, 0x02, 0x03],
        };

        let serialized = env.serialize().unwrap();
        let parsed = Fcep2Envelope::deserialize(&serialized).unwrap();

        assert_eq!(parsed.kind, Fcep2Type::KeyPackage);
        assert_eq!(parsed.target, EnvelopeTarget::DeviceId([0x42u8; 16]));
        assert_eq!(parsed.payload, env.payload);
    }

    #[test]
    fn test_roundtrip_request() {
        let env = Fcep2Envelope {
            kind: Fcep2Type::Request,
            target: EnvelopeTarget::RequestId([0x11u8; 16]),
            payload: b"KP".to_vec(),
        };

        let serialized = env.serialize().unwrap();
        let parsed = Fcep2Envelope::deserialize(&serialized).unwrap();

        assert_eq!(parsed.kind, Fcep2Type::Request);
        assert_eq!(parsed.target, env.target);
        assert_eq!(parsed.payload, env.payload);
    }

    #[test]
    fn test_serialize_for_irc() {
        let env = Fcep2Envelope {
            kind: Fcep2Type::Application,
            target: EnvelopeTarget::GroupId(vec![0x42u8; 16]),
            payload: vec![0x01, 0x02, 0x03],
        };

        // Should work for both PRIVMSG and NOTICE with short targets
        let line = env.serialize_for_irc("PRIVMSG", "#fish11").unwrap();
        assert!(line.starts_with("+FCEP2 A "));

        let line = env.serialize_for_irc("NOTICE", "some_nick").unwrap();
        assert!(line.starts_with("+FCEP2 A "));
    }

    #[test]
    fn test_reject_kind_f() {
        let result = Fcep2Envelope::deserialize("+FCEP2 F dGVzdA dGVzdA");
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_short_gid() {
        let short_gid = URL_SAFE_NO_PAD.encode(&[0u8; 8]);
        let payload = URL_SAFE_NO_PAD.encode(&[1u8; 10]);
        let result = Fcep2Envelope::deserialize(&format!("+FCEP2 A {} {}", short_gid, payload));
        assert!(result.is_err());
    }

    #[test]
    fn test_reject_short_device_id() {
        // K type with < 16 byte target should fail
        let short_did = URL_SAFE_NO_PAD.encode(&[0u8; 8]);
        let payload = URL_SAFE_NO_PAD.encode(&[1u8; 10]);
        let result = Fcep2Envelope::deserialize(&format!("+FCEP2 K {} {}", short_did, payload));
        assert!(result.is_err());
    }

    #[test]
    fn test_is_fcep2_line() {
        assert!(Fcep2Envelope::is_fcep2_line("PRIVMSG #chan :+FCEP2 A abc123 def456"));
        assert!(!Fcep2Envelope::is_fcep2_line("PRIVMSG #chan :+FiSH encrypted"));
    }

    #[test]
    fn test_type_category() {
        assert!(Fcep2Type::Application.is_channel_scoped());
        assert!(Fcep2Type::Proposal.is_channel_scoped());
        assert!(Fcep2Type::Commit.is_channel_scoped());
        assert!(!Fcep2Type::Welcome.is_channel_scoped());
        assert!(!Fcep2Type::KeyPackage.is_channel_scoped());
        assert!(!Fcep2Type::Request.is_channel_scoped());
        assert!(!Fcep2Type::Sync.is_channel_scoped());
        assert!(!Fcep2Type::Ack.is_channel_scoped());
    }

    #[test]
    fn test_envelope_target_device_id() {
        let did = [0x01u8; 16];
        let target = EnvelopeTarget::DeviceId(did);
        let b64 = target.to_base64();
        let decoded = EnvelopeTarget::from_base64(Fcep2Type::KeyPackage, &b64).unwrap();
        assert_eq!(decoded, EnvelopeTarget::DeviceId(did));
    }

    #[test]
    fn test_envelope_target_request_id() {
        let rid = [0x02u8; 16];
        let target = EnvelopeTarget::RequestId(rid);
        let b64 = target.to_base64();
        let decoded = EnvelopeTarget::from_base64(Fcep2Type::Request, &b64).unwrap();
        assert_eq!(decoded, EnvelopeTarget::RequestId(rid));
    }

    #[test]
    fn test_irc_budget() {
        let budget = IrcLineBudget::new("PRIVMSG", "#fish11");
        assert!(budget.available_for_line() > 0);
        // "PRIVMSG #fish11 :\r\n" = 7+1+7+1+1+2 = 19 bytes
        // Available = 512 - 19 = 493
        assert_eq!(budget.available_for_line(), 493);
    }
}
