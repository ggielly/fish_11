//! FCEP-2 Transport & Metadata Types
//!
//! This file contains ONLY transport-safe types: envelope identifiers,
//! bindings, trust states, diagnostics, and persistence records.
//!
//! CRITICAL: No custom cryptographic types live here. MLS objects (KeyPackage,
//! Welcome, Commit, Application messages, Proposals) are opaque byte blobs
//! produced and consumed exclusively by OpenMLS. The transport layer never
//! inspects or interprets their internal structure.

use serde::{Deserialize, Serialize};

// ===== Transport Envelope (RFC Section 9) ───────────────────────────

/// FCEP-2 Transport Envelope Object Types (RFC Section 9)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EnvelopeKind {
    /// MLS Application message ('A')
    Application,
    /// MLS Proposal message ('P')
    Proposal,
    /// MLS Commit message ('C')
    Commit,
    /// MLS Welcome message ('W')
    Welcome,
    /// KeyPackage publication or response ('K')
    KeyPackage,
    /// Request, including KeyPackage & sync ('R')
    Request,
    /// Synchronization object ('S')
    Sync,
    /// Ack or Nack for a request ('X')
    Ack,
}

impl EnvelopeKind {
    pub fn to_char(&self) -> char {
        match self {
            Self::Application => 'A',
            Self::Proposal => 'P',
            Self::Commit => 'C',
            Self::Welcome => 'W',
            Self::KeyPackage => 'K',
            Self::Request => 'R',
            Self::Sync => 'S',
            Self::Ack => 'X',
        }
    }

    pub fn from_char(c: char) -> Result<Self, String> {
        match c {
            'A' => Ok(Self::Application),
            'P' => Ok(Self::Proposal),
            'C' => Ok(Self::Commit),
            'W' => Ok(Self::Welcome),
            'K' => Ok(Self::KeyPackage),
            'R' => Ok(Self::Request),
            'S' => Ok(Self::Sync),
            'X' => Ok(Self::Ack),
            _ => Err(format!("Unknown FCEP-2 envelope kind character: '{}'", c)),
        }
    }

    /// Whether this type is channel-scoped (sent as PRIVMSG per §9.2).
    pub fn is_group_scoped(&self) -> bool {
        matches!(self, Self::Application | Self::Proposal | Self::Commit)
    }

    /// Whether this type is device-scoped (sent as NOTICE per §9.2).
    pub fn is_device_scoped(&self) -> bool {
        !self.is_group_scoped()
    }
}

// ===== Trust & Identity (RFC Section 6) ────────────────────────────

/// Local trust state for known device identities (RFC Section 6.3)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    /// First observed identity; no out-of-band confirmation
    Unknown,
    /// Trust on first use; fingerprint persisted locally
    Tofu,
    /// Fingerprint confirmed via out-of-band mechanism
    Verified,
    /// Known identity presented unexpected signing key
    Changed,
    /// Device removed from all local groups or manually blocked
    Revoked,
}

impl std::fmt::Display for TrustState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrustState::Unknown => write!(f, "UNKNOWN"),
            TrustState::Tofu => write!(f, "TOFU"),
            TrustState::Verified => write!(f, "VERIFIED"),
            TrustState::Changed => write!(f, "CHANGED"),
            TrustState::Revoked => write!(f, "REVOKED"),
        }
    }
}

/// Device Identity representation (RFC Section 6.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    pub device_id: [u8; 16],
    pub credential_fingerprint: [u8; 32],
    pub display_label: String,
    pub trust: TrustState,
}

/// Durable association between an IRC network, channel, and MLS group (RFC Section 7.1)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupBinding {
    pub protocol_version: u16,
    pub network_id: [u8; 32],
    pub canonical_channel: String,
    pub mls_group_id: Vec<u8>,
    pub creator_fingerprint: [u8; 32],
    pub created_at_unix: i64,
}

// ===== Persistence (RFC Section 19 & 21) ───────────────────────────

/// Serializable commit conflict state (RFC Section 15.4).
///
/// Contains ONLY the raw MLS commit bytes and diagnostic metadata.
/// No custom epoch secrets or plaintext membership lists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitConflict {
    pub group_id: Vec<u8>,
    /// The epoch at which the conflict was detected (parent epoch).
    pub old_epoch: u64,
    /// Raw TLS-serialized MLS Commit bytes of the competing commits.
    pub conflicting_commits: Vec<Vec<u8>>,
    pub detected_at_unix: i64,
    pub source_diagnostics: Vec<String>,
}

/// Entry in persistent outbox tracking unsent transport envelopes (RFC Section 19.4)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub id: [u8; 16],
    pub envelope: Vec<u8>,
    pub created_at_unix: i64,
    pub delivered: bool,
    pub sequence: u64,
    pub retry_count: u8,
    pub last_attempt_at_unix: i64,
}

/// Complete state of an active MLS group for persistence (RFC Section 21).
///
/// `serialized_mls_group` contains the OpenMLS-managed state blob.
/// The transport layer NEVER inspects or interprets this data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedGroup {
    pub binding: GroupBinding,
    /// Opaque OpenMLS group state bytes. Managed by OpenMLS StorageProvider.
    pub serialized_mls_group: Vec<u8>,
    pub local_device_id: [u8; 16],
    pub known_devices: Vec<DeviceIdentity>,
    pub conflict: Option<CommitConflict>,
    pub outbox: Vec<OutboxEntry>,
    pub schema_version: u32,
    pub current_epoch: u64,
}

// ===== Deferred Delivery (RFC 13.3) ─────────────────────────────────

/// Object queued for a group we don't know yet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeferredEntry {
    pub entry_id: [u8; 16],
    pub group_id: Vec<u8>,
    pub kind: EnvelopeKind,
    pub payload: Vec<u8>,
    pub source_nick: String,
    pub created_at_unix: i64,
    pub target_id: Vec<u8>,
}

// ===== Sync (RFC 18) ────────────────────────────────────────────────

/// Sync request envelope (RFC 18.1).
/// Transport-only: no authentication, advisory metadata only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequest {
    pub group_id: Vec<u8>,
    pub last_known_epoch: u64,
    pub requester_device_id: [u8; 16],
    pub request_id: [u8; 16],
}

/// Sync response envelope (RFC 18.2).
/// Contains raw MLS Commit bytes, not custom epoch transitions.
/// The receiver MUST process Commits via OpenMLS, not by incrementing a counter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponse {
    pub request_id: [u8; 16],
    pub group_id: Vec<u8>,
    pub current_epoch: u64,
    /// Raw TLS-serialized MLS Commit messages, in epoch order.
    pub epoch_diff: Vec<Vec<u8>>,
    /// Advisory member list (for UI display only, NOT for MLS state).
    pub current_members: Vec<[u8; 16]>,
    pub responder_device_id: [u8; 16],
}

// ===== Diagnostics (RFC 22.3) ───────────────────────────────────────

/// Structured diagnostic event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagnosticEvent {
    pub timestamp_unix: i64,
    pub event_type: String,
    pub group_id: Vec<u8>,
    pub detail: String,
    pub severity: DiagnosticSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticSeverity {
    Info,
    Warn,
    Error,
}

// ===== Rate Limiting (RFC 8.4) ──────────────────────────────────────

/// Per-destination fragment rate limiter state
#[derive(Debug, Clone)]
pub struct FragmentRateBucket {
    pub timestamps: Vec<i64>,
    pub max_per_second: u32,
}

// ===== Legacy types (used by old fcep2 modules) ──────────────────
// These are kept for backward-compatible modules (mls_engine, commit,
// proposal, ordering, etc.). New code should use raw MLS bytes.
// See migration summary below.

/// Custom commit payload : prefer raw TLS-serialized MLS Commit bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitPayload {
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_id: [u8; 16],
    pub proposal_ids: Vec<[u8; 16]>,
    pub signature: Vec<u8>,
    pub created_at_unix: i64,
}

/// Custom commit result : prefer OpenMLS CommitDecision.
#[derive(Debug, Clone)]
pub enum CommitResult {
    Applied { new_epoch: u64, new_epoch_secret: [u8; 32] },
    Conflict { conflict: CommitConflict },
    Rejected { reason: String },
}

/// Custom tracked commit : prefer raw MLS bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedCommit {
    pub commit: CommitPayload,
    pub received_at_unix: i64,
    pub source_nick: String,
    pub hash: [u8; 32],
}

/// Custom ordering result : prefer OpenMLS epoch comparison.
#[derive(Debug)]
pub enum OrderingResult {
    Tracked,
    ConflictDetected { commits: Vec<TrackedCommit> },
}

/// Custom proposal operation : prefer raw TLS-serialized MLS Proposal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalOp {
    Add { key_package_b64: String },
    Remove { removed_device_id: [u8; 16] },
    Update { new_encryption_key: [u8; 32] },
    Reinit,
}

/// Custom proposal : prefer raw TLS-serialized MLS Proposal bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub proposal_id: [u8; 16],
    pub group_id: Vec<u8>,
    pub epoch: u64,
    pub sender_device_id: [u8; 16],
    pub op: ProposalOp,
    pub signature: Vec<u8>,
    pub created_at_unix: i64,
}

/// Fragment assembly buffer : use transport::ReassemblyEngine instead.
#[derive(Debug, Clone)]
pub struct FragmentAssembly {
    pub source_id: String,
    pub object_id: [u8; 16],
    pub kind: EnvelopeKind,
    pub count: u16,
    pub received: Vec<Option<Vec<u8>>>,
    pub created_at_unix: i64,
}

/// Outbox state : managed within PersistedGroup instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboxState {
    pub entries: Vec<OutboxEntry>,
    pub next_sequence: u64,
    pub max_retries: u8,
    pub retry_delay_secs: u64,
}

/// KeyPackage pool entry : managed by OpenMLS StorageProvider instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPackagePoolEntry {
    pub key_package_b64: String,
    pub created_at_unix: i64,
    pub used: bool,
}

// ═══════════════════════════════════════════════════════════════════
// Migration summary
// ═══════════════════════════════════════════════════════════════════
// Removed custom crypto types => replaced by opaque TLS-serialized MLS bytes
// - CommitPayload        => Vec<u8> (raw MLS Commit)
// - Proposal / ProposalOp => Vec<u8> (raw MLS Proposal)
// - FcepApplicationMsg   => Vec<u8> (raw MLS Application message)
// - FcepWelcome          => Vec<u8> (raw MLS Welcome)
// - FcepKeyPackage       => Vec<u8> (raw MLS KeyPackage)
//
// New modules:
// - transport.rs: envelope parsing, budget-correct fragmentation, reassembly
// - persistence.rs: SecretBox trait, EncryptedFileStore, atomic write
// - openmls_adapter.rs: thin OpenMLS wrapper (all crypto delegated here)
// - group_actor.rs: single-owner per group with persist-before-send

// ===== Encryption Policy (RFC 22.1) ─────────────────────────────────

/// Channel encryption mode selection
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionPolicy {
    Always,
    RequireAll,
    BestEffort,
    Disabled,
}
