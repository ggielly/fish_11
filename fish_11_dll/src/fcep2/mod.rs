//! FiSH-11 Channel Encryption Protocol v2 (FCEP-2)
//!
//! MLS over IRC Transport Profile implementation (RFC 9420, docs/FCEP-2_DRAFT.txt)
//!
//! # Module structure
//!
//! ## New modules (recommended path)
//!
//! - `types`             : Transport-safe type definitions (no crypto material)
//! - `transport`         : Envelope parsing, budget-correct fragmentation, reassembly
//! - `persistence`       : Encrypted atomic file store (SecretBox trait)
//! - `openmls_adapter`   : Thin wrapper around the pinned OpenMLS crate
//! - `group_actor`       : Single-owner per group (persist-before-send)
//!
//! ## Legacy modules (DEPRECATED : kept for DLL interface compatibility)
//!
//! - `envelope`          => replaced by `transport`
//! - `fragmentation`     => replaced by `transport`
//! - `mls_engine`        => replaced by `openmls_adapter`
//! - `storage`           => replaced by `persistence`
//! - `commit`            => replaced by raw MLS bytes + OpenMLS
//! - `proposal`          => replaced by raw MLS bytes + OpenMLS
//! - `ordering`          => replaced by OpenMLS epoch management
//! - `conflict`          => simplified to UI-only state in group_actor
//! - `sync`              => replaced by transport-only retrieval (no state mutation)
//!
//! ## Shared modules
//!
//! - `dedup`             : In-memory deduplication (advisory only)
//! - `deferred`          : Deferred delivery for unknown groups
//! - `ratelimit`         : Per-destination fragment rate limiting

// ===== New modules (recommended) ───────────────────────────────────
pub mod group_actor;
pub mod openmls_adapter;
pub mod persistence;
pub mod transport;
pub mod types;

// ===== Legacy modules (deprecated, kept for dll_interface compat) ──
pub mod commit;
pub mod conflict;
pub mod dedup;
pub mod deferred;
pub mod envelope;
pub mod fragmentation;
pub mod mls_engine;
pub mod ordering;
pub mod proposal;
pub mod ratelimit;
pub mod storage;
pub mod sync;

use std::collections::{HashMap, VecDeque};

use conflict::ConflictManager;
use dedup::DeduplicationFilter;
use deferred::DeferredCache;
use mls_engine::{LocalDevice, MlsGroupState};
use once_cell::sync::Lazy;
use ordering::OrderingEngine;
use parking_lot::RwLock;
use proposal::ProposalEngine;
use ratelimit::FragmentRateLimiter;
use storage::FcepStorage;
use transport::ReassemblyEngine;
use types::{DiagnosticEvent, EncryptionPolicy, KeyPackagePoolEntry};

// ===== New globals ─────────────────────────────────────────────────

/// Global fragment reassembly engine (DoS-bounded, per-source quotas).
pub static REASSEMBLY_ENGINE: Lazy<RwLock<ReassemblyEngine>> =
    Lazy::new(|| RwLock::new(ReassemblyEngine::new()));

/// Global diagnostics log (bounded ring buffer).
pub static DIAGNOSTICS_LOG: Lazy<RwLock<VecDeque<DiagnosticEvent>>> =
    Lazy::new(|| RwLock::new(VecDeque::with_capacity(256)));

// ===== Legacy globals (deprecated) ─────────────────────────────────

#[allow(deprecated)]
pub static FCEP2_DEVICE: Lazy<RwLock<Option<LocalDevice>>> = Lazy::new(|| RwLock::new(None));

#[allow(deprecated)]
pub static FCEP2_GROUPS: Lazy<RwLock<HashMap<Vec<u8>, MlsGroupState>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static FCEP2_CHANNEL_MAP: Lazy<RwLock<HashMap<String, Vec<u8>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

#[allow(deprecated)]
pub static CONFLICT_MANAGER: Lazy<RwLock<ConflictManager>> =
    Lazy::new(|| RwLock::new(ConflictManager::new()));

#[allow(deprecated)]
pub static PROPOSAL_ENGINE: Lazy<RwLock<ProposalEngine>> =
    Lazy::new(|| RwLock::new(ProposalEngine::new()));

#[allow(deprecated)]
pub static COMMIT_PROCESSOR: Lazy<RwLock<commit::CommitProcessor>> =
    Lazy::new(|| RwLock::new(commit::CommitProcessor::new()));

#[allow(deprecated)]
pub static ORDERING_ENGINE: Lazy<RwLock<OrderingEngine>> =
    Lazy::new(|| RwLock::new(OrderingEngine::new()));

pub static DEFERRED_CACHE: Lazy<RwLock<DeferredCache>> =
    Lazy::new(|| RwLock::new(DeferredCache::new()));

pub static SYNC_MANAGER: Lazy<RwLock<sync::SyncManager>> =
    Lazy::new(|| RwLock::new(sync::SyncManager::new()));

pub static DEDUP_FILTER: Lazy<RwLock<DeduplicationFilter>> =
    Lazy::new(|| RwLock::new(DeduplicationFilter::new()));

pub static ENCRYPTION_POLICIES: Lazy<RwLock<HashMap<String, EncryptionPolicy>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));

pub static RATE_LIMITER: Lazy<RwLock<FragmentRateLimiter>> =
    Lazy::new(|| RwLock::new(FragmentRateLimiter::new()));

pub static KEY_PACKAGE_POOL: Lazy<RwLock<Vec<KeyPackagePoolEntry>>> =
    Lazy::new(|| RwLock::new(Vec::new()));

/// Initialize or retrieve local device identity (legacy path).
#[allow(deprecated)]
pub fn get_or_init_device(label: &str) -> LocalDevice {
    let mut guard = FCEP2_DEVICE.write();
    if let Some(dev) = guard.as_ref() {
        return dev.clone();
    }

    let storage = FcepStorage::new();
    let dev = storage.load_or_create_device(label).unwrap_or_else(|_| LocalDevice::generate(label));
    *guard = Some(dev.clone());
    dev
}

/// Push a diagnostic event, evicting oldest when full.
pub fn push_diagnostic(
    event_type: impl Into<String>,
    group_id: Vec<u8>,
    detail: impl Into<String>,
    severity: types::DiagnosticSeverity,
) {
    let event = DiagnosticEvent {
        timestamp_unix: chrono::Utc::now().timestamp(),
        event_type: event_type.into(),
        group_id,
        detail: detail.into(),
        severity,
    };
    let mut log = DIAGNOSTICS_LOG.write();
    if log.len() >= 256 {
        log.pop_front();
    }
    log.push_back(event);
}
