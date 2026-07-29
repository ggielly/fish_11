//! OpenMLS provider wrapper
//!
//! FCEP-2 uses OpenMLS's `OpenMlsRustCrypto` for all cryptographic operations.
//! The `MlsGroup` state is held in-memory; for durability, the application layer
//! MUST persist the group state via `PersistedGroup::save()` (in `persistence.rs`)
//! before any network send, and reload via `PersistedGroup::load()` after restart.
//!
//! # StorageProvider (OpenMLS trait)
//!
//! `OpenMlsRustCrypto::default()` uses an ephemeral in-memory `MemoryStorage`.
//! This means OpenMLS key material and PSK state are LOST on process restart.
//! To make MLS state durable across restarts, you must either:
//!
//! 1. Persist the serialized `MlsGroup` via `group.export(RatchetTree::Full)` and
//!    `MlsGroup::load()` after restart : handled by `PersistedGroup`.
//! 2. Wire a persistent `openmls_traits::StorageProvider` implementation that stores
//!    key material in a platform keystore or encrypted database.
//!
//! Until a persistent StorageProvider is wired, every MLS operation that mutates
//! group state MUST be followed by `PersistedGroup::save()`. If that save fails,
//! the application MUST NOT send the resulting network messages, as the in-memory
//! state would be the sole source of truth and would be lost on crash.

use openmls::prelude::*;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The mandatory ciphersuite for FCEP-2.
pub const FCEP2_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

/// Create an OpenMLS provider backed by RustCrypto primitives.
///
/// The storage is in-memory (`MemoryStorage`). See module docs for
/// durability requirements.
pub fn create_provider() -> OpenMlsRustCrypto {
    OpenMlsRustCrypto::default()
}

/// Default sender ratchet configuration for FCEP-2 over IRC.
///
/// - `out_of_order_tolerance`: 20 messages
/// - `maximum_forward_distance`: 2,000 messages
///
/// These values are tuned for typical IRC conditions (moderate reordering,
/// multi-server routing, occasional netsplits).
pub fn default_sender_ratchet_config() -> SenderRatchetConfiguration {
    SenderRatchetConfiguration::new(20, 2000)
}

/// Build an MlsGroup configuration for FCEP-2.
///
/// This sets the mandatory ciphersuite, sender ratchet parameters, and
/// enables the ratchet tree extension for efficient member management.
pub fn build_group_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(FCEP2_CIPHERSUITE)
        .sender_ratchet_configuration(default_sender_ratchet_config())
        .use_ratchet_tree_extension(true)
        .build()
}
