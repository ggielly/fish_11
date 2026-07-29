//! FCEP-2 Fragmentation & Reassembly Engine
//!
//! Handles line-budget payload splitting into +FCEP2 F fragment envelopes,
//! and out-of-order fragment reassembly with bounds & timeouts (RFC Section 10).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use rand::RngCore;

use super::envelope::FcepEnvelope;
use super::types::EnvelopeKind;
use crate::unified_error::DllError;

/// Maximum fragment payload octets targeting 320 payload octets per fragment line (RFC Section 8.4)
pub const DEFAULT_MAX_FRAGMENT_PAYLOAD: usize = 320;

/// Maximum total reassembled payload size: 1 MiB (RFC Section 10.3)
pub const MAX_REASSEMBLED_SIZE: usize = 1_048_576;

/// Reassembly timeout: 120 seconds (RFC Section 10.3)
pub const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(120);

/// Maximum concurrent reassemblies per remote source: 32 (RFC Section 10.3)
pub const MAX_CONCURRENT_REASSEMBLIES_PER_SOURCE: usize = 32;

/// Maximum global concurrent reassemblies across all sources (DoS protection)
pub const MAX_GLOBAL_ASSEMBLIES: usize = 256;

/// Maximum total memory budget for all reassemblies: 8 MiB
pub const MAX_GLOBAL_ASSEMBLY_BYTES: usize = 8 * 1_048_576;

/// Fragment Splitter: converts a payload into a list of IRC lines (either 1 standard line or N fragment lines)
pub fn split_payload(
    kind: EnvelopeKind,
    target_id: &[u8],
    payload: &[u8],
    max_payload_per_fragment: usize,
) -> Vec<String> {
    let standard_line = FcepEnvelope::encode_standard(kind, target_id, payload);

    // If standard line fits under typical line budget (320 payload bytes ~ 512 total line budget), send standard line
    if payload.len() <= max_payload_per_fragment {
        return vec![standard_line];
    }

    // Split payload into chunks
    let chunk_size = max_payload_per_fragment.max(64);
    let chunks: Vec<&[u8]> = payload.chunks(chunk_size).collect();
    let count = chunks.len() as u16;

    let mut object_id = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut object_id);

    let mut lines = Vec::with_capacity(chunks.len());
    for (idx, chunk) in chunks.into_iter().enumerate() {
        let line = FcepEnvelope::encode_fragment(&object_id, idx as u16, count, kind, chunk);
        lines.push(line);
    }

    lines
}

/// Assembly key includes source, object_id AND kind to isolate different object types
/// even if they share the same object_id from the same source.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AssemblyKey {
    transport_source: String,
    object_id: [u8; 16],
    kind: EnvelopeKind,
}

/// Reassembly Engine tracking active fragment assemblies
pub struct ReassemblyEngine {
    assemblies: HashMap<AssemblyKey, AssemblyEntry>,
    /// Total bytes across all assemblies (DoS budget)
    global_bytes: usize,
}

struct AssemblyEntry {
    source_id: String,
    object_id: [u8; 16],
    kind: EnvelopeKind,
    count: u16,
    received_fragments: Vec<Option<Vec<u8>>>,
    total_received_bytes: usize,
    created_at: Instant,
    target_id: Vec<u8>,
}

impl Default for ReassemblyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ReassemblyEngine {
    pub fn new() -> Self {
        Self { assemblies: HashMap::new(), global_bytes: 0 }
    }

    /// Clean up expired assemblies older than 120 seconds
    pub fn cleanup_expired(&mut self) {
        let now = Instant::now();
        let before = self.global_bytes;
        self.assemblies.retain(|_, entry| {
            let keep = now.duration_since(entry.created_at) < REASSEMBLY_TIMEOUT;
            if !keep {
                self.global_bytes = self.global_bytes.saturating_sub(entry.total_received_bytes);
            }
            keep
        });
        // Safety: if retain removed entries, recalculate from scratch to avoid drift
        if self.global_bytes > before {
            self.global_bytes = self.assemblies.values().map(|e| e.total_received_bytes).sum();
        }
    }

    /// Process a received fragment envelope. Returns `Ok(Some(FcepEnvelope::Standard))` when reassembly completes.
    pub fn process_fragment(
        &mut self,
        source_id: &str,
        target_id: &[u8],
        object_id: [u8; 16],
        index: u16,
        count: u16,
        kind: EnvelopeKind,
        fragment_data: Vec<u8>,
    ) -> Result<Option<FcepEnvelope>, DllError> {
        self.cleanup_expired();

        // Reject oversized individual fragments (DoS: a single fragment should fit in IRC line budget)
        if fragment_data.len() > MAX_REASSEMBLED_SIZE {
            return Err(DllError::InvalidInput {
                param: "fragment_size".to_string(),
                reason: "Single fragment exceeds maximum object size".to_string(),
            });
        }

        let key = AssemblyKey { transport_source: source_id.to_string(), object_id, kind };

        // Check source concurrency limit if this is a new assembly
        if !self.assemblies.contains_key(&key) {
            // Check global assembly count limit (DoS protection)
            if self.assemblies.len() >= MAX_GLOBAL_ASSEMBLIES {
                return Err(DllError::InvalidInput {
                    param: "fragment_assembly".to_string(),
                    reason: format!(
                        "Exceeded global max concurrent reassemblies ({})",
                        MAX_GLOBAL_ASSEMBLIES
                    ),
                });
            }

            let active_count =
                self.assemblies.keys().filter(|k| k.transport_source == source_id).count();

            if active_count >= MAX_CONCURRENT_REASSEMBLIES_PER_SOURCE {
                return Err(DllError::InvalidInput {
                    param: "fragment_assembly".to_string(),
                    reason: format!(
                        "Exceeded max concurrent reassemblies ({}) for source {}",
                        MAX_CONCURRENT_REASSEMBLIES_PER_SOURCE, source_id
                    ),
                });
            }

            self.assemblies.insert(
                key.clone(),
                AssemblyEntry {
                    source_id: source_id.to_string(),
                    object_id,
                    kind,
                    count,
                    received_fragments: vec![None; count as usize],
                    total_received_bytes: 0,
                    created_at: Instant::now(),
                    target_id: target_id.to_vec(),
                },
            );
        }

        let entry = self.assemblies.get_mut(&key).unwrap();

        // Validation against existing assembly metadata
        if entry.count != count {
            return Err(DllError::InvalidInput {
                param: "fragment_count".to_string(),
                reason: "Inconsistent count value for active fragment assembly".to_string(),
            });
        }

        if entry.kind != kind {
            return Err(DllError::InvalidInput {
                param: "fragment_kind".to_string(),
                reason: "Inconsistent kind value for active fragment assembly".to_string(),
            });
        }

        let idx = index as usize;
        if entry.received_fragments[idx].is_none() {
            let new_bytes = entry.total_received_bytes + fragment_data.len();

            // Check per-object size limit
            if new_bytes > MAX_REASSEMBLED_SIZE {
                // Remove the broken assembly and free its bytes
                let removed = self.assemblies.remove(&key).unwrap();
                self.global_bytes = self.global_bytes.saturating_sub(removed.total_received_bytes);
                return Err(DllError::InvalidInput {
                    param: "fragment_size".to_string(),
                    reason: "Reassembled object size exceeds 1 MiB limit".to_string(),
                });
            }

            // Check global memory budget (DoS protection)
            if self.global_bytes + fragment_data.len() > MAX_GLOBAL_ASSEMBLY_BYTES {
                return Err(DllError::InvalidInput {
                    param: "fragment_assembly".to_string(),
                    reason: "Global fragment assembly memory budget exceeded".to_string(),
                });
            }

            entry.total_received_bytes = new_bytes;
            self.global_bytes += fragment_data.len();
            entry.received_fragments[idx] = Some(fragment_data);
        }

        // Check if all fragments have arrived
        let is_complete = entry.received_fragments.iter().all(|frag| frag.is_some());

        if is_complete {
            let entry = self.assemblies.remove(&key).unwrap();
            // Free global byte budget
            self.global_bytes = self.global_bytes.saturating_sub(entry.total_received_bytes);
            let mut complete_payload = Vec::with_capacity(entry.total_received_bytes);
            for frag in entry.received_fragments {
                complete_payload.extend_from_slice(&frag.unwrap());
            }

            Ok(Some(FcepEnvelope::Standard {
                kind: entry.kind,
                target_id: entry.target_id,
                payload: complete_payload,
            }))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_and_reassemble() {
        let kind = EnvelopeKind::Application;
        let target_id = vec![1u8; 16];
        let payload = vec![42u8; 1000]; // 1000 bytes > 320 bytes -> will split into 4 fragments

        let lines = split_payload(kind, &target_id, &payload, 300);
        assert_eq!(lines.len(), 4);

        let mut engine = ReassemblyEngine::new();
        let mut final_envelope = None;

        for line in lines {
            let parsed = FcepEnvelope::parse(&line).unwrap();
            if let FcepEnvelope::Fragment { object_id, index, count, kind: k, fragment } = parsed {
                let mut oid = [0u8; 16];
                oid.copy_from_slice(&object_id);
                let res = engine
                    .process_fragment("alice", &target_id, oid, index, count, k, fragment)
                    .unwrap();
                if let Some(env) = res {
                    final_envelope = Some(env);
                }
            }
        }

        assert!(final_envelope.is_some());
        if let FcepEnvelope::Standard { kind: k, target_id: tid, payload: p } =
            final_envelope.unwrap()
        {
            assert_eq!(k, EnvelopeKind::Application);
            assert_eq!(tid, target_id);
            assert_eq!(p, payload);
        }
    }
}
