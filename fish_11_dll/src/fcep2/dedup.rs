//! FCEP-2 Duplicate Object Detection (RFC Section 17.3)
//!
//! LRU-based deduplication filter for incoming FCEP-2 messages.
//! Prevents processing the same application message, proposal, or commit twice.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use super::types::EnvelopeKind;

/// Default capacity for the dedup filter
const DEFAULT_CAPACITY: usize = 8192;

/// Default TTL for seen fingerprints (5 minutes)
const DEFAULT_TTL: Duration = Duration::from_secs(300);

struct DedupEntry {
    seen_at: Instant,
}

/// LRU-style deduplication filter using timestamp-based eviction
pub struct DeduplicationFilter {
    seen: HashMap<[u8; 32], DedupEntry>,
    capacity: usize,
    ttl: Duration,
}

impl Default for DeduplicationFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl DeduplicationFilter {
    pub fn new() -> Self {
        Self {
            seen: HashMap::with_capacity(DEFAULT_CAPACITY),
            capacity: DEFAULT_CAPACITY,
            ttl: DEFAULT_TTL,
        }
    }

    /// Check if a fingerprint has been seen within the TTL window.
    /// If new, inserts it and returns false. If seen, returns true.
    pub fn is_duplicate(&mut self, fingerprint: &[u8; 32]) -> bool {
        self.cleanup_expired();

        if self.seen.contains_key(fingerprint) {
            return true;
        }

        if self.seen.len() >= self.capacity {
            self.evict_oldest();
        }

        self.seen.insert(*fingerprint, DedupEntry { seen_at: Instant::now() });
        false
    }

    /// Compute a deterministic fingerprint for a message (RFC 17.3).
    /// fingerprint = SHA-256(kind_char || group_id || epoch_be || sender_id || nonce_or_hash)
    pub fn compute_fingerprint(
        kind: EnvelopeKind,
        group_id: &[u8],
        epoch: u64,
        sender_id: &[u8; 16],
        nonce_or_hash: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update([kind.to_char() as u8]);
        hasher.update(group_id);
        hasher.update(epoch.to_be_bytes());
        hasher.update(sender_id);
        hasher.update(nonce_or_hash);
        hasher.finalize().into()
    }

    fn cleanup_expired(&mut self) {
        let now = Instant::now();
        self.seen.retain(|_, entry| now.duration_since(entry.seen_at) < self.ttl);
    }

    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self.seen.iter().min_by_key(|(_, e)| e.seen_at).map(|(k, _)| *k) {
            self.seen.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_determinism() {
        let fp1 = DeduplicationFilter::compute_fingerprint(
            EnvelopeKind::Application,
            &[1, 2, 3],
            42,
            &[5u8; 16],
            &[6, 7, 8],
        );
        let fp2 = DeduplicationFilter::compute_fingerprint(
            EnvelopeKind::Application,
            &[1, 2, 3],
            42,
            &[5u8; 16],
            &[6, 7, 8],
        );
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_fingerprint_different_inputs() {
        let fp1 = DeduplicationFilter::compute_fingerprint(
            EnvelopeKind::Application,
            &[1, 2, 3],
            42,
            &[5u8; 16],
            &[6, 7, 8],
        );
        let fp2 = DeduplicationFilter::compute_fingerprint(
            EnvelopeKind::Commit,
            &[1, 2, 3],
            42,
            &[5u8; 16],
            &[6, 7, 8],
        );
        assert_ne!(fp1, fp2);
    }

    #[test]
    fn test_dedup_first_seen_not_duplicate() {
        let mut filter = DeduplicationFilter::new();
        let fp = [1u8; 32];
        assert!(!filter.is_duplicate(&fp));
    }

    #[test]
    fn test_dedup_second_seen_is_duplicate() {
        let mut filter = DeduplicationFilter::new();
        let fp = [2u8; 32];
        assert!(!filter.is_duplicate(&fp));
        assert!(filter.is_duplicate(&fp));
    }
}
