//! FCEP-2 Deferred Delivery Cache (RFC Section 13.3)
//!
//! Bounded in-memory cache for objects arriving before the corresponding
//! Welcome has been processed. Limited to 64 entries, 5-minute TTL.

use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;

use super::types::{DeferredEntry, EnvelopeKind};
use crate::unified_error::DllError;

/// Maximum entries in the deferred cache
const MAX_ENTRIES: usize = 64;

/// Maximum age of deferred entries in seconds (5 minutes)
const MAX_AGE_SECS: i64 = 300;

/// Deferred delivery cache for objects targeting unknown groups
pub struct DeferredCache {
    entries: Vec<DeferredEntry>,
}

impl Default for DeferredCache {
    fn default() -> Self {
        Self::new()
    }
}

impl DeferredCache {
    pub fn new() -> Self {
        Self { entries: Vec::with_capacity(MAX_ENTRIES) }
    }

    /// Enqueue an object for deferred delivery.
    /// Returns the entry_id assigned to this deferred object.
    pub fn enqueue(
        &mut self,
        group_id: Vec<u8>,
        kind: EnvelopeKind,
        payload: Vec<u8>,
        source_nick: &str,
        target_id: Vec<u8>,
    ) -> Result<[u8; 16], DllError> {
        self.cleanup_expired();

        if self.entries.len() >= MAX_ENTRIES {
            // Evict oldest entry
            self.entries.remove(0);
        }

        let mut entry_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut entry_id);

        let entry = DeferredEntry {
            entry_id,
            group_id,
            kind,
            payload,
            source_nick: source_nick.to_string(),
            created_at_unix: now_unix(),
            target_id,
        };

        self.entries.push(entry);
        Ok(entry_id)
    }

    /// Drain all deferred entries for a specific group.
    /// Returns entries sorted by creation time (IRC receipt order).
    pub fn drain_for_group(&mut self, group_id: &[u8]) -> Vec<DeferredEntry> {
        let mut drained: Vec<DeferredEntry> = Vec::new();
        let mut remaining: Vec<DeferredEntry> = Vec::new();

        for entry in self.entries.drain(..) {
            if entry.group_id == group_id {
                drained.push(entry);
            } else {
                remaining.push(entry);
            }
        }

        self.entries = remaining;
        drained.sort_by_key(|e| e.created_at_unix);
        drained
    }

    /// Remove expired entries
    pub fn cleanup_expired(&mut self) {
        let cutoff = now_unix() - MAX_AGE_SECS;
        self.entries.retain(|e| e.created_at_unix > cutoff);
    }

    /// Number of currently cached entries
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }
}

fn now_unix() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_enqueue_and_drain() {
        let mut cache = DeferredCache::new();
        let gid = vec![1u8; 16];

        let _id1 = cache
            .enqueue(gid.clone(), EnvelopeKind::Commit, vec![10], "alice", gid.clone())
            .unwrap();
        let _id2 = cache
            .enqueue(gid.clone(), EnvelopeKind::Application, vec![20], "bob", gid.clone())
            .unwrap();
        assert_eq!(cache.pending_count(), 2);

        let drained = cache.drain_for_group(&gid);
        assert_eq!(drained.len(), 2);
        assert_eq!(cache.pending_count(), 0);
    }

    #[test]
    fn test_drain_only_target_group() {
        let mut cache = DeferredCache::new();
        let gid1 = vec![1u8; 16];
        let gid2 = vec![2u8; 16];

        cache.enqueue(gid1.clone(), EnvelopeKind::Commit, vec![10], "alice", gid1.clone()).unwrap();
        cache.enqueue(gid2.clone(), EnvelopeKind::Commit, vec![20], "bob", gid2.clone()).unwrap();

        let drained = cache.drain_for_group(&gid1);
        assert_eq!(drained.len(), 1);
        assert_eq!(cache.pending_count(), 1);
    }

    #[test]
    fn test_evicts_oldest_when_full() {
        let mut cache = DeferredCache::new();
        for i in 0..MAX_ENTRIES {
            let gid = vec![i as u8; 16];
            cache
                .enqueue(gid.clone(), EnvelopeKind::Application, vec![i as u8], "nick", gid)
                .unwrap();
        }
        // Should still be at capacity
        assert_eq!(cache.pending_count(), MAX_ENTRIES);

        // Adding one more evicts oldest
        let extra_gid = vec![99u8; 16];
        cache
            .enqueue(extra_gid.clone(), EnvelopeKind::Application, vec![99], "nick", extra_gid)
            .unwrap();
        assert_eq!(cache.pending_count(), MAX_ENTRIES);
    }
}
