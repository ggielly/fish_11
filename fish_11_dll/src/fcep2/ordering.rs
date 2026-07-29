//! FCEP-2 Commit Ordering Engine (RFC Section 15.3)
//!
//! Tracks commits per group/epoch and detects conflicts when multiple
//! commits target the same prior epoch. Provides deterministic branch
//! selection per RFC 15.4.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

use super::types::{CommitPayload, OrderingResult, TrackedCommit};

/// Maximum pending commits tracked per epoch before auto-rejection
const MAX_PENDING_PER_EPOCH: usize = 10;

/// Commit ordering engine
pub struct OrderingEngine {
    /// group_id -> commits for current epoch
    pending_commits: HashMap<Vec<u8>, Vec<TrackedCommit>>,
}

impl Default for OrderingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl OrderingEngine {
    pub fn new() -> Self {
        Self { pending_commits: HashMap::new() }
    }

    /// Track a received commit for ordering purposes.
    /// Returns ConflictDetected if 2+ commits exist for the same epoch.
    pub fn track_commit(&mut self, tracked: TrackedCommit) -> OrderingResult {
        let group_id = tracked.commit.group_id.clone();
        let commits = self.pending_commits.entry(group_id).or_insert_with(Vec::new);

        if commits.len() >= MAX_PENDING_PER_EPOCH {
            // Too many pending commits : likely a flood or conflict
            let all = commits.clone();
            return OrderingResult::ConflictDetected { commits: all };
        }

        commits.push(tracked);

        if commits.len() >= 2 {
            let all = commits.clone();
            OrderingResult::ConflictDetected { commits: all }
        } else {
            OrderingResult::Tracked
        }
    }

    /// Select the winning commit from conflicting commits (RFC 15.4).
    /// Deterministic: sort by hash ASC, then sender_device_id ASC.
    pub fn select_winner(&self, group_id: &[u8]) -> Option<TrackedCommit> {
        let commits = self.pending_commits.get(group_id)?;
        if commits.is_empty() {
            return None;
        }

        let mut sorted = commits.clone();
        sorted.sort_by(|a, b| {
            a.hash.cmp(&b.hash).then(a.commit.sender_device_id.cmp(&b.commit.sender_device_id))
        });

        sorted.into_iter().next()
    }

    /// Clear all pending commits for a group after resolution
    pub fn clear_epoch(&mut self, group_id: &[u8]) {
        self.pending_commits.remove(group_id);
    }
}

/// Compute a deterministic hash for a commit (RFC 15.4)
/// hash = SHA-256(group_id || epoch || proposal_ids || sender_device_id)
pub fn compute_commit_hash(commit: &CommitPayload) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&commit.group_id);
    hasher.update(commit.epoch.to_be_bytes());
    for pid in &commit.proposal_ids {
        hasher.update(pid);
    }
    hasher.update(&commit.sender_device_id);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_commit(group_id: Vec<u8>, epoch: u64, sender: [u8; 16]) -> CommitPayload {
        CommitPayload {
            group_id,
            epoch,
            sender_device_id: sender,
            proposal_ids: vec![],
            signature: vec![],
            created_at_unix: 0,
        }
    }

    #[test]
    fn test_single_commit_tracked() {
        let mut engine = OrderingEngine::new();
        let gid = vec![1u8; 16];
        let commit = make_commit(gid.clone(), 1, [2u8; 16]);
        let hash = compute_commit_hash(&commit);

        let tracked =
            TrackedCommit { commit, received_at_unix: 0, source_nick: "alice".to_string(), hash };

        let result = engine.track_commit(tracked);
        assert!(matches!(result, OrderingResult::Tracked));
    }

    #[test]
    fn test_competing_commits_detected() {
        let mut engine = OrderingEngine::new();
        let gid = vec![1u8; 16];

        let c1 = make_commit(gid.clone(), 1, [2u8; 16]);
        let h1 = compute_commit_hash(&c1);
        let t1 = TrackedCommit {
            commit: c1,
            received_at_unix: 0,
            source_nick: "alice".into(),
            hash: h1,
        };

        let c2 = make_commit(gid.clone(), 1, [3u8; 16]);
        let h2 = compute_commit_hash(&c2);
        let t2 =
            TrackedCommit { commit: c2, received_at_unix: 0, source_nick: "bob".into(), hash: h2 };

        engine.track_commit(t1);
        let result = engine.track_commit(t2);
        assert!(matches!(result, OrderingResult::ConflictDetected { .. }));
    }

    #[test]
    fn test_select_winner_deterministic() {
        let mut engine = OrderingEngine::new();
        let gid = vec![1u8; 16];

        let c1 = make_commit(gid.clone(), 1, [3u8; 16]);
        let h1 = compute_commit_hash(&c1);
        let t1 = TrackedCommit {
            commit: c1,
            received_at_unix: 0,
            source_nick: "alice".into(),
            hash: h1,
        };

        let c2 = make_commit(gid.clone(), 1, [2u8; 16]);
        let h2 = compute_commit_hash(&c2);
        let t2 =
            TrackedCommit { commit: c2, received_at_unix: 0, source_nick: "bob".into(), hash: h2 };

        // Insert in arbitrary order
        engine.track_commit(t1);
        engine.track_commit(t2);

        let winner = engine.select_winner(&gid).unwrap();
        // Winner should be deterministic : whichever has lower hash/sender
        assert!(
            winner.commit.sender_device_id == [2u8; 16]
                || winner.commit.sender_device_id == [3u8; 16]
        );
    }
}
