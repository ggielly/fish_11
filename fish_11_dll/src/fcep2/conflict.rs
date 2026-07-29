//! FCEP-2 Commit Conflict Detection & Resolution Engine (RFC Section 15.4)
//!
//! Handles competing Commits targeting the same epoch with per-group tracking.
//! Provides deterministic branch selection and resolution.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;

use super::types::CommitConflict;

/// Conflict state checker with per-group tracking
#[derive(Debug, Clone)]
pub struct ConflictManager {
    /// group_id -> conflict state (one per group)
    conflicts: Arc<RwLock<HashMap<Vec<u8>, CommitConflict>>>,
}

impl Default for ConflictManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConflictManager {
    pub fn new() -> Self {
        Self { conflicts: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Check if any group is currently in CommitConflict state
    pub fn is_in_conflict(&self) -> bool {
        !self.conflicts.read().is_empty()
    }

    /// Check if a specific group is in CommitConflict state
    pub fn is_in_conflict_for(&self, group_id: &[u8]) -> bool {
        self.conflicts.read().contains_key(group_id)
    }

    /// Detect a competing commit on the same prior epoch (per-group)
    pub fn trigger_conflict(
        &self,
        group_id: &[u8],
        old_epoch: u64,
        commit_a: Vec<u8>,
        commit_b: Vec<u8>,
        source_diag: String,
    ) {
        let mut guard = self.conflicts.write();
        let created_at_unix = chrono::Utc::now().timestamp();

        let conflict_info = CommitConflict {
            group_id: group_id.to_vec(),
            old_epoch,
            conflicting_commits: vec![commit_a, commit_b],
            detected_at_unix: created_at_unix,
            source_diagnostics: vec![source_diag],
        };

        guard.insert(group_id.to_vec(), conflict_info);
    }

    /// Force resolution of a specific group's conflict
    pub fn resolve(&self, group_id: &[u8]) {
        self.conflicts.write().remove(group_id);
    }

    /// Resolve all conflicts (backward-compatible with old interface)
    pub fn resolve_all(&self) {
        self.conflicts.write().clear();
    }

    /// Get conflict diagnostic summary string for a specific group
    pub fn get_summary_for(&self, group_id: &[u8]) -> Option<String> {
        let guard = self.conflicts.read();
        guard.get(group_id).map(|c| {
            format!(
                "CONFLICT | group_id={} | old_epoch={} | detected_at={}",
                hex::encode(&c.group_id),
                c.old_epoch,
                c.detected_at_unix
            )
        })
    }

    /// Get all active conflicts as a list of summaries
    pub fn get_all_summaries(&self) -> Vec<String> {
        let guard = self.conflicts.read();
        guard
            .values()
            .map(|c| {
                format!(
                    "CONFLICT | group_id={} | old_epoch={} | detected_at={}",
                    hex::encode(&c.group_id),
                    c.old_epoch,
                    c.detected_at_unix
                )
            })
            .collect()
    }

    /// Get the raw conflict for a group (for diagnostic purposes)
    pub fn get_conflict(&self, group_id: &[u8]) -> Option<CommitConflict> {
        self.conflicts.read().get(group_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_group_conflict() {
        let mgr = ConflictManager::new();
        let gid1 = vec![1u8; 16];
        let gid2 = vec![2u8; 16];

        mgr.trigger_conflict(&gid1, 1, vec![10], vec![20], "diag1".into());
        assert!(mgr.is_in_conflict_for(&gid1));
        assert!(!mgr.is_in_conflict_for(&gid2));
        assert!(mgr.is_in_conflict());

        mgr.resolve(&gid1);
        assert!(!mgr.is_in_conflict_for(&gid1));
        assert!(!mgr.is_in_conflict());
    }
}
