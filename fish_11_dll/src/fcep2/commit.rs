//! FCEP-2 Commit Processing & Staging (RFC Section 15.2)
//!
//! Processes incoming Commits: validates, applies proposals, advances epoch,
//! and detects conflicts when competing commits target the same epoch.

use std::collections::HashMap;

use super::mls_engine::MlsGroupState;
use super::types::{CommitPayload, CommitResult, TrackedCommit};
use super::{CONFLICT_MANAGER, ORDERING_ENGINE};
use crate::unified_error::DllError;

/// Commit processor tracking per-group commit state
pub struct CommitProcessor {
    /// group_id -> last committed epoch
    committed_epochs: HashMap<Vec<u8>, u64>,
}

impl Default for CommitProcessor {
    fn default() -> Self {
        Self::new()
    }
}

impl CommitProcessor {
    pub fn new() -> Self {
        Self { committed_epochs: HashMap::new() }
    }

    /// Process an incoming commit against a group's current state (RFC 15.2)
    pub fn process_commit(
        &mut self,
        commit: &CommitPayload,
        group: &mut MlsGroupState,
        source_nick: &str,
    ) -> Result<CommitResult, DllError> {
        // Validate group_id matches
        if commit.group_id != group.binding.mls_group_id {
            return Ok(CommitResult::Rejected { reason: "Group ID mismatch".to_string() });
        }

        // Validate commit targets the current epoch
        if commit.epoch != group.epoch {
            return Ok(CommitResult::Rejected {
                reason: format!(
                    "Commit epoch {} does not match group epoch {}",
                    commit.epoch, group.epoch
                ),
            });
        }

        // Validate sender is a current member
        if !group.is_member(&commit.sender_device_id) {
            return Ok(CommitResult::Rejected {
                reason: "Sender is not a group member".to_string(),
            });
        }

        // Check for duplicate: same epoch already committed
        if let Some(&last_epoch) = self.committed_epochs.get(&commit.group_id) {
            if last_epoch >= group.epoch {
                // Competing commit detected (RFC 15.3)
                let conflict = super::types::CommitConflict {
                    group_id: commit.group_id.clone(),
                    old_epoch: group.epoch,
                    conflicting_commits: vec![commit.signature.clone()],
                    detected_at_unix: chrono::Utc::now().timestamp(),
                    source_diagnostics: vec![format!("Competing commit from {}", source_nick)],
                };

                CONFLICT_MANAGER.write().trigger_conflict(
                    &commit.group_id,
                    group.epoch,
                    commit.signature.clone(),
                    vec![],
                    format!("Competing commit from {}", source_nick),
                );

                return Ok(CommitResult::Conflict { conflict });
            }
        }

        // Track this commit for ordering (RFC 15.3)
        let hash = super::ordering::compute_commit_hash(commit);
        let tracked = TrackedCommit {
            commit: commit.clone(),
            received_at_unix: chrono::Utc::now().timestamp(),
            source_nick: source_nick.to_string(),
            hash,
        };

        let ordering_result = ORDERING_ENGINE.write().track_commit(tracked);
        if let super::types::OrderingResult::ConflictDetected { commits } = ordering_result {
            let conflict = super::types::CommitConflict {
                group_id: commit.group_id.clone(),
                old_epoch: group.epoch,
                conflicting_commits: commits.iter().map(|c| c.commit.signature.clone()).collect(),
                detected_at_unix: chrono::Utc::now().timestamp(),
                source_diagnostics: commits
                    .iter()
                    .map(|c| format!("from {}", c.source_nick))
                    .collect(),
            };

            CONFLICT_MANAGER.write().trigger_conflict(
                &commit.group_id,
                group.epoch,
                commit.signature.clone(),
                commits[0].commit.signature.clone(),
                format!("Ordering conflict from {}", source_nick),
            );

            return Ok(CommitResult::Conflict { conflict });
        }

        // Apply proposals from the commit
        // (In a real MLS implementation, proposals would be extracted from the commit itself.
        //  Here we use the pending proposal cache which has already been populated.)
        // For now, advance the epoch directly since proposals are applied via ProposalEngine.

        // Advance epoch
        let new_epoch = group.advance_epoch();

        // Record committed epoch
        self.committed_epochs.insert(commit.group_id.clone(), new_epoch);

        Ok(CommitResult::Applied { new_epoch, new_epoch_secret: group.epoch_secret })
    }

    /// Get the last committed epoch for a group
    pub fn last_committed_epoch(&self, group_id: &[u8]) -> Option<u64> {
        self.committed_epochs.get(group_id).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::super::mls_engine::{LocalDevice, MlsGroupState};
    use super::*;

    #[test]
    fn test_process_valid_commit() {
        let mut processor = CommitProcessor::new();
        let alice = LocalDevice::generate("Alice");
        let network_id = [1u8; 32];
        let (mut group, gid) = MlsGroupState::create_group(&alice, network_id, "#test".to_string());

        let commit = CommitPayload {
            group_id: gid.clone(),
            epoch: 1,
            sender_device_id: alice.device_id,
            proposal_ids: vec![],
            signature: vec![],
            created_at_unix: chrono::Utc::now().timestamp(),
        };

        let result = processor.process_commit(&commit, &mut group, "alice").unwrap();
        match result {
            CommitResult::Applied { new_epoch, .. } => assert_eq!(new_epoch, 2),
            _ => panic!("Expected Applied"),
        }
    }

    #[test]
    fn test_reject_wrong_epoch() {
        let mut processor = CommitProcessor::new();
        let alice = LocalDevice::generate("Alice");
        let network_id = [1u8; 32];
        let (mut group, gid) = MlsGroupState::create_group(&alice, network_id, "#test".to_string());

        let commit = CommitPayload {
            group_id: gid,
            epoch: 99,
            sender_device_id: alice.device_id,
            proposal_ids: vec![],
            signature: vec![],
            created_at_unix: chrono::Utc::now().timestamp(),
        };

        let result = processor.process_commit(&commit, &mut group, "alice").unwrap();
        match result {
            CommitResult::Rejected { .. } => {}
            _ => panic!("Expected Rejected"),
        }
    }
}
