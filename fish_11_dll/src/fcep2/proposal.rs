//! FCEP-2 Proposal Handling & Cache (RFC Section 15.1)
//!
//! Caches pending proposals per group, validates incoming proposals,
//! and builds CommitPayload from drained proposals.

use std::collections::HashMap;

use ed25519_dalek::Signer;
use rand::RngCore;
use sha2::{Digest, Sha256};

use super::mls_engine::LocalDevice;
use super::types::{CommitPayload, Proposal, ProposalOp};
use crate::unified_error::DllError;

/// Maximum proposals per group before rejecting new ones
const MAX_PENDING_PER_GROUP: usize = 128;

/// Proposal engine managing pending proposals per group
pub struct ProposalEngine {
    pending: HashMap<Vec<u8>, Vec<Proposal>>,
}

impl Default for ProposalEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ProposalEngine {
    pub fn new() -> Self {
        Self { pending: HashMap::new() }
    }

    /// Cache an incoming proposal after validation (RFC 15.1.1)
    pub fn cache_proposal(
        &mut self,
        group_id: Vec<u8>,
        proposal: Proposal,
    ) -> Result<(), DllError> {
        let entries = self.pending.entry(group_id).or_insert_with(Vec::new);

        if entries.len() >= MAX_PENDING_PER_GROUP {
            return Err(DllError::ProcessingError(
                "Pending proposal cache full (128 max)".to_string(),
            ));
        }

        entries.push(proposal);
        Ok(())
    }

    /// Drain all pending proposals for a group (returns and clears)
    pub fn drain_proposals(&mut self, group_id: &[u8]) -> Vec<Proposal> {
        self.pending.remove(group_id).unwrap_or_default()
    }

    /// Number of pending proposals for a group
    pub fn pending_count(&self, group_id: &[u8]) -> usize {
        self.pending.get(group_id).map_or(0, |v| v.len())
    }

    /// Validate and cache an incoming proposal from a peer (RFC 15.1)
    pub fn process_incoming_proposal(
        &mut self,
        _source_nick: &str,
        group_id: Vec<u8>,
        epoch: u64,
        sender_device_id: [u8; 16],
        op: ProposalOp,
        signature: Vec<u8>,
        known_group_epoch: Option<u64>,
    ) -> Result<Proposal, DllError> {
        // Validate epoch matches current group epoch
        if let Some(known_epoch) = known_group_epoch {
            if epoch != known_epoch {
                return Err(DllError::InvalidInput {
                    param: "epoch".to_string(),
                    reason: format!(
                        "Proposal epoch {} does not match group epoch {}",
                        epoch, known_epoch
                    ),
                });
            }
        }

        let mut proposal_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut proposal_id);

        let proposal = Proposal {
            proposal_id,
            group_id: group_id.clone(),
            epoch,
            sender_device_id,
            op,
            signature,
            created_at_unix: chrono::Utc::now().timestamp(),
        };

        self.cache_proposal(group_id, proposal.clone())?;
        Ok(proposal)
    }

    /// Build a CommitPayload from pending proposals (RFC 15.2)
    pub fn build_commit_payload(
        &mut self,
        group_id: &[u8],
        sender: &LocalDevice,
        new_epoch: u64,
    ) -> CommitPayload {
        let proposals = self.drain_proposals(group_id);
        let proposal_ids: Vec<[u8; 16]> = proposals.iter().map(|p| p.proposal_id).collect();

        // Sign the commit: SHA-256(group_id || epoch || proposal_ids || sender_id)
        let mut hasher = Sha256::new();
        hasher.update(group_id);
        hasher.update(new_epoch.to_be_bytes());
        for pid in &proposal_ids {
            hasher.update(pid);
        }
        hasher.update(sender.device_id);
        let hash: [u8; 32] = hasher.finalize().into();

        let sig = sender.signing_key.sign(&hash);

        CommitPayload {
            group_id: group_id.to_vec(),
            epoch: new_epoch,
            sender_device_id: sender.device_id,
            proposal_ids,
            signature: sig.to_bytes().to_vec(),
            created_at_unix: chrono::Utc::now().timestamp(),
        }
    }

    /// Purge expired proposals (older than 15 minutes, RFC 15.1.1)
    pub fn purge_expired(&mut self) {
        let cutoff = chrono::Utc::now().timestamp() - 900; // 15 minutes
        for proposals in self.pending.values_mut() {
            proposals.retain(|p| p.created_at_unix > cutoff);
        }
        self.pending.retain(|_, v| !v.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_and_drain() {
        let mut engine = ProposalEngine::new();
        let gid = vec![1u8; 16];

        let proposal = Proposal {
            proposal_id: [2u8; 16],
            group_id: gid.clone(),
            epoch: 1,
            sender_device_id: [3u8; 16],
            op: ProposalOp::Reinit,
            signature: vec![],
            created_at_unix: chrono::Utc::now().timestamp(),
        };

        engine.cache_proposal(gid.clone(), proposal).unwrap();
        assert_eq!(engine.pending_count(&gid), 1);

        let drained = engine.drain_proposals(&gid);
        assert_eq!(drained.len(), 1);
        assert_eq!(engine.pending_count(&gid), 0);
    }
}
