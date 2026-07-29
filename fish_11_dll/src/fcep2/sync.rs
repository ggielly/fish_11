//! FCEP-2 Synchronization (RFC Section 18) : Pure Transport Retrieval
//!
//! Sync is a transport-level mechanism for retrieving raw MLS Commit bytes
//! from a relay. The relay provides opaque commit data; only OpenMLS on the
//! receiving side decides whether commits are valid and processable.
//!
//! CRITICAL: The relay's epoch counters and member lists are advisory metadata
//! for UI display only. They MUST NEVER be used to modify MLS group state.
//! All state transitions happen exclusively through OpenMLS processing of
//! the raw commit bytes.

use std::collections::HashMap;

use rand::RngCore;

use super::types::{SyncRequest, SyncResponse};
use crate::unified_error::DllError;

/// Maximum commits to include in a single sync response
const MAX_SYNC_COMMITS: usize = 100;

/// A page of sync results with opaque cursor for pagination.
#[derive(Debug, Clone)]
pub struct SyncPage {
    /// Raw TLS-serialized MLS Commit messages, in epoch order.
    pub commits: Vec<Vec<u8>>,
    /// Opaque cursor for pagination. None means no more pages.
    pub next_cursor: Option<Vec<u8>>,
}

/// Source of historical commits for sync responses.
///
/// Implementations should retrieve commits from the relay's persistent store,
/// ordered by epoch and bounded by page limits.
pub trait CommitSource {
    fn fetch_commits(
        &mut self,
        group_id: &[u8],
        known_epoch: u64,
        cursor: Option<&[u8]>,
        max_objects: usize,
        max_bytes: usize,
    ) -> Result<SyncPage, DllError>;
}

/// Resynchronization manager : handles sync request/response lifecycle.
///
/// This manager only tracks pending requests and provides transport-level
/// utilities. It never modifies MLS group state.
pub struct SyncManager {
    /// Pending outbound sync requests (request_id => request data)
    pending_requests: HashMap<[u8; 16], SyncRequest>,
}

impl Default for SyncManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SyncManager {
    pub fn new() -> Self {
        Self { pending_requests: HashMap::new() }
    }

    /// Create a sync request for a group (RFC 18.1).
    ///
    /// Returns the SyncRequest to be serialized and sent as an FCEP-2 'R' envelope.
    pub fn create_sync_request(
        &mut self,
        group_id: Vec<u8>,
        last_known_epoch: u64,
        device_id: [u8; 16],
    ) -> SyncRequest {
        let mut request_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut request_id);

        let req =
            SyncRequest { group_id, last_known_epoch, requester_device_id: device_id, request_id };

        self.pending_requests.insert(request_id, req.clone());
        req
    }

    /// Process an incoming sync request and generate a response (RFC 18.2).
    ///
    /// The response contains raw MLS Commit bytes fetched from a `CommitSource`.
    /// The `current_members` field is advisory (for UI display only).
    pub fn process_sync_request(
        &self,
        req: &SyncRequest,
        source: &mut impl CommitSource,
    ) -> Result<SyncResponse, DllError> {
        let page = source.fetch_commits(
            &req.group_id,
            req.last_known_epoch,
            None,
            MAX_SYNC_COMMITS,
            1_048_576, // 1 MiB max response
        )?;

        Ok(SyncResponse {
            request_id: req.request_id,
            group_id: req.group_id.clone(),
            current_epoch: page
                .commits
                .last()
                .map(|_| req.last_known_epoch + page.commits.len() as u64)
                .unwrap_or(req.last_known_epoch),
            epoch_diff: page.commits,
            // Advisory: empty member list : clients MUST NOT use this for MLS state.
            current_members: Vec::new(),
            responder_device_id: [0u8; 16],
        })
    }

    /// Process a sync response by extracting raw commits for OpenMLS processing.
    ///
    /// This is a transport-level utility : it does NOT modify any MLS state.
    /// The caller (e.g., `GroupActor::apply_sync`) must feed the commits to OpenMLS.
    pub fn process_sync_response(&mut self, resp: &SyncResponse) -> Result<Vec<Vec<u8>>, DllError> {
        // Validate request_id matches a pending request
        if !self.pending_requests.contains_key(&resp.request_id) {
            return Err(DllError::InvalidInput {
                param: "request_id".to_string(),
                reason: "Unknown sync response (no matching pending request)".to_string(),
            });
        }

        self.pending_requests.remove(&resp.request_id);

        if resp.epoch_diff.is_empty() {
            return Ok(Vec::new());
        }

        Ok(resp.epoch_diff.clone())
    }

    /// Check if a sync response is expected (has a pending request with this ID).
    pub fn is_pending(&self, request_id: &[u8; 16]) -> bool {
        self.pending_requests.contains_key(request_id)
    }
}

/// Result of processing a sync response
#[derive(Debug)]
pub enum SyncApplyResult {
    Updated { new_epoch: u64 },
    NoChange,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_sync_request() {
        let mut manager = SyncManager::new();
        let gid = vec![1u8; 16];
        let req = manager.create_sync_request(gid.clone(), 0, [2u8; 16]);
        assert_eq!(req.group_id, gid);
        assert_eq!(req.last_known_epoch, 0);
        assert!(manager.is_pending(&req.request_id));
    }

    #[test]
    fn test_pending_request_tracking() {
        let mut manager = SyncManager::new();
        let req = manager.create_sync_request(vec![3u8; 16], 5, [4u8; 16]);
        assert!(manager.is_pending(&req.request_id));

        // Process a matching response to remove the pending request
        let resp = SyncResponse {
            request_id: req.request_id,
            group_id: vec![3u8; 16],
            current_epoch: 10,
            epoch_diff: vec![],
            current_members: vec![],
            responder_device_id: [0u8; 16],
        };
        let commits = manager.process_sync_response(&resp).unwrap();
        assert!(commits.is_empty());
        assert!(!manager.is_pending(&req.request_id));
    }
}
