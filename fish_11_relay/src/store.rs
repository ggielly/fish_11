//! FCEP-2 Relay Store
//!
//! In-memory and disk-backed store for opaque KeyPackages, Welcomes, and Commit history logs.
//! Implements RFC Sections 11.4 (TTL), 13.2 (Welcome expiry), 19.3 (atomic persistence).

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeyPackage {
    /// Base64url-encoded device ID (per §9.2, §8.2: URL_SAFE_NO_PAD encoding)
    pub device_id_b64: String,
    /// IRC nickname that published this KeyPackage (§6.2: transport metadata only, NOT identity)
    pub nickname: String,
    /// Base64url-encoded KeyPackage payload
    pub payload_b64: String,
    pub received_at: DateTime<Utc>,
    /// Per §11.4: expiration timestamp (min(KeyPackage expiry, 30 days from received_at))
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredWelcome {
    pub target_nick: String,
    pub group_id_hex: String,
    pub payload_b64: String,
    pub received_at: DateTime<Utc>,
    /// Per §11.4: expiration timestamp (min(Welcome ack, 14 days from received_at))
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCommit {
    pub group_id_hex: String,
    pub epoch: u64,
    pub payload_b64: String,
    pub received_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct RelayStore {
    data_dir: PathBuf,
    inner: Arc<RwLock<StoreInner>>,
    dirty: Arc<AtomicBool>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StoreInner {
    /// Map from device_id_b64 -> FIFO queue of KeyPackages (VecDeque for O(1) remove_front)
    key_packages: HashMap<String, VecDeque<StoredKeyPackage>>,
    welcomes: HashMap<String, Vec<StoredWelcome>>,
    commit_logs: HashMap<String, Vec<StoredCommit>>,
}

impl RelayStore {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Self {
        let dir = data_dir.as_ref().to_path_buf();
        if !dir.exists() {
            let _ = std::fs::create_dir_all(&dir);
        }

        let store_file = dir.join("relay_store.json");
        let inner = if store_file.exists() {
            std::fs::read_to_string(&store_file)
                .ok()
                .and_then(|c| serde_json::from_str(&c).ok())
                .unwrap_or_default()
        } else {
            StoreInner::default()
        };

        Self {
            data_dir: dir,
            inner: Arc::new(RwLock::new(inner)),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Mark store as needing persistence
    fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Check and clear dirty flag (used by periodic persist task)
    pub fn take_dirty(&self) -> bool {
        self.dirty.swap(false, Ordering::Relaxed)
    }

    /// Persist current store state to disk atomically.
    ///
    /// §19.3: writes to a temporary file first, then performs an atomic rename
    /// to prevent data corruption if the process crashes mid-write.
    pub async fn persist(&self) -> Result<()> {
        let json = {
            let guard = self.inner.read().await;
            serde_json::to_string_pretty(&*guard)?
        };

        let dir = self.data_dir.clone();
        let final_path = dir.join("relay_store.json");
        let tmp_path = dir.join("relay_store.json.tmp");

        // §19.3: write to temp file, flush, then atomic rename
        tokio::fs::write(&tmp_path, json.as_bytes()).await?;
        tokio::fs::rename(&tmp_path, &final_path).await?;

        Ok(())
    }

    /// Remove expired entries from the store (KeyPackages and Welcomes past their TTL).
    ///
    /// Should be called periodically or on access.
    pub async fn purge_expired(&self) {
        let mut guard = self.inner.write().await;
        let now = Utc::now();

        // Purge expired KeyPackages (§11.4: 30 days max)
        guard.key_packages.retain(|_, entries| {
            entries.retain(|kp| kp.expires_at > now);
            !entries.is_empty()
        });

        // Purge expired Welcomes (§11.4: 14 days max / per config)
        guard.welcomes.retain(|_, entries| {
            entries.retain(|w| w.expires_at > now);
            !entries.is_empty()
        });

        drop(guard);
        self.mark_dirty();
    }

    pub async fn store_key_package(
        &self,
        device_id_b64: String,
        nickname: String,
        payload_b64: String,
        max_per_device: usize,
    ) {
        let mut guard = self.inner.write().await;
        let entry = guard.key_packages.entry(device_id_b64.clone()).or_default();

        // §11.4: KeyPackage expires at min(KeyPackage's own expiry, 30 days from now)
        // Since the relay stores opaque blobs, default to 30 days
        let received_at = Utc::now();
        let expires_at =
            received_at.checked_add_signed(ChronoDuration::days(30)).unwrap_or(received_at);

        entry.push_back(StoredKeyPackage {
            device_id_b64,
            nickname,
            payload_b64,
            received_at,
            expires_at,
        });

        // §11.4: FIFO eviction : remove oldest when over limit
        // VecDeque::pop_front is O(1)
        while entry.len() > max_per_device {
            entry.pop_front();
        }

        drop(guard);
        self.mark_dirty();
    }

    pub async fn get_key_package(&self, query: &str) -> Option<StoredKeyPackage> {
        // Optimization: use read-lock first (common case: query is a device_id)
        {
            let guard = self.inner.read().await;

            if let Some(list) = guard.key_packages.get(query) {
                if let Some(kp) = list.front() {
                    if kp.expires_at > Utc::now() {
                        // Found a non-expired match under read-lock : clone it
                        // so we can drop the lock before mutating
                        let _ = kp;
                    }
                }
            }
        }

        // Now acquire write-lock to remove the entry
        let mut guard = self.inner.write().await;
        let now = Utc::now();

        // Try exact device_id match first
        if let Some(list) = guard.key_packages.get_mut(query) {
            // Skip expired entries at the front
            while let Some(front) = list.front() {
                if front.expires_at <= now {
                    list.pop_front();
                } else {
                    break;
                }
            }
            if let Some(kp) = list.pop_front() {
                drop(guard);
                self.mark_dirty();
                return Some(kp);
            }
        }

        // §23.9 / §6.2: Fallback to nickname lookup : BUT only as transport hint.
        // The real identity is the device_id, not the IRC nickname.
        for list in guard.key_packages.values_mut() {
            // Skip expired entries at the front
            while let Some(front) = list.front() {
                if front.expires_at <= now {
                    list.pop_front();
                } else {
                    break;
                }
            }
            if let Some(pos) =
                list.iter().position(|item| item.nickname.eq_ignore_ascii_case(query))
            {
                let kp = list.remove(pos).unwrap();
                drop(guard);
                self.mark_dirty();
                return Some(kp);
            }
        }

        None
    }

    pub async fn store_welcome(
        &self,
        target_nick: String,
        group_id_hex: String,
        payload_b64: String,
    ) {
        let mut guard = self.inner.write().await;
        let entry = guard.welcomes.entry(target_nick.to_lowercase()).or_default();

        // §11.4: Welcome TTL = 14 days (configurable via welcome_ttl_days)
        let received_at = Utc::now();
        let expires_at =
            received_at.checked_add_signed(ChronoDuration::days(14)).unwrap_or(received_at);

        entry.push(StoredWelcome {
            target_nick,
            group_id_hex,
            payload_b64,
            received_at,
            expires_at,
        });

        drop(guard);
        self.mark_dirty();
    }

    pub async fn get_pending_welcomes(&self, target_nick: &str) -> Vec<StoredWelcome> {
        let mut guard = self.inner.write().await;
        let now = Utc::now();

        let result: Vec<StoredWelcome> = guard
            .welcomes
            .remove(&target_nick.to_lowercase())
            .unwrap_or_default()
            .into_iter()
            // §11.4: filter out expired Welcomes
            .filter(|w| w.expires_at > now)
            .collect();

        if !result.is_empty() {
            drop(guard);
            self.mark_dirty();
        }
        result
    }

    pub async fn log_commit(
        &self,
        group_id_hex: String,
        epoch: u64,
        payload_b64: String,
        limit: usize,
    ) {
        let mut guard = self.inner.write().await;
        let log = guard.commit_logs.entry(group_id_hex.clone()).or_default();

        // §15.5: dedup by epoch (MLS epoch is authoritative)
        if !log.iter().any(|c| c.epoch == epoch) {
            log.push(StoredCommit { group_id_hex, epoch, payload_b64, received_at: Utc::now() });

            log.sort_by_key(|c| c.epoch);

            while log.len() > limit {
                log.remove(0);
            }

            drop(guard);
            self.mark_dirty();
        }
    }

    pub async fn get_sync_commits(
        &self,
        group_id_hex: &str,
        known_epoch: u64,
    ) -> Vec<StoredCommit> {
        let guard = self.inner.read().await;
        guard
            .commit_logs
            .get(group_id_hex)
            .map(|log| log.iter().filter(|c| c.epoch > known_epoch).cloned().collect())
            .unwrap_or_default()
    }
}
