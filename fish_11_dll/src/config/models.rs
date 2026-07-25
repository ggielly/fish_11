//! Data models for the configuration system

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of previous ratchet keys to retain.
///
/// This window allows decryption of out-of-order messages while maintaining
/// forward secrecy. A window of 2 keys provides tolerance for typical IRC
/// network conditions (reordering, lag) while significantly improving security.
///
/// Security trade-off: Larger window = better reliability but slower FS.
/// Reduced from 5 to 2 keys to minimize the attack surface in case of memory compromise.
/// This means only the 2 most recent previous keys are kept, limiting the exposure
/// window while still handling most common out-of-order message scenarios.
const MAX_PREVIOUS_KEYS: usize = 2;

/// Maximum number of nonces to cache per channel for replay detection.
///
/// Each nonce is 12 bytes. A cache of 100 nonces provides:
/// - Memory: 1.2 KB per channel
/// - Protection window: ~100 messages (depends on traffic)
///
/// Security trade-off: larger cache = longer replay protection but more memory.
const MAX_NONCE_CACHE_SIZE: usize = 100;

/// Data for an entry (user or channel)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EntryData {
    pub key: Option<String>,
    pub date: Option<String>,
    pub is_exchange: Option<bool>,
}

/// Configuration for FiSH11 settings
#[derive(PartialEq, Debug, Clone)]
pub struct Fish11Section {
    pub nickname: String,
    pub process_incoming: bool,
    pub process_outgoing: bool,
    pub plain_prefix: String,
    pub encrypt_notice: bool,
    pub encrypt_action: bool,
    pub mark_position: u8,
    pub mark_encrypted: String,
    pub no_fish10_legacy: bool,
    pub key_ttl: Option<i64>,
    pub encryption_prefix: String,
    pub fish_prefix: bool,
}

impl Default for Fish11Section {
    fn default() -> Self {
        Self {
            nickname: String::new(),
            process_incoming: true,
            process_outgoing: true,
            plain_prefix: "+p ".to_string(),
            encrypt_notice: false,
            encrypt_action: false,
            mark_position: 1,
            mark_encrypted: " 12$chr(183)".to_string(),
            no_fish10_legacy: false,
            key_ttl: None, // None means use default (86400 seconds)
            encryption_prefix: "+FiSH".to_string(),
            fish_prefix: false,
        }
    }
}

/// Startup data section
#[derive(PartialEq, Debug, Clone)]
pub struct StartupSection {
    pub date: Option<u64>,
}

impl Default for StartupSection {
    fn default() -> Self {
        Self { date: None }
    }
}

/// Holds the state for a channel's symmetric key ratchet.
#[derive(PartialEq, Debug, Clone)]
pub struct RatchetState {
    pub current_key: [u8; 32],
    pub epoch: u64,
    // A small window of previous keys to handle out-of-order messages
    pub previous_keys: VecDeque<[u8; 32]>,
}

impl RatchetState {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            current_key: initial_key,
            epoch: 0,
            previous_keys: VecDeque::with_capacity(MAX_PREVIOUS_KEYS),
        }
    }

    pub fn advance(&mut self, next_key: [u8; 32]) {
        use zeroize::Zeroize;

        if self.previous_keys.len() == MAX_PREVIOUS_KEYS {
            // Zeroize the oldest key before dropping it
            if let Some(mut old_key) = self.previous_keys.pop_front() {
                old_key.zeroize();
            }
        }
        self.previous_keys.push_back(self.current_key);
        self.current_key = next_key;
        self.epoch += 1;
    }
}

/// Holds a cache of recently seen nonces to prevent replay attacks.
#[derive(PartialEq, Debug, Clone)]
pub struct NonceCache {
    pub recent_nonces: VecDeque<[u8; 12]>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self { recent_nonces: VecDeque::with_capacity(MAX_NONCE_CACHE_SIZE) }
    }

    pub fn check_and_add(&mut self, nonce: [u8; 12]) -> bool {
        if self.recent_nonces.contains(&nonce) {
            return true; // Nonce is a duplicate
        }
        if self.recent_nonces.len() == MAX_NONCE_CACHE_SIZE {
            self.recent_nonces.pop_front();
        }
        self.recent_nonces.push_back(nonce);
        false // Nonce is new
    }
}

/// Metrics for tracking encryption operations
#[derive(PartialEq, Debug, Clone, Default)]
pub struct EncryptionMetrics {
    /// Number of encryption operations performed
    pub encryption_count: usize,
    /// Number of decryption operations performed
    pub decryption_count: usize,
    /// Number of key exchange operations performed
    pub key_exchange_count: usize,
}

/// Main configuration struct
pub struct FishConfig {
    pub keys: HashMap<String, String>,
    pub nick_networks: HashMap<String, String>,
    pub our_private_key: Option<String>,
    pub our_public_key: Option<String>,
    pub keypair_creation_time: Option<String>,
    pub fish11: Fish11Section,
    pub startup_data: StartupSection,
    pub entries: HashMap<String, EntryData>,
    pub channel_keys: HashMap<String, Vec<u8>>,
    pub channel_ratchet_states: HashMap<String, RatchetState>,
    pub channel_nonce_caches: HashMap<String, NonceCache>,
    pub topics: HashMap<String, String>,
    pub metrics: EncryptionMetrics,
    dirty: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for FishConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FishConfig")
            .field("keys", &self.keys)
            .field("nick_networks", &self.nick_networks)
            .field("our_private_key", &self.our_private_key)
            .field("our_public_key", &self.our_public_key)
            .field("fish11", &self.fish11)
            .field("startup_data", &self.startup_data)
            .field("entries", &self.entries)
            .field("metrics", &self.metrics)
            .finish()
    }
}

impl Clone for FishConfig {
    fn clone(&self) -> Self {
        Self {
            keys: self.keys.clone(),
            nick_networks: self.nick_networks.clone(),
            our_private_key: self.our_private_key.clone(),
            our_public_key: self.our_public_key.clone(),
            keypair_creation_time: self.keypair_creation_time.clone(),
            fish11: self.fish11.clone(),
            startup_data: self.startup_data.clone(),
            entries: self.entries.clone(),
            channel_keys: self.channel_keys.clone(),
            channel_ratchet_states: self.channel_ratchet_states.clone(),
            channel_nonce_caches: self.channel_nonce_caches.clone(),
            topics: self.topics.clone(),
            metrics: self.metrics.clone(),
            dirty: std::sync::atomic::AtomicBool::new(self.is_dirty()),
        }
    }
}

impl PartialEq for FishConfig {
    fn eq(&self, other: &Self) -> bool {
        self.keys == other.keys
            && self.nick_networks == other.nick_networks
            && self.our_private_key == other.our_private_key
            && self.our_public_key == other.our_public_key
            && self.keypair_creation_time == other.keypair_creation_time
            && self.fish11 == other.fish11
            && self.startup_data == other.startup_data
            && self.entries == other.entries
            && self.channel_keys == other.channel_keys
            && self.channel_ratchet_states == other.channel_ratchet_states
            && self.channel_nonce_caches == other.channel_nonce_caches
            && self.topics == other.topics
            && self.metrics == other.metrics
    }
}

impl FishConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        let mut startup_data = StartupSection::default();
        startup_data.date =
            Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
        Self {
            keys: HashMap::new(),
            nick_networks: HashMap::new(),
            our_private_key: None,
            our_public_key: None,
            keypair_creation_time: None,
            fish11: Fish11Section::default(),
            startup_data,
            entries: HashMap::new(),
            channel_keys: HashMap::new(),
            channel_ratchet_states: HashMap::new(),
            channel_nonce_caches: HashMap::new(),
            topics: HashMap::new(),
            metrics: EncryptionMetrics::default(),
            dirty: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Mark the configuration as dirty (needs saving)
    pub fn mark_dirty(&self) {
        self.dirty.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn mark_clean(&self) {
        self.dirty.store(false, std::sync::atomic::Ordering::Relaxed);
    }

    /// Get an entry from the configuration (convenience method)
    pub fn get_entry(&self, key: &str) -> Option<&EntryData> {
        self.entries.get(key)
    }

    /// Set an entry in the configuration (convenience method)
    pub fn set_entry(&mut self, key: String, entry: EntryData) {
        self.entries.insert(key, entry);
        self.mark_dirty();
    }

    /// Get all entries with a specific prefix
    pub fn get_entries_with_prefix(&self, prefix: &str) -> Vec<(String, &EntryData)> {
        self.entries
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, data)| (key.clone(), data))
            .collect()
    }
}
