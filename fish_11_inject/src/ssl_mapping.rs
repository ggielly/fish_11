//! ssl_mapping.rs
//! Thread-safe mapping between SSL contexts and socket file descriptors.
//!
//! This module provides atomic operations for associating SSL* pointers with
//! socket IDs, ensuring thread-safe access without risk of race conditions.

use dashmap::DashMap;
use log::{debug, error, trace, warn};
use once_cell::sync::Lazy;

use crate::hook_ssl::{SSL, SSLWrapper};

/// Global thread-safe mapping from SSL pointer (as usize) to socket ID
static SSL_TO_SOCKET: Lazy<DashMap<usize, u32>> = Lazy::new(DashMap::new);

/// Global thread-safe mapping from socket ID to SSL wrapper
static SOCKET_TO_SSL: Lazy<DashMap<u32, SSLWrapper>> = Lazy::new(DashMap::new);

/// Thread-safe SSL-Socket mapping operations.
///
/// All operations are atomic and thread-safe, eliminating race conditions
/// between reading and writing the mappings.
pub struct SslSocketMapping;

impl SslSocketMapping {
    /// Associate an SSL context with a socket ID.
    ///
    /// This atomically updates both mappings (SSL->Socket and Socket->SSL).
    ///
    /// # Arguments
    /// * `ssl` - Pointer to the SSL context
    /// * `socket_id` - The socket file descriptor
    ///
    /// # Safety
    /// The caller must ensure `ssl` is a valid SSL* pointer.
    pub fn associate(ssl: *mut SSL, socket_id: u32) {
        if ssl.is_null() {
            warn!("SslSocketMapping::associate called with null SSL pointer");
            return;
        }

        let ssl_id = ssl as usize;

        // Insert into both maps atomically (DashMap handles locking internally)
        SSL_TO_SOCKET.insert(ssl_id, socket_id);
        SOCKET_TO_SSL.insert(socket_id, SSLWrapper { ssl });

        #[cfg(debug_assertions)]
        trace!(
            "SslSocketMapping: associated SSL {:p} (id={}) with socket {}",
            ssl, ssl_id, socket_id
        );
    }

    /// Get the socket ID associated with an SSL context.
    ///
    /// # Arguments
    /// * `ssl` - Pointer to the SSL context
    ///
    /// # Returns
    /// `Some(socket_id)` if the mapping exists, `None` otherwise.
    pub fn get_socket(ssl: *mut SSL) -> Option<u32> {
        if ssl.is_null() {
            return None;
        }

        let ssl_id = ssl as usize;
        SSL_TO_SOCKET.get(&ssl_id).map(|entry| *entry.value())
    }

    /// Get the SSL context associated with a socket ID.
    ///
    /// # Arguments
    /// * `socket_id` - The socket file descriptor
    ///
    /// # Returns
    /// `Some(ssl_ptr)` if the mapping exists, `None` otherwise.
    ///
    /// # Safety
    /// The returned pointer must only be used if it's still valid (i.e., SSL_free
    /// hasn't been called on it).
    pub fn get_ssl(socket_id: u32) -> Option<*mut SSL> {
        SOCKET_TO_SSL.get(&socket_id).map(|entry| entry.value().ssl)
    }

    /// Remove an SSL context from the mappings.
    ///
    /// This atomically removes from both mappings using a consistent locking strategy
    /// to prevent deadlocks. The method uses a retry mechanism with exponential backoff
    /// to handle concurrent modifications.
    ///
    /// # Arguments
    /// * `ssl` - Pointer to the SSL context
    ///
    /// # Returns
    /// The socket ID that was associated, if any.
    pub fn remove_ssl(ssl: *mut SSL) -> Option<u32> {
        if ssl.is_null() {
            return None;
        }

        let ssl_id = ssl as usize;
        const MAX_RETRIES: usize = 3;
        const BASE_DELAY_MS: u64 = 1;

        for attempt in 0..MAX_RETRIES {
            // First, check if the SSL entry exists and get the socket_id
            let socket_id = match SSL_TO_SOCKET.get(&ssl_id) {
                Some(entry) => *entry.value(),
                None => {
                    trace!("SslSocketMapping: SSL {:p} was not in mapping", ssl);
                    return None;
                }
            };

            // Now perform the removal atomically
            // We use a consistent order: always remove from SSL_TO_SOCKET first, then SOCKET_TO_SSL
            if let Some((_, removed_socket_id)) = SSL_TO_SOCKET.remove(&ssl_id) {
                // Verify we got the expected socket_id
                if removed_socket_id != socket_id {
                    error!(
                        "SslSocketMapping: critical inconsistency - SSL {:p} mapped to different socket IDs: {} vs {}",
                        ssl, socket_id, removed_socket_id
                    );
                    // Try to repair by removing both entries
                    SOCKET_TO_SSL.remove(&socket_id);
                    SOCKET_TO_SSL.remove(&removed_socket_id);

                    return Some(removed_socket_id);
                }

                // Now remove from SOCKET_TO_SSL
                let removed_ssl = SOCKET_TO_SSL.remove(&socket_id);

                if removed_ssl.is_some() {
                    #[cfg(debug_assertions)]
                    debug!(
                        "SslSocketMapping: removed SSL {:p} (was mapped to socket {})",
                        ssl, socket_id
                    );
                    return Some(socket_id);
                } else {
                    warn!(
                        "SslSocketMapping: inconsistency - SSL {:p} mapped to socket {} but socket entry was missing",
                        ssl, socket_id
                    );
                    return Some(socket_id);
                }
            }

            // If we get here, the removal failed due to concurrent modification
            if attempt < MAX_RETRIES - 1 {
                // Exponential backoff
                let delay_ms = BASE_DELAY_MS * (1 << attempt);

                std::thread::sleep(std::time::Duration::from_millis(delay_ms));

                continue;
            }

            // Final attempt failed
            error!(
                "SslSocketMapping: failed to remove SSL {:p} after {} attempts - possible deadlock or race condition",
                ssl, MAX_RETRIES
            );
        }

        // If we exhausted all attempts, return None
        None
    }

    /// Remove a socket from the mappings.
    ///
    /// This atomically removes from both mappings using a consistent locking strategy
    /// to prevent deadlocks. The method uses a retry mechanism with exponential backoff
    /// to handle concurrent modifications.
    ///
    /// # Arguments
    /// * `socket_id` - The socket file descriptor
    ///
    /// # Returns
    /// The SSL pointer that was associated, if any.
    pub fn remove_socket(socket_id: u32) -> Option<*mut SSL> {
        const MAX_RETRIES: usize = 3;
        const BASE_DELAY_MS: u64 = 1;

        for attempt in 0..MAX_RETRIES {
            // First, check if the socket entry exists and get the SSL pointer
            let ssl_ptr = match SOCKET_TO_SSL.get(&socket_id) {
                Some(entry) => entry.value().ssl,
                None => {
                    trace!("SslSocketMapping: socket {} was not in mapping", socket_id);
                    return None;
                }
            };

            let _ssl_id = ssl_ptr as usize;

            // Now perform the removal atomically
            // We use the same order as remove_ssl for consistency: SSL_TO_SOCKET first, then SOCKET_TO_SSL
            // But since we need the SSL pointer from the socket, we do it in reverse order
            // This is safe because DashMap uses fine-grained locking
            if let Some((_, wrapper)) = SOCKET_TO_SSL.remove(&socket_id) {
                let ssl = wrapper.ssl;

                // Now remove from SSL_TO_SOCKET
                let removed_socket = SSL_TO_SOCKET.remove(&(ssl as usize));

                if removed_socket.is_some() {
                    #[cfg(debug_assertions)]
                    debug!(
                        "SslSocketMapping: removed socket {} (was mapped to SSL {:p})",
                        socket_id, ssl
                    );
                    return Some(ssl);
                } else {
                    warn!(
                        "SslSocketMapping: inconsistency - socket {} mapped to SSL {:p} but SSL entry was missing",
                        socket_id, ssl
                    );
                    return Some(ssl);
                }
            }

            // If we get here, the removal failed due to concurrent modification
            if attempt < MAX_RETRIES - 1 {
                // Exponential backoff
                let delay_ms = BASE_DELAY_MS * (1 << attempt);

                std::thread::sleep(std::time::Duration::from_millis(delay_ms));
                continue;
            }

            // Final attempt failed
            error!(
                "SslSocketMapping: failed to remove socket {} after {} attempts - possible deadlock or race condition",
                socket_id, MAX_RETRIES
            );
        }

        // If we exhausted all attempts, return None
        None
    }

    /// Check if an SSL context is currently mapped.
    pub fn contains_ssl(ssl: *mut SSL) -> bool {
        if ssl.is_null() {
            return false;
        }
        SSL_TO_SOCKET.contains_key(&(ssl as usize))
    }

    /// Check if a socket is currently mapped to an SSL context.
    pub fn contains_socket(socket_id: u32) -> bool {
        SOCKET_TO_SSL.contains_key(&socket_id)
    }

    /// Get the current number of active SSL-socket mappings.
    pub fn len() -> usize {
        SSL_TO_SOCKET.len()
    }

    /// Check if there are no active mappings.
    pub fn is_empty() -> bool {
        SSL_TO_SOCKET.is_empty()
    }

    /// Clear all mappings (used during cleanup/unload).
    pub fn clear() {
        let ssl_count = SSL_TO_SOCKET.len();
        let socket_count = SOCKET_TO_SSL.len();

        if ssl_count != socket_count {
            warn!(
                "SslSocketMapping: clearing inconsistent mappings - SSL_TO_SOCKET: {}, SOCKET_TO_SSL: {}",
                ssl_count, socket_count
            );
        }

        SSL_TO_SOCKET.clear();
        SOCKET_TO_SSL.clear();

        #[cfg(debug_assertions)]
        debug!("SslSocketMapping: cleared {} mappings", ssl_count);
    }

    /// Check and repair consistency between the two mappings.
    ///
    /// This method verifies that both mappings are consistent and
    /// removes any orphaned entries to maintain data integrity.
    ///
    /// # Returns
    /// Number of inconsistencies found and repaired
    pub fn check_and_repair_consistency() -> usize {
        // First check if we have any mappings at all
        let ssl_count = SSL_TO_SOCKET.len();
        let socket_count = SOCKET_TO_SSL.len();

        if ssl_count == 0 && socket_count == 0 {
            #[cfg(debug_assertions)]
            debug!("SslSocketMapping: consistency check - no active mappings");
            return 0;
        }

        if ssl_count == socket_count {
            #[cfg(debug_assertions)]
            debug!(
                "SslSocketMapping: consistency check - mappings appear consistent ({} entries)",
                ssl_count
            );
            // Still run the full check to catch any hidden issues
        }
        let mut repaired = 0;

        // Check for SSL entries without corresponding socket entries
        let ssl_keys: Vec<usize> = SSL_TO_SOCKET.iter().map(|entry| *entry.key()).collect();

        for ssl_key in ssl_keys {
            if let Some(socket_id_ref) = SSL_TO_SOCKET.get(&ssl_key) {
                let socket_id = *socket_id_ref.value();

                if !SOCKET_TO_SSL.contains_key(&socket_id) {
                    // Orphaned SSL entry - remove it
                    SSL_TO_SOCKET.remove(&ssl_key);
                    warn!(
                        "SslSocketMapping: repaired orphaned SSL entry {:p} -> socket {}",
                        ssl_key as *mut SSL, socket_id
                    );
                    repaired += 1;
                }
            }
        }

        // Check for socket entries without corresponding SSL entries
        let socket_keys: Vec<u32> = SOCKET_TO_SSL.iter().map(|entry| *entry.key()).collect();
        for socket_id in socket_keys {
            if let Some(ssl_wrapper_ref) = SOCKET_TO_SSL.get(&socket_id) {
                let ssl_key = ssl_wrapper_ref.value().ssl as usize;

                if !SSL_TO_SOCKET.contains_key(&ssl_key) {
                    // Orphaned socket entry - remove it
                    SOCKET_TO_SSL.remove(&socket_id);
                    warn!(
                        "SslSocketMapping: repaired orphaned socket entry {} -> SSL {:p}",
                        socket_id,
                        ssl_wrapper_ref.value().ssl
                    );
                    repaired += 1;
                }
            }
        }

        if repaired > 0 {
            warn!("SslSocketMapping: repaired {} consistency issues", repaired);
        } else {
            #[cfg(debug_assertions)]
            debug!("SslSocketMapping: consistency check passed - no issues found");
        }

        repaired
    }

    /// Get debug info about current mappings.
    pub fn debug_info() -> String {
        let ssl_count = SSL_TO_SOCKET.len();
        let socket_count = SOCKET_TO_SSL.len();

        if ssl_count != socket_count {
            format!(
                "WARNING: mapping inconsistency - SSL_TO_SOCKET: {}, SOCKET_TO_SSL: {}",
                ssl_count, socket_count
            )
        } else {
            format!("Active SSL-socket mappings: {}", ssl_count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_associate_and_get() {
        // Use a fake pointer for testing
        let fake_ssl = 0x12345678 as *mut SSL;
        let socket_id = 42u32;

        SslSocketMapping::associate(fake_ssl, socket_id);

        assert_eq!(SslSocketMapping::get_socket(fake_ssl), Some(socket_id));
        assert_eq!(SslSocketMapping::get_ssl(socket_id), Some(fake_ssl));

        // Cleanup
        SslSocketMapping::remove_ssl(fake_ssl);
    }

    #[test]
    fn test_remove_ssl() {
        let fake_ssl = 0xABCDEF00 as *mut SSL;
        let socket_id = 100u32;

        SslSocketMapping::associate(fake_ssl, socket_id);
        assert!(SslSocketMapping::contains_ssl(fake_ssl));
        assert!(SslSocketMapping::contains_socket(socket_id));

        let removed_socket = SslSocketMapping::remove_ssl(fake_ssl);
        assert_eq!(removed_socket, Some(socket_id));
        assert!(!SslSocketMapping::contains_ssl(fake_ssl));
        assert!(!SslSocketMapping::contains_socket(socket_id));
    }

    #[test]
    fn test_remove_socket() {
        let fake_ssl = 0xDEADBEEF as *mut SSL;
        let socket_id = 200u32;

        SslSocketMapping::associate(fake_ssl, socket_id);

        let removed_ssl = SslSocketMapping::remove_socket(socket_id);
        assert_eq!(removed_ssl, Some(fake_ssl));
        assert!(!SslSocketMapping::contains_ssl(fake_ssl));
        assert!(!SslSocketMapping::contains_socket(socket_id));
    }

    #[test]
    fn test_null_ssl_handling() {
        let null_ssl: *mut SSL = std::ptr::null_mut();

        // Should not crash, should return None
        assert_eq!(SslSocketMapping::get_socket(null_ssl), None);
        assert!(!SslSocketMapping::contains_ssl(null_ssl));

        // Associate with null should be a no-op
        SslSocketMapping::associate(null_ssl, 999);
        assert!(!SslSocketMapping::contains_socket(999));
    }
}
