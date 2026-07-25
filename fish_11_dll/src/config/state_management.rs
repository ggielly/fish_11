//! Functions for managing channel ratchet state and nonce caches.

use super::config_access::{with_config, with_config_mut};
use super::models::{NonceCache, RatchetState};
use crate::unified_error::{DllResult, FishError};

/// Initializes the ratchet state for a channel if it doesn't exist.
pub fn init_ratchet_state(channel: &str, initial_key: [u8; 32]) -> DllResult<()> {
    let channel_name = channel.to_lowercase();
    with_config_mut(|config| {
        config
            .channel_ratchet_states
            .entry(channel_name)
            .or_insert_with(|| RatchetState::new(initial_key));
        Ok(())
    })?;
    Ok(())
}

/// Retrieves a mutable reference to a channel's ratchet state.
pub fn with_ratchet_state_mut<F, R>(channel: &str, mut action: F) -> DllResult<R>
where
    F: FnMut(&mut RatchetState) -> DllResult<R>,
{
    let channel_name = channel.to_lowercase();
    let outer_result: Result<R, FishError> = with_config_mut(|config| {
        if let Some(state) = config.channel_ratchet_states.get_mut(&channel_name) {
            action(state).map_err(|e| FishError::ConfigError(e.to_string()))
        } else {
            Err(FishError::ConfigError(format!(
                "Ratchet state not found for channel {}",
                &channel_name
            )))
        }
    });

    match outer_result {
        Ok(val) => Ok(val),
        Err(e) => Err(e.into()),
    }
}

/// Checks if a nonce has been seen before for a channel.
/// Returns `true` if the nonce is a duplicate (potential replay).
pub fn check_nonce(channel: &str, nonce: &[u8; 24]) -> DllResult<bool> {
    let channel_name = channel.to_lowercase();
    let result = with_config(|config| {
        if let Some(cache) = config.channel_nonce_caches.get(&channel_name) {
            Ok(cache.recent_nonces.contains(nonce))
        } else {
            Ok(false) // No cache exists, so nonce can't be a duplicate
        }
    })?;
    Ok(result)
}

/// Adds a nonce to the cache for a specific channel.
pub fn add_nonce(channel: &str, nonce: [u8; 24]) -> DllResult<()> {
    let channel_name = channel.to_lowercase();
    with_config_mut(|config| {
        let cache = config.channel_nonce_caches.entry(channel_name).or_insert_with(NonceCache::new);
        cache.check_and_add(nonce); // The model's check_and_add now just adds
        Ok(())
    })?;
    Ok(())
}
