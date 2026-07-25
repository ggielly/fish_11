use std::any::Any;
use std::sync::Mutex;
use std::time::Duration as StdDuration;

use base64::Engine as _;
use base64::engine::general_purpose;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use fish_11_core::globals::MAX_MESSAGE_SIZE;
use hkdf::Hkdf;
use lru_time_cache::LruCache;
use sha2::{Digest, Sha256};

use crate::crypto::MessageCipher;
use crate::error::{FishError, Result};
use crate::utils::{base64_decode, base64_encode, generate_random_bytes};

/// XChaCha20-Poly1305 nonce size: 192 bits (24 bytes)
/// This eliminates nonce collision risk entirely — no practical limit on messages per key.
const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE + 16 + 24; // message + auth tag + nonce
pub const NONCE_SIZE_BYTES: usize = 24; // XChaCha20-Poly1305 nonce size (192 bits)

pub struct ChaCha20Poly1305Cipher;

impl MessageCipher for ChaCha20Poly1305Cipher {
    fn encrypt(
        &self,
        key: &[u8],
        message: &str,
        recipient: Option<&str>,
        associated_data: Option<&[u8]>,
    ) -> Result<String> {
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| FishError::InvalidInput("Key must be 32 bytes".to_string()))?;
        encrypt_message(&key_array, message, recipient, associated_data)
    }

    fn decrypt(
        &self,
        key: &[u8],
        encrypted_data: &str,
        associated_data: Option<&[u8]>,
    ) -> Result<String> {
        let key_array: [u8; 32] = key
            .try_into()
            .map_err(|_| FishError::InvalidInput("Key must be 32 bytes".to_string()))?;
        decrypt_message(&key_array, encrypted_data, associated_data)
    }

    fn generate_key(&self) -> Result<Vec<u8>> {
        let key = generate_symmetric_key()?;
        Ok(key.to_vec())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// Global nonce cache for anti-replay protection (24-byte XChaCha20 nonces)
lazy_static::lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache<[u8; NONCE_SIZE_BYTES], ()>> = Mutex::new(
        LruCache::with_expiry_duration_and_capacity(
            chrono::Duration::hours(1)
                .to_std()
                .unwrap_or_else(|_| StdDuration::from_secs(3600)),
            1000
        )
    );
}

/// Checks if a nonce has been used before.
/// Returns Ok(true) if it is a replay (nonce exists in cache).
/// Returns Ok(false) if it is fresh.
pub fn is_nonce_replay(nonce: &[u8]) -> Result<bool> {
    if nonce.len() != NONCE_SIZE_BYTES {
        return Err(FishError::InvalidInput(format!("Nonce must be {} bytes", NONCE_SIZE_BYTES)));
    }
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(nonce);

    let cache_lock_result = NONCE_CACHE.lock();
    if cache_lock_result.is_err() {
        return Err(FishError::CryptoError("Failed to acquire nonce cache lock".to_string()));
    }
    let mut cache = cache_lock_result.unwrap();

    Ok(cache.contains_key(&nonce_array))
}

/// Marks a nonce as used in the cache.
pub fn mark_nonce_seen(nonce: &[u8]) -> Result<()> {
    if nonce.len() != NONCE_SIZE_BYTES {
        return Err(FishError::InvalidInput(format!("Nonce must be {} bytes", NONCE_SIZE_BYTES)));
    }
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(nonce);

    let cache_lock_result = NONCE_CACHE.lock();
    if cache_lock_result.is_err() {
        return Err(FishError::CryptoError("Failed to acquire nonce cache lock".to_string()));
    }
    let mut cache = cache_lock_result.unwrap();

    cache.insert(nonce_array, ());
    Ok(())
}

/// Generate a new 32-byte symmetric key for XChaCha20-Poly1305
pub fn generate_symmetric_key() -> Result<[u8; 32]> {
    generate_random_bytes(32)
        .try_into()
        .map_err(|_| FishError::CryptoError("Failed to convert Vec<u8> to [u8; 32]".to_string()))
}

pub fn encrypt_message(
    key: &[u8; 32],
    message: &str,
    recipient: Option<&str>,
    associated_data: Option<&[u8]>,
) -> Result<String> {
    // Input validation
    if message.is_empty() {
        return Err(FishError::InvalidInput("Empty message".to_string()));
    }

    if message.len() > MAX_MESSAGE_SIZE {
        return Err(FishError::InvalidInput(format!(
            "Message exceeds maximum size of {} bytes",
            MAX_MESSAGE_SIZE
        )));
    }

    // Generate a secure nonce using fully random bytes (24 bytes for XChaCha20)
    // XChaCha20 uses HChaCha20 to derive a sub-key from the 24-byte nonce,
    // eliminating nonce collision risk — no practical limit on messages per key.
    let nonce_bytes = generate_random_bytes(NONCE_SIZE_BYTES);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(&nonce_bytes[..NONCE_SIZE_BYTES]);

    // Create the cipher
    let chacha_key = Key::from(*key);
    let cipher = XChaCha20Poly1305::new(&chacha_key);
    let nonce = XNonce::from(nonce_array);

    // Encrypt the message, including associated data if provided
    let ciphertext = match associated_data {
        Some(ad) => cipher.encrypt(&nonce, Payload { msg: message.as_bytes(), aad: ad }),
        None => cipher.encrypt(&nonce, Payload { msg: message.as_bytes(), aad: &[] }),
    }
    .map_err(|e| FishError::CryptoError(format!("Encryption failed: {}", e)))?;

    // Concatenate the nonce and ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE_BYTES + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    // Log encryption (audit trail)
    if let Some(rec) = recipient {
        let mut hasher = Sha256::default();
        hasher.update(message.as_bytes());

        let msg_hash = base64_encode(&hasher.finalize()[0..8]);

        #[cfg(debug_assertions)]
        log_audit(&format!("Encrypt for {} - {}", rec, msg_hash));

        // Log sensitive content if DEBUG flag is enabled for sensitive content
        #[cfg(debug_assertions)]
        log::debug!("Crypto: encrypting message for '{}': '{}'", rec, message);
    }

    crate::config::increment_encryption_counter();

    // Base64 encode the result
    Ok(base64_encode(&result))
}

pub fn decrypt_message(
    key: &[u8; 32],
    encrypted_data: &str,
    associated_data: Option<&[u8]>,
) -> Result<String> {
    // Decode base64 data
    let data = base64_decode(encrypted_data)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 data: {}", e)))?;

    // Fuzzing protection - early rejection
    if data.len() > MAX_CIPHERTEXT_SIZE {
        return Err(FishError::CryptoError(format!("Ciphertext too large: {} bytes", data.len())));
    }

    // Check if we have enough data for nonce (24 bytes) + at least some ciphertext
    if data.len() <= NONCE_SIZE_BYTES {
        return Err(FishError::CryptoError("Encrypted data too short".to_string()));
    }

    // Split into nonce and ciphertext : 24 bytes nonce for XChaCha20
    let nonce = &data[..NONCE_SIZE_BYTES];

    // The rest is ciphertext
    let ciphertext = &data[NONCE_SIZE_BYTES..];

    // Create cipher
    let chacha_key = Key::from(*key);
    let cipher = XChaCha20Poly1305::new(&chacha_key);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(nonce);
    let nonce = XNonce::from(nonce_array);

    // Decrypt, including associated data if provided
    let plaintext = match associated_data {
        Some(ad) => cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: ad }),
        None => cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: &[] }),
    }
    .map_err(|e| FishError::CryptoError(format!("Decryption failed: {}", e)))?;

    // Log decryption (audit trail)
    let mut hasher = Sha256::default();

    hasher.update(&plaintext);
    let msg_hash = base64_encode(&hasher.finalize()[0..8]);

    log_audit(&format!("Decrypt - {}", msg_hash));

    #[cfg(debug_assertions)]
    if let Ok(plaintext_str) = std::str::from_utf8(&plaintext) {
        log::debug!("Crypto: decrypted message content: '{}'", plaintext_str);
    }

    // Increment decryption counter
    crate::config::increment_decryption_counter();

    // Convert to string
    String::from_utf8(plaintext)
        .map_err(|e| FishError::CryptoError(format!("UTF-8 conversion failed: {}", e)))
}

/// Advances a symmetric channel key using HKDF to provide Forward Secrecy.
pub fn advance_ratchet_key(
    current_key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_BYTES],
    channel_name: &str,
) -> Result<[u8; 32]> {
    use zeroize::Zeroize;

    let mut temp_current = *current_key;

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), &temp_current);

    let mut next_key = [0u8; 32];

    let info = format!("FCEP-1-RATCHET{}", channel_name.to_lowercase());

    hkdf.expand(info.as_bytes(), &mut next_key).map_err(|e| {
        temp_current.zeroize();
        FishError::CryptoError(format!("HKDF expansion for ratchet failed: {}", e))
    })?;

    temp_current.zeroize();

    Ok(next_key)
}

/// Wraps a channel key using a pre-shared symmetric key (XChaCha20-Poly1305).
pub fn wrap_key(channel_key: &[u8; 32], shared_key_with_member: &[u8; 32]) -> Result<String> {
    let nonce_bytes = generate_random_bytes(NONCE_SIZE_BYTES);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(&nonce_bytes[..NONCE_SIZE_BYTES]);

    let cipher = XChaCha20Poly1305::new(shared_key_with_member.into());
    let nonce = XNonce::from(nonce_array);

    let ciphertext = cipher
        .encrypt(&nonce, channel_key.as_ref())
        .map_err(|e| FishError::CryptoError(format!("Key wrapping failed: {}", e)))?;

    let mut result = Vec::with_capacity(NONCE_SIZE_BYTES + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(general_purpose::STANDARD.encode(&result))
}

/// Unwraps a channel key using a pre-shared symmetric key (XChaCha20-Poly1305).
pub fn unwrap_key(
    wrapped_key_b64: &str,
    shared_key_with_coordinator: &[u8; 32],
) -> Result<[u8; 32]> {
    let wrapped_bytes = general_purpose::STANDARD
        .decode(wrapped_key_b64)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 in wrapped key: {}", e)))?;

    // Minimum size: 24 (nonce) + 16 (auth tag) + 32 (key) = 72 bytes
    if wrapped_bytes.len() < 72 {
        return Err(FishError::CryptoError(format!(
            "Wrapped key too short: expected at least 72 bytes, got {}",
            wrapped_bytes.len()
        )));
    }

    let (nonce_bytes, ciphertext) = wrapped_bytes.split_at(NONCE_SIZE_BYTES);
    let nonce_array: [u8; NONCE_SIZE_BYTES] = nonce_bytes
        .try_into()
        .map_err(|_| FishError::CryptoError("Invalid nonce length".to_string()))?;
    let nonce = XNonce::from(nonce_array);

    let cipher = XChaCha20Poly1305::new(shared_key_with_coordinator.into());

    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|e| {
        FishError::CryptoError(format!(
            "Key unwrapping failed (invalid key or corrupted data): {}",
            e
        ))
    })?;

    let plaintext_len = plaintext.len();

    plaintext.try_into().map_err(|_| {
        FishError::CryptoError(format!(
            "Unwrapped key has invalid length: expected 32 bytes, got {}",
            plaintext_len
        ))
    })
}

/// Log a cryptographic audit event
fn log_audit(event: &str) {
    // Use the standard debug logging
    #[cfg(debug_assertions)]
    log::debug!("[AUDIT] {}", event);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{NonceCache, RatchetState};

    #[test]
    fn test_encrypt_decrypt() {
        let key1 = generate_symmetric_key().unwrap();
        let message = "Secret message";
        let encrypted = encrypt_message(&key1, message, None, None).unwrap();
        let decrypted = decrypt_message(&key1, &encrypted, None).unwrap();
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_ratchet_forward_secrecy() {
        // Test that ratcheting produces different keys each time
        let initial_key = [1u8; 32];
        let nonce1 = [0u8; NONCE_SIZE_BYTES];
        let nonce2 = [1u8; NONCE_SIZE_BYTES];
        let channel = "#test";

        // First ratchet step
        let key1_result = advance_ratchet_key(&initial_key, &nonce1, channel);
        if key1_result.is_err() {
            panic!("Failed to advance ratchet key1: {:?}", key1_result.err());
        }
        let key1 = key1_result.unwrap();
        assert_ne!(key1, initial_key, "Ratcheted key should differ from initial");

        // Second ratchet step (with different nonce)
        let key2_result = advance_ratchet_key(&key1, &nonce2, channel);
        if key2_result.is_err() {
            panic!("Failed to advance ratchet key2: {:?}", key2_result.err());
        }
        let key2 = key2_result.unwrap();
        assert_ne!(key2, key1, "Each ratchet step should produce unique key");
        assert_ne!(key2, initial_key, "Ratcheted key should differ from initial");

        // Verify one-way property: can't derive key1 from key2
        let attempted_reverse_result = advance_ratchet_key(&key2, &nonce1, channel);
        if attempted_reverse_result.is_err() {
            panic!("Failed to advance ratchet reverse: {:?}", attempted_reverse_result.err());
        }
        let attempted_reverse = attempted_reverse_result.unwrap();
        assert_ne!(attempted_reverse, key1, "Ratcheting must be one-way (PCS)");
    }

    #[test]
    fn test_ratchet_nonce_uniqueness() {
        // Different nonces should produce different keys
        let key = [42u8; 32];
        let nonce1 = [0u8; NONCE_SIZE_BYTES];
        let nonce2 = [1u8; NONCE_SIZE_BYTES];
        let channel = "#test";

        let derived1_result = advance_ratchet_key(&key, &nonce1, channel);
        if derived1_result.is_err() {
            panic!("Failed to advance ratchet with nonce1: {:?}", derived1_result.err());
        }
        let derived1 = derived1_result.unwrap();

        let derived2_result = advance_ratchet_key(&key, &nonce2, channel);
        if derived2_result.is_err() {
            panic!("Failed to advance ratchet with nonce2: {:?}", derived2_result.err());
        }
        let derived2 = derived2_result.unwrap();

        assert_ne!(derived1, derived2, "Different nonces must produce different keys");
    }

    #[test]
    fn test_ratchet_channel_binding() {
        // Same key + nonce but different channels should produce different keys
        let key = [42u8; 32];
        let nonce = [0u8; NONCE_SIZE_BYTES];

        let key_ch1_result = advance_ratchet_key(&key, &nonce, "#channel1");
        if key_ch1_result.is_err() {
            panic!("Failed to advance ratchet for channel1: {:?}", key_ch1_result.err());
        }
        let key_ch1 = key_ch1_result.unwrap();

        let key_ch2_result = advance_ratchet_key(&key, &nonce, "#channel2");
        if key_ch2_result.is_err() {
            panic!("Failed to advance ratchet for channel2: {:?}", key_ch2_result.err());
        }
        let key_ch2 = key_ch2_result.unwrap();

        assert_ne!(key_ch1, key_ch2, "Channel name must be bound to key derivation");
    }

    #[test]
    fn test_cross_channel_replay_prevention() {
        // Test that messages encrypted for one channel can't be decrypted for another
        let key = [42u8; 32];
        let message = "Secret message";

        // Encrypt for #channel1
        let encrypted_ch1_result =
            encrypt_message(&key, message, Some("#channel1"), Some(b"#channel1"));
        if encrypted_ch1_result.is_err() {
            panic!("Encryption for channel1 failed: {:?}", encrypted_ch1_result.err());
        }
        let encrypted_ch1 = encrypted_ch1_result.unwrap();

        // Try to decrypt for #channel2 (should fail due to AD mismatch)
        let decrypt_result = decrypt_message(&key, &encrypted_ch1, Some(b"#channel2"));

        assert!(decrypt_result.is_err(), "Cross-channel replay must be prevented by AD");
    }

    #[test]
    fn test_nonce_cache_prevents_replay() {
        let mut cache = NonceCache::new();
        let nonce = [42u8; NONCE_SIZE_BYTES];

        // First check should pass (nonce is new)
        assert!(!cache.check_and_add(nonce), "New nonce should be accepted");

        // Second check should fail (nonce is duplicate)
        assert!(cache.check_and_add(nonce), "Duplicate nonce should be detected");
    }

    #[test]
    fn test_nonce_cache_overflow() {
        let mut cache = NonceCache::new();

        // Add 101 nonces (MAX_NONCE_CACHE_SIZE = 100)
        for i in 0..101 {
            let mut nonce = [0u8; NONCE_SIZE_BYTES];
            nonce[0] = i as u8;
            cache.check_and_add(nonce);
        }

        // First nonce should be evicted (FIFO)
        let first_nonce = [0u8; NONCE_SIZE_BYTES];
        assert!(
            !cache.recent_nonces.contains(&first_nonce),
            "Oldest nonce should be evicted after cache overflow"
        );

        // Last nonce should still be present
        let mut last_nonce = [0u8; NONCE_SIZE_BYTES];
        last_nonce[0] = 100;
        assert!(cache.recent_nonces.contains(&last_nonce), "Most recent nonce should be retained");

        // Cache size should be capped
        assert_eq!(
            cache.recent_nonces.len(),
            100,
            "Cache size should be limited to MAX_NONCE_CACHE_SIZE"
        );
    }

    #[test]
    fn test_ratchet_state_advance() {
        let initial_key = [1u8; 32];
        let mut state = RatchetState::new(initial_key);

        assert_eq!(state.epoch, 0, "Initial epoch should be 0");
        assert!(state.previous_keys.is_empty(), "Initial previous_keys should be empty");

        // Advance once
        let next_key = [2u8; 32];
        state.advance(next_key);

        assert_eq!(state.epoch, 1, "Epoch should increment");
        assert_eq!(state.current_key, next_key, "Current key should be updated");
        assert_eq!(state.previous_keys.len(), 1, "Previous key should be stored");
        assert_eq!(state.previous_keys[0], initial_key, "Initial key should be in previous_keys");

        // Advance 5 more times to test window eviction
        for i in 3..8 {
            let key = [i as u8; 32];
            state.advance(key);
        }

        assert_eq!(state.epoch, 6, "Epoch should be 6 after 6 advances");
        // MAX_PREVIOUS_KEYS = 5, so window holds exactly 5 keys after 6 advances
        assert_eq!(
            state.previous_keys.len(),
            5,
            "Previous keys should be capped at MAX_PREVIOUS_KEYS (5)"
        );

        // Oldest key (initial_key) should be evicted after window fills
        assert!(
            !state.previous_keys.contains(&initial_key),
            "Oldest key should be evicted from window"
        );
    }

    #[test]
    fn test_encrypt_decrypt_with_ratchet_simulation() {
        // Simulate 3-message exchange with ratcheting
        let mut current_key = [42u8; 32];
        let channel = "#test";

        let messages = ["Message 1", "Message 2", "Message 3"];
        let mut encrypted_messages = Vec::new();
        let mut ratchet_keys = Vec::new();

        // Encrypt messages with ratcheting
        for msg in &messages {
            let encrypted_result =
                encrypt_message(&current_key, msg, Some(channel), Some(channel.as_bytes()));
            if encrypted_result.is_err() {
                panic!("Ratchet test encryption failed: {:?}", encrypted_result.err());
            }
            let encrypted = encrypted_result.unwrap();
            encrypted_messages.push(encrypted.clone());
            ratchet_keys.push(current_key);

            // Extract nonce and advance ratchet
            let encrypted_bytes_result = crate::utils::base64_decode(&encrypted);

            if encrypted_bytes_result.is_err() {
                panic!(
                    "Ratchet test failed to base64 decode encrypted data: {:?}",
                    encrypted_bytes_result.err()
                );
            }
            let encrypted_bytes = encrypted_bytes_result.unwrap();

            let nonce_slice = &encrypted_bytes[..NONCE_SIZE_BYTES];
            let nonce_result: std::result::Result<[u8; NONCE_SIZE_BYTES], _> =
                nonce_slice.try_into();
            if nonce_result.is_err() {
                panic!("Ratchet test failed to convert slice to nonce: {:?}", nonce_result.err());
            }
            let nonce: [u8; NONCE_SIZE_BYTES] = nonce_result.unwrap();

            let next_key_result = advance_ratchet_key(&current_key, &nonce, channel);
            if next_key_result.is_err() {
                panic!("Ratchet test failed to advance key: {:?}", next_key_result.err());
            }
            current_key = next_key_result.unwrap();
        }

        // Verify all keys are different
        assert_ne!(ratchet_keys[0], ratchet_keys[1]);
        assert_ne!(ratchet_keys[1], ratchet_keys[2]);
        assert_ne!(ratchet_keys[0], ratchet_keys[2]);

        // Decrypt messages in order (each with its corresponding key)
        for (i, encrypted) in encrypted_messages.iter().enumerate() {
            let decrypted_result =
                decrypt_message(&ratchet_keys[i], encrypted, Some(channel.as_bytes()));
            if decrypted_result.is_err() {
                panic!(
                    "Ratchet test decryption failed for message {}: {:?}",
                    i,
                    decrypted_result.err()
                );
            }
            let decrypted = decrypted_result.unwrap();
            assert_eq!(decrypted, messages[i], "Message {} should decrypt correctly", i);
        }

        // Verify old keys can't decrypt new messages (forward secrecy)
        let decrypt_result =
            decrypt_message(&ratchet_keys[0], &encrypted_messages[2], Some(channel.as_bytes()));
        assert!(
            decrypt_result.is_err(),
            "Old key should not decrypt messages encrypted with newer key"
        );
    }

    #[test]
    fn test_ratchet_state_advancement_with_key_derivation() {
        let initial_key = [1u8; 32];
        let mut state = RatchetState::new(initial_key);
        let nonce = [0u8; NONCE_SIZE_BYTES];

        let key1 = state.current_key;
        let next_key1 = advance_ratchet_key(&key1, &nonce, "#test").unwrap();

        state.advance(next_key1);

        // Key 1 should be in previous_keys
        assert!(state.previous_keys.contains(&key1));
        assert_ne!(state.current_key, key1);

        // Advance again
        let key2 = state.current_key;
        let next_key2 = advance_ratchet_key(&key2, &nonce, "#test").unwrap();

        state.advance(next_key2);

        // Keys should all be different
        assert_ne!(next_key1, next_key2);
    }

    #[test]
    fn test_out_of_order_decryption_logic() {
        // Safely clear the nonce cache
        {
            let cache_result = NONCE_CACHE.lock();
            if cache_result.is_err() {
                panic!("Failed to acquire NONCE_CACHE lock");
            }
            let mut cache = cache_result.unwrap();
            cache.clear();
        }

        let initial_key = [1u8; 32];
        let mut state = RatchetState::new(initial_key);
        let channel = "#test";

        // Generate a sequence of 3 keys
        let key1 = state.current_key;
        let nonce1 = [1u8; NONCE_SIZE_BYTES];
        let next_key1_result = advance_ratchet_key(&key1, &nonce1, channel);

        if next_key1_result.is_err() {
            panic!("Failed to advance ratchet key1: {:?}", next_key1_result.err());
        }
        let next_key1 = next_key1_result.unwrap();

        state.advance(next_key1);

        let key2 = state.current_key;
        let nonce2 = [2u8; NONCE_SIZE_BYTES];
        let next_key2_result = advance_ratchet_key(&key2, &nonce2, channel);

        if next_key2_result.is_err() {
            panic!("Failed to advance ratchet key2: {:?}", next_key2_result.err());
        }
        let next_key2 = next_key2_result.unwrap();
        state.advance(next_key2);

        let key3 = state.current_key;

        // At this point, state.current_key is key3, and state.previous_keys contains [key1, key2]

        // Encrypt messages with their corresponding keys
        let msg1 = "old message";
        let encrypted1_result = encrypt_message(&key1, msg1, None, Some(channel.as_bytes()));
        if encrypted1_result.is_err() {
            panic!("Encryption of msg1 failed: {:?}", encrypted1_result.err());
        }
        let encrypted1 = encrypted1_result.unwrap();

        let msg3 = "current message";
        let encrypted3_result = encrypt_message(&key3, msg3, None, Some(channel.as_bytes()));

        if encrypted3_result.is_err() {
            panic!("Encryption of msg3 failed: {:?}", encrypted3_result.err());
        }
        let encrypted3 = encrypted3_result.unwrap();

        // Decrypting the current message with the current key should work
        let decrypt_current_result =
            decrypt_message(&state.current_key, &encrypted3, Some(channel.as_bytes()));
        if decrypt_current_result.is_err() {
            panic!("Decryption of current message failed: {:?}", decrypt_current_result.err());
        }
        assert_eq!(decrypt_current_result.unwrap(), msg3);

        // Decrypting the old message (msg1) with the current key should fail
        assert!(
            decrypt_message(&state.current_key, &encrypted1, Some(channel.as_bytes())).is_err()
        );

        // Clear the nonce cache to simulate a new session where old messages can be decrypted
        {
            let cache_result = NONCE_CACHE.lock();
            if cache_result.is_err() {
                panic!("Failed to acquire NONCE_CACHE lock");
            }
            let mut cache = cache_result.unwrap();
            cache.clear();
        }

        // But it should succeed if we search through the previous_keys
        let mut decrypted_old_message = None;
        for old_key in &state.previous_keys {
            if let Ok(plaintext) = decrypt_message(old_key, &encrypted1, Some(channel.as_bytes())) {
                decrypted_old_message = Some(plaintext);
                break;
            }
        }
        if decrypted_old_message.is_none() {
            panic!("Failed to decrypt old message with previous keys");
        }
        assert_eq!(decrypted_old_message.unwrap(), msg1);
    }
}
