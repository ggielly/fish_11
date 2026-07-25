use std::ffi::c_char;
use std::os::raw::c_int;
use std::time::Instant;

use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;

use crate::config::{CONFIG, get_key, get_keypair, save_config, set_key, store_keypair};
use crate::crypto::KeyExchange;
use crate::crypto::x25519::{X25519KeyExchange, X25519KeyPair, format_public_key};
use crate::dll_interface::KEY_EXCHANGE_TIMEOUT_SECONDS;
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::{DllError, DllResult};
use crate::utils::{is_socket_connected, normalize_nick};
use crate::{buffer_utils, dll_function_identifier, log_debug, log_error, log_info, log_warn};

dll_function_identifier!(FiSH11_ExchangeKey, data, {
    let overall_start = Instant::now();

    // This function is time-sensitive as it's part of an interactive user workflow.
    // A timeout ensures we don't block the program-caller indefinitely
    // if crypto operations hang.
    let start_time = Instant::now();
    let timeout = std::time::Duration::from_secs(KEY_EXCHANGE_TIMEOUT_SECONDS as u64);

    log_info!("=== Key exchange (serial {:?}) initiated ===", start_time);

    // Parse and validate input
    let parse_start = Instant::now();
    let mut input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let input_trimmed = input.trim();

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let normalized_input = crate::utils::normalize_target(input_trimmed);
    let nickname = normalize_nick(normalized_input);

    #[cfg(debug_assertions)]
    log_debug!("Parse input took {:?}", parse_start.elapsed());

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    #[cfg(debug_assertions)]
    log_debug!(
        "Key exchange initiated for nickname/channel: {} (original: {})",
        nickname,
        input_trimmed
    );

    // Timeout check 1
    check_timeout(start_time, timeout, "before key check")?;

    // Track if we need to save config at the end
    let mut config_modified = false;

    // Check if we're currently connected to IRC
    if !is_likely_connected() {
        log_warn!("Key exchange attempted while not connected to IRC");

        return Err(crate::unified_error::DllError::NotConnected(
            "Cannot perform key exchange when not connected to IRC".to_string(),
        ));
    }

    // Step 1: ensure key exists (may generate new key)
    let step1_start = Instant::now();

    #[cfg(debug_assertions)]
    log_debug!("Starting ensure_key_exists...");

    let key_was_generated = ensure_key_exists(&nickname)?;

    if key_was_generated {
        config_modified = true;
    }

    let step1_duration = step1_start.elapsed();

    #[cfg(debug_assertions)]
    log_debug!(
        "Step 1 (ensure_key_exists) took {:?} - key_generated : {}",
        step1_duration,
        key_was_generated
    );

    #[cfg(debug_assertions)]
    if step1_duration.as_millis() > 500 {
        log_warn!("Step 1 took more than 500ms : {:?}", step1_duration);
    }

    // Timeout check 2
    check_timeout(start_time, timeout, "before keypair generation")?;

    // Step 2: get or generate keypair
    let step2_start = Instant::now();

    #[cfg(debug_assertions)]
    log_debug!("Starting get_or_generate_keypair_internal...");

    let (keypair, keypair_was_generated) = get_or_generate_keypair_internal()?;

    if keypair_was_generated {
        config_modified = true;
    }
    let step2_duration = step2_start.elapsed();

    #[cfg(debug_assertions)]
    log_debug!(
        "Generate or get a keypair took {:?} - keypair_generated: {}",
        step2_duration,
        keypair_was_generated
    );

    #[cfg(debug_assertions)]
    if step2_duration.as_millis() > 500 {
        log_warn!("Get or Generate a keypair 2 took more than 500ms : {:?}", step2_duration);
    }

    // Timeout check 3
    check_timeout(start_time, timeout, "before keypair validation")?;

    // Step 3: validate keypair
    let step3_start = Instant::now();

    #[cfg(debug_assertions)]
    log_debug!("Starting validate_keypair_safety...");

    validate_keypair_safety(&keypair)?;

    let step3_duration = step3_start.elapsed();

    #[cfg(debug_assertions)]
    log_debug!("SValidate keypair took {:?}", step3_duration);

    #[cfg(debug_assertions)]
    if step3_duration.as_millis() > 100 {
        log_warn!("Validate keypair took more than 100ms : {:?}", step3_duration);
    }

    // Step 4: format public key for sharing
    let step4_start = Instant::now();

    #[cfg(debug_assertions)]
    log_debug!("Starting format_public_key...");

    let formatted_key = format_public_key(&keypair.public_key);
    let step4_duration = step4_start.elapsed();

    #[cfg(debug_assertions)]
    log_debug!("Step 4 (formatting) took {:?}", step4_duration);

    if !formatted_key.starts_with("X25519_INIT:") {
        return Err(DllError::KeyInvalid {
            reason: "invalid public key format generated".to_string(),
        });
    }

    #[cfg(debug_assertions)]
    log_debug!("Public key formatted successfully (length: {})", formatted_key.len());

    // Step 5: save config ONCE if anything was modified
    if config_modified {
        let save_start = Instant::now();

        log_info!("Saving configuration changes...");

        // Take a snapshot of the config and release the lock immediately
        let config_snapshot = {
            let config_guard = CONFIG.write();
            config_guard.clone()
        }; // Lock released here

        // Now save without holding the lock
        save_config(&config_snapshot, None)?;

        let save_duration = save_start.elapsed();

        #[cfg(debug_assertions)]
        log_debug!("Configuration saved in {:?}", save_duration);

        if save_duration.as_secs() > 2 {
            log_warn!("Config save took longer than 2 seconds ! Check disk I/O performance.");
        }
    } else {
        #[cfg(debug_assertions)]
        log_debug!("No configuration changes to save");
    }

    // Return the formatted public key token directly so callers
    let total_duration = overall_start.elapsed();

    if key_was_generated {
        #[cfg(debug_assertions)]
        log_debug!(
            "Key exchange setup completed for {} (generated new key) in {:?}",
            nickname,
            total_duration
        );
    } else {
        #[cfg(debug_assertions)]
        log_debug!(
            "Key exchange setup completed successfully for {} in {:?}",
            nickname,
            total_duration
        );
    }

    if total_duration.as_secs() > 3 {
        log_warn!("Key exchange took longer than 3 seconds ! Duration: {:?}", total_duration);
    }

    log_info!("=== Key exchange (serial {:?}) completed ===", start_time);

    // Increment key exchange counter
    crate::config::increment_key_exchange_counter();

    // SECURITY: Clear the source buffer from memory
    crate::utils::secure_clear_string(&mut input);

    // Return only the token, e.g. "FiSH11-PubKey:BASE64..."
    Ok(formatted_key)
});

// ========== HELPER FUNCTIONS ==========

/// Ensure a key exists for the given nickname, generating one if needed
/// Returns (key_was_generated: bool)
fn ensure_key_exists(nickname: &str) -> DllResult<bool> {
    let lookup_start = Instant::now();
    let existing_key = get_key(nickname, None);

    #[cfg(debug_assertions)]
    log_debug!("get_key_default lookup took {:?}", lookup_start.elapsed());

    match existing_key {
        Ok(_) => {
            #[cfg(debug_assertions)]
            log_debug!("Found existing key for {}", nickname);
            Ok(false) // Key already existed
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            log_debug!("No existing key found for {}, generating new key", nickname);

            let keygen_start = Instant::now();
            #[cfg(debug_assertions)]
            log_debug!("Starting RNG for key generation...");

            // Use the secure random key generator with retry logic
            let key_bytes = generate_secure_random_key()?;

            let keygen_duration = keygen_start.elapsed();
            #[cfg(debug_assertions)]
            log_debug!("RNG key generation took {:?}", keygen_duration);

            #[cfg(debug_assertions)]
            if keygen_duration.as_millis() > 200 {
                log_warn!(
                    "RNG took more than 200ms: {:?} - this may indicate entropy pool issues",
                    keygen_duration
                );
            }

            let store_start = Instant::now();
            #[cfg(debug_assertions)]
            log_debug!("Storing key in config...");

            // Store the key with overwrite enabled (in-memory only, no disk I/O yet)
            set_key(nickname, &key_bytes, None, true, true)?;

            #[cfg(debug_assertions)]
            log_debug!("set_key_default took {:?}", store_start.elapsed());

            #[cfg(debug_assertions)]
            log_debug!(
                "Successfully generated and stored new key for {} (not yet saved to disk)",
                nickname
            );
            Ok(true) // Key was generated
        }
    }
}

/// Get or generate our Curve25519 keypair for Diffie-Hellman key exchange
/// Returns (keypair, was_generated: bool)
fn get_or_generate_keypair_internal() -> DllResult<(X25519KeyPair, bool)> {
    let lookup_start = Instant::now();
    let existing_keypair = get_keypair();

    #[cfg(debug_assertions)]
    log_debug!("get_keypair lookup took {:?}", lookup_start.elapsed());

    match existing_keypair {
        Ok(kp) => {
            #[cfg(debug_assertions)]
            log_debug!("Retrieved existing keypair");
            Ok((kp, false))
        }
        Err(_) => {
            #[cfg(debug_assertions)]
            log_debug!("No keypair found, generating new one");

            let keygen_start = Instant::now();

            #[cfg(debug_assertions)]
            log_debug!("Starting keypair generation...");

            // Use Trait for generation
            let engine = X25519KeyExchange;
            let boxed_keypair = engine
                .generate_keypair()
                .map_err(|e| DllError::KeyExchangeFailed(e.to_string()))?;

            // Downcast to concrete type for storage/return
            // Note: Unwrapping is safe here because we know X25519KeyExchange produces X25519KeyPair
            // and we are inside the dll where we know the types.
            let new_keypair = match boxed_keypair.as_any().downcast_ref::<X25519KeyPair>() {
                Some(kp) => X25519KeyPair {
                    private_key: secrecy::Secret::new(*kp.private_key.expose_secret()),
                    public_key: kp.public_key,
                    creation_time: kp.creation_time,
                },
                None => {
                    return Err(DllError::KeyExchangeFailed(
                        "Failed to downcast keypair".to_string(),
                    ));
                }
            };

            let keygen_duration = keygen_start.elapsed();

            #[cfg(debug_assertions)]
            log_debug!("Keypair generation took {:?}", keygen_duration);

            #[cfg(debug_assertions)]
            if keygen_duration.as_millis() > 200 {
                log_warn!("Keypair generation took more than 200ms: {:?}", keygen_duration);
            }

            let store_start = Instant::now();

            #[cfg(debug_assertions)]
            log_debug!("Storing keypair in config...");

            // Store the new keypair (in-memory only, no disk I/O yet)
            store_keypair(&new_keypair)?;

            #[cfg(debug_assertions)]
            log_debug!("store_keypair took {:?}", store_start.elapsed());

            log_info!("Successfully generated and stored new keypair (not yet saved to disk)");
            Ok((new_keypair, true))
        }
    }
}

/// Get or generate our Curve25519 keypair
/// TODO : this is a public API for backward compatibility, need to fix this later
#[allow(dead_code)]
fn get_or_generate_keypair() -> DllResult<X25519KeyPair> {
    get_or_generate_keypair_internal().map(|(kp, _)| kp)
}

/// Validate that a keypair is not all zeros (safety check)
fn validate_keypair_safety(keypair: &X25519KeyPair) -> DllResult<()> {
    // Use the comprehensive validation function
    validate_keypair(keypair)
}

/// Check if function has timed out
fn check_timeout(start_time: Instant, timeout: std::time::Duration, stage: &str) -> DllResult<()> {
    let elapsed = start_time.elapsed();
    if elapsed > timeout {
        Err(DllError::Timeout {
            operation: "Key Exchange".to_string(),
            duration_secs: timeout.as_secs(),
            stage: stage.to_string(),
        })
    } else {
        #[cfg(debug_assertions)]
        log_debug!("Timeout check passed at stage '{}': {:?} elapsed", stage, elapsed);
        Ok(())
    }
}

/// Generate a secure random key.
///
/// This function attempts to generate a random key using the system's RNG.
/// If the RNG fails, it returns a critical error immediately rather than retrying,
/// as RNG failures usually indicate a systemic issue that retries won't fix.
fn generate_secure_random_key() -> DllResult<[u8; 32]> {
    let start = Instant::now();

    let result = std::panic::catch_unwind(|| {
        let mut key_bytes = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut key_bytes);
        key_bytes
    });

    match result {
        Ok(k) => {
            #[cfg(debug_assertions)]
            log_debug!("RNG generation took {:?}", start.elapsed());
            Ok(k)
        }
        Err(_) => {
            // This is a critical security failure
            log_error!("CRITICAL : system RNG failed (panic caught).");
            Err(DllError::RngFailed {
                context: "System random number generator failed (OsRng panic)".to_string(),
            })
        }
    }
}

/// Validate a keypair using comprehensive checks
fn validate_keypair(keypair: &X25519KeyPair) -> DllResult<()> {
    // Check for all-zero keys
    let zeros = [0u8; 32];
    if keypair.public_key.ct_eq(&zeros).into() {
        return Err(DllError::KeyInvalid { reason: "Public key is all zeros".to_string() });
    }
    if keypair.private_key.expose_secret().ct_eq(&zeros).into() {
        return Err(DllError::KeyInvalid { reason: "Private key is all zeros".to_string() });
    }

    // Check if public key is on the curve (basic validation)
    // MSB should be 0 for a valid Montgomery curve point
    if keypair.public_key[31] & 0x80 != 0 {
        return Err(DllError::KeyInvalid {
            reason: "public key is not a valid curve point".to_string(),
        });
    }

    Ok(())
}

fn is_likely_connected() -> bool {
    // Use the robust GetTcpTable2 check implemented in utils
    // This reliably detects if we have an ESTABLISHED TCP connection
    if is_socket_connected() {
        #[cfg(debug_assertions)]
        log_debug!("is_likely_connected: verified TCP connection found via GetTcpTable2");
        return true;
    }

    // Fallback/Log if not connected
    #[cfg(debug_assertions)]
    log_debug!("is_likely_connected: no verified TCP connection found");
    false
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::ptr;

    use super::*;

    // Helper function to create a test buffer
    fn _create_test_buffer(initial_content: &str) -> (*mut c_char, usize) {
        let buffer_size = 4096;
        let c_string = CString::new(initial_content).expect("CString creation failed");
        let bytes = c_string.as_bytes_with_nul();

        unsafe {
            {
                let buffer = libc::malloc(buffer_size) as *mut c_char;
                ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buffer, bytes.len());
                (buffer, buffer_size)
            }
        }
    }

    // Helper to free test buffer
    unsafe fn _free_test_buffer(buffer: *mut c_char) {
        libc::free(buffer as *mut libc::c_void);
    }

    // Helper to read buffer content
    unsafe fn _read_buffer_content(buffer: *mut c_char) -> String {
        std::ffi::CStr::from_ptr(buffer).to_string_lossy().into_owned()
    }

    #[test]
    fn test_ensure_key_exists_creates_new_key() {
        let nickname = "test_new_user";

        // Clean up any existing key first
        let _ = crate::config::delete_key_default(nickname);

        // Call ensure_key_exists
        let result = ensure_key_exists(nickname);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), true); // Should return true since key was generated

        // Verify key was actually stored
        let retrieved = crate::config::get_key_default(nickname);
        assert!(retrieved.is_ok());

        // Clean up
        let _ = crate::config::delete_key_default(nickname);
    }

    #[test]
    fn test_ensure_key_exists_returns_existing_key() {
        let nickname = "test_existing_user";
        let key = [42u8; 32];

        // Store a key first
        let _ = crate::config::set_key_default(nickname, &key, true);

        // Call ensure_key_exists
        let result = ensure_key_exists(nickname);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), false); // Should return false since key already existed

        // Clean up
        let _ = crate::config::delete_key_default(nickname);
    }

    #[test]
    fn test_get_or_generate_keypair_creates_new() {
        // Clear any existing keypair
        let mut config = CONFIG.write();
        config.our_public_key = None;
        config.our_private_key = None;
        drop(config);

        // Call get_or_generate_keypair
        let result = get_or_generate_keypair();

        assert!(result.is_ok());

        let keypair = result.unwrap();

        // Verify it's not all zeros
        assert_ne!(keypair.public_key, [0u8; 32]);
        assert_ne!(keypair.private_key.expose_secret(), &[0u8; 32]);
    }

    #[test]
    fn test_get_or_generate_keypair_returns_existing() {
        use crate::crypto::generate_keypair;
        // Generate and store a keypair
        let original_keypair = generate_keypair();
        let _ = store_keypair(&original_keypair);

        // Call get_or_generate_keypair
        let result = get_or_generate_keypair();

        assert!(result.is_ok());

        let retrieved_keypair = result.unwrap();

        // Verify we got the same keypair back
        assert_eq!(retrieved_keypair.public_key, original_keypair.public_key);
    }

    #[test]
    fn test_validate_keypair_safety_valid() {
        use crate::crypto::generate_keypair;
        let keypair = generate_keypair();

        let result = validate_keypair_safety(&keypair);

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_keypair_safety_all_zeros() {
        let keypair = X25519KeyPair {
            public_key: [0u8; 32],
            private_key: secrecy::Secret::new([0u8; 32]),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair_safety(&keypair);

        assert!(result.is_err());

        if let Err(DllError::KeyInvalid { reason }) = result {
            assert!(reason.contains("all zeros"));
        } else {
            panic!("Expected KeyInvalid error");
        }
    }

    #[test]
    fn test_validate_keypair_safety_public_zero() {
        let mut private_key = [0u8; 32];
        private_key[0] = 1;

        let keypair = X25519KeyPair {
            public_key: [0u8; 32],
            private_key: secrecy::Secret::new(private_key),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair_safety(&keypair);

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_keypair_safety_private_zero() {
        let mut public_key = [0u8; 32];
        public_key[0] = 1;

        let keypair = X25519KeyPair {
            public_key,
            private_key: secrecy::Secret::new([0u8; 32]),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair_safety(&keypair);

        assert!(result.is_err());
    }
    #[test]
    fn test_check_timeout_not_expired() {
        let start_time = Instant::now();
        let timeout = std::time::Duration::from_secs(30);

        let result = check_timeout(start_time, timeout, "test stage");

        assert!(result.is_ok());
    }

    #[test]
    fn test_check_timeout_expired() {
        let start_time = Instant::now() - std::time::Duration::from_secs(100);
        let timeout = std::time::Duration::from_secs(30);

        let result = check_timeout(start_time, timeout, "test stage");

        assert!(result.is_err());
        if let Err(DllError::Timeout { .. }) = result {
            // Correct error type
        } else {
            panic!("Expected Timeout error");
        }
    }

    #[test]
    fn test_generate_secure_random_key() {
        let result = generate_secure_random_key();
        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.len(), 32);
        assert_ne!(key, [0u8; 32]);
    }

    #[test]
    fn test_generate_secure_random_key_uniqueness() {
        let key1 = generate_secure_random_key().unwrap();
        let key2 = generate_secure_random_key().unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_validate_keypair_valid() {
        let keypair = crate::crypto::generate_keypair();
        let result = validate_keypair(&keypair);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_keypair_all_zeros() {
        let keypair = X25519KeyPair {
            public_key: [0u8; 32],
            private_key: secrecy::Secret::new([0u8; 32]),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair(&keypair);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_keypair_public_zero_only() {
        let mut private_key = [0u8; 32];
        private_key[0] = 1; // Make it non-zero

        let keypair = X25519KeyPair {
            public_key: [0u8; 32],
            private_key: secrecy::Secret::new(private_key),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair(&keypair);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_keypair_private_zero_only() {
        let mut public_key = [0u8; 32];
        public_key[0] = 1; // Make it non-zero

        let keypair = X25519KeyPair {
            public_key,
            private_key: secrecy::Secret::new([0u8; 32]),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair(&keypair);
        assert!(result.is_err());
    }

    #[test]
    fn test_ensure_key_exists_creates_and_persists_entry() {
        let nickname = "testuser_persist";

        // Clean up any existing key first
        let _ = crate::config::delete_key_default(nickname);

        let result = ensure_key_exists(nickname);
        assert!(result.is_ok());

        // Verify key was stored
        let retrieved = crate::config::get_key_default(nickname);
        assert!(retrieved.is_ok());

        // Clean up
        let _ = crate::config::delete_key_default(nickname);
    }

    #[test]
    fn test_get_or_generate_keypair_creates_and_persists_keypair() {
        // Clear any existing keypair
        let mut config = CONFIG.write();
        config.our_public_key = None;
        config.our_private_key = None;
        drop(config);

        let result = get_or_generate_keypair();
        assert!(result.is_ok());

        // Verify keypair was stored by retrieving it again
        let retrieved = get_keypair();
        assert!(retrieved.is_ok());
    }
}
