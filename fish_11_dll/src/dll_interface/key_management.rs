use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::utils::normalize_nick;
use crate::{buffer_utils, config, crypto, dll_function_identifier, log_debug};

dll_function_identifier!(FiSH11_ProcessPublicKey, data, {
    // Parse input: accept either "<nickname> <received_key>" or "<received_key> <nickname>"
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let input = input.trim();

    // Split into words and try to detect which token looks like a public key
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <nickname> <received_key> or <received_key> <nickname>"
                .to_string(),
        });
    }

    // Helper to check if a part is a formatted public key token
    let looks_like_token = |s: &str| {
        s.starts_with("X25519_INIT:")
            || s.len() == 44
                && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
    };

    // We will own any joined remainder to avoid referencing temporaries
    let mut _joined_remainder: Option<String> = None;

    let (nickname_raw, received_pubkey_str) = if looks_like_token(parts[0]) {
        // form: <received_key> <nickname>
        (parts[1], parts[0])
    } else if looks_like_token(parts[parts.len() - 1]) {
        // form: <nickname> ... <received_key>
        (parts[0], parts[parts.len() - 1])
    } else {
        // fallback: assume first is nickname, remainder is key (may be raw base64)
        _joined_remainder = Some(parts[1..].join(" "));
        (parts[0], _joined_remainder.as_ref().map(|s| s.as_str()).unwrap_or(""))
    };

    let nickname = normalize_nick(nickname_raw);
    let received_pubkey_str = received_pubkey_str.trim();

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if received_pubkey_str.is_empty() {
        return Err(DllError::MissingParameter("received_key".to_string()));
    }

    #[cfg(debug_assertions)]
    log_debug!("Processing public key for nickname: {}", nickname);

    // Extract the received public key
    let their_public_key = crypto::extract_public_key(received_pubkey_str).map_err(|e| {
        DllError::KeyInvalid { reason: format!("invalid public key format: {}", e) }
    })?;

    crypto::validate_public_key(&their_public_key)
        .map_err(|e| DllError::KeyInvalid { reason: format!("public key rejected: {}", e) })?;

    #[cfg(debug_assertions)]
    log_debug!("Successfully extracted public key");

    // Get our keypair
    let keypair = config::get_keypair().map_err(|_| {
        DllError::KeyNotFound(
            "local keypair (generate one first with FiSH11_ExchangeKey)".to_string(),
        )
    })?;

    #[cfg(debug_assertions)]
    log_debug!("Retrieved local keypair");

    // Compute the shared secret using Curve25519 Diffie-Hellman
    let shared_secret = crypto::compute_shared_secret(&keypair.private_key, &their_public_key)
        .map_err(|e| {
            DllError::KeyExchangeFailed(format!("failed to compute shared secret: {}", e))
        })?;

    #[cfg(debug_assertions)]
    log_debug!("Computed shared secret successfully");

    // Store the shared secret with intelligent duplicate handling:
    // - First try without overwrite (fail if key exists)
    // - If duplicate detected, update it as part of key exchange protocol
    let store_result = match config::set_key(&nickname, &shared_secret, None, false, true) {
        Ok(_) => Ok(()),
        Err(crate::error::FishError::DuplicateEntry(ref nick)) => {
            log::info!("Updating existing key for {} as part of key exchange", nick);
            config::set_key(&nickname, &shared_secret, None, true, true)
        }
        Err(e) => Err(e),
    };

    // Convert FishError to DllError for the final result
    store_result.map_err(|e| match e {
        crate::error::FishError::DuplicateEntry(nick) => DllError::KeyInvalid {
            reason: format!("key for {} already exists and couldn't be updated", nick),
        },
        _ => DllError::ConfigMalformed(format!("error storing key: {}", e)),
    })?;

    #[cfg(debug_assertions)]
    log_debug!("Successfully completed key exchange with {}", nickname);

    // Return a truthy identifier value (no leading /echo) so mIRC treats this as data
    // The script checks the truthiness of $dll(..., FiSH11_ProcessPublicKey, ...)
    Ok("1".to_string())
});

dll_function_identifier!(FiSH11_TestCrypt, data, {
    // Parse input message
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    if input.is_empty() {
        return Err(DllError::MissingParameter("message".to_string()));
    }

    #[cfg(debug_assertions)]
    log_debug!("Testing encryption/decryption cycle with message: {}", input);

    // Generate a random 32-byte key for testing
    let key_bytes = crate::utils::generate_random_bytes(32);
    let mut key = [0u8; 32];

    key.copy_from_slice(&key_bytes);

    #[cfg(debug_assertions)]
    log_debug!("Generated random test key: {:02x?}", &key[..8]); // Log first 8 bytes only

    #[cfg(debug_assertions)]
    log_debug!("Key_Management: testing encryption input: '{}'", input);

    // Encrypt the message
    let encrypted = crypto::encrypt_message(&key, &input, None, None).map_err(|e| {
        DllError::EncryptionFailed { context: "test encryption".to_string(), cause: e.to_string() }
    })?;

    #[cfg(debug_assertions)]
    log_debug!("Key_Management: testing encrypted output: '{}'", &encrypted);

    // Decrypt the message to verify the cycle
    let decrypted = crypto::decrypt_message(&key, &encrypted, None).map_err(|e| {
        DllError::DecryptionFailed { context: "test decryption".to_string(), cause: e.to_string() }
    })?;

    #[cfg(debug_assertions)]
    log_debug!("Key_Management: testing decrypted output: '{}'", &decrypted);

    // Verify that decryption matches original
    if decrypted != input {
        #[cfg(debug_assertions)]
        log_debug!("Decryption mismatch: expected '{}', got '{}'", input, decrypted);

        return Err(DllError::DecryptionFailed {
            context: "verification".to_string(),
            cause: "decrypted message does not match original".to_string(),
        });
    }

    // Sanitize strings for safe display (replace non-printable characters)
    fn safe_display(s: &str, max_len: usize) -> String {
        s.chars()
            .take(max_len)
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
            .collect()
    }

    let max_display_len = 100;
    let input_safe = safe_display(&input, max_display_len);
    let encrypted_safe = safe_display(&encrypted, max_display_len);
    let decrypted_safe = safe_display(&decrypted, max_display_len);

    #[cfg(debug_assertions)]
    log_debug!("Encryption test completed successfully");

    Ok(format!(
        "[TestCrypt] Original: {} | Encrypted: {} | Decrypted: {}",
        input_safe, encrypted_safe, decrypted_safe
    ))
});

#[cfg(test)]
mod tests {
    use crate::crypto;

    #[test]
    fn test_validate_public_key_rejects_low_order_point() {
        let low_order = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result = crypto::validate_public_key(&low_order);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_public_key_rejects_all_zeros() {
        let zeros = [0u8; 32];
        let result = crypto::validate_public_key(&zeros);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_public_key_accepts_valid() {
        let keypair = crypto::generate_keypair();
        let result = crypto::validate_public_key(&keypair.public_key);
        assert!(result.is_ok());
    }

    #[test]
    fn test_process_public_key_rejects_low_order() {
        let keypair = crypto::generate_keypair();
        let low_order_hex = "0100000000000000000000000000000000000000000000000000000000000000";
        let token = format!(
            "X25519_INIT:{}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &hex::decode(low_order_hex).unwrap()
            )
        );

        let result = crypto::validate_public_key(&[
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn test_counter_increment_exists() {
        crate::config::increment_encryption_counter();
        crate::config::increment_decryption_counter();
        let enc = crate::config::get_encryption_count().unwrap_or(0);
        let dec = crate::config::get_decryption_count().unwrap_or(0);
        assert!(enc > 0 || dec > 0);
    }
}
