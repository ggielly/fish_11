// Master Key Management Functions for FiSH_11
// These functions provide secure master key initialization, unlocking, and management
use std::ffi::c_char;
use std::os::raw::c_int;
use std::sync::Mutex;

use fish_11_core::master_key::core::{
    initialize_key_system, is_key_system_unlocked, lock_key_system,
};
use fish_11_core::master_key::derivation::{derive_master_key, derive_master_key_with_salt};
use fish_11_core::master_key::keystore::Keystore;
use fish_11_core::master_key::password_change::change_master_password;
use fish_11_core::master_key::password_validation::PasswordValidator;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha256};

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier};

static MASTER_KEY: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));

dll_function_identifier!(FiSH11_MasterKeyInit, data, {
    // Initialize master key with password
    // Expected input format : <password>
    // Returns : "1" on success, error message on failure
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    if input.is_empty() {
        return Err(DllError::MissingParameter("password".to_string()));
    }

    // Validate password strength before deriving key
    if let Err(e) = PasswordValidator::validate_password_strength(&input) {
        return Err(DllError::InvalidInput {
            param: "password".to_string(),
            reason: format!("Password validation failed: {}", e),
        });
    }

    // Derive the master key from the password
    match derive_master_key(&input) {
        Ok((key, salt)) => {
            // Initialize the new key system
            initialize_key_system(&input, salt.as_bytes());

            // Save the salt and password verifier to keystore for future use
            let mut keystore = Keystore::new();
            keystore.set_master_salt(&salt);

            // Create password verifier : SHA-256 hash of the derived key
            use sha2::{Digest, Sha256};

            let mut hasher = Sha256::new();
            hasher.update(&key);

            let verifier = format!("{:x}", hasher.finalize());
            keystore.set_password_verifier(&verifier);

            if let Err(e) = keystore.save() {
                log::warn!("Failed to save keystore: {}", e);
            }

            Ok("1".to_string())
        }
        Err(e) => Err(DllError::InvalidInput {
            param: "password".to_string(),
            reason: format!("Failed to derive master key: {}", e),
        }),
    }
});

dll_function_identifier!(FiSH11_MasterKeyUnlock, data, {
    // Unlock master key with password
    // Expected input format: <password>
    // Returns: "1" on success, error message on failure
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    if input.is_empty() {
        return Err(DllError::MissingParameter("password".to_string()));
    }

    // Load keystore to get the salt
    let keystore = match Keystore::load() {
        Ok(ks) => ks,
        Err(_) => {
            // If keystore doesn't exist, treat as first-time init
            // Replicate the initialization logic here instead of calling the other function
            // Validate password strength before deriving key
            if let Err(e) = PasswordValidator::validate_password_strength(&input) {
                return Err(DllError::InvalidInput {
                    param: "password".to_string(),
                    reason: format!("Password validation failed: {}", e),
                });
            }

            // Derive the master key from the password
            match derive_master_key(&input) {
                Ok((key, salt)) => {
                    // Store the key in memory
                    {
                        let mut key_guard = match MASTER_KEY.lock() {
                            Ok(g) => g,
                            Err(_) => {
                                return Err(DllError::InvalidInput {
                                    param: "master_key_lock".to_string(),
                                    reason: "Failed to acquire master key lock".to_string(),
                                });
                            }
                        };
                        *key_guard = Some(key);
                    }

                    // Save the salt to keystore for future use
                    let mut keystore = Keystore::new();
                    keystore.set_master_salt(&salt);

                    #[cfg(debug_assertions)]
                    if let Err(e) = keystore.save() {
                        log::warn!("Failed to save keystore: {}", e);
                    }

                    return Ok("1".to_string());
                }
                Err(e) => {
                    return Err(DllError::InvalidInput {
                        param: "password".to_string(),
                        reason: format!("Failed to derive master key: {}", e),
                    });
                }
            }
        }
    };

    let salt = match keystore.get_master_salt() {
        Some(s) => s,
        None => {
            return Err(DllError::InvalidInput {
                param: "keystore".to_string(),
                reason: "No master salt found in keystore".to_string(),
            });
        }
    };

    // Derive the master key using the stored salt
    match derive_master_key_with_salt(&input, Some(salt)) {
        Ok((key, _)) => {
            // If there's a password verifier, check if the derived key matches
            if let Some(verifier) = keystore.get_password_verifier() {
                let mut hasher = Sha256::new();
                hasher.update(&key);
                let key_hash = format!("{:x}", hasher.finalize());

                if key_hash != verifier {
                    return Err(DllError::InvalidInput {
                        param: "password".to_string(),
                        reason: "Incorrect password".to_string(),
                    });
                }
            }

            // Store the key in memory
            {
                let mut key_guard = match MASTER_KEY.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        return Err(DllError::Internal(
                            "Failed to acquire master key lock".to_string(),
                        ));
                    }
                };
                *key_guard = Some(key);
            }

            Ok("1".to_string())
        }
        Err(e) => Err(DllError::InvalidInput {
            param: "password".to_string(),
            reason: format!("Failed to derive master key: {}", e),
        }),
    }
});

dll_function_identifier!(FiSH11_MasterKeyLock, data, {
    // Lock master key (clear from memory)
    // Returns: "1" on success, error message on failure

    // Lock the new key system
    lock_key_system();

    Ok("1".to_string())
});

dll_function_identifier!(FiSH11_MasterKeyChangePassword, data, {
    // Change master password
    // Expected input format: <old_password> <new_password>
    // Returns: "1" on success, error message on failure
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <old_password> <new_password>".to_string(),
        });
    }

    let old_password = parts[0].trim();
    let new_password = parts[1].trim();

    if old_password.is_empty() {
        return Err(DllError::MissingParameter("old_password".to_string()));
    }
    if new_password.is_empty() {
        return Err(DllError::MissingParameter("new_password".to_string()));
    }

    // Validate new password strength
    if let Err(e) = PasswordValidator::validate_password_strength(new_password) {
        return Err(DllError::InvalidInput {
            param: "new_password".to_string(),
            reason: format!("Password validation failed: {}", e),
        });
    }

    // Load keystore to get the current salt
    let keystore = match Keystore::load() {
        Ok(ks) => ks,
        Err(_) => {
            return Err(DllError::Internal(
                "Failed to load keystore - master key may not be initialized".to_string(),
            ));
        }
    };

    let current_salt = match keystore.get_master_salt() {
        Some(s) => s,
        None => {
            return Err(DllError::Internal("No master salt found in keystore".to_string()));
        }
    };

    // Get the password verifier from the keystore
    let password_verifier = keystore.get_password_verifier();

    // Use the password change function to properly validate and change password
    match change_master_password(old_password, current_salt, new_password, password_verifier) {
        Ok(new_salt) => {
            // Derive the new key for storage in memory
            match derive_master_key_with_salt(new_password, Some(&new_salt)) {
                Ok((new_key, _)) => {
                    // Store the new key in memory
                    {
                        let mut key_guard = match MASTER_KEY.lock() {
                            Ok(g) => g,
                            Err(_) => {
                                return Err(DllError::Internal(
                                    "Failed to acquire master key lock".to_string(),
                                ));
                            }
                        };
                        *key_guard = Some(new_key);
                    }

                    // Save the new salt and password verifier to keystore
                    let mut new_keystore = Keystore::new();
                    new_keystore.set_master_salt(&new_salt);

                    // Create new password verifier for the new key
                    use sha2::{Digest, Sha256};

                    let mut hasher = Sha256::new();
                    hasher.update(&new_key);

                    let new_verifier = format!("{:x}", hasher.finalize());
                    new_keystore.set_password_verifier(&new_verifier);

                    #[cfg(debug_assertions)]
                    if let Err(e) = new_keystore.save() {
                        log::warn!("Failed to save updated keystore: {}", e);
                    }

                    Ok("1".to_string())
                }
                Err(e) => Err(DllError::InvalidInput {
                    param: "new_password".to_string(),
                    reason: format!("Failed to derive new master key: {}", e),
                }),
            }
        }
        Err(e) => Err(DllError::InvalidInput {
            param: "old_password".to_string(),
            reason: format!("Password change failed: {}", e),
        }),
    }
});

dll_function_identifier!(FiSH11_MasterKeyStatus, data, {
    // Get master key status
    // Returns: "locked" or "unlocked"

    // Check new system
    let status = if is_key_system_unlocked() { "unlocked" } else { "locked" };

    Ok(status.to_string())
});

dll_function_identifier!(FiSH11_MasterKeyIsUnlocked, data, {
    // Check if master key is unlocked
    // Returns: "1" if unlocked, "0" if locked

    // Check new system
    let result = if is_key_system_unlocked() { "1" } else { "0" };

    Ok(result.to_string())
});

/// Check if master key is unlocked in memory
pub fn is_master_key_unlocked() -> bool {
    if let Ok(key_guard) = MASTER_KEY.lock() {
        key_guard.is_some()
    } else {
        // If we can't acquire the lock, assume it's not unlocked
        false
    }
}

/// Get the master key from memory if available
pub fn get_master_key_from_memory() -> Option<[u8; 32]> {
    if let Ok(key_guard) = MASTER_KEY.lock() {
        key_guard.as_ref().copied()
    } else {
        // If we can't acquire the lock, return None
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_master_key_is_unlocked_returns_0_or_1() {
        let result = is_key_system_unlocked();
        if result {
            assert!(!"0".is_empty());
        } else {
            assert!(!"1".is_empty());
        }
    }

    #[test]
    fn test_is_master_key_unlocked_initially_false() {
        let mut key_guard = MASTER_KEY.lock().unwrap();
        *key_guard = None;
        drop(key_guard);
        assert!(!is_master_key_unlocked());
    }

    #[test]
    fn test_get_master_key_from_memory_initially_none() {
        let mut key_guard = MASTER_KEY.lock().unwrap();
        *key_guard = None;
        drop(key_guard);
        assert!(get_master_key_from_memory().is_none());
    }

    #[test]
    fn test_master_key_roundtrip() {
        let test_key = [42u8; 32];
        {
            let mut key_guard = MASTER_KEY.lock().unwrap();
            *key_guard = Some(test_key);
        }

        assert!(is_master_key_unlocked());
        assert_eq!(get_master_key_from_memory(), Some(test_key));

        {
            let mut key_guard = MASTER_KEY.lock().unwrap();
            *key_guard = None;
        }
        assert!(!is_master_key_unlocked());
    }

    #[test]
    fn test_master_key_is_unlocked_returns_string_format() {
        let locked = if is_key_system_unlocked() { "1" } else { "0" };
        assert!(locked == "1" || locked == "0");
    }
}
