//! engine_registration.rs
//! Handles the registration of the fish_11_dll as an engine within fish_11_inject.

use std::borrow::Cow;
use std::ffi::{CString, c_char};
use std::ptr;

use once_cell::sync::OnceCell;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::PCSTR;

use crate::config::settings::get_encryption_prefix;
use crate::crypto::{blowfish, decrypt_message, encrypt_message};
use crate::legacy;
use crate::legacy::fish10_message_detection;

type GetNetworkNameFn = unsafe extern "C" fn(u32) -> *mut c_char;
static GET_NETWORK_NAME_FN: OnceCell<GetNetworkNameFn> = OnceCell::new();

type FreeStringFn = unsafe extern "C" fn(*mut c_char);
static GET_FREE_STRING_FN: OnceCell<FreeStringFn> = OnceCell::new();

// C-style struct for engine registration
#[repr(C)]
pub struct FishInjectEngine {
    pub version: u32,
    pub engine_name: *const c_char,
    pub is_postprocessor: bool,
    pub on_outgoing_irc_line: unsafe extern "C" fn(u32, *const c_char, usize) -> *mut c_char,
    pub on_incoming_irc_line: unsafe extern "C" fn(u32, *const c_char, usize) -> *mut c_char,
    pub on_socket_closed: unsafe extern "C" fn(u32),
    pub free_string: unsafe extern "C" fn(*mut c_char),
    pub get_network_name: unsafe extern "C" fn(u32) -> *mut c_char,
}

// SAFETY: FishInjectEngine contains raw pointers but is used for FFI with static data
unsafe impl Sync for FishInjectEngine {}

// Real implementation for get_network_name (calls fish_inject's GetNetworkName)
unsafe extern "C" fn get_network_name_impl(socket: u32) -> *mut c_char {
    if let Some(get_network_name_fn) = GET_NETWORK_NAME_FN.get() {
        return get_network_name_fn(socket);
    }
    ptr::null_mut()
}

// Callback for outgoing messages (encryption)
unsafe extern "C" fn on_outgoing(socket: u32, line: *const c_char, _len: usize) -> *mut c_char {
    if line.is_null() {
        #[cfg(debug_assertions)]
        log_debug!("Engine: received null line pointer, ignoring");
        return ptr::null_mut();
    }

    // CRITICAL: use CStr::from_ptr (borrow) NOT CString::from_raw (take ownership)
    //
    // The caller (inject DLL) still owns this pointer!
    let c_str = match std::ffi::CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error!("Invalid UTF-8 in outgoing line: {}", e);
            return ptr::null_mut();
        }
    };

    // Validate line is not empty or truncated
    if c_str.is_empty() {
        #[cfg(debug_assertions)]
        log_debug!("Engine: received empty line, ignoring");
        return ptr::null_mut();
    }

    // Check for truncated lines (should end with \r\n for IRC protocol)
    if !c_str.ends_with("\r\n") && !c_str.ends_with("\n") {
        #[cfg(debug_assertions)]
        log_warn!(
            "Engine: received potentially truncated line (missing IRC line ending): {}",
            c_str
        );
        // Continue processing but log the warning
    }

    // CRITICAL: update the global current network before processing
    //
    // This ensures encryption uses the correct network context
    let network_name = get_network_name_from_inject(socket);
    if let Some(ref net) = network_name {
        crate::set_current_network(net);
    }

    if let Some(encrypted) = attempt_encryption(c_str, network_name.as_deref()) {
        match CString::new(encrypted) {
            Ok(s) => return s.into_raw(),
            Err(e) => {
                log_error!("Failed to create CString for encrypted data: {}", e);
                return ptr::null_mut();
            }
        }
    }
    ptr::null_mut()
}

// Callback for incoming messages (decryption)
unsafe extern "C" fn on_incoming(socket: u32, line: *const c_char, _len: usize) -> *mut c_char {
    if line.is_null() {
        #[cfg(debug_assertions)]
        log_debug!("Engine: received null line pointer for incoming message, ignoring");
        return ptr::null_mut();
    }

    // CRITICAL: use CStr::from_ptr (borrow) NOT CString::from_raw (take ownership)
    //
    // The caller (inject DLL) still owns this pointer!
    let c_str = match std::ffi::CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error!("Invalid UTF-8 in incoming line: {}", e);
            return ptr::null_mut();
        }
    };

    // Validate line is not empty or truncated
    if c_str.is_empty() {
        #[cfg(debug_assertions)]
        log_debug!("Engine: received empty incoming line, ignoring");
        return ptr::null_mut();
    }

    // Check for truncated lines (should end with \r\n for IRC protocol)
    if !c_str.ends_with("\r\n") && !c_str.ends_with("\n") {
        #[cfg(debug_assertions)]
        log_warn!(
            "Engine: received potentially truncated incoming line (missing IRC line ending): {}",
            c_str
        );
        // Continue processing but log the warning
    }

    // CRITICAL: update the global current network before processing
    //
    // This ensures that any DLL functions called (like set_key during key exchange)
    // will use the correct network name for this socket
    let network_name = get_network_name_from_inject(socket);
    if let Some(ref net) = network_name {
        crate::set_current_network(net);

        #[cfg(debug_assertions)]
        log_debug!("Engine: set current network to '{}' for socket {}", net, socket);
    }

    if let Some(decrypted) = attempt_decryption(c_str, network_name.as_deref()) {
        match CString::new(decrypted) {
            Ok(s) => return s.into_raw(),
            Err(e) => {
                log_error!("Failed to create CString for decrypted data: {}", e);
                return ptr::null_mut();
            }
        }
    }
    ptr::null_mut()
}

// Placeholder for socket close event
unsafe extern "C" fn on_close(_socket: u32) {
    // No special handling needed on socket close for now
    // TODO : Implement any necessary cleanup if needed in the future
}

// Function to free memory allocated for returned strings
unsafe extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// Engine definition
#[no_mangle]
pub static FISH_INJECT_ENGINE: FishInjectEngine = FishInjectEngine {
    version: 1,
    engine_name: b"FiSH_11_Engine".as_ptr() as *const _,
    is_postprocessor: false,
    on_outgoing_irc_line: on_outgoing,
    on_incoming_irc_line: on_incoming,
    on_socket_closed: on_close,
    free_string,
    get_network_name: get_network_name_impl,
};

// Function to attempt encryption
fn attempt_encryption(line: &str, network_name: Option<&str>) -> Option<String> {
    // Only encrypt outgoing PRIVMSG/NOTICE/TOPIC commands
    if !line.contains(" PRIVMSG ") && !line.contains(" NOTICE ") && !line.contains(" TOPIC ") {
        return None;
    }

    #[cfg(debug_assertions)]
    log_debug!("Engine: attempting to encrypt outgoing line");

    // Clean the line and extract the message part
    let line_content = line.trim_end_matches(|c| c == '\r' || c == '\n');
    let parts: Vec<&str> = line_content.splitn(2, " :").collect();

    if parts.len() < 2 {
        #[cfg(debug_assertions)]
        log_debug!("Engine: skipping line with no message separator (not a typical PRIVMSG/TOPIC)");
        return None;
    }

    let cmd_part = parts[0];
    let message = parts[1];

    // Skip if already encrypted with FiSH 10 or FiSH 11
    // Get the encryption prefix from config (defaults to "+FiSH")
    let encryption_prefix = get_encryption_prefix().unwrap_or_else(|_| "+FiSH".to_string());
    if fish10_message_detection::is_fish10_message(message)
        || message.starts_with(&encryption_prefix)
    {
        return None;
    }

    // Extract target from command part
    // Could be "PRIVMSG #channel" or ":prefix PRIVMSG #channel"
    let (target_part, is_topic) = if let Some(privmsg_pos) = cmd_part.find(" PRIVMSG ") {
        (&cmd_part[privmsg_pos + 9..], false)
    } else if cmd_part.starts_with("PRIVMSG ") {
        (&cmd_part[8..], false)
    } else if let Some(notice_pos) = cmd_part.find(" NOTICE ") {
        (&cmd_part[notice_pos + 8..], false)
    } else if cmd_part.starts_with("NOTICE ") {
        (&cmd_part[7..], false)
    } else if let Some(topic_pos) = cmd_part.find(" TOPIC ") {
        (&cmd_part[topic_pos + 7..], true)
    } else if cmd_part.starts_with("TOPIC ") {
        (&cmd_part[6..], true)
    } else {
        #[cfg(debug_assertions)]
        log_warn!("Engine: could not extract target from command part: {}", cmd_part);
        return None;
    };

    let target = target_part.trim();

    #[cfg(debug_assertions)]
    log_debug!("Engine: extracted target={}, is_topic={}", target, is_topic);

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let target = crate::utils::normalize_target(target);

    // For topics, we need to use the channel key but NOT advance the ratchet (topics are special)
    // For channels (#, &) in regular messages, we handle encryption with ratchet advancement (like fish11_encryptmsg.rs)
    // For private messages, we use standard key lookup
    let (encrypted, used_legacy) = if is_topic {
        // Handle topic encryption using the channel key but without ratchet advancement
        #[cfg(debug_assertions)]
        log_debug!("Engine: attempting topic encryption for '{}'", target);

        let key_result = crate::config::get_channel_key_with_fallback(target);

        if let Ok(key) = key_result {
            let key_array: &[u8; 32] = match key.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    log_error!("Engine: invalid key length for topic on channel '{}'", target);
                    return None;
                }
            };

            // Encrypt the message with the channel name as Associated Data (to prevent cross-channel replay)
            let encrypted =
                match encrypt_message(key_array, &message, Some(target), Some(target.as_bytes())) {
                    Ok(enc) => enc,
                    Err(e) => {
                        log_error!(
                            "Engine: topic encryption failed for channel '{}': {}",
                            target,
                            e
                        );
                        return None;
                    }
                };

            (encrypted, false)
        } else if let Some(legacy_key) = legacy::get_legacy_key(&target.to_lowercase()) {
            #[cfg(debug_assertions)]
            log_debug!("Engine: using legacy key for topic on '{}'", target);

            let encrypted =
                match blowfish::encrypt_message(&legacy_key, &message, target.as_bytes()) {
                    Ok(enc) => enc,
                    Err(e) => {
                        log_error!(
                            "Engine: legacy topic encryption failed for '{}': {}",
                            target,
                            e
                        );
                        return None;
                    }
                };
            (encrypted, true)
        } else {
            // No key = no encryption, pass through
            return None;
        }
    } else if target.starts_with('#') || target.starts_with('&') {
        #[cfg(debug_assertions)]
        log_debug!("Engine: attempting channel message encryption for '{}'", target);

        // For channels, first check if we have a manual key. If so, use it for simple encryption (no ratchet)
        // If not, use the ratchet state (handles FCEP-1 encryption with forward secrecy)
        if crate::config::has_channel_key(target) {
            // Use the channel key (manual or ratchet-based) but without ratchet advancement
            // This is for when we want to use a fixed key for a channel without forward secrecy
            match crate::config::get_channel_key_with_fallback(target) {
                Ok(key) => {
                    // Log message content if DEBUG flag is enabled for sensitive content
                    #[cfg(debug_assertions)]
                    log_debug!(
                        "Engine: channel message encryption input for channel '{}': '{}'",
                        target,
                        &message
                    );

                    // Encrypt with the fixed key, using the channel name as Associated Data.
                    match encrypt_message(&key, &message, Some(target), Some(target.as_bytes())) {
                        Ok(encrypted_b64) => {
                            #[cfg(debug_assertions)]
                            log_debug!(
                                "Engine: channel message encrypted output for channel '{}': '{}'",
                                target,
                                &encrypted_b64
                            );

                            (encrypted_b64, false)
                        }
                        Err(e) => {
                            log_error!(
                                "Engine: channel encryption failed for '{}' (manual key): {}",
                                target,
                                e
                            );
                            return None;
                        }
                    }
                }
                Err(e) => {
                    log_error!("Engine: failed to get channel key for '{}': {}", target, e);
                    return None;
                }
            }
        } else if let Some(legacy_key) = legacy::get_legacy_key(&target.to_lowercase()) {
            #[cfg(debug_assertions)]
            log_debug!("Engine: using legacy key for channel message on '{}'", target);

            let encrypted = match crate::crypto::blowfish::encrypt_message(
                &legacy_key,
                &message,
                target.as_bytes(),
            ) {
                Ok(enc) => enc,
                Err(e) => {
                    log_error!(
                        "Engine: legacy channel message encryption failed for '{}': {}",
                        target,
                        e
                    );
                    return None;
                }
            };
            (encrypted, true)
        } else {
            // Use ratchet-based encryption (FCEP-1 with forward secrecy)
            match crate::config::with_ratchet_state_mut(target, |state| {
                let current_key = state.current_key;

                #[cfg(debug_assertions)]
                log_debug!(
                    "Engine: ratchet channel encryption input for channel '{}': '{}'",
                    target,
                    &message
                );

                // Encrypt with the current key, using the channel name as Associated Data.
                let encrypted_b64 =
                    encrypt_message(&current_key, &message, Some(target), Some(target.as_bytes()))
                        .map_err(crate::unified_error::DllError::from)?;

                #[cfg(debug_assertions)]
                log_debug!(
                    "Engine: ratchet channel encrypted output for channel '{}': '{}'",
                    target,
                    &encrypted_b64
                );

                // Extract the nonce from the encrypted payload to derive the next key.
                let encrypted_bytes = crate::utils::base64_decode(&encrypted_b64)
                    .map_err(crate::unified_error::DllError::from)?;
                if encrypted_bytes.len() < 24 {
                    return Err(crate::unified_error::DllError::EncryptionFailed {
                        context: "payload validation".to_string(),
                        cause: "Encrypted payload too short to contain a nonce".to_string(),
                    });
                }
                let nonce: [u8; 24] = encrypted_bytes[..24].try_into().map_err(|_| {
                    crate::unified_error::DllError::EncryptionFailed {
                        context: "nonce extraction".to_string(),
                        cause: "Could not convert slice to 24-byte nonce array".to_string(),
                    }
                })?;

                // Advance the ratchet to the next key.
                let next_key = crate::crypto::advance_ratchet_key(&current_key, &nonce, target)?;
                state.advance(next_key);

                Ok(encrypted_b64)
            }) {
                Ok(encrypted_b64) => (encrypted_b64, false),
                Err(e) => {
                    log_error!("Engine: channel encryption failed for '{}': {}", target, e);
                    return None;
                }
            }
        }
    } else {
        // For private messages, use standard key lookup
        log_debug!("Engine: attempting private message encryption for '{}'", target);

        let key_result = crate::config::get_key(target, network_name.as_deref());

        if let Ok(key) = key_result {
            let key_array: &[u8; 32] = match key.as_slice().try_into() {
                Ok(arr) => arr,
                Err(_) => {
                    log_error!("Engine: invalid key length for target '{}'", target);
                    return None;
                }
            };

            #[cfg(debug_assertions)]
            log_debug!(
                "Engine: private message encryption input for target '{}': '{}'",
                target,
                &message
            );

            // Encrypt the message (no AD for private messages).
            let encrypted = match encrypt_message(key_array, &message, Some(target), None) {
                Ok(enc) => {
                    #[cfg(debug_assertions)]
                    log_debug!(
                        "Engine: private message encrypted output for target '{}': '{}'",
                        target,
                        &enc
                    );

                    enc
                }
                Err(e) => {
                    log_error!("Engine: encryption failed for target '{}': {}", target, e);
                    return None;
                }
            };

            (encrypted, false)
        } else if let Some(legacy_key) = legacy::get_legacy_key(&target.to_lowercase()) {
            #[cfg(debug_assertions)]
            log_debug!("Engine: using legacy key for private message on '{}'", target);

            let encrypted = match blowfish::encrypt_message(&legacy_key, &message, &[]) {
                Ok(enc) => enc,
                Err(e) => {
                    log_error!(
                        "Engine: legacy private message encryption failed for '{}': {}",
                        target,
                        e
                    );
                    return None;
                }
            };
            (encrypted, true)
        } else {
            // No key = no encryption, pass through
            #[cfg(debug_assertions)]
            log_debug!(
                "Engine: no key for target '{}' on network '{:?}', not encrypting",
                target,
                network_name
            );
            return None;
        }
    };

    let msg_type = if is_topic {
        "topic"
    } else if target.starts_with('#') || target.starts_with('&') {
        "channel message"
    } else {
        "private message"
    };

    #[cfg(debug_assertions)]
    log_info!("Engine: successfully encrypted {} to '{}'", msg_type, target);

    // Reconstruct line with encrypted data
    // For FiSH 11 topics, use space after prefix. For FiSH 10 legacy, no space.
    let encrypted_line = if is_topic {
        if used_legacy {
            format!("{} :+OK{}\r\n", cmd_part, encrypted)
        } else {
            format!("{} :+FCEP_TOPIC+ {}\r\n", cmd_part, encrypted)
        }
    } else {
        let prefix = if used_legacy { "+OK" } else { encryption_prefix.as_str() };
        format!("{} :{} {}\r\n", cmd_part, prefix, encrypted)
    };

    #[cfg(debug_assertions)]
    log_info!("Engine: outgoing line reconstructed: '{}'", encrypted_line.trim_end());

    Some(encrypted_line)
}

// Function to attempt decryption
fn attempt_decryption(line: &str, network: Option<&str>) -> Option<String> {
    #[cfg(debug_assertions)]
    log_debug!("Engine: attempt_decryption called for line: {}, network: {:?}", line, network);

    // Handle RPL_TOPIC (332) for encrypted channel topics (when joining a channel)
    if line.contains(" 332 ") {
        let msg_index = match line.find(" :") {
            Some(pos) => pos,
            None => return None,
        };
        let message_part = &line[msg_index + 2..];

        let is_fcep = message_part.starts_with("+FCEP_TOPIC+");
        let is_legacy = fish10_message_detection::is_fish10_message(message_part);

        if is_fcep || is_legacy {
            #[cfg(debug_assertions)]
            log_info!("Engine: processing encrypted RPL_TOPIC (332) for channel topic");

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 5 {
                log_warn!("Engine: malformed encrypted topic line (not enough parts): {}", line);
                return None;
            }

            let channel_name = parts[3];
            let key_identifier = crate::utils::normalize_target(channel_name).to_lowercase();

            // Extract the encrypted payload
            let encrypted_payload: Cow<str> = if is_fcep {
                Cow::Borrowed(message_part["+FCEP_TOPIC+".len()..].trim())
            } else {
                Cow::Owned(fish10_message_detection::extract_fish10_payload(message_part).ok()?)
            };

            if is_fcep {
                // FiSH 11 Topic Decryption
                let key = match crate::config::get_channel_key_with_fallback(&key_identifier) {
                    Ok(k) => k.to_vec(),
                    Err(_) => match crate::config::get_key(&key_identifier, network) {
                        Ok(k) => k,
                        Err(_) => return None,
                    },
                };

                let key_array: &[u8; 32] = key.as_slice().try_into().ok()?;
                let decrypted =
                    decrypt_message(key_array, &encrypted_payload, Some(key_identifier.as_bytes()))
                        .ok()?;

                log_info!(
                    "Engine: successfully decrypted FCEP topic for channel '{}'",
                    key_identifier
                );
                let prefix_and_command = &line[..msg_index];
                return Some(format!("{} :{}\r\n", prefix_and_command, decrypted));
            } else {
                // Legacy FiSH 10 Topic Decryption
                if let Some(key) = legacy::get_legacy_key(&key_identifier) {
                    match blowfish::decrypt_message(
                        &key,
                        &encrypted_payload,
                        key_identifier.as_bytes(),
                    ) {
                        Ok(decrypted) => {
                            log_info!(
                                "Engine: successfully decrypted legacy topic for channel '{}'",
                                key_identifier
                            );
                            let prefix_and_command = &line[..msg_index];
                            return Some(format!("{} :{}\r\n", prefix_and_command, decrypted));
                        }
                        Err(e) => {
                            log_error!(
                                "Engine: legacy topic decryption failed for channel '{}': {}",
                                key_identifier,
                                e
                            );
                            return None;
                        }
                    }
                }
            }
        }
    }

    // Handle incoming TOPIC notifications (when someone changes the topic)
    // Format: :nick!user@host TOPIC #channel :+FCEP_TOPIC+ encrypted_data
    if line.starts_with(':') && line.contains(" TOPIC ") {
        let msg_index = match line.find(" :") {
            Some(pos) => pos,
            None => return None,
        };
        let message_part = &line[msg_index + 2..];

        let is_fcep = message_part.starts_with("+FCEP_TOPIC+");
        let is_legacy = fish10_message_detection::is_fish10_message(message_part);

        if is_fcep || is_legacy {
            #[cfg(debug_assertions)]
            log_info!("Engine: processing encrypted incoming TOPIC notification");

            let topic_pos = line.find(" TOPIC ").unwrap();
            let after_topic_cmd = &line[topic_pos + 7..];
            let parts: Vec<&str> = after_topic_cmd.split_whitespace().collect();

            if parts.is_empty() {
                return None;
            }

            let channel_name = parts[0];
            let key_identifier = crate::utils::normalize_target(channel_name).to_lowercase();

            // Extract the encrypted payload
            let encrypted_payload: Cow<str> = if is_fcep {
                Cow::Borrowed(message_part["+FCEP_TOPIC+".len()..].trim())
            } else {
                Cow::Owned(fish10_message_detection::extract_fish10_payload(message_part).ok()?)
            };

            if is_fcep {
                // FiSH 11 Topic Decryption
                let key = match crate::config::get_channel_key_with_fallback(&key_identifier) {
                    Ok(k) => k.to_vec(),
                    Err(_) => match crate::config::get_key(&key_identifier, network) {
                        Ok(k) => k,
                        Err(_) => return None,
                    },
                };

                let key_array: &[u8; 32] = key.as_slice().try_into().ok()?;
                let decrypted =
                    decrypt_message(key_array, &encrypted_payload, Some(key_identifier.as_bytes()))
                        .ok()?;

                log_info!(
                    "Engine: successfully decrypted incoming FCEP topic for channel '{}'",
                    key_identifier
                );
                let prefix_and_command = &line[..msg_index];
                return Some(format!("{} :{}\r\n", prefix_and_command, decrypted));
            } else {
                // Legacy FiSH 10 Topic Decryption
                if let Some(key) = legacy::get_legacy_key(&key_identifier) {
                    match blowfish::decrypt_message(
                        &key,
                        &encrypted_payload,
                        key_identifier.as_bytes(),
                    ) {
                        Ok(decrypted) => {
                            log_info!(
                                "Engine: successfully decrypted incoming legacy topic for channel '{}'",
                                key_identifier
                            );
                            let prefix_and_command = &line[..msg_index];
                            return Some(format!("{} :{}\r\n", prefix_and_command, decrypted));
                        }
                        Err(e) => {
                            log_error!(
                                "Engine: incoming legacy topic decryption failed for channel '{}': {}",
                                key_identifier,
                                e
                            );
                            return None;
                        }
                    }
                }
            }
        }
    }

    // Check if this is a DH1080 key exchange message - these should be handled by the legacy engine
    if line.contains("DH1080_INIT") || line.contains("DH1080_FINISH") {
        #[cfg(debug_assertions)]
        log_debug!("Engine: detected DH1080 message, skipping main engine processing");
        return None;
    }

    // Get the encryption prefix from config (defaults to "+FiSH")
    let encryption_prefix = get_encryption_prefix().unwrap_or_else(|_| "+FiSH".to_string());

    // Find the message part (after the first " :")
    let msg_index = match line.find(" :") {
        Some(pos) => pos,
        None => return None,
    };
    let message_part = &line[msg_index + 2..];

    // Check for encryption markers
    let is_legacy = fish10_message_detection::is_fish10_message(message_part);
    let is_fish11 = message_part.starts_with(&encryption_prefix);

    if !is_legacy && !is_fish11 {
        #[cfg(debug_assertions)]
        log_debug!("Engine: line does not contain a known encryption prefix, skipping");
        return None;
    }

    // Handle legacy decryption
    if is_legacy {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // Extract sender and target
        let sender_raw = parts[0].trim_start_matches(':');
        let sender =
            if let Some(pos) = sender_raw.find('!') { &sender_raw[..pos] } else { sender_raw };
        let target_raw = parts[2];

        // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan..)
        let target = crate::utils::normalize_target(target_raw);

        // Determine which identifier to use for key lookup
        let key_identifier = if target.starts_with('#') || target.starts_with('&') {
            target.to_lowercase()
        } else {
            sender.to_lowercase()
        };

        #[cfg(debug_assertions)]
        log_debug!(
            "Engine: legacy message detected from '{}' to '{}', identifier='{}'",
            sender,
            target,
            key_identifier
        );

        if let Some(key) = legacy::get_legacy_key(&key_identifier) {
            if let Ok(payload) = fish10_message_detection::extract_fish10_payload(message_part) {
                match blowfish::decrypt_message(&key, &payload, key_identifier.as_bytes()) {
                    Ok(decrypted) => {
                        #[cfg(debug_assertions)]
                        log_info!(
                            "Engine: successfully decrypted legacy message from '{}'",
                            sender
                        );
                        let prefix_and_command = &line[..msg_index];
                        return Some(format!("{} :{}\r\n", prefix_and_command, decrypted));
                    }
                    Err(e) => {
                        log_error!(
                            "Engine: legacy decryption failed for sender '{}': {}",
                            sender,
                            e
                        );
                        return None;
                    }
                }
            }
        }

        #[cfg(debug_assertions)]
        log_debug!("Engine: no legacy key found for '{}', passing through", key_identifier);
        return None;
    }

    // CRITICAL: do NOT decrypt key exchange messages !#@
    // X25519_INIT and X25519_FINISH must pass through unchanged so mIRC can handle them
    if line.contains("X25519_INIT:") || line.contains("X25519_FINISH") {
        #[cfg(debug_assertions)]
        log_debug!("Engine: ignoring key exchange message (X25519_INIT/FINISH)");
        return None;
    }

    #[cfg(debug_assertions)]
    log_debug!("Engine: attempting to decrypt line: {}", line);

    // Parse IRC line format: ":nick!user@host PRIVMSG target :+FiSH <data>"
    let parts: Vec<&str> = line.split_whitespace().collect();

    if parts.len() < 4 {
        #[cfg(debug_assertions)]
        log_warn!("Engine: malformed IRC line (not enough parts): {}", line);
        return None;
    }

    // Extract sender nickname (remove : prefix and everything after !)
    let sender_raw = parts[0].trim_start_matches(':');
    let sender = if let Some(pos) = sender_raw.find('!') { &sender_raw[..pos] } else { sender_raw };

    // Extract target (channel or nickname)
    // Format: ":nick!user@host PRIVMSG target :message"
    let target_raw = parts.get(2).unwrap_or(&"");

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan..)
    let target = crate::utils::normalize_target(target_raw);

    // Find the encrypted data after the configured prefix (e.g., ":+FiSH ")
    let fish_marker_search = format!(":{}", encryption_prefix);
    let fish_start = match line.find(&fish_marker_search) {
        Some(pos) => pos + fish_marker_search.len(),
        None => {
            #[cfg(debug_assertions)]
            log_warn!("Engine: FiSH_11 marker found but position parse failed");
            return None;
        }
    };
    let encrypted_data = line[fish_start..].trim();

    // Determine which identifier to use for key lookup
    // For channels (#, &) : we use the channel name and normalize to lowercase.
    // For private messages :  we use the sender's nickname and normalize to lowercase.
    let key_identifier = if target.starts_with('#') || target.starts_with('&') {
        target.to_lowercase()
    } else {
        sender.to_lowercase()
    };

    #[cfg(debug_assertions)]
    log_debug!(
        "Engine: sender={}, target={}, key_identifier={}, encrypted_data_len={}",
        sender,
        target,
        key_identifier,
        encrypted_data.len()
    );

    // Try to get the decryption key
    let key = if key_identifier.starts_with('#') || key_identifier.starts_with('&') {
        // For channel messages, try channel key (manual or ratchet-based) first
        match crate::config::get_channel_key_with_fallback(&key_identifier) {
            Ok(k) => {
                #[cfg(debug_assertions)]
                log_debug!("Engine: using channel key for '{}'", key_identifier);
                k.to_vec() // Convert to vec for compatibility with existing code
            }
            Err(_) => {
                // If no channel key, try the regular key lookup
                match crate::config::get_key(&key_identifier, network) {
                    Ok(k) => {
                        #[cfg(debug_assertions)]
                        log_debug!("Engine: using regular key for '{}'", key_identifier);
                        k
                    }
                    Err(e) => {
                        #[cfg(debug_assertions)]
                        log_warn!("Engine: no key found for '{}': {}", key_identifier, e);
                        return None;
                    }
                }
            }
        }
    } else {
        // For private messages, use regular key lookup with normalized key_identifier
        match crate::config::get_key(&key_identifier, network) {
            Ok(k) => {
                #[cfg(debug_assertions)]
                log_debug!("Engine: using private key for '{}'", key_identifier);
                k
            }
            Err(e) => {
                #[cfg(debug_assertions)]
                log_warn!("Engine: no key found for '{}': {}", key_identifier, e);
                return None;
            }
        }
    };

    let key_array: &[u8; 32] = match key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            log_error!("Engine: invalid key length for identifier '{}'", key_identifier);
            return None;
        }
    };

    // Decrypt the message with the same Associated Data used during encryption
    // For channel messages, the channel name is used as AD
    let associated_data = if key_identifier.starts_with('#') || key_identifier.starts_with('&') {
        Some(key_identifier.as_bytes())
    } else {
        None
    };

    let decrypted = match decrypt_message(key_array, encrypted_data, associated_data) {
        Ok(msg) => msg,
        Err(e) => {
            log_error!("Engine: decryption failed for sender '{}': {}", sender, e);
            return None;
        }
    };

    #[cfg(debug_assertions)]
    log_info!("Engine: successfully decrypted message from '{}'", sender);

    #[cfg(debug_assertions)]
    log_debug!("Engine: decrypted content from '{}': '{}'", sender, &decrypted);

    // Reconstruct the IRC line with decrypted plaintext
    // Format: ":nick!user@host COMMAND target :decrypted_message\r\n"
    // CRITICAL: IRC protocol requires \r\n at the end of each line!

    // Find the start of the message part (the configured prefix, e.g., " :+FiSH ...")
    let prefix_search = format!(" :{}", encryption_prefix);
    let message_part_start = match line.find(&prefix_search) {
        Some(pos) => pos,
        None => {
            log_error!("Engine: could not find message part ' {} ' in line", prefix_search);
            return None;
        }
    };

    // The part of the line before the message is the full prefix, command, and target
    let prefix_and_command = &line[..message_part_start];
    let reconstructed = format!("{} :{}\r\n", prefix_and_command, decrypted);

    Some(reconstructed)
}

type RegisterEngineFn = extern "C" fn(*const FishInjectEngine) -> i32;

pub fn register_engine() {
    #[cfg(debug_assertions)]
    log_info!("Attempting to register FiSH_11 engine with inject0r...");
    unsafe {
        let inject_dll_name = CString::new("fish_11_inject.dll").unwrap();
        let h_module: HMODULE =
            GetModuleHandleA(PCSTR(inject_dll_name.as_ptr() as *const u8)).unwrap_or_default();

        if h_module.0.is_null() {
            #[cfg(debug_assertions)]
            log_warn!("fish_11_inject.dll not found in process. Engine not registered.");
            return;
        }

        let get_network_name_fn_name = CString::new("GetNetworkName").unwrap();
        let get_network_name_fn =
            GetProcAddress(h_module, PCSTR(get_network_name_fn_name.as_ptr() as *const u8));

        if get_network_name_fn.is_none() {
            log_error!("GetNetworkName function not found in fish_11_inject.dll.");
        } else {
            let get_network_name_fn_ptr: GetNetworkNameFn =
                std::mem::transmute(get_network_name_fn.unwrap());
            if let Err(_) = GET_NETWORK_NAME_FN.set(get_network_name_fn_ptr) {
                #[cfg(debug_assertions)]
                log_error!("GetNetworkName function already set, this should not happen.");
            }
        }

        let free_string_fn_name = CString::new("FreeString").unwrap();
        let free_string_fn =
            GetProcAddress(h_module, PCSTR(free_string_fn_name.as_ptr() as *const u8));

        if free_string_fn.is_none() {
            #[cfg(debug_assertions)]
            log_warn!("FreeString function not found in fish_11_inject.dll.");
        } else {
            let free_string_fn_ptr: FreeStringFn = std::mem::transmute(free_string_fn.unwrap());
            if let Err(_) = GET_FREE_STRING_FN.set(free_string_fn_ptr) {
                #[cfg(debug_assertions)]
                log_error!("FreeString function already set, this should not happen.");
            }
        }

        let register_fn_name = CString::new("RegisterEngine").unwrap();
        let register_fn = GetProcAddress(h_module, PCSTR(register_fn_name.as_ptr() as *const u8));

        if register_fn.is_none() {
            #[cfg(debug_assertions)]
            log_error!("RegisterEngine function not found in fish_11_inject.dll.");
            return;
        }

        let register_engine_fn: RegisterEngineFn = std::mem::transmute(register_fn.unwrap());
        let result = register_engine_fn(&FISH_INJECT_ENGINE);

        if result == 0 {
            #[cfg(debug_assertions)]
            log_info!("Successfully registered FiSH_11 engine.");
        } else {
            #[cfg(debug_assertions)]
            log_error!("Failed to register FiSH_11 engine. Error code : {}", result);
        }
    }
}

pub fn get_network_name_from_inject(socket_id: u32) -> Option<String> {
    unsafe {
        if let Some(get_network_name_fn) = GET_NETWORK_NAME_FN.get() {
            let c_char_ptr = get_network_name_fn(socket_id);

            if !c_char_ptr.is_null() {
                // Use CStr::from_ptr to borrow the string, then copy it to a Rust String,
                // and free via the inject DLL's FreeString to respect the API contract.
                // Using CString::from_raw would take ownership and free with the wrong allocator.
                let c_str = std::ffi::CStr::from_ptr(c_char_ptr);
                let rust_string = c_str.to_string_lossy().into_owned();

                if let Some(free_string_fn) = GET_FREE_STRING_FN.get() {
                    free_string_fn(c_char_ptr);
                }

                return Some(rust_string);
            }
        }
    }
    None
}
