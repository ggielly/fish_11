//! This module contains the hooks for Winsock functions
//! It includes the hooks for recv, send, connect, and closesocket

use std::ffi::c_int;
use std::sync::{Arc, Mutex as StdMutex};

use fish_11_core::globals::{
    CMD_JOIN, CMD_NOTICE, CMD_PRIVMSG, KEY_EXCHANGE_INIT, KEY_EXCHANGE_PUBKEY,
};
use log::{debug, error, info, trace, warn};
use retour::{Function, GenericDetour};
use sha2::{Digest, Sha256};
use windows::Win32::Networking::WinSock::{
    SOCKADDR, SOCKET, SOCKET_ERROR, WSAEINTR, WSAEINVAL, WSAGetLastError, WSASetLastError,
};

use crate::socket::handlers::protocol_detection;
use crate::socket::info::SocketInfo;
use crate::socket::state::SocketState;
use crate::{ACTIVE_SOCKETS, DISCARDED_SOCKETS, ENGINES, InjectEngines};

/// Return [`SOCKET_ERROR`] and set a Winsock error for callers (`WSAGetLastError`).
#[inline]
unsafe fn wsa_fail(code: i32) -> c_int {
    WSASetLastError(code);
    SOCKET_ERROR
}

// Type definitions for Winsock functions and ensure "system" ABI (stdcall) for function types
pub type RecvFn = unsafe extern "system" fn(SOCKET, *mut u8, c_int, c_int) -> c_int;
pub type SendFn = unsafe extern "system" fn(SOCKET, *const u8, c_int, c_int) -> c_int;
pub type ConnectFn = unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;
pub type ClosesocketFn = unsafe extern "system" fn(SOCKET) -> c_int;

// Thread-safe static variables for function hooks
pub static RECV_HOOK: StdMutex<Option<GenericDetour<RecvFn>>> = StdMutex::new(None);
pub static SEND_HOOK: StdMutex<Option<GenericDetour<SendFn>>> = StdMutex::new(None);
pub static CONNECT_HOOK: StdMutex<Option<GenericDetour<ConnectFn>>> = StdMutex::new(None);
pub static CLOSESOCKET_HOOK: StdMutex<Option<GenericDetour<ClosesocketFn>>> = StdMutex::new(None);

// Maximum number of bytes to preview in debug logs
const MAXIMUM_PREVIEW_SIZE: usize = 64;
//const TRACE_PREVIEW_SIZE: usize = 16;

/// Copy the trampoline (original API) out of a detour. Callers must **drop the hook mutex**
/// before invoking the returned pointer, or same-thread re-entry into the hook deadlocks on a
/// non-reentrant `std::sync::Mutex`. (`GenericDetour::trampoline` is `&()`; transmute needs a
/// concrete function type : see `retour` tests.)
///
/// # Safety
/// - The `hook` must be a valid, installed detour created by `retour::detour`
/// - The returned function pointer is valid only while the detour is installed
/// - The caller must not call the returned function while holding the hook mutex
#[inline]
unsafe fn recv_detour_original(hook: &GenericDetour<RecvFn>) -> RecvFn {
    std::mem::transmute(hook.trampoline())
}
/// SAFETY: Same constraints as `recv_detour_original` above.
#[inline]
unsafe fn send_detour_original(hook: &GenericDetour<SendFn>) -> SendFn {
    std::mem::transmute(hook.trampoline())
}
/// SAFETY: Same constraints as `recv_detour_original` above.
#[inline]
unsafe fn connect_detour_original(hook: &GenericDetour<ConnectFn>) -> ConnectFn {
    std::mem::transmute(hook.trampoline())
}
/// SAFETY: Same constraints as `recv_detour_original` above.
#[inline]
unsafe fn closesocket_detour_original(hook: &GenericDetour<ClosesocketFn>) -> ClosesocketFn {
    std::mem::transmute(hook.trampoline())
}

/// Hook implementation for recv
pub unsafe extern "system" fn hooked_recv(
    s: SOCKET,
    buf: *mut u8,
    len: c_int,
    flags: c_int,
) -> c_int {
    #[cfg(debug_assertions)]
    info!("* hooked_recv() called for socket {}", s.0);

    let socket_info = get_or_create_socket(s.0 as u32, true);

    // Acquire the hook lock with timeout to avoid deadlocks during hook uninstall
    let hook_guard = match crate::lock_utils::try_lock_timeout(
        &RECV_HOOK,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire RECV_HOOK lock: {}", e);
            return wsa_fail(WSAEINTR.0);
        }
    };
    let original_fn: RecvFn = match hook_guard.as_ref() {
        Some(hook) => unsafe { recv_detour_original(hook) },
        None => {
            error!("Original recv() function not available!");
            return wsa_fail(WSAEINVAL.0);
        }
    };
    drop(hook_guard);

    if socket_info.is_ssl() {
        // For SSL sockets, skip processing here; SSL_read will handle it.
        return original_fn(s, buf, len, flags);
    }

    let bytes_received = original_fn(s, buf, len, flags);

    if bytes_received > 0 {
        let data_slice = std::slice::from_raw_parts(buf, bytes_received as usize); // Write raw data to buffer and process through engines

        #[cfg(debug_assertions)]
        {
            // Detailed debug logging for received socket data
            #[cfg(debug_assertions)]
            debug!("[RECV DEBUG] socket {}: received {} bytes from recv()", s.0, bytes_received);

            // Log hex preview of first 64 bytes
            let preview_len = std::cmp::min(MAXIMUM_PREVIEW_SIZE, data_slice.len());

            debug!(
                "[RECV DEBUG] socket {}: hex preview (first {} bytes): {:02X?}",
                s.0,
                preview_len,
                &data_slice[..preview_len]
            );

            // Try to parse as UTF-8 and log sanitized version
            if let Ok(text) = std::str::from_utf8(data_slice) {
                // Check for network name in server greeting
                if text.contains(" 005 ") {
                    if let Some(network_part) =
                        text.split_whitespace().find(|s| s.starts_with("NETWORK="))
                    {
                        let network_name = network_part.trim_start_matches("NETWORK=");
                        let mut network_name_guard = socket_info.network_name.write();
                        *network_name_guard = Some(network_name.to_string());
                        info!("Socket {}: detected network name: {}", s.0, network_name);
                    }
                }

                let sanitized: String = text
                    .chars()
                    .map(|c| {
                        if c.is_control() && c != '\r' && c != '\n' && c != '\t' { '.' } else { c }
                    })
                    .collect();

                #[cfg(debug_assertions)]
                debug!("[RECV DEBUG] socket {}: UTF-8 content (sanitized): {:?}", s.0, sanitized);

                // Check for IRC protocol markers
                if text.contains(CMD_PRIVMSG)
                    || text.contains(CMD_NOTICE)
                    || text.contains(CMD_JOIN)
                {
                    #[cfg(debug_assertions)]
                    debug!("[RECV DEBUG] socket {}: detected IRC protocol command", s.0);
                }

                // Check for FiSH key exchange markers
                if text.contains(KEY_EXCHANGE_INIT) || text.contains(KEY_EXCHANGE_PUBKEY) {
                    #[cfg(debug_assertions)]
                    debug!("[RECV DEBUG] socket {}: detected FiSH key exchange data", s.0);
                }
            } else {
                #[cfg(debug_assertions)]
                debug!("[RECV DEBUG] socket {}: non-UTF8 binary data", s.0);
            }
        }

        socket_info.write_received_data(data_slice);
        if let Err(e) = socket_info.process_received_lines() {
            error!("Error processing received lines: {:?}", e);
        }

        // Read processed data back into mIRC's buffer.
        // This is the critical step where decrypted data replaces the original encrypted data.
        let processed_buffer = socket_info.get_processed_buffer();

        // Safety: ensure len is non-negative before casting
        let safe_len = if len > 0 { len as usize } else { 0 };

        // Only copy complete lines (ending with \r\n) to avoid returning truncated
        // IRC messages to mIRC, which would corrupt the protocol display.
        // Find the last \r\n boundary within the mIRC buffer size limit.
        let boundary = processed_buffer[..std::cmp::min(safe_len, processed_buffer.len())]
            .windows(2)
            .rposition(|w| w == b"\r\n")
            .map(|pos| pos + 2)
            .unwrap_or(0);

        let bytes_to_copy = boundary;

        if bytes_to_copy > 0 {
            let target_buf = std::slice::from_raw_parts_mut(buf, bytes_to_copy);
            target_buf.copy_from_slice(&processed_buffer[..bytes_to_copy]);

            // Return remaining bytes (incomplete trailing data) to the processed buffer
            // so they survive for the next recv() call.
            if bytes_to_copy < processed_buffer.len() {
                let mut remaining = socket_info.processed_incoming_buffer.lock();
                let leftover = &processed_buffer[bytes_to_copy..];
                remaining.clear();
                remaining.extend(leftover);

                #[cfg(debug_assertions)]
                debug!(
                    "[RECV DEBUG] socket {}: preserved {} bytes of incomplete trailing data",
                    s.0,
                    leftover.len()
                );
            }

            #[cfg(debug_assertions)]
            {
                debug!(
                    "[RECV DEBUG] socket {}: returning {} bytes to mIRC (processed buffer had {} bytes)",
                    s.0,
                    bytes_to_copy,
                    processed_buffer.len()
                );

                if let Ok(text) = std::str::from_utf8(&processed_buffer[..bytes_to_copy]) {
                    info!("[RECV] {}: returning to mIRC: {}", s.0, text.trim_end());
                } else {
                    debug!(
                        "[RECV DEBUG] socket {}: returning binary data (first 64 bytes): {:02X?}",
                        s.0,
                        &processed_buffer[..std::cmp::min(MAXIMUM_PREVIEW_SIZE, bytes_to_copy)]
                    );
                }
            }
        }

        // Clear processed buffer : any incomplete trailing data was already preserved above.
        socket_info.clear_processed_buffer();

        return bytes_to_copy as c_int;
    }

    bytes_received
}

/// Hook implementation for send
pub unsafe extern "system" fn hooked_send(
    s: SOCKET,
    buf: *const u8, // Changed to u8
    len: c_int,
    flags: c_int,
) -> c_int {
    #[cfg(debug_assertions)]
    info!("* hooked_send() called for socket {}", s.0);

    let socket_info = get_or_create_socket(s.0 as u32, false);
    if socket_info.is_ssl() {
        // For SSL sockets, skip processing here; SSL_write will handle it.
        let hook_guard = match crate::lock_utils::try_lock_timeout(
            &SEND_HOOK,
            crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
        ) {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire SEND_HOOK lock: {}", e);
                return wsa_fail(WSAEINTR.0);
            }
        };
        let original_fn: SendFn = match hook_guard.as_ref() {
            Some(hook) => unsafe { send_detour_original(hook) },
            None => {
                error!("Original send function not available!");
                return wsa_fail(WSAEINVAL.0);
            }
        };
        drop(hook_guard);
        return original_fn(s, buf, len, flags);
    }

    if len < 0 || buf.is_null() {
        let hook_guard = match crate::lock_utils::try_lock_timeout(
            &SEND_HOOK,
            crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
        ) {
            Ok(guard) => guard,
            Err(e) => {
                error!("Failed to acquire SEND_HOOK lock: {}", e);
                return wsa_fail(WSAEINTR.0);
            }
        };
        let original_fn: SendFn = match hook_guard.as_ref() {
            Some(hook) => unsafe { send_detour_original(hook) },
            None => {
                error!("Original send function not available!");
                return wsa_fail(WSAEINVAL.0);
            }
        };
        drop(hook_guard);
        return original_fn(s, buf, len, flags);
    }

    // Safety: checked len > 0 above
    let data_slice = std::slice::from_raw_parts(buf, len as usize);

    #[cfg(debug_assertions)]
    {
        debug!("[SEND DEBUG] socket {}: sending {} bytes via send()", s.0, len);

        let preview_len = std::cmp::min(MAXIMUM_PREVIEW_SIZE, data_slice.len());

        debug!(
            "[SEND DEBUG] socket {}: hex preview (first {} bytes): {:02X?}",
            s.0,
            preview_len,
            &data_slice[..preview_len]
        );

        if let Ok(_text) = std::str::from_utf8(data_slice) {}
    }

    if data_slice.len() > 128 {
        let mut hasher = Sha256::new();
        hasher.update(data_slice);
        let hash = hasher.finalize();

        #[cfg(debug_assertions)]
        trace!(
            "Socket {}: [SEND HOOK] large buffer: len={} SHA256={:x}",
            s.0,
            data_slice.len(),
            hash
        );
    }

    // Check first packet for protocol detection
    let stats = socket_info.stats.lock();

    if stats.bytes_sent == 0 && socket_info.get_state() == SocketState::Initializing {
        drop(stats);

        if protocol_detection::is_initial_irc_command(data_slice) {
            let current_state = socket_info.get_state();
            if current_state == SocketState::Initializing || current_state == SocketState::Connected
            {
                socket_info.set_state(SocketState::IrcIdentified);

                #[cfg(debug_assertions)]
                debug!("Socket {}: identified as IRC connection", s.0);
            }
        } else if protocol_detection::is_tls_handshake_packet(data_slice) {
            socket_info.set_ssl(true);
            socket_info.set_state(SocketState::TlsHandshake);

            #[cfg(debug_assertions)]
            debug!("Socket {}: identified as TLS handshake", s.0);
        }
    } else {
        drop(stats);
    }

    if let Err(e) = socket_info.on_sending(data_slice) {
        error!("Error processing outgoing data: {:?}", e);
    }

    let hook_guard = match crate::lock_utils::try_lock_timeout(
        &SEND_HOOK,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire SEND_HOOK lock: {}", e);
            return wsa_fail(WSAEINTR.0);
        }
    };
    let original_fn: SendFn = match hook_guard.as_ref() {
        Some(hook) => unsafe { send_detour_original(hook) },
        None => {
            error!("Original send function not available !");
            return wsa_fail(WSAEINVAL.0);
        }
    };
    drop(hook_guard);

    original_fn(s, buf, len, flags)
}

/// Hook implementation for connect
pub unsafe extern "system" fn hooked_connect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: c_int,
) -> c_int {
    #[cfg(debug_assertions)]
    info!("* hooked_connect() called for socket {}", s.0);

    // Get or create socket info
    let _socket_info = get_or_create_socket(s.0 as u32, true);

    let hook_guard = match crate::lock_utils::try_lock_timeout(
        &CONNECT_HOOK,
        crate::lock_utils::EXTENDED_LOCK_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire CONNECT_HOOK lock: {}", e);
            return wsa_fail(WSAEINTR.0);
        }
    };
    let original_fn: ConnectFn = match hook_guard.as_ref() {
        Some(hook) => unsafe { connect_detour_original(hook) },
        None => {
            error!("Original connect() function not available!");
            return wsa_fail(WSAEINVAL.0);
        }
    };
    drop(hook_guard);

    let result = original_fn(s, name, namelen);

    let socket_info = get_or_create_socket(s.0 as u32, false);

    if result == 0 {
        #[cfg(debug_assertions)]
        debug!("Socket {}: connection established", s.0);

        let current_state = socket_info.get_state();

        if current_state == SocketState::Initializing {
            socket_info.set_state(SocketState::Connected);
        }
    } else if result == SOCKET_ERROR {
        let error = WSAGetLastError();

        if error != WSAEINTR {
            #[cfg(debug_assertions)]
            debug!("Socket {}: connection failed with error {:?}", s.0, error);
            socket_info.set_state(SocketState::Closed);
        }
    }

    result
}

/// Hook implementation for closesocket
pub unsafe extern "system" fn hooked_closesocket(s: SOCKET) -> c_int {
    #[cfg(debug_assertions)]
    info!("* hooked_closesocket() called for socket {}", s.0);
    let socket_id = s.0 as u32;

    if let Some(socket_info) = ACTIVE_SOCKETS.get(&socket_id) {
        let engines = Arc::clone(&socket_info.engines);
        engines.on_socket_closed(socket_id);
    }

    if ACTIVE_SOCKETS.remove(&socket_id).is_some() {
        #[cfg(debug_assertions)]
        debug!("Socket {} removed from tracking", socket_id);
    }

    let hook_guard = match crate::lock_utils::try_lock_timeout(
        &CLOSESOCKET_HOOK,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire CLOSESOCKET_HOOK lock: {}", e);
            return wsa_fail(WSAEINTR.0);
        }
    };
    let original_fn: ClosesocketFn = match hook_guard.as_ref() {
        Some(hook) => unsafe { closesocket_detour_original(hook) },
        None => {
            error!("Original closesocket() function not available !");
            return wsa_fail(WSAEINVAL.0);
        }
    };
    drop(hook_guard);

    original_fn(s)
}

/// Get the socket info (thread-safe with DashMap)
///
/// Lock ordering: **`ENGINES` before `ACTIVE_SOCKETS` insertion** (never hold a DashMap shard
/// lock while waiting on `ENGINES`). This matches `FiSH11_InjectDebugInfo` and avoids deadlock
/// with code that locks `ENGINES` then walks `ACTIVE_SOCKETS`.
pub fn get_or_create_socket(socket_id: u32, _is_ssl: bool) -> Arc<SocketInfo> {
    if let Some(socket_info) = ACTIVE_SOCKETS.get(&socket_id) {
        return socket_info.clone();
    }

    let engines = {
        let mut engines_guard = match ENGINES.lock() {
            Ok(guard) => guard,
            Err(e) => {
                error!("get_or_create_socket() : failed to lock ENGINES: {}", e);
                e.into_inner()
            }
        };

        if engines_guard.is_none() {
            *engines_guard = Some(Arc::new(InjectEngines::new()));
        }

        if let Some(engines_ref) = engines_guard.as_ref() {
            Arc::clone(engines_ref)
        } else {
            error!("get_or_create_socket() : ENGINES is None after initialization attempt");
            Arc::new(InjectEngines::new())
        }
    };

    // Another thread may have inserted while we held ENGINES.
    if let Some(socket_info) = ACTIVE_SOCKETS.get(&socket_id) {
        return socket_info.clone();
    }

    ACTIVE_SOCKETS
        .entry(socket_id)
        .or_insert_with(|| Arc::new(SocketInfo::new(socket_id, engines)))
        .clone()
}

pub(crate) fn _remove_socket(socket_id: u32) {
    ACTIVE_SOCKETS.remove(&socket_id);

    let mut discarded = DISCARDED_SOCKETS.lock().unwrap();

    discarded.push(socket_id);
}

/// Disable one Winsock detour; uses [`crate::lock_utils::UNINSTALL_HOOK_LOCK_TIMEOUT`] instead of
/// blocking `Mutex::lock` so unload does not hang indefinitely if a hook mutex is contended.
unsafe fn uninstall_one_winsock_hook<T: Copy + Function>(
    hook_label: &'static str,
    mutex: &StdMutex<Option<GenericDetour<T>>>,
) {
    let mut guard = match crate::lock_utils::try_lock_timeout(
        mutex,
        crate::lock_utils::UNINSTALL_HOOK_LOCK_TIMEOUT,
    ) {
        Ok(g) => g,
        Err(e) => {
            error!("uninstall_socket_hooks: timed out acquiring {} mutex: {}", hook_label, e);
            return;
        }
    };

    if let Some(hook) = guard.take() {
        match hook.disable() {
            Ok(_) => info!("  - {}() hook disabled", hook_label),
            Err(e) => warn!("  - failed to disable {}() hook: {:?}", hook_label, e),
        }
    }
}

pub fn uninstall_socket_hooks() {
    unsafe {
        uninstall_one_winsock_hook("closesocket", &CLOSESOCKET_HOOK);
        uninstall_one_winsock_hook("connect", &CONNECT_HOOK);
        uninstall_one_winsock_hook("send", &SEND_HOOK);
        uninstall_one_winsock_hook("recv", &RECV_HOOK);
    }
}

#[cfg(test)]
mod tests {
    //use super::*;
    //use crate::engines::InjectEngines;
    //use std::sync::Arc;

    #[test]
    fn test_valid_exports() {
        // Ensure that types compile, simple syntax check :D
        assert!(true);
    }
}
