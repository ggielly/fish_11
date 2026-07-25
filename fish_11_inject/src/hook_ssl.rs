use std::ffi::{CString, c_int, c_void};
use std::sync::Mutex as StdMutex;

use log::{debug, error, info, trace, warn};
use once_cell::sync::Lazy;
use retour::{Function, GenericDetour};
use windows::Win32::Foundation::FARPROC;
use windows::Win32::Networking::WinSock::SOCKET;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::core::PCSTR;

use crate::helpers_inject::handle_poison;
use crate::hook_socket::get_or_create_socket;
use crate::pointer_validation::validate_function_pointer;
use crate::socket::state::SocketState;
use crate::ssl_mapping::SslSocketMapping;

// SSL structure (opaque)
#[repr(C)]
pub struct SSL {
    _private: [u8; 0],
}

pub struct SSLWrapper {
    pub ssl: *mut SSL,
}

// SAFETY: SSLWrapper is used to track SSL connections across threads.
// The raw pointer is managed by OpenSSL which provides its own threading guarantees
// when properly initialized (SSL_library_init / OPENSSL_init_ssl).
// The pointer is only used for identity comparison and mapping, never dereferenced
// directly from Rust code - actual SSL operations go through the original SSL_read/SSL_write.
unsafe impl Send for SSLWrapper {}
unsafe impl Sync for SSLWrapper {}

// SAFETY: SSL is an opaque OpenSSL structure. We only hold raw pointers to it for
// socket-to-SSL mapping purposes. All actual SSL operations (read/write/free) are
// performed through the original OpenSSL function pointers, never through Rust.
// OpenSSL's threading model (when properly initialized) allows pointer storage across threads.
unsafe impl Send for SSL {}
unsafe impl Sync for SSL {}

pub type SslReadFn = unsafe extern "C" fn(*mut SSL, *mut u8, c_int) -> c_int;

/// Extract the original SSL_read function pointer from a detour.
///
/// # Safety
/// - The `hook` must be a valid, installed detour created by `retour::detour`
/// - The returned function pointer is valid only while the detour is installed
/// - The caller must not call the returned function while holding the hook mutex
#[inline]
unsafe fn ssl_read_detour_original(hook: &GenericDetour<SslReadFn>) -> SslReadFn {
    std::mem::transmute(hook.trampoline())
}
pub type SslWriteFn = unsafe extern "C" fn(*mut SSL, *const u8, c_int) -> c_int;
pub type SslConnectFn = unsafe extern "C" fn(*mut SSL) -> c_int;
pub type SslNewFn = unsafe extern "C" fn(*mut c_void) -> *mut SSL;
pub type SslFreeFn = unsafe extern "C" fn(*mut SSL);
pub type SslGetFdFn = unsafe extern "C" fn(*mut SSL) -> c_int;
pub type SslSetFdFn = unsafe extern "C" fn(*mut SSL, c_int) -> c_int;
pub type SslIsInitFinishedProc = unsafe extern "C" fn(*mut SSL) -> i32;

static SSL_IS_INIT_FINISHED: Lazy<StdMutex<Option<SslIsInitFinishedProc>>> =
    Lazy::new(|| StdMutex::new(None));

pub static SSL_READ_HOOK: Lazy<StdMutex<Option<GenericDetour<SslReadFn>>>> =
    Lazy::new(|| StdMutex::new(None));
pub static SSL_WRITE_HOOK: Lazy<StdMutex<Option<GenericDetour<SslWriteFn>>>> =
    Lazy::new(|| StdMutex::new(None));
pub static SSL_CONNECT_HOOK: Lazy<StdMutex<Option<GenericDetour<SslConnectFn>>>> =
    Lazy::new(|| StdMutex::new(None));
pub static SSL_NEW_HOOK: Lazy<StdMutex<Option<GenericDetour<SslNewFn>>>> =
    Lazy::new(|| StdMutex::new(None));
pub static SSL_GET_FD: Lazy<StdMutex<Option<SslGetFdFn>>> = Lazy::new(|| StdMutex::new(None));
pub static SSL_FREE_HOOK: Lazy<StdMutex<Option<GenericDetour<SslFreeFn>>>> =
    Lazy::new(|| StdMutex::new(None));
pub static SSL_HOOKS_INSTALLED: Lazy<StdMutex<bool>> = Lazy::new(|| StdMutex::new(false));
pub static ORIGINAL_SSL_READ: Lazy<StdMutex<Option<SslReadFn>>> = Lazy::new(|| StdMutex::new(None));
pub static ORIGINAL_SSL_WRITE: Lazy<StdMutex<Option<SslWriteFn>>> =
    Lazy::new(|| StdMutex::new(None));
pub static ORIGINAL_SSL_CONNECT: Lazy<StdMutex<Option<SslConnectFn>>> =
    Lazy::new(|| StdMutex::new(None));
pub static ORIGINAL_SSL_NEW: Lazy<StdMutex<Option<SslNewFn>>> = Lazy::new(|| StdMutex::new(None));
pub static ORIGINAL_SSL_FREE: Lazy<StdMutex<Option<SslFreeFn>>> = Lazy::new(|| StdMutex::new(None));

static SSL_SET_FD_HOOK: Lazy<StdMutex<Option<GenericDetour<SslSetFdFn>>>> =
    Lazy::new(|| StdMutex::new(None));

unsafe extern "C" fn hooked_ssl_set_fd(ssl: *mut SSL, fd: c_int) -> c_int {
    static ORIGINAL_SSL_SET_FD: Lazy<StdMutex<Option<SslSetFdFn>>> =
        Lazy::new(|| StdMutex::new(None));
    trace!("SSL_set_fd() called with ssl: {:p}, fd: {}", ssl, fd);

    let original_fn = {
        let guard = match ORIGINAL_SSL_SET_FD.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                error!("ORIGINAL_SSL_SET_FD mutex poisoned in hooked_ssl_set_fd()");
                poisoned.into_inner()
            }
        };
        *guard
    };

    let result = if let Some(func) = original_fn {
        func(ssl, fd)
    } else {
        error!("Original SSL_set_fd is NULL!");
        return -1;
    };

    if result > 0 && !ssl.is_null() {
        SslSocketMapping::associate(ssl, fd as u32);

        let socket_info = get_or_create_socket(fd as u32, true);
        socket_info.set_ssl(true);

        #[cfg(debug_assertions)]
        trace!("Socket {} marked as using SSL", fd);
    }

    result
}

pub fn find_ssl_function(function_name: &str) -> FARPROC {
    let ssl_lib_names = [
        "libssl-3.dll\0",
        "libssl-1_1.dll\0",
        "libssl-1_1-x64.dll\0",
        "ssleay32.dll\0",
        "libssl.dll\0",
        "crypt32.dll\0",
        "schannel.dll\0",
    ];

    let function_variants = [
        function_name.to_string(),
        format!("{}@4", function_name),
        format!("{}@8", function_name),
        format!("{}@12", function_name),
        format!("_{}@4", function_name),
        format!("_{}@8", function_name),
        format!("_{}@12", function_name),
        format!("_{}", function_name),
    ];
    let func_name_cstr = |name: &str| -> CString {
        CString::new(name).unwrap_or_else(|_| {
            CString::new("invalid").expect("Failed to create fallback function name")
        })
    };

    for lib_name in &ssl_lib_names {
        unsafe {
            if let Ok(handle) = GetModuleHandleA(PCSTR::from_raw(lib_name.as_ptr())) {
                if !handle.is_invalid() {
                    for variant in &function_variants {
                        let name_c = func_name_cstr(variant);
                        let func_ptr =
                            GetProcAddress(handle, PCSTR::from_raw(name_c.as_ptr() as *const u8));
                        if func_ptr.is_some() {
                            if let Err(e) = validate_function_pointer(func_ptr, Some(handle)) {
                                warn!("validation failed for found ssl function: {}", e);
                                continue;
                            }
                            #[cfg(debug_assertions)]
                            info!(
                                "Found {} ({}) in {}",
                                function_name,
                                variant,
                                String::from_utf8_lossy(
                                    lib_name.strip_suffix("\0").unwrap().as_bytes()
                                )
                            );
                            return func_ptr;
                        }
                    }
                }
            }
        }
    }

    for lib_name in &ssl_lib_names {
        unsafe {
            if let Ok(handle) = LoadLibraryA(PCSTR::from_raw(lib_name.as_ptr())) {
                if !handle.is_invalid() {
                    for variant in &function_variants {
                        let name_c = func_name_cstr(variant);
                        let func_ptr =
                            GetProcAddress(handle, PCSTR::from_raw(name_c.as_ptr() as *const u8));
                        if func_ptr.is_some() {
                            if let Err(e) = validate_function_pointer(func_ptr, Some(handle)) {
                                warn!("validation failed for loaded ssl function: {}", e);
                                continue;
                            }
                            #[cfg(debug_assertions)]
                            info!(
                                "Loaded {} and found {} ({}) in {}",
                                String::from_utf8_lossy(
                                    lib_name.strip_suffix("\0").unwrap().as_bytes()
                                ),
                                function_name,
                                variant,
                                String::from_utf8_lossy(
                                    lib_name.strip_suffix("\0").unwrap().as_bytes()
                                )
                            );
                            return func_ptr;
                        }
                    }
                }
            }
        }
    }

    warn!("Could not find function {} in any SSL library", function_name);
    None
}

pub unsafe fn store_ssl_mapping(ssl: *mut SSL, socket: SOCKET) {
    if let Some(fd_fn) = *SSL_GET_FD.lock().unwrap_or_else(handle_poison) {
        let fd = fd_fn(ssl);

        SslSocketMapping::associate(ssl, socket.0 as u32);

        #[cfg(debug_assertions)]
        debug!("Mapped SSL {:p} to socket {} (fd={})", ssl, socket.0, fd);
    }
}

pub unsafe extern "C" fn hooked_ssl_read(ssl: *mut SSL, buf: *mut u8, num: c_int) -> c_int {
    // Validate input pointers before any operation
    if ssl.is_null() {
        error!("hooked_ssl_read: ssl pointer is NULL");
        return -1;
    }
    if buf.is_null() {
        error!("hooked_ssl_read: buf pointer is NULL");
        return -1;
    }

    trace!("[h00k] hooked_ssl_read() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);

    let ssl_read_guard = match crate::lock_utils::try_lock_timeout(
        &SSL_READ_HOOK,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire SSL_READ_HOOK lock: {}", e);
            return -1;
        }
    };
    let original_fn: SslReadFn = match ssl_read_guard.as_ref() {
        Some(hook) => unsafe { ssl_read_detour_original(hook) },
        None => {
            error!("Original SSL_read() function not available!");
            return -1;
        }
    };
    // Drop the guard to release the lock
    drop(ssl_read_guard);

    let socket_id = match get_socket_from_ssl_context(ssl) {
        Some(id) => id,
        None => {
            error!("SSL_read called on unknown SSL context {:p}", ssl);
            return original_fn(ssl, buf, num);
        }
    };

    // Call the original SSL_read function
    let bytes_read = original_fn(ssl, buf, num);

    if bytes_read > 0 && !buf.is_null() {
        let data_slice = std::slice::from_raw_parts(buf, bytes_read as usize);

        #[cfg(debug_assertions)]
        {
            if let Ok(text) = std::str::from_utf8(data_slice) {
                // Simplified logging
                trace!("SSL_read data: {}", text);
            }
        }

        if let Ok(text) = std::str::from_utf8(data_slice) {
            #[cfg(debug_assertions)]
            info!(
                "[TLS IN] {}: {} bytes: {}",
                get_or_create_socket(socket_id, true).get_stats(),
                bytes_read,
                text.trim_end()
            );
        } else {
            #[cfg(debug_assertions)]
            info!(
                "[TLS IN] {}: {} bytes (non-UTF8): {:02X?}",
                get_or_create_socket(socket_id, true).get_stats(),
                bytes_read,
                &data_slice[..std::cmp::min(32, data_slice.len())]
            );
        }
        #[cfg(debug_assertions)]
        trace!(
            "[h00k] hooked_ssl_read() decrypted data for socket {} ({} bytes): {:02X?}",
            socket_id,
            bytes_read,
            &data_slice[..std::cmp::min(16, data_slice.len())]
        );
    }

    let ssl_init_fn = match crate::lock_utils::try_lock_timeout(
        &SSL_IS_INIT_FINISHED,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => *guard,
        Err(e) => {
            warn!("Failed to acquire SSL_IS_INIT_FINISHED lock: {}", e);
            None
        }
    };
    if let Some(ssl_init_fn) = ssl_init_fn {
        let handshake_status = ssl_init_fn(ssl);

        if handshake_status != 0 {
            let socket_info = get_or_create_socket(socket_id, true);
            if socket_info.get_state() == SocketState::TlsHandshake {
                #[cfg(debug_assertions)]
                debug!(
                    "[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected",
                    socket_id
                );
                socket_info.set_state(SocketState::Connected);
            }
        }
    }

    if bytes_read <= 0 {
        return bytes_read;
    }

    if buf.is_null() {
        return bytes_read;
    }

    let socket_info = get_or_create_socket(socket_id, true);
    let data_slice = std::slice::from_raw_parts(buf, bytes_read as usize);

    socket_info.write_received_data(data_slice);

    if let Err(e) = socket_info.process_received_lines() {
        error!("Error processing received SSL lines: {:?}", e);
    }

    // Match hooked_recv: engines write decrypted/processed lines into processed_incoming_buffer;
    // mIRC must see that data, not only the raw TLS plaintext in buf.
    let processed_buffer = socket_info.get_processed_buffer();

    let safe_len = if num > 0 { num as usize } else { 0 };

    // Only copy complete lines (ending with \r\n) to avoid returning truncated
    // IRC messages to the application, which would corrupt the protocol.
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
        // so they survive for the next SSL_read call.
        if bytes_to_copy < processed_buffer.len() {
            let mut remaining = socket_info.processed_incoming_buffer.lock();
            let leftover = &processed_buffer[bytes_to_copy..];
            remaining.clear();
            remaining.extend(leftover);

            #[cfg(debug_assertions)]
            debug!(
                "[SSL_read] socket {}: preserved {} bytes of incomplete trailing data",
                socket_id,
                leftover.len()
            );
        }

        #[cfg(debug_assertions)]
        {
            debug!(
                "[SSL_read] socket {}: returning {} bytes to app (processed had {} bytes)",
                socket_id,
                bytes_to_copy,
                processed_buffer.len()
            );
            if let Ok(text) = std::str::from_utf8(&processed_buffer[..bytes_to_copy]) {
                trace!("[SSL_read] returning to app: {}", text.trim_end());
            }
        }
    }

    socket_info.clear_processed_buffer();

    bytes_to_copy as c_int
}

unsafe extern "C" fn hooked_ssl_write(ssl: *mut SSL, buf: *const u8, num: c_int) -> c_int {
    // Validate input pointers before any operation
    if ssl.is_null() {
        error!("hooked_ssl_write: ssl pointer is NULL");
        return -1;
    }
    if buf.is_null() && num > 0 {
        error!("hooked_ssl_write: buf pointer is NULL with positive num={}", num);
        return -1;
    }

    #[cfg(debug_assertions)]
    trace!("[h00k] hooked_ssl_write() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);

    let socket_id = match SslSocketMapping::get_socket(ssl) {
        Some(socket_id) => socket_id,
        None => {
            #[cfg(debug_assertions)]
            trace!("SSL_write(): no socket ID found for SSL {:p}", ssl);

            let original_fn: SslWriteFn = {
                let lock = match ORIGINAL_SSL_WRITE.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => {
                        error!("ORIGINAL_SSL_WRITE mutex poisoned in hooked_ssl_write()");
                        poisoned.into_inner()
                    }
                };
                match *lock {
                    Some(fn_ptr) => fn_ptr,
                    None => {
                        error!("Original SSL_write() function is not available");
                        return -1;
                    }
                }
            };
            return original_fn(ssl, buf, num);
        }
    };

    #[cfg(debug_assertions)]
    trace!("SSL_write: socket {}, {} bytes", socket_id, num);

    if num > 0 && !buf.is_null() {
        let data_slice = std::slice::from_raw_parts(buf, num as usize);

        if let Ok(text) = std::str::from_utf8(data_slice) {
            #[cfg(debug_assertions)]
            info!(
                "[TLS OUT] {}: {} bytes: {}",
                get_or_create_socket(socket_id, true).get_stats(),
                num,
                text.trim_end()
            );
        } else {
            #[cfg(debug_assertions)]
            info!(
                "[TLS OUT] {}: {} bytes (non-UTF8): {:02X?}",
                get_or_create_socket(socket_id, true).get_stats(),
                num,
                &data_slice[..std::cmp::min(32, data_slice.len())]
            );
        }

        let socket_info = get_or_create_socket(socket_id, true);

        if let Err(e) = socket_info.on_sending(data_slice) {
            error!("Error processing outgoing SSL data: {:?}", e);
        }

        #[cfg(debug_assertions)]
        trace!("SSL_write() data: {:?}", data_slice);
    }

    let original_fn: SslWriteFn = {
        let lock = match ORIGINAL_SSL_WRITE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("ORIGINAL_SSL_WRITE mutex poisoned in hooked_ssl_write()");
                poisoned.into_inner()
            }
        };
        match *lock {
            Some(fn_ptr) => fn_ptr,
            None => {
                error!("Original SSL_write() function is not available");
                return -1;
            }
        }
    };

    let result = original_fn(ssl, buf, num);

    {
        let ssl_is_init_finished_fn = match crate::lock_utils::try_lock_timeout(
            &SSL_IS_INIT_FINISHED,
            crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
        ) {
            Ok(guard) => *guard,
            Err(e) => {
                warn!("Failed to acquire SSL_IS_INIT_FINISHED lock: {}", e);
                None
            }
        };
        if let Some(ssl_is_init_finished_fn) = ssl_is_init_finished_fn {
            let handshake_status = ssl_is_init_finished_fn(ssl);

            if handshake_status != 0 {
                if let Some(handshake_sock_id) = get_socket_from_ssl_context(ssl) {
                    let handshake_info = get_or_create_socket(handshake_sock_id, true);
                    if handshake_info.get_state() == SocketState::TlsHandshake {
                        #[cfg(debug_assertions)]
                        debug!(
                            "[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected",
                            handshake_sock_id
                        );
                        handshake_info.set_state(SocketState::Connected);
                    }
                }
            }
        }
    }

    result
}

// TODO : retaining hooked_ssl_connect and others. Maybea potential future features
// The current installation only actively uses read/write/get_fd
unsafe extern "C" fn hooked_ssl_connect(ssl: *mut SSL) -> c_int {
    #[cfg(debug_assertions)]
    debug!("SSL_connect() called for SSL {:p}", ssl);

    let original_fn: SslConnectFn = {
        if let Some(func) = *ORIGINAL_SSL_CONNECT.lock().unwrap_or_else(handle_poison) {
            func
        } else {
            return -1;
        }
    };
    original_fn(ssl)
}

pub unsafe fn install_ssl_hooks(
    ssl_read: SslReadFn,
    ssl_write: SslWriteFn,
    ssl_get_fd: SslGetFdFn,
    ssl_is_init_finished: SslIsInitFinishedProc,
) -> Result<(), String> {
    let mut hooks_installed = SSL_HOOKS_INSTALLED.lock().unwrap_or_else(handle_poison);

    if *hooks_installed {
        return Err("SSL hooks are already installed".to_string());
    }

    let mut ssl_read_hook = SSL_READ_HOOK.lock().unwrap_or_else(handle_poison);
    let mut ssl_write_hook = SSL_WRITE_HOOK.lock().unwrap_or_else(handle_poison);
    let mut original_ssl_read = ORIGINAL_SSL_READ.lock().unwrap_or_else(handle_poison);
    let mut original_ssl_write = ORIGINAL_SSL_WRITE.lock().unwrap_or_else(handle_poison);
    let mut ssl_get_fd_slot = SSL_GET_FD.lock().unwrap_or_else(handle_poison);
    let mut ssl_is_init_finished_slot = SSL_IS_INIT_FINISHED.lock().unwrap_or_else(handle_poison);

    *original_ssl_read = Some(ssl_read);
    *original_ssl_write = Some(ssl_write);
    *ssl_get_fd_slot = Some(ssl_get_fd);
    *ssl_is_init_finished_slot = Some(ssl_is_init_finished);

    *ssl_read_hook = match GenericDetour::new(ssl_read, hooked_ssl_read) {
        Ok(hook) => Some(hook),
        Err(e) => {
            *original_ssl_read = None;
            *original_ssl_write = None;
            *ssl_get_fd_slot = None;
            *ssl_is_init_finished_slot = None;
            return Err(format!("Failed to create SSL_read hook: {}", e));
        }
    };

    *ssl_write_hook = match GenericDetour::new(ssl_write, hooked_ssl_write) {
        Ok(hook) => Some(hook),
        Err(e) => {
            *ssl_read_hook = None;
            *original_ssl_read = None;
            *original_ssl_write = None;
            *ssl_get_fd_slot = None;
            *ssl_is_init_finished_slot = None;
            return Err(format!("Failed to create SSL_write hook: {}", e));
        }
    };

    if let Err(e) = ssl_read_hook
        .as_mut()
        .unwrap()
        .enable()
        .map_err(|e| format!("Failed to enable SSL_read hook: {}", e))
    {
        *ssl_read_hook = None;
        *ssl_write_hook = None;
        *original_ssl_read = None;
        *original_ssl_write = None;
        *ssl_get_fd_slot = None;
        *ssl_is_init_finished_slot = None;
        return Err(e);
    }

    if let Err(e) = ssl_write_hook
        .as_mut()
        .unwrap()
        .enable()
        .map_err(|e| format!("Failed to enable SSL_write hook: {}", e))
    {
        if let Some(hook) = ssl_read_hook.as_mut() {
            if let Err(disable_err) = hook.disable() {
                error!(
                    "Failed to roll back SSL_read hook after SSL_write enable failure: {:?}",
                    disable_err
                );
            }
        }

        *ssl_read_hook = None;
        *ssl_write_hook = None;
        *original_ssl_read = None;
        *original_ssl_write = None;
        *ssl_get_fd_slot = None;
        *ssl_is_init_finished_slot = None;
        return Err(e);
    }

    *hooks_installed = true;

    Ok(())
}

/// Same rationale as [`crate::hook_socket::uninstall_socket_hooks`]: avoid blocking forever on unload.
unsafe fn uninstall_one_ssl_detour<T: Copy + Function>(
    hook_label: &'static str,
    mutex: &StdMutex<Option<GenericDetour<T>>>,
) {
    let mut guard = match crate::lock_utils::try_lock_timeout(
        mutex,
        crate::lock_utils::UNINSTALL_HOOK_LOCK_TIMEOUT,
    ) {
        Ok(g) => g,
        Err(e) => {
            error!("uninstall_ssl_hooks: timed out acquiring {} mutex: {}", hook_label, e);
            return;
        }
    };

    if let Some(hook) = guard.take() {
        if let Err(e) = hook.disable() {
            error!("Failed to disable {} hook: {:?}", hook_label, e);
        }
    }
}

fn clear_ssl_slot<T>(label: &'static str, mutex: &StdMutex<T>, value: T) {
    match crate::lock_utils::try_lock_timeout(mutex, crate::lock_utils::UNINSTALL_HOOK_LOCK_TIMEOUT)
    {
        Ok(mut g) => *g = value,
        Err(e) => error!("uninstall_ssl_hooks: timed out clearing {}: {}", label, e),
    }
}

pub fn uninstall_ssl_hooks() {
    #[cfg(debug_assertions)]
    info!("Uninstalling SSL hooks...");

    unsafe {
        uninstall_one_ssl_detour("SSL_read", &*SSL_READ_HOOK);
        uninstall_one_ssl_detour("SSL_write", &*SSL_WRITE_HOOK);
        uninstall_one_ssl_detour("SSL_connect", &*SSL_CONNECT_HOOK);
        uninstall_one_ssl_detour("SSL_new", &*SSL_NEW_HOOK);
        uninstall_one_ssl_detour("SSL_free", &*SSL_FREE_HOOK);
    }

    SslSocketMapping::clear();

    clear_ssl_slot("ORIGINAL_SSL_READ", &*ORIGINAL_SSL_READ, None);
    clear_ssl_slot("ORIGINAL_SSL_WRITE", &*ORIGINAL_SSL_WRITE, None);
    clear_ssl_slot("ORIGINAL_SSL_CONNECT", &*ORIGINAL_SSL_CONNECT, None);
    clear_ssl_slot("ORIGINAL_SSL_NEW", &*ORIGINAL_SSL_NEW, None);
    clear_ssl_slot("ORIGINAL_SSL_FREE", &*ORIGINAL_SSL_FREE, None);
    clear_ssl_slot("SSL_HOOKS_INSTALLED", &*SSL_HOOKS_INSTALLED, false);
}

unsafe fn get_socket_from_ssl_context(ssl: *mut SSL) -> Option<u32> {
    SslSocketMapping::get_socket(ssl)
}
