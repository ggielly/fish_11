use std::io;
use std::sync::PoisonError;

use fish_11_core::logging;
use log::{error, info, warn};
use retour::GenericDetour;
use windows::Win32::Foundation::FARPROC;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
use windows::core::PCSTR;

use crate::hook_socket::{
    CLOSESOCKET_HOOK, CONNECT_HOOK, ClosesocketFn, ConnectFn, RECV_HOOK, RecvFn, SEND_HOOK, SendFn,
    hooked_closesocket, hooked_connect, hooked_recv, hooked_send, uninstall_socket_hooks,
};
use crate::hook_ssl::{
    SslGetFdFn, SslIsInitFinishedProc, SslReadFn, SslWriteFn, find_ssl_function, install_ssl_hooks,
    uninstall_ssl_hooks,
};
use crate::pointer_validation::validate_function_pointer;

/// Unwrap a `FARPROC` (guaranteed non-null) for subsequent transmute into
/// a concrete Win32 function pointer type.
///
/// This deliberately does NOT perform the final transmute: the caller knows
/// the exact ABI/signature and must do the `std::mem::transmute` itself with
/// an appropriate SAFETY comment.  Keeping the transmute at the call site
/// makes the contract explicit and avoids a generic `T: Copy` that would be
/// too permissive (it would accept `usize`, `[u8; 8]`, etc.).
///
/// # Panics
/// Panics if `ptr` is `None` (symbol not found).
#[inline]
unsafe fn unwrap_farproc(ptr: FARPROC) -> *const () {
    let raw = ptr.expect("FARPROC was None — function pointer resolution failed");
    // SAFETY: FARPROC is `Option<unsafe extern "system" fn() -> isize>`.
    // `raw` is the inner fn pointer (guaranteed non-null by expect).
    // We transmute to `*const ()` — a universal opaque pointer — so the caller
    // can perform the final, typed `transmute` to its concrete function signature.
    std::mem::transmute::<unsafe extern "system" fn() -> isize, *const ()>(raw)
}

/// Initialize the logger
pub fn init_logger() {
    match logging::init_inject_logging() {
        Ok(()) => {
            if logging::is_initialized() {
                info!("Ground zero : logger initialized via fish_11_core !");
            }
        }
        Err(e) => {
            eprintln!("[FiSH_11 Inject] failed to initialize logger: {}", e);
        }
    }
}

/// Function to install all hooks
pub fn install_hooks() -> Result<(), io::Error> {
    info!("Installing Winsock hooks :");

    #[cfg(debug_assertions)]
    info!("install_hooks: starting hook installation process...");

    unsafe {
        #[cfg(debug_assertions)]
        info!("install_hooks: resolving Winsock functions...");

        // Dynamically resolve Winsock functions
        // Note: GenericDetour expects non-nullable function pointers (RecvFn, etc.)
        // We use transmute_copy or transmute to convert FARPROC (Option<fn>) to fn.
        // We must ensure the FARPROC is Some before transmuting to avoid UB (null fn ptr).

        let recv_ptr = get_winsock_function("recv\0");
        if recv_ptr.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to resolve recv() function from ws2_32.dll",
            ));
        }
        // SAFETY: recv_ptr is a valid FARPROC from GetProcAddress("recv") on ws2_32.dll.
        // RecvFn matches the ABI (`extern "system"`) and signature of Winsock `recv`.
        let recv_fn: RecvFn = std::mem::transmute(unwrap_farproc(recv_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: recv function resolved at {:?}", recv_fn as *const ());

        let send_ptr = get_winsock_function("send\0");
        if send_ptr.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to resolve send() function from ws2_32.dll",
            ));
        }
        // SAFETY: send_ptr is a valid FARPROC from GetProcAddress("send") on ws2_32.dll.
        // SendFn matches the ABI (`extern "system"`) and signature of Winsock `send`.
        let send_fn: SendFn = std::mem::transmute(unwrap_farproc(send_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: send function resolved at {:?}", send_fn as *const ());

        let connect_ptr = get_winsock_function("connect\0");
        if connect_ptr.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to resolve connect() function from ws2_32.dll",
            ));
        }
        // SAFETY: connect_ptr is a valid FARPROC from GetProcAddress("connect") on ws2_32.dll.
        // ConnectFn matches the ABI (`extern "system"`) and signature of Winsock `connect`.
        let connect_fn: ConnectFn = std::mem::transmute(unwrap_farproc(connect_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: connect function resolved at {:?}", connect_fn as *const ());

        let closesocket_ptr = get_winsock_function("closesocket\0");
        if closesocket_ptr.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "Failed to resolve closesocket() function from ws2_32.dll",
            ));
        }
        // SAFETY: closesocket_ptr is a valid FARPROC from GetProcAddress("closesocket") on ws2_32.dll.
        // ClosesocketFn matches the ABI (`extern "system"`) and signature of Winsock `closesocket`.
        let closesocket_fn: ClosesocketFn = std::mem::transmute(unwrap_farproc(closesocket_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: closesocket function resolved at {:?}", closesocket_fn as *const ());

        #[cfg(debug_assertions)]
        info!("install_hooks: installing socket hooks...");

        // Install socket hooks
        install_socket_hook::<RecvFn>("recv", recv_fn, hooked_recv, &RECV_HOOK)?;
        #[cfg(debug_assertions)]
        info!("install_hooks: recv hook installed");

        install_socket_hook::<SendFn>("send", send_fn, hooked_send, &SEND_HOOK)?;
        #[cfg(debug_assertions)]
        info!("install_hooks: send hook installed");

        install_socket_hook::<ConnectFn>("connect", connect_fn, hooked_connect, &CONNECT_HOOK)?;
        #[cfg(debug_assertions)]
        info!("install_hooks: connect hook installed");

        install_socket_hook::<ClosesocketFn>(
            "closesocket",
            closesocket_fn,
            hooked_closesocket,
            &CLOSESOCKET_HOOK,
        )?;
        #[cfg(debug_assertions)]
        info!("install_hooks: closesocket hook installed");

        #[cfg(debug_assertions)]
        info!("install_hooks: resolving SSL functions...");

        // Install SSL hooks
        let ssl_read_ptr = find_ssl_function("SSL_read");
        if ssl_read_ptr.is_none() {
            warn!("Could not find SSL_read function, skipping SSL hook installation.");
            return Ok(());
        }
        // SAFETY: ssl_read_ptr is a valid FARPROC from GetProcAddress on a loaded SSL library.
        // SslReadFn matches the ABI (`extern "C"`) and signature of OpenSSL `SSL_read`.
        let ssl_read: SslReadFn = std::mem::transmute(unwrap_farproc(ssl_read_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: SSL_read resolved at {:?}", ssl_read as *const ());

        let ssl_write_ptr = find_ssl_function("SSL_write");
        if ssl_write_ptr.is_none() {
            warn!("Could not find SSL_write function, skipping SSL hook installation.");
            return Ok(());
        }
        // SAFETY: ssl_write_ptr is a valid FARPROC from GetProcAddress on a loaded SSL library.
        // SslWriteFn matches the ABI (`extern "C"`) and signature of OpenSSL `SSL_write`.
        let ssl_write: SslWriteFn = std::mem::transmute(unwrap_farproc(ssl_write_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: SSL_write resolved at {:?}", ssl_write as *const ());

        let ssl_get_fd_ptr = find_ssl_function("SSL_get_fd");
        if ssl_get_fd_ptr.is_none() {
            warn!("Could not find SSL_get_fd function, skipping SSL hook installation.");
            return Ok(());
        }
        // SAFETY: ssl_get_fd_ptr is a valid FARPROC from GetProcAddress on a loaded SSL library.
        // SslGetFdFn matches the ABI (`extern "C"`) and signature of OpenSSL `SSL_get_fd`.
        let ssl_get_fd: SslGetFdFn = std::mem::transmute(unwrap_farproc(ssl_get_fd_ptr));
        #[cfg(debug_assertions)]
        info!("install_hooks: SSL_get_fd resolved at {:?}", ssl_get_fd as *const ());

        let ssl_is_init_finished_ptr = find_ssl_function("SSL_is_init_finished");
        if ssl_is_init_finished_ptr.is_none() {
            warn!("Could not find SSL_is_init_finished function, skipping SSL hook installation.");
            return Ok(());
        }
        // SAFETY: ssl_is_init_finished_ptr is a valid FARPROC from GetProcAddress on a loaded SSL library.
        // SslIsInitFinishedProc matches the ABI (`extern "C"`) and signature of OpenSSL `SSL_is_init_finished`.
        let ssl_is_init_finished: SslIsInitFinishedProc =
            std::mem::transmute(unwrap_farproc(ssl_is_init_finished_ptr));
        #[cfg(debug_assertions)]
        info!(
            "install_hooks: SSL_is_init_finished resolved at {:?}",
            ssl_is_init_finished as *const ()
        );

        if ssl_read as usize == 0
            || ssl_write as usize == 0
            || ssl_get_fd as usize == 0
            || ssl_is_init_finished as usize == 0
        {
            error!(
                "One or more required SSL functions could not be found. Skipping SSL hook installation."
            );
            // This case shouldn't happen if pointers were checked is_none(), but safety nets are good.
        } else {
            #[cfg(debug_assertions)]
            info!("install_hooks: all SSL functions found, installing SSL hooks...");

            match install_ssl_hooks(ssl_read, ssl_write, ssl_get_fd, ssl_is_init_finished) {
                Ok(_) => {
                    info!("w00w00h ! All SSL h00kz successfully installed !");
                    #[cfg(debug_assertions)]
                    info!("install_hooks: SSL hooks installation succeeded");
                }
                Err(e) => {
                    error!("Damn, failed to install SSL hooks: {}", e);
                    #[cfg(debug_assertions)]
                    error!("install_hooks: SSL hooks installation failed: {}", e);
                }
            }
        }

        info!("r0x0r ! All winsock hooks successfully installed !");
        #[cfg(debug_assertions)]
        info!("install_hooks: hook installation process completed successfully");

        Ok(())
    }
}

/// Helper function to install a specific socket hook
unsafe fn install_socket_hook<T: Copy + retour::Function>(
    hook_name: &str,
    original_fn: T,
    hook_fn: T,
    hook_storage: &std::sync::Mutex<Option<GenericDetour<T>>>,
) -> Result<(), io::Error> {
    #[cfg(debug_assertions)]
    info!("install_socket_hook: installing {} hook...", hook_name);

    match GenericDetour::<T>::new(original_fn, hook_fn) {
        Ok(hook) => {
            #[cfg(debug_assertions)]
            info!("install_socket_hook: {} GenericDetour created, enabling...", hook_name);

            hook.enable().map_err(|e| {
                #[cfg(debug_assertions)]
                error!("install_socket_hook: failed to enable {} hook: {:?}", hook_name, e);

                io::Error::new(
                    io::ErrorKind::Other,
                    format!("  - failed to enable {}() hook: {:?}", hook_name, e),
                )
            })?;

            #[cfg(debug_assertions)]
            info!("install_socket_hook: {} hook enabled, storing in mutex...", hook_name);

            *hook_storage.lock().unwrap() = Some(hook);
            info!("  - {}() hook installed", hook_name);

            #[cfg(debug_assertions)]
            info!("install_socket_hook: {} hook installation complete", hook_name);

            Ok(())
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            error!("install_socket_hook: failed to create {} GenericDetour: {:?}", hook_name, e);

            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("  - failed to create {}() hook: {:?}", hook_name, e),
            ))
        }
    }
}

/// Cleanup function for all hooks. This must be called at DLL unload
pub fn cleanup_hooks() {
    info!("Cleaning up hooks :");

    // First uninstall SSL hooks
    uninstall_ssl_hooks();
    info!("  * SSL hooks uninstalled");

    // Then uninstall Winsock hooks
    uninstall_socket_hooks();
    info!("  * Socket hooks uninstalled");

    info!("All h00kz cleaned up sucessfully !");
}

/// 1) Getting a handle to ws2_32.dll.
/// 2) Retrieving the addresses of connect(), send(), recv(), and closesocket() using GetProcAddress.
unsafe fn get_winsock_function(func_name: &str) -> FARPROC {
    #[cfg(debug_assertions)]
    info!("get_winsock_function: looking for function '{}'", func_name);

    let ws2_32_cstr = b"ws2_32.dll\0";
    let ws2_32 = match GetModuleHandleA(PCSTR::from_raw(ws2_32_cstr.as_ptr())) {
        Ok(handle) => handle,
        Err(e) => {
            error!(
                "get_winsock_function: failed to get ws2_32.dll module handle ({}): {}",
                func_name.trim_end_matches('\0'),
                e
            );
            return None;
        }
    };

    // Check if handle is valid? Result handling implies it's valid if Ok.
    // If windows 0.62 uses Result<HMODULE>, Ok(h) usually means success.
    // But good to check? HMODULE wrapping logic ensures it.

    #[cfg(debug_assertions)]
    info!("get_winsock_function: ws2_32.dll handle = {:?}", ws2_32);

    // let func_name_cstr = std::ffi::CString::new(func_name).unwrap();
    // GetProcAddress(handle, PCSTR)
    // Note: func_name input has \0? The caller passes "recv\0".
    // If I use CString::new, it will error if \0 inside.
    // The callers: "recv\0".
    // So `func_name` has embedded null. `CString::new` will fail.
    // I should use `CStr` or just pointers since I know it's null terminated.
    // Or callers should pass "recv" and I add null?
    // Existing code passes "recv\0", so strings are null-terminated str slices.

    let func_addr = GetProcAddress(ws2_32, PCSTR::from_raw(func_name.as_ptr()));

    #[cfg(debug_assertions)]
    info!("get_winsock_function: {} address = {:?}", func_name, func_addr);

    // Validate the pointer before returning
    if let Err(e) = validate_function_pointer(func_addr, Some(ws2_32)) {
        error!("get_winsock_function: security validation failed for {}: {}", func_name, e);
        return None;
    }

    func_addr
}

/// Helper to handle mutex poisoning — abort to prevent silent corruption.
/// A poisoned mutex means a thread panicked while holding the lock, leaving
/// shared state in an inconsistent state. Continuing with corrupted data is
/// worse than crashing.
pub fn handle_poison<T>(err: PoisonError<T>) -> T {
    panic!("Mutex poisoned — aborting to prevent state corruption: {}", err);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logger() {
        init_logger();
    }
}
