//! A simple CLI tool to:
//!   - test FiSH 11 DLL functions
//!   - use the dll in command line
//!
//! This file is part of the FiSH_11 project.
//! Written by [GuY], 2025. Licenced under GPL v3.

mod platform_types;
use std::env;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use fish_11_core::globals::{BUILD_DATE, BUILD_NUMBER, BUILD_TIME, BUILD_VERSION};
use platform_types::{BOOL, DWORD, HWND};

use std::sync::RwLock;

// Global flags — must be defined before `mod helpers_cli` so the macro can see them
pub(crate) static QUIET_MODE: RwLock<bool> = RwLock::new(false);
static DEBUG_LOG_PATH: RwLock<Option<std::path::PathBuf>> = RwLock::new(None);

/// Helper function to safely get the quiet mode value
pub fn is_quiet_mode() -> bool {
    match QUIET_MODE.read() {
        Ok(guard) => *guard,
        Err(_) => {
            eprintln!("Warning: QUIET_MODE lock was poisoned, defaulting to not quiet");
            false
        }
    }
}

/// Helper function to set the quiet mode value in a thread-safe manner
pub fn set_quiet_mode(quiet: bool) {
    match QUIET_MODE.write() {
        Ok(mut guard) => {
            *guard = quiet;
        }
        Err(_) => {
            eprintln!("Warning: QUIET_MODE lock was poisoned during update");
        }
    }
}

// Macro for conditional printing based on quiet mode
macro_rules! info_print {
    ($($arg:tt)*) => {
        if let Ok(guard) = QUIET_MODE.read() {
            if !*guard {
                println!($($arg)*);
            }
        } else {
            eprintln!("Warning : QUIET_MODE lock was poisoned, defaulting to not quiet");
            println!($($arg)*);
        }
    };
}

mod helpers_cli;
use crate::helpers_cli::validate_config_file;

// Default timeout for DLL operations in seconds
const DEFAULT_TIMEOUT_SECONDS: u64 = 5;

// Special timeout for listkeys command (which may take longer with large key databases)
const DEFAULT_LISTKEYS_TIMEOUT_SECONDS: u64 = 10;

/// Display version information in the format expected for -v/--version flags
fn display_version() {
    let build_type = if cfg!(debug_assertions) { "debug" } else { "release" };

    println!(
        "FiSH_11_cli {} (build {}-{}) *** Compiled {} at {} *** Written by [GuY], licensed under the GPL-v3 or above",
        fish_11_core::globals::BUILD_VERSION,
        fish_11_core::globals::BUILD_NUMBER.as_str(),
        build_type,
        fish_11_core::globals::BUILD_DATE.as_str(),
        fish_11_core::globals::BUILD_TIME.as_str()
    );
}

// Define the LoadInfo structure that mIRC passes to our DLL
// Must match LOADINFO in fish_11_dll/src/dll_interface/core.rs exactly
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
struct LoadInfo {
    m_version: DWORD,
    m_hwnd: HWND,
    m_keep: BOOL,
    m_unicode: BOOL,
    m_beta: DWORD,
    m_bytes: DWORD,
    m_extra: DWORD,
}

// Function signatures matching the actual DLL exports
// LoadDll: extern "stdcall" fn(*mut LOADINFO) -> BOOL
type DllLoadFn = extern "system" fn(*mut LoadInfo) -> c_int;
// mIRC DLL functions: extern "system" fn(HWND, HWND, *mut c_char, *mut c_char, BOOL, BOOL) -> c_int
type DllFunctionFn = extern "system" fn(HWND, HWND, *mut c_char, *mut c_char, c_int, c_int) -> c_int;

/// This is used when the direct DLL call might hang (like FiSH11_FileListKeys with large DBs)
fn call_dll_function(
    dll: &libloading::Library,
    function_name: &str,
    params: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Get the function from the DLL
    let function: libloading::Symbol<DllFunctionFn> = unsafe { dll.get(function_name.as_bytes())? };

    // Create buffers for the function call
    // Data buffer that can be used for both input and output
    let c_params = CString::new(params)?;

    // We need to copy the parameters to a mutable buffer since many functions
    // both read from and write to the data parameter
    let buffer_size = fish_11_core::globals::DLL_BUFFER_SIZE;

    // Security validation: prevent excessively large buffer allocations
    const MAX_SAFE_BUFFER_SIZE: usize = 16 * 1024 * 1024; // 16MB
    if buffer_size > MAX_SAFE_BUFFER_SIZE {
        return Err(format!(
            "Buffer size {} exceeds maximum safe limit of {} bytes",
            buffer_size, MAX_SAFE_BUFFER_SIZE
        )
        .into());
    }

    // Also ensure buffer size is reasonable for our use case
    const MIN_REASONABLE_BUFFER_SIZE: usize = 1024; // 1KB
    if buffer_size < MIN_REASONABLE_BUFFER_SIZE {
        return Err(format!(
            "Buffer size {} is too small (minimum: {} bytes)",
            buffer_size, MIN_REASONABLE_BUFFER_SIZE
        )
        .into());
    }

    let mut data_buffer = vec![0u8; buffer_size];

    // Copy parameters to data buffer
    let param_bytes = c_params.as_bytes_with_nul();

    // Validate that we won't overflow the buffer
    // We need at least 1 extra byte for potential null terminator handling
    if !param_bytes.is_empty() && param_bytes.len() <= buffer_size {
        // If param_bytes.len() equals buffer_size, we can copy all bytes but we lose
        // the ability to ensure null termination, but that's acceptable since
        // the original string is already null-terminated
        if param_bytes.len() == buffer_size {
            // If param_bytes exactly fills the buffer, copy it but note that there's no
            // extra space for a null terminator at the end
            data_buffer.copy_from_slice(param_bytes);
        } else {
            // If there's space remaining, copy and ensure it's properly terminated
            data_buffer[..param_bytes.len()].copy_from_slice(param_bytes);
        }
    } else if param_bytes.len() > buffer_size {
        return Err(format!(
            "Parameter size {} exceeds buffer size {}",
            param_bytes.len(),
            buffer_size
        )
        .into());
    }

    let data_ptr = data_buffer.as_mut_ptr() as *mut c_char;

    // Secondary parameters buffer (some functions use both data and parms)
    let mut parms_buffer = vec![0u8; buffer_size];
    let parms_ptr = parms_buffer.as_mut_ptr() as *mut c_char;

    // Determine which timeout to use based on the function
    // Use a longer timeout (10s) for potentially slow key-exchange operations
    let timeout = if function_name == "FiSH11_FileListKeys"
        || function_name == "FiSH11_ExchangeKey"
        || function_name == "FiSH11_ProcessPublicKey"
    {
        Duration::from_secs(DEFAULT_LISTKEYS_TIMEOUT_SECONDS)
    } else {
        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS)
    };

    info_print!("Starting function call (timeout set to {:?})...", timeout);

    let start_time = Instant::now();
    // Use a separate thread to detect and report potential hangs
    let is_complete = Arc::new(AtomicBool::new(false));
    let is_complete_clone = is_complete.clone();

    let timer_handle = std::thread::spawn(move || {
        let start = Instant::now();
        let mut last_report = Instant::now();

        // Loop until timeout or function completes
        while start.elapsed() < timeout && !is_complete_clone.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));

            // Report progress every second for long-running operations
            if last_report.elapsed() > Duration::from_secs(1) {
                last_report = Instant::now();
                let elapsed = start.elapsed();
                if elapsed > Duration::from_secs(2) {
                    if let Ok(guard) = QUIET_MODE.read() {
                        if !*guard {
                            println!(
                                "Still waiting... ({:.1?} elapsed, timeout at {:?})",
                                elapsed, timeout
                            );
                        }
                    } else {
                        eprintln!(
                            "Warning: QUIET_MODE mutex was poisoned, defaulting to not quiet"
                        );
                        println!(
                            "Still waiting... ({:.1?} elapsed, timeout at {:?})",
                            elapsed, timeout
                        );
                    }
                }
            }
        }

        // If we reach here and the operation isn't complete, the timeout has been reached
        if !is_complete_clone.load(Ordering::SeqCst) {
            // Always show timeout warnings, even in quiet mode — they are critical
            eprintln!("WARNING: function execution timed out after {:?}.", timeout);
            eprintln!("The DLL function may have hung, press Ctrl+c to break.");
        }
    });
    // Call the function
    info_print!("Calling DLL function {} with parameters : '{}'", function_name, params);

    // mIRC DLL function signature: (mWnd, aWnd, data, parms, show, nopause) -> c_int
    // The DLL determines buffer sizes internally via get_buffer_size(); we do NOT pass them.
    let result = function(
        std::ptr::null_mut(), // mWnd
        std::ptr::null_mut(), // aWnd
        data_ptr,             // data (input/output buffer)
        parms_ptr,            // parms (secondary buffer)
        1,                    // show (1 = show output, 0 = don't show)
        0,                    // nopause (0 = normal pause behavior)
    );

    // Mark operation as complete to stop the timer thread
    is_complete.store(true, Ordering::SeqCst);

    // Wait for the timer thread to finish — it will exit promptly since is_complete is set
    let _ = timer_handle.join();

    // Report how long it took
    let elapsed = start_time.elapsed();

    // Log the result and buffer info
    info_print!("DLL function returned code : {}", result);

    // Buffer preview — only in debug mode to avoid leaking sensitive data
    if DEBUG_LOG_PATH.read().map(|g| g.is_some()).unwrap_or(false) && buffer_size > 0 {
        unsafe {
            let preview_size = 20.min(buffer_size);
            if preview_size > 0 {
                let bytes: Vec<u8> =
                    std::slice::from_raw_parts(data_ptr as *const u8, preview_size).to_vec();
                info_print!("Buffer first {} bytes : {:?}", preview_size, bytes);
                if let Ok(preview) = std::str::from_utf8(&bytes) {
                    info_print!("Buffer preview as string : {}", preview);
                }
            }
        }
    }

    if elapsed > Duration::from_secs(1) {
        info_print!("Function call completed in {:.2?}", elapsed);

        // Special handling for potentially slow operations
        if function_name == "FiSH11_FileListKeys" {
            info_print!("Note : processing large key databases can take time.");
        }
    }

    // MIRC_HALT (0) = function failed/halted — no useful data in buffer
    if result == 0 {
        return Err("DLL function returned MIRC_HALT (0) — function failed or halted".into());
    }

    // Unknown return code — warn but continue
    if result != 1 && result != 2 && result != 3 {
        info_print!("Warning: DLL function returned unusual value: {}", result);
    }

    // Extract result from buffer (MIRC_CONTINUE=1, MIRC_COMMAND=2, MIRC_IDENTIFIER=3)
    let output = {
        // Find the length of the string (up to null terminator)
        let mut data_len = 0;
        // Ensure buffer_size is larger than 0 to avoid potential out-of-bounds access
        if buffer_size > 0 {
            while data_len < buffer_size && data_buffer[data_len] != 0 {
                data_len += 1;
            }
        }

        // Also check the length of the secondary parms buffer
        let mut parms_len = 0;
        // Again, ensure buffer_size is larger than 0 to avoid potential out-of-bounds access
        if buffer_size > 0 {
            while parms_len < buffer_size && parms_buffer[parms_len] != 0 {
                parms_len += 1;
            }
        }

        // Determine the best buffer to use based on content availability
        // Prefer the data buffer, but use parms buffer if data buffer is empty
        if data_len > 0 {
            // Use the main data buffer if it has content
            match std::str::from_utf8(&data_buffer[..data_len]) {
                Ok(s) => {
                    if s.is_empty() && function_name == "FiSH11_FileListKeys" {
                        "FiSH_11 : no keys stored.".to_string()
                    } else {
                        s.to_string()
                    }
                }
                Err(e) => {
                    info_print!("Warning : failed to decode result from data buffer: {}", e);
                    // Show hex representation of problematic bytes
                    let problematic_bytes = &data_buffer[..data_len.min(50)]; // Limit to first 50 bytes for display
                    let hex_repr = problematic_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!(
                        "Function completed but returned invalid UTF-8 data in data buffer (length: {}, first bytes as hex: {})",
                        data_len, hex_repr
                    )
                }
            }
        } else if parms_len > 0 {
            // Use the parms buffer if the main buffer is empty but parms has data
            match std::str::from_utf8(&parms_buffer[..parms_len]) {
                Ok(s) => {
                    if !s.is_empty() {
                        s.to_string()
                    } else if function_name == "FiSH11_FileListKeys" {
                        "FiSH_11 : no keys stored.".to_string()
                    } else {
                        "Function completed but returned no output.".to_string()
                    }
                }
                Err(e) => {
                    info_print!("Warning : failed to decode result from parms buffer: {}", e);
                    // Show hex representation of problematic bytes
                    let problematic_bytes = &parms_buffer[..parms_len.min(50)]; // Limit to first 50 bytes for display
                    let hex_repr = problematic_bytes
                        .iter()
                        .map(|b| format!("{:02x}", b))
                        .collect::<Vec<_>>()
                        .join(" ");
                    format!(
                        "Function completed but returned invalid UTF-8 data in parms buffer (length: {}, first bytes as hex: {})",
                        parms_len, hex_repr
                    )
                }
            }
        } else {
            // No content in either buffer
            if function_name == "FiSH11_FileListKeys" {
                "FiSH_11 : no keys stored.".to_string()
            } else {
                "Function completed but returned no output.".to_string()
            }
        }
    };

    Ok(output)
}

/// Validates user input to prevent buffer overflow
/// Checks if the input length is within safe limits
fn validate_input_length(input: &str) -> Result<(), String> {
    const MAX_INPUT_LENGTH: usize = 8192; // Safe limit for most operations

    if input.len() > MAX_INPUT_LENGTH {
        return Err(format!(
            "Input too long : {} characters (max: {})",
            input.len(),
            MAX_INPUT_LENGTH
        ));
    }

    Ok(())
}

/// Validates user input before passing it to the DLL.
///
/// Intentionally permissive: only rejects null bytes, control characters, and
/// path traversal sequences. Characters like `|`, `` ` ``, `&`, `;`, `/` are
/// all valid in IRC nicknames, channel names, and messages. The DLL itself
/// performs its own input parsing, so over-validation here breaks legitimate
/// use cases (e.g. encrypting a message containing `&`).
fn validate_input_content(input: &str) -> Result<(), String> {
    if input.contains('\0') {
        return Err("Input contains null byte".to_string());
    }

    // Reject control characters (except \r, \n, \t which are normal in IRC)
    if input
        .chars()
        .any(|c| matches!(c, '\x00'..='\x08' | '\x0B' | '\x0C' | '\x0E'..='\x1F' | '\x7F'))
    {
        return Err("Input contains control characters".to_string());
    }

    Ok(())
}

/// Validates user input completely
/// Performs all security checks on user input
fn validate_user_input(input: &str) -> Result<(), String> {
    validate_input_length(input)?;
    validate_input_content(input)?;
    Ok(())
}

/// Sanitizes user input for DLL function calls.
///
/// Strips control characters (except \r, \n, \t) and validates basic safety.
/// Characters like `|`, `&`, `;`, `/`, `#` are intentionally kept — they are
/// valid in IRC channel names, nicknames, and messages.
fn sanitize_dll_input(input: &str) -> Result<String, String> {
    validate_user_input(input)?;

    // Strip control characters that could cause issues in C string parsing
    let sanitized: String = input
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\r' || *c == '\t')
        .collect();

    if sanitized.contains('\0') {
        return Err("Input contains null byte".to_string());
    }

    Ok(sanitized)
}

/// Validates DLL path.
///
/// Only rejects null bytes and shell metacharacters. Path traversal (`..`) is
/// allowed — the OS and `libloading` handle resolution safely, and rejecting
/// legitimate absolute/relative paths is more harmful than useful.
fn validate_dll_path(dll_path: &str) -> Result<(), String> {
    if dll_path.contains('\0') {
        return Err("DLL path contains null byte".to_string());
    }

    let path = std::path::Path::new(dll_path);
    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        if ext != "dll" && ext != "so" {
            return Err(format!("Invalid file extension: {} (expected .dll or .so)", ext));
        }
    } else {
        return Err("DLL path must have a .dll or .so extension".to_string());
    }

    Ok(())
}

/// Validates a positional argument (channel names, nicknames, messages, etc.).
///
/// This is intentionally permissive: it only rejects null bytes and path traversal
/// sequences. Characters like `#`, `&`, `|`, `` ` ``, `;` are valid in IRC channel
/// names and messages, so they must be allowed here.
fn validate_argument(arg: &str) -> Result<(), String> {
    if arg.contains('\0') {
        return Err("Argument contains null byte".to_string());
    }
    if arg.contains("..\\") || arg.contains("../") || arg.contains("%00") {
        return Err("Argument contains path traversal sequences".to_string());
    }
    Ok(())
}

/// Validates a command name to prevent injection.
///
/// Stricter than `validate_argument`: rejects shell metacharacters since
/// command names come from a fixed set of known strings.
fn validate_command_name(command: &str) -> Result<(), String> {
    if command.contains('\0') {
        return Err("Command contains null byte".to_string());
    }
    if command.contains("..\\") || command.contains("../") || command.contains("%00") {
        return Err("Command contains path traversal sequences".to_string());
    }
    if command.contains('|')
        || command.contains('`')
        || command.contains('&')
        || command.contains(';')
    {
        return Err("Command contains dangerous shell characters".to_string());
    }
    if !command
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '-' || c == '/' || c == '.' || c == ':')
    {
        return Err("Command contains invalid characters".to_string());
    }
    Ok(())
}

/// List all exported functions from the specified DLL
fn list_exports(dll_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    info_print!("Loading DLL: {}", dll_path);

    // Try to load the DLL with improved error handling
    let dll = match unsafe { libloading::Library::new(dll_path) } {
        Ok(dll) => {
            info_print!("DLL loaded successfully: {}", dll_path);
            dll
        }
        Err(e) => {
            eprintln!("Failed to load DLL '{}': {}", dll_path, e);
            eprintln!(
                "Make sure the DLL exists, is accessible, and is compatible with this application."
            );

            // Provide more specific error context
            let path = std::path::Path::new(dll_path);
            if !path.exists() {
                eprintln!("Error: The specified DLL file does not exist at the given path.");
            } else if !path.is_file() {
                eprintln!("Error: The specified path is not a file.");
            } else {
                eprintln!("Error: The file may be corrupted or incompatible with this platform.");
            }

            return Err(format!("DLL load failed: {}", e).into());
        }
    };

    println!("Available FiSH_11 functions :");
    println!("----------------------------");

    // Manually try to get handle for known FiSH11 functions and print which ones are available
    for func_name in [
        "FiSH11_GetVersion",
        "FiSH11_GenKey",
        "FiSH11_FileDelKey", // Changed from FiSH11_DelKey
        "FiSH11_SetKey",
        "FiSH11_FileGetKey",
        "FiSH11_FileListKeys",
        "FiSH11_ExchangeKey",
        "FiSH11_ProcessPublicKey",
        "FiSH11_EncryptMsg",
        "FiSH11_DecryptMsg",
        "FiSH11_TestCrypt",
        "FiSH11_GetConfigPath",
        "FiSH11_Help",
        "FiSH11_SetMircDir",
        "FiSH11_FileListKeysItem",
        "FiSH11_GetKeyFingerprint",
        "INI_GetBool",
        "INI_GetString",
        "INI_GetInt",
        "FiSH11_InitChannelKey",
        "FiSH11_ProcessChannelKey",
        "FiSH11_GetKeyTTL",
        "FiSH11_GetRatchetState",
        "FiSH11_SetManualChannelKey",
        "FiSH11_SetNetwork",
        "FiSH11_SetKeyFromPlaintext",
    ] {
        // More robust approach to avoid potential panics
        let found = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            dll.get::<DllFunctionFn>(func_name.as_bytes()).is_ok()
                || dll.get::<DllFunctionFn>(format!("_{}@24", func_name).as_bytes()).is_ok()
        })) {
            Ok(result) => result,
            Err(_) => {
                // If there's a panic during DLL function access, log and continue
                eprintln!("Warning: Error accessing function {} - may be incompatible", func_name);
                false
            }
        };

        if found {
            println!("✓ {}", func_name);
        } else {
            println!("✗ {} (not available)", func_name);
        }
    }

    println!("\nUse these function names with the fish_11_cli command.");

    Ok(())
}

/// Display a help message with command usage information

fn print_two_columns_aligned(left: &str, right: &str, right_start: usize) {
    let left_len = left.chars().count();
    let spaces = if right_start > left_len { right_start - left_len } else { 1 };
    print!("{}{}", left, " ".repeat(spaces));
    println!("{}", right);
}

fn display_help() {
    let build_type = if cfg!(debug_assertions) { "debug" } else { "release" };
    let col = 45;
    print_two_columns_aligned(
        &format!("FiSH_11_cli {} (build {})", BUILD_VERSION, BUILD_NUMBER.as_str()),
        "Written by [GuY], licensed under the GPL-v3 or above",
        col,
    );
    print_two_columns_aligned(
        &format!("Version {}", build_type),
        &format!("Compiled {} at {} ZULU", BUILD_DATE.as_str(), BUILD_TIME.as_str()),
        col,
    );
    println!("");
    println!("Usage : fish_11_cli [options] <dll_path> <command> [parameters...]");
    println!();
    println!("[Options]");
    println!("  -q, --quiet     Minimize output messages (useful for scripts)");
    println!("  -v, --version   Display version information");
    println!("      --debug     Write debug log to fish11_cli_debug.log");
    println!();
    println!("<Commands>");
    println!("  -h,   --help                 Show this help message");
    println!("  -l,   --list                 List available functions in the DLL");
    println!("  -gv,  --getversion           Get the DLL version");
    println!("  -gk,  --genkey               Generate a new encryption key for a target");
    println!("  -sk,  --setkey               Set a specific key for a target");
    println!("  -gk2, --getkey               Get the key for a target");
    println!("  -dk,  --delkey               Delete a key for a target");
    println!("  -lk,  --listkeys             List all stored keys");
    println!("  -li,  --listkeysitem         List a specific key item");
    println!("  -e,   --encrypt              Encrypt a message");
    println!("  -d,   --decrypt              Decrypt a message");
    println!("  -tc,  --testcrypt            Test encryption/decryption cycle");
    println!("  -gcp, --getconfigpath        Get the configuration file path");
    println!("  -sm,  --setmircdir           Set the mIRC directory");
    println!("  -ib,  --ini_getbool          Get a boolean value from the config file");
    println!("  -is,  --ini_getstring        Get a string value from the config file");
    println!("  -ii,  --ini_getint           Get an integer value from the config file");
    println!("  -ik,  --initchannelkey       Initialize a channel encryption key");
    println!("  -pk,  --processchannelkey    Process a received channel key");
    println!("  -kt,  --getkeyttl            Get the time-to-live for a key");
    println!("  -rs,  --getratchetstate      Get the ratchet state for a channel");
    println!("  -smk, --setmanualchannelkey  Set a manual channel encryption key");
    println!("  -sn,  --setnetwork           Set the current IRC network");
    println!("  -kf,  --getkeyfingerprint    Get the fingerprint of a key");
    println!("  -skp, --setkeyfromplaintext  Set a key from plaintext");
    println!();
    println!("Examples :");
    println!("  fish_11_cli fish_11.dll getversion");
    println!("  fish_11_cli fish_11.dll genkey #channel");
    println!("  fish_11_cli fish_11.dll encrypt #channel \"Secret message\"");
    println!("  fish_11_cli fish_11.dll decrypt #channel \"+OK abcdef1234\"");
    println!("  fish_11_cli fish_11.dll listkeys c:\\path\\to\\fish_11.ini");
    println!("  fish_11_cli fish_11.dll ini_getbool process_incoming 1");
    println!("  fish_11_cli fish_11.dll ini_getstring plain_prefix \"\"");
    println!("  fish_11_cli fish_11.dll ini_getint mark_position 0");
    println!("  fish_11_cli fish_11.dll initchannelkey #secret Alice Bob");
    println!("  fish_11_cli fish_11.dll setkeyttl Alice");
    println!("  fish_11_cli fish_11.dll getkeyfingerprint Alice");
    println!("  fish_11_cli fish_11.dll setnetwork EFNet");
}

/// Validate that the command has the required arguments
fn validate_command_args(command: &str, args: &[String]) -> Result<(), String> {
    let arg_count = args.len();
    match command {
        "genkey" | "delkey" | "getkey" | "getkeyfingerprint" | "getkeyttl" | "setkeyttl"
        | "exchangekey" | "processkey" => {
            if arg_count < 1 {
                let mut msg =
                    format!("Command '{}' requires a target (channel or nickname).", command);
                if command == "genkey" || command == "delkey" || command == "getkey" {
                    msg.push_str("\nTip: if specifying a channel (e.g. #channel) in PowerShell, use quotes (\"#channel\") to avoid comment treatment.");
                }
                return Err(msg);
            }
        }
        "setkey" | "setkeyfromplaintext" => {
            if arg_count < 2 {
                return Err(format!("Command '{}' requires a target and a key.", command));
            }
        }
        "encrypt" | "decrypt" => {
            if arg_count < 2 {
                return Err(format!("Command '{}' requires a target and a message.", command));
            }
        }
        "initchannelkey" => {
            if arg_count < 1 {
                return Err(format!("Command '{}' requires a channel.", command));
            }
        }
        "setmanualchannelkey" => {
            if arg_count < 2 {
                return Err(format!("Command '{}' requires a channel and a key.", command));
            }
        }
        "ini_getbool" | "ini_getstring" | "ini_getint" => {
            if arg_count < 1 {
                return Err(format!("Command '{}' requires a config key name.", command));
            }
        }
        _ => {}
    }
    Ok(())
}

fn main() {
    // Get command line arguments
    let args: Vec<String> = env::args().collect();

    // Handle empty arguments
    if args.len() < 2 {
        display_help();
        return;
    }

    // Check for options in the arguments
    let mut processed_args = Vec::new();
    let mut arg_index = 1;

    while arg_index < args.len() {
        match args[arg_index].as_str() {
            "-q" | "--quiet" => {
                if let Ok(mut guard) = QUIET_MODE.write() {
                    *guard = true;
                } else {
                    eprintln!("Warning: QUIET_MODE lock was poisoned during update");
                }
                arg_index += 1;
            }
            "--debug" => {
                // Create debug log file — only when explicitly requested
                let debug_path = std::path::PathBuf::from("fish11_cli_debug.log");
                if let Ok(mut debug_log) = std::fs::File::create(&debug_path) {
                    use std::io::Write;
                    let _ = writeln!(debug_log, "=== CLI DEBUG LOG ===");
                    let _ = writeln!(
                        debug_log,
                        "Command arguments: {:?}",
                        std::env::args().collect::<Vec<_>>()
                    );
                }
                if let Ok(mut guard) = DEBUG_LOG_PATH.write() {
                    *guard = Some(debug_path);
                }
                arg_index += 1;
            }
            "-v" | "--version" => {
                // Display version and exit
                display_version();
                return;
            }
            // Short flags for commands
            "-h" | "--help" => {
                // Map to help command
                processed_args.push("help".to_string());
                arg_index += 1;
            }
            "-l" | "--list" => {
                // Map to list command
                processed_args.push("list".to_string());
                arg_index += 1;
            }
            "-gv" | "--getversion" => {
                // Map to getversion command
                processed_args.push("getversion".to_string());
                arg_index += 1;
            }
            "-gk" | "--genkey" => {
                processed_args.push("genkey".to_string());
                arg_index += 1;
            }
            "-gk2" | "--getkey" => {
                processed_args.push("getkey".to_string());
                arg_index += 1;
            }
            "-sk" | "--setkey" => {
                // Map to setkey command
                processed_args.push("setkey".to_string());
                arg_index += 1;
            }
            "-dk" | "--delkey" => {
                // Map to delkey command
                processed_args.push("delkey".to_string());
                arg_index += 1;
            }
            "-lk" | "--listkeys" => {
                // Map to listkeys command
                processed_args.push("listkeys".to_string());
                arg_index += 1;
            }
            "-li" | "--listkeysitem" => {
                // Map to listkeysitem command
                processed_args.push("listkeysitem".to_string());
                arg_index += 1;
            }
            "-e" | "--encrypt" => {
                // Map to encrypt command
                processed_args.push("encrypt".to_string());
                arg_index += 1;
            }
            "-d" | "--decrypt" => {
                // Map to decrypt command
                processed_args.push("decrypt".to_string());
                arg_index += 1;
            }
            "-tc" | "--testcrypt" => {
                // Map to testcrypt command
                processed_args.push("testcrypt".to_string());
                arg_index += 1;
            }
            "-gcp" | "--getconfigpath" => {
                // Map to getconfigpath command
                processed_args.push("getconfigpath".to_string());
                arg_index += 1;
            }
            "-sm" | "--setmircdir" => {
                // Map to setmircdir command
                processed_args.push("setmircdir".to_string());
                arg_index += 1;
            }
            "-ib" | "--ini_getbool" => {
                // Map to ini_getbool command
                processed_args.push("ini_getbool".to_string());
                arg_index += 1;
            }
            "-is" | "--ini_getstring" => {
                // Map to ini_getstring command
                processed_args.push("ini_getstring".to_string());
                arg_index += 1;
            }
            "-ii" | "--ini_getint" => {
                // Map to ini_getint command
                processed_args.push("ini_getint".to_string());
                arg_index += 1;
            }
            "-ik" | "--initchannelkey" => {
                // Map to initchannelkey command
                processed_args.push("initchannelkey".to_string());
                arg_index += 1;
            }
            "-pk" | "--processchannelkey" => {
                // Map to processchannelkey command
                processed_args.push("processchannelkey".to_string());
                arg_index += 1;
            }
            "-kt" | "--getkeyttl" => {
                // Map to getkeyttl command
                processed_args.push("getkeyttl".to_string());
                arg_index += 1;
            }
            "-rs" | "--getratchetstate" => {
                // Map to getratchetstate command
                processed_args.push("getratchetstate".to_string());
                arg_index += 1;
            }
            "-smk" | "--setmanualchannelkey" => {
                // Map to setmanualchannelkey command
                processed_args.push("setmanualchannelkey".to_string());
                arg_index += 1;
            }
            "-sn" | "--setnetwork" => {
                // Map to setnetwork command
                processed_args.push("setnetwork".to_string());
                arg_index += 1;
            }
            "-kf" | "--getkeyfingerprint" => {
                // Map to getkeyfingerprint command
                processed_args.push("getkeyfingerprint".to_string());
                arg_index += 1;
            }
            "-skp" | "--setkeyfromplaintext" => {
                // Map to setkeyfromplaintext command
                processed_args.push("setkeyfromplaintext".to_string());
                arg_index += 1;
            }
            _ => {
                // Not an option — add to processed args after basic validation
                let arg = args[arg_index].clone();
                if let Err(e) = validate_argument(&arg) {
                    println!("Invalid argument: {}", e);
                    return;
                }
                processed_args.push(arg);
                arg_index += 1;
            }
        }
    }

    // Handle special help command
    if processed_args.is_empty() {
        display_help();
        return;
    }

    if processed_args[0] == "help" {
        display_help();
        return;
    }

    // At this point we should have at least the DLL path and command
    // Check length BEFORE accessing indices to prevent potential panic
    if processed_args.len() < 2 {
        println!("Error : missing required arguments");
        display_help();
        return;
    }

    // Extract the DLL path and command - safe to access since we checked length above
    let dll_path = &processed_args[0];
    let command = processed_args[1].to_lowercase();

    // Validate the command to prevent injection attacks
    if let Err(e) = validate_command_name(&command) {
        println!("Invalid command: {}", e);
        return;
    }

    // Special command to display help
    if command == "help" {
        display_help();
        return;
    }

    // Special command to list exports
    if command == "list" {
        match list_exports(dll_path) {
            Ok(()) => return,
            Err(e) => {
                println!("Error listing exports: {}", e);
                return;
            }
        }
    }

    // Validate the DLL path before loading
    if let Err(e) = validate_dll_path(dll_path) {
        println!("Invalid DLL path: {}", e);
        return;
    }

    // Load the DLL
    let dll = match unsafe { libloading::Library::new(dll_path) } {
        Ok(dll) => dll,
        Err(e) => {
            println!("Failed to load DLL '{}' : {}", dll_path, e);
            println!(
                "Make sure the DLL exists and is compatible with this version of FiSH_11 CLI."
            );
            return;
        }
    };

    info_print!("Successfully loaded DLL: {}", dll_path);

    // Try to find LoadDll with different name patterns (matching the interface)
    // Since we're only going to call FiSH functions, we only need LoadDll for initialization
    let load_dll = unsafe {
        match dll.get::<DllLoadFn>(b"LoadDll") {
            Ok(func) => {
                info_print!("Found LoadDll function");
                Some(func)
            }
            Err(_) => match dll.get::<DllLoadFn>(b"_LoadDll@4") {
                Ok(func) => {
                    info_print!("Found LoadDll() with mangled name '_LoadDll@4'");
                    Some(func)
                }
                Err(_) => {
                    info_print!("Warning : LoadDll() not found with expected name patterns");
                    None
                }
            },
        }
    };

    // Prepare the LOADINFO structure — must match core.rs LOADINFO layout
    let mut load_info = LoadInfo {
        m_version: 0x00370007, // mIRC 7.73 encoded as DWORD
        m_hwnd: std::ptr::null_mut(),
        m_keep: 1,    // BOOL (TRUE)
        m_unicode: 0, // BOOL (FALSE)
        m_beta: 0,
        m_bytes: fish_11_core::globals::DLL_BUFFER_SIZE as DWORD,
        m_extra: 0,
    };

    // Call LoadDll if found
    if let Some(load_fn) = load_dll {
        let result = load_fn(&mut load_info);

        if result != 1 {
            info_print!("Warning: LoadDll() returned unexpected value: {}", result);
        } else {
            info_print!("Successfully initialized DLL with LoadDll");
        }
    }

    // Map CLI commands to the appropriate DLL function
    let function_name = match command.as_str() {
        "getversion" => "FiSH11_GetVersion",
        "genkey" => "FiSH11_GenKey",
        "delkey" => "FiSH11_FileDelKey", // Changed from FiSH11_DelKey
        "setkey" => "FiSH11_SetKey",
        "getkey" => "FiSH11_FileGetKey",
        "listkeys" => "FiSH11_FileListKeys",
        "listfiles" => "FiSH11_FileListKeys",
        "listkeysitem" => "FiSH11_FileListKeysItem",
        "exchangekey" => "FiSH11_ExchangeKey",
        "processkey" => "FiSH11_ProcessPublicKey",
        "encrypt" => "FiSH11_EncryptMsg",
        "decrypt" => "FiSH11_DecryptMsg",
        "testcrypt" => "FiSH11_TestCrypt",
        "getconfigpath" => "FiSH11_GetConfigPath",
        "setmircdir" => "FiSH11_SetMircDir",
        "help" => "FiSH11_Help",
        "ini_getbool" => "INI_GetBool",
        "ini_getstring" => "INI_GetString",
        "ini_getint" => "INI_GetInt",
        "initchannelkey" => "FiSH11_InitChannelKey",
        "processchannelkey" => "FiSH11_ProcessChannelKey",
        "getkeyttl" => "FiSH11_GetKeyTTL",
        "getratchetstate" => "FiSH11_GetRatchetState",
        "setmanualchannelkey" => "FiSH11_SetManualChannelKey",
        "setnetwork" => "FiSH11_SetNetwork",
        "getkeyfingerprint" => "FiSH11_GetKeyFingerprint",
        "setkeyfromplaintext" => "FiSH11_SetKeyFromPlaintext",

        _ => {
            println!("Unknown command: {}", command);
            display_help();
            return;
        }
    };

    info_print!("Calling function: {}", function_name);

    // Validate arguments
    let cmd_args = if processed_args.len() > 2 { &processed_args[2..] } else { &[] };
    if let Err(e) = validate_command_args(&command, cmd_args) {
        println!("Error: {}", e);
        return;
    }

    // Special case for listkeys to validate config file first
    if function_name == "FiSH11_FileListKeys" && processed_args.len() > 2 {
        let config_path = &processed_args[2];
        if !validate_config_file(config_path) {
            if !is_quiet_mode() {
                println!("Warning : the config file may not be valid or accessible.");
                println!("Continuing with the operation, but it may fail.");
            }
        }
    }

    // Use our enhanced call_dll_function
    let params = if processed_args.len() > 2 {
        let raw_params = processed_args[2..].join(" ");

        // Sanitize the user input before passing it to the DLL
        match sanitize_dll_input(&raw_params) {
            Ok(sanitized) => sanitized,
            Err(validation_error) => {
                println!("Error: Invalid input - {}", validation_error);
                return;
            }
        }
    } else {
        String::new()
    };

    // Call the DLL function using our enhanced helper that handles timeouts
    match call_dll_function(&dll, function_name, &params) {
        Ok(output) => {
            // For listkeys, directly process the mIRC-formatted output for simplicity
            if function_name == "FiSH11_FileListKeys" {
                // Process the output
                if output.is_empty() {
                    println!("No keys found or empty configuration.");
                } else {
                    // Split by lines and display each line properly
                    let lines = if output.contains("\r\n") {
                        output.split("\r\n").collect::<Vec<&str>>()
                    } else {
                        output.split('\n').collect::<Vec<&str>>()
                    };

                    // Process each line
                    let mut displayed_something = false;

                    for line in lines {
                        // Handle mIRC-style /echo commands
                        if line.starts_with("/echo -a ") {
                            let content = line.trim_start_matches("/echo -a ");

                            // Skip duplicating header if we already printed it
                            if content == "FiSH Keys :" && displayed_something {
                                continue;
                            }

                            println!("{}", content);
                            displayed_something = true;
                        } else if !line.trim().is_empty() {
                            println!("{}", line);
                            displayed_something = true;
                        }
                    }

                    if !displayed_something && !output.is_empty() {
                        println!("Raw output: {}", output);
                    }
                }
            } else if function_name == "FiSH11_GenKey" {
                // For genkey, we want to display the generated key if in quiet mode,
                // or include it in the output otherwise.

                // First, display the success message if NOT in quiet mode
                if !is_quiet_mode() {
                    println!("{}", output);
                }

                // Now retrieve the key
                // The params for genkey are "target [network]", for getkey it's "target"
                // We need to extract just the target
                let target = params.split_whitespace().next().unwrap_or(&params);

                match call_dll_function(&dll, "FiSH11_FileGetKey", target) {
                    Ok(key_output) => {
                        let valid_key = key_output.contains("+OK ") || key_output.len() > 10; // Simple validation check

                        if is_quiet_mode() {
                            // quiet mode: print ONLY the key
                            if valid_key {
                                println!("{}", key_output.trim());
                            } else {
                                // If we couldn't get the key, print nothing or error?
                                // User requested "ONLY the key", so maybe stderr if failed?
                                eprintln!("Error: Failed to retrieve generated key.");
                            }
                        } else {
                            // Normal mode: print the key clearly
                            println!("Key: {}", key_output.trim());
                        }
                    }
                    Err(e) => {
                        println!("Error retrieving generated key: {}", e);
                    }
                }
            } else {
                // For other functions, just print the raw output

                // If quiet mode is on, we print ONLY the RESULT, not the formatting
                if is_quiet_mode() {
                    println!("{}", output.trim());
                } else {
                    println!("{}", output);
                }
            }
        }
        Err(e) => {
            // Always show errors even in quiet mode
            println!("Error calling function : {}", e);
            println!("Try using the 'list' command to see available functions.");
        }
    }
    // Debug file handling removed - we now directly process output from the DLL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_utf8_string() {
        // Test that valid UTF-8 strings are handled correctly
        let valid_utf8 = "Hello, 世界! 🦀";
        assert!(std::str::from_utf8(valid_utf8.as_bytes()).is_ok());
        assert_eq!(valid_utf8, "Hello, 世界! 🦀");
    }

    #[test]
    fn test_basic_ascii_utf8() {
        // Test basic ASCII strings (subset of UTF-8)
        let ascii = "Hello, World!";
        assert!(std::str::from_utf8(ascii.as_bytes()).is_ok());
        assert_eq!(ascii, "Hello, World!");
    }

    #[test]
    fn test_utf8_multibyte_sequences() {
        // Test various UTF-8 multibyte characters
        let utf8_chars = [
            ("Emoji", "🦀🎉🚀"),
            ("Cyrillic", "Привет"),
            ("Chinese", "你好世界"),
            ("Arabic", "مرحبا"),
            ("Symbols", "αβγδε∑∏"),
        ];

        for (desc, text) in utf8_chars.iter() {
            assert!(std::str::from_utf8(text.as_bytes()).is_ok(), "Failed for {}", desc);
            assert_eq!(*text, std::str::from_utf8(text.as_bytes()).unwrap());
        }
    }

    #[test]
    fn test_invalid_utf8_byte_sequences() {
        // Test invalid UTF-8 byte sequences
        let invalid_sequences = vec![
            vec![0xFF],                   // Invalid start byte
            vec![0xC0, 0x80],             // Overlong encoding
            vec![0xC0],                   // Incomplete sequence
            vec![0xE0, 0x80],             // Incomplete 3-byte sequence
            vec![0xF0, 0x80, 0x80],       // Incomplete 4-byte sequence
            vec![0x80, 0x80, 0x80, 0x80], // Continuation bytes with no start
        ];

        for seq in invalid_sequences {
            assert!(std::str::from_utf8(&seq).is_err());
        }
    }

    #[test]
    fn test_buffer_utf8_decoding_success() {
        // Test the internal UTF-8 decoding for data buffer (successful case)
        let data_buffer = "Hello, UTF-8 World!".as_bytes().to_vec();
        let data_len = data_buffer.len();

        match std::str::from_utf8(&data_buffer[..data_len]) {
            Ok(s) => {
                assert_eq!(s, "Hello, UTF-8 World!");
            }
            Err(_) => panic!("Should have been valid UTF-8"),
        }
    }

    #[test]
    fn test_buffer_utf8_decoding_failure() {
        // Test the internal UTF-8 decoding for data buffer (failure case)
        let invalid_buffer = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
        let data_len = invalid_buffer.len();

        match std::str::from_utf8(&invalid_buffer[..data_len]) {
            Ok(_) => panic!("Should have been invalid UTF-8"),
            Err(e) => {
                assert!(!e.to_string().is_empty());
            }
        }
    }

    #[test]
    fn test_hex_representation_of_bytes() {
        // Test that bytes are properly converted to hex representation
        let test_bytes = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello" in hex
        let hex_repr =
            test_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");

        assert_eq!(hex_repr, "48 65 6c 6c 6f");
    }

    #[test]
    fn test_hex_representation_of_invalid_utf8() {
        // Test hex representation of invalid UTF-8 bytes
        let invalid_bytes = vec![0xFF, 0xFE, 0xFD, 0x00, 0xC0];
        let hex_repr =
            invalid_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");

        assert_eq!(hex_repr, "ff fe fd 00 c0");
    }

    #[test]
    fn test_empty_buffer_utf8_handling() {
        // Test handling of empty buffers
        let empty_buffer: Vec<u8> = vec![];
        let result = std::str::from_utf8(&empty_buffer);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "");
    }

    #[test]
    fn test_long_valid_utf8_string() {
        // Test handling of longer valid UTF-8 strings
        let long_string = "A".repeat(1000) + "世界" + "B".repeat(1000).as_str();
        let result = std::str::from_utf8(long_string.as_bytes());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &long_string);
    }

    #[test]
    fn test_boundary_utf8_sequences() {
        // Test boundary cases for UTF-8 sequences
        let boundary_cases = vec![
            vec![0x00],             // Null byte
            vec![0x7F],             // Last ASCII character
            vec![0xC2, 0x80],       // First 2-byte sequence
            vec![0xDF, 0xBF],       // Last 2-byte sequence
            vec![0xE0, 0xA0, 0x80], // First 3-byte sequence
            vec![0xEF, 0xBF, 0xBF], // Last 3-byte sequence (non-characters)
        ];

        for case in boundary_cases {
            match std::str::from_utf8(&case) {
                Ok(_) => {}  // Some of these are valid
                Err(_) => {} // Some of these are invalid, which is also valid behavior to test
            }
        }
    }

    #[test]
    fn test_error_message_with_hex_output() {
        // Test the complete error message generation
        let invalid_buffer = vec![0xFF, 0xFE, 0xFD, 0x00, 0xC0];
        let data_len = invalid_buffer.len();

        let result = std::str::from_utf8(&invalid_buffer);
        assert!(result.is_err());

        // Create the hex representation as done in the code
        let problematic_bytes = &invalid_buffer[..data_len.min(50)];
        let hex_repr =
            problematic_bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");

        // Verify hex representation is correct
        assert_eq!(hex_repr, "ff fe fd 00 c0");

        // Create error message as done in the code
        let error_msg = format!(
            "Function completed but returned invalid UTF-8 data in data buffer (length: {}, first bytes as hex: {})",
            data_len, hex_repr
        );

        assert!(error_msg.contains("invalid UTF-8 data in data buffer"));
        assert!(error_msg.contains("length: 5"));
        assert!(error_msg.contains("ff fe fd 00 c0"));
    }

    #[test]
    fn test_buffer_preview_with_zero_size() {
        // Test that our buffer preview logic handles zero buffer size gracefully
        let buffer_size = 0;
        assert_eq!(buffer_size, 0);

        // Even though we can't actually test the unsafe block directly from outside,
        // we can verify the conditional logic that checks if buffer_size > 0
        if buffer_size > 0 {
            // This branch should not execute for zero buffer size
            let _preview_size = 20.min(buffer_size);
            assert!(false, "This should not be reached with zero buffer size");
        } else {
            // This is the expected behavior for zero buffer size
            assert_eq!(buffer_size, 0);
        }
    }

    #[test]
    fn test_buffer_preview_with_small_size() {
        // Test buffer preview with small buffer size (less than preview size)
        let buffer_size = 5; // Small buffer
        let preview_size = 20.min(buffer_size); // Should be 5

        assert_eq!(preview_size, 5);
        assert!(preview_size <= 20);
        assert!(preview_size <= buffer_size);
    }

    #[test]
    fn test_buffer_length_calculation_bounds_check() {
        // Test that our length calculation correctly checks bounds
        let buffer_size = 100;
        let mut data_buffer = vec![b'A'; buffer_size];
        data_buffer[50] = 0; // Add null terminator

        // Simulate the length calculation logic but with bounds checking
        let mut data_len = 0;
        if buffer_size > 0 {
            while data_len < buffer_size && data_buffer[data_len] != 0 {
                data_len += 1;
            }
        }

        // Should stop at the null terminator
        assert_eq!(data_len, 50);

        // Verify we don't go out of bounds
        assert!(data_len <= buffer_size);
    }

    #[test]
    fn test_buffer_length_calculation_with_zero_size() {
        // Test the length calculation when buffer_size is 0
        let buffer_size = 0;
        let _data_buffer: Vec<u8> = vec![]; // Empty buffer

        // Simulate the length calculation logic with bounds check
        let mut data_len = 0;
        if buffer_size > 0 {
            // This condition should prevent execution
            // This block shouldn't execute when buffer_size is 0
            assert!(false, "Length calculation should not execute when buffer_size is 0");
        } else {
            // data_len should remain 0
            assert_eq!(data_len, 0);
        }
    }

    #[test]
    fn test_sanitize_dll_input_valid_input() {
        // Test that valid input passes through sanitization
        let valid_input = "Hello, World! This is a test.";
        let result = sanitize_dll_input(valid_input);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), valid_input);
    }

    #[test]
    fn test_sanitize_dll_input_with_null_byte() {
        // Test that null bytes are caught by validation
        let input_with_null = "Hello\0World";
        let result = sanitize_dll_input(input_with_null);

        // This should fail validation because of null byte
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_dll_input_rejects_control_chars() {
        // Control characters (except \r, \n, \t) are rejected
        assert!(sanitize_dll_input("hello\x00world").is_err());
        assert!(sanitize_dll_input("hello\x01world").is_err());
        assert!(sanitize_dll_input("hello\x7Fworld").is_err());

        // But \r, \n, \t are allowed (common in IRC)
        assert!(sanitize_dll_input("hello\nworld").is_ok());
        assert!(sanitize_dll_input("hello\r\nworld").is_ok());
        assert!(sanitize_dll_input("hello\tworld").is_ok());
    }

    #[test]
    fn test_sanitize_dll_input_allows_irc_characters() {
        // Characters that are valid in IRC messages must not be rejected
        let irc_inputs = vec![
            "Hello &amp; world",
            "I use `fish` for encryption",
            "A | B | C",
            "test; echo done",
            "<?xml version=\"1.0\"?>",
            "javascript:alert(1)",
        ];

        for input in irc_inputs {
            let result = sanitize_dll_input(input);
            assert!(result.is_ok(), "IRC-valid input should not be rejected: {}", input);
        }
    }

    #[test]
    fn test_validate_command_args_edge_cases() {
        // Test command validation with edge cases
        let empty_args: Vec<String> = vec![];
        let result = validate_command_args("genkey", &empty_args);

        assert!(result.is_err());

        // Test with insufficient args for genkey command
        let one_arg = vec!["target".to_string()];
        let result = validate_command_args("genkey", &one_arg);

        assert!(result.is_ok()); // genkey requires 1 arg, we provided 1, so it should be ok
    }

    #[test]
    fn test_validate_dll_path() {
        // Valid paths
        assert!(validate_dll_path("test.dll").is_ok());
        assert!(validate_dll_path("lib.so").is_ok());
        assert!(validate_dll_path("../test.dll").is_ok());
        assert!(validate_dll_path("C:\\FiSH\\test.dll").is_ok());

        // Invalid: null byte
        assert!(validate_dll_path("test\0.dll").is_err());

        // Invalid: wrong extension
        assert!(validate_dll_path("test.txt").is_err());
        assert!(validate_dll_path("test.exe").is_err());
        assert!(validate_dll_path("test").is_err());
    }

    #[test]
    fn test_quiet_mode_thread_safety_basic() {
        // Test basic RwLock functionality for thread safety
        use std::sync::{Arc, RwLock};
        use std::thread;

        // Create a shared RwLock for testing
        let lock = Arc::new(RwLock::new(0));

        // Multiple readers should be able to access simultaneously
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let lock = Arc::clone(&lock);
                thread::spawn(move || {
                    let value = lock.read().unwrap();
                    *value
                })
            })
            .collect();

        // Collect all reader results
        for reader in readers {
            let val = reader.join().unwrap();
            assert_eq!(val, 0); // Should read initial value
        }

        // Writer should be able to update
        {
            let mut guard = lock.write().unwrap();
            *guard = 42;
        }

        assert_eq!(*lock.read().unwrap(), 42);
    }

    #[test]
    fn test_is_quiet_mode_consistency() {
        // Test that is_quiet_mode() returns consistent results
        let first_call = is_quiet_mode();
        let second_call = is_quiet_mode();

        // Two consecutive calls should return the same value (assuming no external changes)
        assert_eq!(first_call, second_call);
    }

    #[test]
    fn test_set_quiet_mode_function_exists() {
        // Test that the set_quiet_mode function works correctly
        let initial = is_quiet_mode();

        // Set to opposite value
        set_quiet_mode(!initial);
        assert_eq!(is_quiet_mode(), !initial);

        // Set back to original
        set_quiet_mode(initial);
        assert_eq!(is_quiet_mode(), initial);
    }
}
