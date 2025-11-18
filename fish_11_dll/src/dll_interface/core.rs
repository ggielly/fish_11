use std::sync::Mutex;
use log;
use crate::platform_types::{BOOL, HWND, c_int};
use crate::{log_debug, log_info};
use crate::dll_interface::DEFAULT_MIRC_BUFFER_SIZE;
use fish_11_core::globals::{BUILD_DATE, BUILD_TIME, BUILD_VERSION, CRATE_VERSION};

#[cfg(windows)]
use winapi::shared::minwindef::{DWORD, HINSTANCE, LPVOID, TRUE};

#[cfg(not(windows))]
type DWORD = u32;
#[cfg(not(windows))]
type HINSTANCE = *mut std::ffi::c_void;
#[cfg(not(windows))]
type LPVOID = *mut std::ffi::c_void;
#[cfg(not(windows))]
const TRUE: c_int = 1;

/// mIRC stuffaize
#[allow(dead_code)]
pub(crate) const MIRC_HALT: c_int = 0;
#[allow(dead_code)]
pub(crate) const MIRC_CONTINUE: c_int = 1;
#[allow(dead_code)]
pub(crate) const MIRC_COMMAND: c_int = 2;
#[allow(dead_code)]
pub(crate) const MIRC_IDENTIFIER: c_int = 3;

/// Returns the maximum amount of data that can be written into the output buffer.
/// Always leaves room for a null terminator.
#[derive(Debug, Clone, Copy)]
#[allow(non_snake_case)]
#[repr(C)]
pub struct LOADINFO {
    pub m_version: DWORD,
    pub m_hwnd: HWND,
    pub m_keep: BOOL,
    pub m_unicode: BOOL,
    pub m_beta: DWORD,
    pub m_bytes: DWORD,
    pub m_extra: DWORD,
}

// SAFETY: C-like struct with primitive fields can be Send/Sync
unsafe impl Send for LOADINFO {}
unsafe impl Sync for LOADINFO {}

pub(crate) static LOAD_INFO: Mutex<Option<LOADINFO>> = Mutex::new(None);
static _INIT_ONCE: std::sync::Once = std::sync::Once::new();

/// Basic buffer size retrieval - does not include fallback to MIRC_BUFFER_SIZE
/// For external use, prefer the module-level get_buffer_size() function
pub(crate) fn get_buffer_size_basic() -> usize {
    // Single lock acquisition
    let guard = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");

    guard
        .as_ref()
        .map(|info| info.m_bytes as usize)
        .unwrap_or(DEFAULT_MIRC_BUFFER_SIZE)
        .saturating_sub(1) // Null terminator space
}

/// ---------------------------------------------------------------------------
/// mIRC DLL Lifecycle Functions
/// ---------------------------------------------------------------------------

/// Windows DLL entry point that handles process attachment/detachment
///
/// This function serves as the main entry point for the FiSH11 DLL and is called by Windows
/// when the DLL is loaded or unloaded. It implements basic lifecycle management but keeps
/// initialization lightweight since most setup is handled by the `LoadDll` function.
///
/// # Arguments
/// * `_hinst` - Handle to the DLL module (unused)
/// * `reason` - Reason code for the call (process attach/detach/thread attach/detach)
/// * `_` - Reserved parameter (unused)
///
/// # Returns
/// Always returns `TRUE` (1) indicating successful handling
///
/// # Behavior
/// - For `DLL_PROCESS_ATTACH`: Marks successful DLL loading
/// - For `DLL_PROCESS_DETACH`: Marks successful DLL unloading
/// - Other cases (thread attach/detach): No special handling
///
/// # Safety Considerations
/// - Minimal processing to avoid loader lock issues
/// - No complex initialization to prevent deadlocks
/// - Actual initialization happens in `LoadDll`
///
/// # Windows Notes
/// - Called in the context of the calling thread
/// - Should avoid calling other DLLs during process attach/detach
/// - Must be declared with `#[no_mangle]` for Windows to find it
///
/// # Example Usage
/// This is an automatic Windows mechanism - not called directly by user code
#[allow(non_snake_case)]
#[no_mangle]
#[cfg(windows)]
pub extern "system" fn DllMain(_hinst: HINSTANCE, reason: DWORD, _: LPVOID) -> BOOL {
    match reason {
        winapi::um::winnt::DLL_PROCESS_ATTACH => {
            // Initialize logger first with Info level (can be changed to Debug for more details)
            let _ = crate::logging::init_logger(log::LevelFilter::Info);

            // Use structured logging helper for module initialization
            crate::logging::log_module_init("DLL Core", &BUILD_VERSION);

            // Log version info once during DLL attach
            if crate::logging::is_logger_initialized() {
                log_info!("DLL Process Attach - FiSH v{} (built {} {})", 
                    BUILD_VERSION, 
                    BUILD_DATE, 
                    BUILD_TIME);
                log_debug!("System information: Process ID: {}", std::process::id());

                // When this DLL is loaded, it tries to register itself with the inject DLL.
                #[cfg(windows)]
                crate::engine_registration::register_engine();

                // Log OS information if available
                #[cfg(target_os = "windows")]
                {
                    use std::env;
                    if let Ok(os_info) = env::var("OS") {
                        log_debug!("Operating System: {}", os_info);
                    }
                }
            }

            TRUE
        }
        winapi::um::winnt::DLL_PROCESS_DETACH => {
            // Use structured logging helper for module shutdown
            crate::logging::log_module_shutdown("DLL Core");

            if crate::logging::is_logger_initialized() {
                log::info!("DLL Process Detach: FiSH_11 DLL unloaded");
            }

            TRUE
        }
        _ => TRUE,
    }
}

/// Load the DLL and initialize it
/// This is needed for mIRC to load the DLL properly
#[no_mangle]
#[cfg(windows)]
pub extern "stdcall" fn LoadDll(load: *mut LOADINFO) -> BOOL {
    // Ensure logger is initialized (in case DllMain didn't do it)
    if !crate::logging::is_logger_initialized() {
        let _ = crate::logging::init_logger(log::LevelFilter::Info);
    }

    // Log version information to file, not to console
    log_debug!("LoadDll called for FiSH v{}", BUILD_VERSION);

    // Log function entry with structured logging
    crate::logging::log_function_entry("LoadDll", None::<i32>);

    // Initialize CONFIG early to avoid lazy initialization deadlocks
    #[cfg(debug_assertions)]
    log::info!("LoadDll: calling init_config() to force CONFIG initialization...");
    
    crate::config::init_config();
    
    #[cfg(debug_assertions)]
    log::info!("LoadDll: CONFIG initialized successfully");

    // Create a structure to hold mIRC client info for logging
    let mut mirc_version = String::from("Unknown mIRC version");
    let mut buffer_size = DEFAULT_MIRC_BUFFER_SIZE;
    let mut unicode_mode = false;

    if !load.is_null() {
        unsafe {
            (*load).m_keep = TRUE;

            // Extract mIRC version information for logging
            let major = ((*load).m_version >> 16) & 0xFFFF;
            let minor = (*load).m_version & 0xFFFF;
            mirc_version = format!("{}.{}", major, minor);
            buffer_size = (*load).m_bytes as usize;
            unicode_mode = (*load).m_unicode != 0;

            // Store the LOADINFO
            let mut global_info = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");
            *global_info = Some(*load);

            // Log structured configuration using standard log macros
            log::info!("CONFIG [mIRC]: version = {}", mirc_version);
            log::info!("CONFIG [mIRC]: buffer_size = {}", buffer_size);
            log::info!("CONFIG [mIRC]: unicode_mode = {}", unicode_mode);
        }
    } else {
        // Log the null pointer situation
        log::warn!("LoadDll called with null pointer - using default buffer size");
    }

    // Log successful initialization
    log::info!(
        "FiSH_11 v{} initialized successfully for mIRC {}",
        BUILD_VERSION,
        mirc_version
    );

    // Log function exit
    log_debug!("EXIT: LoadDll - returned TRUE");

    TRUE
}

/// Unload the DLL
///
/// Called by mIRC when the DLL is being unloaded.
/// Timeout parameter indicates if mIRC is shutting down (1) or just unloading the DLL (0).
///
/// # Arguments
/// * `_timeout` - Timeout indication value (0 = regular unload, 1 = mIRC shutting down)
///
/// # Returns
/// Returns 0 to allow unload or 1 to prevent unload
#[no_mangle]
#[cfg(windows)]
pub extern "stdcall" fn UnloadDll(_timeout: c_int) -> c_int {
    // Log function entry with parameters
    crate::logging::log_function_entry("UnloadDll", Some(_timeout));

    // Log the unloading with additional context
    if _timeout == 1 {
        log::info!("mIRC is shutting down - preparing for unload");
    } else {
        log::info!("mIRC requested DLL unload - regular operation");
    }

    // Clean up resources
    {
        let mut state = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");
        log_debug!("Cleaning up LOAD_INFO resources");
        *state = None;
    }

    // Log final shutdown message
    log::info!("FiSH_11 DLL resources released and ready for unload");

    // Log function exit with return value (0 = allow unload)
    crate::logging::log_function_exit("UnloadDll", Some(0));

    0 // Allow unload
}

// Unix-compatible versions (extern "C" instead of "stdcall")
#[no_mangle]
#[cfg(not(windows))]
pub extern "C" fn LoadDll(load: *mut LOADINFO) -> BOOL {
    // Ensure logger is initialized
    if !crate::logging::is_logger_initialized() {
        let _ = crate::logging::init_logger(log::LevelFilter::Info);
    }

    log_debug!("LoadDll called for FiSH v{}", CRATE_VERSION);
    crate::logging::log_function_entry("LoadDll", None::<i32>);
    
    crate::config::init_config();
    
    let mut mirc_version = String::from("Unknown version");
    let mut buffer_size = DEFAULT_MIRC_BUFFER_SIZE;
    let mut unicode_mode = false;

    if !load.is_null() {
        unsafe {
            (*load).m_keep = TRUE;
            let major = ((*load).m_version >> 16) & 0xFFFF;
            let minor = (*load).m_version & 0xFFFF;
            mirc_version = format!("{}.{}", major, minor);
            buffer_size = (*load).m_bytes as usize;
            unicode_mode = (*load).m_unicode != 0;

            let mut global_info = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");
            *global_info = Some(*load);

            log::info!("CONFIG: version = {}", mirc_version);
            log::info!("CONFIG: buffer_size = {}", buffer_size);
            log::info!("CONFIG: unicode_mode = {}", unicode_mode);
        }
    } else {
        log::warn!("LoadDll called with null pointer - using default buffer size");
    }

    log::info!("FiSH_11 v{} initialized successfully (version {})", CRATE_VERSION, mirc_version);
    log_debug!("EXIT: LoadDll - returned TRUE");

    TRUE
}

#[no_mangle]
#[cfg(not(windows))]
pub extern "C" fn UnloadDll(_timeout: c_int) -> c_int {
    crate::logging::log_function_entry("UnloadDll", Some(_timeout));

    if _timeout == 1 {
        log::info!("Client is shutting down - preparing for unload");
    } else {
        log::info!("Client requested DLL unload - regular operation");
    }

    {
        let mut state = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");
        log_debug!("Cleaning up LOAD_INFO resources");
        *state = None;
    }

    log::info!("FiSH_11 resources released and ready for unload");
    crate::logging::log_function_exit("UnloadDll", Some(0));

    0
}