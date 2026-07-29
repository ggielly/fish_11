//! Lock utilities for safer mutex handling with timeouts.
//!
//! This module provides helpers to avoid deadlocks by using timeouts when
//! acquiring locks, especially important for hook functions that may be
//! called during DLL unload or from multiple threads.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use log::error;

use crate::ENGINES;
use crate::engines::InjectEngines;

/// Default timeout for lock acquisition (100ms)
pub const DEFAULT_LOCK_TIMEOUT: Duration = Duration::from_millis(100);

/// Extended timeout for operations that may take longer (500ms)
pub const EXTENDED_LOCK_TIMEOUT: Duration = Duration::from_millis(500);

/// Timeout when uninstalling hooks during DLL unload (`uninstall_*_hooks`).
/// Longer than [`EXTENDED_LOCK_TIMEOUT`] so a handler can finish, but bounded to avoid hanging forever.
pub const UNINSTALL_HOOK_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Result type for try_lock operations
pub type TryLockResult<'a, T> = Result<MutexGuard<'a, T>, TryLockError>;

/// Error type for try_lock operations
#[derive(Debug)]
pub enum TryLockError {
    /// The lock could not be acquired within the timeout
    Timeout,
    /// The mutex was poisoned (a thread panicked while holding it)
    Poisoned,
}

impl std::fmt::Display for TryLockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TryLockError::Timeout => write!(f, "lock acquisition timed out"),
            TryLockError::Poisoned => write!(f, "mutex was poisoned"),
        }
    }
}

impl std::error::Error for TryLockError {}

/// Try to acquire a std::sync::Mutex with a timeout using spin-wait.
///
/// This is useful for avoiding deadlocks in hook functions where holding
/// a lock for too long could block other threads or cause issues during
/// DLL unload.
///
/// # Arguments
/// * `mutex` - The mutex to lock
/// * `timeout` - Maximum time to wait for the lock
///
/// # Returns
/// * `Ok(guard)` - Lock acquired successfully
/// * `Err(TryLockError::Timeout)` - Could not acquire within timeout
/// * `Err(TryLockError::Poisoned)` - Mutex was poisoned
///
/// # Example
/// ```ignore
/// use std::sync::Mutex;
/// use std::time::Duration;
///
/// let mutex = Mutex::new(42);
/// match try_lock_timeout(&mutex, Duration::from_millis(100)) {
///     Ok(guard) => println!("Got value: {}", *guard),
///     Err(e) => eprintln!("Failed to acquire lock: {}", e),
/// }
/// ```
pub fn try_lock_timeout<T>(mutex: &Mutex<T>, timeout: Duration) -> TryLockResult<'_, T> {
    let start = std::time::Instant::now();
    let spin_interval = Duration::from_micros(100);

    loop {
        match mutex.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                // A poisoned mutex indicates a prior panic while the lock was held.
                // Recovering silently would risk using corrupted shared state.
                // Panic here to surface the corruption immediately.
                panic!("Mutex poisoned : aborting to prevent state corruption: {}", poisoned);
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                if start.elapsed() >= timeout {
                    return Err(TryLockError::Timeout);
                }
                // Brief spin-wait before retrying
                std::thread::sleep(spin_interval);
            }
        }
    }
}

/// Try to acquire a lock with the default timeout (100ms).
///
/// Convenience wrapper around `try_lock_timeout` with `DEFAULT_LOCK_TIMEOUT`.
pub fn try_lock_default<T>(mutex: &Mutex<T>) -> TryLockResult<'_, T> {
    try_lock_timeout(mutex, DEFAULT_LOCK_TIMEOUT)
}

/// Try to acquire a lock with an extended timeout (500ms).
///
/// Useful for operations that may legitimately take longer.
pub fn try_lock_extended<T>(mutex: &Mutex<T>) -> TryLockResult<'_, T> {
    try_lock_timeout(mutex, EXTENDED_LOCK_TIMEOUT)
}

/// Handle mutex poisoning by aborting to prevent silent state corruption.
///
/// A poisoned mutex means a thread panicked while holding the lock,
/// leaving shared state in an unknown/inconsistent condition. Continuing
/// with potentially corrupted data is worse than crashing.
pub fn handle_poison<T>(err: PoisonError<T>) -> T {
    panic!("Mutex poisoned : aborting to prevent state corruption: {}", err);
}

/// Safe access to the global ENGINES mutex with proper error handling.
///
/// This function provides a safe way to access the ENGINES global state
/// with timeout-based locking and proper poison handling.
///
/// # Returns
/// * `Ok(guard)` - Successfully acquired lock
/// * `Err(e)` - Failed to acquire lock with reason
pub fn try_lock_engines() -> TryLockResult<'static, Option<Arc<InjectEngines>>> {
    // Use extended timeout for ENGINES as initialization might take longer
    match try_lock_timeout(&ENGINES, EXTENDED_LOCK_TIMEOUT) {
        Ok(guard) => Ok(guard),
        Err(TryLockError::Timeout) => {
            error!("ENGINES lock acquisition timed out - possible deadlock");
            Err(TryLockError::Timeout)
        }
        Err(TryLockError::Poisoned) => {
            // Poison already logged by try_lock_timeout; propagate the error.
            Err(TryLockError::Poisoned)
        }
    }
}

/// Macro for safe ENGINES access with automatic error handling.
///
/// This macro simplifies the common pattern of accessing the ENGINES global
/// with proper error handling and fallback behavior.
///
/// # Example
/// ```ignore
/// // Get engines with default fallback
/// let engines = get_engines!(Arc::new(InjectEngines::new()));
/// ```
#[macro_export]
macro_rules! get_engines {
    ($fallback:expr) => {{
        match $crate::lock_utils::try_lock_engines() {
            Ok(guard) => {
                if let Some(engines) = &*guard {
                    Arc::clone(engines)
                } else {
                    log::warn!("ENGINES global is None, using fallback");
                    $fallback
                }
            }
            Err(e) => {
                log::error!("Failed to access ENGINES: {}", e);
                $fallback
            }
        }
    }};
}

/// Extract the value from a hook mutex or return a default/error.
///
/// This macro simplifies the common pattern of:
/// 1. Try to lock the hook mutex with timeout
/// 2. Extract the function pointer from Option
/// 3. Return early with an error value if either step fails
///
/// # Example
/// ```ignore
/// // Get the original function pointer with 100ms timeout
/// let original_fn = get_hook_fn!(RECV_HOOK, RecvFn, "recv", -1);
/// ```
#[macro_export]
macro_rules! get_hook_fn {
    ($hook:expr, $fn_type:ty, $name:expr, $error_ret:expr) => {{
        match $crate::lock_utils::try_lock_default(&$hook) {
            Ok(guard) => match guard.as_ref() {
                Some(hook) => hook.trampoline(),
                None => {
                    log::error!("Original {}() function not available!", $name);
                    return $error_ret;
                }
            },
            Err(e) => {
                log::error!("Failed to acquire {} hook lock: {}", $name, e);
                return $error_ret;
            }
        }
    }};
}

/// Same as `get_hook_fn!` but with extended timeout for longer operations.
#[macro_export]
macro_rules! get_hook_fn_extended {
    ($hook:expr, $fn_type:ty, $name:expr, $error_ret:expr) => {{
        match $crate::lock_utils::try_lock_extended(&$hook) {
            Ok(guard) => match guard.as_ref() {
                Some(hook) => hook.trampoline(),
                None => {
                    log::error!("Original {}() function not available!", $name);
                    return $error_ret;
                }
            },
            Err(e) => {
                log::error!("Failed to acquire {} hook lock: {}", $name, e);
                return $error_ret;
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;

    #[test]
    fn test_try_lock_timeout_success() {
        let mutex = Mutex::new(42);
        let result = try_lock_timeout(&mutex, Duration::from_millis(100));
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), 42);
    }

    #[test]
    fn test_try_lock_timeout_contention() {
        let mutex = Arc::new(Mutex::new(0));
        let mutex_clone = Arc::clone(&mutex);

        // Hold the lock in another thread
        let handle = thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            thread::sleep(Duration::from_millis(200));
        });

        // Give the other thread time to acquire the lock
        thread::sleep(Duration::from_millis(10));

        // Try to acquire with a short timeout - should fail
        let result = try_lock_timeout(&mutex, Duration::from_millis(50));
        assert!(matches!(result, Err(TryLockError::Timeout)));

        handle.join().unwrap();
    }

    #[test]
    fn test_try_lock_default() {
        let mutex = Mutex::new("test");
        let result = try_lock_default(&mutex);
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), "test");
    }

    #[test]
    fn test_try_lock_extended() {
        let mutex = Mutex::new(vec![1, 2, 3]);
        let result = try_lock_extended(&mutex);
        assert!(result.is_ok());
        assert_eq!(*result.unwrap(), vec![1, 2, 3]);
    }
}
