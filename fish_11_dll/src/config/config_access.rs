//! Configuration access patterns for FiSH 11

use parking_lot::{RwLockReadGuard, RwLockWriteGuard};

use crate::config::CONFIG;
use crate::config::file_storage::save_config;
use crate::config::models::FishConfig;
use crate::error::Result;
use crate::{log_debug, log_error, log_info, log_warn};

/// A read-only guard for the configuration
pub struct ConfigReadGuard<'a> {
    guard: RwLockReadGuard<'a, FishConfig>,
}

/// A read-write guard for the configuration
pub struct ConfigWriteGuard<'a> {
    guard: RwLockWriteGuard<'a, FishConfig>,
    modified: bool,
}

impl<'a> ConfigReadGuard<'a> {
    /// Get a reference to the inner configuration
    pub fn config(&self) -> &FishConfig {
        &self.guard
    }
}

impl<'a> ConfigWriteGuard<'a> {
    /// Get a mutable reference to the inner configuration
    pub fn config_mut(&mut self) -> &mut FishConfig {
        self.modified = true;
        self.guard.mark_dirty();
        &mut self.guard
    }

    /// Get a reference to the inner configuration
    pub fn config(&self) -> &FishConfig {
        &self.guard
    }

    /// Mark the configuration as modified
    pub fn mark_modified(&mut self) {
        self.modified = true;
        self.guard.mark_dirty();
    }
    /// Save the configuration if it has been modified
    pub fn save_if_modified(&mut self) -> Result<()> {
        if self.modified || self.guard.is_dirty() {
            #[cfg(debug_assertions)]
            log_debug!("ConfigWriteGuard::save_if_modified - saving config due to modifications");

            save_config(&self.guard, None)?;

            self.modified = false;
            // Note: save_config already calls mark_clean() internally
        } else {
            #[cfg(debug_assertions)]
            log_debug!("ConfigWriteGuard::save_if_modified - no modifications, skipping save");
        }
        Ok(())
    }
}

impl<'a> Drop for ConfigWriteGuard<'a> {
    fn drop(&mut self) {
        if self.modified || self.guard.is_dirty() {
            // Add logging to track potential double-save issues
            #[cfg(debug_assertions)]
            log_debug!("ConfigWriteGuard::drop - attempting to save modified config");
            // Try to save, but ignore errors since we're in a destructor
            match save_config(&self.guard, None) {
                Ok(_) => {
                    #[cfg(debug_assertions)]
                    log_debug!("ConfigWriteGuard::drop - config saved successfully");
                }
                Err(e) => {
                    #[cfg(debug_assertions)]
                    log_warn!("ConfigWriteGuard::drop - failed to save config: {}", e);
                }
            }
        } else {
            #[cfg(debug_assertions)]
            log_debug!("ConfigWriteGuard::drop - config not modified, skipping save");
        }
    }
}

/// Get read-only access to the configuration
pub fn read_config() -> Result<ConfigReadGuard<'static>> {
    let guard = CONFIG.read();
    Ok(ConfigReadGuard { guard })
}

pub fn write_config() -> Result<ConfigWriteGuard<'static>> {
    let guard = CONFIG.write();
    Ok(ConfigWriteGuard { guard, modified: false })
}
pub fn with_config<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&FishConfig) -> Result<T>,
{
    #[cfg(debug_assertions)]
    log_info!("with_config : attempting to acquire read lock on CONFIG...");

    let guard = CONFIG.read();

    #[cfg(debug_assertions)]
    {
        let pid = std::process::id();
        let tid = std::thread::current().id();
        let now = chrono::Local::now();
        #[cfg(debug_assertions)]
        log_debug!(
            "with_config: acquired read lock - pid={}, tid={:?}, time={}",
            pid,
            tid,
            now.to_rfc3339()
        );
    }

    let guard = ConfigReadGuard { guard };
    f(guard.config())
}

pub fn with_config_mut<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut FishConfig) -> Result<T>,
{
    #[cfg(debug_assertions)]
    log_info!("with_config_mut : attempting to acquire write lock on CONFIG...");

    let guard = CONFIG.write();

    #[cfg(debug_assertions)]
    {
        let pid = std::process::id();
        let tid = std::thread::current().id();
        let now = chrono::Local::now();

        #[cfg(debug_assertions)]
        log_debug!(
            "with_config_mut: acquired write lock - pid={}, tid={:?}, time={}",
            pid,
            tid,
            now.to_rfc3339()
        );
    }

    let mut guard = ConfigWriteGuard { guard, modified: false };
    let result = f(guard.config_mut());

    // Only save if the operation was successful
    match &result {
        Ok(_) => {
            if let Err(e) = guard.save_if_modified() {
                #[cfg(debug_assertions)]
                log_error!("with_config_mut: Error saving config: {}", e);
                // Mark as not modified to prevent double-save in Drop
                guard.modified = false;
            } else {
                // Successfully saved, mark as not modified to prevent double-save in Drop
                guard.modified = false;
            }
        }
        Err(_) => {
            // Operation failed, don't save changes
            #[cfg(debug_assertions)]
            log_debug!("with_config_mut: operation failed, not saving config");
            guard.modified = false; // Prevent save in Drop
        }
    }

    return result;
}
