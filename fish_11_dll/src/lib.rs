//! FiSH 11 - A secure encryption DLL for mIRC
//!
//! This DLL provides secure communication capabilities for mIRC clients
//! using Curve25519 for key exchange and ChaCha20-Poly1305 for encryption.
//!
//! This is the entry point for the DLL.
//!
//! In the file :
//!   - dll_interface contains the exported functions for mIRC
//!   - crypto contains the cryptographic functions
//!   - error contains the error handling code
//!   - config contains the configuration file handling code
//!   - tests contains the unit tests
//!   - utils contains utility functions
//!   - logging contains the file logging functionality
//!
//! Written by [GuY], 2025. Licensed under the GPL v3.
pub mod buffer_utils;
pub mod config;
pub mod crypto;
pub mod dll_function_utils;
pub mod dll_interface;
pub mod error;
pub mod legacy;
pub mod logging;
pub mod platform_types;
pub mod utils;
#[macro_use]
pub mod logging_macros;
// FCEP-1 channel encryption removed : replaced by FCEP-2 (MLS over IRC)
// pub mod channel_encryption;
#[cfg(windows)]
pub mod engine_registration;
pub mod fcep2;
pub mod unified_error;

use once_cell::sync::Lazy;
/// Global storage for current IRC network name
/// Updated by fish_inject when it detects the network from IRC "005" messages
use parking_lot::RwLock;

pub static CURRENT_NETWORK: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));

// Use the centralized version string from the core library
// Reconstruct the original version string for the DLL using the correct format and centralized build components.
pub fn fish_main_version() -> String {
    format!(
        "*** FiSH_11 core v{} - Compiled {} at {} - Written by [GuY], licensed under the GPL-v3. ***",
        fish_11_core::globals::BUILD_VERSION,
        fish_11_core::globals::BUILD_DATE.as_str(),
        fish_11_core::globals::BUILD_TIME.as_str()
    )
}

/// Set the current IRC network name (called by fish_inject or scripts)
pub fn set_current_network(network: impl Into<String>) {
    let mut current = CURRENT_NETWORK.write();
    *current = Some(network.into());
}

/// Get the current IRC network name
pub fn get_current_network() -> Option<String> {
    CURRENT_NETWORK.read().clone()
}

/// Initialize the legacy FiSH 10 compatibility system
pub fn init_legacy_system() {
    legacy::init_legacy_system();
}
