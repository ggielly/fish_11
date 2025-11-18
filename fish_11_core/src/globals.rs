use once_cell::sync::Lazy;
use regex::Regex;
use std::ffi::c_int;
use std::sync::Mutex;
use std::time::Duration;

pub const MIRC_HALT: c_int = 0;
pub const MIRC_CONTINUE: c_int = 1;
pub const MIRC_COMMAND: c_int = 2;
pub const MIRC_IDENTIFIER: c_int = 3;
pub const MIRC_ERROR: c_int = 4;

// Default maximum bytes that can be returned to mIRC. We still cap
// the runtime-reported buffer size to a safe maximum below.
// TODO : check if it is needed
pub const DEFAULT_MIRC_BUFFER_SIZE: usize = 4096;

// Maximum buffer size we will ever report to callers (including content, we'll
// subtract one for the null terminator in get_buffer_size()). This prevents
// accidentally writing too much to caller buffers; mIRC historically uses 900.
// TODO : check if it is needed
pub const MAX_MIRC_BUFFER_SIZE: usize = 900;

/// Timeout duration for key exchange operations in seconds
pub const KEY_EXCHANGE_TIMEOUT_SECONDS: u64 = 10;

// Typical buffer size for mIRC, used for initial allocation
pub const MIRC_TYPICAL_BUFFER_SIZE: usize = 20480;

pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CURRENT_YEAR: &str = "2025";

pub const FUNCTION_TIMEOUT_SECONDS: Duration = Duration::from_secs(5);

pub static NICK_VALIDATOR: Lazy<Regex> = Lazy::new(|| {
    // RFC 1459 compliant nickname validation
    Regex::new(r"^[a-zA-Z\[\]\\`_^{|}][a-zA-Z0-9\[\]\\`_^{|}-]{0,15}$")
        .expect("Hardcoded RFC 1459 nickname regex should always be valid")
});

// Mutex for accessing/modifying the maximum buffer size
// This value can be changed at runtime based on mIRC buffer settings
pub static MIRC_BUFFER_SIZE: Mutex<usize> = Mutex::new(DEFAULT_MIRC_BUFFER_SIZE);

// Maximum size of a message that can be encrypted/decrypted
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// IRC protocol commands
pub const CMD_PRIVMSG: &str = "PRIVMSG";
pub const CMD_NOTICE: &str = "NOTICE";
pub const CMD_JOIN: &str = "JOIN";
pub const CMD_TOPIC: &str = "TOPIC";

/// IRC numeric replies
pub const RPL_WELCOME: &str = "001";
pub const RPL_TOPIC: &str = "332";
pub const RPL_ISUPPORT: &str = "005";

/// FiSH_11 encryption markers  
pub const ENCRYPTION_PREFIX_FISH: &str = "+FiSH ";
// FiSH_10 legacy
pub const ENCRYPTION_PREFIX_OK: &str = "+OK ";
// mircryption
pub const ENCRYPTION_PREFIX_MCPS: &str = "mcps ";

/// FiSH key exchange markers
pub const KEY_EXCHANGE_INIT: &str = "X25519_INIT";
pub const KEY_EXCHANGE_PUBKEY: &str = "FiSH11-PubKey:";

/// sematic version, e.g "5.0.1-13-g5ee5b76"
pub const BUILD_VERSION: &str = match option_env!("VERGEN_GIT_DESCRIBE") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

/// Build date, e.g "2024-08-01"
pub const BUILD_DATE: &str = match option_env!("VERGEN_BUILD_DATE") {
    Some(date) => date,
    None => "N/A",
};

/// Build time, e.g "23:25:01"
pub const BUILD_TIME: &str = match option_env!("VERGEN_BUILD_TIME") {
    Some(time) => time,
    None => "13:37",
};
