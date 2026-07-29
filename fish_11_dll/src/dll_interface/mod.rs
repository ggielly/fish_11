// FCEP-1 channel encryption removed : replaced by FCEP-2 (MLS over IRC)
// pub use crate::channel_encryption::init_key::FiSH11_InitChannelKey;
// pub use crate::channel_encryption::process_key::FiSH11_ProcessChannelKey;
pub use crate::crypto::dh1080::{
    FiSH10_DH1080_ComputeSecret, FiSH10_DH1080_GenerateKeyPair, FiSH10_DH1080_SetKey,
};
use crate::log_error;

mod fish11_coreversion;
mod fish11_decryptmsg;
mod fish11_encryptmsg;
mod fish11_filedelkey;
mod fish11_filegetkey;
mod fish11_filelistkeys;
mod fish11_filelistkeysitem;
mod fish11_genkey;
mod fish11_getconfigpath;
mod fish11_getencryptionstats;
mod fish11_getkeyttl;
mod fish11_getratchetstate;
mod fish11_hasmanualchannelkey;
mod fish11_hasratchetchannelkey;
mod fish11_help;
mod fish11_removemanualchannelkey;
mod fish11_removeratchetchannelkey;
mod fish11_setencryptionprefix;
mod fish11_setfishprefix;
mod fish11_setmanualchannelkey;
mod fish11_setmanualchannelkeyfrompassword;
mod fish11_setnetwork;
mod fish11_settopic;
mod fish_10;
mod utility;

pub use fish_10::fish10_decryptmsg::FiSH10_DecryptMsg;
pub use fish_10::fish10_encryptmsg::FiSH10_EncryptMsg;
pub use fish_10::fish10_haskey::{FiSH10_GetKey, FiSH10_GetKeyInfo, FiSH10_HasKey};
pub use fish_10::fish10_register_engine::{
    FiSH10_GetEngineVersion, FiSH10_IsEngineAvailable, FiSH10_RegisterEngine,
};
pub use fish_10::fish10_setkey::FiSH10_SetKey;
pub use fish_10::fish10_settopic::{FiSH10_GetTopic, FiSH10_RemoveTopic, FiSH10_SetTopic};
pub use fish11_getencryptionstats::FiSH11_GetEncryptionStats;
pub use fish11_getkeyttl::FiSH11_GetKeyTTL;
pub use fish11_getratchetstate::FiSH11_GetRatchetState;
pub use fish11_hasmanualchannelkey::FiSH11_HasManualChannelKey;
pub use fish11_hasratchetchannelkey::FiSH11_HasRatchetChannelKey;
pub use fish11_masterkey::{
    FiSH11_MasterKeyChangePassword, FiSH11_MasterKeyInit, FiSH11_MasterKeyIsUnlocked,
    FiSH11_MasterKeyLock, FiSH11_MasterKeyStatus, FiSH11_MasterKeyUnlock,
};
pub use fish11_removemanualchannelkey::FiSH11_RemoveManualChannelKey;
pub use fish11_removeratchetchannelkey::FiSH11_RemoveRatchetChannelKey;
pub use fish11_setencryptionprefix::FiSH11_SetEncryptionPrefix;
pub use fish11_setfishprefix::FiSH11_SetFishPrefix;
pub use fish11_setmanualchannelkey::FiSH11_SetManualChannelKey;
pub use fish11_setmanualchannelkeyfrompassword::FiSH11_SetManualChannelKeyFromPassword;
pub use fish11_settopic::{FiSH11_GetTopic, FiSH11_RemoveTopic, FiSH11_SetTopic};
pub use ini_types::{INI_GetBool, INI_GetInt, INI_GetString, INI_SetInt, INI_SetString};
pub use key_management::{FiSH11_ProcessPublicKey, FiSH11_TestCrypt};
pub(crate) mod core;
pub mod dll_error;
pub mod fish11_exchangekey;
pub mod fish11_fcep2;
pub mod fish11_masterkey;
pub mod fish11_setkey;
pub mod fish11_setkeyfromplaintext;
pub mod fish11_setmircdir;
pub mod function_template;
pub mod ini_types;
pub mod key_management;
pub use fish_11_core::globals::{
    CRATE_VERSION, CURRENT_YEAR, DEFAULT_MIRC_BUFFER_SIZE, FUNCTION_TIMEOUT_SECONDS,
    KEY_EXCHANGE_TIMEOUT_SECONDS, MAX_MIRC_BUFFER_SIZE, MIRC_BUFFER_SIZE, MIRC_COMMAND,
    MIRC_CONTINUE, MIRC_DLL_RESULT_PAYLOAD_CAP, MIRC_ERROR, MIRC_HALT, MIRC_IDENTIFIER,
    MIRC_TYPICAL_BUFFER_SIZE, NICK_VALIDATOR,
};
pub use fish11_fcep2::*;
/// Returns the maximum amount of data that can be written into the output buffer (excluding the
/// terminating NUL that mIRC reserves). Falls back to [`MIRC_BUFFER_SIZE`] when [`LOAD_INFO`](crate::dll_interface::core::LOAD_INFO) is unset.
///
/// Note: [`crate::buffer_utils::write_cstring_to_buffer`] still caps each **copied** result string
/// to [`MIRC_DLL_RESULT_PAYLOAD_CAP`] bytes including NUL : see the buffer module docs.
pub(crate) fn get_buffer_size() -> usize {
    use self::core::LOAD_INFO;

    // First try to get buffer size from mIRC information
    let buffer_size = {
        let guard_result = LOAD_INFO.lock();

        if guard_result.is_err() {
            log_error!(
                "FATAL: failed to acquire LOAD_INFO mutex lock in get_buffer_size. DLL may be in corrupted state. Returning default size."
            );
            return DEFAULT_MIRC_BUFFER_SIZE as usize; // Return a default if mutex fails
        }
        let guard = guard_result.unwrap();

        guard.as_ref().map(|info| info.m_bytes as usize).unwrap_or_else(|| {
            // Fall back to our global buffer size
            match MIRC_BUFFER_SIZE.lock() {
                Ok(size) => *size,
                Err(_) => DEFAULT_MIRC_BUFFER_SIZE,
            }
        })
    };

    // Always leave room for null terminator, and cap to MAX_MIRC_BUFFER_SIZE
    let available = buffer_size.saturating_sub(1);

    std::cmp::min(available, MAX_MIRC_BUFFER_SIZE)
}

#[cfg(test)]
/// Test helper: temporarily override both MIRC_BUFFER_SIZE and LOAD_INFO
/// to ensure get_buffer_size() returns the test's actual buffer size.
/// Returns the previous values so they can be restored.
pub(crate) fn override_buffer_size_for_test(size: usize) -> Option<usize> {
    use self::core::LOAD_INFO;

    // Clear LOAD_INFO so get_buffer_size() will use MIRC_BUFFER_SIZE
    let _ = LOAD_INFO.lock().ok().map(|mut guard| *guard = None);

    // Set MIRC_BUFFER_SIZE to the test's buffer size
    MIRC_BUFFER_SIZE.lock().ok().map(|mut g| {
        let prev = *g;
        *g = size;
        prev
    })
}

#[cfg(test)]
mod ini_tests;

#[cfg(test)]
/// Test helper: restore the buffer size after a test
pub(crate) fn restore_buffer_size_for_test(prev_size: Option<usize>) {
    if let Some(size) = prev_size {
        let _ = MIRC_BUFFER_SIZE.lock().ok().map(|mut g| *g = size);
    }
}
