use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{config, dll_function_identifier};

dll_function_identifier!(FiSH11_GetConfigPath, _data, {
    let config_path = config::get_config_path()?;
    Ok(config_path.to_string_lossy().to_string())
});

#[cfg(test)]
mod tests {
    use std::ffi::CStr;
    use std::ptr;

    use super::*;

    #[test]
    fn test_fish11_getconfigpath_normal() {
        let _ = crate::logging::init_logger(log::LevelFilter::Debug);
        let mut buffer: [c_char; 260] = [0; 260];
        let result = FiSH11_GetConfigPath(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        assert_eq!(result, crate::dll_interface::MIRC_IDENTIFIER);
        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        let path_str_result = c_str.to_str();
        if path_str_result.is_err() {
            panic!("Failed to convert C string to Rust string: {:?}", path_str_result.err());
        }
        let path_str = path_str_result.unwrap();
        assert!(path_str.contains("fish_11.ini"));
    }
}
