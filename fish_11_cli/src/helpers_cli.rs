use std::io::Read;
use std::path::{Component, Path};

/// Helper function to check if a path contains directory traversal sequences
/// Returns true if the path is safe, false if it contains traversal attempts
fn is_safe_path<P: AsRef<Path>>(path: P) -> bool {
    let path = path.as_ref();

    // Use Components iterator to check each path component
    for component in path.components() {
        match component {
            Component::ParentDir => return false, // "../" component found
            Component::CurDir => continue,        // "./" component - skip
            Component::Normal(_) => continue,     // Normal component - safe
            Component::RootDir | Component::Prefix(_) => continue, // Root/prefix is OK
        }
    }
    true
}

/// Validates that a config file exists and is accessible
/// Returns true if the file can be accessed, false if there's a problem
pub fn validate_config_file(file_path: &str) -> bool {
    let path = Path::new(file_path);

    // Check for path traversal attacks
    if !is_safe_path(path) {
        if !crate::is_quiet_mode() {
            println!(
                "Error : config file path '{}' contains directory traversal sequences",
                file_path
            );
        }
        return false;
    }

    if !path.exists() {
        if !crate::is_quiet_mode() {
            println!("Error : config file '{}' does not exist", file_path);
        }
        return false;
    }

    if !path.is_file() {
        if !crate::is_quiet_mode() {
            println!("Error : '{}' is not a file", file_path);
        }
        return false;
    }

    // Check if the file has a valid extension (.ini)
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if extension.to_lowercase() != "ini" {
        info_print!("Warning : config file '{}' does not have .ini extension", file_path);
        // Continue anyway, it might still work
    }

    // Try to read a few bytes to verify we have read access
    match std::fs::File::open(path) {
        Ok(mut file) => {
            // Try to read the first few bytes to confirm readability
            let mut buffer = [0u8; 10];
            match file.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        info_print!("Config file '{}' exists and is readable", file_path);
                        true
                    } else {
                        info_print!("Warning : config file '{}' is empty", file_path);
                        true
                    }
                }
                Err(e) => {
                    if !crate::is_quiet_mode() {
                        println!("Error : cannot read from config file '{}': {}", file_path, e);
                    }
                    false
                }
            }
        }
        Err(e) => {
            if !crate::is_quiet_mode() {
                println!("Error : cannot open config file '{}': {}", file_path, e);
            }
            false
        }
    }
}
