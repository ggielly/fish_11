//! FCEP-2 MLS Bot TOML Configuration Engine
//!
//! Loads and manages `fish_mls_bot.toml` : the dedicated configuration file
//! for the standalone MLS test bot. Structure mirrors `fish_11_relay` patterns
//! with additional MLS backlog and encrypted database sections.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::info;

pub const DEFAULT_CONFIG_FILE: &str = "fish_mls_bot.toml";

/// Top-level application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub mls: MlsConfig,
    pub backlog: BacklogConfig,
    pub database: DatabaseConfig,
    pub logging: LoggingConfig,
}

/// IRC server connection parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub use_tls: bool,
    pub nickname: String,
    pub username: String,
    pub realname: String,
    pub channels: Vec<String>,
    pub password: Option<String>,
}

/// FCEP-2 MLS relay / master-key operational parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlsConfig {
    /// Operational mode: "relay" (store-and-forward), "full" (full MLS participant),
    /// or "master-key" (key distribution authority per §11.4)
    pub mode: String,
    pub max_keypackages: usize,
    pub welcome_ttl_days: u64,
    pub commit_history_limit: usize,
    pub rate_limit_per_sec: u64,
}

/// Backlog TCP socket configuration (port 31337)
///
/// Per FCEP-2 §11.4 and §18.3: the relay bot MAY provide an out-of-band
/// TCP channel for Commit log synchronisation and KeyPackage exchange.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BacklogConfig {
    pub enabled: bool,
    pub listen_port: u16,
    pub bind_address: String,
    /// External (public) IP address for NAT traversal. Empty = auto-detect.
    pub external_address: String,
    pub peer_timeout_secs: u64,
    pub max_peers: usize,
}

/// Encrypted NoSQL database configuration
///
/// §19.3: state at rest MUST be encrypted. The `encryption_key` is a
/// mandatory 32-byte hex-or-raw key used to derive sub-keys via HKDF.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub path: String,
    /// 32-byte encryption key (raw UTF-8 or hex-encoded 64-char string)
    pub encryption_key: String,
    pub auto_compact: bool,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level: trace, debug, info, warn, error
    pub level: String,
    /// Optional file path; empty = stderr only
    pub file: String,
}

// ── Defaults ──────────────────────────────────────────────────────────────

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                address: "irc.libera.chat".into(),
                port: 6697,
                use_tls: true,
                nickname: "MLS_Bot".into(),
                username: "mlsbot".into(),
                realname: "FiSH-11 FCEP-2 MLS Test Bot".into(),
                channels: vec!["#fish11-test".into()],
                password: None,
            },
            mls: MlsConfig {
                mode: "relay".into(),
                max_keypackages: 20,
                welcome_ttl_days: 14,
                commit_history_limit: 500,
                rate_limit_per_sec: 4,
            },
            backlog: BacklogConfig {
                enabled: true,
                listen_port: 31337,
                bind_address: "0.0.0.0".into(),
                external_address: String::new(),
                peer_timeout_secs: 30,
                max_peers: 64,
            },
            database: DatabaseConfig {
                path: "./mls_bot_data".into(),
                encryption_key: "CHANGE_ME_32_BYTES_SECRET_KEY!!".into(),
                auto_compact: true,
            },
            logging: LoggingConfig { level: "info".into(), file: String::new() },
        }
    }
}

impl AppConfig {
    /// Load configuration from TOML file, creating a default file if missing.
    pub fn load_or_create<P: AsRef<Path>>(path: P) -> Result<Self> {
        let p = path.as_ref();
        if !p.exists() {
            let default_cfg = AppConfig::default();
            let toml_str = toml::to_string_pretty(&default_cfg)
                .context("Failed to serialize default TOML configuration")?;

            if let Some(parent) = p.parent() {
                if !parent.as_os_str().is_empty() && !parent.exists() {
                    fs::create_dir_all(parent)?;
                }
            }

            fs::write(p, toml_str)
                .with_context(|| format!("Failed to create default config at {}", p.display()))?;

            info!("Created default configuration file: {}", p.display());
            return Ok(default_cfg);
        }

        let content = fs::read_to_string(p)
            .with_context(|| format!("Failed to read config file at {}", p.display()))?;

        let config: AppConfig = toml::from_str(&content)
            .with_context(|| format!("Failed to parse TOML config from {}", p.display()))?;

        info!("Loaded configuration from {}", p.display());
        Ok(config)
    }

    /// Validate all configuration values.
    pub fn validate(&self) -> Result<()> {
        if self.server.port == 0 {
            anyhow::bail!("server.port must be in range 1-65535");
        }
        if self.mls.rate_limit_per_sec < 1 {
            anyhow::bail!("mls.rate_limit_per_sec must be >= 1");
        }
        if self.mls.max_keypackages < 1 {
            anyhow::bail!("mls.max_keypackages must be >= 1");
        }
        if self.mls.welcome_ttl_days < 1 {
            anyhow::bail!("mls.welcome_ttl_days must be >= 1");
        }
        if self.mls.commit_history_limit < 1 {
            anyhow::bail!("mls.commit_history_limit must be >= 1");
        }
        if self.database.encryption_key.len() < 16 {
            anyhow::bail!("database.encryption_key must be at least 16 characters");
        }
        match self.mls.mode.as_str() {
            "relay" | "full" | "master-key" => {}
            other => {
                anyhow::bail!("mls.mode must be 'relay', 'full', or 'master-key', got '{}'", other)
            }
        }
        if self.backlog.listen_port == 0 || self.backlog.listen_port > 65535 {
            anyhow::bail!("backlog.listen_port must be 1-65535");
        }
        Ok(())
    }

    /// Convert to `irc::client::data::Config`
    pub fn to_irc_config(&self) -> irc::client::data::Config {
        irc::client::data::Config {
            server: Some(self.server.address.clone()),
            port: Some(self.server.port),
            use_tls: Some(self.server.use_tls),
            nickname: Some(self.server.nickname.clone()),
            username: Some(self.server.username.clone()),
            realname: Some(self.server.realname.clone()),
            channels: self.server.channels.clone(),
            password: self.server.password.clone(),
            ..Default::default()
        }
    }

    /// Derive the database encryption key as 32 raw bytes.
    ///
    /// Supports both raw UTF-8 keys and hex-encoded (64-char) keys.
    pub fn derive_storage_key(&self) -> Result<[u8; 32]> {
        let raw = self.database.encryption_key.as_bytes();

        if raw.len() == 64 {
            // Try hex decode
            if let Ok(decoded) = hex::decode(raw) {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                return Ok(key);
            }
        }

        // Use HKDF to derive a 32-byte key from the raw material
        use hkdf::Hkdf;
        use sha2::Sha256;
        let salt = b"FiSH11_MLS_BOT_STORAGE_v1";
        let info = b"fish11.mls.bot.storage.key";
        let hk = Hkdf::<Sha256>::new(Some(salt), raw);
        let mut okm = [0u8; 32];
        hk.expand(info, &mut okm).map_err(|e| anyhow::anyhow!("HKDF expansion failed: {}", e))?;
        Ok(okm)
    }
}
